package vlan

import (
	"NetworkSetup/kit"
	"NetworkSetup/secure"
	"NetworkSetup/setup"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"NetworkSetup/vdhcp"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	heartbeatInterval  = 5 * time.Second
	heartbeatFluctuate = 1 * time.Second
	tunPacketQueueSize = 16 * 1024
)

type tcpLink struct {
	conn net.Conn
	mu   sync.Mutex
}

type Client struct {
	tunPacketChan chan []byte
	keyID         atomic.Uint32
	seq           atomic.Uint64
}

func NewClient() *Client { return &Client{tunPacketChan: make(chan []byte, tunPacketQueueSize)} }
func StartClient()       { NewClient().Start() }

func (c *Client) Start() {
	dev, err := setup.CreateTun(Conf.Client.IfName, tunPayloadMTU())
	if err != nil {
		log.Fatalf("创建虚拟网卡失败: %v", err)
	}
	defer dev.Close()
	_ = setup.AllowTunTraffic(Conf.Client.IfName)
	defer setup.CleanupTunTraffic()
	defer setup.CleanupClientProxyRouting()
	c.installCleanupSignal()
	go c.tunToPacketQueue(dev)
	c.startTCP(dev)
}
func (c *Client) installCleanupSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() { <-ch; setup.CleanupClientProxyRouting(); setup.CleanupTunTraffic(); os.Exit(0) }()
}

func (c *Client) startTCP(dev tun.Device) {
	for {
		if err := c.runSession(dev); err != nil {
			log.Printf("会话结束: %v", err)
		}
		time.Sleep(time.Second)
	}
}

func (c *Client) runSession(dev tun.Device) error {
	conn, err := net.Dial("tcp", Conf.Client.ServerIP)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("已连接TCP服务端: %s", Conf.Client.ServerIP)
	sm := &secure.SessionManager{}
	if err := c.performHandshake(conn, sm); err != nil {
		return err
	}
	if err := c.initAddress(conn, sm); err != nil {
		return err
	}
	links := make([]*tcpLink, Conf.Common.TCPConnections)
	links[0] = &tcpLink{conn: conn}
	for i := 1; i < len(links); i++ {
		cc, e := net.Dial("tcp", Conf.Client.ServerIP)
		if e != nil {
			return e
		}
		links[i] = &tcpLink{conn: cc}
		if e := c.performHandshake(cc, sm); e != nil {
			return e
		}
	}
	done := make(chan struct{})
	recv := make(chan struct {
		seq uint64
		pkt []byte
	}, 1024)
	for _, l := range links {
		go c.readLoop(l.conn, sm, done, recv)
	}
	go c.reassembleToTun(dev, done, recv)
	tk := time.NewTicker(kit.RandomInterval(heartbeatInterval, heartbeatFluctuate))
	defer tk.Stop()
	rr := 0
	for {
		select {
		case <-done:
			return fmt.Errorf("link closed")
		case pkt := <-c.tunPacketChan:
			seq := c.seq.Add(1)
			payload := packSeq(seq, pkt)
			l := links[rr%len(links)]
			rr++
			if err := c.writeSecureFrame(l, sm, PacketTypeIP, payload); err != nil {
				return err
			}
		case <-tk.C:
			_ = writeFrameToConn(links[0].conn, PacketTypePing, nil, &links[0].mu)
		}
	}
}
func packSeq(seq uint64, p []byte) []byte {
	b := make([]byte, 8+len(p))
	copy(b[8:], p)
	for i := 7; i >= 0; i-- {
		b[i] = byte(seq)
		seq >>= 8
	}
	return b
}
func unpackSeq(b []byte) (uint64, []byte, bool) {
	if len(b) < 8 {
		return 0, nil, false
	}
	var s uint64
	for i := 0; i < 8; i++ {
		s = (s << 8) | uint64(b[i])
	}
	return s, b[8:], true
}
func (c *Client) reassembleToTun(dev tun.Device, done <-chan struct{}, in <-chan struct {
	seq uint64
	pkt []byte
}) {
	next := uint64(1)
	buf := map[uint64][]byte{}
	for {
		select {
		case <-done:
			return
		case it := <-in:
			buf[it.seq] = it.pkt
			for {
				p, ok := buf[next]
				if !ok {
					break
				}
				delete(buf, next)
				_, _ = dev.Write([][]byte{p}, 0)
				next++
			}
		}
	}
}

func (c *Client) readLoop(conn net.Conn, sm *secure.SessionManager, done chan struct{}, out chan<- struct {
	seq uint64
	pkt []byte
}) {
	for {
		f, err := readFrameFromConn(conn)
		if err != nil {
			close(done)
			return
		}
		if f.Type != PacketTypeSecure {
			continue
		}
		t, p, e := sm.Decrypt(f.IPPacket)
		if e != nil || PacketType(t) != PacketTypeIP {
			continue
		}
		s, pkt, ok := unpackSeq(p)
		if ok {
			out <- struct {
				seq uint64
				pkt []byte
			}{s, pkt}
		}
	}
}

func (c *Client) initAddress(conn net.Conn, sessionMgr *secure.SessionManager) error {
	dhcpIP, dhcpMask, err := c.requestVDHCP(conn, sessionMgr)
	if err != nil {
		return err
	}
	if err = setup.ConfigureTunAddress(Conf.Client.IfName, dhcpIP, dhcpMask); err != nil {
		return err
	}
	if Conf.Common.Proxy {
		if err = setup.SetupClientProxyRouting(Conf.Client.ServerIP, Conf.Client.IfName, Conf.Common.Gateway); err != nil {
			return err
		}
	}
	return nil
}
func (c *Client) requestVDHCP(conn net.Conn, sessionMgr *secure.SessionManager) (string, string, error) {
	discover, _ := vdhcp.EncodeDiscover()
	l := &tcpLink{conn: conn}
	if err := c.writeSecureFrame(l, sessionMgr, PacketTypeVDHCP, discover); err != nil {
		return "", "", err
	}
	frame, err := readFrameFromConn(conn)
	if err != nil {
		return "", "", err
	}
	innerType, plain, err := sessionMgr.Decrypt(frame.IPPacket)
	if err != nil || PacketType(innerType) != PacketTypeVDHCP {
		return "", "", fmt.Errorf("bad dhcp")
	}
	msg, err := vdhcp.DecodeMessage(plain)
	if err != nil {
		return "", "", err
	}
	return msg.IP, msg.SubnetMask, nil
}
func (c *Client) tunToPacketQueue(dev tun.Device) {
	for {
		packets, err := readFromTun(dev)
		if err != nil {
			return
		}
		for _, pkt := range packets {
			c.tunPacketChan <- pkt
		}
	}
}
func (c *Client) writeSecureFrame(link *tcpLink, sm *secure.SessionManager, packetType PacketType, payload []byte) error {
	s := sm.Current()
	if s == nil {
		return fmt.Errorf("no active session")
	}
	sealed, err := s.Encrypt(byte(packetType), payload)
	if err != nil {
		return err
	}
	return writeFrameToConn(link.conn, PacketTypeSecure, sealed, &link.mu)
}

func (c *Client) performHandshake(conn net.Conn, sessionMgr *secure.SessionManager) error {
	if len(Conf.Common.Identity.Private) == 0 {
		return fmt.Errorf("common.privateKey is required")
	}
	hs := secure.NewHandshaker(Conf.Common.Identity, Conf.Common.PeerStatic)
	keyID := c.keyID.Add(1)
	session, err := hs.InitiatorHandshake(
		func(msg []byte) error { return writeFrameToConn(conn, PacketTypeHandshakeInit, msg, &sync.Mutex{}) },
		func() ([]byte, error) {
			frame, err := readFrameFromConn(conn)
			if err != nil {
				return nil, err
			}
			if frame.Type != PacketTypeHandshakeResp {
				return nil, fmt.Errorf("unexpected handshake frame type=%d", frame.Type)
			}
			return frame.IPPacket, nil
		}, keyID)
	if err != nil {
		return err
	}
	sessionMgr.Rotate(session)
	return nil
}
