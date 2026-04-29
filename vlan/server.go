package vlan

import (
	"NetworkSetup/secure"
	"NetworkSetup/setup"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"NetworkSetup/vdhcp"
	"golang.zx2c4.com/wireguard/tun"
)

var (
	serverTunDev tun.Device
	serverTunMu  sync.Mutex
)

type tcpConnState struct {
	conn    net.Conn
	mu      sync.Mutex
	session *secure.CryptoSession
}
type ClientPeer struct {
	peerPublicKey, deviceID, virtualIP string
	session                            *secure.SessionManager
	conns                              []*tcpConnState
	connMu                             sync.RWMutex
	sendQueue                          chan []byte
	sendDone                           chan struct{}
	sendCloseOnce                      sync.Once
	rr                                 atomic.Uint32
	downSeq                            atomic.Uint64
}

type PeerTable struct {
	sync.RWMutex
	m map[string]*ClientPeer
}

type Server struct {
	clientTable *PeerTable
	tunDev      tun.Device
	tunMu       sync.Mutex
	dhcp        *vdhcp.Manager
	dhcpMask    string
	keyID       atomic.Uint32
	peerByPub   map[string]*ClientPeer
	peerMu      sync.Mutex
}

const (
	serverPeerSendQueueSize = 16 * 1024
	serverPeerSendWorkers   = 8
)

func NewServer() *Server {
	return &Server{clientTable: &PeerTable{m: map[string]*ClientPeer{}}, peerByPub: map[string]*ClientPeer{}}
}
func StartServer() { NewServer().Start() }
func (s *Server) Start() {
	if err := s.initVDHCP(); err != nil {
		log.Fatalf("初始化虚拟DHCP失败: %v", err)
	}
	if err := s.initGateway(); err != nil {
		log.Fatalf("初始化服务端网关失败: %v", err)
	}
	s.installCleanupSignal()
	s.startTCP()
}
func (s *Server) installCleanupSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() { <-ch; ShutdownServerGateway(); os.Exit(0) }()
}
func (s *Server) initVDHCP() error {
	m, err := vdhcp.NewManager(Conf.VDHCP.StartIP, Conf.VDHCP.EndIP)
	if err != nil {
		return err
	}
	s.dhcp = m
	s.dhcpMask = Conf.Common.SubnetMask
	return nil
}
func (s *Server) initGateway() error {
	if !Conf.Common.Proxy {
		return nil
	}
	ifName := Conf.Server.IfName
	if ifName == "" {
		ifName = "LwyV-Gateway"
	}
	mask := Conf.Common.SubnetMask
	dev, err := setup.CreateTun(ifName, tunPayloadMTU())
	if err != nil {
		return err
	}
	if err = setup.ConfigureTunAddress(ifName, Conf.Common.Gateway, mask); err != nil {
		return err
	}
	if err = setup.EnableServerGatewayNAT(ifName, Conf.Common.Gateway, mask, Conf.Server.EgressIf); err != nil {
		return err
	}
	s.tunDev = dev
	serverTunMu.Lock()
	serverTunDev = dev
	serverTunMu.Unlock()
	go s.tunToClients(dev)
	return nil
}
func ShutdownServerGateway() {
	serverTunMu.Lock()
	if serverTunDev != nil {
		_ = serverTunDev.Close()
		serverTunDev = nil
	}
	serverTunMu.Unlock()
	setup.DisableServerGatewayNAT()
}

func (s *Server) startTCP() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", Conf.Server.Port))
	if err != nil {
		log.Fatalf("TCP服务端启动失败: %v", err)
	}
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleConn(c)
	}
}
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	st := &tcpConnState{conn: conn}
	peer, err := s.handshakeConn(st)
	if err != nil {
		return
	}
	for {
		frame, err := readFrameFromConn(conn)
		if err != nil {
			s.detachConn(peer, st)
			return
		}
		switch frame.Type {
		case PacketTypePing:
			_ = writeFrameToConn(conn, PacketTypePong, nil, &st.mu)
		case PacketTypeSecure:
			inner, p, e := st.session.Decrypt(frame.IPPacket)
			if e != nil {
				continue
			}
			if PacketType(inner) == PacketTypeVDHCP {
				s.handleVDHCP(peer, p, st)
			} else if PacketType(inner) == PacketTypeIP {
				s.handleIP(peer, p)
			}
		}
	}
}
func (s *Server) handshakeConn(st *tcpConnState) (*ClientPeer, error) {
	frame, err := readFrameFromConn(st.conn)
	if err != nil {
		return nil, err
	}
	if frame.Type != PacketTypeHandshakeInit {
		return nil, fmt.Errorf("need hs")
	}
	hs := secure.NewHandshaker(Conf.Common.Identity, nil)
	keyID := s.keyID.Add(1)
	sess, remotePub, err := hs.ResponderHandshake(func(msg []byte) error { return writeFrameToConn(st.conn, PacketTypeHandshakeResp, msg, &st.mu) }, func() ([]byte, error) { return frame.IPPacket, nil }, keyID)
	if err != nil {
		return nil, err
	}
	st.session = sess
	pub := base64.StdEncoding.EncodeToString(remotePub)
	s.peerMu.Lock()
	peer := s.peerByPub[pub]
	if peer == nil {
		peer = &ClientPeer{peerPublicKey: pub, deviceID: secure.DeviceIDFromPublicKey(remotePub), session: &secure.SessionManager{}, sendQueue: make(chan []byte, serverPeerSendQueueSize), sendDone: make(chan struct{})}
		s.peerByPub[pub] = peer
		for i := 0; i < serverPeerSendWorkers; i++ {
			go s.peerSendLoop(peer)
		}
	}
	peer.session.Rotate(sess)
	peer.conns = append(peer.conns, st)
	s.peerMu.Unlock()
	return peer, nil
}
func (s *Server) detachConn(peer *ClientPeer, st *tcpConnState) {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	n := peer.conns[:0]
	for _, c := range peer.conns {
		if c != st {
			n = append(n, c)
		}
	}
	peer.conns = n
}
func (s *Server) peerSendLoop(peer *ClientPeer) {
	for {
		select {
		case <-peer.sendDone:
			return
		case pkt := <-peer.sendQueue:
			_ = s.writeSecureFrame(peer, PacketTypeIP, pkt)
		}
	}
}
func (s *Server) handleVDHCP(peer *ClientPeer, pkt []byte, st *tcpConnState) {
	if s.dhcp == nil {
		return
	}
	msg, err := vdhcp.DecodeMessage(pkt)
	if err != nil || msg.Type != vdhcp.MessageTypeDiscover {
		return
	}
	ip, err := s.dhcp.Allocate(peer.peerPublicKey)
	if err != nil {
		return
	}
	offer, _ := vdhcp.EncodeOffer(ip, s.dhcpMask, Conf.Common.Gateway)
	sealed, _ := st.session.Encrypt(byte(PacketTypeVDHCP), offer)
	_ = writeFrameToConn(st.conn, PacketTypeSecure, sealed, &st.mu)
	peer.virtualIP = ip
	s.clientTable.Lock()
	s.clientTable.m[ip] = peer
	s.clientTable.Unlock()
}
func (s *Server) handleIP(peer *ClientPeer, pkt []byte) {
	_, raw, ok := unpackSeq(pkt)
	if !ok {
		return
	}
	h, err := headerParsing(raw)
	if err != nil || peer.virtualIP == "" || h.SrcIP != peer.virtualIP {
		return
	}
	if h.IsBroadcast {
		s.broadcastPacket(h.SrcIP, raw)
		return
	}
	s.clientTable.RLock()
	t, ok := s.clientTable.m[h.DstIP]
	s.clientTable.RUnlock()
	if !ok {
		_ = s.writeToServerTun(raw)
		return
	}
	_ = s.enqueuePeerPacket(t, raw)
}
func (s *Server) broadcastPacket(src string, raw []byte) {
	s.clientTable.RLock()
	peers := make([]*ClientPeer, 0, len(s.clientTable.m))
	for ip, p := range s.clientTable.m {
		if ip != src {
			peers = append(peers, p)
		}
	}
	s.clientTable.RUnlock()
	for _, p := range peers {
		_ = s.enqueuePeerPacket(p, raw)
	}
}
func (s *Server) enqueuePeerPacket(peer *ClientPeer, raw []byte) error {
	seq := peer.downSeq.Add(1)
	buf := packSeq(seq, raw)
	select {
	case <-peer.sendDone:
		return fmt.Errorf("closed")
	case peer.sendQueue <- buf:
		return nil
	}
}
func (s *Server) writeSecureFrame(peer *ClientPeer, packetType PacketType, payload []byte) error {
	peer.connMu.RLock()
	if len(peer.conns) == 0 {
		peer.connMu.RUnlock()
		return fmt.Errorf("no conn")
	}
	idx := int(peer.rr.Add(1)) % len(peer.conns)
	st := peer.conns[idx]
	peer.connMu.RUnlock()
	sealed, err := st.session.Encrypt(byte(packetType), payload)
	if err != nil {
		return err
	}
	return writeFrameToConn(st.conn, PacketTypeSecure, sealed, &st.mu)
}
func (s *Server) writeToServerTun(pkt []byte) error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunDev == nil {
		return fmt.Errorf("server TUN is not enabled")
	}
	return writeToTun(s.tunDev, pkt)
}
func (s *Server) tunToClients(dev tun.Device) {
	for {
		packets, err := readFromTun(dev)
		if err != nil {
			return
		}
		for _, pkt := range packets {
			h, err := headerParsing(pkt)
			if err != nil {
				continue
			}
			s.clientTable.RLock()
			p, ok := s.clientTable.m[h.DstIP]
			s.clientTable.RUnlock()
			if !ok {
				continue
			}
			_ = s.enqueuePeerPacket(p, pkt)
		}
	}
}
