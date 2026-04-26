package vlan

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"NetworkSetup/vdhcp"
	"NetworkSetup/vlan/secure"
	kcp "github.com/xtaci/kcp-go/v5"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	heartbeatInterval  = 5 * time.Second
	heartbeatFluctuate = 1 * time.Second
	readTimeout        = 16 * time.Second
	tunPacketQueueSize = 1024
)

type Client struct {
	// tunPacketChan：把“读 TUN”和“写网络”解耦，避免互相阻塞。
	tunPacketChan chan []byte
	// keyID：每次握手递增，用于会话轮转标识。
	keyID atomic.Uint32
}

func NewClient() *Client {
	return &Client{tunPacketChan: make(chan []byte, tunPacketQueueSize)}
}

func StartClient() { NewClient().Start() }

func (c *Client) Start() {
	// 1) 创建 TUN 网卡；2) 放行本机策略；3) 启动收发循环。
	dev, err := createTun(Conf.Client.IfName, Conf.Common.MTU)
	if err != nil {
		log.Fatalf("创建虚拟网卡失败: %v", err)
	}
	defer dev.Close()
	_ = allowTunTraffic(Conf.Client.IfName)
	defer cleanupTunTraffic()
	defer cleanupClientProxyRouting()
	c.installCleanupSignal()
	go c.tunToPacketQueue(dev)

	switch Conf.Common.Mode {
	case "TCP":
		// TCP 模式：稳定、易调试。
		c.startTCP(dev)
	case "KCP":
		// KCP 模式：基于 UDP，通常时延更低。
		c.startKCP(dev)
	default:
		log.Fatalf("不支持类型: %s", Conf.Common.Mode)
	}
}

func (c *Client) installCleanupSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cleanupClientProxyRouting()
		cleanupTunTraffic()
		os.Exit(0)
	}()
}

func (c *Client) startTCP(dev tun.Device) {
	for {
		// 断线自动重连。
		conn, err := net.DialTimeout("tcp", Conf.Client.ServerIP, 5*time.Second)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		c.runSession(dev, conn)
	}
}

func (c *Client) startKCP(dev tun.Device) {
	for {
		conn, err := kcp.DialWithOptions(Conf.Client.ServerIP, nil, 0, 0)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		setupKCPSession(conn)
		c.runSession(dev, conn)
	}
}

func (c *Client) runSession(dev tun.Device, conn net.Conn) {
	// 每次连接对应一个会话管理器（保存当前密钥状态）。
	sessionMgr := &secure.SessionManager{}
	if err := c.performHandshake(conn, sessionMgr); err != nil {
		_ = conn.Close()
		return
	}
	if err := c.initAddress(conn, sessionMgr); err != nil {
		_ = conn.Close()
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 下行：网络 -> TUN
		c.connToTun(dev, conn, sessionMgr)
	}()
	// 上行：TUN/心跳 -> 网络
	c.clientSendLoop(conn, done, sessionMgr)
	_ = conn.Close()
	cleanupClientProxyRouting()
}

func (c *Client) initAddress(conn net.Conn, sessionMgr *secure.SessionManager) error {
	// 通过虚拟 DHCP 从服务端申请一个虚拟网段地址。
	dhcpIP, dhcpMask, err := c.requestVDHCP(conn, sessionMgr)
	if err != nil {
		return err
	}
	if err = configureTunAddress(Conf.Client.IfName, dhcpIP, dhcpMask); err != nil {
		return fmt.Errorf("配置虚拟网卡 IP 失败: %w", err)
	}
	if Conf.Common.Proxy {
		// 代理模式：把默认流量经虚拟网卡导向服务端网关。
		if err = setupClientProxyRouting(Conf.Client.ServerIP, Conf.Client.IfName, Conf.Common.Gateway); err != nil {
			return fmt.Errorf("客户端代理路由初始化失败: %w", err)
		}
	}
	return nil
}

func (c *Client) requestVDHCP(conn net.Conn, sessionMgr *secure.SessionManager) (string, string, error) {
	// DHCP Discover -> Offer 的最小流程（简化版 DHCP 协议）。
	discover, err := vdhcp.EncodeDiscover()
	if err != nil {
		return "", "", err
	}
	if err = c.writeSecureFrame(conn, sessionMgr, PacketTypeVDHCP, discover); err != nil {
		return "", "", err
	}
	frame, err := readFrame(conn, maxFramePayload())
	if err != nil || frame.Type != PacketTypeSecure {
		return "", "", fmt.Errorf("读取DHCP OFFER失败")
	}
	innerType, plain, err := sessionMgr.Decrypt(frame.IPPacket)
	if err != nil || PacketType(innerType) != PacketTypeVDHCP {
		return "", "", fmt.Errorf("解密DHCP OFFER失败")
	}
	msg, err := vdhcp.DecodeMessage(plain)
	if err != nil || msg.Type != vdhcp.MessageTypeOffer || msg.IP == "" || msg.SubnetMask == "" {
		return "", "", fmt.Errorf("解析DHCP OFFER失败")
	}
	return msg.IP, msg.SubnetMask, nil
}

func (c *Client) tunToPacketQueue(dev tun.Device) {
	for {
		packets, err := readFromTun(dev, Conf.Common.MTU)
		if err != nil {
			return
		}
		for _, pkt := range packets {
			select {
			case c.tunPacketChan <- pkt:
				// 成功入队。
			default:
				// 队列满时丢弃，优先保证主循环不阻塞。
			}
		}
	}
}

func (c *Client) clientSendLoop(conn net.Conn, done <-chan struct{}, sessionMgr *secure.SessionManager) {
	ticker := time.NewTicker(RandomInterval(heartbeatInterval, heartbeatFluctuate))
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// 心跳包用于保活与探测链路可用性。
			if err := writeFrame(conn, PacketTypePing, nil); err != nil {
				return
			}
		case pkt := <-c.tunPacketChan:
			// 所有业务包都先走会话加密，再发外层 Secure 帧。
			if err := c.writeSecureFrame(conn, sessionMgr, PacketTypeIP, pkt); err != nil {
				return
			}
		}
	}
}

func (c *Client) connToTun(dev tun.Device, conn net.Conn, sessionMgr *secure.SessionManager) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		frame, err := readFrame(conn, maxFramePayload())
		if err != nil {
			return
		}
		if frame.Type == PacketTypePong {
			// 心跳响应包，不进 TUN。
			continue
		}
		if frame.Type != PacketTypeSecure {
			// 仅处理加密数据帧。
			continue
		}
		innerType, plain, err := sessionMgr.Decrypt(frame.IPPacket)
		if err != nil || PacketType(innerType) != PacketTypeIP {
			continue
		}
		if err = writeToTun(dev, plain); err != nil {
			// TUN 写失败通常意味着网卡已关闭或系统层异常。
			return
		}
	}
}

func (c *Client) writeSecureFrame(conn net.Conn, sessionMgr *secure.SessionManager, packetType PacketType, payload []byte) error {
	s := sessionMgr.Current()
	if s == nil {
		return fmt.Errorf("no active session")
	}
	sealed, err := s.Encrypt(byte(packetType), payload)
	if err != nil {
		return err
	}
	return writeFrame(conn, PacketTypeSecure, sealed)
}

func (c *Client) performHandshake(conn net.Conn, sessionMgr *secure.SessionManager) error {
	// 客户端作为发起方（Initiator）完成一次 Noise 握手。
	if len(Conf.Common.Identity.Private) == 0 {
		return fmt.Errorf("common.privateKey is required")
	}
	hs := secure.NewHandshaker(Conf.Common.Identity, Conf.Common.PeerStatic)
	keyID := c.keyID.Add(1)
	session, err := hs.InitiatorHandshake(
		func(msg []byte) error { return writeFrame(conn, PacketTypeHandshakeInit, msg) },
		func() ([]byte, error) {
			frame, err := readFrame(conn, secure.MaxHandshakeMsgSize)
			if err != nil {
				return nil, err
			}
			if frame.Type != PacketTypeHandshakeResp {
				return nil, fmt.Errorf("unexpected handshake frame type=%d", frame.Type)
			}
			return frame.IPPacket, nil
		},
		keyID,
	)
	if err != nil {
		return err
	}
	sessionMgr.Rotate(session)
	return nil
}
