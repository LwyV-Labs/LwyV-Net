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
	"sync/atomic"
	"syscall"
	"time"

	"NetworkSetup/vdhcp"

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
	dev, err := setup.CreateTun(Conf.Client.IfName, Conf.Common.MTU)
	if err != nil {
		log.Fatalf("创建虚拟网卡失败: %v", err)
	}
	defer dev.Close()
	_ = setup.AllowTunTraffic(Conf.Client.IfName)
	defer setup.CleanupTunTraffic()
	defer setup.CleanupClientProxyRouting()

	c.installCleanupSignal()

	go c.tunToPacketQueue(dev)

	c.startKCP(dev)

}

func (c *Client) installCleanupSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		setup.CleanupClientProxyRouting()
		setup.CleanupTunTraffic()
		os.Exit(0)
	}()
}

func (c *Client) startKCP(dev tun.Device) {
	for {
		conn, err := kcp.DialWithOptions(Conf.Client.ServerIP, nil, 0, 0)
		if err != nil {
			log.Printf("连接服务端失败: %v，1秒后重试", err)
			time.Sleep(time.Second)
			continue
		}
		log.Printf("已连接服务端: %s", Conf.Client.ServerIP)
		setupKCPSession(conn)
		c.runSession(dev, conn)
	}
}

func (c *Client) runSession(dev tun.Device, conn net.Conn) {
	// 每次连接对应一个会话管理器（保存当前密钥状态）。
	sessionMgr := &secure.SessionManager{}
	if err := c.performHandshake(conn, sessionMgr); err != nil {
		log.Printf("认证握手失败: %v", err)
		_ = conn.Close()
		return
	}
	log.Printf("认证握手成功，开始申请虚拟地址")
	if err := c.initAddress(conn, sessionMgr); err != nil {
		log.Printf("初始化地址失败: %v", err)
		_ = conn.Close()
		return
	}
	log.Printf("虚拟地址初始化完成，进入收发循环")
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 下行：网络 -> TUN
		c.connToTun(dev, conn, sessionMgr)
	}()
	// 上行：TUN/心跳 -> 网络
	c.clientSendLoop(conn, done, sessionMgr)
	_ = conn.Close()
	setup.CleanupClientProxyRouting()
}

func (c *Client) initAddress(conn net.Conn, sessionMgr *secure.SessionManager) error {
	// 通过虚拟 DHCP 从服务端申请一个虚拟网段地址。
	dhcpIP, dhcpMask, err := c.requestVDHCP(conn, sessionMgr)
	if err != nil {
		return err
	}
	log.Printf("✅ 客户端已获取 VDHCP 虚拟地址: ip=%s mask=%s", dhcpIP, dhcpMask)
	if err = setup.ConfigureTunAddress(Conf.Client.IfName, dhcpIP, dhcpMask); err != nil {
		return fmt.Errorf("配置虚拟网卡 IP 失败: %w", err)
	}
	if Conf.Common.Proxy {
		// 代理模式：把默认流量经虚拟网卡导向服务端网关。
		if err = setup.SetupClientProxyRouting(Conf.Client.ServerIP, Conf.Client.IfName, Conf.Common.Gateway); err != nil {
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
		log.Printf("发送DHCP Discover失败: %v", err)
		return "", "", err
	}
	frame, err := readFrame(conn, maxFramePayload())
	if err != nil {
		log.Printf("读取DHCP Offer失败: err=%v", err)
		return "", "", fmt.Errorf("读取DHCP OFFER失败")
	}
	if frame.Type != PacketTypeSecure {
		log.Printf("读取DHCP Offer失败: 非预期类型=%d", frame.Type)
		return "", "", fmt.Errorf("读取DHCP OFFER失败")
	}
	innerType, plain, err := sessionMgr.Decrypt(frame.IPPacket)
	if err != nil || PacketType(innerType) != PacketTypeVDHCP {
		log.Printf("解密DHCP Offer失败: err=%v innerType=%d", err, innerType)
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
	ticker := time.NewTicker(kit.RandomInterval(heartbeatInterval, heartbeatFluctuate))
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
			log.Printf("读取服务端数据失败，连接即将重建: %v", err)
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
			log.Printf("解密业务数据失败: err=%v innerType=%d", err, innerType)
			continue
		}
		if err = writeToTun(dev, plain); err != nil {
			// TUN 写失败通常意味着网卡已关闭或系统层异常。
			log.Printf("写入TUN失败: %v", err)
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
	log.Printf("开始认证握手: keyID=%d", keyID)
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
		log.Printf("握手协商失败: keyID=%d err=%v", keyID, err)
		return err
	}
	sessionMgr.Rotate(session)
	log.Printf("握手完成并切换会话: keyID=%d", keyID)
	return nil
}
