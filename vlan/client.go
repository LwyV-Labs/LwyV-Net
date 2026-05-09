package vlan

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/config"
	"github.com/LwyV-Labs/LwyV-Net/secure"
	"github.com/LwyV-Labs/LwyV-Net/tunSetup"
	"github.com/LwyV-Labs/LwyV-Net/vdhcp"
)

const (
	heartbeatInterval  = 5 * time.Second
	heartbeatFluctuate = 1 * time.Second
)

type Client struct {
	stats trafficCounter
	// keyID：每次握手递增，用于会话轮转标识。
	keyID atomic.Uint32

	stop atomic.Bool
	conn net.Conn
	tun  *tunSetup.TUNTunnel
}

var cconf config.ClientConfig

func NewClient(confs config.ClientConfig) *Client {
	cconf = confs
	return &Client{}
}

func (c *Client) Start(selectIndex int) {
	// 1) 选择目标服务端配置；2) 创建 TUN 网卡；3) 启动收发循环。
	var err error
	if c.tun, err = tunSetup.NewTUNTunnel(cconf.IfName, cconf.Servers[selectIndex].MTU); err != nil {
		log.Fatalf("创建虚拟网卡失败: %v", err)
	}
	// Windows 上当目标别名已存在时，系统可能返回带后缀的新别名（如 “xxx 2”）。
	// 后续路由/DNS 必须使用真实网卡名，否则会出现“看起来配置成功但流量不进 TUN”。
	if realIf := c.tun.Name(); realIf != "" && realIf != cconf.IfName {
		log.Printf("⚠️ TUN网卡名发生重命名: configured=%s actual=%s", cconf.IfName, realIf)
		cconf.IfName = realIf
	}
	if err = tunSetup.AllowTunTraffic(cconf.IfName); err != nil {
		log.Fatalf("配置TUN策略失败: %v", err)
	}

	cconf.PeerStatic, err = secure.ParsePublicKey(cconf.Servers[selectIndex].PublicKey)
	if err != nil {
		log.Printf("服务端公钥配置错误: servers[%d].publicKey err=%v", selectIndex, err)
	}

	for !c.stop.Load() {
		conn, err := net.Dial("tcp", cconf.Servers[selectIndex].ServerIP)
		if err != nil {
			log.Printf("连接服务端失败: %v，1秒后重试", err)
			time.Sleep(time.Second)
			continue
		}
		c.conn = conn
		log.Printf("✅ 已连接服务端: %s", cconf.Servers[selectIndex].ServerIP)
		c.runSession(conn, cconf.Servers[selectIndex].ServerIP)
		time.Sleep(time.Second)
	}
}

func (c *Client) Stop() {
	c.stop.Store(true)

	tunSetup.CleanupClientProxyRouting()
	tunSetup.CleanupTunTraffic()

	// 关闭客户端连接
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Printf("TCP连接关闭失败: %v", err)
		}
		c.conn = nil
	}

	// 关闭TUN设备。优先关闭 TUNTunnel，让内部读写 goroutine 一起退出。
	if c.tun != nil {
		if err := c.tun.Close(); err != nil {
			log.Printf("TUN关闭失败: %v", err)
		}
		c.tun = nil
	}

	log.Printf("客户端已停止")
}

func (c *Client) runSession(conn net.Conn, serverIP string) {
	// 每次连接对应一个会话管理器（保存当前密钥状态）。
	sessionMgr := &secure.SessionManager{}
	if err := c.performHandshake(conn, sessionMgr); err != nil {
		log.Printf("认证握手失败: %v", err)
		_ = conn.Close()
		return
	}
	log.Printf("认证握手成功，开始申请虚拟地址")
	if err := c.initAddress(conn, sessionMgr, serverIP); err != nil {
		log.Printf("初始化地址失败: %v", err)
		_ = conn.Close()
		return
	}
	log.Printf("✅ 虚拟地址配置成功")
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 下行：网络 -> TUN
		c.connToTun(conn, sessionMgr)
	}()
	// 上行：TUN/心跳 -> 网络
	c.clientSendLoop(conn, done, sessionMgr)
}

func (c *Client) initAddress(conn net.Conn, sessionMgr *secure.SessionManager, serverIP string) error {
	// 通过虚拟 DHCP 从服务端申请一个虚拟网段地址。
	dhcpIP, dhcpMask, dhcpGateway, err := c.requestVDHCP(conn, sessionMgr)
	if err != nil {
		return err
	}
	log.Printf("✅ 客户端已获取 VDHCP 虚拟地址: ip=%s mask=%s", dhcpIP, dhcpMask)
	if err = tunSetup.ConfigureTunAddress(cconf.IfName, dhcpIP, dhcpMask); err != nil {
		return fmt.Errorf("配置虚拟网卡 IP 失败: %w", err)
	}
	if cconf.Proxy {
		// 代理模式：把默认流量经虚拟网卡导向服务端网关。
		if err = tunSetup.SetupClientProxyRouting(serverIP, cconf.IfName, dhcpGateway); err != nil {
			return fmt.Errorf("客户端代理路由初始化失败: %w", err)
		}
	}
	return nil
}

func (c *Client) requestVDHCP(conn net.Conn, sessionMgr *secure.SessionManager) (string, string, string, error) {
	// DHCP Discover -> Offer 的最小流程（简化版 DHCP 协议）。
	discover, err := vdhcp.EncodeDiscover()
	if err != nil {
		return "", "", "", err
	}
	if err = writeSecureFrame(conn, sessionMgr, PacketTypeVDHCP, discover); err != nil {
		log.Printf("发送DHCP Discover失败: %v", err)
		return "", "", "", err
	}
	frame, err := readFrame(conn)
	if err != nil {
		log.Printf("读取DHCP Offer失败: err=%v", err)
		return "", "", "", fmt.Errorf("读取DHCP OFFER失败: %w", err)
	}
	if frame.Type != PacketTypeSecure {
		log.Printf("读取DHCP Offer失败: 非预期类型=%d", frame.Type)
		return "", "", "", fmt.Errorf("读取DHCP OFFER失败")
	}
	innerType, plain, err := sessionMgr.Decrypt(frame.IPPacket)
	if err != nil || PacketType(innerType) != PacketTypeVDHCP {
		log.Printf("解密DHCP Offer失败: err=%v innerType=%d", err, innerType)
		return "", "", "", fmt.Errorf("解密DHCP OFFER失败")
	}
	msg, err := vdhcp.DecodeMessage(plain)
	if err != nil || msg.Type != vdhcp.MessageTypeOffer || msg.IP == "" || msg.SubnetMask == "" || msg.Gateway == "" {
		return "", "", "", fmt.Errorf("解析DHCP OFFER失败")
	}
	return msg.IP, msg.SubnetMask, msg.Gateway, nil
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
		case pkt, ok := <-c.tun.ReadChan():
			if !ok {
				return
			}
			// 所有业务包都先走会话加密，再发外层 Secure 帧。
			if err := writeSecureFrame(conn, sessionMgr, PacketTypeIP, pkt); err != nil {
				return
			}
			c.stats.addUpload(len(pkt))
		}
	}
}

func (c *Client) connToTun(conn net.Conn, sessionMgr *secure.SessionManager) {
	for {
		frame, err := readFrame(conn)
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
			log.Printf("解密业务数据失败: err=%v innerType=%d", err, innerType)
			continue
		}
		c.stats.addDownload(len(plain))
		if err = c.tun.Write(plain); err != nil {
			// TUN 写失败通常意味着网卡已关闭或系统层异常。
			log.Printf("写入TUN失败: %v", err)
			return
		}
	}
}

func (c *Client) performHandshake(conn net.Conn, sessionMgr *secure.SessionManager) error {
	// 客户端作为发起方（Initiator）完成一次 Noise 握手。
	if len(cconf.Identity.Private) == 0 {
		return fmt.Errorf("common.privateKey is required")
	}
	hs := secure.NewHandshaker(cconf.Identity, cconf.PeerStatic)
	keyID := c.keyID.Add(1)
	log.Printf("开始认证握手: keyID=%d", keyID)
	session, err := hs.InitiatorHandshake(
		func(msg []byte) error { return writeFrame(conn, PacketTypeHandshakeInit, msg) },
		func() ([]byte, error) {
			frame, err := readFrame(conn)
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

func (c *Client) GetTrafficStats() TrafficStats {
	return c.stats.snapshot()
}

// RandomInterval 生成：基础时间 ± 浮动范围 的随机间隔
func RandomInterval(base, fluctuate time.Duration) time.Duration {
	// 生成 [-fluctuate, fluctuate] 之间的随机 Duration
	offset := time.Duration(rand.Int63n(2*int64(fluctuate)+1)) - fluctuate
	return base + offset
}
