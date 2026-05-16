package vlan

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/LwyV-Labs/LwyV-Net/config"
	"github.com/LwyV-Labs/LwyV-Net/tcpx"
	"github.com/LwyV-Labs/LwyV-Net/tunSetup"
	"github.com/LwyV-Labs/LwyV-Net/vdhcp"
)

type Client struct {
	stats TrafficCounter
	conf  config.ClientConfig

	tun       *tunSetup.TUNTunnel
	transport *tcpx.Client

	mu      sync.Mutex
	started bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	session clientSession

	onVDHCPAssigned VDHCPAssignedCallback
}

type clientSession struct {
	conn     *tcpx.SecureConn
	clientID string
	reqID    string
	ready    bool
	remote   string
	lastIP   string
	lastMask string
	lastGW   string
	lastDNS  []string
}

func NewClient(conf config.ClientConfig) *Client {
	return &Client{conf: conf}
}

func (c *Client) Start() {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		log.Printf("客户端已启动，忽略重复 Start")
		return
	}
	c.started = true
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.mu.Unlock()

	if err := c.initTransport(); err != nil {
		log.Fatalf("客户端 tcpx 初始化失败: %v", err)
	}

	c.wg.Add(1)
	go c.runTransport()
}

func (c *Client) Stop() {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return
	}
	c.started = false
	cancel := c.cancel
	transport := c.transport
	c.session = clientSession{}
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if transport != nil {
		_ = transport.Close()
	}
	c.wg.Wait()

	tunSetup.CleanupClientProxyRouting()
	tunSetup.CleanupTunTraffic()
	if c.tun != nil {
		_ = c.tun.Close()
	}
	log.Printf("客户端已停止")
}

func (c *Client) initTun(mtu int) error {
	var err error
	c.tun, err = tunSetup.NewTUNTunnel(c.conf.IfName, mtu)
	if err != nil {
		return fmt.Errorf("创建虚拟网卡失败: %w", err)
	}
	if err = tunSetup.AllowTunTraffic(c.conf.IfName); err != nil {
		return fmt.Errorf("配置 TUN 策略失败: %w", err)
	}
	return nil
}

func (c *Client) initTransport() error {
	serverPubHex, err := tcpx.NormalizePublicKeyHex(c.conf.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("服务端公钥格式错误: %w", err)
	}
	clientID, err := tcpx.PublicKeyHexFromPrivate(c.conf.PrivateKey)
	if err != nil {
		return fmt.Errorf("客户端私钥格式错误: %w", err)
	}
	log.Printf("✅ 客户端身份准备完成 clientID=%s", shortID(clientID))

	transport, err := tcpx.NewClient(tcpx.ClientConfig{
		Addr:               c.conf.Server,
		ServerPublicKeyHex: serverPubHex,
		ReconnectBase:      c.conf.TCP.ReconnectBase(),
		ReconnectJitter:    c.conf.TCP.ReconnectJitter(),
		BaseConfig: tcpx.BaseConfig{
			ReadTimeout:       c.conf.TCP.ClientReadTimeout(),
			WriteTimeout:      c.conf.TCP.ClientWriteTimeout(),
			HeartbeatBase:     c.conf.TCP.ClientHeartbeatBase(),
			HeartbeatJitter:   c.conf.TCP.ClientHeartbeatJitter(),
			KeyRotateInterval: c.conf.TCP.KeyRotateInterval(),
			OldKeyGrace:       c.conf.TCP.ClientOldKeyGrace(),
		},
		OnConnect:    c.onTCPConnect,
		OnDisconnect: c.onTCPDisconnect,
		OnMessage:    c.onTCPMessage,
	})
	if err != nil {
		return err
	}
	c.transport = transport
	return nil
}

func (c *Client) runTransport() {
	defer c.wg.Done()
	if err := c.transport.Run(c.ctx); err != nil && c.ctx.Err() == nil {
		log.Printf("tcpx 客户端退出: %v", err)
	}
}

func (c *Client) onTCPConnect(conn *tcpx.SecureConn) {
	auth, clientID, err := EncodeClientAuth(c.conf.PrivateKey, c.conf.ServerPublicKey)
	if err != nil {
		log.Printf("生成客户端身份认证失败: %v", err)
		_ = conn.Close()
		return
	}

	discover, reqID, err := vdhcp.EncodeDiscover()
	if err != nil {
		log.Printf("生成 VDHCP DISCOVER 失败: %v", err)
		_ = conn.Close()
		return
	}

	c.mu.Lock()
	c.session = clientSession{
		conn:     conn,
		clientID: clientID,
		reqID:    reqID,
		remote:   conn.RemoteAddr().String(),
	}
	c.mu.Unlock()

	log.Printf("✅ tcpx 握手成功 remote=%s，发送客户端身份认证", conn.RemoteAddr())
	if err := conn.Write(Pack(TypeAuth, auth)); err != nil {
		log.Printf("发送客户端身份认证失败: %v", err)
		_ = conn.Close()
		return
	}
	if err := conn.Write(Pack(TypeVDHCP, discover)); err != nil {
		log.Printf("发送 VDHCP DISCOVER 失败: %v", err)
		_ = conn.Close()
		return
	}
	log.Printf("✅ 已发送 VDHCP DISCOVER clientID=%s", shortID(clientID))
}

func (c *Client) onTCPDisconnect(err error) {
	c.mu.Lock()
	old := c.session
	c.session = clientSession{}
	ctx := c.ctx
	c.mu.Unlock()

	if old.conn != nil && ctx != nil && ctx.Err() == nil {
		log.Printf("tcpx 连接断开 remote=%s，将自动重连: %v", old.remote, err)
	}
}

func (c *Client) onTCPMessage(conn *tcpx.SecureConn, raw []byte) {
	if !c.isCurrentConn(conn) {
		return
	}

	typ, payload, err := Unpack(raw)
	if err != nil {
		log.Printf("解析应用层数据失败: %v", err)
		_ = conn.Close()
		return
	}

	switch typ {
	case TypeVDHCP:
		if err := c.handleVDHCP(conn, payload); err != nil {
			log.Printf("处理 VDHCP 响应失败: %v", err)
			_ = conn.Close()
		}
	case TypeIP:
		if !c.isReadyConn(conn) {
			return
		}
		if c.tun == nil {
			return
		}
		c.stats.AddDownload(len(payload))
		if err := c.tun.Write(payload); err != nil {
			log.Printf("写入 TUN 失败: %v", err)
		}
	case TypeAuth:
		log.Printf("客户端收到 TypeAuth，忽略")
	default:
		log.Printf("未知应用层类型: %d", typ)
		_ = conn.Close()
	}
}

func (c *Client) handleVDHCP(conn *tcpx.SecureConn, payload []byte) error {
	msg, err := vdhcp.DecodeMessage(payload)
	if err != nil {
		return err
	}
	if msg.Type == vdhcp.MessageTypeNak {
		return fmt.Errorf("VDHCP NAK: %s", msg.Reason)
	}

	c.mu.Lock()
	reqID := c.session.reqID
	alreadyReady := c.session.ready
	c.mu.Unlock()
	if alreadyReady {
		return nil
	}
	if err := vdhcp.ValidateOffer(msg, reqID); err != nil {
		return err
	}

	if err := c.configureAddress(msg.IP, msg.SubnetMask, msg.Gateway, msg.DNS, msg.MTU); err != nil {
		return err
	}

	var assigned VDHCPAssignedInfo
	c.mu.Lock()
	if c.session.conn == conn {
		c.session.ready = true
		c.session.lastIP = msg.IP
		c.session.lastMask = msg.SubnetMask
		c.session.lastGW = msg.Gateway
		c.session.lastDNS = append([]string(nil), msg.DNS...)
		assigned = VDHCPAssignedInfo{
			ClientID:     c.session.clientID,
			RemoteAddr:   c.session.remote,
			IP:           msg.IP,
			SubnetMask:   msg.SubnetMask,
			Gateway:      msg.Gateway,
			DNS:          append([]string(nil), msg.DNS...),
			MTU:          msg.MTU,
			LeaseSeconds: msg.LeaseSeconds,
		}
	}
	c.mu.Unlock()

	log.Printf("✅ 虚拟地址配置成功 ip=%s mask=%s gateway=%s dns=%v", msg.IP, msg.SubnetMask, msg.Gateway, msg.DNS)
	if assigned.IP != "" {
		c.emitVDHCPAssigned(assigned)
	}
	return nil
}

func (c *Client) configureAddress(ip, mask, gateway string, dns []string, mtu int) error {
	if c.tun == nil {
		if err := c.initTun(mtu); err != nil {
			return fmt.Errorf("创建虚拟网卡失败: %w", err)
		}
		c.wg.Add(1)
		go c.tunToTCP()
	}
	if err := tunSetup.ConfigureTunAddress(c.conf.IfName, ip, mask); err != nil {
		return fmt.Errorf("配置虚拟网卡 IP 失败: %w", err)
	}
	if !c.conf.Proxy {
		return nil
	}
	// 重连后先清理旧代理路由，避免残留规则与新网关冲突。
	tunSetup.CleanupClientProxyRouting()
	if err := tunSetup.SetupClientProxyRouting(c.conf.Server, c.conf.IfName, gateway, dns); err != nil {
		return fmt.Errorf("客户端代理路由初始化失败: %w", err)
	}
	return nil
}

func (c *Client) tunToTCP() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case pkt, ok := <-c.tun.ReadChan():
			if !ok {
				return
			}
			conn := c.readyConn()
			if conn == nil {
				// 未完成认证/DHCP 时丢弃 TUN 包，避免把未配置好的数据发进隧道。
				continue
			}
			if err := conn.Write(Pack(TypeIP, pkt)); err != nil {
				log.Printf("写 TCP 通道错误: %v", err)
				_ = conn.Close()
				continue
			}
			c.stats.AddUpload(len(pkt))
		}
	}
}

func (c *Client) isCurrentConn(conn *tcpx.SecureConn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session.conn == conn
}

func (c *Client) isReadyConn(conn *tcpx.SecureConn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session.conn == conn && c.session.ready
}

func (c *Client) readyConn() *tcpx.SecureConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session.ready {
		return c.session.conn
	}
	return nil
}

func (c *Client) GetTrafficStats() TrafficStats {
	return c.stats.Snapshot()
}
