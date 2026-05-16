package vlan2

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/conf2"
	"github.com/LwyV-Labs/LwyV-Net/securetcp"
	"github.com/LwyV-Labs/LwyV-Net/tunSetup"
	"github.com/LwyV-Labs/LwyV-Net/vdhcp2"
	"github.com/LwyV-Labs/LwyV-Net/vlan"
)

type Client struct {
	stats       vlan.TrafficCounter
	tun         *tunSetup.TUNTunnel
	conn        *securetcp.Client
	conf        conf2.ClientConfig
	reconnectMu sync.Mutex // 防止多个重连回调同时执行
}

func NewClient(conf conf2.ClientConfig) *Client {
	client := &Client{
		conf: conf,
	}
	return client
}

func (c *Client) Start() {
	// 1) 选择目标服务端配置；2) 创建 TUN 网卡；3) 启动收发循环。
	var err error
	if c.tun, err = tunSetup.NewTUNTunnel(c.conf.IfName, c.conf.MTU); err != nil {
		log.Fatalf("⚠️ 创建虚拟网卡失败: %v", err)
	}

	if err = tunSetup.AllowTunTraffic(c.conf.IfName); err != nil {
		log.Fatalf("⚠️ 配置TUN策略失败: %v", err)
	}

	kp, err := securetcp.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("✅ 客户端密钥生成成功\n 私钥：PrivateKey[%s] \n 公钥：publicKey[%s]", kp.PrivateKeyB64, kp.PublicKeyB64)

	conn, err := securetcp.NewClient(securetcp.ClientConfig{
		Address:             c.conf.Server,
		ClientPrivateKeyB64: c.conf.PrivateKey,
		ServerPublicKeyB64:  c.conf.ServerPublicKey,
		AutoReconnect:       true,
		CommonConfig: securetcp.CommonConfig{
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    8 * time.Second,
			HeartbeatBase:   4 * time.Second,
			HeartbeatJitter: 1 * time.Second,
			RekeyInterval:   45 * time.Second,
			OldKeyGrace:     20 * time.Second,
		},
		OnReconnect: func() {
			c.reconnectInit()
		},
	})

	c.conn = conn
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if err := conn.Connect(ctx); err != nil {
		log.Fatal(err)
	}

	log.Printf("认证握手成功，开始申请虚拟地址")
	if err := c.initAddress(); err != nil {
		log.Printf("初始化地址失败: %v", err)
		_ = conn.Close()
		return
	}
	log.Printf("✅ 虚拟地址配置成功")

	go c.connToTun()
	// 上行：TUN/心跳 -> 网络
	c.clientSendLoop()

}

func (c *Client) Stop() {
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

func (c *Client) reconnectInit() {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	log.Println("✅ TCP 重连成功，重新申请虚拟地址...")
	if err := c.initAddress(); err != nil {
		log.Printf("重连后申请虚拟地址失败: %v", err)
		// 这里可以根据需要关闭连接或继续尝试，但 securetcp 会自动保持重连
		return
	}
	log.Println("✅ 虚拟地址重新配置成功")
}

func (c *Client) initAddress() error {
	// 通过虚拟 DHCP 从服务端申请一个虚拟网段地址。
	dhcpIP, dhcpMask, dhcpGateway, err := c.requestVDHCP(context.Background())
	if err != nil {
		return err
	}
	log.Printf("✅ 客户端已获取 VDHCP 虚拟地址: ip=%s mask=%s", dhcpIP, dhcpMask)
	if err = tunSetup.ConfigureTunAddress(c.conf.IfName, dhcpIP, dhcpMask); err != nil {
		return fmt.Errorf("配置虚拟网卡 IP 失败: %w", err)
	}
	if c.conf.Proxy {
		// 代理模式：把默认流量经虚拟网卡导向服务端网关。
		if err = tunSetup.SetupClientProxyRouting(c.conf.Server, c.conf.IfName, dhcpGateway); err != nil {
			return fmt.Errorf("客户端代理路由初始化失败: %w", err)
		}
	}
	return nil
}

func (c *Client) requestVDHCP(ctx context.Context) (string, string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	discover, reqID, err := vdhcp2.EncodeDiscover()
	if err != nil {
		return "", "", "", err
	}

	if err := c.conn.Write(ctx, Pack(TypeVDHCP, discover)); err != nil {
		return "", "", "", fmt.Errorf("发送 VDHCP DISCOVER 失败: %w", err)
	}

	raw, err := c.conn.Read(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("读取 VDHCP OFFER 失败: %w", err)
	}

	typ, payload, err := Unpack(raw)
	if err != nil {
		return "", "", "", err
	}
	if typ != TypeVDHCP {
		return "", "", "", fmt.Errorf("expected VDHCP response, got type=%d", typ)
	}

	msg, err := vdhcp2.DecodeMessage(payload)
	if err != nil {
		return "", "", "", err
	}

	if msg.Type == vdhcp2.MessageTypeNak {
		return "", "", "", fmt.Errorf("VDHCP NAK: %s", msg.Reason)
	}

	if err := vdhcp2.ValidateOffer(msg, reqID); err != nil {
		return "", "", "", err
	}

	return msg.IP, msg.SubnetMask, msg.Gateway, nil
}

func (c *Client) connToTun() {
	for {
		raw, err := c.conn.Read(context.Background())
		if err != nil {
			continue
		}

		typ, payload, err := Unpack(raw)
		if err != nil {
			log.Printf("解析应用层数据失败: %v", err)
			continue
		}

		switch typ {
		case TypeIP:
			c.stats.AddDownload(len(payload))
			if err := c.tun.Write(payload); err != nil {
				log.Printf("写入TUN失败: %v", err)
				continue
			}

		case TypeVDHCP:
			// 后续如果做 RENEW / SERVER_NOTICE 可以在这里处理。
			log.Printf("收到VDHCP控制消息，暂未处理")

		default:
			log.Printf("未知数据类型: %d", typ)
			return
		}
	}
}

func (c *Client) clientSendLoop() {
	for {
		pkt, ok := <-c.tun.ReadChan()
		if !ok {
			continue
		}

		payload := Pack(TypeIP, pkt)

		if err := c.conn.Write(context.Background(), payload); err != nil {
			continue
		}

		c.stats.AddUpload(len(pkt))
	}
}
func (c *Client) GetTrafficStats() vlan.TrafficStats {
	return c.stats.Snapshot()
}
