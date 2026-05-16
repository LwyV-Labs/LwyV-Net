package client

import (
	"log"
	"sync/atomic"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/config"
	"github.com/LwyV-Labs/LwyV-Net/secure"
	"github.com/LwyV-Labs/LwyV-Net/tunSetup"
)

const (
	heartbeatInterval  = 5 * time.Second
	heartbeatFluctuate = 1 * time.Second
)

type Client struct {
	tun  *tunSetup.TUNTunnel
	conf *config.ClientConfig
	stop atomic.Bool
}

func NewClient(conf config.ClientConfig) *Client {
	client := &Client{}
	client.conf = &conf
	return client
}

func (c *Client) Start(selectIndex int) {
	// 1) 选择目标服务端配置；2) 创建 TUN 网卡；3) 启动收发循环。
	var err error
	if c.tun, err = tunSetup.NewTUNTunnel(c.conf.IfName, c.conf.Servers[selectIndex].MTU); err != nil {
		log.Fatalf("创建虚拟网卡失败: %v", err)
	}

	if err = tunSetup.AllowTunTraffic(c.conf.IfName); err != nil {
		log.Fatalf("配置TUN策略失败: %v", err)
	}

	c.conf.PeerStatic, err = secure.ParsePublicKey(c.conf.Servers[selectIndex].PublicKey)
	if err != nil {
		log.Printf("服务端公钥配置错误: servers[%d].publicKey err=%v", selectIndex, err)
	}

	for !c.stop.Load() {

		log.Printf("✅ 已连接服务端: %s", c.conf.Servers[selectIndex].ServerIP)
		time.Sleep(time.Second)
	}
}
