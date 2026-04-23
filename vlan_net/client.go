package vlan_net

import (
	"log"
	"net"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	heartbeatInterval  = 5 * time.Second
	readTimeout        = 16 * time.Second
	tunPacketQueueSize = 1024
)

var (
	tunPacketChan = make(chan []byte, tunPacketQueueSize)
)

func StartClient() {
	dev, err := createTun(Conf.Client.IfName, Conf.Common.MTU)
	if err != nil {
		log.Fatalf("创建虚拟网卡失败: %v", err)
	}
	defer dev.Close()

	if err := configureTunAddress(Conf.Client.IfName, Conf.Client.LocalIP, Conf.Client.SubnetMask); err != nil {
		log.Fatalf("配置虚拟网卡 IP 失败: %v", err)
	}

	if err := allowTunTraffic(Conf.Client.IfName); err != nil {
		log.Printf("放行虚拟网卡流量失败: %v", err)
	}
	defer cleanupTunTraffic()

	if Conf.Common.Proxy {
		if err := addDefaultRoute(Conf.Client.IfName, Conf.Common.Gateway); err != nil {
			log.Printf("默认路由添加失败: %v", err)
		}
	}

	go tunToPacketQueue(dev)

	if Conf.Common.Mode == "TCP" {
		startTCPClient(dev)
	} else if Conf.Common.Mode == "KCP" {
		startKCPClient(dev)
	} else {
		log.Fatalf("不支持类型: %s", Conf.Common.Mode)
	}
}

func startTCPClient(dev tun.Device) {
	for {
		conn, err := net.DialTimeout("tcp", Conf.Client.ServerIP, 5*time.Second)
		if err != nil {
			log.Printf("连接失败: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		log.Printf("✅ 已连接服务端: %s", Conf.Client.ServerIP)

		// TCP -> TUN 单独运行；一旦它退出，说明当前TCP连接不可用，需要重连。
		tcpDone := make(chan struct{})
		go func() {
			defer close(tcpDone)
			connToTun(dev, conn)
		}()

		// TCP连接期间，把TUN队列中的包发送到TCP。
		clientSendLoop(conn, tcpDone)

		_ = conn.Close()
		log.Println("连接断开，准备重连...")
	}
}

func startKCPClient(dev tun.Device) {

	block, err := kcp.NewAESGCMCrypt(Conf.Common.Key)
	if err != nil {
		log.Fatalf("KCP AES-GCM 初始化失败: %v", err)
	}

	for {
		conn, err := kcp.DialWithOptions(Conf.Client.ServerIP, block, 0, 0)
		if err != nil {
			log.Printf("KCP连接失败: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		setupKCPSession(conn)

		log.Printf("✅ 已连接KCP服务端: %s", Conf.Client.ServerIP)

		// KCP -> TUN 单独运行；一旦它退出，说明当前KCP连接不可用，需要重连。
		kcpDone := make(chan struct{})
		go func() {
			defer close(kcpDone)
			connToTun(dev, conn)
		}()

		// KCP连接期间，把TUN队列中的包发送到KCP。
		clientSendLoop(conn, kcpDone)

		_ = conn.Close()
		log.Println("连接断开，准备重连...")
	}
}

// tunToPacketQueue TUN -> packet queue
func tunToPacketQueue(dev tun.Device) {
	// 官方 Read 要求：必须是 [][]byte + []int
	bufs := make([][]byte, 1)               // 一次读1个包
	sizes := make([]int, 1)                 // 存储每个包的长度
	bufs[0] = make([]byte, Conf.Common.MTU) // 包缓冲区

	log.Printf("▶ 启动：TUN → Queue")
	for {
		// 读取TUN设备数据
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			log.Printf("TUN读取失败: %v", err)
			return
		}
		if n <= 0 {
			continue
		}
		if sizes[0] <= 0 || sizes[0] > len(bufs[0]) {
			continue
		}

		// 必须复制一份，因为 bufs[0] 会在下一次 dev.Read 时复用。
		pkt := make([]byte, sizes[0])
		copy(pkt, bufs[0][:sizes[0]])

		// 队列满时丢包，避免断线或慢连接时把TUN读取goroutine永久堵住。
		select {
		case tunPacketChan <- pkt:
		default:
			log.Printf("TUN发送队列已满，丢弃IP包: %d bytes", len(pkt))
		}
	}
}

// clientSendLoop Queue -> conn(KCP,TCP)
func clientSendLoop(conn net.Conn, kcpDone <-chan struct{}) {
	log.Printf("▶ 启动：Queue → %s", Conf.Common.Mode)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-kcpDone:
			return

		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := writePacket(conn, []byte("PING")); err != nil {
				log.Printf("%s心跳发送失败: %v", Conf.Common.Mode, err)
				return
			}

		case pkt := <-tunPacketChan:
			_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := writePacket(conn, pkt); err != nil {
				log.Printf("%s发送失败: %v", Conf.Common.Mode, err)
				return
			}
		}
	}
}

// connToTun conn(KCP,TCP) -> TUN
func connToTun(dev tun.Device, conn net.Conn) {
	log.Printf("▶ 启动：%s → Queue", Conf.Common.Mode)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

		// 接收包
		pkt, err := readPacket(conn, Conf.Common.MTU)
		if err != nil {
			log.Printf("%s接收失败: %v", Conf.Common.Mode, err)
			return
		}
		if string(pkt) == "PONG" {
			continue
		}
		// 写入TUN设备数据
		bufs := [][]byte{pkt}
		_, err = dev.Write(bufs, 0)
		if err != nil {
			log.Printf("TUN写入失败: %v", err)
			return
		}
	}
}
