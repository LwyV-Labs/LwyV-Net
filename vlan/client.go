package vlan

import (
	"fmt"
	"log"
	"net"
	"time"

	"NetworkSetup/vdhcp"

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
	routeInited   bool
	cleanupRoute  func()
)

func StartClient() {
	dev, err := createTun(Conf.Client.IfName, Conf.Common.MTU)
	if err != nil {
		log.Fatalf("创建虚拟网卡失败: %v", err)
	}
	defer dev.Close()

	if err := allowTunTraffic(Conf.Client.IfName); err != nil {
		log.Printf("放行虚拟网卡流量失败: %v", err)
	}
	defer cleanupTunTraffic()

	go tunToPacketQueue(dev)

	defer func() {
		if cleanupRoute != nil {
			cleanupRoute()
		}
	}()

	if Conf.Common.Mode == "TCP" {
		startTCPClient(dev, &cleanupRoute)
	} else if Conf.Common.Mode == "KCP" {
		startKCPClient(dev, &cleanupRoute)
	} else {
		log.Fatalf("不支持类型: %s", Conf.Common.Mode)
	}
}

func startTCPClient(dev tun.Device, cleanupRoute *func()) {
	for {
		conn, err := net.DialTimeout("tcp", Conf.Client.ServerIP, 5*time.Second)
		if err != nil {
			log.Printf("连接失败: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}
		log.Printf("✅ 已连接服务端: %s", Conf.Client.ServerIP)

		if err = initClientAddress(conn, cleanupRoute); err != nil {
			log.Printf("客户端地址初始化失败: %v", err)
			_ = conn.Close()
			time.Sleep(1 * time.Second)
			continue
		}

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

func startKCPClient(dev tun.Device, cleanupRoute *func()) {

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

		if err = initClientAddress(conn, cleanupRoute); err != nil {
			log.Printf("客户端地址初始化失败: %v", err)
			_ = conn.Close()
			time.Sleep(1 * time.Second)
			continue
		}

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

func initClientAddress(conn net.Conn, cleanupRoute *func()) error {

	dhcpIP, dhcpMask, err := requestVDHCP(conn)
	if err != nil {
		return err
	}
	ip := dhcpIP
	mask := dhcpMask

	if err := configureTunAddress(Conf.Client.IfName, ip, mask); err != nil {
		return fmt.Errorf("配置虚拟网卡 IP 失败: %w", err)
	}
	log.Printf("✅ 客户端地址已配置: %s/%s", ip, mask)

	if Conf.Common.Proxy {
		if !routeInited { // 仅未初始化时执行
			cleanup, err := setupClientProxyRouting(
				Conf.Client.ServerIP,
				Conf.Client.IfName,
				Conf.Common.Gateway,
			)
			if err != nil {
				return fmt.Errorf("客户端代理路由初始化失败: %w", err)
			}
			*cleanupRoute = cleanup
			routeInited = true // 标记为已初始化

		}
	}

	return nil
}

func requestVDHCP(conn net.Conn) (string, string, error) {
	discover, err := vdhcp.EncodeDiscover()
	if err != nil {
		return "", "", err
	}

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err = writePacket(conn, discover); err != nil {
		return "", "", fmt.Errorf("发送DHCP DISCOVER失败: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	pkt, err := readPacket(conn, Conf.Common.MTU)
	if err != nil {
		return "", "", fmt.Errorf("读取DHCP OFFER失败: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	msg, err := vdhcp.DecodeMessage(pkt)
	if err != nil {
		return "", "", fmt.Errorf("解析DHCP OFFER失败: %w", err)
	}

	if msg.Type == vdhcp.MessageTypeNak {
		return "", "", fmt.Errorf("DHCP NAK: %s", msg.Reason)
	}
	if msg.Type != vdhcp.MessageTypeOffer {
		return "", "", fmt.Errorf("unexpected DHCP message type: %s", msg.Type)
	}
	if msg.IP == "" || msg.SubnetMask == "" {
		return "", "", fmt.Errorf("DHCP OFFER缺少IP或子网掩码")
	}

	log.Printf("✅ 收到V-DHCP地址: %s/%s", msg.IP, msg.SubnetMask)
	return msg.IP, msg.SubnetMask, nil
}

// tunToPacketQueue TUN -> packet queue
func tunToPacketQueue(dev tun.Device) {

	log.Printf("▶ 启动：TUN → Queue")

	for {
		packets, err := readFromTun(dev, Conf.Common.MTU)
		if err != nil {
			log.Printf("TUN读取失败: %v", err)
			return
		}

		for _, pkt := range packets {
			select {
			case tunPacketChan <- pkt:
			default:
				log.Printf("TUN发送队列已满，丢弃IP包: %d bytes", len(pkt))
			}
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
		err = writeToTun(dev, pkt)
		if err != nil {
			log.Printf("TUN写入失败: %v", err)
			return
		}
	}
}
