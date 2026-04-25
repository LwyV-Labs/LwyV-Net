package vlan

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"NetworkSetup/vdhcp"

	"github.com/google/uuid"
	kcp "github.com/xtaci/kcp-go/v5"
	"golang.zx2c4.com/wireguard/tun"
)

type ClientPeer struct {
	conn      net.Conn
	mu        sync.Mutex
	clientID  string
	virtualIP string
}
type KcpClient struct {
	sync.RWMutex
	m map[string]*ClientPeer
}

// 客户端路由表：key=虚拟IP，value=客户端连接对象
var clientKcpTable = &KcpClient{m: make(map[string]*ClientPeer)}

var (
	serverTunDev   tun.Device
	serverTunMu    sync.Mutex
	serverDHCP     *vdhcp.Manager
	serverDHCPMask string
)

func StartServer() {
	if err := initServerVDHCP(); err != nil {
		log.Fatalf("初始化虚拟DHCP失败: %v", err)
	}

	if err := initServerGateway(); err != nil {
		log.Fatalf("初始化服务端网关失败: %v", err)
	}

	installServerCleanupSignal()

	if Conf.Common.Mode == "TCP" {
		startTCPServer()
	} else if Conf.Common.Mode == "KCP" {
		startKCPServer()
	} else if Conf.Common.Mode == "ALL" {
		go startTCPServer()
		startKCPServer()
	} else {
		log.Fatalf("{%s}不支持类型", Conf.Common.Mode)
	}
}

func installServerCleanupSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-ch
		log.Println("收到退出信号，开始清理服务端网关...")

		shutdownServerGateway()

		os.Exit(0)
	}()
}

func initServerVDHCP() error {

	manager, err := vdhcp.NewManager(Conf.VDHCP.StartIP, Conf.VDHCP.EndIP)
	if err != nil {
		return err
	}

	serverDHCP = manager
	serverDHCPMask = Conf.Common.SubnetMask

	log.Printf("✅ 虚拟DHCP已启用: %s - %s", Conf.VDHCP.StartIP, Conf.VDHCP.EndIP)
	return nil
}

func initServerGateway() error {
	if !Conf.Common.Proxy {
		return nil
	}

	ifName := Conf.Server.IfName
	if ifName == "" {
		ifName = "LwyV-Gateway"
	}

	mask := Conf.Common.SubnetMask

	dev, err := createTun(ifName, Conf.Common.MTU)
	if err != nil {
		return fmt.Errorf("创建服务端TUN失败: %w", err)
	}

	if err = configureTunAddress(ifName, Conf.Common.Gateway, mask); err != nil {
		_ = dev.Close()
		return fmt.Errorf("配置服务端TUN地址失败: %w", err)
	}

	if err = enableServerGatewayNAT(ifName, Conf.Common.Gateway, mask, Conf.Server.EgressIf); err != nil {
		_ = dev.Close()
		return fmt.Errorf("配置服务端NAT失败: %w", err)
	}

	serverTunDev = dev
	go tunToClients(dev)
	log.Printf("✅ 服务端网关已启用: if=%s gw=%s/%s", ifName, Conf.Common.Gateway, mask)
	return nil
}

func startTCPServer() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", Conf.Server.Port))
	if err != nil {
		log.Fatalf("服务端启动失败: %v", err)
	}
	defer listener.Close()

	log.Printf("✅ TCP 服务端启动成功，监听 :%d", Conf.Server.Port)
	log.Println("📝 等待客户端连接并转发IP包...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		go handleClient(conn)
	}
}

func startKCPServer() {
	block, err := kcp.NewAESGCMCrypt(Conf.Common.Key)
	if err != nil {
		log.Fatalf("KCP AES-GCM 初始化失败: %v", err)
	}
	listener, err := kcp.ListenWithOptions(fmt.Sprintf(":%d", Conf.Server.Port), block, 0, 0)
	if err != nil {
		log.Fatalf("KCP服务端启动失败: %v", err)
	}
	defer listener.Close()

	log.Printf("✅ KCP 服务端启动成功，监听UDP :%d", Conf.Server.Port)
	log.Println("📝 等待客户端连接并转发IP包...")

	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			log.Printf("📝 接受连接失败: %v", err)
			continue
		}
		setupKCPSession(conn)
		go handleClient(conn)
	}
}

// 处理单个用户连接
func handleClient(conn net.Conn) {
	peer := &ClientPeer{
		conn:     conn,
		clientID: uuid.NewString(),
	}

	defer cleanupClientPeer(peer)

	log.Printf("🔌 新客户端连接: %s", conn.RemoteAddr().String())

	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

		frame, err := readFrame(conn, Conf.Common.MTU)
		if err != nil {
			log.Printf("客户端断开连接: %s, 错误: %v", conn.RemoteAddr().String(), err)
			return
		}
		//log.Printf("📦 收到帧: type=%d len=%d from=%s", frame.Type, len(frame.IPPacket), conn.RemoteAddr().String())

		switch frame.Type {
		case PacketTypePing:
			if !handlePingPacket(peer) {
				return
			}

		case PacketTypeVDHCP:
			handleVDHCPPacket(peer, frame.IPPacket)

		case PacketTypeIP:
			handleIPPacket(peer, frame.IPPacket)

		default:
			log.Printf("忽略未知报文类型: %d", frame.Type)
		}
	}
}

// 清理连接
func cleanupClientPeer(peer *ClientPeer) {
	clientKcpTable.Lock()
	for ip, p := range clientKcpTable.m {
		if p == peer {
			delete(clientKcpTable.m, ip)
			log.Printf("🗑️ 清理客户端路由: %s", ip)
		}
	}
	clientKcpTable.Unlock()

	if serverDHCP != nil && peer.clientID != "" {
		serverDHCP.Release(peer.clientID)
		log.Printf("🧹 回收虚拟DHCP租约: clientID=%s", peer.clientID)
	}

	if err := peer.conn.Close(); err != nil {
		log.Printf("🔌 客户端关闭失败: %v", err)
		return
	}

	log.Printf("🔌 客户端已断开: %s", peer.conn.RemoteAddr().String())
}

// 处理Ping报文
func handlePingPacket(peer *ClientPeer) bool {
	peer.mu.Lock()
	defer peer.mu.Unlock()

	_ = peer.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	if err := writeFrame(peer.conn, PacketTypePong, nil); err != nil {
		log.Printf("PONG发送失败: %v", err)
		return false
	}

	return true
}

// 处理VDHCP请求ip报文
func handleVDHCPPacket(peer *ClientPeer, pkt []byte) bool {
	if serverDHCP == nil {
		log.Printf("忽略vdhcp报文: serverDHCP未启用")
		return false
	}

	msg, err := vdhcp.DecodeMessage(pkt)
	if err != nil {
		log.Printf("忽略非法vdhcp报文: %v", err)
		return false
	}

	if msg.Type != vdhcp.MessageTypeDiscover {
		log.Printf("忽略非Discover的vdhcp报文: %v", msg.Type)
		return false
	}

	ip, err := serverDHCP.Allocate(peer.clientID)
	if err != nil {
		nak, _ := vdhcp.EncodeNak(err.Error())

		peer.mu.Lock()
		_ = peer.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = writeFrame(peer.conn, PacketTypeVDHCP, nak)
		peer.mu.Unlock()

		log.Printf("❌ vdhcp分配失败 [%s]: %v", peer.clientID, err)
		return true
	}

	offer, err := vdhcp.EncodeOffer(ip, serverDHCPMask, Conf.Common.Gateway)
	if err != nil {
		log.Printf("❌ vdhcp响应编码失败 [%s]: %v", peer.clientID, err)
		return true
	}

	peer.mu.Lock()
	_ = peer.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = writeFrame(peer.conn, PacketTypeVDHCP, offer)
	peer.mu.Unlock()

	if err != nil {
		log.Printf("❌ vdhcp响应发送失败 [%s]: %v", peer.clientID, err)
		return true
	}

	peer.virtualIP = ip

	clientKcpTable.Lock()
	clientKcpTable.m[ip] = peer
	clientKcpTable.Unlock()

	log.Printf("✅ vdhcp分配成功: clientID=%s ip=%s mask=%s", peer.clientID, ip, serverDHCPMask)

	return true
}

// 处理转发一般IP报文
func handleIPPacket(peer *ClientPeer, pkt []byte) {
	heardInfo, err := headerParsing(pkt)
	if err != nil {
		log.Printf("包头解析错误，丢弃：%v", err)
		return
	}

	if peer.virtualIP == "" {
		log.Printf("丢弃未分配虚拟IP客户端的报文: claimed=%s", heardInfo.SrcIP)
		return
	}

	// DHCP分配ip后防止伪造源IP
	if heardInfo.SrcIP != peer.virtualIP {
		log.Printf("丢弃伪造源IP包: real=%s claimed=%s", peer.virtualIP, heardInfo.SrcIP)
		return
	}

	//log.Printf(
	//	"📥 收到IP包 | 类型:%s | 来源:%s | 目标:%s | 真实地址:%s | 大小:%d",
	//	heardInfo.ProtoName,
	//	heardInfo.SrcIP,
	//	heardInfo.DstIP,
	//	peer.conn.RemoteAddr().String(),
	//	len(pkt),
	//)

	// 广播/组播
	if heardInfo.IsBroadcast {
		broadcastPacket(&heardInfo, pkt)
		return
	}

	// 单播：优先查虚拟客户端路由
	clientKcpTable.RLock()
	targetPeer, exists := clientKcpTable.m[heardInfo.DstIP]
	clientKcpTable.RUnlock()

	if !exists {
		handleOutboundPacket(&heardInfo, pkt)
		return
	}

	forwardPacketToPeer(targetPeer, heardInfo.DstIP, pkt)
}

// 向外网转发流量
func handleOutboundPacket(heardInfo *IPHeaderInfo, pkt []byte) {
	if err := writeToServerTun(pkt); err != nil {
		log.Printf("⚠️ 外网转发失败(写入服务端TUN): %v", err)
		return
	}

	log.Printf("🌍 外网转发: %s -> %s", heardInfo.SrcIP, heardInfo.DstIP)
}

// 客户端转发
func forwardPacketToPeer(targetPeer *ClientPeer, dstIP string, pkt []byte) {
	targetPeer.mu.Lock()
	err := writeFrame(targetPeer.conn, PacketTypeIP, pkt)
	targetPeer.mu.Unlock()

	if err != nil {
		log.Printf("转发失败 [%s]: %v", dstIP, err)
		return
	}

	log.Printf("✅ 成功转发至: %s", dstIP)
}

func writeToServerTun(pkt []byte) error {
	serverTunMu.Lock()
	defer serverTunMu.Unlock()

	if serverTunDev == nil {
		return fmt.Errorf("server TUN is not enabled")
	}

	return writeToTun(serverTunDev, pkt)
}

func tunToClients(dev tun.Device) {

	log.Printf("▶ 启动：Server TUN -> Client")

	for {
		packets, err := readFromTun(dev, Conf.Common.MTU)
		if err != nil {
			log.Printf("服务端TUN读取失败: %v", err)
			return
		}

		for _, pkt := range packets {
			heardInfo, err := headerParsing(pkt)
			if err != nil {
				log.Printf("服务端TUN回包解析失败: %v, len=%d", err, len(pkt))
				continue
			}

			log.Printf("📤 服务端TUN回包 | 类型:%s | 来源:%s | 目标:%s | 大小:%d",
				heardInfo.ProtoName, heardInfo.SrcIP, heardInfo.DstIP, len(pkt))

			clientKcpTable.RLock()
			targetPeer, exists := clientKcpTable.m[heardInfo.DstIP]
			clientKcpTable.RUnlock()
			if !exists {
				log.Printf("⚠️ 回包目标未注册: %s", heardInfo.DstIP)
				continue
			}

			targetPeer.mu.Lock()
			err = writeFrame(targetPeer.conn, PacketTypeIP, pkt)
			targetPeer.mu.Unlock()
			if err != nil {
				log.Printf("服务端TUN回包转发失败 [%s]: %v", heardInfo.DstIP, err)
				continue
			}

			log.Printf("✅ 外网回包已转发至: %s", heardInfo.DstIP)
		}
	}
}
