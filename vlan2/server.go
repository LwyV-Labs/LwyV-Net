package vlan2

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/conf2"
	"github.com/LwyV-Labs/LwyV-Net/securetcp"
	"github.com/LwyV-Labs/LwyV-Net/tunSetup"
	"github.com/LwyV-Labs/LwyV-Net/vdhcp2"
	"github.com/LwyV-Labs/LwyV-Net/vlan"
	"golang.org/x/net/ipv4"
)

type ClientPeer struct {
	stats         vlan.TrafficCounter
	conn          *securetcp.Conn
	mu            sync.Mutex
	peerPublicKey string
	deviceID      string
	virtualIP     string
	sendQueue     chan []byte
	sendDone      chan struct{}
	sendCloseOnce sync.Once
}

type PeerTrafficInfo struct {
	DeviceID      string
	VirtualIP     string
	RemoteAddr    string
	UploadBytes   uint64
	DownloadBytes uint64
	UploadBps     float64
	DownloadBps   float64
}

type KcpClient struct {
	sync.RWMutex
	m map[string]*ClientPeer
}

type Server struct {
	clientTable *KcpClient

	secureSrv *securetcp.Server
	cancel    context.CancelFunc

	tun *tunSetup.TUNTunnel

	dhcp     *vdhcp2.Manager
	dhcpMask string

	conf conf2.ServerConfig

	stop atomic.Bool
}

const (
	// 服务端每个客户端连接的下行发送队列大小。
	// 把“路由决策/读TUN”与“实际网络写入”解耦，避免写阻塞导致周期性卡顿。
	serverPeerSendQueueSize = 16 * 1024

	serverLeaseTTL     = 24 * time.Hour
	serverOfflineGrace = 5 * time.Minute
)

func NewServer(conf conf2.ServerConfig) *Server {
	server := &Server{
		conf:        conf,
		clientTable: &KcpClient{m: make(map[string]*ClientPeer)},
	}
	return server
}

func (s *Server) Start() {
	var err error

	// 1) 初始化地址池（vDHCP）。
	manager, err := vdhcp2.NewManager(vdhcp2.ManagerConfig{
		StartIP:      s.conf.VDHCP.StartIP,
		EndIP:        s.conf.VDHCP.EndIP,
		SubnetMask:   s.conf.VDHCP.SubnetMask,
		Gateway:      s.conf.VDHCP.Gateway,
		MTU:          s.conf.MTU,
		LeaseTTL:     serverLeaseTTL,
		OfflineGrace: serverOfflineGrace,
	})
	if err != nil {
		log.Fatalf("初始化虚拟DHCP失败: %v", err)
	}
	s.dhcp = manager
	s.dhcpMask = s.conf.VDHCP.SubnetMask
	log.Printf("✅ 虚拟DHCP已启用: %s - %s", s.conf.VDHCP.StartIP, s.conf.VDHCP.EndIP)

	// 定时清理断线超时且没有重连的租约。
	go s.sweepDHCPLeases()

	// 2) 如开启代理则初始化服务端网关/NAT。
	if s.conf.Proxy {
		if s.tun, err = tunSetup.NewTUNTunnel(s.conf.IfName, s.conf.MTU); err != nil {
			log.Fatalf("创建服务端TUN失败: %v", err)
		}
		if err = tunSetup.ConfigureTunAddress(s.conf.IfName, s.conf.VDHCP.Gateway, s.conf.VDHCP.SubnetMask); err != nil {
			log.Fatalf("配置服务端TUN地址失败: %v", err)
		}
		if err = tunSetup.EnableServerGatewayNAT(s.conf.IfName, s.conf.VDHCP.Gateway, s.conf.VDHCP.SubnetMask); err != nil {
			log.Fatalf("配置服务端NAT失败: %v", err)
		}
		go s.tunToClients()
		log.Printf("✅ 服务端网关已启用: if=%s gw=%s/%s", s.conf.IfName, s.conf.VDHCP.Gateway, s.conf.VDHCP.SubnetMask)
	}

	// 3) 启动 securetcp 服务端。
	// 注意：这里假设 s.conf.Identity.Private 已经是 securetcp 需要的 base64 X25519 私钥。
	// 如果你的配置字段名字不是这个，改成你自己的服务端长期私钥字段即可。
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	srv, err := securetcp.NewServer(securetcp.ServerConfig{
		Address:             fmt.Sprintf(":%d", s.conf.Port),
		ServerPrivateKeyB64: s.conf.PrivateKey,
		CommonConfig: securetcp.CommonConfig{
			ReadTimeout:     60 * time.Second,
			WriteTimeout:    15 * time.Second,
			HeartbeatBase:   10 * time.Second,
			HeartbeatJitter: 5 * time.Second,
			RekeyInterval:   45 * time.Second,
			OldKeyGrace:     30 * time.Second,
		},
	})
	if err != nil {
		log.Fatalf("初始化 securetcp 服务端失败: %v", err)
	}
	s.secureSrv = srv

	log.Printf("✅ securetcp 服务端启动成功，监听 :%d", s.conf.Port)
	log.Println("📝 等待客户端连接并转发IP包...")

	if err = srv.ListenAndServe(ctx, s.handleClient); err != nil && !s.stop.Load() {
		log.Printf("securetcp 服务端退出: %v", err)
	}
}

func (s *Server) Stop() {
	s.stop.Store(true)

	if s.cancel != nil {
		s.cancel()
	}
	if s.secureSrv != nil {
		if err := s.secureSrv.Close(); err != nil {
			log.Printf("关闭 securetcp 服务端失败: %v", err)
		}
		s.secureSrv = nil
	}

	if s.conf.Proxy {
		tunSetup.DisableServerGatewayNAT()
	}

	// 关闭所有客户端连接。
	s.clientTable.Lock()
	for _, peer := range s.clientTable.m {
		peer.sendCloseOnce.Do(func() {
			close(peer.sendDone)
		})
		_ = peer.conn.Close()
	}
	s.clientTable.Unlock()

	// 关闭服务端 TUN。优先关闭 TUNTunnel，让内部读写 goroutine 一起退出。
	if s.tun != nil {
		if err := s.tun.Close(); err != nil {
			log.Printf("关闭服务端TUN失败: %v", err)
		}
		s.tun = nil
	}

	log.Printf("服务端已停止")
}

func (s *Server) handleClient(conn *securetcp.Conn) {
	clientID := conn.PeerStaticPublicKeyB64()
	peer := &ClientPeer{
		conn:          conn,
		peerPublicKey: clientID,
		deviceID:      clientID,
		sendQueue:     make(chan []byte, serverPeerSendQueueSize),
		sendDone:      make(chan struct{}),
	}

	go s.peerSendLoop(peer)
	defer s.cleanupClientPeer(peer)

	log.Printf("客户端认证成功 remote=%s clientID=%s", conn.RemoteAddr(), shortID(clientID))

	for {
		raw, err := conn.Read(context.Background())
		if err != nil {
			return
		}

		typ, payload, err := Unpack(raw)
		if err != nil {
			log.Printf("解析应用层数据失败: remote=%s err=%v", conn.RemoteAddr(), err)
			return
		}

		switch typ {
		case TypeVDHCP:
			s.handleVDHCP(peer, payload)
		case TypeIP:
			s.handleIP(peer, payload)
		default:
			log.Printf("未知应用层类型: %d", typ)
			return
		}
	}
}

func (s *Server) peerSendLoop(peer *ClientPeer) {
	for {
		select {
		case <-peer.sendDone:
			return
		case pkt := <-peer.sendQueue:
			payload := Pack(TypeIP, pkt)

			peer.mu.Lock()
			err := peer.conn.Write(payload)
			peer.mu.Unlock()

			if err != nil {
				return
			}
			peer.stats.AddUpload(len(pkt))
		}
	}
}

func (s *Server) cleanupClientPeer(peer *ClientPeer) {
	peer.sendCloseOnce.Do(func() {
		close(peer.sendDone)
	})

	// 连接结束时，只删除当前 peer 自己占用的路由项。
	// 注意：如果同一个 clientID 已经重连并替换了路由项，这里不能误删新连接。
	if peer.virtualIP != "" {
		s.clientTable.Lock()
		if current := s.clientTable.m[peer.virtualIP]; current == peer {
			delete(s.clientTable.m, peer.virtualIP)
		}
		s.clientTable.Unlock()
	}

	// 不要立即 Release；给 AutoReconnect 留一个 grace window。
	if s.dhcp != nil && peer.peerPublicKey != "" {
		s.dhcp.MarkOffline(peer.peerPublicKey)
	}

	log.Printf("客户端断开: clientID=%s ip=%s", shortID(peer.peerPublicKey), peer.virtualIP)
	_ = peer.conn.Close()
}

func (s *Server) handleVDHCP(peer *ClientPeer, pkt []byte) {
	if s.dhcp == nil {
		return
	}

	msg, err := vdhcp2.DecodeMessage(pkt)
	if err != nil {
		log.Printf("无效 VDHCP 消息: client=%s err=%v", shortID(peer.peerPublicKey), err)
		return
	}

	switch msg.Type {
	case vdhcp2.MessageTypeDiscover:
		s.handleDHCPDiscover(peer, msg)
	default:
		log.Printf("暂不支持的 VDHCP 类型: client=%s type=%s", shortID(peer.peerPublicKey), msg.Type)
	}
}

func (s *Server) handleDHCPDiscover(peer *ClientPeer, msg vdhcp2.Message) {
	lease, err := s.dhcp.Acquire(peer.peerPublicKey)
	if err != nil {
		nak, _ := vdhcp2.EncodeNak(msg.RequestID, err.Error())
		peer.mu.Lock()
		_ = peer.conn.Write(Pack(TypeVDHCP, nak))
		peer.mu.Unlock()
		return
	}

	offer, err := vdhcp2.EncodeOffer(
		msg.RequestID,
		lease.IP,
		s.dhcpMask,
		s.conf.VDHCP.Gateway,
		serverLeaseTTL,
	)
	if err != nil {
		return
	}

	peer.mu.Lock()
	err = peer.conn.Write(Pack(TypeVDHCP, offer))
	peer.mu.Unlock()
	if err != nil {
		return
	}

	peer.virtualIP = lease.IP

	// 注册“虚拟IP -> 连接”的路由映射。
	// 如果同一个长期身份重连，通常会拿到同一个 IP，这里用新连接替换旧连接。
	var oldPeer *ClientPeer
	s.clientTable.Lock()
	oldPeer = s.clientTable.m[lease.IP]
	s.clientTable.m[lease.IP] = peer
	s.clientTable.Unlock()

	if oldPeer != nil && oldPeer != peer {
		_ = oldPeer.conn.Close()
	}

	log.Printf("DHCP分配成功: client=%s ip=%s", shortID(peer.peerPublicKey), lease.IP)
}

func (s *Server) handleIP(peer *ClientPeer, pkt []byte) {
	peer.stats.AddDownload(len(pkt))

	ipHdr, err := ipv4.ParseHeader(pkt)
	if err != nil {
		return
	}

	// 基本校验：源地址必须等于该 peer 分配到的虚拟地址，防止伪造。
	if peer.virtualIP == "" ||
		ipHdr.Src.String() != peer.virtualIP ||
		vlan.IsBroadcast(ipHdr.Dst) ||
		vlan.IsMulticast(ipHdr.Dst) ||
		vlan.IsSubnetBroadcast(ipHdr.Dst, s.conf.VDHCP.Gateway, s.conf.VDHCP.SubnetMask) {
		return
	}

	s.clientTable.RLock()
	targetPeer, exists := s.clientTable.m[ipHdr.Dst.String()]
	s.clientTable.RUnlock()

	// 目标是虚拟网内其他客户端，直接转发。
	if exists {
		_ = s.enqueuePeerPacket(targetPeer, pkt)
		return
	}

	// 目标不是虚拟网内客户端，如果服务端启用了代理/TUN，就写入服务端 TUN。
	if s.tun != nil {
		_ = s.tun.Write(pkt)
	}
}

func (s *Server) enqueuePeerPacket(peer *ClientPeer, pkt []byte) error {
	buf := make([]byte, len(pkt))
	copy(buf, pkt)

	select {
	case <-peer.sendDone:
		return fmt.Errorf("peer sender closed")
	case peer.sendQueue <- buf:
		return nil
	}
}

func (s *Server) tunToClients() {
	if s.tun == nil {
		return
	}

	// 从服务端网关 TUN 读到的数据，按目标 IP 发回对应客户端。
	for pkt := range s.tun.ReadChan() {
		ipHdr, err := ipv4.ParseHeader(pkt)
		if err != nil {
			continue
		}

		s.clientTable.RLock()
		targetPeer, exists := s.clientTable.m[ipHdr.Dst.String()]
		s.clientTable.RUnlock()
		if !exists {
			continue
		}
		_ = s.enqueuePeerPacket(targetPeer, pkt)
	}
}

func (s *Server) sweepDHCPLeases() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for !s.stop.Load() {
		<-ticker.C
		if s.stop.Load() {
			return
		}
		if s.dhcp != nil {
			s.dhcp.SweepExpired()
		}
	}
}

func (s *Server) GetTrafficStatsByIP(virtualIP string) (vlan.TrafficStats, bool) {
	s.clientTable.RLock()
	peer, ok := s.clientTable.m[virtualIP]
	s.clientTable.RUnlock()
	if !ok {
		return vlan.TrafficStats{}, false
	}
	return peer.stats.Snapshot(), true
}

func (s *Server) GetTrafficStatsByDeviceID(deviceID string) (vlan.TrafficStats, bool) {
	s.clientTable.RLock()
	defer s.clientTable.RUnlock()
	for _, peer := range s.clientTable.m {
		if peer.deviceID == deviceID || peer.peerPublicKey == deviceID {
			return peer.stats.Snapshot(), true
		}
	}
	return vlan.TrafficStats{}, false
}

func (s *Server) ListPeerTraffic() []PeerTrafficInfo {
	s.clientTable.RLock()
	defer s.clientTable.RUnlock()

	peers := make([]PeerTrafficInfo, 0, len(s.clientTable.m))
	for _, peer := range s.clientTable.m {
		stats := peer.stats.Snapshot()
		remoteAddr := ""
		if peer.conn != nil && peer.conn.RemoteAddr() != nil {
			remoteAddr = peer.conn.RemoteAddr().String()
		}
		peers = append(peers, PeerTrafficInfo{
			DeviceID:      peer.deviceID,
			VirtualIP:     peer.virtualIP,
			RemoteAddr:    remoteAddr,
			UploadBytes:   stats.UploadBytes,
			DownloadBytes: stats.DownloadBytes,
			UploadBps:     stats.UploadBps,
			DownloadBps:   stats.DownloadBps,
		})
	}
	return peers
}

func shortID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
