package vlan

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/LwyV-Labs/LwyV-Net/config"
	"github.com/LwyV-Labs/LwyV-Net/secure"
	"github.com/LwyV-Labs/LwyV-Net/tunSetup"
	"github.com/LwyV-Labs/LwyV-Net/vdhcp"
)

type ClientPeer struct {
	stats         trafficCounter
	conn          net.Conn
	mu            sync.Mutex
	peerPublicKey string
	deviceID      string
	virtualIP     string
	allowedIPs    []net.IPNet
	sessionMgr    *secure.SessionManager
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

	listener net.Listener

	tun *tunSetup.TUNTunnel

	dhcp     *vdhcp.Manager
	dhcpMask string
	keyID    atomic.Uint32

	stop atomic.Bool
}

const (
	// 服务端每个客户端连接的下行发送队列大小。
	// 把“路由决策/读TUN”与“实际网络写入”解耦，避免写阻塞导致周期性卡顿。
	serverPeerSendQueueSize = 16 * 1024
)

func NewServer(confs config.Config) *Server {
	conf = confs
	return &Server{clientTable: &KcpClient{m: make(map[string]*ClientPeer)}}
}

func (s *Server) Start() {
	// 1 初始化地址池（vDHCP）
	manager, err := vdhcp.NewManager(conf.VDHCP.StartIP, conf.VDHCP.EndIP)
	if err != nil {
		log.Fatalf("初始化虚拟DHCP失败: %v", err)
	}
	s.dhcp = manager
	s.dhcpMask = conf.Common.SubnetMask
	log.Printf("✅ 虚拟DHCP已启用: %s - %s", conf.VDHCP.StartIP, conf.VDHCP.EndIP)

	// 2 如开启代理则初始化服务端网关/NAT
	if conf.Common.Proxy {
		if s.tun, err = tunSetup.NewTUNTunnel(conf.Server.IfName, conf.Common.MTU); err != nil {
			log.Fatalf("创建服务端TUN失败: %V", err)
		}
		if err = tunSetup.ConfigureTunAddress(conf.Server.IfName, conf.Common.Gateway, conf.Common.SubnetMask); err != nil {
			log.Fatalf("配置服务端TUN地址失败: %V", err)
		}
		if err = tunSetup.EnableServerGatewayNAT(conf.Server.IfName, conf.Common.Gateway, conf.Common.SubnetMask, conf.Server.EgressIf); err != nil {
			log.Fatalf("配置服务端NAT失败: %V", err)
		}
	}
	// 启动下行分发：服务端 TUN -> 对应客户端。
	go s.tunToClients()
	log.Printf("✅ 服务端网关已启用: if=%s gw=%s/%s", conf.Server.IfName, conf.Common.Gateway, conf.Common.SubnetMask)

	// 3) 启动 KCP 监听
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", conf.Server.Port))
	if err != nil {
		log.Fatalf("服务端启动失败: %v", err)
	}

	log.Printf("✅ TCP 服务端启动成功，监听 :%d", conf.Server.Port)
	log.Println("📝 等待客户端连接并转发IP包...")

	for !s.stop.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.stop.Load() {
				return
			}
			log.Printf("接受连接失败: %v", err)
			continue
		}
		go s.handleClient(conn)
	}
}

func (s *Server) Stop() {
	s.stop.Store(true)
	tunSetup.DisableServerGatewayNAT()

	// 关闭监听器，让 Accept() 退出
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			log.Printf("关闭服务端监听失败: %v", err)
		}
		s.listener = nil
	}

	// 关闭所有客户端连接
	s.clientTable.Lock()
	for _, peer := range s.clientTable.m {
		// 给发送队列发出信号
		peer.sendCloseOnce.Do(func() {
			close(peer.sendDone)
		})
		// 关闭连接
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

func (s *Server) handleClient(conn net.Conn) {
	// 一个连接对应一个 peer，上面维护其会话和分配到的虚拟 IP。
	peer := &ClientPeer{
		conn:       conn,
		sessionMgr: &secure.SessionManager{},
		sendQueue:  make(chan []byte, serverPeerSendQueueSize),
		sendDone:   make(chan struct{}),
	}
	go s.peerSendLoop(peer)
	defer s.cleanupClientPeer(peer)

	if err := s.performHandshake(peer, nil); err != nil {
		log.Printf("客户端首次认证失败 remote=%s err=%v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("客户端认证成功 remote=%s device=%s", conn.RemoteAddr(), peer.deviceID)

	for {
		frame, err := readFrame(conn, maxFramePayload(), defaultReadFrameTimeout)
		if err != nil {
			return
		}
		switch frame.Type {
		case PacketTypePing:
			// 客户端保活包。
			if !s.handlePing(peer) {
				return
			}
		case PacketTypeSecure:
			// 业务密文帧。
			s.handleSecurePacket(peer, frame.IPPacket)
		case PacketTypeHandshakeInit:
			// 支持连接内重握手（密钥轮转）。
			if err := s.performHandshake(peer, frame.IPPacket); err != nil {
				log.Printf("客户端重认证失败 remote=%s device=%s err=%v", conn.RemoteAddr(), peer.deviceID, err)
				return
			}
			log.Printf("客户端重认证成功 remote=%s device=%s", conn.RemoteAddr(), peer.deviceID)
		default:
			log.Printf("handleClient收到处理未识别类型")
		}
	}
}

func (s *Server) peerSendLoop(peer *ClientPeer) {
	for {
		select {
		case <-peer.sendDone:
			return
		case pkt := <-peer.sendQueue:
			peer.mu.Lock()
			err := writeSecureFrame(peer.conn, peer.sessionMgr, PacketTypeIP, pkt)
			peer.mu.Unlock()
			if err != nil {
				return
			}
			peer.stats.addUpload(len(pkt))
		}
	}
}

func (s *Server) cleanupClientPeer(peer *ClientPeer) {
	peer.sendCloseOnce.Do(func() {
		close(peer.sendDone)
	})
	// 连接结束时，需要从路由表和 DHCP 租约中清理。
	s.clientTable.Lock()
	for ip, p := range s.clientTable.m {
		if p == peer {
			delete(s.clientTable.m, ip)
		}
	}
	s.clientTable.Unlock()
	if s.dhcp != nil && peer.peerPublicKey != "" {
		s.dhcp.Release(peer.peerPublicKey)
	}
	log.Printf("客户端断开: device=%s ip=%s", peer.deviceID, peer.virtualIP)
	_ = peer.conn.Close()
}

func (s *Server) performHandshake(peer *ClientPeer, initMsg []byte) error {
	// 服务端作为响应方（Responder）完成握手，并拿到对端公钥。
	if len(conf.Common.Identity.Private) == 0 {
		return fmt.Errorf("common.privateKey is required")
	}
	hs := secure.NewHandshaker(conf.Common.Identity, nil)
	keyID := s.keyID.Add(1)
	log.Printf("开始处理客户端认证: remote=%s localKeyID=%d", peer.conn.RemoteAddr(), keyID)
	session, remotePub, err := hs.ResponderHandshake(
		func(msg []byte) error { return writeFrame(peer.conn, PacketTypeHandshakeResp, msg) },
		func() ([]byte, error) {
			if len(initMsg) > 0 {
				msg := initMsg
				initMsg = nil
				return msg, nil
			}
			frame, err := readFrame(peer.conn, maxFramePayload(), defaultReadFrameTimeout)
			if err != nil {
				return nil, err
			}
			if frame.Type != PacketTypeHandshakeInit {
				return nil, fmt.Errorf("unexpected handshake frame type=%d", frame.Type)
			}
			return frame.IPPacket, nil
		},
		keyID,
	)
	if err != nil {
		log.Printf("客户端认证失败: remote=%s localKeyID=%d err=%v", peer.conn.RemoteAddr(), keyID, err)
		return err
	}
	if !config.IsPeerStaticAllowed(remotePub) {
		return fmt.Errorf("peer public key not allowed")
	}
	peer.peerPublicKey = base64.StdEncoding.EncodeToString(remotePub)
	peer.deviceID = secure.DeviceIDFromPublicKey(remotePub)
	// 用新会话替换旧会话，实现平滑轮转。
	peer.sessionMgr.Rotate(session)
	log.Printf("客户端认证通过: remote=%s device=%s", peer.conn.RemoteAddr(), peer.deviceID)
	return nil
}

func (s *Server) handlePing(peer *ClientPeer) bool {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	return writeFrame(peer.conn, PacketTypePong, nil) == nil
}

func (s *Server) handleSecurePacket(peer *ClientPeer, pkt []byte) {
	// 先解密外层 secure 帧，再看内层业务类型。
	innerType, plain, err := peer.sessionMgr.Decrypt(pkt)
	if err != nil {
		log.Printf("解密数据失败: device=%s err=%v", peer.deviceID, err)
		return
	}
	switch PacketType(innerType) {
	case PacketTypeVDHCP:
		s.handleVDHCP(peer, plain)
	case PacketTypeIP:
		s.handleIP(peer, plain)
	default:
		log.Printf("handleSecurePacket收到处理未识别类型")
	}
}

func (s *Server) handleVDHCP(peer *ClientPeer, pkt []byte) {
	if s.dhcp == nil {
		return
	}
	msg, err := vdhcp.DecodeMessage(pkt)
	if err != nil || msg.Type != vdhcp.MessageTypeDiscover {
		log.Printf("无效DHCP Discover: device=%s err=%v type=%s", peer.deviceID, err, msg.Type)
		return
	}
	ip, err := s.dhcp.Allocate(peer.peerPublicKey)
	if err != nil {
		// 地址池耗尽时返回 NAK。
		nak, _ := vdhcp.EncodeNak(err.Error())
		peer.mu.Lock()
		_ = writeSecureFrame(peer.conn, peer.sessionMgr, PacketTypeVDHCP, nak)
		peer.mu.Unlock()
		return
	}
	offer, err := vdhcp.EncodeOffer(ip, s.dhcpMask, conf.Common.Gateway)
	if err != nil {
		return
	}
	peer.mu.Lock()
	err = writeSecureFrame(peer.conn, peer.sessionMgr, PacketTypeVDHCP, offer)
	peer.mu.Unlock()
	if err != nil {
		return
	}
	peer.virtualIP = ip
	log.Printf("DHCP分配成功: device=%s ip=%s", peer.deviceID, ip)
	// 注册“虚拟IP -> 连接”的路由映射。
	s.clientTable.Lock()
	s.clientTable.m[ip] = peer
	s.clientTable.Unlock()
}

func (s *Server) handleIP(peer *ClientPeer, pkt []byte) {
	peer.stats.addDownload(len(pkt))
	heardInfo, err := headerParsing(pkt)
	// 基本校验：源地址必须等于该 peer 分配到的虚拟地址，防止伪造。
	if err != nil || peer.virtualIP == "" || heardInfo.SrcIP != peer.virtualIP || heardInfo.IsBroadcast {
		return
	}

	s.clientTable.RLock()
	targetPeer, exists := s.clientTable.m[heardInfo.DstIP]
	s.clientTable.RUnlock()
	// 如果存在就转发
	if exists {
		_ = s.enqueuePeerPacket(targetPeer, pkt)
		return
	}
	// 如果启动TUN了就代理
	if s.tun != nil {
		_ = s.tun.Write(pkt)
	}
}

func (s *Server) enqueuePeerPacket(peer *ClientPeer, pkt []byte) error {
	// 异步发送需要独立缓冲，避免上游切片被复用导致数据错乱。
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
	// 从服务端网关 TUN 读到的数据，按目标 IP 发回对应客户端。
	for pkt := range s.tun.ReadChan() {
		heardInfo, err := headerParsing(pkt)
		if err != nil {
			continue
		}
		s.clientTable.RLock()
		targetPeer, exists := s.clientTable.m[heardInfo.DstIP]
		s.clientTable.RUnlock()
		if !exists {
			continue
		}
		_ = s.enqueuePeerPacket(targetPeer, pkt)
	}
}

func (s *Server) GetTrafficStatsByIP(virtualIP string) (TrafficStats, bool) {
	s.clientTable.RLock()
	peer, ok := s.clientTable.m[virtualIP]
	s.clientTable.RUnlock()
	if !ok {
		return TrafficStats{}, false
	}
	return peer.stats.snapshot(), true
}

func (s *Server) GetTrafficStatsByDeviceID(deviceID string) (TrafficStats, bool) {
	s.clientTable.RLock()
	defer s.clientTable.RUnlock()
	for _, peer := range s.clientTable.m {
		if peer.deviceID == deviceID {
			return peer.stats.snapshot(), true
		}
	}
	return TrafficStats{}, false
}

func (s *Server) ListPeerTraffic() []PeerTrafficInfo {
	s.clientTable.RLock()
	defer s.clientTable.RUnlock()
	peers := make([]PeerTrafficInfo, 0, len(s.clientTable.m))
	for _, peer := range s.clientTable.m {
		stats := peer.stats.snapshot()
		peers = append(peers, PeerTrafficInfo{
			DeviceID:      peer.deviceID,
			VirtualIP:     peer.virtualIP,
			RemoteAddr:    peer.conn.RemoteAddr().String(),
			UploadBytes:   stats.UploadBytes,
			DownloadBytes: stats.DownloadBytes,
			UploadBps:     stats.UploadBps,
			DownloadBps:   stats.DownloadBps,
		})
	}
	return peers
}
