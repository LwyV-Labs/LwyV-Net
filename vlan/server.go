package vlan

import (
	"NetworkSetup/secure"
	"NetworkSetup/setup"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"NetworkSetup/vdhcp"

	"golang.zx2c4.com/wireguard/tun"
)

var (
	serverTunDev tun.Device
	serverTunMu  sync.Mutex
)

type ClientPeer struct {
	remote        *net.UDPAddr
	peerPublicKey string
	deviceID      string
	virtualIP     string
	allowedIPs    []net.IPNet
	session       *secure.SessionManager
	sendQueue     chan []byte
	sendDone      chan struct{}
	sendCloseOnce sync.Once
}

type PeerTable struct {
	sync.RWMutex
	m map[string]*ClientPeer
}

type Server struct {
	clientTable *PeerTable
	udpConn     *net.UDPConn
	tunDev      tun.Device
	tunMu       sync.Mutex
	dhcp        *vdhcp.Manager
	dhcpMask    string
	keyID       atomic.Uint32
}

const (
	// 服务端每个客户端连接的下行发送队列大小。
	// 把“路由决策/读TUN”与“实际网络写入”解耦，避免写阻塞导致周期性卡顿。
	serverPeerSendQueueSize = 4096
)

func NewServer() *Server {
	return &Server{clientTable: &PeerTable{m: make(map[string]*ClientPeer)}}
}

func StartServer() { NewServer().Start() }

func (s *Server) Start() {
	// 启动顺序：
	// 1) 初始化地址池（vDHCP）
	// 2) 如开启代理则初始化服务端网关/NAT
	// 3) 启动 UDP 监听
	if err := s.initVDHCP(); err != nil {
		log.Fatalf("初始化虚拟DHCP失败: %v", err)
	}
	if err := s.initGateway(); err != nil {
		log.Fatalf("初始化服务端网关失败: %v", err)
	}
	s.installCleanupSignal()

	s.startUDP()
}

func (s *Server) installCleanupSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		log.Println("收到退出信号，开始清理服务端网关...")
		ShutdownServerGateway()
		os.Exit(0)
	}()
}

func (s *Server) initVDHCP() error {
	manager, err := vdhcp.NewManager(Conf.VDHCP.StartIP, Conf.VDHCP.EndIP)
	if err != nil {
		return err
	}
	s.dhcp = manager
	s.dhcpMask = Conf.Common.SubnetMask
	log.Printf("✅ 虚拟DHCP已启用: %s - %s", Conf.VDHCP.StartIP, Conf.VDHCP.EndIP)
	return nil
}

func (s *Server) initGateway() error {
	// 只有在 proxy=true 时才需要服务端扮演“虚拟网关”。
	if !Conf.Common.Proxy {
		return nil
	}
	ifName := Conf.Server.IfName
	if ifName == "" {
		ifName = "LwyV-Gateway"
	}
	mask := Conf.Common.SubnetMask
	dev, err := setup.CreateTun(ifName, tunPayloadMTU())
	if err != nil {
		return fmt.Errorf("创建服务端TUN失败: %w", err)
	}

	if err = setup.ConfigureTunAddress(ifName, Conf.Common.Gateway, mask); err != nil {
		_ = dev.Close()
		return fmt.Errorf("配置服务端TUN地址失败: %w", err)
	}
	if err = setup.EnableServerGatewayNAT(ifName, Conf.Common.Gateway, mask, Conf.Server.EgressIf); err != nil {
		_ = dev.Close()
		return fmt.Errorf("配置服务端NAT失败: %w", err)
	}
	s.tunDev = dev
	serverTunMu.Lock()
	serverTunDev = dev
	serverTunMu.Unlock()
	// 启动下行分发：服务端 TUN -> 对应客户端。
	go s.tunToClients(dev)
	log.Printf("✅ 服务端网关已启用: if=%s gw=%s/%s", ifName, Conf.Common.Gateway, mask)
	return nil
}

func ShutdownServerGateway() {
	// 先回收 TUN 设备，再清理 NAT / FORWARD 规则，避免规则残留影响宿主机网络。
	serverTunMu.Lock()
	if serverTunDev != nil {
		_ = serverTunDev.Close()
		serverTunDev = nil
	}
	serverTunMu.Unlock()
	setup.DisableServerGatewayNAT()
}

func (s *Server) startUDP() {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: Conf.Server.Port}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDP服务端启动失败: %v", err)
	}
	defer udpConn.Close()
	s.udpConn = udpConn

	_ = udpConn.SetReadBuffer(16 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(16 * 1024 * 1024)

	log.Printf("✅ UDP 服务端启动成功，监听UDP :%d", Conf.Server.Port)

	peers := make(map[string]*ClientPeer)
	var peersMu sync.Mutex
	buf := make([]byte, udpPacketBufferSize)

	for {
		n, remote, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP读取失败: %v", err)
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		key := remote.String()

		peersMu.Lock()
		peer := peers[key]
		if peer == nil {
			remoteCopy := *remote
			peer = &ClientPeer{
				remote:    &remoteCopy,
				session:   &secure.SessionManager{},
				sendQueue: make(chan []byte, serverPeerSendQueueSize),
				sendDone:  make(chan struct{}),
			}
			go s.peerSendLoop(peer)
			peers[key] = peer
		}
		peersMu.Unlock()

		if err := s.handleClientPacket(peer, pkt); err != nil {
			log.Printf("客户端连接状态已重置: remote=%s err=%v", key, err)
			peersMu.Lock()
			delete(peers, key)
			peersMu.Unlock()
			s.cleanupClientPeer(peer)
		}
	}
}

func (s *Server) handleClientPacket(peer *ClientPeer, datagram []byte) error {
	frame, err := decodeFrame(datagram)
	if err != nil {
		return err
	}
	switch frame.Type {
	case PacketTypePing:
		// 客户端保活包。
		if !s.handlePing(peer) {
			return fmt.Errorf("failed to reply pong")
		}
	case PacketTypeSecure:
		// 业务密文帧。
		s.handleSecurePacket(peer, frame.IPPacket)
	case PacketTypeHandshakeInit:
		// 支持连接内重握手（密钥轮转）。
		if err := s.performHandshake(peer, frame.IPPacket); err != nil {
			return err
		}
		log.Printf("客户端认证成功 remote=%s device=%s", peer.remote, peer.deviceID)
	default:
		log.Printf("handleClient收到未识别帧类型: type=%d", frame.Type)
	}
	return nil
}

func (s *Server) peerSendLoop(peer *ClientPeer) {
	for {
		select {
		case <-peer.sendDone:
			return
		case pkt := <-peer.sendQueue:
			err := s.writeSecureFrame(peer, PacketTypeIP, pkt)
			if err != nil {
				return
			}
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
	log.Printf("客户端断开: remote=%s device=%s ip=%s", peer.remote, peer.deviceID, peer.virtualIP)
}

func (s *Server) handlePing(peer *ClientPeer) bool {
	return writeUDPFrameTo(s.udpConn, peer.remote, PacketTypePong, nil) == nil
}

func (s *Server) handleSecurePacket(peer *ClientPeer, pkt []byte) {
	// 先解密外层 secure 帧，再看内层业务类型。
	innerType, plain, err := peer.session.Decrypt(pkt)
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
		log.Printf("handleSecurePacket收到未识别内层类型: type=%d", innerType)
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
		_ = s.writeSecureFrame(peer, PacketTypeVDHCP, nak)
		return
	}
	offer, err := vdhcp.EncodeOffer(ip, s.dhcpMask, Conf.Common.Gateway)
	if err != nil {
		return
	}
	err = s.writeSecureFrame(peer, PacketTypeVDHCP, offer)
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
	heardInfo, err := headerParsing(pkt)
	// 基本校验：源地址必须等于该 peer 分配到的虚拟地址，防止伪造。
	if err != nil || peer.virtualIP == "" || heardInfo.SrcIP != peer.virtualIP {
		return
	}
	if heardInfo.IsBroadcast {
		// 广播/组播：复制给其它在线 peer。
		s.broadcastPacket(&heardInfo, pkt)
		return
	}
	s.clientTable.RLock()
	targetPeer, exists := s.clientTable.m[heardInfo.DstIP]
	s.clientTable.RUnlock()
	if !exists {
		// 目标不在客户端表中：交给服务端网关 TUN（若已启用）。
		_ = s.writeToServerTun(pkt)
		return
	}
	_ = s.enqueuePeerPacket(targetPeer, pkt)
}

func (s *Server) broadcastPacket(heardInfo *IPHeaderInfo, pkt []byte) {
	targets := make(map[string]*ClientPeer)
	s.clientTable.RLock()
	for ip, targetPeer := range s.clientTable.m {
		if ip != heardInfo.SrcIP {
			targets[ip] = targetPeer
		}
	}
	s.clientTable.RUnlock()
	for _, targetPeer := range targets {
		_ = s.enqueuePeerPacket(targetPeer, pkt)
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

func (s *Server) writeSecureFrame(peer *ClientPeer, packetType PacketType, payload []byte) error {
	cs := peer.session.Current()
	if cs == nil {
		return fmt.Errorf("no active session")
	}
	sealed, err := cs.Encrypt(byte(packetType), payload)
	if err != nil {
		return err
	}
	return writeUDPFrameTo(s.udpConn, peer.remote, PacketTypeSecure, sealed)
}

func (s *Server) performHandshake(peer *ClientPeer, initMsg []byte) error {
	// 服务端作为响应方（Responder）完成握手，并拿到对端公钥。
	if len(Conf.Common.Identity.Private) == 0 {
		return fmt.Errorf("common.privateKey is required")
	}
	hs := secure.NewHandshaker(Conf.Common.Identity, nil)
	keyID := s.keyID.Add(1)
	log.Printf("开始处理客户端认证: remote=%s localKeyID=%d", peer.remote, keyID)
	session, remotePub, err := hs.ResponderHandshake(
		func(msg []byte) error { return writeUDPFrameTo(s.udpConn, peer.remote, PacketTypeHandshakeResp, msg) },
		func() ([]byte, error) {
			if len(initMsg) > 0 {
				msg := initMsg
				initMsg = nil
				return msg, nil
			}
			return nil, fmt.Errorf("missing handshake init message")
		},
		keyID,
	)
	if err != nil {
		log.Printf("客户端认证失败: remote=%s localKeyID=%d err=%v", peer.remote, keyID, err)
		return err
	}
	if !isPeerStaticAllowed(remotePub) {
		return fmt.Errorf("peer public key not allowed")
	}
	peer.peerPublicKey = base64.StdEncoding.EncodeToString(remotePub)
	peer.deviceID = secure.DeviceIDFromPublicKey(remotePub)
	// 用新会话替换旧会话，实现平滑轮转。
	peer.session.Rotate(session)
	log.Printf("客户端认证通过: remote=%s device=%s", peer.remote, peer.deviceID)
	return nil
}

func isPeerStaticAllowed(remotePub []byte) bool {
	if len(allowedPeerStaticSet) == 0 {
		return true
	}
	_, ok := allowedPeerStaticSet[string(remotePub)]
	return ok
}

func (s *Server) writeToServerTun(pkt []byte) error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	if s.tunDev == nil {
		return fmt.Errorf("server TUN is not enabled")
	}
	return writeToTun(s.tunDev, pkt)
}

func (s *Server) tunToClients(dev tun.Device) {
	for {
		// 从服务端网关 TUN 读到的数据，按目标 IP 发回对应客户端。
		packets, err := readFromTun(dev)
		if err != nil {
			return
		}
		for _, pkt := range packets {
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
}
