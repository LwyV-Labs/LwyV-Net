package vlan

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/config"
	"github.com/LwyV-Labs/LwyV-Net/tcpx"
	"github.com/LwyV-Labs/LwyV-Net/tunSetup"
	"github.com/LwyV-Labs/LwyV-Net/vdhcp"
	"golang.org/x/net/ipv4"
)

const (
	serverPeerSendQueueSize = 16 * 1024
	serverLeaseTTL          = 24 * time.Hour
	serverOfflineGrace      = 5 * time.Minute
)

type Server struct {
	conf config.ServerConfig

	peers *peerRegistry
	tcp   *tcpx.Server
	tun   *tunSetup.TUNTunnel
	dhcp  *vdhcp.Manager

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	stop      atomic.Bool
	startedAt time.Time

	eventMu         sync.RWMutex
	onVDHCPAssigned VDHCPAssignedCallback

	management        *http.Server
	managementMu      sync.Mutex
	managementEvents  []ManagementEvent
	managementEventID uint64
}

func NewServer(conf config.ServerConfig) *Server {
	return &Server{conf: conf, peers: newPeerRegistry()}
}

func (s *Server) Start() {
	if err := s.initDHCP(); err != nil {
		log.Fatalf("初始化虚拟 DHCP 失败: %v", err)
	}
	if s.conf.Proxy {
		if err := s.initGatewayTun(); err != nil {
			log.Fatalf("初始化服务端网关失败: %v", err)
		}
	}
	if err := s.initTCP(); err != nil {
		log.Fatalf("初始化 tcpx 服务端失败: %v", err)
	}

	s.startedAt = time.Now()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.recordManagementEvent("server_started", "服务端已启动", map[string]any{
		"port":  s.conf.Port,
		"proxy": s.conf.Proxy,
	})
	if err := s.initManagement(); err != nil {
		log.Fatalf("初始化 Management API 失败: %v", err)
	}

	s.wg.Add(1)
	go s.sweepDHCPLeases()
	if s.tun != nil {
		s.wg.Add(1)
		go s.tunToClients()
	}

	log.Printf("✅ tcpx 服务端启动成功，监听 :%d", s.conf.Port)
	log.Println("📝 等待客户端连接并转发 IP 包...")
	if err := s.tcp.ListenAndServe(s.ctx); err != nil && !s.stop.Load() {
		log.Printf("tcpx 服务端退出: %v", err)
	}
}

func (s *Server) Stop() {
	if !s.stop.CompareAndSwap(false, true) {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.tcp != nil {
		_ = s.tcp.Close()
	}
	s.shutdownManagement()
	for _, peer := range s.peers.all() {
		peer.close()
	}
	if s.conf.Proxy {
		tunSetup.DisableServerGatewayNAT()
	}
	if s.tun != nil {
		_ = s.tun.Close()
	}
	s.wg.Wait()
	log.Printf("服务端已停止")
}

func (s *Server) initDHCP() error {
	manager, err := vdhcp.NewManager(vdhcp.ManagerConfig{
		StartIP:      s.conf.VDHCP.StartIP,
		EndIP:        s.conf.VDHCP.EndIP,
		SubnetMask:   s.conf.VDHCP.SubnetMask,
		Gateway:      s.conf.VDHCP.Gateway,
		DNS:          s.conf.VDHCP.DNS,
		MTU:          s.conf.MTU,
		LeaseTTL:     serverLeaseTTL,
		OfflineGrace: serverOfflineGrace,
	})
	if err != nil {
		return err
	}
	s.dhcp = manager
	log.Printf("✅ 虚拟 DHCP 已启用: %s - %s dns=%v", s.conf.VDHCP.StartIP, s.conf.VDHCP.EndIP, s.conf.VDHCP.DNS)
	return nil
}

func (s *Server) initGatewayTun() error {
	var err error
	s.tun, err = tunSetup.NewTUNTunnel(s.conf.IfName, s.conf.MTU)
	if err != nil {
		return fmt.Errorf("创建服务端 TUN 失败: %w", err)
	}
	if err = tunSetup.ConfigureTunAddress(s.conf.IfName, s.conf.VDHCP.Gateway, s.conf.VDHCP.SubnetMask); err != nil {
		return fmt.Errorf("配置服务端 TUN 地址失败: %w", err)
	}
	if err = tunSetup.EnableServerGatewayNAT(s.conf.IfName, s.conf.VDHCP.Gateway, s.conf.VDHCP.SubnetMask); err != nil {
		return fmt.Errorf("配置服务端 NAT 失败: %w", err)
	}
	log.Printf("✅ 服务端网关已启用: if=%s gw=%s/%s", s.conf.IfName, s.conf.VDHCP.Gateway, s.conf.VDHCP.SubnetMask)
	return nil
}

func (s *Server) initTCP() error {
	serverPrivHex, err := tcpx.NormalizePrivateKeyHex(s.conf.PrivateKey)
	if err != nil {
		return fmt.Errorf("服务端私钥格式错误: %w", err)
	}
	srv, err := tcpx.NewServer(tcpx.ServerConfig{
		Addr:                fmt.Sprintf(":%d", s.conf.Port),
		StaticPrivateKeyHex: serverPrivHex,
		BaseConfig: tcpx.BaseConfig{
			ReadTimeout:       s.conf.TCP.ServerReadTimeout(),
			WriteTimeout:      s.conf.TCP.ServerWriteTimeout(),
			HeartbeatBase:     s.conf.TCP.ServerHeartbeatBase(),
			HeartbeatJitter:   s.conf.TCP.ServerHeartbeatJitter(),
			KeyRotateInterval: s.conf.TCP.KeyRotateInterval(),
			OldKeyGrace:       s.conf.TCP.OldKeyGrace(),
		},
		OnConnect:    s.onTCPConnect,
		OnDisconnect: s.onTCPDisconnect,
		OnMessage:    s.onTCPMessage,
	})
	if err != nil {
		return err
	}
	s.tcp = srv
	return nil
}

func (s *Server) onTCPConnect(conn *tcpx.SecureConn) {
	peer := newClientPeer(conn)
	s.peers.addConn(peer)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.peerSendLoop(peer)
	}()
	log.Printf("tcpx 连接成功 remote=%s，等待客户端身份认证", conn.RemoteAddr())
}

func (s *Server) onTCPDisconnect(conn *tcpx.SecureConn, err error) {
	if conn == nil {
		if err != nil && !s.stop.Load() {
			log.Printf("tcpx 握手失败: %v", err)
		}
		return
	}
	peer := s.peers.byConn(conn)
	if peer == nil {
		return
	}
	if err != nil && !s.stop.Load() {
		log.Printf("客户端连接断开 remote=%s err=%v", conn.RemoteAddr(), err)
	}
	s.cleanupPeer(peer)
}

func (s *Server) onTCPMessage(conn *tcpx.SecureConn, raw []byte) {
	peer := s.peers.byConn(conn)
	if peer == nil {
		_ = conn.Close()
		return
	}
	typ, payload, err := Unpack(raw)
	if err != nil {
		log.Printf("解析应用层数据失败: remote=%s err=%v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}

	switch typ {
	case TypeAuth:
		s.handleClientAuth(peer, payload)
	case TypeVDHCP:
		if !peer.authed() {
			log.Printf("未认证客户端发送 VDHCP，关闭连接 remote=%s", conn.RemoteAddr())
			_ = conn.Close()
			return
		}
		s.handleVDHCP(peer, payload)
	case TypeIP:
		if !peer.authed() {
			log.Printf("未认证客户端发送 IP，关闭连接 remote=%s", conn.RemoteAddr())
			_ = conn.Close()
			return
		}
		s.handleIP(peer, payload)
	default:
		log.Printf("未知应用层类型: %d", typ)
		_ = conn.Close()
	}
}

func (s *Server) handleClientAuth(peer *ClientPeer, payload []byte) {
	clientID, err := VerifyClientAuth(payload, s.conf.PrivateKey)
	if err != nil {
		log.Printf("客户端身份认证失败 remote=%s err=%v", peer.remoteAddr(), err)
		s.recordManagementEvent("auth_failed", "客户端身份认证失败", map[string]any{
			"remoteAddr": peer.remoteAddr(),
			"error":      err.Error(),
		})
		_ = peer.conn.Close()
		return
	}
	if !peer.setIdentity(clientID) {
		log.Printf("客户端重复认证身份不一致 remote=%s", peer.remoteAddr())
		_ = peer.conn.Close()
		return
	}
	log.Printf("客户端身份认证成功 remote=%s clientID=%s", peer.remoteAddr(), shortID(clientID))
	s.recordManagementEvent("client_authed", "客户端身份认证成功", map[string]any{
		"clientID":   clientID,
		"remoteAddr": peer.remoteAddr(),
	})
}

func (s *Server) handleVDHCP(peer *ClientPeer, pkt []byte) {
	msg, err := vdhcp.DecodeMessage(pkt)
	if err != nil {
		log.Printf("无效 VDHCP 消息: client=%s err=%v", shortID(peer.clientID()), err)
		return
	}
	if msg.Type != vdhcp.MessageTypeDiscover {
		log.Printf("暂不支持的 VDHCP 类型: client=%s type=%s", shortID(peer.clientID()), msg.Type)
		return
	}
	s.handleDHCPDiscover(peer, msg)
}

func (s *Server) handleDHCPDiscover(peer *ClientPeer, msg vdhcp.Message) {
	lease, err := s.dhcp.Acquire(peer.clientID())
	if err != nil {
		nak, _ := vdhcp.EncodeNak(msg.RequestID, err.Error())
		_ = peer.write(Pack(TypeVDHCP, nak))
		return
	}
	offer, err := vdhcp.EncodeOffer(msg.RequestID, lease.IP, s.conf.VDHCP.SubnetMask, s.conf.VDHCP.Gateway, s.conf.VDHCP.DNS, s.conf.MTU, serverLeaseTTL)
	if err != nil {
		return
	}
	if err := peer.write(Pack(TypeVDHCP, offer)); err != nil {
		_ = peer.conn.Close()
		return
	}
	oldPeer := s.peers.bindIP(peer, lease.IP)
	if oldPeer != nil && oldPeer != peer {
		oldPeer.close()
	}
	log.Printf("DHCP 分配成功: client=%s ip=%s dns=%v", shortID(peer.clientID()), lease.IP, s.conf.VDHCP.DNS)
	s.emitVDHCPAssigned(VDHCPAssignedInfo{
		ClientID:     peer.clientID(),
		RemoteAddr:   peer.remoteAddr(),
		IP:           lease.IP,
		SubnetMask:   s.conf.VDHCP.SubnetMask,
		Gateway:      s.conf.VDHCP.Gateway,
		DNS:          append([]string(nil), s.conf.VDHCP.DNS...),
		MTU:          s.conf.MTU,
		LeaseSeconds: int64(serverLeaseTTL.Seconds()),
	})
}

func (s *Server) handleIP(peer *ClientPeer, pkt []byte) {
	peer.stats.AddDownload(len(pkt))

	ipHdr, err := ipv4.ParseHeader(pkt)
	if err != nil {
		return
	}
	if !peer.ownsIP(ipHdr.Src.String()) ||
		IsBroadcast(ipHdr.Dst) ||
		IsMulticast(ipHdr.Dst) ||
		IsSubnetBroadcast(ipHdr.Dst, s.conf.VDHCP.Gateway, s.conf.VDHCP.SubnetMask) {
		return
	}

	if target := s.peers.byIP(ipHdr.Dst.String()); target != nil {
		_ = target.enqueue(pkt)
		return
	}
	if s.tun != nil {
		_ = s.tun.Write(pkt)
	}
}

func (s *Server) peerSendLoop(peer *ClientPeer) {
	for {
		select {
		case <-peer.done:
			return
		case pkt := <-peer.sendQueue:
			if err := peer.write(Pack(TypeIP, pkt)); err != nil {
				_ = peer.conn.Close()
				return
			}
			peer.stats.AddUpload(len(pkt))
		}
	}
}

func (s *Server) cleanupPeer(peer *ClientPeer) {
	peer.close()
	s.peers.remove(peer)
	if peer.clientID() != "" {
		s.dhcp.MarkOffline(peer.clientID())
	}
	log.Printf("客户端断开: clientID=%s ip=%s", shortID(peer.clientID()), peer.ip())
	s.recordManagementEvent("client_disconnected", "客户端断开", map[string]any{
		"clientID":  peer.clientID(),
		"virtualIP": peer.ip(),
	})
}

func (s *Server) tunToClients() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case pkt, ok := <-s.tun.ReadChan():
			if !ok {
				return
			}
			ipHdr, err := ipv4.ParseHeader(pkt)
			if err != nil {
				continue
			}
			if target := s.peers.byIP(ipHdr.Dst.String()); target != nil {
				_ = target.enqueue(pkt)
			}
		}
	}
}

func (s *Server) sweepDHCPLeases() {
	defer s.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if s.dhcp != nil {
				s.dhcp.SweepExpired()
			}
		}
	}
}

func (s *Server) GetTrafficStatsByIP(virtualIP string) (TrafficStats, bool) {
	peer := s.peers.byIP(virtualIP)
	if peer == nil {
		return TrafficStats{}, false
	}
	return peer.stats.Snapshot(), true
}

func (s *Server) GetTrafficStatsByDeviceID(deviceID string) (TrafficStats, bool) {
	peer := s.peers.byID(deviceID)
	if peer == nil {
		return TrafficStats{}, false
	}
	return peer.stats.Snapshot(), true
}

func (s *Server) ListPeerTraffic() []PeerTrafficInfo {
	peers := s.peers.withIP()
	out := make([]PeerTrafficInfo, 0, len(peers))
	for _, peer := range peers {
		stats := peer.stats.Snapshot()
		out = append(out, PeerTrafficInfo{
			DeviceID:      peer.clientID(),
			VirtualIP:     peer.ip(),
			RemoteAddr:    peer.remoteAddr(),
			UploadBytes:   stats.UploadBytes,
			DownloadBytes: stats.DownloadBytes,
			UploadBps:     stats.UploadBps,
			DownloadBps:   stats.DownloadBps,
		})
	}
	return out
}
