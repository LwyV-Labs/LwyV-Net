package vlan2

import (
	"fmt"
	"sync"

	"github.com/LwyV-Labs/LwyV-Net/tcpx"
)

type ClientPeer struct {
	stats TrafficCounter
	conn  *tcpx.SecureConn

	mu        sync.Mutex
	id        string
	virtualIP string

	sendQueue chan []byte
	done      chan struct{}
	closeOnce sync.Once
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

func newClientPeer(conn *tcpx.SecureConn) *ClientPeer {
	return &ClientPeer{
		conn:      conn,
		sendQueue: make(chan []byte, serverPeerSendQueueSize),
		done:      make(chan struct{}),
	}
}

func (p *ClientPeer) setIdentity(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.id != "" && p.id != id {
		return false
	}
	p.id = id
	return true
}

func (p *ClientPeer) setIP(ip string) {
	p.mu.Lock()
	p.virtualIP = ip
	p.mu.Unlock()
}

func (p *ClientPeer) clientID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.id
}

func (p *ClientPeer) ip() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.virtualIP
}

func (p *ClientPeer) authed() bool {
	return p.clientID() != ""
}

func (p *ClientPeer) ownsIP(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.virtualIP != "" && p.virtualIP == ip
}

func (p *ClientPeer) remoteAddr() string {
	if p == nil || p.conn == nil || p.conn.RemoteAddr() == nil {
		return ""
	}
	return p.conn.RemoteAddr().String()
}

func (p *ClientPeer) write(payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return fmt.Errorf("peer conn is nil")
	}
	return p.conn.Write(payload)
}

func (p *ClientPeer) enqueue(pkt []byte) error {
	buf := make([]byte, len(pkt))
	copy(buf, pkt)
	select {
	case <-p.done:
		return fmt.Errorf("peer sender closed")
	case p.sendQueue <- buf:
		return nil
	}
}

func (p *ClientPeer) close() {
	p.closeOnce.Do(func() {
		close(p.done)
		if p.conn != nil {
			_ = p.conn.Close()
		}
	})
}

type peerRegistry struct {
	mu    sync.RWMutex
	conns map[*tcpx.SecureConn]*ClientPeer
	ips   map[string]*ClientPeer
	ids   map[string]*ClientPeer
}

func newPeerRegistry() *peerRegistry {
	return &peerRegistry{
		conns: make(map[*tcpx.SecureConn]*ClientPeer),
		ips:   make(map[string]*ClientPeer),
		ids:   make(map[string]*ClientPeer),
	}
}

func (r *peerRegistry) addConn(peer *ClientPeer) {
	r.mu.Lock()
	r.conns[peer.conn] = peer
	r.mu.Unlock()
}

func (r *peerRegistry) bindIP(peer *ClientPeer, ip string) *ClientPeer {
	r.mu.Lock()
	defer r.mu.Unlock()

	old := r.ips[ip]
	peer.setIP(ip)
	r.ips[ip] = peer
	if id := peer.clientID(); id != "" {
		r.ids[id] = peer
	}
	return old
}

func (r *peerRegistry) remove(peer *ClientPeer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current := r.conns[peer.conn]; current == peer {
		delete(r.conns, peer.conn)
	}
	if ip := peer.ip(); ip != "" {
		if current := r.ips[ip]; current == peer {
			delete(r.ips, ip)
		}
	}
	if id := peer.clientID(); id != "" {
		if current := r.ids[id]; current == peer {
			delete(r.ids, id)
		}
	}
}

func (r *peerRegistry) byConn(conn *tcpx.SecureConn) *ClientPeer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conns[conn]
}

func (r *peerRegistry) byIP(ip string) *ClientPeer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ips[ip]
}

func (r *peerRegistry) byID(id string) *ClientPeer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ids[id]
}

func (r *peerRegistry) all() []*ClientPeer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[*ClientPeer]struct{}, len(r.conns)+len(r.ips))
	for _, peer := range r.conns {
		seen[peer] = struct{}{}
	}
	for _, peer := range r.ips {
		seen[peer] = struct{}{}
	}
	out := make([]*ClientPeer, 0, len(seen))
	for peer := range seen {
		out = append(out, peer)
	}
	return out
}

func (r *peerRegistry) withIP() []*ClientPeer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ClientPeer, 0, len(r.ips))
	for _, peer := range r.ips {
		out = append(out, peer)
	}
	return out
}
