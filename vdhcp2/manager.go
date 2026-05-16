package vdhcp2

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type Lease struct {
	ClientID  string
	IP        string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
	Online    bool
}

type ManagerConfig struct {
	StartIP      string
	EndIP        string
	SubnetMask   string
	Gateway      string
	MTU          int
	LeaseTTL     time.Duration
	OfflineGrace time.Duration
}

type Manager struct {
	mu sync.Mutex

	cfg ManagerConfig

	start uint32
	end   uint32

	leaseByID map[string]*Lease
	ownerByIP map[string]string

	reserved map[string]struct{}
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	start := net.ParseIP(cfg.StartIP).To4()
	end := net.ParseIP(cfg.EndIP).To4()
	gw := net.ParseIP(cfg.Gateway).To4()

	if start == nil || end == nil {
		return nil, fmt.Errorf("startIP/endIP must be valid IPv4")
	}
	if gw == nil {
		return nil, fmt.Errorf("gateway must be valid IPv4")
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 24 * time.Hour
	}
	if cfg.OfflineGrace <= 0 {
		cfg.OfflineGrace = 5 * time.Minute
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1300
	}

	startU := ipToUint32(start)
	endU := ipToUint32(end)
	if startU > endU {
		return nil, fmt.Errorf("startIP must be <= endIP")
	}

	m := &Manager{
		cfg:       cfg,
		start:     startU,
		end:       endU,
		leaseByID: make(map[string]*Lease),
		ownerByIP: make(map[string]string),
		reserved:  make(map[string]struct{}),
	}

	// 网关地址不能分配给客户端。
	m.reserved[gw.String()] = struct{}{}

	return m, nil
}

func (m *Manager) Acquire(clientID string) (*Lease, error) {
	if clientID == "" {
		return nil, fmt.Errorf("clientID is empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// 老客户端重连，优先返回原 IP。
	if lease, ok := m.leaseByID[clientID]; ok {
		lease.Online = true
		lease.UpdatedAt = now
		lease.ExpiresAt = now.Add(m.cfg.LeaseTTL)
		return cloneLease(lease), nil
	}

	// 新客户端分配 IP。
	for ipU := m.start; ipU <= m.end; ipU++ {
		ip := uint32ToIP(ipU).String()

		if _, reserved := m.reserved[ip]; reserved {
			continue
		}
		if _, used := m.ownerByIP[ip]; used {
			continue
		}

		lease := &Lease{
			ClientID:  clientID,
			IP:        ip,
			CreatedAt: now,
			UpdatedAt: now,
			ExpiresAt: now.Add(m.cfg.LeaseTTL),
			Online:    true,
		}

		m.leaseByID[clientID] = lease
		m.ownerByIP[ip] = clientID

		return cloneLease(lease), nil
	}

	return nil, fmt.Errorf("ip pool exhausted")
}

func (m *Manager) MarkOffline(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lease, ok := m.leaseByID[clientID]
	if !ok {
		return
	}

	now := time.Now()
	lease.Online = false
	lease.UpdatedAt = now

	// 不是立即释放，而是给自动重连留窗口。
	lease.ExpiresAt = now.Add(m.cfg.OfflineGrace)
}

func (m *Manager) Release(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseLocked(clientID)
}

func (m *Manager) SweepExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for clientID, lease := range m.leaseByID {
		if lease.Online {
			continue
		}
		if now.After(lease.ExpiresAt) {
			m.releaseLocked(clientID)
		}
	}
}

func (m *Manager) releaseLocked(clientID string) {
	lease, ok := m.leaseByID[clientID]
	if !ok {
		return
	}
	delete(m.leaseByID, clientID)
	delete(m.ownerByIP, lease.IP)
}

func cloneLease(l *Lease) *Lease {
	cp := *l
	return &cp
}

func ipToUint32(ip net.IP) uint32 {
	v := ip.To4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
