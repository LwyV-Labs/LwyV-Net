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
	next  uint32

	leaseByID map[string]*Lease
	ownerByIP map[string]string
	reserved  map[string]struct{}
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	start := net.ParseIP(cfg.StartIP).To4()
	end := net.ParseIP(cfg.EndIP).To4()
	gw := net.ParseIP(cfg.Gateway).To4()
	mask := net.ParseIP(cfg.SubnetMask).To4()

	if start == nil || end == nil {
		return nil, fmt.Errorf("startIP/endIP must be valid IPv4")
	}
	if gw == nil {
		return nil, fmt.Errorf("gateway must be valid IPv4")
	}
	if mask == nil {
		return nil, fmt.Errorf("subnetMask must be valid IPv4 mask")
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
		next:      startU,
		leaseByID: make(map[string]*Lease),
		ownerByIP: make(map[string]string),
		reserved:  make(map[string]struct{}),
	}
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
	m.sweepExpiredLocked(now)

	if lease, ok := m.leaseByID[clientID]; ok {
		lease.Online = true
		lease.UpdatedAt = now
		lease.ExpiresAt = now.Add(m.cfg.LeaseTTL)
		return cloneLease(lease), nil
	}

	ip, err := m.allocateIPLocked()
	if err != nil {
		return nil, err
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
	m.sweepExpiredLocked(time.Now())
}

func (m *Manager) Snapshot() []Lease {
	m.mu.Lock()
	defer m.mu.Unlock()

	leases := make([]Lease, 0, len(m.leaseByID))
	for _, lease := range m.leaseByID {
		leases = append(leases, *cloneLease(lease))
	}
	return leases
}

func (m *Manager) allocateIPLocked() (string, error) {
	poolSize := uint64(m.end) - uint64(m.start) + 1
	for scanned := uint64(0); scanned < poolSize; scanned++ {
		ipU := m.next
		m.advanceNextLocked()
		ip := uint32ToIP(ipU).String()
		if _, reserved := m.reserved[ip]; reserved {
			continue
		}
		if _, used := m.ownerByIP[ip]; used {
			continue
		}
		return ip, nil
	}
	return "", fmt.Errorf("ip pool exhausted")
}

func (m *Manager) advanceNextLocked() {
	if m.next >= m.end {
		m.next = m.start
		return
	}
	m.next++
}

func (m *Manager) sweepExpiredLocked(now time.Time) {
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
