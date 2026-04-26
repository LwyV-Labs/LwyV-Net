package vdhcp

import (
	"fmt"
	"net"
	"sync"
)

type Manager struct {
	mu sync.Mutex
	// pool: 可分配地址池（按 startIP~endIP 顺序生成）。
	pool []string
	// leaseByID: clientID -> IP
	leaseByID map[string]string
	// leaseOwnerBy: IP -> clientID（用于快速判断占用）
	leaseOwnerBy map[string]string
}

func NewManager(startIP, endIP string) (*Manager, error) {
	start := net.ParseIP(startIP).To4()
	end := net.ParseIP(endIP).To4()
	if start == nil || end == nil {
		return nil, fmt.Errorf("startIP/endIP must be valid IPv4")
	}

	startU := ipToUint32(start)
	endU := ipToUint32(end)
	if startU > endU {
		return nil, fmt.Errorf("startIP must be <= endIP")
	}

	pool := make([]string, 0, endU-startU+1)
	for ip := startU; ip <= endU; ip++ {
		pool = append(pool, uint32ToIP(ip).String())
	}

	return &Manager{
		pool:         pool,
		leaseByID:    make(map[string]string),
		leaseOwnerBy: make(map[string]string),
	}, nil
}

func (m *Manager) Allocate(clientID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 同一个 clientID 重复申请，返回历史租约（幂等）。
	if ip, ok := m.leaseByID[clientID]; ok {
		return ip, nil
	}

	// 线性扫描池，找到第一个未占用 IP。
	for _, ip := range m.pool {
		if _, used := m.leaseOwnerBy[ip]; used {
			continue
		}
		m.leaseByID[clientID] = ip
		m.leaseOwnerBy[ip] = clientID
		return ip, nil
	}

	return "", fmt.Errorf("ip pool exhausted")
}

func (m *Manager) Release(clientID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ip, ok := m.leaseByID[clientID]
	if !ok {
		return
	}
	// 双向索引都要删除，避免“脏租约”。
	delete(m.leaseByID, clientID)
	delete(m.leaseOwnerBy, ip)
}

func ipToUint32(ip net.IP) uint32 {
	v := ip.To4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
