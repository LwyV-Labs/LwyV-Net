package vdhcp

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
)

const (
	MessageTypeDiscover = "DISCOVER"
	MessageTypeOffer    = "OFFER"
	MessageTypeNak      = "NAK"
)

type Message struct {
	Type       string `json:"type"`
	IP         string `json:"ip,omitempty"`
	SubnetMask string `json:"subnetMask,omitempty"`
	Gateway    string `json:"gateway,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func EncodeDiscover() ([]byte, error) {
	return json.Marshal(Message{Type: MessageTypeDiscover})
}

func EncodeOffer(ip, subnetMask, gateway string) ([]byte, error) {
	return json.Marshal(Message{Type: MessageTypeOffer, IP: ip, SubnetMask: subnetMask, Gateway: gateway})
}

func EncodeNak(reason string) ([]byte, error) {
	return json.Marshal(Message{Type: MessageTypeNak, Reason: reason})
}

func DecodeMessage(pkt []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(pkt, &msg); err != nil {
		return msg, err
	}
	if msg.Type == "" {
		return msg, fmt.Errorf("invalid DHCP message: type is empty")
	}
	return msg, nil
}

type Manager struct {
	mu           sync.Mutex
	pool         []string
	leaseByID    map[string]string
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

	if ip, ok := m.leaseByID[clientID]; ok {
		return ip, nil
	}

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
