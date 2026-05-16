package vlan

// VDHCPAssignedInfo is emitted after a vDHCP address has been assigned.
type VDHCPAssignedInfo struct {
	ClientID     string   `json:"clientID"`
	RemoteAddr   string   `json:"remoteAddr"`
	IP           string   `json:"ip"`
	SubnetMask   string   `json:"subnetMask"`
	Gateway      string   `json:"gateway"`
	DNS          []string `json:"dns"`
	MTU          int      `json:"mtu"`
	LeaseSeconds int64    `json:"leaseSeconds"`
}

// VDHCPAssignedCallback is called after vDHCP assignment succeeds.
type VDHCPAssignedCallback func(info VDHCPAssignedInfo)

func (c *Client) SetOnVDHCPAssigned(cb VDHCPAssignedCallback) {
	c.mu.Lock()
	c.onVDHCPAssigned = cb
	c.mu.Unlock()
}

func (s *Server) SetOnVDHCPAssigned(cb VDHCPAssignedCallback) {
	s.eventMu.Lock()
	s.onVDHCPAssigned = cb
	s.eventMu.Unlock()
}

func (c *Client) emitVDHCPAssigned(info VDHCPAssignedInfo) {
	c.mu.Lock()
	cb := c.onVDHCPAssigned
	c.mu.Unlock()
	if cb != nil {
		cb(cloneVDHCPAssignedInfo(info))
	}
}

func (s *Server) emitVDHCPAssigned(info VDHCPAssignedInfo) {
	info = cloneVDHCPAssignedInfo(info)
	s.recordManagementEvent("vdhcp_assigned", "vDHCP 分配成功", info)

	s.eventMu.RLock()
	cb := s.onVDHCPAssigned
	s.eventMu.RUnlock()
	if cb != nil {
		cb(cloneVDHCPAssignedInfo(info))
	}
}

func cloneVDHCPAssignedInfo(info VDHCPAssignedInfo) VDHCPAssignedInfo {
	info.DNS = append([]string(nil), info.DNS...)
	return info
}
