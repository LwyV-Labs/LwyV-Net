package vlan

import "sync"

var (
	serverCtlMu sync.Mutex
	serverCtl   *Server
)

func StartManagedServer() bool {
	serverCtlMu.Lock()
	defer serverCtlMu.Unlock()
	if serverCtl != nil && serverCtl.running.Load() {
		return false
	}
	s := NewServer()
	serverCtl = s
	go s.Start()
	return true
}

func ManagedServerStatus() ServerRuntimeStatus {
	serverCtlMu.Lock()
	s := serverCtl
	serverCtlMu.Unlock()
	if s == nil {
		return ServerRuntimeStatus{}
	}
	return s.SnapshotStatus()
}
