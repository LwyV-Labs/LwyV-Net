package vlan

import "sync"

var (
	clientCtlMu sync.Mutex
	clientCtl   *Client
)

func StartManagedClient() bool {
	clientCtlMu.Lock()
	defer clientCtlMu.Unlock()
	if clientCtl != nil && clientCtl.IsRunning() {
		return false
	}
	c := NewClient()
	clientCtl = c
	go c.Start()
	return true
}

func DisconnectManagedClient() bool {
	clientCtlMu.Lock()
	defer clientCtlMu.Unlock()
	if clientCtl == nil {
		return false
	}
	clientCtl.Stop()
	return true
}

type ClientRuntimeStatus struct {
	Running   bool   `json:"running"`
	Connected bool   `json:"connected"`
	ServerIP  string `json:"serverIP"`
}

func ManagedClientStatus() ClientRuntimeStatus {
	clientCtlMu.Lock()
	defer clientCtlMu.Unlock()
	status := ClientRuntimeStatus{
		Running:   false,
		Connected: false,
		ServerIP:  Conf.Client.ServerIP,
	}
	if clientCtl != nil {
		status.Running = clientCtl.IsRunning()
		status.Connected = clientCtl.IsConnected()
	}
	return status
}
