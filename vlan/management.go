package vlan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type managementStatusResponse struct {
	Status        string                `json:"status"`
	StartedAt     time.Time             `json:"startedAt"`
	UptimeSeconds int64                 `json:"uptimeSeconds"`
	TCPPort       int                   `json:"tcpPort"`
	IfName        string                `json:"ifName"`
	MTU           int                   `json:"mtu"`
	Proxy         bool                  `json:"proxy"`
	PeerCount     int                   `json:"peerCount"`
	AuthedPeers   int                   `json:"authedPeers"`
	AssignedPeers int                   `json:"assignedPeers"`
	Traffic       managementTrafficInfo `json:"traffic"`
	VDHCP         managementVDHCPInfo   `json:"vdhcp"`
}

type managementVDHCPInfo struct {
	StartIP    string   `json:"startIP"`
	EndIP      string   `json:"endIP"`
	SubnetMask string   `json:"subnetMask"`
	Gateway    string   `json:"gateway"`
	DNS        []string `json:"dns"`
}

type managementPeerInfo struct {
	ClientID      string  `json:"clientID"`
	VirtualIP     string  `json:"virtualIP"`
	RemoteAddr    string  `json:"remoteAddr"`
	Authed        bool    `json:"authed"`
	Assigned      bool    `json:"assigned"`
	UploadBytes   uint64  `json:"uploadBytes"`
	DownloadBytes uint64  `json:"downloadBytes"`
	UploadBps     float64 `json:"uploadBps"`
	DownloadBps   float64 `json:"downloadBps"`
}

type managementTrafficInfo struct {
	UploadBytes   uint64  `json:"uploadBytes"`
	DownloadBytes uint64  `json:"downloadBytes"`
	UploadBps     float64 `json:"uploadBps"`
	DownloadBps   float64 `json:"downloadBps"`
}

func (s *Server) initManagement() error {
	if !s.conf.Management.Enabled {
		return nil
	}
	addr := strings.TrimSpace(s.conf.Management.Addr)
	if addr == "" {
		addr = "127.0.0.1:18080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleManagementStatus)
	mux.HandleFunc("/api/peers", s.handleManagementPeers)
	mux.HandleFunc("/api/traffic", s.handleManagementTraffic)
	mux.HandleFunc("/api/vdhcp/leases", s.handleManagementLeases)
	mux.HandleFunc("/api/events", s.handleManagementEvents)
	mux.HandleFunc("/api", s.handleManagementIndex)
	mux.HandleFunc("/api/", s.handleManagementIndex)

	s.management = &http.Server{
		Addr:              addr,
		Handler:           s.managementMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("✅ Management API 已启用: http://%s/api", addr)
		if err := s.management.Serve(ln); err != nil && err != http.ErrServerClosed && !s.stop.Load() {
			log.Printf("Management API 退出: %v", err)
		}
	}()
	return nil
}

func (s *Server) shutdownManagement() {
	if s.management == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.management.Shutdown(ctx); err != nil {
		log.Printf("Management API 关闭失败: %v", err)
	}
}

func (s *Server) managementMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, X-Management-Token, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeManagementError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !s.managementAuthorized(r) {
			writeManagementError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) managementAuthorized(r *http.Request) bool {
	token := strings.TrimSpace(s.conf.Management.Token)
	if token == "" {
		return true
	}
	if r.Header.Get("X-Management-Token") == token {
		return true
	}
	return r.Header.Get("Authorization") == "Bearer "+token
}

func (s *Server) handleManagementIndex(w http.ResponseWriter, r *http.Request) {
	writeManagementJSON(w, http.StatusOK, map[string]any{
		"endpoints": []string{
			"/api/status",
			"/api/peers",
			"/api/traffic",
			"/api/vdhcp/leases",
			"/api/events",
		},
	})
}

func (s *Server) handleManagementStatus(w http.ResponseWriter, r *http.Request) {
	peers := s.managementPeers()
	var authed, assigned int
	var traffic managementTrafficInfo
	for _, peer := range peers {
		if peer.Authed {
			authed++
		}
		if peer.Assigned {
			assigned++
		}
		traffic.UploadBytes += peer.UploadBytes
		traffic.DownloadBytes += peer.DownloadBytes
		traffic.UploadBps += peer.UploadBps
		traffic.DownloadBps += peer.DownloadBps
	}

	writeManagementJSON(w, http.StatusOK, managementStatusResponse{
		Status:        "running",
		StartedAt:     s.startedAt,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		TCPPort:       s.conf.Port,
		IfName:        s.conf.IfName,
		MTU:           s.conf.MTU,
		Proxy:         s.conf.Proxy,
		PeerCount:     len(peers),
		AuthedPeers:   authed,
		AssignedPeers: assigned,
		Traffic:       traffic,
		VDHCP: managementVDHCPInfo{
			StartIP:    s.conf.VDHCP.StartIP,
			EndIP:      s.conf.VDHCP.EndIP,
			SubnetMask: s.conf.VDHCP.SubnetMask,
			Gateway:    s.conf.VDHCP.Gateway,
			DNS:        append([]string(nil), s.conf.VDHCP.DNS...),
		},
	})
}

func (s *Server) handleManagementPeers(w http.ResponseWriter, r *http.Request) {
	writeManagementJSON(w, http.StatusOK, s.managementPeers())
}

func (s *Server) handleManagementTraffic(w http.ResponseWriter, r *http.Request) {
	var out managementTrafficInfo
	for _, peer := range s.managementPeers() {
		out.UploadBytes += peer.UploadBytes
		out.DownloadBytes += peer.DownloadBytes
		out.UploadBps += peer.UploadBps
		out.DownloadBps += peer.DownloadBps
	}
	writeManagementJSON(w, http.StatusOK, out)
}

func (s *Server) handleManagementLeases(w http.ResponseWriter, r *http.Request) {
	if s.dhcp == nil {
		writeManagementJSON(w, http.StatusOK, []any{})
		return
	}
	writeManagementJSON(w, http.StatusOK, s.dhcp.Snapshot())
}

func (s *Server) handleManagementEvents(w http.ResponseWriter, r *http.Request) {
	writeManagementJSON(w, http.StatusOK, s.managementEventsSnapshot())
}

func (s *Server) managementPeers() []managementPeerInfo {
	peers := s.peers.all()
	out := make([]managementPeerInfo, 0, len(peers))
	for _, peer := range peers {
		stats := peer.stats.Snapshot()
		clientID := peer.clientID()
		virtualIP := peer.ip()
		out = append(out, managementPeerInfo{
			ClientID:      clientID,
			VirtualIP:     virtualIP,
			RemoteAddr:    peer.remoteAddr(),
			Authed:        clientID != "",
			Assigned:      virtualIP != "",
			UploadBytes:   stats.UploadBytes,
			DownloadBytes: stats.DownloadBytes,
			UploadBps:     stats.UploadBps,
			DownloadBps:   stats.DownloadBps,
		})
	}
	return out
}

func writeManagementJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("management json encode failed: %v", err)
	}
}

func writeManagementError(w http.ResponseWriter, status int, message string) {
	writeManagementJSON(w, status, map[string]string{
		"error": fmt.Sprintf("%s", message),
	})
}
