package securetcp

import (
	"context"
	"fmt"
	"net"
	"sync"
)

type Server struct {
	cfg  ServerConfig
	priv any

	lnMu sync.Mutex
	ln   net.Listener
}

type Handler func(*Conn)

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg.normalize()
	if cfg.Address == "" {
		cfg.Address = ":9443"
	}
	if cfg.ServerPrivateKeyB64 == "" {
		return nil, fmt.Errorf("server private key is required")
	}
	if _, err := parsePrivateKeyB64(cfg.ServerPrivateKeyB64); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg}, nil
}

func (s *Server) ListenAndServe(ctx context.Context, h Handler) error {
	if ctx == nil {
		ctx = context.Background()
	}
	priv, err := parsePrivateKeyB64(s.cfg.ServerPrivateKeyB64)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return err
	}
	s.lnMu.Lock()
	s.ln = ln
	s.lnMu.Unlock()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		nc, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}
		go func(raw net.Conn) {
			hs, err := serverHandshake(raw, s.cfg.CommonConfig, priv)
			if err != nil {
				_ = raw.Close()
				return
			}
			sc, err := newConn(raw, s.cfg.CommonConfig, RoleServer, hs, false, s.cfg.ServerInitiatesRekey)
			if err != nil {
				return
			}
			sc.Start()
			if h != nil {
				h(sc)
			}
		}(nc)
	}
}

func (s *Server) Close() error {
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}
