package tcpx

import (
	"context"
	"crypto/ecdh"
	"net"
	"sync"
)

type ServerConfig struct {
	BaseConfig
	Addr                string
	StaticPrivateKeyHex string

	OnConnect    func(*SecureConn)
	OnDisconnect func(*SecureConn, error)
	OnMessage    func(*SecureConn, []byte)
}

type Server struct {
	cfg  ServerConfig
	priv *ecdh.PrivateKey

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

func NewServer(cfg ServerConfig) (*Server, error) {
	cfg.BaseConfig.setDefaults()
	priv, err := ParsePrivateKeyHex(cfg.StaticPrivateKeyHex)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, priv: priv}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.closed = false
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		raw, err := ln.Accept()
		if err != nil {
			if s.isClosed() || ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(raw)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) handleConn(raw net.Conn) {
	secure, err := serverHandshake(raw, s.cfg.BaseConfig, s.priv)
	if err != nil {
		_ = raw.Close()
		if s.cfg.OnDisconnect != nil {
			s.cfg.OnDisconnect(nil, err)
		}
		return
	}
	if s.cfg.OnConnect != nil {
		s.cfg.OnConnect(secure)
	}
	defer secure.Close()

	for {
		msg, err := secure.Read()
		if err != nil {
			if s.cfg.OnDisconnect != nil {
				s.cfg.OnDisconnect(secure, err)
			}
			return
		}
		if s.cfg.OnMessage != nil {
			s.cfg.OnMessage(secure, msg)
		}
	}
}
