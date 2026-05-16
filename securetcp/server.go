package securetcp

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Handler handles one accepted secure connection. Return when that connection should close.
type Handler func(*Conn)

// Server is a secure TCP server.
type Server struct {
	ln      net.Listener
	cfg     Config
	cache   *sessionCache
	handler Handler
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// Listen starts a server listener and accepts connections in the background.
func Listen(addr string, cfg Config, handler Handler) (*Server, error) {
	if err := cfg.NormalizeServer(); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ln: ln, cfg: cfg, cache: newSessionCache(), handler: handler, ctx: ctx, cancel: cancel}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *Server) Addr() net.Addr { return s.ln.Addr() }

func (s *Server) Close() error {
	s.cancel()
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
		}
		s.wg.Add(1)
		go s.handleRawConn(nc)
	}
}

func (s *Server) handleRawConn(nc net.Conn) {
	defer s.wg.Done()
	res, err := serverHandshake(nc, s.cfg, s.cache)
	if err != nil {
		_ = nc.Close()
		return
	}
	conn, err := newConn(nc, s.cfg, roleServer, res.master)
	if err != nil {
		_ = nc.Close()
		return
	}
	if s.handler != nil {
		s.handler(conn)
	}
	_ = conn.Close()
}
