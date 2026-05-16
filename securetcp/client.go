package securetcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type Client struct {
	cfg ClientConfig

	mu     sync.RWMutex
	conn   *Conn
	closed bool
}

func NewClient(cfg ClientConfig) (*Client, error) {
	cfg.normalize()
	if cfg.Address == "" {
		return nil, fmt.Errorf("client address is required")
	}
	if cfg.ClientPrivateKeyB64 == "" {
		return nil, fmt.Errorf("client private key is required")
	}
	if cfg.ServerPublicKeyB64 == "" {
		return nil, fmt.Errorf("server public key is required")
	}
	if _, err := parsePrivateKeyB64(cfg.ClientPrivateKeyB64); err != nil {
		return nil, err
	}
	if _, err := parsePublicKeyB64(cfg.ServerPublicKeyB64); err != nil {
		return nil, err
	}
	return &Client{cfg: cfg}, nil
}

func (c *Client) Connect(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := c.connectOnce(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return ErrClosed
	}
	old := c.conn
	c.conn = conn
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (c *Client) connectOnce(ctx context.Context) (*Conn, error) {
	priv, err := parsePrivateKeyB64(c.cfg.ClientPrivateKeyB64)
	if err != nil {
		return nil, err
	}
	serverPub, err := parsePublicKeyB64(c.cfg.ServerPublicKeyB64)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", c.cfg.Address)
	if err != nil {
		return nil, err
	}
	hs, err := clientHandshake(raw, c.cfg.CommonConfig, priv, serverPub)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	sc, err := newConn(raw, c.cfg.CommonConfig, RoleClient, hs, true, true)
	if err != nil {
		return nil, err
	}
	sc.Start()
	go c.monitor(sc)
	return sc, nil
}

func (c *Client) monitor(sc *Conn) {
	<-sc.Done()
	c.mu.RLock()
	auto := c.cfg.AutoReconnect
	closed := c.closed
	isCurrent := c.conn == sc
	c.mu.RUnlock()
	if !auto || closed || !isCurrent {
		return
	}
	ctx := context.Background()
	_ = c.reconnectLoop(ctx)
}

func (c *Client) reconnectLoop(ctx context.Context) error {
	delay := c.cfg.ReconnectBaseDelay
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		c.mu.RLock()
		closed := c.closed
		c.mu.RUnlock()
		if closed {
			return ErrClosed
		}
		conn, err := c.connectOnce(ctx)
		if err == nil {
			c.mu.Lock()
			old := c.conn
			c.conn = conn
			c.mu.Unlock()
			if old != nil && old != conn {
				_ = old.Close()
			}
			return nil
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		delay *= 2
		if delay > c.cfg.ReconnectMaxDelay {
			delay = c.cfg.ReconnectMaxDelay
		}
	}
}

func (c *Client) getConn() *Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

func (c *Client) Write(ctx context.Context, p []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		sc := c.getConn()
		if sc == nil {
			if !c.cfg.AutoReconnect {
				return ErrReconnectOff
			}
			if err := c.reconnectLoop(ctx); err != nil {
				return err
			}
			continue
		}
		err := sc.Write(p)
		if err == nil {
			return nil
		}
		if !c.cfg.AutoReconnect {
			return err
		}
		if err := c.reconnectLoop(ctx); err != nil {
			return err
		}
	}
}

func (c *Client) Read(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		sc := c.getConn()
		if sc == nil {
			if !c.cfg.AutoReconnect {
				return nil, ErrReconnectOff
			}
			if err := c.reconnectLoop(ctx); err != nil {
				return nil, err
			}
			continue
		}
		b, err := sc.Read(ctx)
		if err == nil {
			return b, nil
		}
		if !c.cfg.AutoReconnect {
			return nil, err
		}
		if err := c.reconnectLoop(ctx); err != nil {
			return nil, err
		}
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	sc := c.conn
	c.conn = nil
	c.mu.Unlock()
	if sc != nil {
		return sc.Close()
	}
	return nil
}
