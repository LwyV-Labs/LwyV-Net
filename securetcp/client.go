package securetcp

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Client manages client-side dialing, optional session resumption and optional reconnect.
type Client struct {
	addr string
	cfg  Config

	mu     sync.Mutex
	conn   *Conn
	ticket *SessionTicket
	closed bool
}

func NewClient(addr string, cfg Config) (*Client, error) {
	if err := cfg.NormalizeClient(); err != nil {
		return nil, err
	}
	return &Client{addr: addr, cfg: cfg}, nil
}

func (c *Client) CurrentConn() *Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// Connect establishes one secure connection. If a valid ticket exists, it tries resumption first.
func (c *Client) Connect(ctx context.Context) (*Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	ticket := c.ticket.clone()
	c.mu.Unlock()

	conn, res, err := c.connectOnce(ctx, ticket)
	if err != nil && ticket != nil {
		// Server may reject stale resume tickets. Retry once with a full handshake.
		conn, res, err = c.connectOnce(ctx, nil)
	}
	if err != nil {
		return nil, err
	}
	secureConn, err := newConn(conn, c.cfg, roleClient, res.master)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	c.mu.Lock()
	c.conn = secureConn
	c.ticket = res.ticket.clone()
	c.mu.Unlock()
	secureConn.onClose = func(error) {
		c.mu.Lock()
		if c.conn == secureConn {
			c.conn = nil
		}
		c.mu.Unlock()
	}
	return secureConn, nil
}

func (c *Client) connectOnce(ctx context.Context, ticket *SessionTicket) (net.Conn, handshakeResult, error) {
	d := &net.Dialer{Timeout: c.cfg.DialTimeout}
	nc, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, handshakeResult{}, err
	}
	res, err := clientHandshake(nc, c.cfg, ticket)
	if err != nil {
		_ = nc.Close()
		return nil, handshakeResult{}, err
	}
	return nc, res, nil
}

// Run connects, calls handler for each connection, and reconnects after accidental disconnects.
// It stops on ctx cancellation, Client.Close, handler return with active local close, or when AutoReconnect is false.
func (c *Client) Run(ctx context.Context, handler Handler) error {
	backoff := c.cfg.ReconnectInitialBackoff
	for {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return ErrClosed
		}
		conn, err := c.Connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !c.cfg.AutoReconnect {
				return err
			}
			if !sleepContext(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, c.cfg.ReconnectMaxBackoff)
			continue
		}
		backoff = c.cfg.ReconnectInitialBackoff
		if handler != nil {
			handler(conn)
		}
		select {
		case <-conn.Done():
		case <-ctx.Done():
			_ = conn.Close()
			return ctx.Err()
		}
		if conn.ActiveClose() || !c.cfg.AutoReconnect {
			if err := conn.CloseError(); err != nil && !errors.Is(err, ErrClosed) {
				return err
			}
			return nil
		}
		if !sleepContext(ctx, backoff) {
			return ctx.Err()
		}
		backoff = nextBackoff(backoff, c.cfg.ReconnectMaxBackoff)
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	n := cur * 2
	if n <= 0 || n > max {
		return max
	}
	return n
}
