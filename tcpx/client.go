package tcpx

import (
	"context"
	"crypto/ecdh"
	"net"
	"sync"
	"time"
)

type ClientConfig struct {
	BaseConfig
	Addr               string
	ServerPublicKeyHex string

	// Android 用它调用 VpnService.protect(fd)
	DialContext func(ctx context.Context, network string, addr string) (net.Conn, error)

	ReconnectBase   time.Duration
	ReconnectJitter time.Duration

	OnConnect    func(*SecureConn)
	OnDisconnect func(error)
	OnMessage    func(*SecureConn, []byte)
}

type Client struct {
	cfg       ClientConfig
	serverPub *ecdh.PublicKey

	mu      sync.Mutex
	conn    *SecureConn
	running bool
	closed  bool
	cancel  context.CancelFunc
}

func NewClient(cfg ClientConfig) (*Client, error) {
	cfg.BaseConfig.setDefaults()
	if cfg.ReconnectBase == 0 {
		cfg.ReconnectBase = time.Second
	}
	if cfg.ReconnectJitter == 0 {
		cfg.ReconnectJitter = 3 * time.Second
	}
	pub, err := ParsePublicKeyHex(cfg.ServerPublicKeyHex)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, serverPub: pub}, nil
}

func (c *Client) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return ErrReconnectStop
	}
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.running = true
	c.closed = false
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.running = false
		c.conn = nil
		c.mu.Unlock()
		cancel()
	}()

	for {
		if ctx.Err() != nil || c.isClosed() {
			return nil
		}
		err := c.connectAndServe(ctx)
		if ctx.Err() != nil || c.isClosed() {
			return nil
		}
		if err != nil && c.cfg.OnDisconnect != nil {
			c.cfg.OnDisconnect(err)
		}
		if !sleepContext(ctx, randomInterval(c.cfg.ReconnectBase, c.cfg.ReconnectJitter)) {
			return nil
		}
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	cancel := c.cancel
	conn := c.conn
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *Client) Write(payload []byte) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return ErrClosed
	}
	return conn.Write(payload)
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *Client) connectAndServe(ctx context.Context) error {
	var (
		raw net.Conn
		err error
	)

	if c.cfg.DialContext != nil {
		raw, err = c.cfg.DialContext(ctx, "tcp", c.cfg.Addr)
	} else {
		dialer := &net.Dialer{}
		raw, err = dialer.DialContext(ctx, "tcp", c.cfg.Addr)
	}

	if err != nil {
		return err
	}

	secure, err := clientHandshake(raw, c.cfg.BaseConfig, c.serverPub)
	if err != nil {
		_ = raw.Close()
		return err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = secure.Close()
		return ErrClosed
	}
	c.conn = secure
	c.mu.Unlock()

	if c.cfg.OnConnect != nil {
		c.cfg.OnConnect(secure)
	}

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		_ = secure.Close()
		c.mu.Lock()
		if c.conn == secure {
			c.conn = nil
		}
		c.mu.Unlock()
	}()

	go c.heartbeatLoop(serveCtx, secure)

	for {
		msg, err := secure.Read()
		if err != nil {
			return err
		}
		if c.cfg.OnMessage != nil {
			c.cfg.OnMessage(secure, msg)
		}
	}
}

func (c *Client) heartbeatLoop(ctx context.Context, conn *SecureConn) {
	for {
		if !sleepContext(ctx, randomInterval(c.cfg.HeartbeatBase, c.cfg.HeartbeatJitter)) {
			return
		}
		if err := conn.SendPing(); err != nil {
			_ = conn.Close()
			return
		}
	}
}
