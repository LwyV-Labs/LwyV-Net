package securetcp

import (
	"context"
	"sync"
	"time"
)

// MobileClient is a gomobile-friendly wrapper for Android/Kotlin.
// Kotlin can call Start, Stop, Write and Read without dealing with Go channels.
type MobileClient struct {
	client  *Client
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	started bool
	lastErr string
}

// NewMobileClient creates a mobile wrapper. serverPublicKey must be the server X25519 public key.
// clientPrivateKey may be nil/empty; in that case a temporary identity is generated.
func NewMobileClient(addr string, serverPublicKey []byte, clientPrivateKey []byte) (*MobileClient, error) {
	cfg := Config{
		ServerStaticPublicKey:  append([]byte(nil), serverPublicKey...),
		ClientStaticPrivateKey: append([]byte(nil), clientPrivateKey...),
		AllowResume:            true,
		AutoReconnect:          true,
	}
	client, err := NewClient(addr, cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &MobileClient{client: client, ctx: ctx, cancel: cancel}, nil
}

func (m *MobileClient) Start() error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()
	go func() {
		err := m.client.Run(m.ctx, func(conn *Conn) {})
		if err != nil && err != context.Canceled && err != ErrClosed {
			m.mu.Lock()
			m.lastErr = err.Error()
			m.mu.Unlock()
		}
	}()
	return nil
}

func (m *MobileClient) Stop() {
	m.cancel()
	_ = m.client.Close()
}

func (m *MobileClient) IsConnected() bool {
	conn := m.client.CurrentConn()
	return conn != nil && !conn.IsClosed()
}

func (m *MobileClient) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

func (m *MobileClient) Write(data []byte) error {
	conn := m.client.CurrentConn()
	if conn == nil || conn.IsClosed() {
		return ErrNotConnected
	}
	return conn.WriteMessage(data)
}

// Read waits up to timeoutMillis for a DATA frame. timeoutMillis <= 0 means wait forever.
func (m *MobileClient) Read(timeoutMillis int) ([]byte, error) {
	conn := m.client.CurrentConn()
	if conn == nil || conn.IsClosed() {
		return nil, ErrNotConnected
	}
	if timeoutMillis <= 0 {
		return conn.ReadMessage()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMillis)*time.Millisecond)
	defer cancel()
	msg, err := conn.ReadMessageContext(ctx)
	if err == context.DeadlineExceeded {
		return nil, ErrReadTimeout
	}
	return msg, err
}
