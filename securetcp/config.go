package securetcp

import (
	"errors"
	"time"
)

// Config controls protocol, timeout, heartbeat, crypto and reconnect behavior.
// The zero value is usable for most fields after Normalize is called, except
// client-side ServerStaticPublicKey, which must be provided for server identity verification.
type Config struct {
	// Protocol.
	Magic        uint16
	MaxFrameSize uint32

	// Heartbeat.
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration

	// I/O deadlines. A zero value disables that deadline.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// Key rotation. Set RekeyInterval <= 0 to disable automatic rekey.
	RekeyInterval time.Duration
	OldKeyGrace   time.Duration

	// Session resumption.
	AllowResume      bool
	SessionTicketTTL time.Duration

	// Dial/reconnect.
	DialTimeout             time.Duration
	AutoReconnect           bool
	ReconnectInitialBackoff time.Duration
	ReconnectMaxBackoff     time.Duration

	// Static X25519 identity keys.
	// Server: ServerStaticPrivateKey is required unless GenerateMissingKeys is true.
	// Client: ServerStaticPublicKey is required. ClientStaticPrivateKey may be generated.
	ServerStaticPrivateKey []byte
	ServerStaticPublicKey  []byte
	ClientStaticPrivateKey []byte
	ClientStaticPublicKey  []byte

	// GenerateMissingKeys generates missing server/client private keys in Normalize.
	// For production servers, persist the generated server private key instead of rotating it every start.
	GenerateMissingKeys bool

	// InboundBuffer controls the number of decrypted DATA frames buffered by Conn.
	InboundBuffer int
}

const (
	DefaultMagic        uint16 = 0x4c56 // 'LV'
	DefaultMaxFrameSize        = 4 * 1024 * 1024
)

var (
	ErrClosed            = errors.New("securetcp: closed")
	ErrFrameTooLarge     = errors.New("securetcp: frame too large")
	ErrBadFrame          = errors.New("securetcp: bad frame")
	ErrBadMagic          = errors.New("securetcp: bad magic")
	ErrBadVersion        = errors.New("securetcp: bad version")
	ErrHandshakeFailed   = errors.New("securetcp: handshake failed")
	ErrMissingServerKey  = errors.New("securetcp: missing server static public key")
	ErrMissingPrivateKey = errors.New("securetcp: missing private key")
	ErrMessageTooLarge   = errors.New("securetcp: message too large")
	ErrNotConnected      = errors.New("securetcp: not connected")
	ErrReadTimeout       = errors.New("securetcp: read timeout")
)

func (c *Config) NormalizeClient() error {
	c.applyDefaults()
	if len(c.ServerStaticPublicKey) != x25519PublicKeySize {
		return ErrMissingServerKey
	}
	if len(c.ClientStaticPrivateKey) == 0 {
		kp, err := GenerateKeyPair()
		if err != nil {
			return err
		}
		c.ClientStaticPrivateKey = kp.Private
		c.ClientStaticPublicKey = kp.Public
	} else if len(c.ClientStaticPublicKey) == 0 {
		pub, err := PublicKeyFromPrivate(c.ClientStaticPrivateKey)
		if err != nil {
			return err
		}
		c.ClientStaticPublicKey = pub
	}
	return nil
}

func (c *Config) NormalizeServer() error {
	c.applyDefaults()
	if len(c.ServerStaticPrivateKey) == 0 {
		if !c.GenerateMissingKeys {
			return ErrMissingPrivateKey
		}
		kp, err := GenerateKeyPair()
		if err != nil {
			return err
		}
		c.ServerStaticPrivateKey = kp.Private
		c.ServerStaticPublicKey = kp.Public
	} else if len(c.ServerStaticPublicKey) == 0 {
		pub, err := PublicKeyFromPrivate(c.ServerStaticPrivateKey)
		if err != nil {
			return err
		}
		c.ServerStaticPublicKey = pub
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Magic == 0 {
		c.Magic = DefaultMagic
	}
	if c.MaxFrameSize == 0 {
		c.MaxFrameSize = DefaultMaxFrameSize
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = 15 * time.Second
	}
	if c.HeartbeatTimeout == 0 {
		c.HeartbeatTimeout = 45 * time.Second
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 60 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 10 * time.Second
	}
	if c.RekeyInterval == 0 {
		c.RekeyInterval = 30 * time.Minute
	}
	if c.OldKeyGrace == 0 {
		c.OldKeyGrace = 2 * time.Minute
	}
	if c.SessionTicketTTL == 0 {
		c.SessionTicketTTL = 10 * time.Minute
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.ReconnectInitialBackoff == 0 {
		c.ReconnectInitialBackoff = time.Second
	}
	if c.ReconnectMaxBackoff == 0 {
		c.ReconnectMaxBackoff = 30 * time.Second
	}
	if c.InboundBuffer <= 0 {
		c.InboundBuffer = 64
	}
}
