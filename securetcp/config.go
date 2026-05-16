package securetcp

import "time"

const (
	DefaultMagic           uint32 = 0x4c575954 // "LWYT"
	DefaultVersion         byte   = 1
	DefaultMaxFramePayload        = 4 << 20 // 4 MiB
)

type CommonConfig struct {
	Magic           uint32
	Version         byte
	MaxFramePayload uint32
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration

	HeartbeatBase   time.Duration
	HeartbeatJitter time.Duration

	RekeyInterval time.Duration
	OldKeyGrace   time.Duration
	ReplayWindow  uint64
}

func (c *CommonConfig) normalize() {
	if c.Magic == 0 {
		c.Magic = DefaultMagic
	}
	if c.Version == 0 {
		c.Version = DefaultVersion
	}
	if c.MaxFramePayload == 0 {
		c.MaxFramePayload = DefaultMaxFramePayload
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 60 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 15 * time.Second
	}
	if c.HeartbeatBase <= 0 {
		c.HeartbeatBase = 20 * time.Second
	}
	if c.HeartbeatJitter < 0 {
		c.HeartbeatJitter = 0
	}
	if c.RekeyInterval <= 0 {
		c.RekeyInterval = 10 * time.Minute
	}
	if c.OldKeyGrace <= 0 {
		c.OldKeyGrace = 30 * time.Second
	}
	if c.ReplayWindow == 0 {
		c.ReplayWindow = 4096
	}
}

type ClientConfig struct {
	CommonConfig
	Address string

	ClientPrivateKeyB64 string
	ServerPublicKeyB64  string

	AutoReconnect      bool
	ReconnectBaseDelay time.Duration
	ReconnectMaxDelay  time.Duration

	OnReconnect func()
}

func (c *ClientConfig) normalize() {
	c.CommonConfig.normalize()
	if c.ReconnectBaseDelay <= 0 {
		c.ReconnectBaseDelay = 500 * time.Millisecond
	}
	if c.ReconnectMaxDelay <= 0 {
		c.ReconnectMaxDelay = 10 * time.Second
	}
}

type ServerConfig struct {
	CommonConfig
	Address string

	ServerPrivateKeyB64 string

	// ServerInitiatesRekey is normally false. The client already rekeys automatically.
	// Turn it on only when you know both sides can tolerate simultaneous rekey attempts.
	ServerInitiatesRekey bool
}

func (c *ServerConfig) normalize() {
	c.CommonConfig.normalize()
}
