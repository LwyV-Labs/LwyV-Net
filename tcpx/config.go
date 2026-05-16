package tcpx

import "time"

const (
	DefaultMagic        uint32 = 0x54435058 // "TCPX"
	DefaultVersion      uint16 = 1
	DefaultMaxPayload          = 4 << 20 // 4 MiB
	DefaultReplayWindow        = 64
)

type BaseConfig struct {
	Magic        uint32
	Version      uint16
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxPayload   uint32

	HeartbeatBase   time.Duration
	HeartbeatJitter time.Duration

	KeyRotateInterval time.Duration
	OldKeyGrace       time.Duration
	ReplayWindow      uint64
}

func (c *BaseConfig) setDefaults() {
	if c.Magic == 0 {
		c.Magic = DefaultMagic
	}
	if c.Version == 0 {
		c.Version = DefaultVersion
	}
	if c.MaxPayload == 0 {
		c.MaxPayload = DefaultMaxPayload
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 45 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 10 * time.Second
	}
	if c.HeartbeatBase == 0 {
		c.HeartbeatBase = 15 * time.Second
	}
	if c.HeartbeatJitter == 0 {
		c.HeartbeatJitter = 5 * time.Second
	}
	if c.KeyRotateInterval == 0 {
		c.KeyRotateInterval = 10 * time.Minute
	}
	if c.OldKeyGrace == 0 {
		c.OldKeyGrace = 2 * time.Minute
	}
	if c.ReplayWindow == 0 {
		c.ReplayWindow = DefaultReplayWindow
	}
}
