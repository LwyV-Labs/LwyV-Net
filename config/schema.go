package config

import "time"

type ClientConfig struct {
	PrivateKey      string          `json:"privateKey"`
	Server          string          `json:"server"`
	ServerPublicKey string          `json:"serverPublicKey"`
	IfName          string          `json:"ifName"`
	Proxy           bool            `json:"proxy"`
	TCP             TransportConfig `json:"tcp,omitempty"`
}

type ServerConfig struct {
	PrivateKey string          `json:"privateKey"`
	Port       int             `json:"port"`
	IfName     string          `json:"ifName"`
	MTU        int             `json:"mtu"`
	Proxy      bool            `json:"proxy"`
	VDHCP      VDHCPConfig     `json:"vdhcp"`
	TCP        TransportConfig `json:"tcp,omitempty"`
}

type VDHCPConfig struct {
	StartIP    string   `json:"startIP"`
	EndIP      string   `json:"endIP"`
	SubnetMask string   `json:"subnetMask"`
	Gateway    string   `json:"gateway"`
	DNS        []string `json:"dns"`
}

// TransportConfig is optional. A zero value keeps the package defaults.
// Existing client.json/server.json remain compatible because this field is omitted.
type TransportConfig struct {
	ReadTimeoutSeconds       int `json:"readTimeoutSeconds,omitempty"`
	WriteTimeoutSeconds      int `json:"writeTimeoutSeconds,omitempty"`
	HeartbeatBaseSeconds     int `json:"heartbeatBaseSeconds,omitempty"`
	HeartbeatJitterSeconds   int `json:"heartbeatJitterSeconds,omitempty"`
	KeyRotateIntervalSeconds int `json:"keyRotateIntervalSeconds,omitempty"`
	OldKeyGraceSeconds       int `json:"oldKeyGraceSeconds,omitempty"`
	ReconnectBaseSeconds     int `json:"reconnectBaseSeconds,omitempty"`
	ReconnectJitterSeconds   int `json:"reconnectJitterSeconds,omitempty"`
}

func secondsOrDefault(v int, d time.Duration) time.Duration {
	if v <= 0 {
		return d
	}
	return time.Duration(v) * time.Second
}

func (c TransportConfig) ClientReadTimeout() time.Duration {
	return secondsOrDefault(c.ReadTimeoutSeconds, 10*time.Second)
}

func (c TransportConfig) ClientWriteTimeout() time.Duration {
	return secondsOrDefault(c.WriteTimeoutSeconds, 8*time.Second)
}

func (c TransportConfig) ServerReadTimeout() time.Duration {
	return secondsOrDefault(c.ReadTimeoutSeconds, 60*time.Second)
}

func (c TransportConfig) ServerWriteTimeout() time.Duration {
	return secondsOrDefault(c.WriteTimeoutSeconds, 15*time.Second)
}

func (c TransportConfig) ClientHeartbeatBase() time.Duration {
	return secondsOrDefault(c.HeartbeatBaseSeconds, 4*time.Second)
}

func (c TransportConfig) ClientHeartbeatJitter() time.Duration {
	return secondsOrDefault(c.HeartbeatJitterSeconds, time.Second)
}

func (c TransportConfig) ServerHeartbeatBase() time.Duration {
	return secondsOrDefault(c.HeartbeatBaseSeconds, 10*time.Second)
}

func (c TransportConfig) ServerHeartbeatJitter() time.Duration {
	return secondsOrDefault(c.HeartbeatJitterSeconds, 5*time.Second)
}

func (c TransportConfig) KeyRotateInterval() time.Duration {
	return secondsOrDefault(c.KeyRotateIntervalSeconds, 45*time.Second)
}

func (c TransportConfig) OldKeyGrace() time.Duration {
	return secondsOrDefault(c.OldKeyGraceSeconds, 30*time.Second)
}

func (c TransportConfig) ClientOldKeyGrace() time.Duration {
	return secondsOrDefault(c.OldKeyGraceSeconds, 20*time.Second)
}

func (c TransportConfig) ReconnectBase() time.Duration {
	return secondsOrDefault(c.ReconnectBaseSeconds, time.Second)
}

func (c TransportConfig) ReconnectJitter() time.Duration {
	return secondsOrDefault(c.ReconnectJitterSeconds, 3*time.Second)
}
