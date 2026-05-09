package config

import "github.com/LwyV-Labs/LwyV-Net/secure"

// Config 总配置结构体（对应整个yaml文件）
type Config struct {
	Server ServerConfig `json:"server"`
	Client ClientConfig `json:"client"`
}

type BaseConfig struct {
	PrivateKey     string          `json:"privateKey"`
	PeerPublicKeys []string        `json:"peerPublicKeys"`
	Identity       secure.Identity `json:"-"`
	PeerStatic     []byte          `json:"-"`
	Proxy          bool            `json:"proxy"`
}

// ServerConfig 服务端配置
type ServerConfig struct {
	BaseConfig
	MTU      int         `json:"mtu"`
	Port     int         `json:"port"`
	IfName   string      `json:"ifName"`
	EgressIf string      `json:"egressIf"`
	VDHCP    VDHCPConfig `json:"vdhcp"`
}

type ServerEndpoint struct {
	Name      string `json:"name"`
	ServerIP  string `json:"ip"`
	PublicKey string `json:"publicKey"`
	MTU       int    `json:"mtu"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	BaseConfig
	IfName      string           `json:"ifName"`
	Servers     []ServerEndpoint `json:"servers"`
	MTU         int              `json:"-"`
	SelectedIdx int              `json:"-"`
}

// VDHCPConfig 虚拟DHCP配置
type VDHCPConfig struct {
	StartIP    string `json:"startIP"`
	EndIP      string `json:"endIP"`
	SubnetMask string `json:"subnetMask"`
	Gateway    string `json:"gateway"`
}
