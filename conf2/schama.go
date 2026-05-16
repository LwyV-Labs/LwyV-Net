package conf2

type ClientConfig struct {
	PrivateKey      string `json:"privateKey"`
	Server          string `json:"server"`
	ServerPublicKey string `json:"serverPublicKey"`
	IfName          string `json:"ifName"`
	MTU             int    `json:"mtu"`
	Proxy           bool   `json:"proxy"`
}

type ServerConfig struct {
	PrivateKey string      `json:"privateKey"`
	Port       int         `json:"port"`
	IfName     string      `json:"ifName"`
	MTU        int         `json:"mtu"`
	Proxy      bool        `json:"proxy"`
	VDHCP      VDHCPConfig `json:"vdhcp"`
}

type VDHCPConfig struct {
	StartIP    string `json:"startIP"`
	EndIP      string `json:"endIP"`
	SubnetMask string `json:"subnetMask"`
	Gateway    string `json:"gateway"`
}
