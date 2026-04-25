package vlan

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 总配置结构体（对应整个yaml文件）
type Config struct {
	Common CommonConfig `yaml:"common"`
	Server ServerConfig `yaml:"server"`
	Client ClientConfig `yaml:"client"`
	VDHCP  VDHCPConfig  `yaml:"vdhcp"`
}

// CommonConfig 通用配置
type CommonConfig struct {
	Password   string `yaml:"password"`
	Key        []byte
	MTU        int    `yaml:"mtu"`
	Mode       string `yaml:"mode"`
	Proxy      bool   `yaml:"proxy"`
	Gateway    string `yaml:"gateway"`
	SubnetMask string `yaml:"subnetMask"`
}

// ServerConfig 服务端配置
type ServerConfig struct {
	Port     int    `yaml:"port"`
	IfName   string `yaml:"ifName"`
	EgressIf string `yaml:"egressIf"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	IfName   string `yaml:"ifName"`
	ServerIP string `yaml:"serverIP"`
}

// VDHCPConfig 虚拟DHCP配置
type VDHCPConfig struct {
	StartIP string `yaml:"startIP"`
	EndIP   string `yaml:"endIP"`
}

var Conf Config

// InitConfig 加载配置文件
func InitConfig(path string) {
	// 读取文件
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("加载配置文件失败：%v", err)
	}
	// 解析yaml到结构体
	err = yaml.Unmarshal(data, &Conf)
	if err != nil {
		log.Fatalf("解析配置文件失败：%v", err)
	}

	validateConfig()
}

func validateConfig() {
	Conf.Common.Key = get32Key(Conf.Common.Password)

	if Conf.Server.Port <= 0 || Conf.Server.Port > 65535 {
		log.Fatalf("非法服务端端口: %d", Conf.Server.Port)
	}
	// 检查客户端ServerIP
	if Conf.Client.ServerIP == "" {
		log.Fatalf("客户端ServerIP不能为空")
	}
	// 检查网关和子网掩码
	if net.ParseIP(Conf.Common.Gateway) == nil {
		log.Fatalf("非法网关地址: %s", Conf.Common.Gateway)
	}
	if _, err := maskToPrefix(Conf.Common.SubnetMask); err != nil {
		log.Fatalf("非法子网掩码: %s, 错误: %v", Conf.Common.SubnetMask, err)
	}
	Conf.Common.Mode = strings.ToUpper(Conf.Common.Mode)
}

func get32Key(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func generateTunnelKey() (string, error) {
	key := make([]byte, 32) // 32字节 = AES-256
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
