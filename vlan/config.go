package vlan

import (
	"NetworkSetup/secure"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net"
	"os"

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
	PrivateKey    string `yaml:"privateKey"`
	PeerPublicKey string `yaml:"peerPublicKey"`
	Identity      secure.Identity
	PeerStatic    []byte
	MTU           int    `yaml:"mtu"`
	Proxy         bool   `yaml:"proxy"`
	Gateway       string `yaml:"gateway"`
	SubnetMask    string `yaml:"subnetMask"`
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
	// 第一步：把配置文件完整读入内存。
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("加载配置文件失败：%v", err)
	}
	// 第二步：将 YAML 反序列化到全局配置结构体 Conf。
	err = yaml.Unmarshal(data, &Conf)
	if err != nil {
		log.Fatalf("解析配置文件失败：%v", err)
	}

	// 第三步：做字段合法性校验 + 衍生字段填充（例如密钥解析）。
	validateConfig()
}

func validateConfig() {
	// privateKey / peerPublicKey 在 YAML 中是字符串，
	// 这里会解析成后续握手加密真正要用的二进制对象。
	if Conf.Common.PrivateKey != "" {
		identity, err := secure.ParsePrivateKey(Conf.Common.PrivateKey)
		if err != nil {
			log.Fatalf("解析privateKey失败: %v", err)
		}
		Conf.Common.Identity = identity
	}
	if Conf.Common.PeerPublicKey != "" {
		peer, err := secure.ParsePublicKey(Conf.Common.PeerPublicKey)
		if err != nil {
			log.Fatalf("解析peerPublicKey失败: %v", err)
		}
		Conf.Common.PeerStatic = peer
	}

	// 端口属于高风险配置，先做范围检查。
	if Conf.Server.Port <= 0 || Conf.Server.Port > 65535 {
		log.Fatalf("非法服务端端口: %d", Conf.Server.Port)
	}
	// 客户端目标地址不能为空（格式校验由 Dial 时再次兜底）。
	if Conf.Client.ServerIP == "" {
		log.Fatalf("客户端ServerIP不能为空")
	}
	// 网关、掩码必须能被正确解析。
	if net.ParseIP(Conf.Common.Gateway) == nil {
		log.Fatalf("非法网关地址: %s", Conf.Common.Gateway)
	}
	if _, err := maskToPrefix(Conf.Common.SubnetMask); err != nil {
		log.Fatalf("非法子网掩码: %s, 错误: %v", Conf.Common.SubnetMask, err)
	}
}

func generateTunnelKey() (string, error) {
	// 生成 32 字节随机密钥，并编码成 base64 字符串便于存储/传输。
	key := make([]byte, 32) // 32字节 = AES-256
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
