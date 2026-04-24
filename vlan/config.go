package vlan

import (
	"crypto/sha256"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 总配置结构体（对应整个yaml文件）
type Config struct {
	Common CommonConfig `yaml:"common"`
	Server ServerConfig `yaml:"server"`
	Client ClientConfig `yaml:"client"`
}

// CommonConfig 通用配置
type CommonConfig struct {
	Password string `yaml:"password"`
	Key      []byte
	MTU      int    `yaml:"mtu"`
	Mode     string `yaml:"mode"`
	Proxy    bool   `yaml:"proxy"`
	Gateway  string `yaml:"gateway"`
}

// ServerConfig 服务端配置
type ServerConfig struct {
	Port       int    `yaml:"port"`
	IfName     string `yaml:"ifName"`
	SubnetMask string `yaml:"subnetMask"`
	EgressIf   string `yaml:"egressIf"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	IfName     string `yaml:"ifName"`
	ServerIP   string `yaml:"serverIP"`
	LocalIP    string `yaml:"localIP"`
	SubnetMask string `yaml:"subnetMask"`
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
	// 根据密码生成32位密钥
	Conf.Common.Key = get32Key(Conf.Common.Password)
	keyLen := len(Conf.Common.Key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		log.Fatalf("AES key 长度错误: %d，必须是 16/24/32 字节", keyLen)
	}

	if Conf.Common.MTU <= 0 || Conf.Common.MTU > 9000 {
		log.Fatalf("MTU 配置异常: %d", Conf.Common.MTU)
	}

	Conf.Common.Mode = strings.ToUpper(Conf.Common.Mode)

}

func get32Key(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
