package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/LwyV-Labs/LwyV-Net/secure"

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
	PrivateKey     string          `yaml:"privateKey"`
	PeerPublicKeys []string        `yaml:"peerPublicKeys"`
	Identity       secure.Identity `yaml:"-"`
	PeerStatic     []byte          `yaml:"-"`
	MTU            int             `yaml:"mtu"`
	Proxy          bool            `yaml:"proxy"`
	Gateway        string          `yaml:"gateway"`
	SubnetMask     string          `yaml:"subnetMask"`
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

const path = "config.yaml"

var allowedPeerStaticSet map[string]struct{}

// LoadConfig 自动加载配置文件
func LoadConfig() Config {
	allowedPeerStaticSet = make(map[string]struct{})
	Conf := Config{}

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
	// 若配置未填写本机私钥，则启动时自动生成并回写配置，避免首次部署手工操作。
	if strings.TrimSpace(Conf.Common.PrivateKey) == "" {
		publicKey, genErr := GenerateAndWriteKeys(path, "")
		if genErr != nil {
			log.Fatalf("common.privateKey为空且自动初始化失败: %v", genErr)
		}
		log.Printf("✅ 检测到 common.privateKey 为空，已自动生成并写入配置文件: %s", path)
		log.Printf("本机 publicKey: %s", publicKey)
		log.Printf("请把该 publicKey 填到对端 config.yaml 的 common.peerPublicKeys[0]")
		// 回写后重新加载一次配置，确保内存中的 Conf 与磁盘一致。
		data, err = os.ReadFile(path)
		if err != nil {
			log.Fatalf("重新加载配置文件失败：%v", err)
		}
		if err = yaml.Unmarshal(data, &Conf); err != nil {
			log.Fatalf("重新解析配置文件失败：%v", err)
		}
	}

	// 第三步：做字段合法性校验 + 衍生字段填充（例如密钥解析）。
	// privateKey / peerPublicKey 在 YAML 中是字符串，
	// 这里会解析成后续握手加密真正要用的二进制对象。
	if Conf.Common.PrivateKey != "" {
		identity, err := secure.ParsePrivateKey(Conf.Common.PrivateKey)
		if err != nil {
			log.Fatalf("解析privateKey失败: %v", err)
		}
		Conf.Common.Identity = identity
	}
	for i, key := range Conf.Common.PeerPublicKeys {
		peer, err := secure.ParsePublicKey(key)
		if err != nil {
			log.Fatalf("解析peerPublicKeys[%d]失败: %v", i, err)
		}
		if i == 0 {
			// IK 作为发起方需要预先知道服务端静态公钥，这里约定使用列表首项。
			Conf.Common.PeerStatic = append([]byte(nil), peer...)
		}
		if allowedPeerStaticSet == nil {
			allowedPeerStaticSet = make(map[string]struct{})
		}
		allowedPeerStaticSet[string(peer)] = struct{}{}
	}

	// 网关、掩码必须能被正确解析。
	if net.ParseIP(Conf.Common.Gateway) == nil {
		log.Fatalf("非法网关地址: %s", Conf.Common.Gateway)
	}
	if _, err := MaskToPrefix(Conf.Common.SubnetMask); err != nil {
		log.Fatalf("非法子网掩码: %s, 错误: %v", Conf.Common.SubnetMask, err)
	}
	return Conf
}

func IsPeerStaticAllowed(remotePub []byte) bool {
	if len(allowedPeerStaticSet) == 0 {
		return true
	}
	_, ok := allowedPeerStaticSet[string(remotePub)]
	return ok
}

func MaskToPrefix(mask string) (int, error) {
	// 把点分十进制掩码（255.255.255.0）转成前缀长度（24）。
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return 0, fmt.Errorf("非法子网掩码: %s", mask)
	}
	ones, bits := net.IPMask(ip).Size()
	if bits != 32 {
		return 0, fmt.Errorf("非法子网掩码: %s", mask)
	}
	return ones, nil
}

// GenerateAndWriteKeys 生成一组 Noise IK / ECDH 长期身份密钥，并写入配置文件。
//
// 注意：
//   - privateKey 是“本机”的长期私钥，会自动写入 common.privateKey。
//   - 返回值 publicKey 是“本机”的长期公钥，需要复制到对端配置的 common.peerPublicKeys[0]。
//   - peerPublicKey 传空字符串时，不会覆盖配置中已有的 common.peerPublicKeys。
//   - peerPublicKey 非空时，会校验其为 base64 32 bytes，并写入 common.peerPublicKeys 的第 1 项。
func GenerateAndWriteKeys(path string, peerPublicKey string) (publicKey string, err error) {
	privateKey, publicKey, err := generateNoiseKeyPair()
	if err != nil {
		return "", err
	}

	if _, err := secure.ParsePrivateKey(privateKey); err != nil {
		return "", err
	}
	if _, err := secure.ParsePublicKey(publicKey); err != nil {
		return "", err
	}
	if peerPublicKey != "" {
		if _, err := secure.ParsePublicKey(peerPublicKey); err != nil {
			return "", fmt.Errorf("peerPublicKey非法: %w", err)
		}
	}

	if err := writeKeysToConfig(path, privateKey, peerPublicKey); err != nil {
		return "", err
	}
	return publicKey, nil
}

func generateNoiseKeyPair() (privateKey string, publicKey string, err error) {
	// X25519 是 Noise IK / ECDH 常用的 32 字节 Curve25519 密钥。
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(private.Bytes()),
		base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()),
		nil
}

func writeKeysToConfig(path string, privateKey string, peerPublicKey string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}
	if privateKey != "" {
		cfg.Common.PrivateKey = privateKey
	}
	if peerPublicKey != "" {
		cfg.Common.PeerPublicKeys = []string{peerPublicKey}
	}

	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("编码配置文件失败: %w", err)
	}

	perm := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	if err := os.WriteFile(path, out, perm); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	return nil
}
