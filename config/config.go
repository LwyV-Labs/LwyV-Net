package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/LwyV-Labs/LwyV-Net/secure"
)

// Config 总配置结构体（对应整个yaml文件）
type Config struct {
	Common CommonConfig `json:"common"`
	Server ServerConfig `json:"server"`
	Client ClientConfig `json:"client"`
	VDHCP  VDHCPConfig  `json:"vdhcp"`
}

type ServerFileConfig struct {
	Common CommonConfig `json:"common"`
	Server ServerConfig `json:"server"`
	VDHCP  VDHCPConfig  `json:"vdhcp"`
}

type ClientFileConfig struct {
	Common CommonConfig `json:"common"`
	Client ClientConfig `json:"client"`
}

// CommonConfig 通用配置
type CommonConfig struct {
	PrivateKey     string          `json:"privateKey"`
	PeerPublicKeys []string        `json:"peerPublicKeys"`
	Identity       secure.Identity `json:"-"`
	PeerStatic     []byte          `json:"-"`
	MTU            int             `json:"mtu"`
	Proxy          bool            `json:"proxy"`
	SubnetMask     string          `json:"subnetMask"`
}

// ServerConfig 服务端配置
type ServerConfig struct {
	Port     int    `json:"port"`
	IfName   string `json:"ifName"`
	EgressIf string `json:"egressIf"`
}

type ServerEndpoint struct {
	Name      string `json:"name"`
	ServerIP  string `json:"ip"`
	PublicKey string `json:"publicKey"`
	MTU       int    `json:"mtu"`
}

// ClientConfig 客户端配置
type ClientConfig struct {
	IfName      string           `json:"ifName"`
	Servers     []ServerEndpoint `json:"servers"`
	SelectedIdx int              `json:"-"`
}

// VDHCPConfig 虚拟DHCP配置
type VDHCPConfig struct {
	StartIP    string `json:"startIP"`
	EndIP      string `json:"endIP"`
	SubnetMask string `json:"subnetMask"`
	Gateway    string `json:"gateway"`
}

const (
	serverConfigPath = "server.json"
	clientConfigPath = "client.json"
)

var allowedPeerStaticSet map[string]struct{}

func LoadClientConfig(serverIndex int) Config {
	allowedPeerStaticSet = make(map[string]struct{})
	Conf := Config{}
	path := clientConfigPath
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("加载配置文件失败：%v", err)
	}
	clientConf := ClientFileConfig{}
	if err = json.Unmarshal(data, &clientConf); err != nil {
		log.Fatalf("解析配置文件失败：%v", err)
	}
	Conf.Common = clientConf.Common
	Conf.Client = clientConf.Client
	validateClientConfig(&Conf, serverIndex)
	return Conf
}

func LoadServerConfig() Config {
	allowedPeerStaticSet = make(map[string]struct{})
	Conf := Config{}
	path := serverConfigPath
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("加载配置文件失败：%v", err)
	}
	serverConf := ServerFileConfig{}
	if err = json.Unmarshal(data, &serverConf); err != nil {
		log.Fatalf("解析配置文件失败：%v", err)
	}
	Conf.Common = serverConf.Common
	Conf.Server = serverConf.Server
	Conf.VDHCP = serverConf.VDHCP
	validateServerConfig(&Conf)
	return Conf
}

func validateClientConfig(conf *Config, serverIndex int) {
	if len(conf.Client.Servers) == 0 {
		log.Fatalf("client.servers 不能为空")
	}
	if serverIndex < 1 || serverIndex > len(conf.Client.Servers) {
		log.Fatalf("服务端序号无效: %d，合法范围: 1-%d", serverIndex, len(conf.Client.Servers))
	}
	selected := conf.Client.Servers[serverIndex-1]
	conf.Client.SelectedIdx = serverIndex - 1
	if strings.TrimSpace(selected.PublicKey) == "" {
		log.Fatalf("client.servers[%d].publicKey 不能为空", serverIndex-1)
	}
	if selected.MTU <= 0 {
		log.Fatalf("client.servers[%d].mtu 必须大于0", serverIndex-1)
	}
	conf.Common.PeerPublicKeys = []string{selected.PublicKey}
	conf.Common.MTU = selected.MTU
	fillCommonDerivedFields(conf)
}

func validateServerConfig(conf *Config) {
	fillCommonDerivedFields(conf)
	if net.ParseIP(conf.VDHCP.Gateway) == nil {
		log.Fatalf("非法网关地址: %s", conf.VDHCP.Gateway)
	}
	if conf.VDHCP.SubnetMask != "" {
		if _, err := MaskToPrefix(conf.VDHCP.SubnetMask); err != nil {
			log.Fatalf("非法子网掩码: %s, 错误: %v", conf.VDHCP.SubnetMask, err)
		}
	}
}

func fillCommonDerivedFields(conf *Config) {
	// privateKey / peerPublicKeys 在 JSON 中是字符串，
	// 这里会解析成后续握手加密真正要用的二进制对象。
	if conf.Common.PrivateKey != "" {
		identity, err := secure.ParsePrivateKey(conf.Common.PrivateKey)
		if err != nil {
			log.Fatalf("解析privateKey失败: %v", err)
		}
		conf.Common.Identity = identity
	} else {
		log.Fatalf("common.privateKey 不能为空")
	}
	for i, key := range conf.Common.PeerPublicKeys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		peer, err := secure.ParsePublicKey(key)
		if err != nil {
			log.Fatalf("解析peerPublicKeys[%d]失败: %v", i, err)
		}
		if i == 0 {
			// IK 作为发起方需要预先知道服务端静态公钥，这里约定使用列表首项。
			conf.Common.PeerStatic = append([]byte(nil), peer...)
		}
		allowedPeerStaticSet[string(peer)] = struct{}{}
	}
}

func IsPeerStaticAllowed(remotePub []byte) bool {
	if len(allowedPeerStaticSet) == 0 {
		return true
	}
	_, ok := allowedPeerStaticSet[string(remotePub)]
	return ok
}

func (c Config) SelectedServer() ServerEndpoint {
	if len(c.Client.Servers) == 0 {
		return ServerEndpoint{}
	}
	idx := c.Client.SelectedIdx
	if idx < 0 || idx >= len(c.Client.Servers) {
		idx = 0
	}
	return c.Client.Servers[idx]
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
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}
	if privateKey != "" {
		cfg.Common.PrivateKey = privateKey
	}
	if peerPublicKey != "" {
		cfg.Common.PeerPublicKeys = []string{peerPublicKey}
	}

	out, err := json.MarshalIndent(&cfg, "", "  ")
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
