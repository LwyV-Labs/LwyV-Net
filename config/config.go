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

const (
	serverConfigPath = "server.json"
	clientConfigPath = "client.json"
)

var allowedPeerStaticSet map[string]struct{}

func LoadClientConfig(serverIndex int) ClientConfig {
	allowedPeerStaticSet = make(map[string]struct{})
	Conf := ClientConfig{}
	path := clientConfigPath
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("加载配置文件失败：%v", err)
	}
	if err = json.Unmarshal(data, &Conf); err != nil {
		log.Fatalf("解析配置文件失败：%v", err)
	}
	validateClientConfig(&Conf, serverIndex)
	return Conf
}

func LoadServerConfig() ServerConfig {
	allowedPeerStaticSet = make(map[string]struct{})
	Conf := ServerConfig{}
	path := serverConfigPath
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("加载配置文件失败：%v", err)
	}
	if err = json.Unmarshal(data, &Conf); err != nil {
		log.Fatalf("解析配置文件失败：%v", err)
	}
	validateServerConfig(&Conf)
	return Conf
}

func validateClientConfig(conf *ClientConfig, serverIndex int) {
	if len(conf.Servers) == 0 {
		log.Fatalf("client.servers 不能为空")
	}
	if serverIndex < 1 || serverIndex > len(conf.Servers) {
		log.Fatalf("服务端序号无效: %d，合法范围: 1-%d", serverIndex, len(conf.Servers))
	}
	selected := conf.Servers[serverIndex-1]
	conf.SelectedIdx = serverIndex - 1
	if strings.TrimSpace(selected.PublicKey) == "" {
		log.Fatalf("client.servers[%d].publicKey 不能为空", serverIndex-1)
	}
	if selected.MTU <= 0 {
		log.Fatalf("client.servers[%d].mtu 必须大于0", serverIndex-1)
	}
	conf.PeerPublicKeys = []string{selected.PublicKey}
	conf.MTU = selected.MTU
	fillDerivedFields(&conf.BaseConfig)
}

func validateServerConfig(conf *ServerConfig) {
	fillDerivedFields(&conf.BaseConfig)
	if net.ParseIP(conf.VDHCP.Gateway) == nil {
		log.Fatalf("非法网关地址: %s", conf.VDHCP.Gateway)
	}
	if conf.VDHCP.SubnetMask != "" {
		if _, err := MaskToPrefix(conf.VDHCP.SubnetMask); err != nil {
			log.Fatalf("非法子网掩码: %s, 错误: %v", conf.VDHCP.SubnetMask, err)
		}
	}
}

func fillDerivedFields(base *BaseConfig) {
	// privateKey / peerPublicKeys 在 JSON 中是字符串，
	// 这里会解析成后续握手加密真正要用的二进制对象。
	if base.PrivateKey != "" {
		identity, err := secure.ParsePrivateKey(base.PrivateKey)
		if err != nil {
			log.Fatalf("解析privateKey失败: %v", err)
		}
		base.Identity = identity
	} else {
		log.Fatalf("privateKey 不能为空")
	}
	for i, key := range base.PeerPublicKeys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		peer, err := secure.ParsePublicKey(key)
		if err != nil {
			log.Fatalf("解析peerPublicKeys[%d]失败: %v", i, err)
		}
		if i == 0 {
			// IK 作为发起方需要预先知道服务端静态公钥，这里约定使用列表首项。
			base.PeerStatic = append([]byte(nil), peer...)
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

func (c ClientConfig) SelectedServer() ServerEndpoint {
	if len(c.Servers) == 0 {
		return ServerEndpoint{}
	}
	idx := c.SelectedIdx
	if idx < 0 || idx >= len(c.Servers) {
		idx = 0
	}
	return c.Servers[idx]
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

	var out []byte
	if path == serverConfigPath {
		var cfg ServerConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("解析配置文件失败: %w", err)
		}
		if privateKey != "" {
			cfg.PrivateKey = privateKey
		}
		if peerPublicKey != "" {
			cfg.PeerPublicKeys = []string{peerPublicKey}
		}
		out, err = json.MarshalIndent(&cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("编码配置文件失败: %w", err)
		}
	} else {
		var cfg ClientConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("解析配置文件失败: %w", err)
		}
		if privateKey != "" {
			cfg.PrivateKey = privateKey
		}
		if peerPublicKey != "" {
			cfg.PeerPublicKeys = []string{peerPublicKey}
		}
		out, err = json.MarshalIndent(&cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("编码配置文件失败: %w", err)
		}
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
