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

func LoadClientConfig() ClientConfig {
	Conf := ClientConfig{}
	path := clientConfigPath
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("加载配置文件失败：%v", err)
	}
	if err = json.Unmarshal(data, &Conf); err != nil {
		log.Fatalf("解析配置文件失败：%v", err)
	}
	validateClientConfig(&Conf)
	return Conf
}

func LoadServerConfig() ServerConfig {
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

func validateClientConfig(conf *ClientConfig) {
	if len(conf.Servers) == 0 {
		log.Fatalf("client.servers 不能为空")
	}
	for i, server := range conf.Servers {
		if strings.TrimSpace(server.PublicKey) == "" {
			log.Fatalf("client.servers[%d].publicKey 不能为空", i)
		}
		if server.MTU <= 0 {
			log.Fatalf("client.servers[%d].mtu 必须大于0", i)
		}
	}
	fillDerivedFields(&conf.BaseConfig, clientConfigPath)
}

func validateServerConfig(conf *ServerConfig) {
	fillDerivedFields(&conf.BaseConfig, serverConfigPath)
	if net.ParseIP(conf.VDHCP.Gateway) == nil {
		log.Fatalf("非法网关地址: %s", conf.VDHCP.Gateway)
	}
	if conf.VDHCP.SubnetMask != "" {
		if _, err := MaskToPrefix(conf.VDHCP.SubnetMask); err != nil {
			log.Fatalf("非法子网掩码: %s, 错误: %v", conf.VDHCP.SubnetMask, err)
		}
	}
}

func fillDerivedFields(base *BaseConfig, path string) {
	// privateKey / peerPublicKeys 在 JSON 中是字符串，
	// 这里会解析成后续握手加密真正要用的二进制对象。
	if strings.TrimSpace(base.PrivateKey) == "" {
		privateKey, publicKey, err := GenerateAndWriteKeys(path)

		if err != nil {
			log.Fatalf("自动生成privateKey失败: %v", err)
		}
		base.PrivateKey = privateKey
		log.Printf("privateKey 为空，已自动生成新密钥；请持久化该密钥。publicKey=%s", publicKey)
	}
	identity, err := secure.ParsePrivateKey(base.PrivateKey)
	if err != nil {
		log.Fatalf("解析privateKey失败: %v", err)
	}
	base.Identity = identity
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
func GenerateAndWriteKeys(path string) (privateKey string, publicKey string, err error) {
	private, public, err := generateNoiseKeyPair()
	if err != nil {
		return "", "", err
	}
	if _, err := secure.ParsePrivateKey(private); err != nil {
		return "", "", err
	}
	if _, err := secure.ParsePublicKey(public); err != nil {
		return "", "", err
	}
	if err := writeKeysToConfig(path, privateKey); err != nil {
		return "", "", err
	}
	return private, public, nil
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

func writeKeysToConfig(path string, privateKey string) error {
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
