package conf2

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
	var conf ClientConfig
	mustLoadJSON(clientConfigPath, &conf)

	if strings.TrimSpace(conf.Server) == "" {
		log.Fatalf("client.server 不能为空")
	}
	if strings.TrimSpace(conf.ServerPublicKey) == "" {
		log.Fatalf("client.serverPublicKey 不能为空")
	}
	if conf.IfName == "" {
		conf.IfName = "LwyV-NetAdapter"
	}
	if conf.MTU <= 0 {
		conf.MTU = 1300
	}

	ensurePrivateKey(clientConfigPath, &conf.PrivateKey)

	if _, err := secure.ParsePrivateKey(conf.PrivateKey); err != nil {
		log.Fatalf("解析 client.privateKey 失败: %v", err)
	}
	if _, err := secure.ParsePublicKey(conf.ServerPublicKey); err != nil {
		log.Fatalf("解析 client.serverPublicKey 失败: %v", err)
	}

	return conf
}

func LoadServerConfig() ServerConfig {
	var conf ServerConfig
	mustLoadJSON(serverConfigPath, &conf)

	if conf.Port <= 0 {
		conf.Port = 9999
	}
	if conf.IfName == "" {
		conf.IfName = "LwyV-Gateway"
	}
	if conf.MTU <= 0 {
		conf.MTU = 1300
	}

	if conf.VDHCP.StartIP == "" {
		conf.VDHCP.StartIP = "172.19.0.10"
	}
	if conf.VDHCP.EndIP == "" {
		conf.VDHCP.EndIP = "172.19.0.200"
	}
	if conf.VDHCP.SubnetMask == "" {
		conf.VDHCP.SubnetMask = "255.255.255.0"
	}
	if conf.VDHCP.Gateway == "" {
		conf.VDHCP.Gateway = "172.19.0.254"
	}

	if net.ParseIP(conf.VDHCP.Gateway) == nil {
		log.Fatalf("非法网关地址: %s", conf.VDHCP.Gateway)
	}
	if _, err := MaskToPrefix(conf.VDHCP.SubnetMask); err != nil {
		log.Fatalf("非法子网掩码: %s, 错误: %v", conf.VDHCP.SubnetMask, err)
	}

	ensurePrivateKey(serverConfigPath, &conf.PrivateKey)

	if _, err := secure.ParsePrivateKey(conf.PrivateKey); err != nil {
		log.Fatalf("解析 server.privateKey 失败: %v", err)
	}

	return conf
}

func mustLoadJSON(path string, v any) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}
}

func ensurePrivateKey(path string, key *string) {
	if strings.TrimSpace(*key) != "" {
		return
	}

	privateKey, publicKey, err := generateNoiseKeyPair()
	if err != nil {
		log.Fatalf("自动生成 privateKey 失败: %v", err)
	}

	*key = privateKey

	if err := patchPrivateKey(path, privateKey); err != nil {
		log.Fatalf("写入 privateKey 失败: %v", err)
	}

	log.Printf("privateKey 为空，已自动生成并写回配置文件；publicKey=%s", publicKey)
}

func patchPrivateKey(path string, privateKey string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	m["privateKey"] = privateKey

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("编码配置文件失败: %w", err)
	}

	perm := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}

	return os.WriteFile(path, out, perm)
}

func generateNoiseKeyPair() (privateKey string, publicKey string, err error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(private.Bytes()),
		base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()),
		nil
}

func MaskToPrefix(mask string) (int, error) {
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
