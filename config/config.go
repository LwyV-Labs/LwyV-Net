package config

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/LwyV-Labs/LwyV-Net/tcpx"
)

const (
	serverConfigPath = "server.json"
	clientConfigPath = "client.json"
)

func LoadClientConfig() ClientConfig {
	conf, err := LoadClientConfigFrom(clientConfigPath)
	if err != nil {
		log.Fatal(err)
	}
	return conf
}

func LoadServerConfig() ServerConfig {
	conf, err := LoadServerConfigFrom(serverConfigPath)
	if err != nil {
		log.Fatal(err)
	}
	return conf
}

func LoadClientConfigFrom(path string) (ClientConfig, error) {
	var conf ClientConfig
	if err := loadJSON(path, &conf); err != nil {
		return conf, err
	}
	applyClientDefaults(&conf)

	if strings.TrimSpace(conf.Server) == "" {
		return conf, fmt.Errorf("client.server 不能为空")
	}
	if strings.TrimSpace(conf.ServerPublicKey) == "" {
		return conf, fmt.Errorf("client.serverPublicKey 不能为空")
	}
	if err := ensurePrivateKey(path, &conf.PrivateKey); err != nil {
		return conf, err
	}
	if _, err := tcpx.ParsePrivateKeyAny(conf.PrivateKey); err != nil {
		return conf, fmt.Errorf("解析 client.privateKey 失败: %w", err)
	}
	if _, err := tcpx.ParsePublicKeyAny(conf.ServerPublicKey); err != nil {
		return conf, fmt.Errorf("解析 client.serverPublicKey 失败: %w", err)
	}
	return conf, nil
}

func LoadServerConfigFrom(path string) (ServerConfig, error) {
	var conf ServerConfig
	if err := loadJSON(path, &conf); err != nil {
		return conf, err
	}
	applyServerDefaults(&conf)

	if err := validateVDHCP(conf.VDHCP); err != nil {
		return conf, err
	}
	if err := ensurePrivateKey(path, &conf.PrivateKey); err != nil {
		return conf, err
	}
	if _, err := tcpx.ParsePrivateKeyAny(conf.PrivateKey); err != nil {
		return conf, fmt.Errorf("解析 server.privateKey 失败: %w", err)
	}
	return conf, nil
}

func applyClientDefaults(conf *ClientConfig) {
	if conf.IfName == "" {
		conf.IfName = "LwyV-NetAdapter"
	}
}

func applyServerDefaults(conf *ServerConfig) {
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
	conf.VDHCP.DNS = normalizeDNSServers(conf.VDHCP.DNS)
	if len(conf.VDHCP.DNS) == 0 {
		conf.VDHCP.DNS = defaultDNSServers()
	}
}

func validateVDHCP(conf VDHCPConfig) error {
	start := net.ParseIP(conf.StartIP).To4()
	end := net.ParseIP(conf.EndIP).To4()
	gateway := net.ParseIP(conf.Gateway).To4()
	if start == nil {
		return fmt.Errorf("非法 vdhcp.startIP: %s", conf.StartIP)
	}
	if end == nil {
		return fmt.Errorf("非法 vdhcp.endIP: %s", conf.EndIP)
	}
	if gateway == nil {
		return fmt.Errorf("非法 vdhcp.gateway: %s", conf.Gateway)
	}
	if len(conf.DNS) == 0 {
		return fmt.Errorf("vdhcp.dns 不能为空")
	}
	for _, dns := range conf.DNS {
		if net.ParseIP(dns).To4() == nil {
			return fmt.Errorf("非法 vdhcp.dns: %s", dns)
		}
	}
	if ipToUint32(start) > ipToUint32(end) {
		return fmt.Errorf("vdhcp.startIP 必须小于或等于 vdhcp.endIP")
	}
	if _, err := MaskToPrefix(conf.SubnetMask); err != nil {
		return fmt.Errorf("非法 vdhcp.subnetMask: %s: %w", conf.SubnetMask, err)
	}
	return nil
}

func defaultDNSServers() []string {
	return []string{"8.8.8.8", "1.1.1.1"}
}

func normalizeDNSServers(in []string) []string {
	out := make([]string, 0, len(in))
	for _, dns := range in {
		dns = strings.TrimSpace(dns)
		if dns == "" {
			continue
		}
		out = append(out, dns)
	}
	return out
}

func loadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("加载配置文件失败 %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("解析配置文件失败 %s: %w", path, err)
	}
	return nil
}

func ensurePrivateKey(path string, key *string) error {
	if strings.TrimSpace(*key) != "" {
		return nil
	}
	privateKey, publicKey, err := tcpx.GenerateStaticKeyBase64()
	if err != nil {
		return fmt.Errorf("自动生成 privateKey 失败: %w", err)
	}
	*key = privateKey
	if err := patchPrivateKey(path, privateKey); err != nil {
		return fmt.Errorf("写入 privateKey 失败: %w", err)
	}
	log.Printf("privateKey 为空，已自动生成并写回配置文件；publicKey=%s", publicKey)
	return nil
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

func MaskToPrefix(mask string) (int, error) {
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return 0, fmt.Errorf("非法子网掩码: %s", mask)
	}
	ones, bits := net.IPMask(ip).Size()
	if bits != 32 || ones < 0 {
		return 0, fmt.Errorf("非法子网掩码: %s", mask)
	}
	return ones, nil
}

func ipToUint32(ip net.IP) uint32 {
	v := ip.To4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}
