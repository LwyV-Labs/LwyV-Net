package vlan

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"

	"NetworkSetup/secure"

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
	PrivateKey     string              `yaml:"privateKey"`
	PeerPublicKeys []string            `yaml:"peerPublicKeys"`
	Identity       secure.Identity     `yaml:"-"`
	PeerStatic     []byte              `yaml:"-"`
	PeerStaticSet  map[string]struct{} `yaml:"-"`
	MTU            int                 `yaml:"mtu"`
	Proxy          bool                `yaml:"proxy"`
	Gateway        string              `yaml:"gateway"`
	SubnetMask     string              `yaml:"subnetMask"`
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
	for i, key := range Conf.Common.PeerPublicKeys {
		peer, err := secure.ParsePublicKey(key)
		if err != nil {
			log.Fatalf("解析peerPublicKeys[%d]失败: %v", i, err)
		}
		if Conf.Common.PeerStaticSet == nil {
			Conf.Common.PeerStaticSet = make(map[string]struct{})
		}
		Conf.Common.PeerStaticSet[string(peer)] = struct{}{}
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

// GenerateAndWriteKeys 生成一组 Noise IK / ECDH 长期身份密钥，并写入配置文件。
//
// 注意：
//   - privateKey 是“本机”的长期私钥，会自动写入 common.privateKey。
//   - 返回值 publicKey 是“本机”的长期公钥，需要复制到对端配置的 common.peerPublicKey。
//   - peerPublicKey 传空字符串时，不会覆盖配置中已有的 common.peerPublicKey。
//   - peerPublicKey 非空时，会校验其为 base64 32 bytes，并写入 common.peerPublicKey。
func GenerateAndWriteKeys(path string, peerPublicKey string) (publicKey string, err error) {
	privateKey, publicKey, err := generateNoiseKeyPair()
	if err != nil {
		return "", err
	}

	if err := validateBase64Key("generated privateKey", privateKey); err != nil {
		return "", err
	}
	if err := validateBase64Key("generated publicKey", publicKey); err != nil {
		return "", err
	}
	if peerPublicKey != "" {
		if err := validateBase64Key("peerPublicKey", peerPublicKey); err != nil {
			return "", err
		}
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

func validateBase64Key(name string, value string) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s不是合法base64: %w", name, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("%s长度错误: got %d bytes, want 32 bytes", name, len(raw))
	}
	return nil
}

func writeKeysToConfig(path string, privateKey string, peerPublicKey string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	rootMap, err := rootMappingNode(&root)
	if err != nil {
		return err
	}
	common, err := ensureMappingValue(rootMap, "common")
	if err != nil {
		return err
	}

	if privateKey != "" {
		setStringValue(common, "privateKey", privateKey, "Noise IK / ECDH 身份密钥（base64 32 bytes）")
	}
	if peerPublicKey != "" {
		setStringValue(common, "peerPublicKey", peerPublicKey, "对端设备长期公钥（base64 32 bytes）")
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&root); err != nil {
		_ = encoder.Close()
		return fmt.Errorf("编码配置文件失败: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("关闭YAML编码器失败: %w", err)
	}

	perm := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	if err := os.WriteFile(path, buf.Bytes(), perm); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	return nil
}

func rootMappingNode(root *yaml.Node) (*yaml.Node, error) {
	if root.Kind == 0 {
		root.Kind = yaml.DocumentNode
		root.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	if root.Kind != yaml.DocumentNode {
		return nil, fmt.Errorf("配置文件根节点必须是YAML文档")
	}
	if len(root.Content) == 0 {
		root.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	if root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("配置文件根节点必须是map")
	}
	return root.Content[0], nil
}

func ensureMappingValue(mapping *yaml.Node, key string) (*yaml.Node, error) {
	if mapping.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("节点%s的父级不是map", key)
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		keyNode := mapping.Content[i]
		valueNode := mapping.Content[i+1]
		if keyNode.Value != key {
			continue
		}
		if valueNode.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s必须是map", key)
		}
		return valueNode, nil
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valueNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	mapping.Content = append(mapping.Content, keyNode, valueNode)
	return valueNode, nil
}

func setStringValue(mapping *yaml.Node, key string, value string, headComment string) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		keyNode := mapping.Content[i]
		valueNode := mapping.Content[i+1]
		if keyNode.Value != key {
			continue
		}
		valueNode.Kind = yaml.ScalarNode
		valueNode.Tag = "!!str"
		valueNode.Value = value
		valueNode.Style = yaml.DoubleQuotedStyle
		return
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	if headComment != "" {
		keyNode.HeadComment = headComment
	}
	valueNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: yaml.DoubleQuotedStyle}
	mapping.Content = append(mapping.Content, keyNode, valueNode)
}
