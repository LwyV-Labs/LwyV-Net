package webui

import (
	"NetworkSetup/secure"
	"NetworkSetup/vlan"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type configPayload struct {
	Common vlan.CommonConfig `json:"common" yaml:"common"`
	Server vlan.ServerConfig `json:"server" yaml:"server"`
	Client vlan.ClientConfig `json:"client" yaml:"client"`
	VDHCP  vlan.VDHCPConfig  `json:"vdhcp" yaml:"vdhcp"`
}

type keyInfo struct {
	PublicKey  string `json:"publicKey"`
	Generated  bool   `json:"generated"`
	HasPrivate bool   `json:"hasPrivate"`
}

func loadConfig(path string) (configPayload, error) {
	var cfg configPayload
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err = yaml.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func saveConfig(path string, cfg configPayload) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err = os.WriteFile(path, raw, 0644); err != nil {
		return err
	}
	return nil
}

func autoOpenBrowser(listenAddr string) {
	if runtime.GOOS != "windows" {
		return
	}
	url := toLocalURL(listenAddr)
	go func() {
		time.Sleep(500 * time.Millisecond)
		if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start(); err != nil {
			fmt.Printf("自动打开浏览器失败: %v\n", err)
		}
	}()
}

func toLocalURL(listenAddr string) string {
	addr := strings.TrimSpace(listenAddr)
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		return "http://127.0.0.1" + addr
	}
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return "http://127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
	}
	if strings.HasPrefix(addr, "localhost:") || strings.HasPrefix(addr, "127.0.0.1:") {
		return "http://" + addr
	}
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	return "http://" + addr
}

func getKeyInfo(path string) (keyInfo, error) {
	var info keyInfo
	cfg, err := loadConfig(path)
	if err != nil {
		return info, err
	}
	privateKey := strings.TrimSpace(cfg.Common.PrivateKey)
	if privateKey == "" {
		return keyInfo{HasPrivate: false}, nil
	}
	identity, err := secure.ParsePrivateKey(privateKey)
	if err != nil {
		return info, err
	}
	return keyInfo{
		PublicKey:  base64.StdEncoding.EncodeToString(identity.Public),
		Generated:  false,
		HasPrivate: true,
	}, nil
}
