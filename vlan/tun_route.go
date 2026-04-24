package vlan

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

type defaultRouteInfo struct {
	Gateway string
	IfName  string
	IfIndex string
}

type clientProxyRouteState struct {
	mu sync.Mutex

	active bool

	serverIP string

	origGateway string
	origIfName  string

	tunIfName  string
	tunGateway string
}

var clientProxyRoute clientProxyRouteState

func setupClientProxyRouting(serverAddr, tunIfName, tunGateway string) error {
	clientProxyRoute.mu.Lock()
	defer clientProxyRoute.mu.Unlock()

	// 如果之前已经设置过，先清理，避免重连时状态叠加
	if clientProxyRoute.active {
		cleanupClientProxyRoutingLocked()
	}

	serverIP, err := resolveServerIPv4(serverAddr)
	if err != nil {
		return fmt.Errorf("解析服务端地址失败: %w", err)
	}

	orig, err := getDefaultRoute()
	if err != nil {
		return fmt.Errorf("探测真实默认路由失败: %w", err)
	}

	log.Printf("🌐 当前真实默认路由: if=%s gw=%s", orig.IfName, orig.Gateway)

	// 先给服务端公网 IP 加例外路由，强制走真实出口
	if err := addHostRoute(serverIP, orig.Gateway, orig.IfName); err != nil {
		return fmt.Errorf("添加服务端例外路由失败: %w", err)
	}
	log.Printf("✅ 已添加服务端例外路由: %s/32 -> %s dev %s", serverIP, orig.Gateway, orig.IfName)

	// 再把默认路由切到 TUN
	if err := addDefaultRoute(tunIfName, tunGateway); err != nil {
		_ = deleteHostRoute(serverIP, orig.Gateway, orig.IfName)
		return fmt.Errorf("切换默认路由到TUN失败: %w", err)
	}
	log.Printf("✅ 已切换默认路由到TUN: default -> %s dev %s", tunGateway, tunIfName)

	clientProxyRoute.active = true
	clientProxyRoute.serverIP = serverIP
	clientProxyRoute.origGateway = orig.Gateway
	clientProxyRoute.origIfName = orig.IfName
	clientProxyRoute.tunIfName = tunIfName
	clientProxyRoute.tunGateway = tunGateway

	return nil
}

func shutdownServerGateway() {
	serverTunMu.Lock()
	if serverTunDev != nil {
		_ = serverTunDev.Close()
		serverTunDev = nil
	}
	serverTunMu.Unlock()

	disableServerGatewayNAT()
}

func cleanupClientProxyRouting() {
	clientProxyRoute.mu.Lock()
	defer clientProxyRoute.mu.Unlock()

	cleanupClientProxyRoutingLocked()
}

func cleanupClientProxyRoutingLocked() {
	if !clientProxyRoute.active {
		return
	}

	if err := deleteDefaultRoute(clientProxyRoute.tunIfName, clientProxyRoute.tunGateway); err != nil {
		log.Printf("清理TUN默认路由失败: %v", err)
	} else {
		log.Printf("🧹 已清理TUN默认路由")
	}

	if err := addDefaultRoute(clientProxyRoute.origIfName, clientProxyRoute.origGateway); err != nil {
		log.Printf("恢复真实默认路由失败: %v", err)
	} else {
		log.Printf("🧹 已恢复真实默认路由: default -> %s dev %s",
			clientProxyRoute.origGateway,
			clientProxyRoute.origIfName,
		)
	}

	if err := deleteHostRoute(clientProxyRoute.serverIP, clientProxyRoute.origGateway, clientProxyRoute.origIfName); err != nil {
		log.Printf("清理服务端例外路由失败: %v", err)
	} else {
		log.Printf("🧹 已清理服务端例外路由")
	}

	clientProxyRoute.active = false
	clientProxyRoute.serverIP = ""
	clientProxyRoute.origGateway = ""
	clientProxyRoute.origIfName = ""
	clientProxyRoute.tunIfName = ""
	clientProxyRoute.tunGateway = ""
}

func resolveServerIPv4(serverAddr string) (string, error) {
	host := serverAddr

	if h, _, err := net.SplitHostPort(serverAddr); err == nil {
		host = h
	} else {
		host = strings.TrimSpace(serverAddr)
	}

	if ip := net.ParseIP(host); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return "", fmt.Errorf("暂不支持IPv6服务端地址: %s", host)
		}
		return ip4.String(), nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("DNS解析失败: %w", err)
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}

	return "", fmt.Errorf("域名 %s 没有可用IPv4地址", host)
}
