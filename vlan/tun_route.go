package vlan

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type defaultRouteInfo struct {
	Gateway string
	IfName  string
	IfIndex string
}

func setupClientProxyRouting(serverAddr, tunIfName, tunGateway string) (func(), error) {
	serverIP, err := resolveServerIPv4(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("解析服务端地址失败: %w", err)
	}

	orig, err := getDefaultRoute()
	if err != nil {
		return nil, fmt.Errorf("探测真实默认路由失败: %w", err)
	}

	log.Printf("🌐 当前真实默认路由: if=%s gw=%s", orig.IfName, orig.Gateway)

	// 先给服务端公网IP加例外路由，强制走真实出口
	if err := addHostRoute(serverIP, orig.Gateway, orig.IfName); err != nil {
		return nil, fmt.Errorf("添加服务端例外路由失败: %w", err)
	}
	log.Printf("✅ 已添加服务端例外路由: %s/32 -> %s dev %s", serverIP, orig.Gateway, orig.IfName)

	// 再把默认路由切到TUN
	if err := addDefaultRoute(tunIfName, tunGateway); err != nil {
		_ = deleteHostRoute(serverIP, orig.Gateway, orig.IfName)
		return nil, fmt.Errorf("切换默认路由到TUN失败: %w", err)
	}
	log.Printf("✅ 已切换默认路由到TUN: default -> %s dev %s", tunGateway, tunIfName)

	cleanup := func() {
		if err := deleteDefaultRoute(tunIfName, tunGateway); err != nil {
			log.Printf("清理TUN默认路由失败: %v", err)
		} else {
			log.Printf("🧹 已清理TUN默认路由")
		}

		if err := addDefaultRoute(orig.IfName, orig.Gateway); err != nil {
			log.Printf("恢复真实默认路由失败: %v", err)
		} else {
			log.Printf("🧹 已恢复真实默认路由: default -> %s dev %s", orig.Gateway, orig.IfName)
		}

		if err := deleteHostRoute(serverIP, orig.Gateway, orig.IfName); err != nil {
			log.Printf("清理服务端例外路由失败: %v", err)
		} else {
			log.Printf("🧹 已清理服务端例外路由")
		}
	}

	return cleanup, nil
}

func resolveServerIPv4(serverAddr string) (string, error) {
	host := serverAddr

	// 常规 host:port
	if h, _, err := net.SplitHostPort(serverAddr); err == nil {
		host = h
	} else {
		// 兼容没有端口的情况
		host = strings.TrimSpace(serverAddr)
	}

	// 如果本身就是IP
	if ip := net.ParseIP(host); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return "", fmt.Errorf("暂不支持IPv6服务端地址: %s", host)
		}
		return ip4.String(), nil
	}

	// 如果是域名，必须在切默认路由前先解析
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
