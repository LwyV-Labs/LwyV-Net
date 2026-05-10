package tunSetup

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

var defaultProxyDNS = []string{"8.8.8.8", "1.1.1.1"}

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
	origIfIndex string

	tunIfName  string
	tunGateway string
	dnsApplied bool
}

var clientProxyRoute clientProxyRouteState

func SetupClientProxyRouting(serverAddr, tunIfName, tunGateway string) error {
	clientProxyRoute.mu.Lock()
	defer clientProxyRoute.mu.Unlock()

	// 如果之前已经设置过，先清理，避免重连时状态叠加
	if clientProxyRoute.active {
		CleanupClientProxyRoutingLocked()
	}

	serverIP, err := ResolveServerIPv4(serverAddr)
	if err != nil {
		return fmt.Errorf("解析服务端地址失败: %w", err)
	}

	orig, err := GetDefaultRoute()
	if err != nil {
		return fmt.Errorf("探测真实默认路由失败: %w", err)
	}

	// Windows 下优先使用 InterfaceIndex，避免中文 InterfaceAlias 导致 New-NetRoute 失败。
	// Linux 下 IfIndex 为空，仍然使用 IfName。
	origIfRef := orig.IfName
	if orig.IfIndex != "" {
		origIfRef = orig.IfIndex
	}

	log.Printf("🌐 当前真实默认路由: if=%s ifIndex=%s gw=%s",
		orig.IfName,
		orig.IfIndex,
		orig.Gateway,
	)

	// 先给服务端公网 IP 加例外路由，强制走真实出口
	if err := AddHostRoute(serverIP, orig.Gateway, origIfRef); err != nil {
		return fmt.Errorf("添加服务端例外路由失败: %w", err)
	}

	log.Printf("✅ 已添加服务端例外路由: %s/32 -> %s dev %s",
		serverIP,
		orig.Gateway,
		origIfRef,
	)

	// 不再改系统 default(0.0.0.0/0)，改为注入两条 /1 分裂默认路由到 TUN，
	// 依靠最长前缀匹配优先命中，实现“透明接管”且避免与原默认路由 metric 竞争。
	if err := AddSplitDefaultRoutesToTun(tunIfName, tunGateway); err != nil {
		_ = DeleteHostRoute(serverIP, orig.Gateway, origIfRef)
		return fmt.Errorf("注入TUN分裂默认路由失败: %w", err)
	}

	log.Printf("✅ 已注入TUN分裂默认路由: 0.0.0.0/1,128.0.0.0/1 -> %s dev %s", tunGateway, tunIfName)
	if err := SetInterfaceDNS(tunIfName, defaultProxyDNS); err != nil {
		_ = DeleteSplitDefaultRoutesFromTun(tunIfName, tunGateway)
		_ = DeleteHostRoute(serverIP, orig.Gateway, origIfRef)
		return fmt.Errorf("设置TUN DNS失败: %w", err)
	}
	log.Printf("✅ 已设置TUN DNS: if=%s dns=%v", tunIfName, defaultProxyDNS)

	clientProxyRoute.active = true
	clientProxyRoute.serverIP = serverIP
	clientProxyRoute.origGateway = orig.Gateway
	clientProxyRoute.origIfName = orig.IfName
	clientProxyRoute.origIfIndex = orig.IfIndex
	clientProxyRoute.tunIfName = tunIfName
	clientProxyRoute.tunGateway = tunGateway
	clientProxyRoute.dnsApplied = true

	return nil
}

func CleanupClientProxyRouting() {
	clientProxyRoute.mu.Lock()
	defer clientProxyRoute.mu.Unlock()

	CleanupClientProxyRoutingLocked()
}

func CleanupClientProxyRoutingLocked() {
	if !clientProxyRoute.active {
		return
	}

	// Windows 下恢复真实默认路由时继续使用 InterfaceIndex。
	// Linux 下 origIfIndex 为空，使用原始网卡名。
	origIfRef := clientProxyRoute.origIfName
	if clientProxyRoute.origIfIndex != "" {
		origIfRef = clientProxyRoute.origIfIndex
	}

	if err := DeleteSplitDefaultRoutesFromTun(clientProxyRoute.tunIfName, clientProxyRoute.tunGateway); err != nil {
		log.Printf("清理TUN分裂默认路由失败: %v", err)
	} else {
		log.Printf("🧹 已清理TUN分裂默认路由")
	}
	if clientProxyRoute.dnsApplied {
		if err := ResetInterfaceDNS(clientProxyRoute.tunIfName); err != nil {
			log.Printf("恢复TUN DNS失败: %v", err)
		} else {
			log.Printf("🧹 已恢复TUN DNS自动获取")
		}
	}

	if err := AddDefaultRoute(origIfRef, clientProxyRoute.origGateway); err != nil {
		log.Printf("恢复真实默认路由失败: %v", err)
	} else {
		log.Printf("🧹 已恢复真实默认路由: default -> %s dev %s",
			clientProxyRoute.origGateway,
			origIfRef,
		)
	}

	if err := DeleteHostRoute(clientProxyRoute.serverIP, clientProxyRoute.origGateway, origIfRef); err != nil {
		log.Printf("清理服务端例外路由失败: %v", err)
	} else {
		log.Printf("🧹 已清理服务端例外路由")
	}

	clientProxyRoute.active = false
	clientProxyRoute.serverIP = ""
	clientProxyRoute.origGateway = ""
	clientProxyRoute.origIfName = ""
	clientProxyRoute.origIfIndex = ""
	clientProxyRoute.tunIfName = ""
	clientProxyRoute.tunGateway = ""
	clientProxyRoute.dnsApplied = false
}

func ResolveServerIPv4(serverAddr string) (string, error) {
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
