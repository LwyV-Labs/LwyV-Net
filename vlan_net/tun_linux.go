//go:build linux

package vlan_net

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

const tunWriteOffset = 10

func createTun(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

func configureTunAddress(ifName, ip, mask string) error {
	prefix, err := maskToPrefix(mask)
	if err != nil {
		return err
	}

	if err := exec.Command("ip", "link", "set", "dev", ifName, "up").Run(); err != nil {
		return err
	}
	if err := exec.Command("ip", "addr", "replace", fmt.Sprintf("%s/%d", ip, prefix), "dev", ifName).Run(); err != nil {
		return err
	}
	return nil
}

func allowTunTraffic(ifName string) error {
	return nil
}

func cleanupTunTraffic() {
}

func getDefaultRoute() (*defaultRouteInfo, error) {
	out, err := exec.Command("sh", "-c", "ip route show default | head -n 1").Output()
	if err != nil {
		return nil, fmt.Errorf("获取默认路由失败: %w", err)
	}

	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil, fmt.Errorf("默认路由为空")
	}

	fields := strings.Fields(line)
	info := &defaultRouteInfo{}

	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 < len(fields) {
				info.Gateway = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				info.IfName = fields[i+1]
			}
		}
	}

	if info.Gateway == "" || info.IfName == "" {
		return nil, fmt.Errorf("解析默认路由失败: %s", line)
	}

	return info, nil
}

func addHostRoute(hostIP, gateway, ifName string) error {
	return exec.Command(
		"ip", "route", "replace",
		fmt.Sprintf("%s/32", hostIP),
		"via", gateway,
		"dev", ifName,
	).Run()
}

func deleteHostRoute(hostIP, gateway, ifName string) error {
	return exec.Command(
		"ip", "route", "del",
		fmt.Sprintf("%s/32", hostIP),
		"via", gateway,
		"dev", ifName,
	).Run()
}

func addDefaultRoute(ifName, gateway string) error {
	return exec.Command(
		"ip", "route", "replace",
		"default",
		"via", gateway,
		"dev", ifName,
	).Run()
}

func deleteDefaultRoute(ifName, gateway string) error {
	return exec.Command(
		"ip", "route", "del",
		"default",
		"via", gateway,
		"dev", ifName,
	).Run()
}

func maskToPrefix(mask string) (int, error) {
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
