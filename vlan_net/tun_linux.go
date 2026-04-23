//go:build linux

package vlan_net

import (
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

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
	// 先留空；如果你要做 Linux 网关/NAT，再补 iptables/nftables
	return nil
}

func cleanupTunTraffic() {
}

func addDefaultRoute(ifName, gateway string) error {
	return exec.Command("ip", "route", "replace", "default", "via", gateway, "dev", ifName).Run()
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
