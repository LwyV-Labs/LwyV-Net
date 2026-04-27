//go:build linux

package setup

import (
	"NetworkSetup/kit"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
	"golang.org/x/sys/unix"
)

const TunWriteOffset = 0

func CreateTun(name string, mtu int) (tun.Device, error) {
	// 显式使用 IFF_NO_PI 且不启用 IFF_VNET_HDR，统一读写 offset=0 的数据面行为。
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	return tun.CreateTUNFromFile(os.NewFile(uintptr(fd), "/dev/net/tun"), mtu)
}

func ConfigureTunAddress(ifName, ip, mask string) error {
	prefix, err := kit.MaskToPrefix(mask)
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

func AllowTunTraffic(ifName string) error {
	return nil
}

func CleanupTunTraffic() {
}

func SetInterfaceDNS(ifName string, dns []string) error {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		// 非 systemd-resolved 环境下可能不存在 resolvectl，这里不强制失败。
		return nil
	}
	args := append([]string{"dns", ifName}, dns...)
	if err := exec.Command("resolvectl", args...).Run(); err != nil {
		return err
	}
	// 将该接口标记为默认 DNS 路由域，避免继续走原始出口 DNS。
	return exec.Command("resolvectl", "domain", ifName, "~.").Run()
}

func ResetInterfaceDNS(ifName string) error {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return nil
	}
	return exec.Command("resolvectl", "revert", ifName).Run()
}

func GetDefaultRoute() (*defaultRouteInfo, error) {
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

func AddHostRoute(hostIP, gateway, ifName string) error {
	return exec.Command(
		"ip", "route", "replace",
		fmt.Sprintf("%s/32", hostIP),
		"via", gateway,
		"dev", ifName,
	).Run()
}

func DeleteHostRoute(hostIP, gateway, ifName string) error {
	return exec.Command(
		"ip", "route", "del",
		fmt.Sprintf("%s/32", hostIP),
		"via", gateway,
		"dev", ifName,
	).Run()
}

func AddDefaultRoute(ifName, gateway string) error {
	return exec.Command(
		"ip", "route", "replace",
		"default",
		"via", gateway,
		"dev", ifName,
	).Run()
}

func DeleteDefaultRoute(ifName, gateway string) error {
	return exec.Command(
		"ip", "route", "del",
		"default",
		"via", gateway,
		"dev", ifName,
	).Run()
}
