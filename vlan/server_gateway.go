package vlan

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func enableServerGatewayNAT(ifName, gatewayIP, mask, egressIf string) error {
	prefix, err := maskToPrefixValue(mask)
	if err != nil {
		return err
	}
	subnet := fmt.Sprintf("%s/%d", networkAddr(gatewayIP, mask), prefix)

	if egressIf == "" {
		egressIf, err = detectDefaultEgressIf()
		if err != nil {
			return err
		}
	}

	if err = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("启用IP转发失败: %w", err)
	}

	if err = ensureIptablesRule("filter", "FORWARD", "-i", ifName, "-o", egressIf, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err = ensureIptablesRule("filter", "FORWARD", "-i", egressIf, "-o", ifName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err = ensureIptablesRule("nat", "POSTROUTING", "-s", subnet, "-o", egressIf, "-j", "MASQUERADE"); err != nil {
		return err
	}

	return nil
}

func detectDefaultEgressIf() (string, error) {
	out, err := exec.Command("sh", "-c", "ip route get 1.1.1.1 | awk '/dev/ {for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}'").Output()
	if err != nil {
		return "", fmt.Errorf("探测出口网卡失败: %w", err)
	}
	iface := strings.TrimSpace(string(out))
	if iface == "" {
		return "", fmt.Errorf("探测出口网卡失败: 空结果")
	}
	return iface, nil
}

func ensureIptablesRule(table, chain string, args ...string) error {
	checkArgs := append([]string{"-t", table, "-C", chain}, args...)
	if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
		return nil
	}
	addArgs := append([]string{"-t", table, "-A", chain}, args...)
	if err := exec.Command("iptables", addArgs...).Run(); err != nil {
		return fmt.Errorf("添加iptables规则失败 [%s/%s %v]: %w", table, chain, args, err)
	}
	return nil
}

func networkAddr(ip, mask string) string {
	ipv4 := net.ParseIP(ip).To4()
	maskIP := net.ParseIP(mask).To4()
	if ipv4 == nil || maskIP == nil {
		return ip
	}
	return net.IPv4(ipv4[0]&maskIP[0], ipv4[1]&maskIP[1], ipv4[2]&maskIP[2], ipv4[3]&maskIP[3]).String()
}

func maskToPrefixValue(mask string) (int, error) {
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
