package vlan

import (
	"NetworkSetup/kit"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
)

type serverGatewayNATState struct {
	mu sync.Mutex

	active bool

	ifName     string
	egressIf   string
	subnet     string
	oldForward string
}

var serverNATState serverGatewayNATState

func enableServerGatewayNAT(ifName, gatewayIP, mask, egressIf string) error {
	serverNATState.mu.Lock()
	defer serverNATState.mu.Unlock()

	if serverNATState.active {
		disableServerGatewayNATLocked()
	}

	prefix, err := kit.MaskToPrefix(mask)
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

	oldForwardBytes, _ := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
	oldForward := strings.TrimSpace(string(oldForwardBytes))
	if oldForward == "" {
		oldForward = "0"
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

	// 可选，但建议加：避免 TCP MTU 问题
	if err = ensureIptablesRule(
		"mangle",
		"FORWARD",
		"-i", ifName,
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
	); err != nil {
		return err
	}

	serverNATState.active = true
	serverNATState.ifName = ifName
	serverNATState.egressIf = egressIf
	serverNATState.subnet = subnet
	serverNATState.oldForward = oldForward

	return nil
}

func disableServerGatewayNAT() {
	serverNATState.mu.Lock()
	defer serverNATState.mu.Unlock()

	disableServerGatewayNATLocked()
}

func disableServerGatewayNATLocked() {
	if !serverNATState.active {
		return
	}

	ifName := serverNATState.ifName
	egressIf := serverNATState.egressIf
	subnet := serverNATState.subnet

	_ = deleteIptablesRule("mangle", "FORWARD",
		"-i", ifName,
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
	)

	_ = deleteIptablesRule("nat", "POSTROUTING",
		"-s", subnet,
		"-o", egressIf,
		"-j", "MASQUERADE",
	)

	_ = deleteIptablesRule("filter", "FORWARD",
		"-i", egressIf,
		"-o", ifName,
		"-m", "state",
		"--state", "RELATED,ESTABLISHED",
		"-j", "ACCEPT",
	)

	_ = deleteIptablesRule("filter", "FORWARD",
		"-i", ifName,
		"-o", egressIf,
		"-j", "ACCEPT",
	)

	if serverNATState.oldForward != "" {
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward="+serverNATState.oldForward).Run()
	}

	log.Printf("🧹 已清理服务端NAT/FORWARD/mangle规则")

	serverNATState.active = false
	serverNATState.ifName = ""
	serverNATState.egressIf = ""
	serverNATState.subnet = ""
	serverNATState.oldForward = ""
}

func deleteIptablesRule(table, chain string, args ...string) error {
	checkArgs := append([]string{"-t", table, "-C", chain}, args...)
	if err := exec.Command("iptables", checkArgs...).Run(); err != nil {
		return nil
	}

	delArgs := append([]string{"-t", table, "-D", chain}, args...)
	if err := exec.Command("iptables", delArgs...).Run(); err != nil {
		return fmt.Errorf("删除iptables规则失败 [%s/%s %v]: %w", table, chain, args, err)
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
