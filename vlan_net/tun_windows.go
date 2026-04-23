//go:build windows

package vlan_net

import (
	"fmt"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	fwRuleIn  = "VLAN_NET_ALLOW_ALL_IN"
	fwRuleOut = "VLAN_NET_ALLOW_ALL_OUT"
)

func runPowerShell(ps string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v, output: %s", err, string(out))
	}
	return nil
}

func removeFirewallRulesForTun() error {
	ps := fmt.Sprintf(`
Get-NetFirewallRule -DisplayName %q -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName %q -ErrorAction SilentlyContinue | Remove-NetFirewallRule
`, fwRuleIn, fwRuleOut)

	return runPowerShell(ps)
}

func createTun(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

func configureTunAddress(ifName, ip, mask string) error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		ifName, "static", ip, mask)
	return cmd.Run()
}

func allowTunTraffic(ifName string) error {
	ps := fmt.Sprintf(`
$alias = %q
New-NetFirewallRule -DisplayName %q -Direction Inbound  -Action Allow -Enabled True -Profile Any -InterfaceAlias $alias
New-NetFirewallRule -DisplayName %q -Direction Outbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $alias
`, ifName, fwRuleIn, fwRuleOut)

	return runPowerShell(ps)
}

func cleanupTunTraffic() {
	_ = removeFirewallRulesForTun()
}

func addDefaultRoute(ifName, gateway string) error {
	_ = exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", gateway).Run()
	return exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", gateway, "metric", "5", "if", ifName).Run()
}
