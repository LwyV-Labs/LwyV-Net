//go:build windows

package vlan_net

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	fwRuleIn  = "VLAN_NET_ALLOW_ALL_IN"
	fwRuleOut = "VLAN_NET_ALLOW_ALL_OUT"
)

const tunWriteOffset = 0

func runPowerShell(ps string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v, output: %s", err, string(out))
	}
	return nil
}

func runPowerShellOutput(ps string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v, output: %s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
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

func getDefaultRoute() (*defaultRouteInfo, error) {
	ps := `
$rt = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
    Where-Object { $_.NextHop -ne "0.0.0.0" } |
    Sort-Object RouteMetric |
    Select-Object -First 1

if (-not $rt) {
    throw "no default route found"
}

$ifAlias = (Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $rt.InterfaceIndex -ErrorAction Stop).InterfaceAlias
Write-Output ($rt.NextHop + "|" + $ifAlias + "|" + $rt.InterfaceIndex)
`
	out, err := runPowerShellOutput(ps)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(out, "|")
	if len(parts) != 3 {
		return nil, fmt.Errorf("解析默认路由失败: %s", out)
	}

	return &defaultRouteInfo{
		Gateway: strings.TrimSpace(parts[0]),
		IfName:  strings.TrimSpace(parts[1]),
		IfIndex: strings.TrimSpace(parts[2]),
	}, nil
}

func addHostRoute(hostIP, gateway, ifName string) error {
	ps := fmt.Sprintf(`
$dst   = %q
$gw    = %q
$alias = %q

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $dst -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

New-NetRoute -AddressFamily IPv4 -DestinationPrefix $dst -InterfaceAlias $alias -NextHop $gw -RouteMetric 1 -ErrorAction Stop
`, hostIP+"/32", gateway, ifName)

	return runPowerShell(ps)
}

func deleteHostRoute(hostIP, gateway, ifName string) error {
	ps := fmt.Sprintf(`
$dst   = %q
$alias = %q

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $dst -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, hostIP+"/32", ifName)

	return runPowerShell(ps)
}

func addDefaultRoute(ifName, gateway string) error {
	ps := fmt.Sprintf(`
$alias = %q
$gw    = %q

Start-Sleep -Milliseconds 800

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

New-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $alias -NextHop $gw -RouteMetric 5 -ErrorAction Stop
`, ifName, gateway)

	return runPowerShell(ps)
}

func deleteDefaultRoute(ifName, gateway string) error {
	ps := fmt.Sprintf(`
$alias = %q

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, ifName)

	return runPowerShell(ps)
}
