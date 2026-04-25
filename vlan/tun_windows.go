//go:build windows

package vlan

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
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command",
		ps,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v, output: %s", err, string(out))
	}
	return nil
}

func runPowerShellOutput(ps string) (string, error) {
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command",
		ps,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v, output: %s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func psResolveInterfaceIndexFunc() string {
	return `
function Resolve-InterfaceIndex {
    param([string]$ifRef)

    if ($ifRef -match '^\d+$') {
        return [int]$ifRef
    }

    $iface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceAlias $ifRef -ErrorAction Stop |
        Select-Object -First 1

    return [int]$iface.InterfaceIndex
}
`
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

Get-NetFirewallRule -DisplayName %q -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName %q -ErrorAction SilentlyContinue | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName %q -Direction Inbound  -Action Allow -Enabled True -Profile Any -InterfaceAlias $alias
New-NetFirewallRule -DisplayName %q -Direction Outbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $alias
`, ifName, fwRuleIn, fwRuleOut, fwRuleIn, fwRuleOut)

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

func addHostRoute(hostIP, gateway, ifRef string) error {
	ps := fmt.Sprintf(`
%s

$dst = %q
$gw = %q
$ifRef = %q
$ifIndex = Resolve-InterfaceIndex $ifRef

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $dst -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -eq $ifIndex } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

New-NetRoute -AddressFamily IPv4 -DestinationPrefix $dst -InterfaceIndex $ifIndex -NextHop $gw -RouteMetric 1 -ErrorAction Stop
`, psResolveInterfaceIndexFunc(), hostIP+"/32", gateway, ifRef)

	return runPowerShell(ps)
}

func deleteHostRoute(hostIP, gateway, ifRef string) error {
	ps := fmt.Sprintf(`
%s

$dst = %q
$ifRef = %q
$ifIndex = Resolve-InterfaceIndex $ifRef

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $dst -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -eq $ifIndex } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, psResolveInterfaceIndexFunc(), hostIP+"/32", ifRef)

	return runPowerShell(ps)
}

func addDefaultRoute(ifRef, gateway string) error {
	ps := fmt.Sprintf(`
%s

$ifRef = %q
$gw = %q

Start-Sleep -Milliseconds 800

$ifIndex = Resolve-InterfaceIndex $ifRef

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -eq $ifIndex } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

New-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $ifIndex -NextHop $gw -RouteMetric 5 -ErrorAction Stop
`, psResolveInterfaceIndexFunc(), ifRef, gateway)

	return runPowerShell(ps)
}

func deleteDefaultRoute(ifRef, gateway string) error {
	ps := fmt.Sprintf(`
%s

$ifRef = %q
$ifIndex = Resolve-InterfaceIndex $ifRef

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -eq $ifIndex } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, psResolveInterfaceIndexFunc(), ifRef)

	return runPowerShell(ps)
}
