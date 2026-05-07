//go:build windows

package tunSetup

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

func CreateTun(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}

func RunPowerShell(ps string) error {
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

func RunPowerShellOutput(ps string) (string, error) {
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

func PsResolveInterfaceIndexFunc() string {
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

func RemoveFirewallRulesForTun() error {
	ps := fmt.Sprintf(`
Get-NetFirewallRule -DisplayName %q -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName %q -ErrorAction SilentlyContinue | Remove-NetFirewallRule
`, fwRuleIn, fwRuleOut)

	return RunPowerShell(ps)
}

func ConfigureTunAddress(ifName, ip, mask string) error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		ifName, "static", ip, mask)
	return cmd.Run()
}

func AllowTunTraffic(ifName string) error {
	ps := fmt.Sprintf(`
$alias = %q

Get-NetFirewallRule -DisplayName %q -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName %q -ErrorAction SilentlyContinue | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName %q -Direction Inbound  -Action Allow -Enabled True -Profile Any -InterfaceAlias $alias
New-NetFirewallRule -DisplayName %q -Direction Outbound -Action Allow -Enabled True -Profile Any -InterfaceAlias $alias
`, ifName, fwRuleIn, fwRuleOut, fwRuleIn, fwRuleOut)

	return RunPowerShell(ps)
}

func CleanupTunTraffic() {
	_ = RemoveFirewallRulesForTun()
}

func SetInterfaceDNS(ifName string, dns []string) error {
	if len(dns) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(dns))
	for _, d := range dns {
		quoted = append(quoted, fmt.Sprintf("%q", d))
	}
	ps := fmt.Sprintf(`
$alias = %q
$servers = @(%s)
Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $servers -ErrorAction Stop
`, ifName, strings.Join(quoted, ", "))
	return RunPowerShell(ps)
}

func ResetInterfaceDNS(ifName string) error {
	ps := fmt.Sprintf(`
$alias = %q
Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses -ErrorAction Stop
`, ifName)
	return RunPowerShell(ps)
}

func GetDefaultRoute() (*defaultRouteInfo, error) {
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

	out, err := RunPowerShellOutput(ps)
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

func AddHostRoute(hostIP, gateway, ifRef string) error {
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
`, PsResolveInterfaceIndexFunc(), hostIP+"/32", gateway, ifRef)

	return RunPowerShell(ps)
}

func DeleteHostRoute(hostIP, gateway, ifRef string) error {
	ps := fmt.Sprintf(`
%s

$dst = %q
$ifRef = %q
$ifIndex = Resolve-InterfaceIndex $ifRef

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $dst -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -eq $ifIndex } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, PsResolveInterfaceIndexFunc(), hostIP+"/32", ifRef)

	return RunPowerShell(ps)
}

func AddDefaultRoute(ifRef, gateway string) error {
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
`, PsResolveInterfaceIndexFunc(), ifRef, gateway)

	return RunPowerShell(ps)
}

func DeleteDefaultRoute(ifRef, gateway string) error {
	ps := fmt.Sprintf(`
%s

$ifRef = %q
$ifIndex = Resolve-InterfaceIndex $ifRef

Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -eq $ifIndex } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
`, PsResolveInterfaceIndexFunc(), ifRef)

	return RunPowerShell(ps)
}
