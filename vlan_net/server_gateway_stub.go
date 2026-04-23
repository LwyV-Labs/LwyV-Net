//go:build !linux

package vlan_net

func enableServerGatewayNAT(ifName, gatewayIP, mask, egressIf string) error {
	return nil
}
