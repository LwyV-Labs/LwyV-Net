package main

import (
	"NetworkSetup/vlan_net"
	"log"
	"os"
)

func main() {

	vlan_net.InitConfig("config.yaml")

	if len(os.Args) < 2 {
		vlan_net.StartClient()
		return
	}

	runType := os.Args[1]
	if runType == "server" {
		vlan_net.StartServer()
	} else {
		log.Fatal(runType + " is not a valid runType")
	}
}
