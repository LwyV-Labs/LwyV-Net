package main

import (
	vlan "NetworkSetup/vlan"
	"log"
	"os"
)

func main() {
	vlan.InitConfig("config.yaml")

	if len(os.Args) < 2 {
		vlan.StartClient()
		return
	}

	runType := os.Args[1]
	if runType == "server" {
		vlan.StartServer()
	} else {
		log.Fatal(runType + " is not a valid runType")
	}
}
