package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/config"
	"github.com/LwyV-Labs/LwyV-Net/tcpx"
	"github.com/LwyV-Labs/LwyV-Net/vlan"
)

func main() {
	mode := parseRunMode(os.Args)
	switch mode {
	case RunModeGenKey:
		genKey()
	case RunModeServer:
		runServer()
	case RunModeClient:
		runClient()
	}
}

func genKey() {
	privateKey, publicKey, err := tcpx.GenerateStaticKeyBase64()
	if err != nil {
		log.Fatalf("生成密钥失败: %v", err)
	}
	fmt.Printf("privateKey: %s\npublicKey:  %s\n", privateKey, publicKey)
}

func runServer() {
	server := vlan.NewServer(config.LoadServerConfig())
	go server.Start()

	stopStats := make(chan struct{})
	go monitorServerStats(server, stopStats)

	waitSignal()
	close(stopStats)
	server.Stop()
}

func runClient() {
	client := vlan.NewClient(config.LoadClientConfig())
	client.Start()

	stopStats := make(chan struct{})
	go monitorClientStats(client, stopStats)

	waitSignal()
	close(stopStats)
	client.Stop()
	fmt.Println()
}

func waitSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func monitorClientStats(client *vlan.Client, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	fmt.Println()
	for {
		select {
		case <-stop:
			fmt.Print("\r\033[2K")
			return
		case <-ticker.C:
			stats := client.GetTrafficStats()
			fmt.Printf("\r\033[2K[Client] Up: %-12s Down: %-12s Used Up: %-12s Used Down: %-12s",
				formatSpeed(stats.UploadBps)+"/s",
				formatSpeed(stats.DownloadBps)+"/s",
				formatBytes(stats.UploadBytes),
				formatBytes(stats.DownloadBytes),
			)
		}
	}
}

func monitorServerStats(server *vlan.Server, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			peers := server.ListPeerTraffic()
			if len(peers) == 0 {
				continue
			}
			fmt.Print("\033[2J\033[H")
			for i, p := range peers {
				fmt.Printf("%d) device=%-18s ip=%-15s remote=%-22s\n", i+1, shortConsoleID(p.DeviceID), p.VirtualIP, p.RemoteAddr)
				fmt.Printf("   Up: %-12s Down: %-12s UsedUp: %-12s UsedDown: %-12s\n",
					formatSpeed(p.UploadBps)+"/s",
					formatSpeed(p.DownloadBps)+"/s",
					formatBytes(p.UploadBytes),
					formatBytes(p.DownloadBytes),
				)
			}
		}
	}
}

func shortConsoleID(s string) string {
	if len(s) <= 18 {
		return s
	}
	return s[:18]
}
