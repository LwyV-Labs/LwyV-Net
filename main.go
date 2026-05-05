package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/vlan"
)

func main() {
	mode := parseRunMode(os.Args)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	switch mode {
	case "genkey":
		vlan.Genkey()
		return
	case string(vlan.RunModeServer):
		server := vlan.NewServer()
		go server.Start()
		stopStats := make(chan struct{})
		go monitorServerStats(server, stopStats)
		<-ch
		close(stopStats)
		server.Stop()
		return
	case string(vlan.RunModeClient):
		client := vlan.NewClient()
		go client.Start()
		stopStats := make(chan struct{})
		go monitorClientStats(client, stopStats)
		<-ch
		close(stopStats)
		client.Stop()
		fmt.Println()
		return
	}

}

func parseRunMode(args []string) string {
	if len(args) < 2 {
		return string(vlan.RunModeClient)
	}
	switch args[1] {
	case "genkey", string(vlan.RunModeServer), string(vlan.RunModeClient):
		return args[1]
	default:
		log.Fatalf("%s is not a valid runType", args[1])
		return ""
	}
}

func monitorClientStats(client *vlan.Client, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			stats := client.GetTrafficStats()
			fmt.Printf("\r[Client] Up: %s/s  Down: %s/s  Used Up: %s  Used Down: %s", formatSpeed(stats.UploadBps), formatSpeed(stats.DownloadBps), formatBytes(stats.UploadBytes), formatBytes(stats.DownloadBytes))
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
			fmt.Print("\033[H\033[2J")
			fmt.Printf("[Server] Clients: %d\n", len(peers))
			for i, p := range peers {
				fmt.Printf("%d) device=%s ip=%s remote=%s\n", i+1, p.DeviceID, p.VirtualIP, p.RemoteAddr)
				fmt.Printf("   Up: %s/s  Down: %s/s  UsedUp: %s  UsedDown: %s\n", formatSpeed(p.UploadBps), formatSpeed(p.DownloadBps), formatBytes(p.UploadBytes), formatBytes(p.DownloadBytes))
			}
		}
	}
}

func formatBytes(b uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(b)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d%s", b, units[i])
	}
	return fmt.Sprintf("%.2f%s", v, units[i])
}

func formatSpeed(bps float64) string {
	if bps < 0 {
		bps = 0
	}
	return formatBytes(uint64(bps))
}
