package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/conf2"
	"github.com/LwyV-Labs/LwyV-Net/vlan2"
)

func main() {
	mode := parseRunMode(os.Args)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	switch mode {
	case string(RunModeServer):
		server := vlan2.NewServer(conf2.LoadServerConfig())
		go server.Start()
		stopStats := make(chan struct{})
		go monitorServerStats2(server, stopStats)
		<-ch
		close(stopStats)
		server.Stop()
		return
	case string(RunModeClient):
		client := vlan2.NewClient(conf2.LoadClientConfig())
		go client.Start()
		stopStats := make(chan struct{})
		go monitorClientStats2(client, stopStats)
		<-ch
		close(stopStats)
		client.Stop()
		fmt.Println()
		return
	}

}

func monitorClientStats2(client *vlan2.Client, stop <-chan struct{}) {
	time.Sleep(8 * time.Second)
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

			up := formatSpeed(stats.UploadBps) + "/s"
			down := formatSpeed(stats.DownloadBps) + "/s"
			usedUp := formatBytes(stats.UploadBytes)
			usedDown := formatBytes(stats.DownloadBytes)

			fmt.Printf(
				"\r\033[2K[Client] Up: %-12s Down: %-12s Used Up: %-12s Used Down: %-12s",
				up,
				down,
				usedUp,
				usedDown,
			)
		}
	}
}

func monitorServerStats2(server *vlan2.Server, stop <-chan struct{}) {
	time.Sleep(5 * time.Second)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return

		case <-ticker.C:
			peers := server.ListPeerTraffic()

			fmt.Print("\033[2J\033[H")
			fmt.Printf("[Server] Clients: %d\n", len(peers))

			for i, p := range peers {
				fmt.Printf("%d) device=%-18s ip=%-15s remote=%-22s\n",
					i+1,
					p.DeviceID,
					p.VirtualIP,
					p.RemoteAddr,
				)

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
