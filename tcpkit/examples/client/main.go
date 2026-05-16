package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/LwyV-Labs/LwyV-Net/tcpkit"
)

type clientHandler struct{}

func (clientHandler) OnEvent(e *tcpkit.Event) {
	switch e.GetType() {
	case tcpkit.EventOpen:
		fmt.Println("connected:", e.GetConnection().GetRemoteAddr())
	case tcpkit.EventData:
		fmt.Println("server:", string(e.GetPayload()))
	case tcpkit.EventClose:
		fmt.Println("closed:", e.GetMessage())
	case tcpkit.EventError:
		fmt.Println("client error:", e.GetMessage())
	}
}

func main() {
	cfg := tcpkit.NewConfig()
	cfg.HeartbeatIntervalMillis = 15_000
	cfg.ReadTimeoutMillis = 45_000
	cfg.WriteTimeoutMillis = 10_000
	cfg.NotifyHeartbeat = false

	client := tcpkit.NewClient("127.0.0.1:9000", cfg, clientHandler{})

	if err := client.Start(); err != "" {
		panic(err)
	}
	defer client.Stop()

	fmt.Println("type message and press Enter, input q to quit")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "q" || line == "quit" || line == "exit" {
			return
		}
		if line == "" {
			continue
		}
		if err := client.SendText(line); err != "" {
			fmt.Println("send error:", err)
		}
	}
}
