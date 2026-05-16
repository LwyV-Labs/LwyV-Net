package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/LwyV-Labs/LwyV-Net/tcpkit"
)

type serverHandler struct{}

func (serverHandler) OnEvent(e *tcpkit.Event) {
	switch e.GetType() {
	case tcpkit.EventOpen:
		fmt.Println("client open:", e.GetConnection().GetRemoteAddr())
	case tcpkit.EventData:
		text := string(e.GetPayload())
		fmt.Println("client data:", text)
		e.GetConnection().SendText("server received: " + text)
	case tcpkit.EventClose:
		fmt.Println("client close:", e.GetMessage())
	case tcpkit.EventError:
		fmt.Println("server error:", e.GetMessage())
	}
}

func main() {
	cfg := tcpkit.NewConfig()
	cfg.HeartbeatIntervalMillis = 15_000
	cfg.ReadTimeoutMillis = 45_000
	cfg.WriteTimeoutMillis = 10_000
	cfg.NotifyHeartbeat = false

	server := tcpkit.NewServer(":9000", cfg, serverHandler{})

	if err := server.Start(); err != "" {
		panic(err)
	}
	fmt.Println("server listening on :9000")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	server.Stop()
}
