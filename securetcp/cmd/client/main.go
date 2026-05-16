package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/securetcp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "server address")
	pubHex := flag.String("pub", "", "server public key hex")
	msg := flag.String("msg", "hello securetcp", "message to send")
	loop := flag.Bool("loop", false, "keep sending messages and auto reconnect after accidental disconnect")
	interval := flag.Duration("interval", 2*time.Second, "send interval in loop mode")
	flag.Parse()

	serverPub, err := hex.DecodeString(strings.TrimSpace(*pubHex))
	if err != nil || len(serverPub) != 32 {
		log.Fatalf("invalid -pub, need 32-byte hex server public key")
	}

	client, err := securetcp.NewClient(*addr, securetcp.Config{
		ServerStaticPublicKey: serverPub,
		AllowResume:           true,
		AutoReconnect:         *loop,
		HeartbeatInterval:     10 * time.Second,
		HeartbeatTimeout:      30 * time.Second,
		ReadTimeout:           60 * time.Second,
		WriteTimeout:          10 * time.Second,
		RekeyInterval:         2 * time.Minute,
		OldKeyGrace:           30 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *loop {
		err = client.Run(ctx, func(c *securetcp.Conn) {
			log.Printf("connected: %s", c.NetConn().RemoteAddr())
			runLoop(ctx, c, *msg, *interval)
			log.Printf("connection ended, reconnecting if not actively stopped")
		})
		if err != nil && ctx.Err() == nil {
			log.Fatal(err)
		}
		return
	}

	conn, err := client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if err := conn.WriteMessage([]byte(*msg)); err != nil {
		log.Fatal(err)
	}
	replyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := conn.ReadMessageContext(replyCtx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("reply: %s\n", string(reply))
}

func runLoop(ctx context.Context, c *securetcp.Conn, msg string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	seq := 1
	for {
		select {
		case <-ctx.Done():
			_ = c.Close()
			return
		case <-c.Done():
			return
		case <-ticker.C:
			body := fmt.Sprintf("%s #%d", msg, seq)
			seq++
			if err := c.WriteMessage([]byte(body)); err != nil {
				return
			}

			readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			reply, err := c.ReadMessageContext(readCtx)
			cancel()
			if err != nil {
				return
			}
			fmt.Printf("reply: %s\n", string(reply))
		}
	}
}
