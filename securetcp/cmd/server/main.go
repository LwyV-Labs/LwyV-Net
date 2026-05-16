package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/securetcp"
)

func main() {
	addr := flag.String("addr", ":9443", "listen address")
	serverKey := flag.String("server-key", "", "server private key base64")
	readTimeout := flag.Duration("read-timeout", 60*time.Second, "read timeout")
	writeTimeout := flag.Duration("write-timeout", 15*time.Second, "write timeout")
	flag.Parse()

	if *serverKey == "" {
		kp, err := securetcp.GenerateKeyPair()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("No -server-key provided. Generated a temporary server key pair:")
		fmt.Println("SERVER_PRIVATE=", kp.PrivateKeyB64)
		fmt.Println("SERVER_PUBLIC =", kp.PublicKeyB64)
		fmt.Println("Restart with -server-key $SERVER_PRIVATE, and pass SERVER_PUBLIC to the client.")
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := securetcp.NewServer(securetcp.ServerConfig{
		Address:             *addr,
		ServerPrivateKeyB64: *serverKey,
		CommonConfig: securetcp.CommonConfig{
			ReadTimeout:     *readTimeout,
			WriteTimeout:    *writeTimeout,
			HeartbeatBase:   20 * time.Second,
			HeartbeatJitter: 8 * time.Second,
			RekeyInterval:   2 * time.Minute,
			OldKeyGrace:     30 * time.Second,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("securetcp server listening on", *addr)
	err = srv.ListenAndServe(ctx, func(c *securetcp.Conn) {
		log.Printf("client connected: %s peerStatic=%s", c.RemoteAddr(), c.PeerStaticPublicKeyB64())
		for {
			msg, err := c.Read(ctx)
			if err != nil {
				log.Printf("client %s disconnected: %v", c.RemoteAddr(), err)
				return
			}
			log.Printf("recv from %s: %q", c.RemoteAddr(), string(msg))
			_ = c.Write([]byte("echo: " + string(msg)))
		}
	})
	if err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
