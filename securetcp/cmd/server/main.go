package main

import (
	"encoding/hex"
	"errors"
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
	addr := flag.String("addr", ":9000", "listen address")
	keyFile := flag.String("key", "server_x25519.key", "hex encoded server private key file")
	flag.Parse()

	privateKey, publicKey, err := loadOrCreateServerKey(*keyFile)
	if err != nil {
		log.Fatalf("server key error: %v", err)
	}

	srv, err := securetcp.Listen(*addr, securetcp.Config{
		ServerStaticPrivateKey: privateKey,
		AllowResume:            true,
		HeartbeatInterval:      10 * time.Second,
		HeartbeatTimeout:       30 * time.Second,
		ReadTimeout:            60 * time.Second,
		WriteTimeout:           10 * time.Second,
		RekeyInterval:          2 * time.Minute,
		OldKeyGrace:            30 * time.Second,
	}, func(c *securetcp.Conn) {
		remote := c.NetConn().RemoteAddr().String()
		log.Printf("client connected: %s", remote)
		defer log.Printf("client disconnected: %s", remote)

		for {
			msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			log.Printf("recv from %s: %q", remote, string(msg))
			if err := c.WriteMessage(append([]byte("echo: "), msg...)); err != nil {
				return
			}
		}
	})
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	defer srv.Close()

	fmt.Printf("listening: %s\n", srv.Addr())
	fmt.Printf("server public key hex: %s\n", hex.EncodeToString(publicKey))
	fmt.Println("copy this public key to the client -pub argument")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Println("server shutting down")
}

func loadOrCreateServerKey(path string) ([]byte, []byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		privateKey, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, nil, err
		}
		publicKey, err := securetcp.PublicKeyFromPrivate(privateKey)
		return privateKey, publicKey, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	kp, err := securetcp.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(kp.Private)), 0600); err != nil {
		return nil, nil, err
	}
	return kp.Private, kp.Public, nil
}
