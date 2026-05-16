package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/securetcp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9443", "server address")
	clientKey := flag.String("client-key", "", "client private key base64")
	serverPub := flag.String("server-pub", "", "server public key base64")
	msg := flag.String("msg", "hello securetcp", "message to send")
	n := flag.Int("n", 3, "message count")
	flag.Parse()

	if *clientKey == "" {
		kp, err := securetcp.GenerateKeyPair()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("No -client-key provided. Generated a temporary client key pair:")
		fmt.Println("CLIENT_PRIVATE=", kp.PrivateKeyB64)
		fmt.Println("CLIENT_PUBLIC =", kp.PublicKeyB64)
		fmt.Println("Restart with -client-key $CLIENT_PRIVATE and -server-pub $SERVER_PUBLIC.")
		return
	}
	if *serverPub == "" {
		log.Fatal("missing -server-pub")
	}

	cli, err := securetcp.NewClient(securetcp.ClientConfig{
		Address:             *addr,
		ClientPrivateKeyB64: *clientKey,
		ServerPublicKeyB64:  *serverPub,
		AutoReconnect:       true,
		CommonConfig: securetcp.CommonConfig{
			ReadTimeout:     60 * time.Second,
			WriteTimeout:    15 * time.Second,
			HeartbeatBase:   10 * time.Second,
			HeartbeatJitter: 5 * time.Second,
			RekeyInterval:   45 * time.Second,
			OldKeyGrace:     30 * time.Second,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	ctx := context.Background()
	if err := cli.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	log.Println("connected to", *addr)

	for i := 0; i < *n; i++ {
		body := fmt.Sprintf("%s #%d", *msg, i+1)
		if err := cli.Write(ctx, []byte(body)); err != nil {
			log.Fatal(err)
		}
		reply, err := cli.Read(ctx)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("reply: %q", string(reply))
		time.Sleep(1 * time.Second)
	}
}
