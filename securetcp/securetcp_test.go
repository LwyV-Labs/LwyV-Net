package securetcp

import (
	"context"
	"testing"
	"time"
)

func TestEchoAndRekey(t *testing.T) {
	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Listen("127.0.0.1:0", Config{
		ServerStaticPrivateKey: serverKP.Private,
		AllowResume:            true,
		HeartbeatInterval:      time.Second,
		HeartbeatTimeout:       5 * time.Second,
		RekeyInterval:          time.Hour,
	}, func(c *Conn) {
		for {
			msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(append([]byte("echo:"), msg...))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	client, err := NewClient(srv.Addr().String(), Config{
		ServerStaticPublicKey: serverKP.Public,
		AllowResume:           true,
		HeartbeatInterval:     time.Second,
		HeartbeatTimeout:      5 * time.Second,
		RekeyInterval:         time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.WriteMessage([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "echo:hello" {
		t.Fatalf("unexpected echo: %q", msg)
	}
	if err := conn.InitiateRekey(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := conn.WriteMessage([]byte("after")); err != nil {
		t.Fatal(err)
	}
	msg, err = conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "echo:after" {
		t.Fatalf("unexpected echo after rekey: %q", msg)
	}
}

func TestResume(t *testing.T) {
	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Listen("127.0.0.1:0", Config{
		ServerStaticPrivateKey: serverKP.Private,
		AllowResume:            true,
		RekeyInterval:          time.Hour,
	}, func(c *Conn) {
		for {
			msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(msg)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	client, err := NewClient(srv.Addr().String(), Config{ServerStaticPublicKey: serverKP.Public, AllowResume: true, RekeyInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	conn1, err := client.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn1.Close()
	conn2, err := client.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	if err := conn2.WriteMessage([]byte("resumed")); err != nil {
		t.Fatal(err)
	}
	msg, err := conn2.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "resumed" {
		t.Fatalf("unexpected msg: %q", msg)
	}
}
