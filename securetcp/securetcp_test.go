package securetcp

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestFrameReadWrite(t *testing.T) {
	cfg := CommonConfig{ReadTimeout: time.Second, WriteTimeout: time.Second}
	cfg.normalize()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	go func() {
		_ = writeFrame(a, cfg, FrameData, []byte("abc"))
	}()
	typ, payload, err := readFrame(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if typ != FrameData || string(payload) != "abc" {
		t.Fatalf("got typ=%v payload=%q", typ, payload)
	}
}

func TestSecureConnOverPipe(t *testing.T) {
	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	serverPriv, err := parsePrivateKeyB64(serverKP.PrivateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, err := parsePrivateKeyB64(clientKP.PrivateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := parsePublicKeyB64(serverKP.PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}

	cfg := CommonConfig{
		ReadTimeout:   2 * time.Second,
		WriteTimeout:  2 * time.Second,
		HeartbeatBase: time.Hour,
		RekeyInterval: time.Hour,
	}
	cfg.normalize()

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	serverReady := make(chan *Conn, 1)
	serverErr := make(chan error, 1)
	go func() {
		hs, err := serverHandshake(serverRaw, cfg, serverPriv)
		if err != nil {
			serverErr <- err
			return
		}
		sc, err := newConn(serverRaw, cfg, RoleServer, hs, false, false)
		if err != nil {
			serverErr <- err
			return
		}
		sc.Start()
		serverReady <- sc
	}()

	hs, err := clientHandshake(clientRaw, cfg, clientPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := newConn(clientRaw, cfg, RoleClient, hs, false, false)
	if err != nil {
		t.Fatal(err)
	}
	cc.Start()

	var sc *Conn
	select {
	case sc = <-serverReady:
	case err := <-serverErr:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake timeout")
	}
	defer cc.Close()
	defer sc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cc.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	msg, err := sc.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "hello" {
		t.Fatalf("server read %q", msg)
	}
	if err := sc.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	reply, err := cc.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "world" {
		t.Fatalf("client read %q", reply)
	}
}
