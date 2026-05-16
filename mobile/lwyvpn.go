// Package mobile is the gomobile-friendly Android wrapper for LwyV-Net.
//
// Android/Kotlin owns VpnService and creates the VPN interface. Go owns tcpx,
// client auth, vDHCP, reconnect, and packet forwarding through the fd passed by
// Kotlin.
package mobile

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/LwyV-Labs/LwyV-Net/tcpx"
	vdhcp2 "github.com/LwyV-Labs/LwyV-Net/vdhcp"
)

const (
	stateStarting     = "starting"
	stateConnecting   = "connecting"
	stateConnected    = "connected"
	stateAuthenticing = "authenticating"
	stateAddressing   = "requesting_address"
	stateReady        = "ready"
	stateDisconnected = "disconnected"
	stateStopped      = "stopped"
)

// Keep the mobile protocol self-contained. Do not import vlan2 here, because
// vlan2 also imports desktop TUN/router code. gomobile would then try to compile
// that desktop code for Android.
type payloadType byte

const (
	typeAuth  payloadType = 1
	typeVDHCP payloadType = 2
	typeIP    payloadType = 3
)

const (
	clientAuthVersion     byte = 1
	clientAuthNonceSize        = 16
	clientAuthMACSize          = sha256.Size
	clientAuthPayloadSize      = 1 + 32 + clientAuthNonceSize + clientAuthMACSize
)

// EventListener is implemented by Kotlin/Java.
//
// gomobile binds simple types well: string, bool, int64, []byte. Avoid exposing
// context.Context, channels, time.Duration, net.Conn, maps, or complex structs.
type EventListener interface {
	OnState(state string)
	OnError(message string)

	// Called after vDHCP returns an address.
	// Kotlin should create VpnService.Builder here and then call AttachTun(fd, mtu).
	OnAddress(ip string, subnetMask string, gateway string, mtu int64)

	// Called once per second while the client is running.
	OnTraffic(uploadBytes int64, downloadBytes int64)
}

// SocketProtector is implemented by Kotlin/Java using VpnService.protect(fd).
// The real tcpx TCP socket must be protected, otherwise a full-tunnel VPN route
// can capture the tunnel socket itself and create a routing loop.
type SocketProtector interface {
	Protect(fd int64) bool
}

// Client is the Android-facing LwyV-Net client.
type Client struct {
	mu sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc

	tcpxClient *tcpx.Client
	tun        *androidTun

	listener  EventListener
	protector SocketProtector

	server          string
	serverPublicKey string
	privateKey      string // base64 or hex accepted; generated as base64 when empty
	publicKey       string // base64, derived from privateKey

	mtu int64

	pendingDHCPReqID string
	ip               string
	subnetMask       string
	gateway          string

	started      atomic.Bool
	sessionReady atomic.Bool
	uploadBytes  atomic.Int64
	downBytes    atomic.Int64
}

// NewClient creates a mobile client instance. Kotlin normally calls
// mobile.NewClient().
func NewClient() *Client {
	return &Client{}
}

// GeneratePrivateKey returns a base64 X25519 private key.
func GeneratePrivateKey() (string, error) {
	priv, _, err := tcpx.GenerateStaticKeyBase64()
	return priv, err
}

// PublicKeyFromPrivate returns a base64 X25519 public key for privateKey.
func PublicKeyFromPrivate(privateKey string) (string, error) {
	return tcpx.PublicKeyBase64FromPrivate(privateKey)
}

// NormalizePublicKeyHex converts hex/base64/base64url X25519 public key to hex.
func NormalizePublicKeyHex(publicKey string) (string, error) {
	return tcpx.NormalizePublicKeyHex(publicKey)
}

// MaskToPrefix converts dotted IPv4 mask, such as 255.255.255.0, to 24.
func MaskToPrefix(mask string) (int64, error) {
	ip := net.ParseIP(strings.TrimSpace(mask)).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 mask: %s", mask)
	}
	ones, bits := net.IPMask(ip).Size()
	if bits != 32 || ones < 0 {
		return 0, fmt.Errorf("invalid IPv4 mask: %s", mask)
	}
	return int64(ones), nil
}

// Start starts the encrypted TCP control/session loop.
//
// privateKey can be empty. If empty, Go generates one. Kotlin should then call
// PrivateKey() and persist it, otherwise the client will become a new identity
// on the next app start and vDHCP will allocate another IP.
//
// mtu should normally be your config MTU, for example 1300. If mtu <= 0, 1300 is
// used.
func (c *Client) Start(server string, serverPublicKey string, privateKey string, mtu int64, listener EventListener, protector SocketProtector) error {
	server = strings.TrimSpace(server)
	serverPublicKey = strings.TrimSpace(serverPublicKey)
	privateKey = strings.TrimSpace(privateKey)

	if server == "" {
		return errors.New("server is empty")
	}
	if serverPublicKey == "" {
		return errors.New("serverPublicKey is empty")
	}
	if listener == nil {
		return errors.New("EventListener is nil")
	}
	if protector == nil {
		return errors.New("SocketProtector is nil; implement it with VpnService.protect(fd)")
	}
	if mtu <= 0 {
		mtu = 1300
	}

	if privateKey == "" {
		generated, err := GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate private key: %w", err)
		}
		privateKey = generated
	}
	publicKey, err := PublicKeyFromPrivate(privateKey)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	serverPublicKeyHex, err := tcpx.NormalizePublicKeyHex(serverPublicKey)
	if err != nil {
		return fmt.Errorf("parse server public key: %w", err)
	}

	if !c.started.CompareAndSwap(false, true) {
		return errors.New("client already started")
	}

	ctx, cancel := context.WithCancel(context.Background())

	c.mu.Lock()
	c.ctx = ctx
	c.cancel = cancel
	c.listener = listener
	c.protector = protector
	c.server = server
	c.serverPublicKey = serverPublicKey
	c.privateKey = privateKey
	c.publicKey = publicKey
	c.mtu = mtu
	c.pendingDHCPReqID = ""
	c.ip = ""
	c.subnetMask = ""
	c.gateway = ""
	c.tcpxClient = nil
	c.tun = nil
	c.uploadBytes.Store(0)
	c.downBytes.Store(0)
	c.sessionReady.Store(false)
	c.mu.Unlock()

	c.emitState(stateStarting)

	client, err := tcpx.NewClient(tcpx.ClientConfig{
		Addr:               server,
		ServerPublicKeyHex: serverPublicKeyHex,
		DialContext:        c.dialContext,
		BaseConfig: tcpx.BaseConfig{
			ReadTimeout:       45 * time.Second,
			WriteTimeout:      10 * time.Second,
			HeartbeatBase:     15 * time.Second,
			HeartbeatJitter:   5 * time.Second,
			KeyRotateInterval: 10 * time.Minute,
			OldKeyGrace:       2 * time.Minute,
			ReplayWindow:      64,
			MaxPayload:        4 << 20,
		},
		ReconnectBase:   time.Second,
		ReconnectJitter: 3 * time.Second,
		OnConnect: func(conn *tcpx.SecureConn) {
			c.onConnect(conn)
		},
		OnDisconnect: func(err error) {
			c.onDisconnect(err)
		},
		OnMessage: func(conn *tcpx.SecureConn, payload []byte) {
			c.onMessage(conn, payload)
		},
	})
	if err != nil {
		c.Stop()
		return err
	}

	c.mu.Lock()
	c.tcpxClient = client
	c.mu.Unlock()

	go c.trafficLoop(ctx)
	go func() {
		c.emitState(stateConnecting)
		if err := client.Run(ctx); err != nil && ctx.Err() == nil {
			c.emitError("tcpx run: " + err.Error())
		}
		c.sessionReady.Store(false)
		c.emitState(stateStopped)
	}()

	return nil
}

// AttachTun attaches Android VpnService fd to the Go forwarding loop.
//
// fd must come from ParcelFileDescriptor.detachFd(). After AttachTun returns,
// Go owns fd and Kotlin should not close that fd again.
func (c *Client) AttachTun(fd int64, mtu int64) error {
	if fd < 0 {
		return fmt.Errorf("invalid tun fd: %d", fd)
	}
	if mtu <= 0 {
		c.mu.RLock()
		mtu = c.mtu
		c.mu.RUnlock()
		if mtu <= 0 {
			mtu = 1300
		}
	}

	c.mu.Lock()
	if !c.started.Load() || c.ctx == nil {
		c.mu.Unlock()
		return errors.New("client is not started")
	}
	oldTun := c.tun
	t := newAndroidTun(int(fd), int(mtu))
	c.tun = t
	c.mtu = mtu
	ctx := c.ctx
	c.mu.Unlock()

	if oldTun != nil {
		_ = oldTun.Close()
	}

	go t.readLoop(ctx, func(pkt []byte) {
		// During reconnect/session setup, packets are dropped quietly. This avoids
		// flooding Android logs when apps continue sending while the tunnel is down.
		if err := c.SendIP(pkt); err != nil && c.sessionReady.Load() {
			c.emitError("send ip: " + err.Error())
		}
	}, func(err error) {
		c.emitError("tun read: " + err.Error())
	})

	c.emitState(stateReady)
	return nil
}

// SendIP sends one raw IPv4 packet to the server. Normally called internally by
// androidTun.readLoop.
func (c *Client) SendIP(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	if !c.sessionReady.Load() {
		return nil
	}
	c.mu.RLock()
	client := c.tcpxClient
	c.mu.RUnlock()
	if client == nil {
		return errors.New("tcpx client is nil")
	}
	if err := client.Write(pack(typeIP, pkt)); err != nil {
		return err
	}
	c.uploadBytes.Add(int64(len(pkt)))
	return nil
}

// Stop closes the TCP session, TUN fd, and all loops.
func (c *Client) Stop() {
	if !c.started.CompareAndSwap(true, false) {
		return
	}

	c.sessionReady.Store(false)

	c.mu.Lock()
	cancel := c.cancel
	client := c.tcpxClient
	tun := c.tun
	c.cancel = nil
	c.ctx = nil
	c.tcpxClient = nil
	c.tun = nil
	c.pendingDHCPReqID = ""
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if client != nil {
		_ = client.Close()
	}
	if tun != nil {
		_ = tun.Close()
	}
	c.emitState(stateStopped)
}

func (c *Client) PrivateKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.privateKey
}

func (c *Client) PublicKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.publicKey
}

func (c *Client) VirtualIP() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ip
}

func (c *Client) SubnetMask() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.subnetMask
}

func (c *Client) Gateway() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gateway
}

func (c *Client) UploadBytes() int64 {
	return c.uploadBytes.Load()
}

func (c *Client) DownloadBytes() int64 {
	return c.downBytes.Load()
}

func (c *Client) dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	c.mu.RLock()
	protector := c.protector
	c.mu.RUnlock()

	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(network, address string, raw syscall.RawConn) error {
			var protectErr error
			if err := raw.Control(func(fd uintptr) {
				if protector != nil && !protector.Protect(int64(fd)) {
					protectErr = errors.New("VpnService.protect(fd) returned false")
				}
			}); err != nil {
				return err
			}
			return protectErr
		},
	}
	return dialer.DialContext(ctx, network, address)
}

func (c *Client) onConnect(conn *tcpx.SecureConn) {
	c.sessionReady.Store(false)
	c.emitState(stateConnected)
	c.emitState(stateAuthenticing)

	c.mu.RLock()
	privateKey := c.privateKey
	serverPublicKey := c.serverPublicKey
	c.mu.RUnlock()

	authPayload, _, err := encodeClientAuth(privateKey, serverPublicKey)
	if err != nil {
		c.emitError("encode auth: " + err.Error())
		_ = conn.Close()
		return
	}
	if err := conn.Write(pack(typeAuth, authPayload)); err != nil {
		c.emitError("send auth: " + err.Error())
		_ = conn.Close()
		return
	}

	c.emitState(stateAddressing)
	discover, reqID, err := vdhcp2.EncodeDiscover()
	if err != nil {
		c.emitError("encode vdhcp discover: " + err.Error())
		_ = conn.Close()
		return
	}
	c.mu.Lock()
	c.pendingDHCPReqID = reqID
	c.mu.Unlock()

	if err := conn.Write(pack(typeVDHCP, discover)); err != nil {
		c.emitError("send vdhcp discover: " + err.Error())
		_ = conn.Close()
		return
	}
}

func (c *Client) onDisconnect(err error) {
	c.sessionReady.Store(false)
	if err != nil {
		c.emitError("disconnected: " + err.Error())
	}
	c.mu.Lock()
	c.pendingDHCPReqID = ""
	c.mu.Unlock()
	c.emitState(stateDisconnected)
}

func (c *Client) onMessage(conn *tcpx.SecureConn, raw []byte) {
	typ, payload, err := unpack(raw)
	if err != nil {
		c.emitError("unpack message: " + err.Error())
		_ = conn.Close()
		return
	}

	switch typ {
	case typeVDHCP:
		c.handleVDHCP(conn, payload)
	case typeIP:
		c.handleIP(payload)
	case typeAuth:
		c.emitError("unexpected TypeAuth from server")
		_ = conn.Close()
	default:
		c.emitError(fmt.Sprintf("unknown payload type: %d", typ))
		_ = conn.Close()
	}
}

func (c *Client) handleVDHCP(conn *tcpx.SecureConn, payload []byte) {
	msg, err := vdhcp2.DecodeMessage(payload)
	if err != nil {
		c.emitError("decode vdhcp: " + err.Error())
		_ = conn.Close()
		return
	}
	if msg.Type == vdhcp2.MessageTypeNak {
		c.emitError("vdhcp nak: " + msg.Reason)
		_ = conn.Close()
		return
	}

	c.mu.RLock()
	reqID := c.pendingDHCPReqID
	c.mu.RUnlock()
	if err := vdhcp2.ValidateOffer(msg, reqID); err != nil {
		c.emitError("invalid vdhcp offer: " + err.Error())
		_ = conn.Close()
		return
	}

	c.mu.Lock()
	c.ip = msg.IP
	c.subnetMask = msg.SubnetMask
	c.gateway = msg.Gateway
	c.pendingDHCPReqID = ""
	mtu := c.mtu
	listener := c.listener
	c.mu.Unlock()

	c.sessionReady.Store(true)
	if listener != nil {
		listener.OnAddress(msg.IP, msg.SubnetMask, msg.Gateway, mtu)
	}
}

func (c *Client) handleIP(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	c.mu.RLock()
	tun := c.tun
	c.mu.RUnlock()
	if tun == nil {
		// Server may send packets before Kotlin attaches fd. Drop them.
		return
	}
	if err := tun.Write(pkt); err != nil {
		c.emitError("tun write: " + err.Error())
		return
	}
	c.downBytes.Add(int64(len(pkt)))
}

func (c *Client) trafficLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			listener := c.listener
			c.mu.RUnlock()
			if listener != nil {
				listener.OnTraffic(c.uploadBytes.Load(), c.downBytes.Load())
			}
		}
	}
}

func (c *Client) emitState(state string) {
	c.mu.RLock()
	listener := c.listener
	c.mu.RUnlock()
	if listener != nil {
		listener.OnState(state)
	}
}

func (c *Client) emitError(message string) {
	c.mu.RLock()
	listener := c.listener
	c.mu.RUnlock()
	if listener != nil {
		listener.OnError(message)
	}
}

func pack(t payloadType, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = byte(t)
	copy(out[1:], payload)
	return out
}

func unpack(b []byte) (payloadType, []byte, error) {
	if len(b) < 1 {
		return 0, nil, errors.New("empty payload")
	}
	t := payloadType(b[0])
	switch t {
	case typeAuth, typeVDHCP, typeIP:
		return t, b[1:], nil
	default:
		return 0, nil, fmt.Errorf("unknown payload type: %d", b[0])
	}
}

func encodeClientAuth(clientPrivateKey string, serverPublicKey string) ([]byte, string, error) {
	clientPriv, err := tcpx.ParsePrivateKeyAny(clientPrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse client private key: %w", err)
	}
	serverPub, err := tcpx.ParsePublicKeyAny(serverPublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("parse server public key: %w", err)
	}

	shared, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, "", fmt.Errorf("client auth ecdh: %w", err)
	}
	clientPubRaw := clientPriv.PublicKey().Bytes()
	serverPubRaw := serverPub.Bytes()

	nonce := make([]byte, clientAuthNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	mac := clientAuthMAC(shared, clientPubRaw, serverPubRaw, nonce)

	payload := make([]byte, 0, clientAuthPayloadSize)
	payload = append(payload, clientAuthVersion)
	payload = append(payload, clientPubRaw...)
	payload = append(payload, nonce...)
	payload = append(payload, mac...)
	return payload, hex.EncodeToString(clientPubRaw), nil
}

func clientAuthMAC(shared []byte, clientPub []byte, serverPub []byte, nonce []byte) []byte {
	root := hmac.New(sha256.New, shared)
	_, _ = root.Write([]byte("vlan2 client auth root v2"))
	prk := root.Sum(nil)

	mac := hmac.New(sha256.New, prk)
	_, _ = mac.Write([]byte("vlan2 client auth payload v2"))
	_, _ = mac.Write(clientPub)
	_, _ = mac.Write(serverPub)
	_, _ = mac.Write(nonce)
	return mac.Sum(nil)
}
