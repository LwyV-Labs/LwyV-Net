// Package tcpkit implements a small framed TCP protocol with client/server,
// heartbeat, read/write deadlines and exact-length IO helpers.
//
// Frame format, 10 bytes header, big endian:
//
//	uint32 magic | uint8 version | uint8 frame_type | uint32 payload_length | payload
package tcpkit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// HeaderSize is the fixed frame header size: magic(4)+version(1)+type(1)+length(4).
	HeaderSize = 10

	// Defaults. Magic is ASCII "TKIT".
	DefaultMagic                   int64 = 0x544B4954
	DefaultVersion                 int32 = 1
	DefaultMaxPayloadBytes         int64 = 4 * 1024 * 1024
	DefaultReadTimeoutMillis       int64 = 45_000
	DefaultWriteTimeoutMillis      int64 = 10_000
	DefaultHeartbeatIntervalMillis int64 = 15_000
)

const (
	// FrameTypeData carries application bytes.
	FrameTypeData int32 = 1
	// FrameTypePing is sent automatically by the client after the TCP connection is established.
	FrameTypePing int32 = 2
	// FrameTypePong is sent automatically after receiving Ping.
	FrameTypePong int32 = 3
	// FrameTypeClose is a graceful close notification.
	FrameTypeClose int32 = 4
)

const (
	EventOpen  int32 = 1
	EventData  int32 = 2
	EventFrame int32 = 3
	EventClose int32 = 4
	EventError int32 = 5
)

var (
	errClosed          = errors.New("tcpkit: connection closed")
	errBadMagic        = errors.New("tcpkit: bad magic")
	errBadVersion      = errors.New("tcpkit: bad version")
	errBadFrameType    = errors.New("tcpkit: bad frame type")
	errPayloadTooLarge = errors.New("tcpkit: payload too large")
)

var globalConnID int64

// Config is intentionally simple for gomobile/Android binding.
// Durations use milliseconds, not time.Duration, because int64 maps more cleanly to Kotlin/Java.
type Config struct {
	Magic                   int64
	Version                 int32
	MaxPayloadBytes         int64
	ReadTimeoutMillis       int64
	WriteTimeoutMillis      int64
	HeartbeatIntervalMillis int64

	// ServerAutoPing makes server also send Ping periodically. Default false.
	// Even when false, server still automatically responds Pong to client Ping.
	ServerAutoPing bool

	// NotifyHeartbeat emits EventFrame for Ping/Pong. Default false to reduce callback noise.
	NotifyHeartbeat bool
}

// NewConfig returns a safe default config.
func NewConfig() *Config {
	return &Config{
		Magic:                   DefaultMagic,
		Version:                 DefaultVersion,
		MaxPayloadBytes:         DefaultMaxPayloadBytes,
		ReadTimeoutMillis:       DefaultReadTimeoutMillis,
		WriteTimeoutMillis:      DefaultWriteTimeoutMillis,
		HeartbeatIntervalMillis: DefaultHeartbeatIntervalMillis,
		ServerAutoPing:          false,
		NotifyHeartbeat:         false,
	}
}

// Handler is the single callback interface. Kotlin only needs to implement OnEvent.
type Handler interface {
	OnEvent(e *Event)
}

// Event is delivered to Handler.OnEvent.
type Event struct {
	eventType int32
	conn      *Connection
	frameType int32
	payload   []byte
	message   string
}

func (e *Event) GetType() int32             { return e.eventType }
func (e *Event) GetConnection() *Connection { return e.conn }
func (e *Event) GetFrameType() int32        { return e.frameType }
func (e *Event) GetPayload() []byte         { return cloneBytes(e.payload) }
func (e *Event) GetMessage() string         { return e.message }

// Frame represents a decoded protocol frame.
type Frame struct {
	frameType int32
	payload   []byte
}

func (f *Frame) GetType() int32     { return f.frameType }
func (f *Frame) GetPayload() []byte { return cloneBytes(f.payload) }
func (f *Frame) GetLength() int64   { return int64(len(f.payload)) }

type normalizedConfig struct {
	magic             uint32
	version           uint8
	maxPayload        uint32
	readTimeout       time.Duration
	writeTimeout      time.Duration
	heartbeatInterval time.Duration
	serverAutoPing    bool
	notifyHeartbeat   bool
}

func normalizeConfig(c *Config) normalizedConfig {
	if c == nil {
		c = NewConfig()
	}
	magic := c.Magic
	if magic <= 0 || magic > int64(^uint32(0)) {
		magic = DefaultMagic
	}
	version := c.Version
	if version <= 0 || version > 255 {
		version = DefaultVersion
	}
	maxPayload := c.MaxPayloadBytes
	if maxPayload <= 0 || maxPayload > int64(^uint32(0)) {
		maxPayload = DefaultMaxPayloadBytes
	}
	readTimeout := millisToDuration(c.ReadTimeoutMillis)
	writeTimeout := millisToDuration(c.WriteTimeoutMillis)
	heartbeat := millisToDuration(c.HeartbeatIntervalMillis)

	return normalizedConfig{
		magic:             uint32(magic),
		version:           uint8(version),
		maxPayload:        uint32(maxPayload),
		readTimeout:       readTimeout,
		writeTimeout:      writeTimeout,
		heartbeatInterval: heartbeat,
		serverAutoPing:    c.ServerAutoPing,
		notifyHeartbeat:   c.NotifyHeartbeat,
	}
}

func millisToDuration(ms int64) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// EncodeFrame returns a complete wire frame: header + payload.
func EncodeFrame(frameType int32, payload []byte, cfg *Config) ([]byte, error) {
	nc := normalizeConfig(cfg)
	if err := validateFrameType(frameType); err != nil {
		return nil, err
	}
	if len(payload) > int(nc.maxPayload) {
		return nil, fmt.Errorf("%w: %d > %d", errPayloadTooLarge, len(payload), nc.maxPayload)
	}

	out := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(out[0:4], nc.magic)
	out[4] = nc.version
	out[5] = byte(frameType)
	binary.BigEndian.PutUint32(out[6:10], uint32(len(payload)))
	copy(out[HeaderSize:], payload)
	return out, nil
}

// DecodeFrame decodes exactly one complete frame from data.
func DecodeFrame(data []byte, cfg *Config) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, io.ErrUnexpectedEOF
	}
	nc := normalizeConfig(cfg)
	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != nc.magic {
		return nil, errBadMagic
	}
	if data[4] != nc.version {
		return nil, errBadVersion
	}
	ft := int32(data[5])
	if err := validateFrameType(ft); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(data[6:10])
	if n > nc.maxPayload {
		return nil, fmt.Errorf("%w: %d > %d", errPayloadTooLarge, n, nc.maxPayload)
	}
	if len(data) != HeaderSize+int(n) {
		return nil, io.ErrUnexpectedEOF
	}
	payload := make([]byte, int(n))
	copy(payload, data[HeaderSize:])
	return &Frame{frameType: ft, payload: payload}, nil
}

func validateFrameType(frameType int32) error {
	switch frameType {
	case FrameTypeData, FrameTypePing, FrameTypePong, FrameTypeClose:
		return nil
	default:
		return fmt.Errorf("%w: %d", errBadFrameType, frameType)
	}
}

func readFrame(r io.Reader, nc normalizedConfig) (*Frame, error) {
	header := make([]byte, HeaderSize)
	if err := readExact(r, header); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(header[0:4]) != nc.magic {
		return nil, errBadMagic
	}
	if header[4] != nc.version {
		return nil, errBadVersion
	}
	ft := int32(header[5])
	if err := validateFrameType(ft); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[6:10])
	if n > nc.maxPayload {
		return nil, fmt.Errorf("%w: %d > %d", errPayloadTooLarge, n, nc.maxPayload)
	}
	payload := make([]byte, int(n))
	if n > 0 {
		if err := readExact(r, payload); err != nil {
			return nil, err
		}
	}
	return &Frame{frameType: ft, payload: payload}, nil
}

// readExact keeps reading until buf is full or an error occurs.
func readExact(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	return err
}

// writeExact keeps writing until data is fully written or an error occurs.
func writeExact(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// Connection wraps one TCP connection.
type Connection struct {
	id      int64
	conn    net.Conn
	cfg     normalizedConfig
	handler Handler
	onDone  func(*Connection)

	writeMu   sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	closed    int32
	lastPong  int64
}

func newConnection(conn net.Conn, cfg normalizedConfig, handler Handler, onDone func(*Connection)) *Connection {
	id := atomic.AddInt64(&globalConnID, 1)
	return &Connection{
		id:       id,
		conn:     conn,
		cfg:      cfg,
		handler:  handler,
		onDone:   onDone,
		done:     make(chan struct{}),
		lastPong: time.Now().UnixNano(),
	}
}

func (c *Connection) GetID() int64 { return c.id }

func (c *Connection) GetRemoteAddr() string {
	if c == nil || c.conn == nil || c.conn.RemoteAddr() == nil {
		return ""
	}
	return c.conn.RemoteAddr().String()
}

func (c *Connection) GetLocalAddr() string {
	if c == nil || c.conn == nil || c.conn.LocalAddr() == nil {
		return ""
	}
	return c.conn.LocalAddr().String()
}

func (c *Connection) IsClosed() bool {
	return c == nil || atomic.LoadInt32(&c.closed) != 0
}

func (c *Connection) LastPongUnixMillis() int64 {
	ns := atomic.LoadInt64(&c.lastPong)
	if ns <= 0 {
		return 0
	}
	return ns / int64(time.Millisecond)
}

// Send sends an application data frame.
func (c *Connection) Send(data []byte) string {
	return errString(c.sendFrame(FrameTypeData, data))
}

// SendText is convenient for Kotlin/Java callers.
func (c *Connection) SendText(s string) string {
	return c.Send([]byte(s))
}

// SendFrame sends any valid frame type. Empty string means success.
func (c *Connection) SendFrame(frameType int32, payload []byte) string {
	return errString(c.sendFrame(frameType, payload))
}

func (c *Connection) sendFrame(frameType int32, payload []byte) error {
	if c == nil || c.conn == nil {
		return errClosed
	}
	select {
	case <-c.done:
		return errClosed
	default:
	}
	if err := validateFrameType(frameType); err != nil {
		return err
	}
	if len(payload) > int(c.cfg.maxPayload) {
		return fmt.Errorf("%w: %d > %d", errPayloadTooLarge, len(payload), c.cfg.maxPayload)
	}

	frame := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], c.cfg.magic)
	frame[4] = c.cfg.version
	frame[5] = byte(frameType)
	binary.BigEndian.PutUint32(frame[6:10], uint32(len(payload)))
	copy(frame[HeaderSize:], payload)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.cfg.writeTimeout > 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.cfg.writeTimeout))
	}
	if err := writeExact(c.conn, frame); err != nil {
		c.emit(EventError, frameType, nil, err.Error())
		c.closeWithReason("write failed: " + err.Error())
		return err
	}
	return nil
}

// Close gracefully closes the connection. It attempts to send a Close frame first.
func (c *Connection) Close() string {
	if c == nil {
		return ""
	}
	_ = c.sendFrame(FrameTypeClose, nil)
	c.closeWithReason("closed by user")
	return ""
}

func (c *Connection) run(autoPing bool) {
	c.emit(EventOpen, 0, nil, "")

	if autoPing && c.cfg.heartbeatInterval > 0 {
		go c.heartbeatLoop()
	}

	for {
		if c.cfg.readTimeout > 0 {
			_ = c.conn.SetReadDeadline(time.Now().Add(c.cfg.readTimeout))
		}
		frame, err := readFrame(c.conn, c.cfg)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			c.emit(EventError, 0, nil, err.Error())
			c.closeWithReason("read failed: " + err.Error())
			return
		}

		switch frame.frameType {
		case FrameTypeData:
			c.emit(EventData, FrameTypeData, frame.payload, "")
		case FrameTypePing:
			if c.cfg.notifyHeartbeat {
				c.emit(EventFrame, FrameTypePing, frame.payload, "")
			}
			// Server and client both auto-pong for robustness.
			_ = c.sendFrame(FrameTypePong, frame.payload)
		case FrameTypePong:
			atomic.StoreInt64(&c.lastPong, time.Now().UnixNano())
			if c.cfg.notifyHeartbeat {
				c.emit(EventFrame, FrameTypePong, frame.payload, "")
			}
		case FrameTypeClose:
			c.closeWithReason("remote closed")
			return
		}
	}
}

func (c *Connection) heartbeatLoop() {
	ticker := time.NewTicker(c.cfg.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if err := c.sendFrame(FrameTypePing, nil); err != nil {
				return
			}
		}
	}
}

func (c *Connection) closeWithReason(reason string) {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.closed, 1)
		close(c.done)
		if c.conn != nil {
			_ = c.conn.Close()
		}
		if c.onDone != nil {
			c.onDone(c)
		}
		c.emit(EventClose, 0, nil, reason)
	})
}

func (c *Connection) emit(eventType int32, frameType int32, payload []byte, message string) {
	if c == nil || c.handler == nil {
		return
	}
	e := &Event{
		eventType: eventType,
		conn:      c,
		frameType: frameType,
		payload:   cloneBytes(payload),
		message:   message,
	}
	safeCall(c.handler, e)
}

func emitServer(handler Handler, eventType int32, message string) {
	if handler == nil {
		return
	}
	safeCall(handler, &Event{eventType: eventType, message: message})
}

func safeCall(handler Handler, e *Event) {
	defer func() { _ = recover() }()
	handler.OnEvent(e)
}

// Client is an async TCP client.
type Client struct {
	addr    string
	cfg     normalizedConfig
	handler Handler

	mu   sync.Mutex
	conn *Connection
}

func NewClient(addr string, cfg *Config, handler Handler) *Client {
	return &Client{addr: addr, cfg: normalizeConfig(cfg), handler: handler}
}

// Start connects and starts the read loop in a goroutine. Empty string means success.
func (c *Client) Start() string {
	if c == nil {
		return "nil client"
	}
	c.mu.Lock()
	if c.conn != nil && !c.conn.IsClosed() {
		c.mu.Unlock()
		return "client already started"
	}
	c.mu.Unlock()

	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		emitServer(c.handler, EventError, err.Error())
		return err.Error()
	}
	cc := newConnection(conn, c.cfg, c.handler, func(done *Connection) {
		c.mu.Lock()
		if c.conn == done {
			c.conn = nil
		}
		c.mu.Unlock()
	})

	c.mu.Lock()
	c.conn = cc
	c.mu.Unlock()

	go cc.run(true) // client auto-ping after connection established
	return ""
}

func (c *Client) Stop() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	cc := c.conn
	c.conn = nil
	c.mu.Unlock()
	if cc != nil {
		return cc.Close()
	}
	return ""
}

func (c *Client) Send(data []byte) string {
	cc := c.GetConnection()
	if cc == nil {
		return errClosed.Error()
	}
	return cc.Send(data)
}

func (c *Client) SendText(s string) string {
	return c.Send([]byte(s))
}

func (c *Client) GetConnection() *Connection {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

func (c *Client) IsConnected() bool {
	cc := c.GetConnection()
	return cc != nil && !cc.IsClosed()
}

// Server accepts TCP clients and wraps each accepted net.Conn as Connection.
type Server struct {
	addr    string
	cfg     normalizedConfig
	handler Handler

	mu       sync.Mutex
	listener net.Listener
	conns    sync.Map // map[int64]*Connection
	closed   int32
}

func NewServer(addr string, cfg *Config, handler Handler) *Server {
	return &Server{addr: addr, cfg: normalizeConfig(cfg), handler: handler}
}

// Start listens and starts accepting in a goroutine. Empty string means success.
func (s *Server) Start() string {
	if s == nil {
		return "nil server"
	}
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		return "server already started"
	}
	atomic.StoreInt32(&s.closed, 0)
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		emitServer(s.handler, EventError, err.Error())
		return err.Error()
	}
	s.listener = ln
	s.mu.Unlock()

	go s.acceptLoop(ln)
	return ""
}

// StartBlocking listens and accepts in the current goroutine. Empty string means normal stop/success.
func (s *Server) StartBlocking() string {
	if s == nil {
		return "nil server"
	}
	s.mu.Lock()
	if s.listener != nil {
		s.mu.Unlock()
		return "server already started"
	}
	atomic.StoreInt32(&s.closed, 0)
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		emitServer(s.handler, EventError, err.Error())
		return err.Error()
	}
	s.listener = ln
	s.mu.Unlock()

	return s.acceptLoop(ln)
}

func (s *Server) acceptLoop(ln net.Listener) string {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&s.closed) != 0 {
				return ""
			}
			emitServer(s.handler, EventError, err.Error())
			continue
		}

		cc := newConnection(conn, s.cfg, s.handler, func(done *Connection) {
			s.conns.Delete(done.GetID())
		})
		s.conns.Store(cc.GetID(), cc)
		go cc.run(s.cfg.serverAutoPing)
	}
}

func (s *Server) Stop() string {
	if s == nil {
		return ""
	}
	atomic.StoreInt32(&s.closed, 1)

	s.mu.Lock()
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	s.conns.Range(func(_, value any) bool {
		if c, ok := value.(*Connection); ok {
			_ = c.Close()
		}
		return true
	})
	return ""
}

func (s *Server) Broadcast(data []byte) string {
	if s == nil {
		return "nil server"
	}
	var firstErr string
	s.conns.Range(func(_, value any) bool {
		if c, ok := value.(*Connection); ok {
			if err := c.Send(data); err != "" && firstErr == "" {
				firstErr = err
			}
		}
		return true
	})
	return firstErr
}

func (s *Server) BroadcastText(text string) string {
	return s.Broadcast([]byte(text))
}

func (s *Server) ConnectionCount() int64 {
	if s == nil {
		return 0
	}
	var n int64
	s.conns.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
