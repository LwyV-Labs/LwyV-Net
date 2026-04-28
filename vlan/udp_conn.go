package vlan

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	udpPacketBufferSize = 64 * 1024
	udpPeerQueueSize    = 128 * 1024
)

type udpTimeoutError struct{}

func (udpTimeoutError) Error() string   { return "i/o timeout" }
func (udpTimeoutError) Timeout() bool   { return true }
func (udpTimeoutError) Temporary() bool { return true }

type udpFrameConn struct {
	pc       *net.UDPConn
	remote   *net.UDPAddr
	incoming chan []byte

	readMu  sync.Mutex
	readBuf []byte

	writeMu sync.Mutex

	deadlineMu   sync.Mutex
	readDeadline time.Time

	done      chan struct{}
	closeOnce sync.Once
	onClose   func()

	closePacketConn bool
}

func dialUDPFrameConn(serverAddr string) (net.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	pc, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	_ = pc.SetReadBuffer(16 * 1024 * 1024)
	_ = pc.SetWriteBuffer(16 * 1024 * 1024)

	return &udpFrameConn{
		pc:              pc,
		done:            make(chan struct{}),
		closePacketConn: true,
	}, nil
}

func newUDPServerFrameConn(pc *net.UDPConn, remote *net.UDPAddr, onClose func()) *udpFrameConn {
	return &udpFrameConn{
		pc:       pc,
		remote:   remote,
		incoming: make(chan []byte, udpPeerQueueSize),
		done:     make(chan struct{}),
		onClose:  onClose,
	}
}

func (c *udpFrameConn) enqueue(pkt []byte) bool {
	select {
	case <-c.done:
		return false
	case c.incoming <- pkt:
		return true
	default:
		// UDP 数据面允许丢包，队列满时不要阻塞整个服务端收包循环。
		return false
	}
}

func (c *udpFrameConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		pkt, err := c.readDatagram()
		if err != nil {
			return 0, err
		}
		c.readBuf = pkt
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *udpFrameConn) readDatagram() ([]byte, error) {
	if c.incoming != nil {
		return c.readQueuedDatagram()
	}

	buf := make([]byte, udpPacketBufferSize)
	n, err := c.pc.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *udpFrameConn) readQueuedDatagram() ([]byte, error) {
	deadline := c.getReadDeadline()
	if deadline.IsZero() {
		select {
		case <-c.done:
			return nil, net.ErrClosed
		case pkt := <-c.incoming:
			return pkt, nil
		}
	}

	wait := time.Until(deadline)
	if wait <= 0 {
		return nil, udpTimeoutError{}
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-c.done:
		return nil, net.ErrClosed
	case pkt := <-c.incoming:
		return pkt, nil
	case <-timer.C:
		return nil, udpTimeoutError{}
	}
}

func (c *udpFrameConn) Write(p []byte) (int, error) {
	if len(p) > udpPacketBufferSize {
		return 0, errors.New("udp frame too large")
	}

	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var (
		n   int
		err error
	)
	if c.remote != nil {
		n, err = c.pc.WriteToUDP(p, c.remote)
	} else {
		n, err = c.pc.Write(p)
	}
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (c *udpFrameConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		if c.onClose != nil {
			c.onClose()
		}
		if c.closePacketConn {
			err = c.pc.Close()
		}
	})
	return err
}

func (c *udpFrameConn) LocalAddr() net.Addr {
	if c.pc == nil {
		return nil
	}
	return c.pc.LocalAddr()
}

func (c *udpFrameConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	if c.pc == nil {
		return nil
	}
	return c.pc.RemoteAddr()
}

func (c *udpFrameConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *udpFrameConn) SetReadDeadline(t time.Time) error {
	if c.incoming == nil && c.pc != nil {
		return c.pc.SetReadDeadline(t)
	}
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *udpFrameConn) SetWriteDeadline(t time.Time) error {
	if c.incoming == nil && c.pc != nil {
		return c.pc.SetWriteDeadline(t)
	}
	return nil
}

func (c *udpFrameConn) getReadDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline
}
