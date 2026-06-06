package twin

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

type Client struct {
	cfg     *ClientConfig
	pool    *ECHPool
	closed  bool
	closeMu sync.Mutex
}

type udpSession struct {
	stream  *smux.Stream
	addrStr string
	recvCh  chan udpPacketMsg
	closeCh chan struct{}
}

type udpPacketMsg struct {
	addr string
	data []byte
}

func NewClient(cfg *ClientConfig) (*Client, error) {
	if err := cfg.fillDefaults(); err != nil {
		return nil, err
	}
	c := &Client{
		cfg: cfg,
	}
	c.pool = NewECHPool(cfg)
	c.pool.Start()
	if err := c.pool.WaitForReady(10 * time.Second); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	stream, chID, _, err := c.pool.openTCPStream(target)
	if err != nil {
		return nil, fmt.Errorf("twin dial tcp: %w", err)
	}
	logf("[client] TCP open: %s channel:%d", target, chID)
	return &twinStream{stream: stream}, nil
}

func (c *Client) ListenPacket() (net.PacketConn, error) {
	return &twinPacketConn{
		client:   c,
		inbound:  make(chan udpPacketMsg, 256),
		sessions: make(map[string]*udpSession),
		closeCh:  make(chan struct{}),
	}, nil
}

func (c *Client) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	_ = c.pool.Close()
	c.closed = true
	return nil
}

func (c *Client) IsClosed() bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return true
	}
	return false
}

func (c *Client) openUDPSession(target string) (*udpSession, error) {
	stream, chID, _, err := c.pool.openUDPStream(target)
	if err != nil {
		return nil, err
	}
	us := &udpSession{
		stream:  stream,
		addrStr: target,
		recvCh:  make(chan udpPacketMsg, 256),
		closeCh: make(chan struct{}),
	}
	go func() {
		for {
			addrStr, payload, err := readUDPReply(stream)
			if err != nil {
				close(us.closeCh)
				return
			}
			select {
			case us.recvCh <- udpPacketMsg{addr: addrStr, data: payload}:
			default:
			}
		}
	}()
	logf("[client] UDP open: %s channel:%d", target, chID)
	return us, nil
}

// twinStream wraps a smux.Stream as net.Conn
type twinStream struct {
	stream *smux.Stream
}

func (s *twinStream) Read(b []byte) (int, error)           { return s.stream.Read(b) }
func (s *twinStream) Write(b []byte) (int, error)          { return s.stream.Write(b) }
func (s *twinStream) Close() error                          { return s.stream.Close() }
func (s *twinStream) LocalAddr() net.Addr                   { return nil }
func (s *twinStream) RemoteAddr() net.Addr                  { return nil }
func (s *twinStream) SetDeadline(t time.Time) error         { return s.stream.SetDeadline(t) }
func (s *twinStream) SetReadDeadline(t time.Time) error     { return s.stream.SetReadDeadline(t) }
func (s *twinStream) SetWriteDeadline(t time.Time) error    { return s.stream.SetWriteDeadline(t) }

var _ net.Conn = (*twinStream)(nil)

// twinPacketConn implements net.PacketConn over twin UDP
type twinPacketConn struct {
	client   *Client
	mu       sync.Mutex
	sessions map[string]*udpSession
	closed   bool
	inbound  chan udpPacketMsg
	closeCh  chan struct{}
	wg       sync.WaitGroup
}

func (pc *twinPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	addrStr := addr.String()
	pc.mu.Lock()
	sess, ok := pc.sessions[addrStr]
	pc.mu.Unlock()

	if !ok {
		newSess, err := pc.client.openUDPSession(addrStr)
		if err != nil {
			return 0, fmt.Errorf("open udp session: %w", err)
		}
		pc.mu.Lock()
		if pc.closed {
			pc.mu.Unlock()
			_ = newSess.stream.Close()
			return 0, net.ErrClosed
		}
		if existing, ok := pc.sessions[addrStr]; ok {
			pc.mu.Unlock()
			_ = newSess.stream.Close()
			sess = existing
		} else {
			pc.sessions[addrStr] = newSess
			pc.mu.Unlock()
			sess = newSess
			pc.wg.Add(1)
			go pc.udpReadLoop(newSess)
		}
	}

	if err := writeChunk(sess.stream, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (pc *twinPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-pc.closeCh:
		return 0, nil, net.ErrClosed
	case pkt, ok := <-pc.inbound:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data)
		udpAddr, _ := net.ResolveUDPAddr("udp", pkt.addr)
		return n, udpAddr, nil
	}
}

func (pc *twinPacketConn) udpReadLoop(sess *udpSession) {
	defer pc.wg.Done()
	defer func() {
		pc.mu.Lock()
		delete(pc.sessions, sess.addrStr)
		pc.mu.Unlock()
	}()
	for {
		select {
		case <-sess.closeCh:
			return
		case pkt, ok := <-sess.recvCh:
			if !ok {
				return
			}
			select {
			case pc.inbound <- pkt:
			default:
			}
		}
	}
}

func (pc *twinPacketConn) Close() error {
	pc.mu.Lock()
	if pc.closed {
		pc.mu.Unlock()
		return nil
	}
	pc.closed = true
	sessions := pc.sessions
	pc.sessions = make(map[string]*udpSession)
	close(pc.closeCh)
	pc.mu.Unlock()

	for _, sess := range sessions {
		_ = sess.stream.Close()
	}
	pc.wg.Wait()
	return nil
}

func (pc *twinPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (pc *twinPacketConn) SetDeadline(t time.Time) error      { return nil }
func (pc *twinPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (pc *twinPacketConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.PacketConn = (*twinPacketConn)(nil)
