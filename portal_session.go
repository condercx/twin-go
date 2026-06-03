package twin

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
)

const (
	tcpConnectTimeout = 10 * time.Second
	tcpIdleTimeout    = 300 * time.Second
)

type PortalSession struct {
	conn   *quic.Conn
	config *Config
	ctx    context.Context
	cancel context.CancelFunc

	udpRelay *udpRelay
}

func NewPortalSession(conn *quic.Conn, cfg *Config) *PortalSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortalSession{
		conn:   conn,
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (ps *PortalSession) Run() {
	defer ps.cancel()

	remoteAddr := ps.conn.RemoteAddr().String()
	logf("portal session: new connection from %s", remoteAddr)

	clientSendBPS, clientRecvBPS, err := ps.authenticate()
	if err != nil {
		logf("portal session: auth failed from %s: %v", remoteAddr, err)
		return
	}
	logf("portal session: auth ok from %s (send=%d recv=%d)", remoteAddr, clientSendBPS, clientRecvBPS)

	if clientRecvBPS > 0 {
		logf("portal session: server BrutalSender send=%d bps (client recv)", clientRecvBPS)
		sender := NewBrutalSender(congestion.ByteCount(clientRecvBPS))
		ps.conn.SetCongestionControl(sender)
	}

	ps.udpRelay = newUDPRelay(ps.conn, ps.ctx)
	go ps.udpRelay.run()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ps.streamLoop()
	}()
	wg.Wait()
}

func (ps *PortalSession) authenticate() (clientSendBPS, clientRecvBPS uint64, err error) {
	ctx, cancel := context.WithTimeout(ps.ctx, authStreamDeadline)
	defer cancel()

	stream, err := ps.conn.AcceptStream(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("accept auth stream: %w", err)
	}
	defer stream.Close()

	clientSendBPS, clientRecvBPS, err = ReadAuth(stream, ps.config.Password)
	if err != nil {
		WriteAuthResult(stream, false, 0, 0)
		return clientSendBPS, clientRecvBPS, err
	}

	serverSendBPS := clientRecvBPS
	serverRecvBPS := clientSendBPS
	if err := WriteAuthResult(stream, true, serverSendBPS, serverRecvBPS); err != nil {
		return 0, 0, fmt.Errorf("write auth result: %w", err)
	}

	return clientSendBPS, clientRecvBPS, nil
}

func (ps *PortalSession) streamLoop() {
	for {
		stream, err := ps.conn.AcceptStream(ps.ctx)
		if err != nil {
			if ps.ctx.Err() != nil {
				return
			}
			logf("portal session: accept stream error: %v", err)
			continue
		}
		go ps.handleStream(stream)
	}
}

func (ps *PortalSession) handleStream(stream *quic.Stream) {
	defer stream.Close()

	var typeByte [1]byte
	if _, err := io.ReadFull(stream, typeByte[:]); err != nil {
		return
	}

	switch typeByte[0] {
	case 0x00:
		target, err := readTarget(stream)
		if err != nil {
			return
		}
		ps.handleStreamTCP(stream, target)
	case 0x01:
		target, err := readTarget(stream)
		if err != nil {
			return
		}
		ps.handleStreamUDP(stream, target)
	case 0x02:
		target, err := readTarget(stream)
		if err != nil {
			return
		}
		_ = target
		sessionID := ps.udpRelay.allocateID()
		var resp [5]byte
		resp[0] = 0
		binary.BigEndian.PutUint32(resp[1:5], sessionID)
		stream.Write(resp[:5])
		stream.Close()
	default:
		logf("portal session: unknown stream type 0x%02x", typeByte[0])
	}
}

func (ps *PortalSession) handleStreamTCP(stream *quic.Stream, target string) {
	conn, err := net.DialTimeout("tcp", target, tcpConnectTimeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// Set TCP keepalive and idle timeout
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetLinger(0)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// upstream -> client: copy with deadline awareness
	go func() {
		defer wg.Done()
		defer stream.Close()
		buf := make([]byte, 32*1024)
		for {
			conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// client -> upstream: copy with deadline awareness
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}
			conn.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

func (ps *PortalSession) handleStreamUDP(stream *quic.Stream, target string) {
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer stream.Close()
		for {
			var lenBuf [2]byte
			if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
				return
			}
			datalen := binary.BigEndian.Uint16(lenBuf[:])
			if datalen == 0 {
				return
			}
			data := make([]byte, datalen)
			if _, err := io.ReadFull(stream, data); err != nil {
				return
			}
			conn.SetWriteDeadline(time.Now().Add(tcpIdleTimeout))
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
			if _, err := stream.Write(lenBuf[:]); err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

type udpRelay struct {
	conn    *quic.Conn
	ctx     context.Context
	mu      sync.Mutex
	nextID  uint32
	sockets map[uint32]*udpSocket
}

type udpSocket struct {
	id    uint32
	relay *udpRelay
	conn  *net.UDPConn
}

func newUDPRelay(conn *quic.Conn, ctx context.Context) *udpRelay {
	return &udpRelay{
		conn:    conn,
		ctx:     ctx,
		nextID:  1,
		sockets: make(map[uint32]*udpSocket),
	}
}

func (r *udpRelay) allocateID() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID
	r.nextID++
	return id
}

func (r *udpRelay) run() {
	for {
		raw, err := r.conn.ReceiveDatagram(r.ctx)
		if err != nil {
			return
		}
		var msg udpMessage
		if err := msg.unpack(raw); err != nil {
			continue
		}
		r.handleDatagram(msg)
	}
}

func (r *udpRelay) handleDatagram(msg udpMessage) {
	r.mu.Lock()
	sock, ok := r.sockets[msg.SessionID]
	r.mu.Unlock()

	if !ok {
		if len(msg.Host) == 0 {
			return
		}
		udpAddr := &net.UDPAddr{IP: net.ParseIP(msg.Host), Port: int(msg.Port)}
		if udpAddr.IP == nil {
			return
		}
		udpConn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return
		}
		sock = &udpSocket{
			id:    msg.SessionID,
			relay: r,
			conn:  udpConn,
		}
		r.mu.Lock()
		r.sockets[msg.SessionID] = sock
		r.mu.Unlock()
		go sock.readLoop()
	}

	if len(msg.Data) > 0 {
		sock.conn.Write(msg.Data)
	}
}

func (s *udpSocket) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			break
		}
		addr := s.conn.RemoteAddr().(*net.UDPAddr)
		replyMsg := udpMessage{
			SessionID: s.id,
			Host:      addr.IP.String(),
			Port:      uint16(addr.Port),
			FragCount: 1,
			Data:      make([]byte, n),
		}
		copy(replyMsg.Data, buf[:n])

		packed := replyMsg.pack()
		if err := s.relay.conn.SendDatagram(packed); err != nil {
			var errSize *quic.DatagramTooLargeError
			if errors.As(err, &errSize) {
				frags := fragUDPMessage(replyMsg, int(errSize.MaxDatagramPayloadSize))
				for _, f := range frags {
					s.relay.conn.SendDatagram(f.pack())
				}
			}
		}
	}

	s.relay.mu.Lock()
	delete(s.relay.sockets, s.id)
	s.relay.mu.Unlock()
	s.conn.Close()
}



