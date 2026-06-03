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
	streamIdleTimeout = 300 * time.Second
	maxConcurrentTCP  = 256
)

type PortalSession struct {
	conn   *quic.Conn
	config *Config
	ctx    context.Context
	cancel context.CancelFunc

	udpRelay   *udpRelay
	sideMux    *FlowMux
	sideMux2   *FlowMux

	tcpWorker chan struct{}
}

func NewPortalSession(conn *quic.Conn, cfg *Config) *PortalSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortalSession{
		conn:      conn,
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
		tcpWorker: make(chan struct{}, maxConcurrentTCP),
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
	var typeByte [1]byte
	if _, err := io.ReadFull(stream, typeByte[:]); err != nil {
		stream.Close()
		return
	}

	switch typeByte[0] {
	case 0x00:
		// TCP proxy (legacy direct stream)
		defer stream.Close()
		target, err := readTarget(stream)
		if err != nil {
			return
		}
		ps.handleStreamTCP(stream, target)

	case 0x02:
		// UDP datagram session allocation
		defer stream.Close()
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

	case 0x03:
		// Primary side channel flow mux - stream stays open
		logf("portal session: primary side channel from %s", ps.conn.RemoteAddr().String())
		mux := NewFlowMux(stream)
		mux.Start()
		ps.sideMux = mux
		go ps.sideMuxAcceptLoop(mux)

	case 0x04:
		// Secondary side channel flow mux - stream stays open
		logf("portal session: secondary side channel from %s", ps.conn.RemoteAddr().String())
		mux := NewFlowMux(stream)
		mux.Start()
		ps.sideMux2 = mux
		go ps.sideMuxAcceptLoop(mux)

	default:
		stream.Close()
		logf("portal session: unknown stream type 0x%02x", typeByte[0])
	}
}

func (ps *PortalSession) sideMuxAcceptLoop(mux *FlowMux) {
	defer mux.Close()
	for {
		fa, err := mux.Accept()
		if err != nil || fa == nil {
			return
		}
		ps.tcpWorker <- struct{}{}
		go func(fa *flowAccept) {
			defer func() { <-ps.tcpWorker }()
			ps.handleFlowTCP(fa)
		}(fa)
	}
}

func (ps *PortalSession) handleFlowTCP(fa *flowAccept) {
	conn, err := net.DialTimeout("tcp", fa.Target, tcpConnectTimeout)
	if err != nil {
		return
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	streamCtx, cancel := context.WithCancel(ps.ctx)
	defer cancel()

	go func() {
		timer := time.NewTimer(streamIdleTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			cancel()
		case <-streamCtx.Done():
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(fa.IO, conn)
		fa.IO.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, fa.IO)
	}()
	wg.Wait()
}

func (ps *PortalSession) handleStreamTCP(stream *quic.Stream, target string) {
	conn, err := net.DialTimeout("tcp", target, tcpConnectTimeout)
	if err != nil {
		return
	}
	defer conn.Close()

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	streamCtx, cancel := context.WithCancel(ps.ctx)
	defer cancel()

	go func() {
		timer := time.NewTimer(streamIdleTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			cancel()
		case <-streamCtx.Done():
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer stream.Close()
		io.Copy(stream, conn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
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
