package twin

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
)

type PortalSession struct {
	conn   *quic.Conn
	config *Config
	ctx    context.Context
	cancel context.CancelFunc
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
	logf("portal session: auth ok from %s", remoteAddr)

	// Wire BrutalSender on the server side.
	// Server sends data TO client ? use client's recvBPS (what they can receive) as our send rate.
	// Server receives data FROM client ? use client's sendBPS as our recv rate.
	if clientRecvBPS > 0 {
		logf("portal session: server BrutalSender send=%d bps (client recv) from client send=%d bps", clientRecvBPS, clientSendBPS)
		sender := NewBrutalSender(congestion.ByteCount(clientRecvBPS))
		ps.conn.SetCongestionControl(sender)
	}

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

	// Server responds with its bandwidth allocation.
	// serverSendBPS = what server will send to client = client's recv capacity
	// serverRecvBPS = what server expects to receive = client's send capacity
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
			return
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

	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return
	}
	targetLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	targetBytes := make([]byte, targetLen)
	if _, err := io.ReadFull(stream, targetBytes); err != nil {
		return
	}
	target := string(targetBytes)

	switch typeByte[0] {
	case 0x00:
		ps.handleStreamTCP(stream, target)
	case 0x01:
		ps.handleStreamUDP(stream, target)
	default:
		logf("portal session: unknown stream type 0x%02x from %s", typeByte[0], target)
	}
}

func (ps *PortalSession) handleStreamTCP(stream *quic.Stream, target string) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(stream, conn)
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
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
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
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
