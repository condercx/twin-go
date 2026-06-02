package twin

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/metacubex/quic-go"
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

	if err := ps.authenticate(); err != nil {
		logf("portal session: auth failed from %s: %v", remoteAddr, err)
		return
	}
	logf("portal session: auth ok from %s", remoteAddr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ps.streamLoop()
	}()
	wg.Wait()
}

func (ps *PortalSession) authenticate() error {
	ctx, cancel := context.WithTimeout(ps.ctx, authStreamDeadline)
	defer cancel()

	stream, err := ps.conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept auth stream: %w", err)
	}
	defer stream.Close()

	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return fmt.Errorf("read pwd len: %w", err)
	}
	pwdLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	receivedPwd := make([]byte, pwdLen)
	if _, err := io.ReadFull(stream, receivedPwd); err != nil {
		return fmt.Errorf("read pwd: %w", err)
	}
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return fmt.Errorf("read nonce len: %w", err)
	}
	nonceLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(stream, nonce); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}

	if string(receivedPwd) != ps.config.Password {
		stream.Write([]byte{1})
		return fmt.Errorf("password mismatch")
	}
	if _, err := stream.Write([]byte{0}); err != nil {
		return fmt.Errorf("write auth ok: %w", err)
	}
	return nil
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

	// client → target: read length-prefixed frames from stream, write to UDP
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

	// target → client: read from UDP, write length-prefixed frames to stream
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