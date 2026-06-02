package twin

import (
	"context"
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

	udpFlows *PortalUDPFlowManager
}

func NewPortalSession(conn *quic.Conn, cfg *Config) *PortalSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortalSession{
		conn:     conn,
		config:   cfg,
		ctx:      ctx,
		cancel:   cancel,
		udpFlows: NewPortalUDPFlowManager(),
	}
}

func (ps *PortalSession) Run() {
	defer ps.cancel()
	defer ps.udpFlows.CloseAll()

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
