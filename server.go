package twin

import (
	"context"
	"fmt"
	"net"
	"sync"

	qtls "github.com/metacubex/tls"

	"github.com/metacubex/quic-go"
	"github.com/condercx/twin-go/obfs"
)

type Server struct {
	config   *Config
	listener *quic.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewServer(cfg *Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *Server) Start() error {
	addr := s.config.ServerAddrString()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("twin server: resolve addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("twin server: listen udp: %w", err)
	}

	// Wrap with obfuscation using the server password as key
	key := DeriveObfsKey(s.config.Password)
	obfsConn := obfs.NewObfsPacketConn(udpConn, key)

	tlsCfg := &qtls.Config{
		Certificates: []qtls.Certificate{s.config.TLSCert},
		MinVersion:   qtls.VersionTLS13,
		NextProtos:   []string{"twin"},
	}
	if s.config.SNI != "" {
		tlsCfg.ServerName = s.config.SNI
	}

	quicCfg := NewQUICConfig(s.config)
	listener, err := quic.Listen(obfsConn, tlsCfg, quicCfg)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("twin server: listen quic: %w", err)
	}
	s.listener = listener
	logf("twin server listening on %s", addr)

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			logf("twin server: accept error: %v", err)
			continue
		}
		session := NewPortalSession(conn, s.config)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			session.Run()
		}()
	}
}

func (s *Server) Close() error {
	s.cancel()
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
	return nil
}
