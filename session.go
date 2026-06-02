package twin

import (
	"context"
	"time"

	"github.com/metacubex/quic-go"
)

type SessionState int

const (
	SessionInitial SessionState = iota
	SessionConnecting
	SessionAuthenticating
	SessionReady
	SessionClosed
)

type Session struct {
	config *Config
	state  SessionState

	quicConn *quic.Conn
	sideChan *SideChannel

	ctx    context.Context
	cancel context.CancelFunc

	startTime time.Time
}

func NewSession(cfg *Config) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		config:   cfg,
		state:    SessionInitial,
		sideChan: NewSideChannel(cfg.SideChannel, cfg.SideStrategy),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (s *Session) State() SessionState {
	return s.state
}

func (s *Session) SetState(state SessionState) {
	s.state = state
}

func (s *Session) SetQUICConn(conn *quic.Conn) {
	s.quicConn = conn
}

func (s *Session) QUICConn() *quic.Conn {
	return s.quicConn
}

func (s *Session) SideChannel() *SideChannel {
	return s.sideChan
}

func (s *Session) Config() *Config {
	return s.config
}

func (s *Session) Close() error {
	s.cancel()
	s.SetState(SessionClosed)
	if s.quicConn != nil {
		return s.quicConn.CloseWithError(0, "session closed")
	}
	return nil
}

func (s *Session) Context() context.Context {
	return s.ctx
}

func (s *Session) Uptime() time.Duration {
	if s.startTime.IsZero() {
		return 0
	}
	return time.Since(s.startTime)
}
