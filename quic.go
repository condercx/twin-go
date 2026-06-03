package twin

import (
	"github.com/metacubex/quic-go"
	"time"
)

func NewQUICConfig(cfg *Config) *quic.Config {
	initialStreamWindow := uint64(DefaultInitialStreamReceiveWindow)
	maxStreamWindow := uint64(DefaultMaxStreamReceiveWindow)
	initialConnWindow := uint64(DefaultInitialConnectionReceiveWindow)
	maxConnWindow := uint64(DefaultMaxConnectionReceiveWindow)
	maxIdleTimeout := DefaultMaxIdleTimeout
	keepAlive := DefaultKeepAlivePeriod
	disablePMTU := true
	maxStreams := DefaultMaxIncomingStreams

	if cfg != nil {
		if cfg.InitialStreamReceiveWindow > 0 {
			initialStreamWindow = cfg.InitialStreamReceiveWindow
		}
		if cfg.MaxStreamReceiveWindow > 0 {
			maxStreamWindow = cfg.MaxStreamReceiveWindow
		}
		if cfg.InitialConnectionReceiveWindow > 0 {
			initialConnWindow = cfg.InitialConnectionReceiveWindow
		}
		if cfg.MaxConnectionReceiveWindow > 0 {
			maxConnWindow = cfg.MaxConnectionReceiveWindow
		}
		if cfg.MaxIdleTimeout > 0 {
			maxIdleTimeout = cfg.MaxIdleTimeout
		}
		if cfg.KeepAlivePeriod > 0 {
			keepAlive = cfg.KeepAlivePeriod
		}
		if cfg.DisablePMTU != nil {
			disablePMTU = *cfg.DisablePMTU
		}
		if cfg.MaxIncomingStreams > 0 {
			maxStreams = cfg.MaxIncomingStreams
		}
	}

	if keepAlive >= maxIdleTimeout {
		keepAlive = maxIdleTimeout / 4
	}
	if keepAlive < 5*time.Second {
		keepAlive = 5 * time.Second
	}

	return &quic.Config{
		InitialStreamReceiveWindow:     initialStreamWindow,
		MaxStreamReceiveWindow:         maxStreamWindow,
		InitialConnectionReceiveWindow: initialConnWindow,
		MaxConnectionReceiveWindow:     maxConnWindow,
		MaxIdleTimeout:                 maxIdleTimeout,
		KeepAlivePeriod:                keepAlive,
		EnableDatagrams:                true,
		DisablePathMTUDiscovery:        disablePMTU,
		MaxIncomingStreams:             maxStreams,
	}
}

