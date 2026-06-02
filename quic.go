package twin

import (
	"github.com/metacubex/quic-go"
)

func NewQUICConfig(cfg *Config) *quic.Config {
	initialStreamWindow := uint64(DefaultInitialStreamReceiveWindow)
	maxStreamWindow := uint64(DefaultMaxStreamReceiveWindow)
	initialConnWindow := uint64(DefaultInitialConnectionReceiveWindow)
	maxConnWindow := uint64(DefaultMaxConnectionReceiveWindow)

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
	}

	return &quic.Config{
		InitialStreamReceiveWindow:     initialStreamWindow,
		MaxStreamReceiveWindow:         maxStreamWindow,
		InitialConnectionReceiveWindow: initialConnWindow,
		MaxConnectionReceiveWindow:     maxConnWindow,
		MaxIdleTimeout:                 DefaultMaxIdleTimeout,
		KeepAlivePeriod:                DefaultKeepAlivePeriod,
		EnableDatagrams:                true,
		DisablePathMTUDiscovery:        true,
	}
}
