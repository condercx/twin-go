package twin

import (
	"fmt"
	qtls "github.com/metacubex/tls"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultInitialStreamReceiveWindow     = 8 * 1024 * 1024
	DefaultMaxStreamReceiveWindow         = 64 * 1024 * 1024
	DefaultInitialConnectionReceiveWindow = 16 * 1024 * 1024
	DefaultMaxConnectionReceiveWindow     = 256 * 1024 * 1024
	DefaultMaxIdleTimeout                 = 120 * time.Second
	DefaultKeepAlivePeriod                = 15 * time.Second
	DefaultUDPPayloadSize                 = 1200
	DefaultMaxIncomingStreams             = 1024

	maxBurstPackets        = 30
	defaultBurstMultiplier = 3.0

	smallPacketThreshold = 200
	highLossThreshold    = 0.15
	mediumLossThreshold  = 0.05
)

type SideStrategy int

const (
	SideStrategyAuto   SideStrategy = 0
	SideStrategyMirror SideStrategy = 1
	SideStrategySplit  SideStrategy = 2
)

func (s SideStrategy) String() string {
	switch s {
	case SideStrategyAuto:
		return "auto"
	case SideStrategyMirror:
		return "mirror"
	case SideStrategySplit:
		return "split"
	default:
		return "unknown"
	}
}

func ParseSideStrategy(v string) (SideStrategy, error) {
	switch strings.ToLower(v) {
	case "auto", "":
		return SideStrategyAuto, nil
	case "mirror":
		return SideStrategyMirror, nil
	case "split":
		return SideStrategySplit, nil
	default:
		return SideStrategyAuto, fmt.Errorf("unknown side strategy: %s", v)
	}
}

type Config struct {
	ServerAddr string `json:"server,omitempty"`
	ServerPort int    `json:"port,omitempty"`
	Password   string `json:"password,omitempty"`
	SNI        string `json:"sni,omitempty"`
	SkipCert   bool   `json:"skip-cert-verify,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`

	UpBPS   uint64 `json:"up,omitempty"`
	DownBPS uint64 `json:"down,omitempty"`

	SideChannel  bool         `json:"side-channel,omitempty"`
	SideStrategy SideStrategy `json:"side-strategy,omitempty"`

	InitialStreamReceiveWindow     uint64 `json:"initial-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow         uint64 `json:"max-stream-receive-window,omitempty"`
	InitialConnectionReceiveWindow uint64 `json:"initial-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow     uint64 `json:"max-connection-receive-window,omitempty"`
	MaxIncomingStreams             int  `json:"max-incoming-streams,omitempty"`

	KeepAlivePeriod time.Duration `json:"-"`
	MaxIdleTimeout  time.Duration `json:"-"`
	DisablePMTU     *bool         `json:"-"`

	TLSCert  qtls.Certificate `json:"-"`
	CertFile string `json:"cert-file,omitempty"`
	KeyFile  string `json:"key-file,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		SideChannel:  true,
		SideStrategy: SideStrategyAuto,
		InitialStreamReceiveWindow:     DefaultInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         DefaultMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: DefaultInitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     DefaultMaxConnectionReceiveWindow,
		KeepAlivePeriod:                0,
		MaxIdleTimeout:                 0,
		MaxIncomingStreams:             DefaultMaxIncomingStreams,
	}
}

func ParseConfig(rawURL string) (*Config, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("twin: parse url: %w", err)
	}
	cfg := DefaultConfig()
	cfg.ServerAddr = u.Hostname()
	portStr := u.Port()
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("twin: invalid port: %w", err)
		}
		cfg.ServerPort = port
	} else {
		cfg.ServerPort = 443
	}
	q := u.Query()
	if v := q.Get("password"); v != "" {
		cfg.Password = v
	}
	if v := q.Get("sni"); v != "" {
		cfg.SNI = v
	}
	if v := q.Get("up"); v != "" {
		cfg.UpBPS = parseBPS(v)
	}
	if v := q.Get("down"); v != "" {
		cfg.DownBPS = parseBPS(v)
	}
	if v := q.Get("skip-cert-verify"); v == "true" || v == "1" {
		cfg.SkipCert = true
	}
	if v := q.Get("fingerprint"); v != "" {
		cfg.Fingerprint = v
	}
	if v := q.Get("side-channel"); v == "false" || v == "0" {
		cfg.SideChannel = false
	}
	if v := q.Get("side-strategy"); v != "" {
		if s, err := ParseSideStrategy(v); err == nil {
			cfg.SideStrategy = s
		}
	}
	return &cfg, nil
}

func parseBPS(s string) uint64 {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0
	}
	var multiplier uint64 = 1
	switch {
	case strings.HasSuffix(s, "G"):
		multiplier = 1000 * 1000 * 1000
		s = strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		multiplier = 1000 * 1000
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		multiplier = 1000
		s = strings.TrimSuffix(s, "K")
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v * multiplier
}

func (c *Config) ServerAddrString() string {
	if c.ServerPort != 0 {
		return net.JoinHostPort(c.ServerAddr, strconv.Itoa(c.ServerPort))
	}
	return c.ServerAddr
}

