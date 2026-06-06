package twin

import (
	"fmt"
	"strconv"
	"strings"
	"net"
)

type TLSMode string

const (
	TLSModeWS  TLSMode = "ws"
	TLSModeWSS TLSMode = "wss"
)

type ClientConfig struct {
	Password     string
	ServerAddr   string
	ServerPort   int
	TLSMode      TLSMode
	SNI          string
	Insecure     bool
	ConnCount    int
	ECHHost      string
	ECHDNSServer string
	ProxyIPs     []string
}

type ServerConfig struct {
	Password  string
	Listeners []ListenerConfig
	Forward   string
}

type ListenerConfig struct {
	Listen   string
	TLSMode  TLSMode
	CertFile string
	KeyFile  string
}

const DefaultECHHost = "cloudflare-ech.com"
const DefaultECHDNSServer = "https://doh.pub/dns-query"

func (c *ClientConfig) fillDefaults() error {
	if c.Password == "" {
		return fmt.Errorf("twin: password is required")
	}
	if c.ServerAddr == "" {
		return fmt.Errorf("twin: server address is required")
	}
	if c.ServerPort == 0 {
		c.ServerPort = 443
	}
	if c.TLSMode == "" {
		c.TLSMode = TLSModeWSS
	}
	if c.SNI == "" {
		c.SNI = c.ServerAddr
	}
	if c.ConnCount <= 0 {
		c.ConnCount = 3
	}
	if c.TLSMode == TLSModeWSS && c.ECHHost == "" {
		c.ECHHost = DefaultECHHost
	}
	if c.TLSMode == TLSModeWSS && c.ECHDNSServer == "" {
		c.ECHDNSServer = DefaultECHDNSServer
	}
	var cleaned []string
	for _, ip := range c.ProxyIPs {
		if ip = strings.TrimSpace(ip); ip != "" {
			cleaned = append(cleaned, ip)
		}
	}
	c.ProxyIPs = cleaned
	return nil
}

func (c *ClientConfig) ServerURL() string {
	scheme := "ws"
	if c.TLSMode == TLSModeWSS {
		scheme = "wss"
	}
	host := c.ServerAddr
	port := c.ServerPort
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if p != "" {
			if parsed, e := strconv.Atoi(p); e == nil {
				port = parsed
			}
		}
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, host, port)
}

func (s *ServerConfig) fillDefaults() error {
	if s.Password == "" {
		return fmt.Errorf("twin: server password is required")
	}
	if len(s.Listeners) == 0 {
		return fmt.Errorf("twin: at least one listener required")
	}
	for i, l := range s.Listeners {
		if l.Listen == "" {
			return fmt.Errorf("twin: listener %d: listen address required", i)
		}
		if l.TLSMode == "" {
			s.Listeners[i].TLSMode = TLSModeWS
		}
	}
	return nil
}
