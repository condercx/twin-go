package twin

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	qtls "github.com/metacubex/tls"

	"github.com/metacubex/quic-go"
)

type Client struct {
	config *Config
	conn   *quic.Conn
}

func NewClient(cfg *Config) *Client {
	return &Client{config: cfg}
}

func (c *Client) Dial(ctx context.Context) error {
	addr := c.config.ServerAddrString()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("udp conn: %w", err)
	}

	tlsCfg := &qtls.Config{
		ServerName:         c.config.SNI,
		InsecureSkipVerify: c.config.SkipCert,
		MinVersion:         qtls.VersionTLS13,
		NextProtos:         []string{"twin"},
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = c.config.ServerAddr
	}

	quicCfg := NewQUICConfig(c.config)
	conn, err := quic.Dial(ctx, packetConn, udpAddr, tlsCfg, quicCfg)
	if err != nil {
		return fmt.Errorf("quic dial: %w", err)
	}
	c.conn = conn

	stream, err := conn.OpenStream()
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	defer stream.Close()

	if err := stream.SetDeadline(time.Now().Add(authStreamDeadline)); err != nil {
		return fmt.Errorf("set auth deadline: %w", err)
	}

	pwdBytes := []byte(c.config.Password)
	var buf []byte
	pwdLen := []byte{byte(len(pwdBytes) >> 8), byte(len(pwdBytes))}
	buf = append(buf, pwdLen...)
	buf = append(buf, pwdBytes...)
	nonceLen := []byte{0, 16}
	buf = append(buf, nonceLen...)
	nonce := make([]byte, 16)
	buf = append(buf, nonce...)

	if _, err := stream.Write(buf); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}

	result := make([]byte, 1)
	if _, err := io.ReadFull(stream, result); err != nil {
		return fmt.Errorf("read auth result: %w", err)
	}
	if result[0] != 0 {
		return fmt.Errorf("auth failed")
	}

	logf("twin client: connected and authenticated to %s", addr)
	return nil
}

func (c *Client) DialTCP(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	targetBytes := []byte(target)
	lenBuf := []byte{byte(len(targetBytes) >> 8), byte(len(targetBytes))}
	if _, err := stream.Write(lenBuf); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write target len: %w", err)
	}
	if _, err := stream.Write(targetBytes); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write target: %w", err)
	}
	return stream, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.CloseWithError(0, "client closing")
	}
	return nil
}
