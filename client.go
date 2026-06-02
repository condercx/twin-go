package twin

import (
	"context"
	"fmt"
	"io"
	"net"

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
	return c.authConn()
}

// SetConn sets an externally-dialed QUIC connection and authenticates it.
func (c *Client) SetConn(conn *quic.Conn) error {
	c.conn = conn
	return c.authConn()
}

// authConn performs the authentication handshake over the existing QUIC connection.
func (c *Client) authConn() error {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	defer stream.Close()
	if err := WriteAuth(stream, c.config.Password); err != nil {
		return err
	}
	addr := c.config.ServerAddrString()
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

