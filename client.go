package twin

import (
	"context"
	"fmt"
	"io"
	"net"

	qtls "github.com/metacubex/tls"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
)

type Client struct {
	config *Config
	conn   *quic.Conn
}

func NewClient(cfg *Config) *Client {
	return &Client{config: cfg}
}

func (c *Client) Dial(ctx context.Context, packetConn net.PacketConn, udpAddr *net.UDPAddr) error {
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

func (c *Client) SetConn(conn *quic.Conn) error {
	c.conn = conn
	return c.authConn()
}

func (c *Client) authConn() error {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	defer stream.Close()

	// Send auth with bandwidth info
	sendBPS := c.config.UpBPS
	recvBPS := c.config.DownBPS
	if sendBPS == 0 {
		sendBPS = 100 * 1024 * 1024 // default 100 Mbps
	}
	if recvBPS == 0 {
		recvBPS = 100 * 1024 * 1024
	}
	// We send UpBPS (what client can send) and DownBPS (what client can receive)
	// From client perspective:
	//   sendBPS = our upload capacity = what we send TO server = server's recv
	//   recvBPS = our download capacity = what we receive FROM server = server's send
	tx := sendBPS
	rx := recvBPS

	if err := WriteAuth(stream, c.config.Password, tx, rx); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	// Server responds with what it will use for its BrutalSender
	// We already read serverBPS from auth result in WriteAuth
	// Apply BrutalSender for client's upload direction (what client sends to server)
	if tx > 0 {
		logf("setting client BrutalSender send BPS=%d (server recv)", tx)
		sender := NewBrutalSender(congestion.ByteCount(tx))
		c.conn.SetCongestionControl(sender)
	}

	addr := c.config.ServerAddrString()
	logf("twin client: connected and authenticated to %s (tx=%d bps, rx=%d bps)", addr, tx, rx)
	return nil
}

// writeTarget writes length-prefixed target address to stream
func writeTarget(stream io.Writer, target string) error {
	targetBytes := []byte(target)
	lenBuf := []byte{byte(len(targetBytes) >> 8), byte(len(targetBytes))}
	if _, err := stream.Write(lenBuf); err != nil {
		return err
	}
	if _, err := stream.Write(targetBytes); err != nil {
		return err
	}
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

	if _, err := stream.Write([]byte{0x00}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write type: %w", err)
	}
	if err := writeTarget(stream, target); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func (c *Client) DialUDP(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	if _, err := stream.Write([]byte{0x01}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write type: %w", err)
	}
	if err := writeTarget(stream, target); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.CloseWithError(0, "client closing")
	}
	return nil
}
