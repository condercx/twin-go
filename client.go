package twin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	qtls "github.com/metacubex/tls"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
)

const (
	openStreamTimeout  = 10 * time.Second
	headerWriteTimeout = 10 * time.Second
)

type Client struct {
	config *Config
	conn   *quic.Conn

	udpSessionMutex sync.RWMutex
	udpSessionMap   map[uint32]chan *udpMessage
	udpDefragger    defragger
}

func NewClient(cfg *Config) *Client {
	return &Client{config: cfg}
}

func (c *Client) IsClosed() bool {
	if c.conn == nil {
		return true
	}
	return c.conn.Context().Err() != nil
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
	return c.postAuth()
}

func (c *Client) SetConn(conn *quic.Conn) error {
	c.conn = conn
	return c.postAuth()
}

func (c *Client) postAuth() error {
	if err := c.authConn(); err != nil {
		return err
	}
	c.udpSessionMap = make(map[uint32]chan *udpMessage)
	go c.handleMessage()
	return nil
}

func (c *Client) authConn() error {
	ctx, cancel := context.WithTimeout(context.Background(), authStreamDeadline)
	defer cancel()

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	defer stream.Close()

	sendBPS := c.config.UpBPS
	recvBPS := c.config.DownBPS
	if sendBPS == 0 {
		sendBPS = 100 * 1024 * 1024
	}
	if recvBPS == 0 {
		recvBPS = 100 * 1024 * 1024
	}

	if err := WriteAuth(stream, c.config.Password, sendBPS, recvBPS); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	if sendBPS > 0 {
		logf("setting client BrutalSender send BPS=%d", sendBPS)
		sender := NewBrutalSender(congestion.ByteCount(sendBPS))
		c.conn.SetCongestionControl(sender)
	}

	addr := c.config.ServerAddrString()
	logf("twin client: connected and authenticated to %s (tx=%d bps, rx=%d bps)", addr, sendBPS, recvBPS)
	return nil
}

func (c *Client) openStream() (*quic.Stream, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), openStreamTimeout)
	defer cancel()

	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	return stream, nil
}

func writeHeader(stream *quic.Stream, b []byte) error {
	stream.SetWriteDeadline(time.Now().Add(headerWriteTimeout))
	_, err := stream.Write(b)
	stream.SetWriteDeadline(time.Time{})
	return err
}

func (c *Client) DialTCP(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, err
	}

	if err := writeHeader(stream, []byte{0x00}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write type: %w", err)
	}
	targetBytes := []byte(target)
	lenBuf := []byte{byte(len(targetBytes) >> 8), byte(len(targetBytes))}
	if err := writeHeader(stream, lenBuf); err != nil {
		stream.Close()
		return nil, err
	}
	if err := writeHeader(stream, targetBytes); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func (c *Client) DialUDPStream(ctx context.Context, target string) (io.ReadWriteCloser, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, err
	}

	if err := writeHeader(stream, []byte{0x01}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write type: %w", err)
	}
	targetBytes := []byte(target)
	lenBuf := []byte{byte(len(targetBytes) >> 8), byte(len(targetBytes))}
	if err := writeHeader(stream, lenBuf); err != nil {
		stream.Close()
		return nil, err
	}
	if err := writeHeader(stream, targetBytes); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func (c *Client) handleMessage() {
	for {
		msg, err := c.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		var udpMsg udpMessage
		if err := udpMsg.unpack(msg); err != nil {
			continue
		}
		dfMsg := c.udpDefragger.feed(udpMsg)
		if dfMsg == nil {
			continue
		}
		c.udpSessionMutex.RLock()
		ch, ok := c.udpSessionMap[dfMsg.SessionID]
		if ok {
			select {
			case ch <- dfMsg:
			default:
			}
		}
		c.udpSessionMutex.RUnlock()
	}
}

func (c *Client) NewUDPSession(ctx context.Context) (*UDPSession, error) {
	stream, err := c.openStream()
	if err != nil {
		return nil, err
	}

	if _, err := stream.Write([]byte{0x02}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write udp open: %w", err)
	}
	if err := writeTarget(stream, ""); err != nil {
		stream.Close()
		return nil, err
	}

	var resp [5]byte
	if _, err := io.ReadFull(stream, resp[:]); err != nil {
		stream.Close()
		return nil, fmt.Errorf("read udp session response: %w", err)
	}
	if resp[0] != 0 {
		stream.Close()
		return nil, fmt.Errorf("server rejected UDP session")
	}
	sessionID := uint32(resp[1])<<24 | uint32(resp[2])<<16 | uint32(resp[3])<<8 | uint32(resp[4])
	stream.Close()

	nCh := make(chan *udpMessage, 1024)
	c.udpSessionMutex.Lock()
	c.udpSessionMap[sessionID] = nCh
	c.udpSessionMutex.Unlock()

	return &UDPSession{
		client:    c,
		SessionID: sessionID,
		MsgCh:     nCh,
	}, nil
}

type UDPSession struct {
	client    *Client
	SessionID uint32
	MsgCh     <-chan *udpMessage
	closed    bool
}

func (s *UDPSession) WriteTo(data []byte, host string, port uint16) error {
	msg := udpMessage{
		SessionID: s.SessionID,
		Host:      host,
		Port:      port,
		FragCount: 1,
		Data:      data,
	}
	err := s.client.conn.SendDatagram(msg.pack())
	if err != nil {
		var errSize *quic.DatagramTooLargeError
		if !errors.As(err, &errSize) {
			return err
		}
		fragMsgs := fragUDPMessage(msg, int(errSize.MaxDatagramPayloadSize))
		for _, fragMsg := range fragMsgs {
			err = s.client.conn.SendDatagram(fragMsg.pack())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *UDPSession) ReadFrom() ([]byte, string, uint16, error) {
	msg := <-s.MsgCh
	if msg == nil {
		return nil, "", 0, io.EOF
	}
	return msg.Data, msg.Host, msg.Port, nil
}

func (s *UDPSession) Close() {
	if s.closed {
		return
	}
	s.closed = true
	s.client.udpSessionMutex.Lock()
	delete(s.client.udpSessionMap, s.SessionID)
	s.client.udpSessionMutex.Unlock()
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.CloseWithError(0, "client closing")
	}
	return nil
}
