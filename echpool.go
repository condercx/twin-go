package twin

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

var (
	DialTimeout        = 3 * time.Second
	WSHandshakeTimeout = 5 * time.Second
	ReconnectDelay     = 1 * time.Second
	RTTProbeTimeout    = 2 * time.Second
	ReadBufSize        = 64 * 1024
)

type ECHPool struct {
	wsServerAddr  string
	connectionNum int
	targetIPs     []string
	clientID      string
	cfg           ClientConfig

	wsConnsMu     sync.RWMutex
	smuxConns     []*smux.Session
	channelRTT    []int64
	selectCounter uint64
	readyCount    int32
}

func NewECHPool(cfg *ClientConfig) *ECHPool {
	total := cfg.ConnCount
	if len(cfg.ProxyIPs) > 0 {
		total = len(cfg.ProxyIPs) * cfg.ConnCount
	}
	return &ECHPool{
		wsServerAddr:  cfg.ServerURL(),
		connectionNum: cfg.ConnCount,
		targetIPs:     cfg.ProxyIPs,
		clientID:      uuid.NewString(),
		cfg:           *cfg,
		smuxConns:     make([]*smux.Session, total),
		channelRTT:    make([]int64, total),
	}
}

func (p *ECHPool) WaitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if int(atomic.LoadInt32(&p.readyCount)) >= len(p.smuxConns)/2+1 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("twin: timeout waiting for channels to connect")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (p *ECHPool) Start() {
	for i := 0; i < len(p.smuxConns); i++ {
		ip := ""
		if len(p.targetIPs) > 0 {
			if idx := i / p.connectionNum; idx < len(p.targetIPs) {
				ip = p.targetIPs[idx]
			}
		}
		go p.dialAndServe(i, ip)
	}
}

func (p *ECHPool) dialAndServe(idx int, ip string) {
	chID := idx + 1
	for {
		wsConn, err := dialWebSocket(&p.cfg, ip, chID)
		if err != nil {
			logf("[client] channel %d connect failed: %v", chID, err)
			time.Sleep(ReconnectDelay)
			continue
		}
		wsNet := newWSNetConn(wsConn)
		sess, err := smux.Client(wsNet, nil)
		if err != nil {
			_ = wsConn.Close()
			logf("[client] channel %d smux init failed: %v", chID, err)
			time.Sleep(ReconnectDelay)
			continue
		}
		p.wsConnsMu.Lock()
		p.smuxConns[idx] = sess
		p.channelRTT[idx] = 0
		p.wsConnsMu.Unlock()
		atomic.AddInt32(&p.readyCount, 1)
		logf("[client] channel %d ready (smux)", chID)

		if rtt, err := probeRTTOnce(sess, RTTProbeTimeout); err == nil {
			atomic.StoreInt64(&p.channelRTT[idx], rtt)
		}

		done := make(chan error, 1)
		go probeRTTLoop(sess, idx, &p.channelRTT, done)
		var probeErr error
		select {
		case probeErr = <-done:
		case <-wsNet.Dead():
			_ = sess.Close()
			<-done
			probeErr = wsNet.DeadErr()
			if probeErr == nil {
				probeErr = io.EOF
			}
		}
		_ = sess.Close()
		_ = wsConn.Close()
		p.wsConnsMu.Lock()
		p.smuxConns[idx] = nil
		p.channelRTT[idx] = 0
		p.wsConnsMu.Unlock()
		logf("[client] channel %d disconnected, reconnecting...", chID)
		time.Sleep(ReconnectDelay)
	}
}

func (p *ECHPool) openBestStream() (*smux.Stream, int, int, error) {
	p.wsConnsMu.RLock()
	type candidate struct {
		idx int
		rtt int64
	}
	cands := make([]candidate, 0, len(p.smuxConns))
	for i, sess := range p.smuxConns {
		if sess == nil || sess.IsClosed() {
			continue
		}
		rtt := atomic.LoadInt64(&p.channelRTT[i])
		if rtt <= 0 {
			rtt = int64(RTTProbeTimeout.Nanoseconds())
		}
		cands = append(cands, candidate{idx: i, rtt: rtt})
	}
	p.wsConnsMu.RUnlock()
	if len(cands) == 0 {
		return nil, 0, 0, fmt.Errorf("twin: no available smux channels")
	}
	minRTT := cands[0].rtt
	for _, c := range cands[1:] {
		if c.rtt < minRTT {
			minRTT = c.rtt
		}
	}
	tieWindow := int64((10 * time.Millisecond).Nanoseconds())
	near := make([]candidate, 0, len(cands))
	for _, c := range cands {
		if c.rtt <= minRTT+tieWindow {
			near = append(near, c)
		}
	}
	pick := int(atomic.AddUint64(&p.selectCounter, 1)-1) % len(near)
	best := near[pick]
	p.wsConnsMu.RLock()
	sess := p.smuxConns[best.idx]
	p.wsConnsMu.RUnlock()
	if sess == nil || sess.IsClosed() {
		return nil, 0, 0, fmt.Errorf("twin: channel unavailable")
	}
	decision := best.idx + 1
	s, err := sess.OpenStream()
	if err != nil {
		return nil, 0, 0, err
	}
	return s, best.idx + 1, decision, nil
}

func (p *ECHPool) openTCPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	if err := writeSmuxOpenHeader(s, streamKindTCP, 0, target); err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	return s, chID, decision, nil
}

func (p *ECHPool) openUDPStream(target string) (*smux.Stream, int, int, error) {
	s, chID, decision, err := p.openBestStream()
	if err != nil {
		return nil, 0, 0, err
	}
	if err := writeSmuxOpenHeader(s, streamKindUDP, 0, target); err != nil {
		_ = s.Close()
		return nil, 0, 0, err
	}
	return s, chID, decision, nil
}

func (p *ECHPool) Close() error {
	p.wsConnsMu.Lock()
	defer p.wsConnsMu.Unlock()
	for i, sess := range p.smuxConns {
		if sess != nil {
			_ = sess.Close()
			p.smuxConns[i] = nil
		}
	}
	return nil
}

func dialWebSocket(cfg *ClientConfig, ip string, channelID int) (*websocket.Conn, error) {
	hostName := cfg.SNI
	if hostName == "" {
		hostName = cfg.ServerAddr
	}
	scheme := "ws"
	if cfg.TLSMode == TLSModeWSS {
		scheme = "wss"
	}
	u, _ := url.Parse(scheme + "://" + net.JoinHostPort(hostName, strconv.Itoa(cfg.ServerPort)) + "/")
	q := u.Query()
	q.Set("client_id", "")
	if channelID > 0 {
		q.Set("channel_id", strconv.Itoa(channelID))
	}
	u.RawQuery = q.Encode()
	wsURL := u.String()

	newDialer := func() websocket.Dialer {
		d := websocket.Dialer{
			HandshakeTimeout: WSHandshakeTimeout,
			ReadBufferSize:   ReadBufSize,
			WriteBufferSize:  ReadBufSize,
		}
		if cfg.Password != "" {
			d.Subprotocols = []string{cfg.Password}
		}
		return d
	}

	if scheme == "ws" {
		dialer := newDialer()
		if ip != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(address)
				return net.DialTimeout(network, net.JoinHostPort(ip, port), DialTimeout)
			}
		}
		conn, _, err := dialer.Dial(wsURL, nil)
		return conn, err
	}

	// wss path
	serverName := cfg.SNI
	var tlsCfg *tls.Config
	if ech, echErr := getECHList(); echErr == nil {
		tlsCfg, _ = buildTLSConfigWithECH(serverName, ech)
	}
	if tlsCfg != nil {
		tlsCfg.InsecureSkipVerify = cfg.Insecure
	} else {
		tlsCfg = buildStandardTLSConfig(serverName, cfg.Insecure)
	}

	dialer := newDialer()
	dialer.TLSClientConfig = tlsCfg

	if ip != "" {
		dialer.NetDial = func(network, address string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(address)
			if host, p, err := net.SplitHostPort(ip); err == nil {
				return net.DialTimeout(network, net.JoinHostPort(host, p), DialTimeout)
			}
			return net.DialTimeout(network, net.JoinHostPort(ip, port), DialTimeout)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("auth failed: token mismatch")
		}
		return nil, err
	}
	return conn, nil
}

func probeRTTOnce(sess *smux.Session, timeout time.Duration) (int64, error) {
	start := time.Now()
	s, err := sess.OpenStream()
	if err != nil {
		return 0, err
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(timeout))
	if err := writeSmuxOpenHeader(s, streamKindPing, 0, ""); err != nil {
		return 0, err
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(start.UnixNano()))
	if _, err := s.Write(payload); err != nil {
		return 0, err
	}
	ack := make([]byte, 8)
	if _, err := io.ReadFull(s, ack); err != nil {
		return 0, err
	}
	if !bytes.Equal(ack, payload) {
		return 0, errors.New("ping ack mismatch")
	}
	return time.Since(start).Nanoseconds(), nil
}

func probeRTTLoop(sess *smux.Session, idx int, channelRTT *[]int64, done chan error) {
	var exitErr error
	defer func() {
		done <- exitErr
		close(done)
	}()
	ticker := time.NewTicker(RTTProbeTimeout)
	defer ticker.Stop()
	for {
		rtt, err := probeRTTOnce(sess, RTTProbeTimeout)
		if err != nil {
			atomic.StoreInt64(&(*channelRTT)[idx], int64(RTTProbeTimeout.Nanoseconds()))
			if sess.IsClosed() {
				exitErr = err
				return
			}
			<-ticker.C
			continue
		}
		atomic.StoreInt64(&(*channelRTT)[idx], rtt)
		<-ticker.C
	}
}