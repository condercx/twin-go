package twin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

type serverContext struct {
	cfg *ServerConfig
	sessions sync.Map
}

type clientSession struct {
	clientID   string
	nextChanID uint64
	mu         sync.RWMutex
	channels   map[uint64]*wsChannel
}

type wsChannel struct {
	id      uint64
	conn    *websocket.Conn
	session *clientSession
}

type Server struct {
	cfg    *ServerConfig
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	srvCtx *serverContext
	doneCh chan struct{}
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	if err := cfg.fillDefaults(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
		srvCtx: &serverContext{cfg: cfg},
		doneCh: make(chan struct{}),
	}, nil
}

func (s *Server) Start() error {
	for _, l := range s.cfg.Listeners {
		s.wg.Add(1)
		go s.runListener(l)
	}
	go func() {
		s.wg.Wait()
		close(s.doneCh)
	}()
	logf("[server] started with %d listener(s)", len(s.cfg.Listeners))
	return nil
}

func (s *Server) runListener(lc ListenerConfig) {
	defer s.wg.Done()

	path := "/"
	allowedNets := []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}}

	upgrader := websocket.Upgrader{
		CheckOrigin:    func(r *http.Request) bool { return true },
		ReadBufferSize: ReadBufSize,
		WriteBufferSize: ReadBufSize,
	}

	if s.cfg.Password != "" {
		upgrader.Subprotocols = []string{s.cfg.Password}
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ip := net.ParseIP(clientIP)
		allowed := false
		for _, n := range allowedNets {
			if n.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		if s.cfg.Password != "" {
			proto := r.Header.Get("Sec-WebSocket-Protocol")
			if proto != s.cfg.Password {
				logf("[server] auth failed from %s", clientIP)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		cid := r.URL.Query().Get("client_id")
		if cid == "" {
			cid = uuid.NewString()
		}
		channelID := uint64(0)
		if v := r.URL.Query().Get("channel_id"); v != "" {
			if parsed, parseErr := strconv.ParseUint(v, 10, 64); parseErr == nil {
				channelID = parsed
			}
		}

		session := s.getOrCreateSession(cid)
		ch := session.addChannel(wsConn, channelID)
		logf("[server] client %s channel %d connected, IP: %s", shortID(cid), ch.id, clientIP)
		go s.handleChannel(ch)
	})

	server := &http.Server{Addr: lc.Listen, Handler: mux}

	if lc.TLSMode == TLSModeWSS {
		if lc.CertFile != "" && lc.KeyFile != "" {
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			logf("[server] WSS listening on %s", lc.Listen)
			if err := server.ListenAndServeTLS(lc.CertFile, lc.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf("[server] WSS %s error: %v", lc.Listen, err)
			}
		} else {
			cert, err := generateSelfSignedCert()
			if err != nil {
				logf("[server] generate self-signed cert failed: %v", err)
				return
			}
			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			}
			logf("[server] WSS (self-signed) listening on %s", lc.Listen)
			if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf("[server] WSS %s error: %v", lc.Listen, err)
			}
		}
	} else {
		logf("[server] WS listening on %s", lc.Listen)
		if err := server.ListenAndServe(); err != nil {
			logf("[server] WS %s error: %v", lc.Listen, err)
			// Fatal error - exit to prevent deadlock
			panic(err)
		}
	}
}

func (s *Server) handleChannel(ch *wsChannel) {
	wsConn := ch.conn
	session := ch.session

	defer func() {
		_ = wsConn.Close()
		session.removeChannel(ch.id, ch)
	}()

	netConn := newWSNetConn(wsConn)
	sess, err := smux.Server(netConn, nil)
	if err != nil {
		logf("[server] channel %d smux init failed: %v", ch.id, err)
		return
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			logf("[server] client channel %d disconnected", ch.id)
			return
		}
		go s.handleStream(session, ch, stream)
	}
}

func (s *Server) handleStream(session *clientSession, ch *wsChannel, stream *smux.Stream) {
	defer stream.Close()

	kind, strategy, target, err := readSmuxOpenHeader(stream)
	if err != nil {
		return
	}

	switch kind {
	case streamKindPing:
		payload := make([]byte, 8)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return
		}
		_, _ = stream.Write(payload)

	case streamKindTCP:
		logf("[server] client:%s TCP: %s channel:%d", shortID(session.clientID), target, ch.id)
		var tcpConn net.Conn
		if s.cfg.Forward != "" {
			tcpConn, err = dialViaSocks5("tcp", target)
		} else {
			tcpConn, err = dialTCPWithStrategy(target, strategy)
		}
		if err != nil {
			return
		}
		proxyConnStream(tcpConn, stream)
		logf("[server] client:%s TCP close: %s channel:%d", shortID(session.clientID), target, ch.id)

	case streamKindUDP:
		logf("[server] client:%s UDP: %s channel:%d", shortID(session.clientID), target, ch.id)
		var relay UDPRelayer
		if s.cfg.Forward != "" {
			socksRelay, errSocks := newSOCKS5UDPRelay(target, s.cfg.Forward)
			if errSocks != nil {
				logf("[server] SOCKS5 UDP relay create failed: %v", errSocks)
				return
			}
			relay = socksRelay
		} else {
			addr, errResolve := resolveUDPWithStrategy(target, strategy)
			if errResolve != nil {
				return
			}
			udpConn, errListen := net.ListenUDP("udp", nil)
			if errListen != nil {
				return
			}
			relay = &directUDPRelayer{conn: udpConn, target: addr}
		}
		if relay == nil {
			return
		}
		defer relay.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				packet, e := readChunk(stream)
				if e != nil {
					return
				}
				if len(packet) == 0 {
					continue
				}
				if _, e = relay.Write(packet); e != nil {
					return
				}
			}
		}()
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		defer bufPool.Put(bufPtr)
		for {
			_ = relay.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, e := relay.Read(buf)
			if e != nil {
				var netErr net.Error
				if errors.As(e, &netErr) && netErr.Timeout() {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				return
			}
			if err := writeUDPReply(stream, addr.String(), buf[:n]); err != nil {
				return
			}
		}
	}
}

func (s *Server) getOrCreateSession(clientID string) *clientSession {
	if v, ok := s.srvCtx.sessions.Load(clientID); ok {
		if cs, okType := v.(*clientSession); okType && cs != nil {
			return cs
		}
		s.srvCtx.sessions.Delete(clientID)
	}
	cs := &clientSession{
		clientID: clientID,
		channels: make(map[uint64]*wsChannel),
	}
	actual, _ := s.srvCtx.sessions.LoadOrStore(clientID, cs)
	if ret, ok := actual.(*clientSession); ok && ret != nil {
		return ret
	}
	s.srvCtx.sessions.Store(clientID, cs)
	return cs
}

func (cs *clientSession) addChannel(wsConn *websocket.Conn, preferredID uint64) *wsChannel {
	newID := preferredID
	if newID == 0 {
		newID = atomic.AddUint64(&cs.nextChanID, 1)
	}
	ch := &wsChannel{
		id:      newID,
		conn:    wsConn,
		session: cs,
	}
	var replaced *wsChannel
	cs.mu.Lock()
	if old, ok := cs.channels[ch.id]; ok {
		replaced = old
	}
	cs.channels[ch.id] = ch
	cs.mu.Unlock()
	if replaced != nil {
		_ = replaced.conn.Close()
	}
	return ch
}

func (cs *clientSession) removeChannel(id uint64, current *wsChannel) {
	cs.mu.Lock()
	if ch, ok := cs.channels[id]; ok && ch == current {
		delete(cs.channels, id)
	}
	empty := len(cs.channels) == 0
	cs.mu.Unlock()
	if empty {
		logf("[server] client session %s gone", cs.clientID)
	}
}

func (s *Server) Close() error {
	s.cancel()
	return nil
}

func dialViaSocks5(network, addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, DialTimeout)
}

type UDPRelayer interface {
	Read(buffer []byte) (int, *net.UDPAddr, error)
	Write(data []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

type directUDPRelayer struct {
	conn   *net.UDPConn
	target *net.UDPAddr
}

func (d *directUDPRelayer) Read(buffer []byte) (int, *net.UDPAddr, error) { return d.conn.ReadFromUDP(buffer) }
func (d *directUDPRelayer) Write(data []byte) (int, error)                { return d.conn.WriteToUDP(data, d.target) }
func (d *directUDPRelayer) SetReadDeadline(t time.Time) error             { return d.conn.SetReadDeadline(t) }
func (d *directUDPRelayer) Close() error                                  { return d.conn.Close() }

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "bing.com",
			Organization: []string{"Twin"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(36500 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"bing.com"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}

func newSOCKS5UDPRelay(targetAddr, forwardAddr string) (UDPRelayer, error) {
	return nil, errors.New("SOCKS5 forward: not yet fully implemented")
}

func (s *Server) Done() <-chan struct{} {
	return s.doneCh
}