package obfs

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
	"sync"
	"time"
)

const saltLen = 16

type XPlusObfuscator struct {
	Key []byte
}

func NewXPlusObfuscator(key []byte) *XPlusObfuscator {
	return &XPlusObfuscator{Key: key}
}

func (x *XPlusObfuscator) Obfuscate(in []byte, out []byte) int {
	rand.Read(out[:saltLen])
	key := sha256.Sum256(append(x.Key, out[:saltLen]...))
	for i, c := range in {
		out[i+saltLen] = c ^ key[i%sha256.Size]
	}
	return len(in) + saltLen
}

func (x *XPlusObfuscator) Deobfuscate(in []byte, out []byte) int {
	pLen := len(in) - saltLen
	if pLen <= 0 || len(out) < pLen {
		return 0
	}
	key := sha256.Sum256(append(x.Key, in[:saltLen]...))
	for i, c := range in[saltLen:] {
		out[i] = c ^ key[i%sha256.Size]
	}
	return pLen
}

// ObfsPacketConn wraps a net.PacketConn and applies XPlus on every read/write.
// Every QUIC packet is obfuscated so DPI cannot identify the protocol.
type ObfsPacketConn struct {
	conn net.PacketConn
	obfs *XPlusObfuscator
	mu   sync.Mutex
	buf  []byte
}

func NewObfsPacketConn(conn net.PacketConn, key []byte) *ObfsPacketConn {
	return &ObfsPacketConn{
		conn: conn,
		obfs: NewXPlusObfuscator(key),
		buf:  make([]byte, 65536),
	}
}

func (c *ObfsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.conn.ReadFrom(c.buf)
	if err != nil {
		return 0, nil, err
	}
	decLen := c.obfs.Deobfuscate(c.buf[:n], p)
	if decLen == 0 {
		return 0, nil, nil // skip invalid
	}
	return decLen, addr, nil
}

func (c *ObfsPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	buf := make([]byte, len(p)+saltLen)
	_ = c.obfs.Obfuscate(p, buf)
	c.mu.Unlock()
	_, err := c.conn.WriteTo(buf, addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ObfsPacketConn) Close() error                 { return c.conn.Close() }
func (c *ObfsPacketConn) LocalAddr() net.Addr          { return c.conn.LocalAddr() }
func (c *ObfsPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *ObfsPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *ObfsPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
