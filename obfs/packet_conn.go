package obfs

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
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
}

func NewObfsPacketConn(conn net.PacketConn, key []byte) *ObfsPacketConn {
	return &ObfsPacketConn{
		conn: conn,
		obfs: NewXPlusObfuscator(key),
	}
}

func (c *ObfsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65536)
	n, addr, err := c.conn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < saltLen {
		return 0, addr, nil
	}
	decLen := c.obfs.Deobfuscate(buf[:n], p)
	if decLen == 0 {
		return 0, addr, nil
	}
	return decLen, addr, nil
}

func (c *ObfsPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	buf := make([]byte, len(p)+saltLen)
	_ = c.obfs.Obfuscate(p, buf)
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
