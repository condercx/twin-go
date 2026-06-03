package twin

import (
	"crypto/sha256"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	authNonceSize      = 16
	authStreamDeadline = 30 * time.Second
	obfsKeyLen         = 32
)

var (
	ErrAuthFailed = errors.New("twin: authentication failed")
)

type AuthStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

// DeriveObfsKey derives an XPlus obfuscation key from the password.
// Both client and server call this independently with the same password.
func DeriveObfsKey(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:obfsKeyLen]
}

func WriteAuth(w AuthStream, password string, sendBPS, recvBPS uint64) error {
	if err := w.SetDeadline(time.Now().Add(authStreamDeadline)); err != nil {
		return fmt.Errorf("set auth deadline: %w", err)
	}

	nonce := make([]byte, authNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	pwdBytes := []byte(password)

	var buf []byte
	pwdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(pwdLen, uint16(len(pwdBytes)))
	buf = append(buf, pwdLen...)
	buf = append(buf, pwdBytes...)
	nonceLen := make([]byte, 2)
	binary.BigEndian.PutUint16(nonceLen, uint16(len(nonce)))
	buf = append(buf, nonceLen...)
	buf = append(buf, nonce...)

	bpsBuf := make([]byte, 16)
	binary.BigEndian.PutUint64(bpsBuf[0:8], sendBPS)
	binary.BigEndian.PutUint64(bpsBuf[8:16], recvBPS)
	buf = append(buf, bpsBuf...)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}

	success, _, _, err := ReadAuthResult(w)
	if err != nil {
		return err
	}
	if !success {
		return ErrAuthFailed
	}
	return nil
}

func ReadAuth(r io.Reader, expectedPassword string) (sendBPS, recvBPS uint64, err error) {
	lenBuf := make([]byte, 2)

	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, 0, fmt.Errorf("read pwd len: %w", err)
	}
	pwdLen := binary.BigEndian.Uint16(lenBuf)

	pwdBytes := make([]byte, pwdLen)
	if _, err := io.ReadFull(r, pwdBytes); err != nil {
		return 0, 0, fmt.Errorf("read pwd: %w", err)
	}

	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, 0, fmt.Errorf("read nonce len: %w", err)
	}
	nonceLen := binary.BigEndian.Uint16(lenBuf)

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return 0, 0, fmt.Errorf("read nonce: %w", err)
	}
	_ = nonce

	bpsBuf := make([]byte, 16)
	if _, err := io.ReadFull(r, bpsBuf); err != nil {
		return 0, 0, fmt.Errorf("read bps: %w", err)
	}
	sendBPS = binary.BigEndian.Uint64(bpsBuf[0:8])
	recvBPS = binary.BigEndian.Uint64(bpsBuf[8:16])

	if string(pwdBytes) != expectedPassword {
		return sendBPS, recvBPS, ErrAuthFailed
	}
	return sendBPS, recvBPS, nil
}

func WriteAuthResult(w io.Writer, success bool, serverSendBPS, serverRecvBPS uint64) error {
	buf := make([]byte, 17)
	if success {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	binary.BigEndian.PutUint64(buf[1:9], serverSendBPS)
	binary.BigEndian.PutUint64(buf[9:17], serverRecvBPS)
	_, err := w.Write(buf)
	return err
}

func ReadAuthResult(r io.Reader) (success bool, serverSendBPS, serverRecvBPS uint64, err error) {
	buf := make([]byte, 17)
	if _, err := io.ReadFull(r, buf); err != nil {
		return false, 0, 0, fmt.Errorf("read auth result: %w", err)
	}
	success = buf[0] == 0
	serverSendBPS = binary.BigEndian.Uint64(buf[1:9])
	serverRecvBPS = binary.BigEndian.Uint64(buf[9:17])
	return
}
