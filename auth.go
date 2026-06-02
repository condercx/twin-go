package twin

import (
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
)

var (
	ErrAuthFailed = errors.New("twin: authentication failed")
)

type AuthStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

func WriteAuth(w AuthStream, password string) error {
	if err := w.SetDeadline(time.Now().Add(authStreamDeadline)); err != nil {
		return fmt.Errorf("set auth deadline: %w", err)
	}

	nonce := make([]byte, authNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	pwdBytes := []byte(password)

	// Format: [pwdLen:2][pwdBytes][nonceLen:2][nonceBytes]
	var buf []byte
	pwdLen := make([]byte, 2)
	binary.BigEndian.PutUint16(pwdLen, uint16(len(pwdBytes)))
	buf = append(buf, pwdLen...)
	buf = append(buf, pwdBytes...)
	nonceLen := make([]byte, 2)
	binary.BigEndian.PutUint16(nonceLen, uint16(len(nonce)))
	buf = append(buf, nonceLen...)
	buf = append(buf, nonce...)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}

	result := make([]byte, 1)
	if _, err := io.ReadFull(w, result); err != nil {
		return fmt.Errorf("read auth result: %w", err)
	}
	if result[0] != 0 {
		return ErrAuthFailed
	}
	return nil
}

func ReadAuth(r io.Reader, expectedPassword string) error {
	lenBuf := make([]byte, 2)

	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return fmt.Errorf("read pwd len: %w", err)
	}
	pwdLen := binary.BigEndian.Uint16(lenBuf)

	pwdBytes := make([]byte, pwdLen)
	if _, err := io.ReadFull(r, pwdBytes); err != nil {
		return fmt.Errorf("read pwd: %w", err)
	}

	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return fmt.Errorf("read nonce len: %w", err)
	}
	nonceLen := binary.BigEndian.Uint16(lenBuf)

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}

	_ = nonce

	if string(pwdBytes) != expectedPassword {
		return ErrAuthFailed
	}
	return nil
}

func WriteAuthResult(w io.Writer, success bool) error {
	var result byte
	if success {
		result = 0
	} else {
		result = 1
	}
	_, err := w.Write([]byte{result})
	return err
}
