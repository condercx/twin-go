//go:build !go1.24

package twin

import (
	"crypto/tls"
	"errors"
)

var echListMu RWMutexPlaceholder
var echList []byte

// RWMutexPlaceholder is replaced by sync.RWMutex on Go 1.24+.
type RWMutexPlaceholder struct{}

func (m *RWMutexPlaceholder) Lock()    {}
func (m *RWMutexPlaceholder) Unlock()  {}
func (m *RWMutexPlaceholder) RLock()   {}
func (m *RWMutexPlaceholder) RUnlock() {}

func prepareECH(host, dnsServer string) error {
	return nil // silently ignore on older Go versions
}

func refreshECH(host, dnsServer string) error {
	return nil
}

func getECHList() ([]byte, error) {
	return nil, errors.New("ECH requires Go 1.24+")
}

func buildTLSConfigWithECH(serverName string, echConfig []byte) (*tls.Config, error) {
	return nil, errors.New("ECH requires Go 1.24+")
}

func buildStandardTLSConfig(serverName string, insecure bool) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	}
}