//go:build go1.24

package twin

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"sync"
)

var (
	echListMu sync.RWMutex
	echList   []byte
	refreshMu sync.Mutex
)

func prepareECH(host, dnsServer string) error {
	ech, err := queryHTTPSRecord(host, dnsServer)
	if err != nil { return nil }
	raw, err := base64.StdEncoding.DecodeString(ech)
	if err != nil { return nil }
	echListMu.Lock()
	echList = raw
	echListMu.Unlock()
	return nil
}

func refreshECH(host, dnsServer string) error {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	return prepareECH(host, dnsServer)
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH list not available")
	}
	ret := make([]byte, len(echList))
	copy(ret, echList)
	return ret, nil
}

func buildTLSConfigWithECH(serverName string, echConfig []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		EncryptedClientHelloConfigList: echConfig,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("server rejected ECH")
		},
		RootCAs: roots,
	}, nil
}

func buildStandardTLSConfig(serverName string, insecure bool) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: insecure,
	}
}