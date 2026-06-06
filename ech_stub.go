//go:build !go1.24

package twin

import (
	"crypto/tls"
	"errors"
)

func prepareECH(host, dnsServer string) error {
	return nil
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
