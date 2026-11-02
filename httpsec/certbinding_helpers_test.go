package httpsec_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// clientCert is a client certificate a test presents: the parsed certificate,
// the TLS certificate a client dials with, and its RFC 8705 thumbprint.
type clientCert struct {
	cert  *x509.Certificate
	tls   tls.Certificate
	thumb string
}

// newClientCert makes a self-signed client certificate named cn. The library
// compares thumbprints only, so nothing here needs a chain.
func newClientCert(t *testing.T, cn string) clientCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	sum := sha256.Sum256(der)

	return clientCert{
		cert:  cert,
		tls:   tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert},
		thumb: base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

// pem is the certificate PEM-encoded.
func (c clientCert) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}))
}

// escaped is the certificate as nginx's $ssl_client_escaped_cert forwards it:
// PEM, URL-encoded.
func (c clientCert) escaped() string { return url.QueryEscape(c.pem()) }
