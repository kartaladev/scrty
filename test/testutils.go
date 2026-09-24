package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mailpit"
)

// smtpImage is the SMTP test server every RunTestSMTP caller gets, pinned by
// digest so a remote tag move cannot change what the tests ran against.
const smtpImage = "axllent/mailpit@sha256:7eef0f38dbc85e4e264f2edf5d70fbb694826791e05cb2cae4fc9e3282f968f5"

// TestOption customises a helper in this package. Each helper documents the
// options it reads and the default each one replaces.
//
// The name stutters as test.TestOption and stays that way: RunTestX(t,
// ...TestOption) is this repository's convention for every container helper,
// and the prefix is what tells a caller these are not library options.
//
//nolint:revive // stuttering name kept deliberately, see above
type TestOption func(*testConfig)

type testConfig struct {
	image    string
	username string
	password string
}

// WithTestSMTPImage replaces the digest-pinned SMTP server image RunTestSMTP
// starts. Use it to reproduce a report against another version; the default
// is what CI runs.
func WithTestSMTPImage(ref string) TestOption {
	return func(c *testConfig) { c.image = ref }
}

// WithTestSMTPCredentials replaces the credentials the SMTP server requires.
// The default is a fixed pair; the server rejects a session that authenticates
// with anything else, so a test that expects a refusal sets its own.
func WithTestSMTPCredentials(username, password string) TestOption {
	return func(c *testConfig) {
		c.username = username
		c.password = password
	}
}

// SMTPConn is how a test reaches the SMTP server RunTestSMTP started.
//
// RootCAs trusts the certificate the server presents on STARTTLS, and is
// generated per test. A sender under test therefore keeps its certificate
// verification on: the test trusts this one server, not every server.
type SMTPConn struct {
	Host     string
	Port     int
	Username string
	Password string
	RootCAs  *x509.CertPool

	api string // the container's HTTP API, for reading received messages
}

// ReceivedMessage is one message the test server accepted, as it arrived on
// the wire. The subject is decoded from its encoded-word form so a caller
// compares readable text; every other field is left exactly as received.
type ReceivedMessage struct {
	DecodedSubject string
	Body           string
	Headers        map[string]string
}

// RunTestSMTP starts an SMTP server for one test and returns how to reach it.
//
// The server requires AUTH and requires STARTTLS, so a send that skips either
// is refused rather than quietly accepted — the point of testing against a
// real server is that it enforces what an in-process script only pretends to.
// The certificate is generated for this test alone and offered back through
// SMTPConn.RootCAs.
//
// The container is torn down with the test. Every test that needs SMTP calls
// this rather than starting its own: one helper means one place to change the
// image, the ports and the readiness rule.
//
// It skips the test when Docker is unavailable, because an unrunnable
// integration test is more useful skipped than failing for a reason that has
// nothing to do with the code.
func RunTestSMTP(t *testing.T, opts ...TestOption) SMTPConn {
	t.Helper()

	testcontainers.SkipIfProviderIsNotHealthy(t)

	cfg := &testConfig{
		image:    smtpImage,
		username: "mailbot",
		password: "s3cret",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	certPEM, keyPEM, pool := serverCertificate(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	ctx := t.Context()

	ctr, err := mailpit.Run(ctx, cfg.image,
		mailpit.WithSMTPAuth(cfg.username, cfg.password),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				HostFilePath:      certPath,
				ContainerFilePath: "/certs/cert.pem",
				FileMode:          0o644,
			},
			testcontainers.ContainerFile{
				HostFilePath:      keyPath,
				ContainerFilePath: "/certs/key.pem",
				FileMode:          0o644,
			},
		),
		testcontainers.WithEnv(map[string]string{
			"MP_SMTP_TLS_CERT": "/certs/cert.pem",
			"MP_SMTP_TLS_KEY":  "/certs/key.pem",
			// The credentials option above also permits AUTH in the clear,
			// which the server refuses to combine with required encryption.
			// Encryption wins: credentials only ever cross an upgraded
			// connection here.
			"MP_SMTP_AUTH_ALLOW_INSECURE": "false",
			"MP_SMTP_REQUIRE_STARTTLS":    "true",
		}),
	)
	require.NoError(t, err, "failed to start SMTP test container")

	t.Cleanup(func() {
		// Not t.Context(): it is already cancelled by the time cleanup runs,
		// and Terminate would fail before it removed anything.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := ctr.Terminate(cleanupCtx); err != nil {
			t.Fatalf("failed to terminate SMTP container: %s", err)
		}
	})

	endpoint, err := ctr.SMTPEndpoint(ctx)
	require.NoError(t, err, "failed to read the SMTP endpoint")
	host, portText, err := net.SplitHostPort(endpoint)
	require.NoError(t, err, "unexpected SMTP endpoint %q", endpoint)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err, "unexpected SMTP port %q", portText)

	api, err := ctr.HTTPURL(ctx)
	require.NoError(t, err, "failed to read the message API URL")

	return SMTPConn{
		Host:     host,
		Port:     port,
		Username: cfg.username,
		Password: cfg.password,
		RootCAs:  pool,
		api:      strings.TrimSuffix(api, "/"),
	}
}

// Messages returns what the server has received, newest last.
func (c SMTPConn) Messages(t *testing.T) []ReceivedMessage {
	t.Helper()

	var list struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(c.get(t, c.api+"/api/v1/messages"), &list))

	// The API reports newest first.
	out := make([]ReceivedMessage, 0, len(list.Messages))
	for i := len(list.Messages) - 1; i >= 0; i-- {
		raw := c.get(t, c.api+"/api/v1/message/"+list.Messages[i].ID+"/raw")

		parsed, err := mail.ReadMessage(strings.NewReader(string(raw)))
		require.NoError(t, err, "received message is not parseable")

		body, err := io.ReadAll(parsed.Body)
		require.NoError(t, err, "failed to read the received body")

		// The subject crosses the wire in encoded-word form whenever it is not
		// plain ASCII. Decoding it here is what lets a caller assert the text
		// the recipient will read, rather than one particular encoding of it.
		subject, err := (&mime.WordDecoder{}).DecodeHeader(parsed.Header.Get("Subject"))
		require.NoError(t, err, "received subject is not decodable")

		headers := make(map[string]string, len(parsed.Header))
		for name, values := range parsed.Header {
			headers[name] = strings.Join(values, ", ")
		}

		out = append(out, ReceivedMessage{
			DecodedSubject: subject,
			Body:           string(body),
			Headers:        headers,
		})
	}

	return out
}

func (c SMTPConn) get(t *testing.T, url string) []byte {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "message API request to %s failed", url)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "message API %s answered %s", url, body)

	return body
}

// serverCertificate mints a certificate the test SMTP server presents on
// STARTTLS, valid for the loopback names a mapped container port is reached
// by, together with a pool that trusts exactly it.
func serverCertificate(t *testing.T) (certPEM, keyPEM []byte, pool *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	pool = x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))

	return certPEM, keyPEM, pool
}
