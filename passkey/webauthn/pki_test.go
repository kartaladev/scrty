package webauthn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/passkey/webauthn/webauthntest"
)

// testCA is a certificate and the key it certifies.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial = struct {
	sync.Mutex
	n int64
}{}

func nextSerial() *big.Int {
	serial.Lock()
	defer serial.Unlock()
	serial.n++
	return big.NewInt(serial.n)
}

// issue creates a certificate for subject signed by parent (self-signed when
// parent is nil).
func issue(t *testing.T, parent *testCA, subject pkix.Name, isCA bool, crlURL string) *testCA {
	t.Helper()
	return issueUntil(t, parent, subject, isCA, crlURL, time.Now().Add(60*24*time.Hour))
}

// issueUntil is issue with the certificate valid until notAfter.
func issueUntil(t *testing.T, parent *testCA, subject pkix.Name, isCA bool, crlURL string, notAfter time.Time) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if crlURL != "" {
		tmpl.CRLDistributionPoints = []string{crlURL}
	}

	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key}
}

func newRoot(t *testing.T, cn string) *testCA {
	return issue(t, nil, pkix.Name{CommonName: cn, Organization: []string{"Test"}}, true, "")
}

// attestationCert is a packed attestation certificate as WebAuthn §8.2.1
// requires it, issued by root.
func attestationCert(t *testing.T, root *testCA) *testCA {
	return issue(t, root, pkix.Name{
		Country: []string{"US"}, Organization: []string{"Test Vendor"},
		OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Test Authenticator",
	}, false, "")
}

func stdB64(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }

// basicAttestation answers a registration with a packed attestation signed by
// att, carrying att's certificate in x5c: the full ("basic") attestation a
// hardware security key makes.
func basicAttestation(t *testing.T, a *webauthntest.Authenticator, att *testCA) []byte {
	t.Helper()
	body := a.Create(rpID, rpOrigin, challenge, []byte("handle-0123456789"), webauthntest.AttestationPacked)

	var msg map[string]any
	require.NoError(t, json.Unmarshal(body, &msg))
	resp := msg["response"].(map[string]any)

	clientData, err := base64.RawURLEncoding.DecodeString(resp["clientDataJSON"].(string))
	require.NoError(t, err)
	rawObj, err := base64.RawURLEncoding.DecodeString(resp["attestationObject"].(string))
	require.NoError(t, err)

	var obj struct {
		Fmt      string          `cbor:"fmt"`
		AttStmt  cbor.RawMessage `cbor:"attStmt"`
		AuthData []byte          `cbor:"authData"`
	}
	require.NoError(t, cbor.Unmarshal(rawObj, &obj))

	cdh := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, obj.AuthData...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, att.key, digest[:])
	require.NoError(t, err)

	stmt, err := cbor.Marshal(map[string]any{"alg": -7, "sig": sig, "x5c": [][]byte{att.cert.Raw}})
	require.NoError(t, err)
	obj.AttStmt = stmt
	rawObj, err = cbor.Marshal(obj)
	require.NoError(t, err)

	resp["attestationObject"] = base64.RawURLEncoding.EncodeToString(rawObj)
	out, err := json.Marshal(msg)
	require.NoError(t, err)
	return out
}

func aaguidString(a [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", a[0:4], a[4:6], a[6:8], a[8:10], a[10:16])
}

// mdsEntry is a metadata BLOB entry for an authenticator model whose
// attestation certificates chain to attRoot, with the given status.
func mdsEntry(aaguid [16]byte, attRoot *testCA, status string) map[string]any {
	id := aaguidString(aaguid)
	return map[string]any{
		"aaguid": id,
		"metadataStatement": map[string]any{
			"aaguid":                      id,
			"description":                 "Test security key",
			"protocolFamily":              "fido2",
			"schema":                      3,
			"attestationTypes":            []string{"basic_full"},
			"attestationRootCertificates": []string{stdB64(attRoot.cert)},
		},
		"statusReports":          []map[string]any{{"status": status, "effectiveDate": "2024-01-01"}},
		"timeOfLastStatusChange": "2024-01-01",
	}
}

// blob is a metadata BLOB's payload.
type blob struct {
	no         int
	nextUpdate time.Time
	entries    []map[string]any
}

// sign encodes b as an MDS3 JWT signed by signer, whose chain (signer first)
// goes in the x5c header.
func (b blob) sign(t *testing.T, signer *testCA, chain ...*x509.Certificate) []byte {
	t.Helper()
	x5c := []string{stdB64(signer.cert)}
	for _, c := range chain {
		x5c = append(x5c, stdB64(c))
	}
	return b.signWith(t, jwt.SigningMethodES256, signer.key, map[string]any{"x5c": x5c})
}

// signWith encodes b as a JWT signed by key under method, with header's
// members added to the JOSE header.
func (b blob) signWith(t *testing.T, method jwt.SigningMethod, key any, header map[string]any) []byte {
	t.Helper()
	entries := b.entries
	if entries == nil {
		entries = []map[string]any{}
	}
	tok := jwt.NewWithClaims(method, jwt.MapClaims{
		"legalHeader": "test",
		"no":          b.no,
		"nextUpdate":  b.nextUpdate.UTC().Format(time.DateOnly),
		"entries":     entries,
	})
	for k, v := range header {
		tok.Header[k] = v
	}
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return []byte(s)
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Now()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
