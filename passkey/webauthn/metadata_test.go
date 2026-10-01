package webauthn_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/passkey/webauthn"
	"github.com/kartaladev/scrty/passkey/webauthn/webauthntest"
)

// mdsHarness is a metadata service on an httptest TLS server, reached
// through the confined client, and a verifier requiring trusted attestation
// from it.
type mdsHarness struct {
	env   *attestationEnv
	clock *fakeClock
	v     *webauthn.Verifier

	mu     sync.Mutex
	hits   int
	status int
	body   []byte
}

func newMDSHarness(t *testing.T, signer func(e *attestationEnv) *testCA) *mdsHarness {
	t.Helper()
	h := &mdsHarness{env: newAttestationEnv(t), clock: newFakeClock(), status: http.StatusOK}
	if signer != nil {
		h.env.signer = signer(h.env)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.hits++
		if r.URL.Path != "/blob" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(h.status)
		_, _ = w.Write(h.body)
	}))
	t.Cleanup(srv.Close)

	client, err := outbound.New(outbound.WithHTTPClient(srv.Client()), outbound.WithAllowedOrigins(srv.URL))
	require.NoError(t, err)

	src := webauthn.MetadataFromMDS(client,
		webauthn.WithMDSURL(srv.URL+"/blob"), webauthn.WithMDSRoot(h.env.mdsRoot.cert), webauthn.WithMDSClock(h.clock))
	h.v = newVerifier(t, webauthn.WithTrustedAttestation(src))
	return h
}

// publish makes the service answer with a BLOB of serial no, valid until
// nextUpdate, listing the env's authenticator model as certified.
func (h *mdsHarness) publish(t *testing.T, no int, nextUpdate time.Time) {
	t.Helper()
	raw := blob{no: no, nextUpdate: nextUpdate, entries: []map[string]any{mdsEntry(h.env.aaguid, h.env.attRoot, "FIDO_CERTIFIED")}}.
		sign(t, h.env.signer, h.env.mdsRoot.cert)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status, h.body = http.StatusOK, raw
}

func (h *mdsHarness) fail() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status, h.body = http.StatusInternalServerError, nil
}

func (h *mdsHarness) fetches() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits
}

// register runs a trusted registration from a basic-attested authenticator.
func (h *mdsHarness) register(t *testing.T) (*passkey.NewCredential, error) {
	t.Helper()
	a := webauthntest.New(t)
	a.AAGUID = h.env.aaguid
	p, err := h.v.ParseRegistration(basicAttestation(t, a, h.env.att))
	require.NoError(t, err)
	return h.v.VerifyRegistration(t.Context(), p, passkey.RegistrationExpectation{Challenge: challenge, UV: passkey.UVRequired})
}

func trustedOK(t *testing.T, nc *passkey.NewCredential, err error) {
	t.Helper()
	require.NoError(t, err)
	assert.True(t, nc.AttestationTrusted)
}

func TestMetadataFromMDS(t *testing.T) {
	t.Parallel()

	day := 24 * time.Hour

	type testCase struct {
		name   string
		signer func(e *attestationEnv) *testCA
		assert func(t *testing.T, h *mdsHarness)
	}

	cases := []testCase{
		{
			name: "one fetch, then a cached read before nextUpdate",
			assert: func(t *testing.T, h *mdsHarness) {
				h.publish(t, 1, h.clock.Now().Add(3*day))
				nc, err := h.register(t)
				trustedOK(t, nc, err)
				h.clock.Advance(2 * time.Hour)
				nc, err = h.register(t)
				trustedOK(t, nc, err)
				assert.Equal(t, 1, h.fetches())
			},
		},
		{
			name: "a refetch once nextUpdate has passed",
			assert: func(t *testing.T, h *mdsHarness) {
				h.publish(t, 1, h.clock.Now().Add(2*day))
				nc, err := h.register(t)
				trustedOK(t, nc, err)
				h.publish(t, 2, h.clock.Now().Add(6*day))
				h.clock.Advance(3 * day)
				nc, err = h.register(t)
				trustedOK(t, nc, err)
				assert.Equal(t, 2, h.fetches())
			},
		},
		{
			name: "a refetch after 24 hours even when nextUpdate is later",
			assert: func(t *testing.T, h *mdsHarness) {
				h.publish(t, 1, h.clock.Now().Add(30*day))
				nc, err := h.register(t)
				trustedOK(t, nc, err)
				h.clock.Advance(23 * time.Hour)
				_, err = h.register(t)
				require.NoError(t, err)
				assert.Equal(t, 1, h.fetches())
				h.clock.Advance(2 * time.Hour)
				_, err = h.register(t)
				require.NoError(t, err)
				assert.Equal(t, 2, h.fetches())
			},
		},
		{
			name: "a failed refetch keeps refusing rather than trusting stale metadata",
			assert: func(t *testing.T, h *mdsHarness) {
				h.publish(t, 1, h.clock.Now().Add(2*day))
				nc, err := h.register(t)
				trustedOK(t, nc, err)
				h.fail()
				h.clock.Advance(3 * day)
				_, err = h.register(t)
				require.ErrorIs(t, err, passkey.ErrAttestationRefused)
				_, err = h.register(t)
				require.ErrorIs(t, err, passkey.ErrAttestationRefused)
				assert.Equal(t, 3, h.fetches(), "each refusal tries the service again")
				h.publish(t, 2, h.clock.Now().Add(2*day))
				nc, err = h.register(t)
				trustedOK(t, nc, err)
			},
		},
		{
			name: "a BLOB whose serial number goes backwards is refused",
			assert: func(t *testing.T, h *mdsHarness) {
				h.publish(t, 5, h.clock.Now().Add(2*day))
				nc, err := h.register(t)
				trustedOK(t, nc, err)
				h.publish(t, 4, h.clock.Now().Add(6*day))
				h.clock.Advance(3 * day)
				_, err = h.register(t)
				require.ErrorIs(t, err, passkey.ErrAttestationRefused)
			},
		},
		{
			name: "a BLOB already past its nextUpdate is refused",
			assert: func(t *testing.T, h *mdsHarness) {
				h.publish(t, 1, h.clock.Now().Add(-2*day))
				_, err := h.register(t)
				require.ErrorIs(t, err, passkey.ErrAttestationRefused)
			},
		},
		{
			name: "an unsuccessful status is refused",
			assert: func(t *testing.T, h *mdsHarness) {
				h.fail()
				_, err := h.register(t)
				require.ErrorIs(t, err, passkey.ErrAttestationRefused)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, newMDSHarness(t, tc.signer))
		})
	}
}

// TestMetadata_NoRequestLeavesOutsideTheConfinedClient pins that decoding a
// BLOB makes no request of its own: the signing certificate names a CRL on a
// server the confined client was never configured for, and nothing may reach
// it.
func TestMetadata_NoRequestLeavesOutsideTheConfinedClient(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	crlHits := 0
	crl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		crlHits++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(crl.Close)

	h := newMDSHarness(t, func(e *attestationEnv) *testCA {
		return issue(t, e.mdsRoot, pkix.Name{CommonName: "Test MDS Signer"}, false, crl.URL+"/signer.crl")
	})
	h.publish(t, 1, h.clock.Now().Add(48*time.Hour))

	nc, err := h.register(t)
	trustedOK(t, nc, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, crlHits, "the BLOB decoder sent a request outside the confined client")
}

// TestMetadataBlob_SigningRules pins how a BLOB's JWT signature is judged:
// the algorithms allowed, the headers refused, the signing chain checked
// against the configured root at the source's clock, and the root's own key
// when the BLOB carries no chain.
func TestMetadataBlob_SigningRules(t *testing.T) {
	t.Parallel()

	day := 24 * time.Hour

	type testCase struct {
		name    string
		token   func(t *testing.T, e *attestationEnv, b blob) []byte
		advance time.Duration                        // how far the source's clock is ahead of real time
		root    func(t *testing.T) *x509.Certificate // the configured root; nil means the env's
		assert  func(t *testing.T, nc *passkey.NewCredential, err error)
	}

	refused := func(t *testing.T, nc *passkey.NewCredential, err error) {
		require.ErrorIs(t, err, passkey.ErrAttestationRefused)
		assert.Nil(t, nc)
	}
	x5c := func(certs ...*testCA) map[string]any {
		out := make([]string, 0, len(certs))
		for _, c := range certs {
			out = append(out, stdB64(c.cert))
		}
		return map[string]any{"x5c": out}
	}

	cases := []testCase{
		{
			name: "a BLOB with no x5c signed by the root's own key is accepted",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				return b.signWith(t, jwa.ES256(), e.mdsRoot.key, nil)
			},
			assert: trustedOK,
		},
		{
			name: "a BLOB with no x5c signed by a key other than the root's is refused",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				return b.signWith(t, jwa.ES256(), e.signer.key, nil)
			},
			assert: refused,
		},
		{
			name: "an unsigned BLOB (alg none) is refused",
			token: func(t *testing.T, _ *attestationEnv, b blob) []byte {
				return b.signWith(t, jwa.NoSignature(), nil, nil)
			},
			assert: refused,
		},
		{
			name: "an HS256 BLOB keyed with the root's public key is refused",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				return b.signWith(t, jwa.HS256(), e.mdsRoot.cert.RawSubjectPublicKeyInfo, nil)
			},
			assert: refused,
		},
		{
			name: "an EdDSA BLOB is refused, even signed by an Ed25519 root's own key",
			token: func(t *testing.T, _ *attestationEnv, b blob) []byte {
				return b.signWith(t, jwa.EdDSA(), ed25519Root(t).key, nil)
			},
			root:   func(t *testing.T) *x509.Certificate { return ed25519Root(t).cert },
			assert: refused,
		},
		{
			name: "a BLOB naming an x5u header is refused",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				h := x5c(e.signer, e.mdsRoot)
				h["x5u"] = "https://mds.example.com/chain.pem"
				return b.signWith(t, jwa.ES256(), e.signer.key, h)
			},
			assert: refused,
		},
		{
			name: "a BLOB signed by the key its own jwk header embeds is refused",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				embedded, err := jwk.Import[jwk.Key](e.signer.key.Public())
				require.NoError(t, err)
				return b.signWith(t, jwa.ES256(), e.signer.key, map[string]any{"jwk": embedded})
			},
			assert: refused,
		},
		{
			name: "a BLOB naming a jku header is refused when signed by a key other than the root's, and the jku is never fetched",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				// The jku serves the signer's key, so honouring it would accept the BLOB.
				embedded, err := jwk.Import[jwk.Key](e.signer.key.Public())
				require.NoError(t, err)
				require.NoError(t, embedded.Set(jwk.AlgorithmKey, jwa.ES256()))
				require.NoError(t, embedded.Set(jwk.KeyIDKey, "mds"))
				set := jwk.NewSet()
				require.NoError(t, set.AddKey(embedded))
				var fetches atomic.Int32
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					fetches.Add(1)
					_ = json.NewEncoder(w).Encode(set)
				}))
				t.Cleanup(func() {
					srv.Close()
					assert.Zero(t, fetches.Load(), "the jku was fetched")
				})
				return b.signWith(t, jwa.ES256(), e.signer.key, map[string]any{"jku": srv.URL, "kid": "mds"})
			},
			assert: refused,
		},
		{
			name: "a BLOB whose exp has passed at the source's clock is refused",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				b.claims = map[string]any{"exp": time.Now().Add(day).Unix()}
				return b.signWith(t, jwa.ES256(), e.mdsRoot.key, nil)
			},
			advance: 2 * day,
			assert:  refused,
		},
		{
			name: "a BLOB whose nbf is still ahead of the source's clock is refused",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				b.claims = map[string]any{"nbf": time.Now().Add(day).Unix()}
				return b.signWith(t, jwa.ES256(), e.mdsRoot.key, nil)
			},
			assert: refused,
		},
		{
			name: "a signing certificate expired at the source's clock is refused",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				leaf := issueUntil(t, e.mdsRoot, pkix.Name{CommonName: "Short-lived MDS Signer"}, false, "", time.Now().Add(day))
				return b.signWith(t, jwa.ES256(), leaf.key, x5c(leaf, e.mdsRoot))
			},
			advance: 2 * day,
			assert:  refused,
		},
		{
			name: "a signing chain ending at a root other than the configured one is refused",
			token: func(t *testing.T, _ *attestationEnv, b blob) []byte {
				foreign := newRoot(t, "Foreign MDS Root")
				leaf := issue(t, foreign, pkix.Name{CommonName: "Foreign MDS Signer"}, false, "")
				return b.signWith(t, jwa.ES256(), leaf.key, x5c(leaf, foreign))
			},
			assert: refused,
		},
		{
			name: "a BLOB signed by a key other than its x5c certificate's is refused",
			token: func(t *testing.T, e *attestationEnv, b blob) []byte {
				impostor := issue(t, nil, pkix.Name{CommonName: "Impostor"}, false, "")
				return b.signWith(t, jwa.ES256(), impostor.key, x5c(e.signer, e.mdsRoot))
			},
			assert: refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newAttestationEnv(t)
			clk := newFakeClock()
			clk.Advance(tc.advance)
			b := blob{no: 1, nextUpdate: time.Now().Add(5 * day), entries: []map[string]any{mdsEntry(e.aaguid, e.attRoot, "FIDO_CERTIFIED")}}
			raw := tc.token(t, e, b)
			root := e.mdsRoot.cert
			if tc.root != nil {
				root = tc.root(t)
			}
			src := webauthn.MetadataBlob(func(context.Context) ([]byte, error) { return raw, nil },
				webauthn.WithMDSRoot(root), webauthn.WithMDSClock(clk))
			v := newVerifier(t, webauthn.WithTrustedAttestation(src))

			a := webauthntest.New(t)
			a.AAGUID = e.aaguid
			p, err := v.ParseRegistration(basicAttestation(t, a, e.att))
			require.NoError(t, err)
			nc, err := v.VerifyRegistration(t.Context(), p, passkey.RegistrationExpectation{Challenge: challenge, UV: passkey.UVRequired})
			tc.assert(t, nc, err)
		})
	}
}

// ed25519RootCA is a self-signed Ed25519 root, made once: the EdDSA case
// needs the same root to sign the BLOB and to be configured.
var ed25519RootCA = struct {
	sync.Once
	cert *x509.Certificate
	key  ed25519.PrivateKey
	err  error
}{}

type ed25519CA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func ed25519Root(t *testing.T) ed25519CA {
	t.Helper()
	ed25519RootCA.Do(func() {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			ed25519RootCA.err = err
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: "Ed25519 MDS Root"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour),
			BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
		if err != nil {
			ed25519RootCA.err = err
			return
		}
		ed25519RootCA.cert, ed25519RootCA.err = x509.ParseCertificate(der)
		ed25519RootCA.key = key
	})
	require.NoError(t, ed25519RootCA.err)
	return ed25519CA{cert: ed25519RootCA.cert, key: ed25519RootCA.key}
}
