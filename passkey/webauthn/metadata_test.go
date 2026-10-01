package webauthn_test

import (
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

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
