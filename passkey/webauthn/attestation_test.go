package webauthn_test

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/passkey/webauthn"
	"github.com/kartaladev/scrty/passkey/webauthn/webauthntest"
)

// attestationEnv is a test PKI: an authenticator model's attestation root
// and certificate, and a metadata BLOB signer under a test MDS root.
type attestationEnv struct {
	aaguid  [16]byte
	attRoot *testCA
	att     *testCA
	mdsRoot *testCA
	signer  *testCA
}

func newAttestationEnv(t *testing.T) *attestationEnv {
	t.Helper()
	attRoot := newRoot(t, "Test Attestation Root")
	mdsRoot := newRoot(t, "Test MDS Root")
	return &attestationEnv{
		aaguid:  [16]byte{0xa1, 0xa2, 0xa3, 0xa4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		attRoot: attRoot,
		att:     attestationCert(t, attRoot),
		mdsRoot: mdsRoot,
		signer:  issue(t, mdsRoot, pkix.Name{CommonName: "Test MDS Signer"}, false, ""),
	}
}

// source is a consumer-supplied metadata source serving one BLOB with
// entries, signed under the env's MDS root.
func (e *attestationEnv) source(t *testing.T, entries ...map[string]any) webauthn.MetadataSource {
	t.Helper()
	raw := blob{no: 1, nextUpdate: time.Now().Add(72 * time.Hour), entries: entries}.sign(t, e.signer, e.mdsRoot.cert)
	return webauthn.MetadataBlob(func(context.Context) ([]byte, error) { return raw, nil }, webauthn.WithMDSRoot(e.mdsRoot.cert))
}

func TestAttestation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T, e *attestationEnv) []webauthn.Option
		body   func(t *testing.T, a *webauthntest.Authenticator, e *attestationEnv) []byte
		assert func(t *testing.T, nc *passkey.NewCredential, err error)
	}

	none := func(_ *testing.T, a *webauthntest.Authenticator, _ *attestationEnv) []byte {
		return a.Create(rpID, rpOrigin, challenge, []byte("handle-0123456789"), webauthntest.AttestationNone)
	}
	self := func(_ *testing.T, a *webauthntest.Authenticator, _ *attestationEnv) []byte {
		return a.Create(rpID, rpOrigin, challenge, []byte("handle-0123456789"), webauthntest.AttestationPacked)
	}
	basic := func(t *testing.T, a *webauthntest.Authenticator, e *attestationEnv) []byte {
		return basicAttestation(t, a, e.att)
	}
	trusted := func(allowed ...[16]byte) func(t *testing.T, e *attestationEnv) []webauthn.Option {
		return func(t *testing.T, e *attestationEnv) []webauthn.Option {
			return []webauthn.Option{webauthn.WithTrustedAttestation(e.source(t, mdsEntry(e.aaguid, e.attRoot, "FIDO_CERTIFIED")), allowed...)}
		}
	}
	refused := func(t *testing.T, nc *passkey.NewCredential, err error) {
		require.ErrorIs(t, err, passkey.ErrAttestationRefused)
		assert.Nil(t, nc)
	}

	cases := []testCase{
		{
			name: "the default accepts none and records no format",
			body: none,
			assert: func(t *testing.T, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.Empty(t, nc.AttestationFormat)
				assert.Empty(t, nc.AttestationStatement)
				assert.False(t, nc.AttestationTrusted)
			},
		},
		{
			name: "the default accepts an unrequested packed statement and records nothing of it",
			body: self,
			assert: func(t *testing.T, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.Empty(t, nc.AttestationFormat)
				assert.Empty(t, nc.AttestationStatement)
			},
		},
		{
			name: "record mode keeps a packed format and its statement",
			opts: func(*testing.T, *attestationEnv) []webauthn.Option {
				return []webauthn.Option{webauthn.WithAttestationRecord()}
			},
			body: self,
			assert: func(t *testing.T, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.Equal(t, "packed", nc.AttestationFormat)
				var stmt map[string]any
				require.NoError(t, cbor.Unmarshal(nc.AttestationStatement, &stmt))
				assert.Contains(t, stmt, "sig")
				assert.Contains(t, stmt, "alg")
				assert.False(t, nc.AttestationTrusted)
			},
		},
		{
			name: "record mode accepts none, recording the format only",
			opts: func(*testing.T, *attestationEnv) []webauthn.Option {
				return []webauthn.Option{webauthn.WithAttestationRecord()}
			},
			body: none,
			assert: func(t *testing.T, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.Equal(t, "none", nc.AttestationFormat)
				assert.Empty(t, nc.AttestationStatement)
			},
		},
		{
			name:   "trusted mode refuses none",
			opts:   trusted(),
			body:   none,
			assert: refused,
		},
		{
			name:   "trusted mode refuses self attestation",
			opts:   trusted(),
			body:   self,
			assert: refused,
		},
		{
			name: "trusted mode accepts a statement chaining to a certified metadata entry",
			opts: trusted(),
			body: basic,
			assert: func(t *testing.T, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.True(t, nc.AttestationTrusted)
				assert.Equal(t, "packed", nc.AttestationFormat)
				assert.NotEmpty(t, nc.AttestationStatement)
			},
		},
		{
			name: "trusted mode accepts a model on the allowlist",
			opts: func(t *testing.T, e *attestationEnv) []webauthn.Option { return trusted(e.aaguid)(t, e) },
			body: basic,
			assert: func(t *testing.T, nc *passkey.NewCredential, err error) {
				require.NoError(t, err)
				assert.True(t, nc.AttestationTrusted)
			},
		},
		{
			name:   "trusted mode refuses a model off the allowlist",
			opts:   trusted([16]byte{9, 9, 9}),
			body:   basic,
			assert: refused,
		},
		{
			name: "trusted mode refuses a revoked model",
			opts: func(t *testing.T, e *attestationEnv) []webauthn.Option {
				return []webauthn.Option{webauthn.WithTrustedAttestation(e.source(t, mdsEntry(e.aaguid, e.attRoot, "REVOKED")))}
			},
			body:   basic,
			assert: refused,
		},
		{
			name: "trusted mode refuses a model the metadata does not list",
			opts: func(t *testing.T, e *attestationEnv) []webauthn.Option {
				return []webauthn.Option{webauthn.WithTrustedAttestation(e.source(t))}
			},
			body:   basic,
			assert: refused,
		},
		{
			name: "trusted mode refuses a certificate that does not chain to the entry's root",
			opts: func(t *testing.T, e *attestationEnv) []webauthn.Option {
				other := newRoot(t, "Another Root")
				return []webauthn.Option{webauthn.WithTrustedAttestation(e.source(t, mdsEntry(e.aaguid, other, "FIDO_CERTIFIED")))}
			},
			body:   basic,
			assert: refused,
		},
		{
			name: "trusted mode refuses when the metadata cannot be had",
			opts: func(*testing.T, *attestationEnv) []webauthn.Option {
				src := webauthn.MetadataBlob(func(context.Context) ([]byte, error) { return nil, errors.New("unavailable") })
				return []webauthn.Option{webauthn.WithTrustedAttestation(src)}
			},
			body:   basic,
			assert: refused,
		},
		{
			name: "trusted mode refuses metadata signed outside the configured root",
			opts: func(t *testing.T, e *attestationEnv) []webauthn.Option {
				raw := blob{no: 1, nextUpdate: time.Now().Add(72 * time.Hour), entries: []map[string]any{mdsEntry(e.aaguid, e.attRoot, "FIDO_CERTIFIED")}}.sign(t, e.signer, e.mdsRoot.cert)
				other := newRoot(t, "Unrelated MDS Root")
				src := webauthn.MetadataBlob(func(context.Context) ([]byte, error) { return raw, nil }, webauthn.WithMDSRoot(other.cert))
				return []webauthn.Option{webauthn.WithTrustedAttestation(src)}
			},
			body:   basic,
			assert: refused,
		},
		{
			name: "a response that does not verify is authentication failed, not an attestation refusal",
			opts: trusted(),
			body: func(t *testing.T, a *webauthntest.Authenticator, e *attestationEnv) []byte {
				a.UV = false
				return basicAttestation(t, a, e.att)
			},
			assert: func(t *testing.T, nc *passkey.NewCredential, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, passkey.ErrAttestationRefused)
				assert.Nil(t, nc)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newAttestationEnv(t)
			var opts []webauthn.Option
			if tc.opts != nil {
				opts = tc.opts(t, e)
			}
			v := newVerifier(t, opts...)

			a := webauthntest.New(t)
			a.AAGUID = e.aaguid
			p, err := v.ParseRegistration(tc.body(t, a, e))
			require.NoError(t, err)
			nc, err := v.VerifyRegistration(t.Context(), p, passkey.RegistrationExpectation{Challenge: challenge, UV: passkey.UVRequired})
			tc.assert(t, nc, err)
		})
	}
}

func TestAttestation_Conveyance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T) []webauthn.Option
		assert func(t *testing.T, opts map[string]any)
	}

	cases := []testCase{
		{
			name:   "the default requests none",
			assert: func(t *testing.T, opts map[string]any) { assert.Equal(t, "none", opts["attestation"]) },
		},
		{
			name:   "record mode requests direct",
			opts:   func(*testing.T) []webauthn.Option { return []webauthn.Option{webauthn.WithAttestationRecord()} },
			assert: func(t *testing.T, opts map[string]any) { assert.Equal(t, "direct", opts["attestation"]) },
		},
		{
			name: "trusted mode requests direct",
			opts: func(t *testing.T) []webauthn.Option {
				return []webauthn.Option{webauthn.WithTrustedAttestation(newAttestationEnv(t).source(t))}
			},
			assert: func(t *testing.T, opts map[string]any) { assert.Equal(t, "direct", opts["attestation"]) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var opts []webauthn.Option
			if tc.opts != nil {
				opts = tc.opts(t)
			}
			raw, err := newVerifier(t, opts...).CreationOptions(t.Context(), passkey.CreationInput{
				UserHandle: []byte("handle"), UserName: "alice", DisplayName: "Alice", Challenge: challenge,
				Timeout: time.Minute, UV: passkey.UVRequired, ResidentKey: passkey.ResidentKeyRequired,
			})
			require.NoError(t, err)
			tc.assert(t, decode(t, raw))
		})
	}
}

func TestAttestation_ConfigurationErrors(t *testing.T) {
	t.Parallel()

	fetch := func(context.Context) ([]byte, error) { return nil, nil }
	plainClient, err := outbound.New()
	require.NoError(t, err)

	type testCase struct {
		name   string
		opts   []webauthn.Option
		assert func(t *testing.T, err error)
	}

	configErr := func(t *testing.T, err error) { require.ErrorIs(t, err, passkey.ErrConfig) }

	cases := []testCase{
		{name: "trusted attestation without a metadata source", opts: []webauthn.Option{webauthn.WithTrustedAttestation(nil)}, assert: configErr},
		{
			name:   "record and trusted at once",
			opts:   []webauthn.Option{webauthn.WithAttestationRecord(), webauthn.WithTrustedAttestation(webauthn.MetadataBlob(fetch))},
			assert: configErr,
		},
		{name: "a metadata blob without a fetch function", opts: []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataBlob(nil))}, assert: configErr},
		{name: "the MDS without a client", opts: []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataFromMDS(nil))}, assert: configErr},
		{
			name:   "a nil metadata option",
			opts:   []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataBlob(fetch, nil))},
			assert: configErr,
		},
		{
			name:   "a nil metadata root",
			opts:   []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataBlob(fetch, webauthn.WithMDSRoot(nil)))},
			assert: configErr,
		},
		{
			name:   "a nil metadata clock",
			opts:   []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataBlob(fetch, webauthn.WithMDSClock(nil)))},
			assert: configErr,
		},
		{
			name:   "an MDS URL on a consumer-fetched blob, which has none",
			opts:   []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataBlob(fetch, webauthn.WithMDSURL("https://mds.example.com/")))},
			assert: configErr,
		},
		{
			name:   "an MDS URL the client would refuse",
			opts:   []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataFromMDS(plainClient, webauthn.WithMDSURL("http://mds.example.com/")))},
			assert: configErr,
		},
		{
			name:   "a malformed MDS URL",
			opts:   []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataFromMDS(plainClient, webauthn.WithMDSURL("::not a url")))},
			assert: configErr,
		},
		{
			name: "the MDS with its default URL is accepted",
			opts: []webauthn.Option{webauthn.WithTrustedAttestation(webauthn.MetadataFromMDS(plainClient))},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := webauthn.New(relyingParty(), tc.opts...)
			tc.assert(t, err)
		})
	}
}
