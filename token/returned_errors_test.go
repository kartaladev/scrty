package token_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/token"
)

// errKeySourceFixture is the fixture every leak row in this change is proven
// against: a dependency's error quoting an address and a user reference the
// returned error must never repeat.
var errKeySourceFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

// failingSigner wraps a real crypto.Signer's Public key but fails every Sign
// call with err, so a test can drive a consumer key source's crypto.Signer
// into failing without a mock — jwt.Sign inspects the signer's public key
// before it ever calls Sign, so the wrapped key must be genuine.
type failingSigner struct {
	crypto.Signer
	err error
}

func (f *failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, f.err
}

// failingSignerKeySource is a signingkey.KeySource whose current key signs
// with failingSigner, so Generate reaches the consumer key source's own
// signing failure.
type failingSignerKeySource struct {
	kid    string
	signer crypto.Signer
}

var _ signingkey.KeySource = (*failingSignerKeySource)(nil)

func (s *failingSignerKeySource) GetSigner(alg signingkey.Alg) (string, crypto.Signer, bool) {
	if alg != signingkey.RS256 {
		return "", nil, false
	}
	return s.kid, s.signer, true
}

func (s *failingSignerKeySource) VerificationKeys() ([]signingkey.PublicKey, error) {
	return nil, nil
}

func newFailingSignerKeySource(t *testing.T, err error) *failingSignerKeySource {
	t.Helper()

	private, genErr := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, genErr)

	return &failingSignerKeySource{
		kid:    "failing-key-1",
		signer: &failingSigner{Signer: private, err: err},
	}
}

// TestGeneratorReturnedErrors pins the diagnostic-redaction requirement for
// Generate's own returned error (design decision 8): a consumer key source's
// crypto.Signer failing to sign comes back as fixed library text, with the
// signer's own error still reachable by identity.
func TestGeneratorReturnedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		run    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "the key source's signer fails to sign",
			run: func(t *testing.T) error {
				t.Helper()

				keys := newFailingSignerKeySource(t, errKeySourceFixture)
				gen, err := token.NewGenerator(keys)
				require.NoError(t, err)

				_, genErr := gen.Generate(t.Context(), "jti-1", &identity.Principal{Username: "alice"})
				return genErr
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), "alice@example.com",
					"the returned error quoted the signer's own text")
				assert.NotContains(t, err.Error(), "u-123",
					"the returned error quoted the signer's own text")
				assert.ErrorIs(t, err, errKeySourceFixture, "the signer's own error is no longer reachable")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}

// TestVerifierReturnedErrors pins the diagnostic-redaction requirement for
// Verify's own returned error (design decision 8): a key source that cannot
// supply its verification keys comes back as fixed library text, with the key
// source's own error still reachable by identity, and still not matching
// ErrTokenInvalid — an outage in obtaining the keys is not a verdict on the
// token.
func TestVerifierReturnedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		run    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "the key source cannot supply its verification keys",
			run: func(t *testing.T) error {
				t.Helper()

				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys().Return(nil, errKeySourceFixture)

				ver, err := token.NewVerifier(token.VerifyWithKeySource(keys))
				require.NoError(t, err)

				_, verifyErr := ver.Verify(t.Context(), "any.token.here")

				return verifyErr
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), "alice@example.com",
					"the returned error quoted the key source's own text")
				assert.NotContains(t, err.Error(), "u-123",
					"the returned error quoted the key source's own text")
				assert.ErrorIs(t, err, errKeySourceFixture, "the key source's own error is no longer reachable")
				assert.NotErrorIs(t, err, token.ErrTokenInvalid,
					"an unavailable key set must still not be reported as a refused token")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}
