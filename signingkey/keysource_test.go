package signingkey_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

// externalKeySource stands in for a consumer's own key service: it holds a key
// no KeyManager ever generated, published, or knows about, and satisfies the
// port on its own. It deliberately does not report a lifetime.
//
// It names no JOSE type, which is the point of the port's shape: a consumer
// implements it with the standard library alone.
type externalKeySource struct {
	kid    string
	signer crypto.Signer
	public ed25519.PublicKey
}

func newExternalKeySource(t *testing.T) *externalKeySource {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return &externalKeySource{kid: "external-1", signer: private, public: public}
}

func (s *externalKeySource) GetSigner(alg signingkey.Alg) (string, crypto.Signer, bool) {
	if alg != signingkey.EdDSA {
		return "", nil, false
	}
	return s.kid, s.signer, true
}

func (s *externalKeySource) VerificationKeys() ([]signingkey.PublicKey, error) {
	return []signingkey.PublicKey{{
		Kid: s.kid,
		Alg: signingkey.EdDSA,
		Key: s.public,
	}}, nil
}

// TestKeySource pins that the key manager and a consumer's own source are
// interchangeable behind one port: each supplies a signer and the set that
// verifies what it signed.
func TestKeySource(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		source func(t *testing.T) signingkey.KeySource
		assert func(t *testing.T, source signingkey.KeySource)
	}

	// issuesAndVerifies is shared: the cases differ only in which
	// implementation of the port is behind them.
	issuesAndVerifies := func(t *testing.T, source signingkey.KeySource) {
		kid, _, ok := source.GetSigner(signingkey.EdDSA)
		require.True(t, ok, "the source supplies a signer for EdDSA")
		require.NotEmpty(t, kid)

		token := signWithCurrent(t, source, "issued over the port")

		require.True(t, publishes(source, kid), "the source publishes the key that signed")
		set := publishedSet(t, source)
		published, found := set.LookupKeyID(kid)
		require.True(t, found)
		isPrivate, err := jwk.IsPrivateKey(published)
		require.NoError(t, err)
		assert.False(t, isPrivate)

		payload, err := jws.Verify(token, jws.WithKeySet(set))
		require.NoError(t, err, "the source's own set verifies what its signer signed")
		assert.Equal(t, "issued over the port", string(payload))

		_, _, rsOK := source.GetSigner(signingkey.RS256)
		assert.False(t, rsOK, "a source reports no signer for an algorithm it does not hold")
	}

	cases := []testCase{
		{
			name: "the key manager implements it",
			source: func(t *testing.T) signingkey.KeySource {
				km, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.EdDSA),
				)
				require.NoError(t, err)
				return km
			},
			assert: issuesAndVerifies,
		},
		{
			name: "a consumer's own source is accepted with no key manager constructed",
			source: func(t *testing.T) signingkey.KeySource {
				return newExternalKeySource(t)
			},
			assert: issuesAndVerifies,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.source(t))
		})
	}
}

// TestLifetimeReporter pins the optional half of the port: a source may say how
// long its keys live, and one that does not is simply not asked.
func TestLifetimeReporter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		source func(t *testing.T) signingkey.KeySource
		assert func(t *testing.T, reporter signingkey.LifetimeReporter, reports bool)
	}

	cases := []testCase{
		{
			name: "the key manager reports the lifetime and interval it was configured with",
			source: func(t *testing.T) signingkey.KeySource {
				km, err := signingkey.NewKeyManager(t.Context(),
					signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
					signingkey.WithAlgs(signingkey.EdDSA),
					signingkey.WithLifetime(48*time.Hour),
					signingkey.WithRotateInterval(6*time.Hour),
				)
				require.NoError(t, err)
				return km
			},
			assert: func(t *testing.T, reporter signingkey.LifetimeReporter, reports bool) {
				require.True(t, reports, "the key manager reports its lifetime")
				assert.Equal(t, 48*time.Hour, reporter.KeyLifetime())
				assert.Equal(t, 6*time.Hour, reporter.RotateInterval())
			},
		},
		{
			name: "a source that does not report a lifetime gets no such check",
			source: func(t *testing.T) signingkey.KeySource {
				return newExternalKeySource(t)
			},
			assert: func(t *testing.T, reporter signingkey.LifetimeReporter, reports bool) {
				assert.False(t, reports, "the optional half is genuinely optional")
				assert.Nil(t, reporter)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reporter, reports := tc.source(t).(signingkey.LifetimeReporter)
			tc.assert(t, reporter, reports)
		})
	}
}
