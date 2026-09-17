package token_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/token"
)

func TestGenerateClaims(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		algs   []signingkey.Alg
		opts   func(clock *fixedClock) []token.GenerateOption
		assert func(t *testing.T, keys *signingkey.KeyManager, raw string, err error)
	}

	cases := []testCase{
		{
			name: "the default token is RS256, lives 15 minutes and names the current key",
			opts: func(clock *fixedClock) []token.GenerateOption {
				return []token.GenerateOption{
					token.WithIssuer("https://auth.example"),
					token.WithClock(clock),
				}
			},
			assert: func(t *testing.T, keys *signingkey.KeyManager, raw string, err error) {
				require.NoError(t, err)

				header := decodeHeader(t, raw)
				assert.Equal(t, "RS256", header["alg"])

				wantKid, _, ok := keys.GetSigner(signingkey.RS256)
				require.True(t, ok)
				assert.Equal(t, wantKid, header["kid"])

				claims := decodeClaims(t, raw)
				assert.Equal(t, "s-7", claims["jti"])
				assert.Equal(t, "https://auth.example", claims["iss"])
				assert.Equal(t, "alice", claims["sub"])
				assert.EqualValues(t, issuedAt.Unix(), claims["iat"])
				assert.EqualValues(t, issuedAt.Add(15*time.Minute).Unix(), claims["exp"])
				assert.NotContains(t, claims, "aud", "no audience configured, no aud claim")
			},
		},
		{
			name: "a consumer replaces the algorithm and the lifetime",
			algs: []signingkey.Alg{signingkey.ES256},
			opts: func(clock *fixedClock) []token.GenerateOption {
				return []token.GenerateOption{
					token.WithSigningAlg(signingkey.ES256),
					token.WithLifetime(5 * time.Minute),
					token.WithClock(clock),
				}
			},
			assert: func(t *testing.T, keys *signingkey.KeyManager, raw string, err error) {
				require.NoError(t, err)

				header := decodeHeader(t, raw)
				assert.Equal(t, "ES256", header["alg"])

				wantKid, _, ok := keys.GetSigner(signingkey.ES256)
				require.True(t, ok)
				assert.Equal(t, wantKid, header["kid"])

				claims := decodeClaims(t, raw)
				assert.EqualValues(t, issuedAt.Add(5*time.Minute).Unix(), claims["exp"])
			},
		},
		{
			name: "a configured audience is carried",
			opts: func(clock *fixedClock) []token.GenerateOption {
				return []token.GenerateOption{
					token.WithAudience("api"),
					token.WithClock(clock),
				}
			},
			assert: func(t *testing.T, _ *signingkey.KeyManager, raw string, err error) {
				require.NoError(t, err)
				assert.Contains(t, decodeClaims(t, raw)["aud"], "api")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t, tc.algs...)
			clock := &fixedClock{now: issuedAt}

			gen, err := token.NewGenerator(keys, tc.opts(clock)...)
			require.NoError(t, err)

			raw, err := gen.Generate(t.Context(), "s-7", alice())
			tc.assert(t, keys, raw, err)
		})
	}
}

// TestAudienceRoundTrip pins that what the generator writes into aud is what a
// verifier configured with the same audience accepts. The two halves are
// configured independently, so a generator that cannot set aud fails here even
// though both sides are configured identically.
func TestAudienceRoundTrip(t *testing.T) {
	t.Parallel()

	keys := newKeySource(t)

	gen, err := token.NewGenerator(keys, token.WithAudience("api"))
	require.NoError(t, err)

	raw, err := gen.Generate(t.Context(), "s-1", alice())
	require.NoError(t, err)

	ver, err := token.NewVerifier(
		token.VerifyWithKeySource(keys),
		token.VerifyWithAudience("api"),
	)
	require.NoError(t, err)

	claims, err := ver.Verify(t.Context(), raw)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.Subject())
}

func TestNewGeneratorValidation(t *testing.T) {
	t.Parallel()

	// reporting builds a key source that reports a 24-hour key lifetime and a
	// 1-hour rotation interval, so its usable window is 23 hours.
	reporting := func(t *testing.T) signingkey.KeySource {
		t.Helper()

		return newKeySourceWith(t,
			signingkey.WithLifetime(24*time.Hour),
			signingkey.WithRotateInterval(time.Hour))
	}

	// refused asserts that a wiring mistake is identifiable as a configuration
	// error without matching message text, and that it says which mistake.
	refused := func(mentions string) func(*testing.T, token.Generator, error) {
		return func(t *testing.T, gen token.Generator, err error) {
			t.Helper()

			require.ErrorIs(t, err, token.ErrConfig)
			assert.Nil(t, gen, "a refused configuration yields no generator")
			assert.Contains(t, err.Error(), mentions)
		}
	}
	constructed := func(t *testing.T, gen token.Generator, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, gen)
	}

	type testCase struct {
		name   string
		keys   func(t *testing.T) signingkey.KeySource
		opts   []token.GenerateOption
		assert func(t *testing.T, gen token.Generator, err error)
	}

	cases := []testCase{
		{
			name:   "no key source",
			keys:   func(_ *testing.T) signingkey.KeySource { return nil },
			assert: refused("key source"),
		},
		{
			name:   "a nil clock",
			keys:   reporting,
			opts:   []token.GenerateOption{token.WithClock(nil)},
			assert: refused("clock"),
		},
		{
			name:   "an unknown signing algorithm",
			keys:   reporting,
			opts:   []token.GenerateOption{token.WithSigningAlg("RS256-but-misspelled")},
			assert: refused("unknown signing algorithm"),
		},
		{
			name:   "a zero lifetime",
			keys:   reporting,
			opts:   []token.GenerateOption{token.WithLifetime(0)},
			assert: refused("positive"),
		},
		{
			name:   "a negative lifetime",
			keys:   reporting,
			opts:   []token.GenerateOption{token.WithLifetime(-time.Second)},
			assert: refused("positive"),
		},
		{
			name:   "a lifetime that outlives the key",
			keys:   reporting,
			opts:   []token.GenerateOption{token.WithLifetime(24 * time.Hour)},
			assert: refused("outlive"),
		},
		{
			name:   "a lifetime one second past the usable window",
			keys:   reporting,
			opts:   []token.GenerateOption{token.WithLifetime(23*time.Hour + time.Second)},
			assert: refused("outlive"),
		},
		{
			name:   "a lifetime exactly filling the usable window is accepted",
			keys:   reporting,
			opts:   []token.GenerateOption{token.WithLifetime(23 * time.Hour)},
			assert: constructed,
		},
		{
			name:   "the default lifetime over a reporting key source is accepted",
			keys:   reporting,
			assert: constructed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen, err := token.NewGenerator(tc.keys(t), tc.opts...)
			tc.assert(t, gen, err)
		})
	}
}

// TestGenerateRefusesRatherThanIssuingAnUnusableToken also pins the rule that
// no failure on the issue path is identifiable as ErrTokenInvalid: that is the
// verdict on a token a caller presented, and a consumer who maps it to
// "credential refused" must not see it from a failed issue.
func TestGenerateRefusesRatherThanIssuingAnUnusableToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		algs      []signingkey.Alg
		opts      []token.GenerateOption
		principal func() *identity.Principal
		assert    func(t *testing.T, raw string, err error)
	}

	cases := []testCase{
		{
			name:      "no current key for the configured algorithm",
			opts:      []token.GenerateOption{token.WithSigningAlg(signingkey.EdDSA)},
			principal: alice,
			assert: func(t *testing.T, raw string, err error) {
				require.Error(t, err)
				assert.Empty(t, raw, "never an unsigned token")
				assert.Contains(t, err.Error(), "EdDSA")
			},
		},
		{
			name:      "no principal to name as subject",
			principal: func() *identity.Principal { return nil },
			assert: func(t *testing.T, raw string, err error) {
				require.ErrorIs(t, err, identity.ErrNoPrincipal)
				assert.Empty(t, raw)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen, err := token.NewGenerator(newKeySource(t, tc.algs...), tc.opts...)
			require.NoError(t, err)

			raw, err := gen.Generate(t.Context(), "s-1", tc.principal())
			tc.assert(t, raw, err)
			assert.NotErrorIs(t, err, token.ErrTokenInvalid,
				"a failure to issue is not the verdict on a presented token")
		})
	}
}

// TestGeneratorVerifiesItsOwnTokens pins that one construction issues and
// verifies under the same key source, issuer, audience and clock, and that the
// clock really is the one both halves read.
func TestGeneratorVerifiesItsOwnTokens(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fixedClock{now: issuedAt}

	gen, err := token.NewGenerator(newKeySource(t),
		token.WithIssuer("https://auth.example"),
		token.WithAudience("api"),
		token.WithClock(clock),
	)
	require.NoError(t, err)

	raw, err := gen.Generate(t.Context(), "s-7", alice())
	require.NoError(t, err)

	claims, err := gen.Verify(t.Context(), raw)
	require.NoError(t, err, "the generator verifies with its own key source, issuer and audience")
	assert.Equal(t, "alice", claims.Subject())
	assert.Equal(t, "s-7", claims.ID())

	assert.EqualValues(t, issuedAt.Unix(), decodeClaims(t, raw)["iat"],
		"iat is read from the injected source, not the wall clock")

	// The same source drives verification: 14 minutes on, the default
	// 15-minute token still verifies.
	clock.Advance(14 * time.Minute)
	_, err = gen.Verify(t.Context(), raw)
	require.NoError(t, err)

	// Two more minutes and it is past its expiry.
	clock.Advance(2 * time.Minute)
	_, err = gen.Verify(t.Context(), raw)
	require.ErrorIs(t, err, token.ErrTokenInvalid)
}

// TestConsumerSuppliedKeySource pins that a key source a consumer wrote — the
// shape a KMS-backed or HSM-backed source takes — issues and verifies with no
// KeyManager involved, and that a source which cannot report its lifetimes
// simply gets no lifetime cap.
func TestConsumerSuppliedKeySource(t *testing.T) {
	t.Parallel()

	external := newExternalKeySource(t)
	require.NotImplements(t, (*signingkey.LifetimeReporter)(nil), external,
		"the point of this source is that it cannot report its lifetimes")

	// A reporting key source would refuse this lifetime; one that cannot
	// report has nothing to check it against.
	gen, err := token.NewGenerator(external, token.WithLifetime(30*24*time.Hour))
	require.NoError(t, err)

	raw, err := gen.Generate(t.Context(), "s-1", alice())
	require.NoError(t, err)
	assert.Equal(t, "consumer-owned-key-1", decodeHeader(t, raw)["kid"])

	ver, err := token.NewVerifier(token.VerifyWithKeySource(external))
	require.NoError(t, err)

	claims, err := ver.Verify(t.Context(), raw)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.Subject())

	// The algorithm is still pinned: this source holds no ES256 key.
	esGen, err := token.NewGenerator(external, token.WithSigningAlg(signingkey.ES256))
	require.NoError(t, err)

	_, err = esGen.Generate(t.Context(), "s-2", alice())
	require.Error(t, err)
}
