package token_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// Standalone: a table of its own: its rows vary the clock-driven options and assert against the key source, unlike TestGenerateRefusesRatherThanIssuingAnUnusableToken's.
func TestGenerateClaims(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		algs   []signingkey.Alg
		opts   func(clock *clockwork.FakeClock) []token.Option
		assert func(t *testing.T, keys *signingkey.Keys, raw string, err error)
	}

	cases := []testCase{
		{
			name: "the default token is RS256, lives 15 minutes and names the current key",
			opts: func(clock *clockwork.FakeClock) []token.Option {
				return []token.Option{
					token.WithIssuer("https://auth.example"),
					token.WithoutAudience(),
					token.WithClock(clock),
				}
			},
			assert: func(t *testing.T, keys *signingkey.Keys, raw string, err error) {
				require.NoError(t, err)

				header := decodeHeader(t, raw)
				assert.Equal(t, "RS256", header["alg"])

				wantKid, _, ok := keys.Signer(signingkey.RS256)
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
			opts: func(clock *clockwork.FakeClock) []token.Option {
				return []token.Option{
					token.WithoutIssuer(),
					token.WithoutAudience(),
					token.WithSigningAlg(signingkey.ES256),
					token.WithTokenLifetime(5 * time.Minute),
					token.WithClock(clock),
				}
			},
			assert: func(t *testing.T, keys *signingkey.Keys, raw string, err error) {
				require.NoError(t, err)

				header := decodeHeader(t, raw)
				assert.Equal(t, "ES256", header["alg"])

				wantKid, _, ok := keys.Signer(signingkey.ES256)
				require.True(t, ok)
				assert.Equal(t, wantKid, header["kid"])

				claims := decodeClaims(t, raw)
				assert.EqualValues(t, issuedAt.Add(5*time.Minute).Unix(), claims["exp"])
			},
		},
		{
			name: "a configured audience is carried",
			opts: func(clock *clockwork.FakeClock) []token.Option {
				return []token.Option{
					token.WithoutIssuer(),
					token.WithAudience("api"),
					token.WithClock(clock),
				}
			},
			assert: func(t *testing.T, _ *signingkey.Keys, raw string, err error) {
				require.NoError(t, err)
				assert.Contains(t, decodeClaims(t, raw)["aud"], "api")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t, tc.algs...)
			clock := clockwork.NewFakeClockAt(issuedAt)

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
// Standalone: it issues with one construction and verifies with a second, independently configured verifier.
func TestAudienceRoundTrip(t *testing.T) {
	t.Parallel()

	keys := newKeySource(t)

	gen, err := token.NewGenerator(keys, token.WithoutIssuer(), token.WithAudience("api"))
	require.NoError(t, err)

	raw, err := gen.Generate(t.Context(), "s-1", alice())
	require.NoError(t, err)

	ver, err := token.NewVerifier(
		token.WithVerifyKeySource(keys),
		token.WithVerifyAudience("api"),
		token.WithoutVerifyIssuer(),
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
			signingkey.WithKeyLifetime(24*time.Hour),
			signingkey.WithRotateInterval(time.Hour))
	}

	// consumerClockAt is the instant a consumer's own read-only clock reports,
	// for the "consumer clock" row below.
	consumerClockAt := time.Date(2030, 6, 15, 8, 30, 0, 0, time.UTC)

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
		opts   []token.Option
		assert func(t *testing.T, gen token.Generator, err error)
	}

	cases := []testCase{
		{
			name:   "no key source",
			keys:   func(_ *testing.T) signingkey.KeySource { return nil },
			assert: refused("key source"),
		},
		{
			// The classic wiring mistake: a constructor's error went
			// unchecked, or a field on a wiring struct was never set, so the
			// interface is not nil but the pointer inside it is. The
			// LifetimeReporter assertion succeeds on it, and the report is
			// then read off a nil receiver.
			name: "a typed-nil key source",
			keys: func(_ *testing.T) signingkey.KeySource {
				var missing *signingkey.Keys

				return missing
			},
			assert: refused("key source"),
		},
		{
			name:   "a nil clock",
			keys:   reporting,
			opts:   []token.Option{token.WithClock(nil)},
			assert: refused("clock"),
		},
		{
			// *clockwork.FakeClock implements Now through a pointer receiver, so
			// a nil one passed to WithClock is an interface holding a nil
			// pointer: `== nil` misses it, and only the reflect-based check the
			// constructor uses catches it before the first Generate reads from a
			// nil receiver.
			name:   "a typed-nil clock",
			keys:   reporting,
			opts:   []token.Option{token.WithClock((*clockwork.FakeClock)(nil))},
			assert: refused("clock"),
		},
		{
			// A Now-only consumer type: `time-source` "Read-only source for a
			// read-only component". Construction succeeds, and the generator
			// reads its time from the consumer's clock: iat comes back equal
			// to the fixed instant, not to the system clock's.
			name: "a consumer's own read-only clock is the generator's time source",
			keys: reporting,
			opts: []token.Option{token.WithClock(fixedClock{at: consumerClockAt})},
			assert: func(t *testing.T, gen token.Generator, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, gen)

				raw, genErr := gen.Generate(t.Context(), "s-consumer-clock", alice())
				require.NoError(t, genErr)
				assert.EqualValues(t, consumerClockAt.Unix(), decodeClaims(t, raw)["iat"],
					"the generator did not read the consumer's own clock")
			},
		},
		{
			// password, identity and signingkey all skip a nil option, and a
			// consumer building a slice of options conditionally leaves one
			// nil without thinking about it.
			name:   "a nil option is skipped",
			keys:   reporting,
			opts:   []token.Option{nil, token.WithTokenLifetime(time.Minute), nil},
			assert: constructed,
		},
		{
			name:   "an unknown signing algorithm",
			keys:   reporting,
			opts:   []token.Option{token.WithSigningAlg("RS256-but-misspelled")},
			assert: refused("unsupported signing algorithm"),
		},
		{
			// The JOSE stack knows the name "none" and resolves it, so
			// asking it whether an algorithm exists is the wrong question.
			// "no option enables unsigned tokens" has to rest on a rule this
			// package tests, not on what a dependency happens to refuse at
			// the first signature.
			name:   "none as the signing algorithm",
			keys:   reporting,
			opts:   []token.Option{token.WithSigningAlg("none")},
			assert: refused("unsupported signing algorithm"),
		},
		{
			// HS256 exists too, and it is symmetric: the verification key is
			// the signing key. This library's key sources cannot produce it.
			name:   "a symmetric signing algorithm",
			keys:   reporting,
			opts:   []token.Option{token.WithSigningAlg("HS256")},
			assert: refused("unsupported signing algorithm"),
		},
		{
			name:   "every algorithm the key sources can produce is accepted",
			keys:   reporting,
			opts:   []token.Option{token.WithSigningAlg(signingkey.ES256)},
			assert: constructed,
		},
		{
			name:   "a zero lifetime",
			keys:   reporting,
			opts:   []token.Option{token.WithTokenLifetime(0)},
			assert: refused("positive"),
		},
		{
			name:   "a negative lifetime",
			keys:   reporting,
			opts:   []token.Option{token.WithTokenLifetime(-time.Second)},
			assert: refused("positive"),
		},
		{
			// Expiry is recorded in whole seconds, so a fractional lifetime
			// would issue tokens that expire at an instant nobody asked for.
			name:   "a sub-second lifetime",
			keys:   reporting,
			opts:   []token.Option{token.WithTokenLifetime(500 * time.Millisecond)},
			assert: refused("whole number of seconds"),
		},
		{
			name:   "a lifetime that is not a whole number of seconds",
			keys:   reporting,
			opts:   []token.Option{token.WithTokenLifetime(1500 * time.Millisecond)},
			assert: refused("whole number of seconds"),
		},
		{
			name:   "a one-second lifetime is accepted",
			keys:   reporting,
			opts:   []token.Option{token.WithTokenLifetime(time.Second)},
			assert: constructed,
		},
		{
			name:   "a lifetime that outlives the key",
			keys:   reporting,
			opts:   []token.Option{token.WithTokenLifetime(24 * time.Hour)},
			assert: refused("outlive"),
		},
		{
			name:   "a lifetime one second past the usable window",
			keys:   reporting,
			opts:   []token.Option{token.WithTokenLifetime(23*time.Hour + time.Second)},
			assert: refused("outlive"),
		},
		{
			name:   "a lifetime exactly filling the usable window is accepted",
			keys:   reporting,
			opts:   []token.Option{token.WithTokenLifetime(23 * time.Hour)},
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

			// No row is about the issuer or the audience, so every row waives
			// both and is refused, or constructed, for its own reason alone.
			opts := append([]token.Option{token.WithoutIssuer(), token.WithoutAudience()}, tc.opts...)

			gen, err := token.NewGenerator(tc.keys(t), opts...)
			tc.assert(t, gen, err)
		})
	}
}

// TestGenerateRefusesRatherThanIssuingAnUnusableToken also pins the rule that
// no failure on the issue path is identifiable as ErrInvalid: that is the
// verdict on a token a caller presented, and a consumer who maps it to
// "credential refused" must not see it from a failed issue.
// Standalone: a table of its own: its rows vary the identifier and principal, and every row carries a shared refusal assertion.
func TestGenerateRefusesRatherThanIssuingAnUnusableToken(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		algs      []signingkey.Alg
		opts      []token.Option
		id        string
		principal func() *identity.Principal
		assert    func(t *testing.T, raw string, err error)
	}

	cases := []testCase{
		{
			name:      "no current key for the configured algorithm",
			opts:      []token.Option{token.WithSigningAlg(signingkey.EdDSA)},
			id:        "s-1",
			principal: alice,
			assert: func(t *testing.T, raw string, err error) {
				require.Error(t, err)
				assert.Empty(t, raw, "never an unsigned token")
				assert.Contains(t, err.Error(), "EdDSA")
			},
		},
		{
			name:      "no principal to name as subject",
			id:        "s-1",
			principal: func() *identity.Principal { return nil },
			assert: func(t *testing.T, raw string, err error) {
				require.ErrorIs(t, err, identity.ErrNoPrincipal)
				assert.Empty(t, raw)
			},
		},
		{
			// identity.Principal is a plain exported struct, so a store row
			// with a blank username reaches here as a non-nil principal that
			// names nobody. Issuing for it would put sub: "" in a valid
			// token, which Claims.Subject cannot tell from "no subject at
			// all", and a consumer comparing the subject to a row's username
			// would then match every blank-username row.
			name:      "a principal with no username to name as subject",
			id:        "s-1",
			principal: func() *identity.Principal { return &identity.Principal{ID: "u-1"} },
			assert: func(t *testing.T, raw string, err error) {
				require.ErrorIs(t, err, token.ErrNoSubject)
				assert.Empty(t, raw)
				assert.NotErrorIs(t, err, identity.ErrNoPrincipal,
					"there is a principal; what it lacks is a username")
			},
		},
		{
			// jti is the session identifier on the session path, and
			// Claims.ID reports the empty string both for a token that
			// carries none and for one carrying "".
			name:      "no token identifier to carry as jti",
			id:        "",
			principal: alice,
			assert: func(t *testing.T, raw string, err error) {
				require.ErrorIs(t, err, token.ErrNoTokenID)
				assert.Empty(t, raw)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// No row is about the issuer or the audience, so every row waives
			// both.
			opts := append([]token.Option{token.WithoutIssuer(), token.WithoutAudience()}, tc.opts...)

			gen, err := token.NewGenerator(newKeySource(t, tc.algs...), opts...)
			require.NoError(t, err)

			raw, err := gen.Generate(t.Context(), tc.id, tc.principal())
			tc.assert(t, raw, err)
			assert.NotErrorIs(t, err, token.ErrInvalid,
				"a failure to issue is not the verdict on a presented token")
		})
	}
}

// TestGeneratorVerifiesItsOwnTokens pins that one construction issues and
// verifies under the same key source, issuer, audience and clock, and that the
// clock really is the one both halves read.
// Standalone: it advances one clock across three verifications of a single token.
func TestGeneratorVerifiesItsOwnTokens(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := clockwork.NewFakeClockAt(issuedAt)

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
	require.ErrorIs(t, err, token.ErrInvalid)
}

// TestConsumerSuppliedKeySource pins that a key source a consumer wrote — the
// shape a KMS-backed or HSM-backed source takes — issues and verifies with no
// Keys involved, and that a source which cannot report its lifetimes
// simply gets no lifetime cap.
// Standalone: it issues and verifies through a hand-written consumer key source, then through a second generator on it.
func TestConsumerSuppliedKeySource(t *testing.T) {
	t.Parallel()

	external := newExternalKeySource(t)
	require.NotImplements(t, (*signingkey.LifetimeReporter)(nil), external,
		"the point of this source is that it cannot report its lifetimes")

	// A reporting key source would refuse this lifetime; one that cannot
	// report has nothing to check it against.
	gen, err := token.NewGenerator(external,
		token.WithoutIssuer(), token.WithoutAudience(),
		token.WithTokenLifetime(30*24*time.Hour))
	require.NoError(t, err)

	raw, err := gen.Generate(t.Context(), "s-1", alice())
	require.NoError(t, err)
	assert.Equal(t, "consumer-owned-key-1", decodeHeader(t, raw)["kid"])

	ver, err := token.NewVerifier(token.WithVerifyKeySource(external),
		token.WithoutVerifyIssuer(), token.WithoutVerifyAudience())
	require.NoError(t, err)

	claims, err := ver.Verify(t.Context(), raw)
	require.NoError(t, err)
	assert.Equal(t, "alice", claims.Subject())

	// The algorithm is still pinned: this source holds no ES256 key.
	esGen, err := token.NewGenerator(external,
		token.WithoutIssuer(), token.WithoutAudience(),
		token.WithSigningAlg(signingkey.ES256))
	require.NoError(t, err)

	_, err = esGen.Generate(t.Context(), "s-2", alice())
	require.Error(t, err)
}

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

func (s *failingSignerKeySource) Signer(alg signingkey.Alg) (string, crypto.Signer, bool) {
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
// Standalone: it issues through a key source whose signer fails, a source no other generator table builds.
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
				gen, err := token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience())
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
