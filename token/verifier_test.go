package token_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/token"
)

// TestNewVerifierValidation pins that every wiring mistake is refused at
// construction, identifiably and without matching message text, rather than
// surfacing at the first request.
func TestNewVerifierValidation(t *testing.T) {
	t.Parallel()

	refused := func(mentions string) func(*testing.T, token.Verifier, error) {
		return func(t *testing.T, ver token.Verifier, err error) {
			t.Helper()

			require.ErrorIs(t, err, token.ErrConfig)
			assert.Nil(t, ver, "a refused configuration yields no verifier")
			assert.Contains(t, err.Error(), mentions)
		}
	}
	constructed := func(t *testing.T, ver token.Verifier, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, ver)
	}

	type testCase struct {
		name   string
		opts   func(t *testing.T) []token.VerifyOption
		assert func(t *testing.T, ver token.Verifier, err error)
	}

	withKeys := func(opts ...token.VerifyOption) func(*testing.T) []token.VerifyOption {
		return func(t *testing.T) []token.VerifyOption {
			t.Helper()

			return append([]token.VerifyOption{token.VerifyWithKeySource(newKeySource(t))}, opts...)
		}
	}

	cases := []testCase{
		{
			name:   "no key source",
			opts:   func(_ *testing.T) []token.VerifyOption { return nil },
			assert: refused("key source"),
		},
		{
			// A non-nil interface holding a nil pointer: the plain nil check
			// lets it through, and it reaches the JOSE stack at the first
			// request instead of failing at wiring time.
			name: "a typed-nil key source",
			opts: func(_ *testing.T) []token.VerifyOption {
				var missing *signingkey.KeyManager

				return []token.VerifyOption{token.VerifyWithKeySource(missing)}
			},
			assert: refused("key source"),
		},
		{
			name:   "a nil clock",
			opts:   withKeys(token.VerifyWithClock(nil)),
			assert: refused("clock"),
		},
		{
			name: "a typed-nil clock",
			opts: func(t *testing.T) []token.VerifyOption {
				t.Helper()

				var missing *fixedClock

				return withKeys(token.VerifyWithClock(missing))(t)
			},
			assert: refused("clock"),
		},
		{
			name:   "a zero maximum token size",
			opts:   withKeys(token.VerifyWithMaxTokenSize(0)),
			assert: refused("maximum token size"),
		},
		{
			name:   "a negative maximum token size",
			opts:   withKeys(token.VerifyWithMaxTokenSize(-1)),
			assert: refused("maximum token size"),
		},
		{
			name:   "a nil option is skipped",
			opts:   withKeys(nil, token.VerifyWithIssuer("https://auth.example"), nil),
			assert: constructed,
		},
		{
			name:   "a key source alone is enough",
			opts:   withKeys(),
			assert: constructed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ver, err := token.NewVerifier(tc.opts(t)...)
			tc.assert(t, ver, err)
		})
	}
}

func TestVerifyKeySelection(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		token  func(t *testing.T, keys *signingkey.KeyManager) string
		assert func(t *testing.T, claims *token.Claims, err error)
	}

	cases := []testCase{
		{
			name: "a token this key source did not sign",
			token: func(t *testing.T, _ *signingkey.KeyManager) string {
				other, err := token.NewGenerator(newKeySource(t))
				require.NoError(t, err)

				raw, err := other.Generate(t.Context(), "s-1", alice())
				require.NoError(t, err)

				return raw
			},
			assert: rejected,
		},
		{
			name: "no key identifier in the header",
			token: func(t *testing.T, keys *signingkey.KeyManager) string {
				_, signer, ok := keys.GetSigner(signingkey.RS256)
				require.True(t, ok)

				return signRaw(t, signer, "", signingkey.RS256, validClaims(time.Now()))
			},
			assert: rejected,
		},
		{
			name: "a key identifier that is not in the set",
			token: func(t *testing.T, keys *signingkey.KeyManager) string {
				_, signer, ok := keys.GetSigner(signingkey.RS256)
				require.True(t, ok)

				return signRaw(t, signer, "not-a-kid-in-the-set", signingkey.RS256, validClaims(time.Now()))
			},
			assert: rejected,
		},
		{
			name: "the same claims named by the current key are accepted",
			token: func(t *testing.T, keys *signingkey.KeyManager) string {
				return signClaims(t, keys, validClaims(time.Now()))
			},
			assert: func(t *testing.T, claims *token.Claims, err error) {
				require.NoError(t, err)
				require.NotNil(t, claims)
				assert.Equal(t, "alice", claims.Subject())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)

			ver, err := token.NewVerifier(token.VerifyWithKeySource(keys))
			require.NoError(t, err)

			claims, err := ver.Verify(t.Context(), tc.token(t, keys))
			tc.assert(t, claims, err)
		})
	}
}

// TestVerifyAlgorithmPinning covers the two classic verifier bypasses. Both
// tokens are built by hand: asking the library to produce them would test its
// refusal to create a forgery rather than this package's refusal to accept one.
// If either row ever passes, verification is accepting a forged token.
func TestVerifyAlgorithmPinning(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		token func(t *testing.T, keys *signingkey.KeyManager) string
	}

	cases := []testCase{
		{
			name: "alg none with an empty signature",
			token: func(t *testing.T, keys *signingkey.KeyManager) string {
				kid, _, ok := keys.GetSigner(signingkey.RS256)
				require.True(t, ok)

				header := encodeSegment(t, map[string]any{"alg": "none", "typ": "JWT", "kid": kid})
				claims := encodeSegment(t, validClaims(time.Now()))

				// An empty third segment: no signature at all.
				return header + "." + claims + "."
			},
		},
		{
			name: "HS256 over an RS256 key, signed with that key's public half as the secret",
			token: func(t *testing.T, keys *signingkey.KeyManager) string {
				kid, signer, ok := keys.GetSigner(signingkey.RS256)
				require.True(t, ok)

				// The attacker knows the public key: it is published in the
				// JWK Set. Using it as an HMAC secret is the algorithm
				// confusion attack.
				public, err := x509.MarshalPKIXPublicKey(signer.Public())
				require.NoError(t, err)

				header := encodeSegment(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": kid})
				claims := encodeSegment(t, validClaims(time.Now()))

				mac := hmac.New(sha256.New, public)
				_, err = mac.Write([]byte(header + "." + claims))
				require.NoError(t, err)

				return header + "." + claims + "." +
					base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			},
		},
		{
			name: "one payload character changed on a validly signed token",
			token: func(t *testing.T, keys *signingkey.KeyManager) string {
				return tamperPayload(t, signClaims(t, keys, validClaims(time.Now())))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)

			ver, err := token.NewVerifier(token.VerifyWithKeySource(keys))
			require.NoError(t, err)

			claims, err := ver.Verify(t.Context(), tc.token(t, keys))
			require.ErrorIs(t, err, token.ErrTokenInvalid)
			assert.Nil(t, claims)
		})
	}
}

func TestVerifyTimeChecks(t *testing.T) {
	t.Parallel()

	base := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	expiry := base.Add(15 * time.Minute)

	type testCase struct {
		name     string
		claims   map[string]any
		verifyAt time.Time
		assert   func(t *testing.T, claims *token.Claims, err error)
	}

	accepted := func(t *testing.T, claims *token.Claims, err error) {
		require.NoError(t, err)
		assert.NotNil(t, claims)
	}
	cases := []testCase{
		{
			name:     "a token with no exp is rejected",
			claims:   map[string]any{"sub": "alice", "jti": "s-1"},
			verifyAt: base,
			assert:   rejected,
		},
		{
			name:     "one second before exp is accepted",
			claims:   map[string]any{"sub": "alice", "jti": "s-1", "exp": expiry.Unix()},
			verifyAt: expiry.Add(-time.Second),
			assert:   accepted,
		},
		{
			name:     "one second after exp is rejected, so no skew is tolerated",
			claims:   map[string]any{"sub": "alice", "jti": "s-1", "exp": expiry.Unix()},
			verifyAt: expiry.Add(time.Second),
			assert:   rejected,
		},
		{
			// At one-second resolution a sub-second tolerance is invisible:
			// the row above passes whether or not half a second of skew is
			// allowed. Expiry is exclusive, so the instant named by exp is
			// already too late, and any tolerance at all shows up here.
			name:     "the instant named by exp is already rejected, so not even sub-second skew is tolerated",
			claims:   map[string]any{"sub": "alice", "jti": "s-1", "exp": expiry.Unix()},
			verifyAt: expiry,
			assert:   rejected,
		},
		{
			name: "an iat in the future is rejected",
			claims: map[string]any{
				"sub": "alice", "jti": "s-1",
				"iat": base.Add(time.Minute).Unix(),
				"exp": base.Add(time.Hour).Unix(),
			},
			verifyAt: base,
			assert:   rejected,
		},
		{
			name: "an nbf in the future is rejected",
			claims: map[string]any{
				"sub": "alice", "jti": "s-1",
				"nbf": base.Add(time.Minute).Unix(),
				"exp": base.Add(time.Hour).Unix(),
			},
			verifyAt: base,
			assert:   rejected,
		},
		{
			name: "an iat and nbf already past are accepted",
			claims: map[string]any{
				"sub": "alice", "jti": "s-1",
				"iat": base.Add(-time.Minute).Unix(),
				"nbf": base.Add(-time.Minute).Unix(),
				"exp": base.Add(time.Hour).Unix(),
			},
			verifyAt: base,
			assert:   accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)
			raw := signClaims(t, keys, tc.claims)

			ver, err := token.NewVerifier(
				token.VerifyWithKeySource(keys),
				token.VerifyWithClock(&fixedClock{now: tc.verifyAt}),
			)
			require.NoError(t, err)

			claims, err := ver.Verify(t.Context(), raw)
			tc.assert(t, claims, err)
		})
	}
}

// TestVerifyClaimEnforcement pins that iss and aud are enforced exactly when
// the consumer configured them — never because the configured value happens to
// be non-empty, and never when nothing was configured.
//
// Issuer and audience share the whole call shape, so they share one table:
// kept apart, each gained rows the other lacked and neither absence was
// visible.
func TestVerifyClaimEnforcement(t *testing.T) {
	t.Parallel()

	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

	const (
		mine  = "https://auth.example"
		other = "https://evil.example"
	)

	type testCase struct {
		name       string
		claim      string
		value      any // nil means the token does not carry the claim
		configured []token.VerifyOption
		assert     func(t *testing.T, claims *token.Claims, err error)
	}

	cases := []testCase{
		{
			name:       "a configured issuer that matches is accepted",
			claim:      "iss",
			value:      mine,
			configured: []token.VerifyOption{token.VerifyWithIssuer(mine)},
			assert:     accepted,
		},
		{
			name:       "a configured issuer that differs is rejected",
			claim:      "iss",
			value:      other,
			configured: []token.VerifyOption{token.VerifyWithIssuer(mine)},
			assert:     rejected,
		},
		{
			name:       "a configured issuer that is absent is rejected",
			claim:      "iss",
			value:      nil,
			configured: []token.VerifyOption{token.VerifyWithIssuer(mine)},
			assert:     rejected,
		},
		{
			name:       "an issuer configured as the empty string is still enforced",
			claim:      "iss",
			value:      mine,
			configured: []token.VerifyOption{token.VerifyWithIssuer("")},
			assert:     rejected,
		},
		{
			name:   "an unconfigured issuer does not reject another issuer",
			claim:  "iss",
			value:  "https://other.example",
			assert: accepted,
		},
		{
			name:   "an unconfigured issuer does not reject an absent one",
			claim:  "iss",
			value:  nil,
			assert: accepted,
		},
		{
			name:       "a configured audience that matches is accepted",
			claim:      "aud",
			value:      []any{"api"},
			configured: []token.VerifyOption{token.VerifyWithAudience("api")},
			assert:     accepted,
		},
		{
			name:       "a configured audience that differs is rejected",
			claim:      "aud",
			value:      []any{"admin"},
			configured: []token.VerifyOption{token.VerifyWithAudience("api")},
			assert:     rejected,
		},
		{
			name:       "a configured audience that is absent is rejected",
			claim:      "aud",
			value:      nil,
			configured: []token.VerifyOption{token.VerifyWithAudience("api")},
			assert:     rejected,
		},
		{
			name:       "a configured audience present among several is accepted",
			claim:      "aud",
			value:      []any{"admin", "api"},
			configured: []token.VerifyOption{token.VerifyWithAudience("api")},
			assert:     accepted,
		},
		{
			name:       "an audience configured as the empty string is still enforced",
			claim:      "aud",
			value:      []any{"api"},
			configured: []token.VerifyOption{token.VerifyWithAudience("")},
			assert:     rejected,
		},
		{
			name:   "an unconfigured audience does not reject an audience",
			claim:  "aud",
			value:  []any{"api"},
			assert: accepted,
		},
		{
			name:   "an unconfigured audience does not reject an absent one",
			claim:  "aud",
			value:  nil,
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)
			claims := validClaims(at)
			if tc.value != nil {
				claims[tc.claim] = tc.value
			}
			raw := signClaims(t, keys, claims)

			opts := append([]token.VerifyOption{
				token.VerifyWithKeySource(keys),
				token.VerifyWithClock(&fixedClock{now: at}),
			}, tc.configured...)

			ver, err := token.NewVerifier(opts...)
			require.NoError(t, err)

			got, err := ver.Verify(t.Context(), raw)
			tc.assert(t, got, err)
		})
	}
}

// TestVerifyErrorClassification separates a refused token from a failure to
// perform the check at all. Conflating them makes an outage look like an
// authentication failure, so the second and third rows assert the negative.
func TestVerifyErrorClassification(t *testing.T) {
	t.Parallel()

	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	unreachable := errors.New("key service unreachable")

	type testCase struct {
		name   string
		keys   func(t *testing.T) signingkey.KeySource
		token  func(t *testing.T, keys signingkey.KeySource) string
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, claims *token.Claims, err error)
	}

	cases := []testCase{
		{
			name: "an expired token is ErrTokenInvalid and keeps the expiry cause",
			keys: func(t *testing.T) signingkey.KeySource { return newKeySource(t) },
			token: func(t *testing.T, keys signingkey.KeySource) string {
				return signClaims(t, keys, map[string]any{
					"sub": "alice", "jti": "s-1",
					"exp": at.Add(-time.Minute).Unix(),
				})
			},
			assert: func(t *testing.T, claims *token.Claims, err error) {
				require.ErrorIs(t, err, token.ErrTokenInvalid)
				assert.Nil(t, claims)
				assert.ErrorIs(t, err, jwt.TokenExpiredError{},
					"the specific cause survives the wrap")
			},
		},
		{
			name: "a key source that cannot supply its key set is not ErrTokenInvalid",
			keys: func(t *testing.T) signingkey.KeySource {
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys().Return(nil, unreachable).Times(1)

				return keys
			},
			token: func(_ *testing.T, _ signingkey.KeySource) string { return "any.token.here" },
			assert: func(t *testing.T, claims *token.Claims, err error) {
				require.ErrorIs(t, err, unreachable)
				assert.Nil(t, claims)
				assert.NotErrorIs(t, err, token.ErrTokenInvalid,
					"an unavailable key set is not a refused token")
			},
		},
		{
			name: "a key source that hands over no keys at all is not ErrTokenInvalid",
			keys: func(t *testing.T) signingkey.KeySource {
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys().Return(nil, nil).Times(1)

				return keys
			},
			token: func(t *testing.T, _ signingkey.KeySource) string {
				return signClaims(t, newKeySource(t), validClaims(at))
			},
			assert: func(t *testing.T, claims *token.Claims, err error) {
				require.Error(t, err)
				assert.Nil(t, claims)
				assert.NotErrorIs(t, err, token.ErrTokenInvalid,
					"a source that supplied no keys has not judged the token")
			},
		},
		{
			name: "a key source holding no keys at all is not ErrTokenInvalid",
			keys: func(t *testing.T) signingkey.KeySource {
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys().Return([]signingkey.PublicKey{}, nil).Times(1)

				return keys
			},
			token: func(t *testing.T, _ signingkey.KeySource) string {
				return signClaims(t, newKeySource(t), validClaims(at))
			},
			assert: func(t *testing.T, claims *token.Claims, err error) {
				require.Error(t, err)
				assert.Nil(t, claims)
				assert.NotErrorIs(t, err, token.ErrTokenInvalid,
					"with nothing to check against, the verifier has reached no verdict")
			},
		},
		{
			name: "a key this package cannot read is an outage, not a token checked against the rest",
			keys: func(t *testing.T) signingkey.KeySource {
				signing := newKeySource(t)
				published, err := signing.VerificationKeys()
				require.NoError(t, err)

				// A source of the consumer's own hands over whatever a
				// crypto.PublicKey can hold, and this package can read only
				// some of that. The key that actually signed is published
				// alongside the unreadable one on purpose: a verifier that
				// quietly drops what it cannot read would still hold the
				// signing key, and would answer as though nothing were wrong.
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().GetSigner(gomock.Any()).DoAndReturn(signing.GetSigner).AnyTimes()
				keys.EXPECT().VerificationKeys().Return(append(
					[]signingkey.PublicKey{{
						Kid: "unreadable-1",
						Alg: signingkey.RS256,
						Key: "not a key at all",
					}},
					published...,
				), nil).AnyTimes()

				return keys
			},
			token: func(t *testing.T, keys signingkey.KeySource) string {
				return signClaims(t, keys, validClaims(at))
			},
			assert: func(t *testing.T, claims *token.Claims, err error) {
				require.Error(t, err)
				assert.Nil(t, claims)
				assert.NotErrorIs(t, err, token.ErrTokenInvalid,
					"a source supplying a key this package cannot read has not judged the token")
			},
		},
		{
			name: "a cancelled context is not ErrTokenInvalid",
			keys: func(t *testing.T) signingkey.KeySource { return newKeySource(t) },
			token: func(t *testing.T, keys signingkey.KeySource) string {
				return signClaims(t, keys, validClaims(at))
			},
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				return cancelled
			},
			assert: func(t *testing.T, claims *token.Claims, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, claims)
				assert.NotErrorIs(t, err, token.ErrTokenInvalid,
					"a check that never ran cannot conclude the token is invalid")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := tc.keys(t)

			ver, err := token.NewVerifier(
				token.VerifyWithKeySource(keys),
				token.VerifyWithClock(&fixedClock{now: at}),
			)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			claims, err := ver.Verify(ctx, tc.token(t, keys))
			tc.assert(t, claims, err)
		})
	}
}

// TestVerifyRejectsNonCanonicalEncoding pins that one issued token has exactly
// one presentation that verifies. jwt.Parse is lenient: it trims surrounding
// whitespace and rebuilds the signing input from the decoded segments, so
// base64 padding, the standard +/ alphabet and stray Unicode space all survive
// it. A consumer keying a revocation list, a replay cache, an idempotency
// record or a rate-limit bucket on the presented string would then fail to
// recognise a re-encoded presentation of a token it has already seen and
// refused.
//
// Every row is the issued token as far as the JOSE stack is concerned — the
// shared body proves that first — so a row rejected below is rejected for its
// encoding alone and the rejections are not vacuous.
func TestVerifyRejectsNonCanonicalEncoding(t *testing.T) {
	t.Parallel()

	recode := func(t *testing.T, segment string, enc *base64.Encoding) string {
		t.Helper()

		raw, err := base64.RawURLEncoding.DecodeString(segment)
		require.NoError(t, err)

		return enc.EncodeToString(raw)
	}
	// rebuild presents the token with one segment re-encoded under enc.
	rebuild := func(index int, enc *base64.Encoding) func(*testing.T, string) string {
		return func(t *testing.T, issued string) string {
			t.Helper()

			parts := strings.Split(issued, ".")
			require.Len(t, parts, 3)
			parts[index] = recode(t, parts[index], enc)

			return strings.Join(parts, ".")
		}
	}
	surround := func(prefix, suffix string) func(*testing.T, string) string {
		return func(_ *testing.T, issued string) string { return prefix + issued + suffix }
	}

	type testCase struct {
		name      string
		present   func(t *testing.T, issued string) string
		canonical bool // the row presents the issued string unchanged
		assert    func(t *testing.T, claims *token.Claims, err error)
	}

	cases := []testCase{
		{
			name:      "the issued string itself",
			present:   func(_ *testing.T, issued string) string { return issued },
			canonical: true,
			assert:    accepted,
		},
		{
			name:    "base64 padding on the header",
			present: rebuild(0, base64.URLEncoding),
			assert:  rejected,
		},
		{
			name:    "base64 padding on the payload",
			present: rebuild(1, base64.URLEncoding),
			assert:  rejected,
		},
		{
			name:    "base64 padding on the signature",
			present: rebuild(2, base64.URLEncoding),
			assert:  rejected,
		},
		{
			name:    "the standard base64 alphabet on the signature",
			present: rebuild(2, base64.StdEncoding),
			assert:  rejected,
		},
		{
			name:    "a trailing newline",
			present: surround("", "\n"),
			assert:  rejected,
		},
		{
			name:    "leading and trailing ASCII whitespace",
			present: surround(" \t", "\r\n"),
			assert:  rejected,
		},
		{
			name:    "a trailing no-break space",
			present: surround("", " "),
			assert:  rejected,
		},
		{
			name:    "a trailing ideographic space",
			present: surround("", "　"),
			assert:  rejected,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)
			set := verificationKeySet(t, keys)

			issued := signClaims(t, keys, validClaims(time.Now()))
			presented := tc.present(t, issued)
			if tc.canonical {
				require.Equal(t, issued, presented, "a canonical row presents the issued string unchanged")
			} else {
				require.NotEqual(t, issued, presented, "a non-canonical row must really differ")
			}

			// Provenance: a verifier that only pins the key set accepts this
			// exact string, so it carries the issued token's claims and its
			// valid signature. Rejecting it is a deliberate strictness.
			_, naive := jwt.Parse([]byte(presented),
				jwt.WithKeySet(set), jwt.WithRequiredClaim(jwt.ExpirationKey))
			require.NoError(t, naive,
				"the presentation must be one a naive verifier accepts, or its rejection proves nothing")

			ver, err := token.NewVerifier(token.VerifyWithKeySource(keys))
			require.NoError(t, err)

			claims, err := ver.Verify(t.Context(), presented)
			tc.assert(t, claims, err)
		})
	}
}

// TestVerifyBoundsTheInputItAccepts pins that an unauthenticated string cannot
// buy unbounded work. jws.Parse base64-decodes all three segments before any
// signature is checked, so without a ceiling a single request allocates
// several times the bytes it sent.
//
// The oversized token is genuine: the row that raises the ceiling verifies
// that exact string, so the default's refusal is about its size and nothing
// else.
func TestVerifyBoundsTheInputItAccepts(t *testing.T) {
	t.Parallel()

	signing := newKeySource(t)

	padded := validClaims(time.Now())
	padded["pad"] = strings.Repeat("x", 12<<10)
	oversized := signClaims(t, signing, padded)
	require.Greater(t, len(oversized), 8<<10, "the token must exceed the default ceiling")

	type testCase struct {
		name   string
		keys   func(t *testing.T) signingkey.KeySource
		opts   []token.VerifyOption
		assert func(t *testing.T, claims *token.Claims, err error)
	}

	cases := []testCase{
		{
			name:   "the default ceiling refuses it",
			keys:   func(_ *testing.T) signingkey.KeySource { return signing },
			assert: rejected,
		},
		{
			name: "a consumer raises the ceiling and the same string verifies",
			keys: func(_ *testing.T) signingkey.KeySource { return signing },
			opts: []token.VerifyOption{token.VerifyWithMaxTokenSize(64 << 10)},
			assert: func(t *testing.T, claims *token.Claims, err error) {
				require.NoError(t, err)
				require.NotNil(t, claims)
				assert.Equal(t, "alice", claims.Subject())
			},
		},
		{
			name: "the refusal costs no key lookup",
			keys: func(t *testing.T) signingkey.KeySource {
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys().Times(0)

				return keys
			},
			assert: rejected,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ver, err := token.NewVerifier(
				append([]token.VerifyOption{token.VerifyWithKeySource(tc.keys(t))}, tc.opts...)...)
			require.NoError(t, err)

			claims, err := ver.Verify(t.Context(), oversized)
			tc.assert(t, claims, err)
		})
	}
}

// TestVerifyTimeChecksResistProcessGlobalJWXSettings pins that the time checks
// this package documents as unrelaxable are not in fact relaxable by any other
// package in the consumer's binary.
//
// jwx rounds both operands of every time comparison by a process-global
// truncation that jwt.Settings writes, so a transitive dependency's init could
// widen it and make an nbf or iat far in the future acceptable. This
// verification path pins its own truncation, so the setting has no effect
// here.
//
// It mutates process-global state and therefore never runs in parallel.
func TestVerifyTimeChecksResistProcessGlobalJWXSettings(t *testing.T) {
	at := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	keys := newKeySource(t)

	// nbf and iat 50 minutes ahead; exp far enough out that expiry plays no
	// part in the verdict.
	raw := signClaims(t, keys, map[string]any{
		"sub": "alice", "jti": "s-1",
		"nbf": at.Add(50 * time.Minute).Unix(),
		"iat": at.Add(50 * time.Minute).Unix(),
		"exp": at.Add(24 * time.Hour).Unix(),
	})

	ver, err := token.NewVerifier(
		token.VerifyWithKeySource(keys),
		token.VerifyWithClock(&fixedClock{now: at}),
	)
	require.NoError(t, err)

	// Provenance: the token is well formed and validly signed, and only its
	// nbf and iat stand between it and acceptance — an hour on, the same
	// string verifies.
	later, err := token.NewVerifier(
		token.VerifyWithKeySource(keys),
		token.VerifyWithClock(&fixedClock{now: at.Add(time.Hour)}),
	)
	require.NoError(t, err)
	claims, err := later.Verify(t.Context(), raw)
	accepted(t, claims, err)

	claims, err = ver.Verify(t.Context(), raw)
	rejected(t, claims, err)

	// Any package in the consumer's binary can do this, including a
	// dependency's init, which no consumer of this library ever sees.
	require.NoError(t, jwt.Settings(jwt.WithTruncation(time.Hour)))
	t.Cleanup(func() { require.NoError(t, jwt.Settings(jwt.WithTruncation(0))) })

	claims, err = ver.Verify(t.Context(), raw)
	rejected(t, claims, err)
}
