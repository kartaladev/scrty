package token_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/signingkey"
	"github.com/kartaladev/scrty/token"
)

func TestNewVerifierRequiresKeySource(t *testing.T) {
	t.Parallel()

	ver, err := token.NewVerifier()
	require.Error(t, err)
	assert.Nil(t, ver)
	assert.Contains(t, err.Error(), "key source")
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
				keys.EXPECT().JWKS().Return(nil, unreachable).Times(1)

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
