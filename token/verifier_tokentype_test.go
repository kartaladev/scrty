package token_test

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	typedIssuer   = "https://auth.example"
	typedAudience = "api"
)

// signWithHeader signs valid claims, with typedIssuer and typedAudience, under
// the key source's current RS256 key and exactly the header members given besides
// alg and kid. It is written out by hand, with no JOSE library, because the point
// of these tokens is a header a library would refuse to build or would complete
// by itself: one with no typ at all, or one whose typ is not a string.
func signWithHeader(t *testing.T, keys signingkey.KeySource, members map[string]any) string {
	t.Helper()

	kid, signer, err := keys.Signer(t.Context(), signingkey.RS256)
	require.NoError(t, err)

	header := map[string]any{"alg": "RS256", "kid": kid}
	for name, value := range members {
		header[name] = value
	}

	claims := validClaims(time.Now())
	claims["iss"] = typedIssuer
	claims["aud"] = typedAudience

	input := encodeSegment(t, header) + "." + encodeSegment(t, claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// withTyp signs a token declaring typ, under the same keys, issuer and audience
// every row of TestVerifier_TokenType verifies with.
func withTyp(typ any) func(t *testing.T, keys signingkey.KeySource) string {
	return func(t *testing.T, keys signingkey.KeySource) string {
		t.Helper()

		return signWithHeader(t, keys, map[string]any{"typ": typ})
	}
}

// TestVerifier_TokenType pins that a verifier accepts only the type it is for.
// Every token differs from the others only in its header: the keys, the issuer
// and the audience all match, so a row accepted or refused was decided by typ.
func TestVerifier_TokenType(t *testing.T) {
	t.Parallel()

	refusedAsConfig := func(t *testing.T, claims *token.Claims, err error) {
		t.Helper()

		require.ErrorIs(t, err, token.ErrConfig)
		assert.Nil(t, claims)
	}

	type testCase struct {
		name   string
		opts   []token.VerifyOption
		token  func(t *testing.T, keys signingkey.KeySource) string
		assert func(t *testing.T, claims *token.Claims, err error)
	}

	atVerifier := []token.VerifyOption{token.WithVerifyTokenType(token.TypeAccessToken)}

	cases := []testCase{
		{name: "the first-party type is accepted", token: withTyp("scrty+jwt"), assert: accepted},
		{name: "the type is compared without regard to case", token: withTyp("SCRTY+JWT"), assert: accepted},
		{name: "the media-type prefix is ignored", token: withTyp("application/SCRTY+JWT"), assert: accepted},
		{
			name: "no typ is refused",
			token: func(t *testing.T, keys signingkey.KeySource) string {
				t.Helper()

				return signWithHeader(t, keys, nil)
			},
			assert: rejected,
		},
		// The token-type confusion test: an access token with the first-party
		// verifier's own keys, issuer and audience.
		{name: "an access token is refused", token: withTyp("at+jwt"), assert: rejected},
		{name: "an ID token is refused", token: withTyp("JWT"), assert: rejected},
		{name: "a logout token is refused", token: withTyp("logout+jwt"), assert: rejected},
		{name: "an empty typ is refused", token: withTyp(""), assert: rejected},
		{name: "a typ that is not a string is refused", token: withTyp(42), assert: rejected},
		{name: "a dotted capital I does not fold to i", token: withTyp("applİcatİon/scrty+jwt"), assert: rejected},
		{
			name:   "a Kelvin sign does not fold to k",
			opts:   []token.VerifyOption{token.WithVerifyTokenType("kyc+jwt")},
			token:  withTyp("\u212Ayc+jwt"),
			assert: rejected,
		},
		{
			name:  "a refusal renders no presented value",
			token: withTyp("secret-looking-type"),
			assert: func(t *testing.T, claims *token.Claims, err error) {
				t.Helper()

				rejected(t, claims, err)
				assert.NotContains(t, err.Error(), "secret-looking-type")
			},
		},
		{name: "the prefix is ignored only once", token: withTyp("application/application/scrty+jwt"), assert: rejected},
		{
			name: "a member spelled TYP is not typ",
			token: func(t *testing.T, keys signingkey.KeySource) string {
				t.Helper()

				return signWithHeader(t, keys, map[string]any{"TYP": "scrty+jwt"})
			},
			assert: rejected,
		},
		{
			name:   "a verifier for access tokens accepts one with the prefix",
			opts:   atVerifier,
			token:  withTyp("application/at+jwt"),
			assert: accepted,
		},
		{
			name:   "a verifier for access tokens refuses a first-party token",
			opts:   atVerifier,
			token:  withTyp("scrty+jwt"),
			assert: rejected,
		},
		{
			name:   "the configured type is compared in the same form",
			opts:   []token.VerifyOption{token.WithVerifyTokenType("Application/AT+JWT")},
			token:  withTyp("at+jwt"),
			assert: accepted,
		},
		{
			name:   "no value stands for any type",
			opts:   []token.VerifyOption{token.WithVerifyTokenType("*")},
			token:  withTyp("at+jwt"),
			assert: rejected,
		},
		{name: "an empty configured type is refused", opts: []token.VerifyOption{token.WithVerifyTokenType("")}, assert: refusedAsConfig},
		{name: "a blank configured type is refused", opts: []token.VerifyOption{token.WithVerifyTokenType(" ")}, assert: refusedAsConfig},
		{
			name:   "the prefix alone as a configured type is refused",
			opts:   []token.VerifyOption{token.WithVerifyTokenType("application/")},
			assert: refusedAsConfig,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)
			verifier, err := token.NewVerifier(append([]token.VerifyOption{
				token.WithVerifyKeySource(keys),
				token.WithVerifyIssuer(typedIssuer),
				token.WithVerifyAudience(typedAudience),
			}, tc.opts...)...)
			if err != nil {
				tc.assert(t, nil, err)

				return
			}

			claims, err := verifier.Verify(t.Context(), tc.token(t, keys))
			tc.assert(t, claims, err)
		})
	}
}

// TestGenerator_VerifiesItsOwnType pins that a generator verifies under the type
// it issues under, and that the type separates two generators sharing keys.
func TestGenerator_VerifiesItsOwnType(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		issuer []token.Option
		judge  []token.Option
		assert func(t *testing.T, claims *token.Claims, err error)
	}

	appType := []token.Option{token.WithTokenType("app+jwt")}

	cases := []testCase{
		{name: "the default verifies its own", assert: accepted},
		{name: "a consumer's type verifies its own", issuer: appType, judge: appType, assert: accepted},
		{name: "the default refuses a consumer's type", issuer: appType, assert: rejected},
		{name: "a consumer's type refuses the default", judge: appType, assert: rejected},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)
			build := func(opts []token.Option) *token.JWTGenerator {
				gen, err := token.NewGenerator(keys, append([]token.Option{
					token.WithoutIssuer(), token.WithoutAudience(),
				}, opts...)...)
				require.NoError(t, err)

				return gen
			}

			raw, err := build(tc.issuer).Generate(t.Context(), "s-1", alice())
			require.NoError(t, err)

			claims, err := build(tc.judge).Verify(t.Context(), raw)
			tc.assert(t, claims, err)
		})
	}
}
