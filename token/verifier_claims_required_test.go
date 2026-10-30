package token_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token"
)

// TestNewVerifierRequiresIssuerAndAudience pins that a verifier checks the
// issuer and the audience of every token unless the consumer waives each check
// by name: a verifier given neither the claim nor its waiver, or both, is a
// wiring mistake refused at construction. Two services that share a key source
// then cannot accept each other's tokens by default.
func TestNewVerifierRequiresIssuerAndAudience(t *testing.T) {
	t.Parallel()

	const issuer = "https://auth.example"

	type testCase struct {
		name string
		// generate is the generator's configuration for the token the verifier
		// is handed.
		generate []token.Option
		verify   []token.VerifyOption
		assert   func(t *testing.T, claims *token.Claims, err error)
	}

	refusedAtConstruction := func(t *testing.T, claims *token.Claims, err error) {
		t.Helper()

		require.ErrorIs(t, err, token.ErrConfig)
		assert.NotErrorIs(t, err, token.ErrInvalid)
		assert.Nil(t, claims)
	}

	cases := []testCase{
		{
			name:     "neither issuer nor waiver",
			generate: []token.Option{token.WithIssuer(issuer), token.WithAudience("api")},
			verify:   []token.VerifyOption{token.WithVerifyAudience("api")},
			assert:   refusedAtConstruction,
		},
		{
			name:     "neither audience nor waiver",
			generate: []token.Option{token.WithIssuer(issuer), token.WithAudience("api")},
			verify:   []token.VerifyOption{token.WithVerifyIssuer(issuer)},
			assert:   refusedAtConstruction,
		},
		{
			name:     "issuer and its waiver",
			generate: []token.Option{token.WithIssuer(issuer), token.WithAudience("api")},
			verify: []token.VerifyOption{
				token.WithVerifyIssuer(issuer), token.WithoutVerifyIssuer(),
				token.WithVerifyAudience("api"),
			},
			assert: refusedAtConstruction,
		},
		{
			name:     "audience and its waiver",
			generate: []token.Option{token.WithIssuer(issuer), token.WithAudience("api")},
			verify: []token.VerifyOption{
				token.WithVerifyIssuer(issuer),
				token.WithVerifyAudience("api"), token.WithoutVerifyAudience(),
			},
			assert: refusedAtConstruction,
		},
		{
			name:     "an empty issuer is not a configuration",
			generate: []token.Option{token.WithIssuer(issuer), token.WithAudience("api")},
			verify:   []token.VerifyOption{token.WithVerifyIssuer(""), token.WithVerifyAudience("api")},
			assert:   refusedAtConstruction,
		},
		{
			name:     "an empty audience is not a configuration",
			generate: []token.Option{token.WithIssuer(issuer), token.WithAudience("api")},
			verify:   []token.VerifyOption{token.WithVerifyIssuer(issuer), token.WithVerifyAudience("")},
			assert:   refusedAtConstruction,
		},
		{
			name:     "waived issuer accepts any iss",
			generate: []token.Option{token.WithIssuer("https://other.example"), token.WithAudience("api")},
			verify:   []token.VerifyOption{token.WithoutVerifyIssuer(), token.WithVerifyAudience("api")},
			assert:   accepted,
		},
		{
			name:     "waived audience accepts any aud",
			generate: []token.Option{token.WithIssuer(issuer), token.WithAudience("api")},
			verify:   []token.VerifyOption{token.WithVerifyIssuer(issuer), token.WithoutVerifyAudience()},
			assert:   accepted,
		},
		{
			name:     "token for another service",
			generate: []token.Option{token.WithIssuer(issuer), token.WithAudience("service-a")},
			verify:   []token.VerifyOption{token.WithVerifyAudience("service-b"), token.WithoutVerifyIssuer()},
			assert:   rejected,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)

			gen, err := token.NewGenerator(keys, tc.generate...)
			require.NoError(t, err)

			raw, err := gen.Generate(t.Context(), "s-1", alice())
			require.NoError(t, err)

			ver, err := token.NewVerifier(append([]token.VerifyOption{token.WithVerifyKeySource(keys)}, tc.verify...)...)
			if err != nil {
				tc.assert(t, nil, err)
				return
			}

			claims, err := ver.Verify(t.Context(), raw)
			tc.assert(t, claims, err)
		})
	}
}
