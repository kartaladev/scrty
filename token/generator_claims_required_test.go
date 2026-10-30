package token_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// TestNewGeneratorRequiresIssuerAndAudience pins that a generator, which
// verifies the tokens it issues, follows the verifier's rule: each of the
// issuer and the audience is configured or waived by name, never neither and
// never both. A configured claim is minted and checked; a waived one is
// neither.
func TestNewGeneratorRequiresIssuerAndAudience(t *testing.T) {
	t.Parallel()

	const issuer = "https://b.example"

	type testCase struct {
		name    string
		options []token.Option
		// assert receives the key source the generator was built on, so a row
		// can build a second generator sharing it.
		assert func(t *testing.T, keys *signingkey.Keys, gen token.Generator, err error)
	}

	refusedAtConstruction := func(t *testing.T, _ *signingkey.Keys, gen token.Generator, err error) {
		t.Helper()

		require.ErrorIs(t, err, token.ErrConfig)
		assert.Nil(t, gen)
	}

	cases := []testCase{
		{
			name:    "neither issuer nor waiver",
			options: []token.Option{token.WithAudience("service-b")},
			assert:  refusedAtConstruction,
		},
		{
			name:    "neither audience nor waiver",
			options: []token.Option{token.WithIssuer(issuer)},
			assert:  refusedAtConstruction,
		},
		{
			name: "issuer and its waiver",
			options: []token.Option{
				token.WithIssuer(issuer), token.WithoutIssuer(),
				token.WithAudience("service-b"),
			},
			assert: refusedAtConstruction,
		},
		{
			name: "audience and its waiver",
			options: []token.Option{
				token.WithIssuer(issuer),
				token.WithAudience("service-b"), token.WithoutAudience(),
			},
			assert: refusedAtConstruction,
		},
		{
			name:    "an empty issuer is not a configuration",
			options: []token.Option{token.WithIssuer(""), token.WithAudience("service-b")},
			assert:  refusedAtConstruction,
		},
		{
			name:    "an empty audience is not a configuration",
			options: []token.Option{token.WithIssuer(issuer), token.WithAudience("")},
			assert:  refusedAtConstruction,
		},
		{
			// Two services whose issuer and audience come from settings left
			// unset would each mint iss "" and aud [""], and each accept the
			// other's tokens.
			name:    "two services with empty settings",
			options: []token.Option{token.WithIssuer(""), token.WithAudience("")},
			assert: func(t *testing.T, keys *signingkey.Keys, serviceB token.Generator, err error) {
				refusedAtConstruction(t, keys, serviceB, err)

				serviceA, err := token.NewGenerator(keys, token.WithIssuer(""), token.WithAudience(""))
				refusedAtConstruction(t, keys, serviceA, err)
			},
		},
		{
			name:    "two services sharing a key source",
			options: []token.Option{token.WithIssuer(issuer), token.WithAudience("service-b")},
			assert: func(t *testing.T, keys *signingkey.Keys, serviceB token.Generator, err error) {
				require.NoError(t, err)

				serviceA, err := token.NewGenerator(keys,
					token.WithIssuer(issuer), token.WithAudience("service-a"))
				require.NoError(t, err)

				raw, err := serviceA.Generate(t.Context(), "s-1", alice())
				require.NoError(t, err)

				claims, err := serviceB.Verify(t.Context(), raw)
				rejected(t, claims, err)
			},
		},
		{
			name:    "waived on purpose",
			options: []token.Option{token.WithoutIssuer(), token.WithoutAudience()},
			assert: func(t *testing.T, _ *signingkey.Keys, gen token.Generator, err error) {
				require.NoError(t, err)

				raw, err := gen.Generate(t.Context(), "s-1", alice())
				require.NoError(t, err)

				payload := segment(t, raw, 1)
				assert.NotContains(t, payload, "iss")
				assert.NotContains(t, payload, "aud")

				claims, err := gen.Verify(t.Context(), raw)
				accepted(t, claims, err)
			},
		},
		{
			name:    "waived on purpose accepts a foreign issuer and audience",
			options: []token.Option{token.WithoutIssuer(), token.WithoutAudience()},
			assert: func(t *testing.T, keys *signingkey.Keys, gen token.Generator, err error) {
				require.NoError(t, err)

				foreign, err := token.NewGenerator(keys,
					token.WithIssuer("https://other.example"), token.WithAudience("other"))
				require.NoError(t, err)

				raw, err := foreign.Generate(t.Context(), "s-1", alice())
				require.NoError(t, err)

				payload := segment(t, raw, 1)
				require.Equal(t, "https://other.example", payload["iss"])
				require.Equal(t, []any{"other"}, payload["aud"])

				claims, err := gen.Verify(t.Context(), raw)
				accepted(t, claims, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)

			gen, err := token.NewGenerator(keys, tc.options...)
			tc.assert(t, keys, gen, err)
		})
	}
}
