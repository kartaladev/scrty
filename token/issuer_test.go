package token_test

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

const (
	issuerName  = "https://id.example.com"
	apiAudience = "https://api.example.com"
)

// accessIssue is a request that succeeds, for a row to change one thing about.
func accessIssue(change ...func(*token.Issue)) token.Issue {
	in := token.Issue{
		Type:     token.TypeAccessToken,
		Subject:  "u-1",
		ID:       "j-1",
		Audience: []string{apiAudience},
		Claims:   map[string]any{"client_id": "billing-web", "scope": "openid profile"},
	}
	for _, apply := range change {
		apply(&in)
	}

	return in
}

// withClaim is a change to accessIssue carrying one further claim.
func withClaim(name string, value any) func(*token.Issue) {
	return func(in *token.Issue) { in.Claims = map[string]any{name: value} }
}

// verifierFor is a verifier for the given type under the issuer's own name, with
// an audience of apiAudience.
func verifierFor(t *testing.T, keys signingkey.KeySource, typ string) *token.JWTVerifier {
	t.Helper()

	verifier, err := token.NewVerifier(
		token.WithVerifyKeySource(keys),
		token.WithVerifyIssuer(issuerName),
		token.WithVerifyAudience(apiAudience),
		token.WithVerifyTokenType(typ),
	)
	require.NoError(t, err)

	return verifier
}

// issued is what a row of TestIssuer asserts on: the token and the keys that
// signed it, so a row can verify what it was given.
type issued struct {
	raw  string
	keys signingkey.KeySource
}

// verified verifies the token as its own type, failing the row if it is refused.
func (i issued) verified(t *testing.T, typ string) *token.Claims {
	t.Helper()

	claims, err := verifierFor(t, i.keys, typ).Verify(t.Context(), i.raw)
	require.NoError(t, err)

	return claims
}

func TestIssuer(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	fixed := token.WithClock(fixedClock{at: time.Now().Truncate(time.Second)})

	refusedAsConfig := func(t *testing.T, got issued, err error) {
		t.Helper()

		require.ErrorIs(t, err, token.ErrConfig)
		assert.NotErrorIs(t, err, token.ErrInvalid)
		assert.Empty(t, got.raw)
	}
	replaces := func(name string, value any) testIssue {
		return testIssue{
			name:   "a further claim cannot replace " + name,
			in:     accessIssue(withClaim(name, value)),
			assert: refusedAsConfig,
		}
	}

	cases := []testIssue{
		{
			name: "an access token carries what was declared",
			in:   accessIssue(),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				claims := got.verified(t, token.TypeAccessToken)
				assert.Equal(t, "u-1", claims.Subject())
				assert.Equal(t, "j-1", claims.ID())
				assert.Equal(t, []string{apiAudience}, claims.Audience())

				clientID, ok := claims.Claim("client_id")
				assert.True(t, ok)
				assert.Equal(t, "billing-web", clientID)

				scope, ok := claims.Claim("scope")
				assert.True(t, ok)
				assert.Equal(t, "openid profile", scope)

				iss, ok := claims.Claim("iss")
				assert.True(t, ok)
				assert.Equal(t, issuerName, iss)

				assert.Equal(t, "at+jwt", decodeHeader(t, got.raw)["typ"])
				assert.Equal(t, "RS256", decodeHeader(t, got.raw)["alg"])
			},
		},
		{
			name: "every kind of token verifies only as itself",
			in:   accessIssue(func(in *token.Issue) { in.Type = token.TypeIDToken }),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				got.verified(t, token.TypeIDToken)
				for _, other := range []string{token.TypeFirstParty, token.TypeAccessToken, token.TypeLogoutToken} {
					_, verifyErr := verifierFor(t, got.keys, other).Verify(t.Context(), got.raw)
					require.ErrorIs(t, verifyErr, token.ErrInvalid, other)
				}
			},
		},
		{
			name: "the further claims the provider's tokens use travel unchanged",
			in: accessIssue(func(in *token.Issue) {
				in.Claims = map[string]any{
					"client_id": "billing-web", "scope": "openid", "nonce": "n-1", "auth_time": 1700000000,
					"acr": "urn:loa:2", "amr": []string{"pwd", "otp"}, "azp": "billing-web", "sid": "s-1",
					"gid":    "family-1",
					"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
				}
			}),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				payload := decodeClaims(t, got.raw)
				assert.Equal(t, "billing-web", payload["client_id"])
				assert.Equal(t, "openid", payload["scope"])
				assert.Equal(t, "n-1", payload["nonce"])
				assert.EqualValues(t, 1700000000, payload["auth_time"])
				assert.Equal(t, "urn:loa:2", payload["acr"])
				assert.Equal(t, []any{"pwd", "otp"}, payload["amr"])
				assert.Equal(t, "billing-web", payload["azp"])
				assert.Equal(t, "s-1", payload["sid"])
				assert.Equal(t, "family-1", payload["gid"])
				assert.Contains(t, payload["events"], "http://schemas.openid.net/event/backchannel-logout")

				claims := got.verified(t, token.TypeAccessToken)
				amr, ok := claims.Claim("amr")
				assert.True(t, ok)
				assert.Equal(t, []any{"pwd", "otp"}, amr)
				_, ok = claims.Claim("absent")
				assert.False(t, ok)
			},
		},
		{
			name: "an audience of several values is carried whole",
			in: accessIssue(func(in *token.Issue) {
				in.Audience = []string{"https://other.example.com", apiAudience}
			}),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				assert.Equal(t, []string{"https://other.example.com", apiAudience},
					got.verified(t, token.TypeAccessToken).Audience())
			},
		},
		{
			name: "the audience a caller is handed is the caller's own",
			in:   accessIssue(),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				claims := got.verified(t, token.TypeAccessToken)
				claims.Audience()[0] = "rewritten"
				assert.Equal(t, []string{apiAudience}, claims.Audience())
			},
		},
		{
			name: "a confirmation claim is carried as the verifier reads it",
			in:   accessIssue(withClaim("cnf", map[string]any{"jkt": thumbprint("k")})),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				assert.Equal(t, thumbprint("k"), got.verified(t, token.TypeAccessToken).Confirmation().JKT)
			},
		},
		{
			name: "a Confirmation value is carried under its members' own names",
			in:   accessIssue(withClaim("cnf", token.Confirmation{X5TS256: thumbprint("k")})),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				assert.Equal(t, thumbprint("k"), got.verified(t, token.TypeAccessToken).Confirmation().X5TS256)
			},
		},
		{
			name: "the zero Confirmation is no cnf claim",
			in:   accessIssue(withClaim("cnf", token.Confirmation{})),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				assert.NotContains(t, decodeClaims(t, got.raw), "cnf")
			},
		},
		{
			name:   "a malformed thumbprint in cnf is refused",
			in:     accessIssue(withClaim("cnf", map[string]any{"jkt": "short"})),
			assert: refusedAsConfig,
		},
		{
			name:   "a cnf naming both bindings is refused",
			in:     accessIssue(withClaim("cnf", map[string]any{"jkt": thumbprint("k"), "x5t#S256": thumbprint("k")})),
			assert: refusedAsConfig,
		},
		{
			name:   "a cnf with a member this package does not check is refused",
			in:     accessIssue(withClaim("cnf", map[string]any{"kid": "k"})),
			assert: refusedAsConfig,
		},
		{name: "a cnf of another shape is refused", in: accessIssue(withClaim("cnf", "jkt")), assert: refusedAsConfig},
		{
			name: "a zero lifetime takes the issuer's",
			opts: []token.Option{token.WithTokenLifetime(2 * time.Minute), fixed},
			in:   accessIssue(),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				payload := decodeClaims(t, got.raw)
				assert.EqualValues(t, 120, payload["exp"].(float64)-payload["iat"].(float64))
			},
		},
		{
			name: "a lifetime is for that token alone",
			opts: []token.Option{token.WithTokenLifetime(2 * time.Minute), fixed},
			in:   accessIssue(func(in *token.Issue) { in.Lifetime = 5 * time.Minute }),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				payload := decodeClaims(t, got.raw)
				assert.EqualValues(t, 300, payload["exp"].(float64)-payload["iat"].(float64))
			},
		},
		{
			name: "iat and exp are the issuer's clock's",
			opts: []token.Option{token.WithClock(fixedClock{at: at})},
			in:   accessIssue(),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)

				payload := decodeClaims(t, got.raw)
				assert.EqualValues(t, at.Unix(), payload["iat"])
				assert.EqualValues(t, at.Add(15*time.Minute).Unix(), payload["exp"])
			},
		},
		{
			name: "a lifetime at the key cap is issued",
			in:   accessIssue(func(in *token.Issue) { in.Lifetime = 23 * time.Hour }),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, got.raw)
			},
		},
		{
			name:   "a lifetime past the key cap is refused",
			in:     accessIssue(func(in *token.Issue) { in.Lifetime = 24 * time.Hour }),
			assert: refusedAsConfig,
		},
		{
			name:   "a negative lifetime is refused",
			in:     accessIssue(func(in *token.Issue) { in.Lifetime = -time.Minute }),
			assert: refusedAsConfig,
		},
		{
			name:   "a lifetime of part of a second is refused",
			in:     accessIssue(func(in *token.Issue) { in.Lifetime = 1500 * time.Millisecond }),
			assert: refusedAsConfig,
		},
		{
			name: "an empty subject is refused",
			in:   accessIssue(func(in *token.Issue) { in.Subject = "" }),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()

				require.ErrorIs(t, err, token.ErrNoSubject)
				assert.NotErrorIs(t, err, token.ErrInvalid)
				assert.Empty(t, got.raw)
			},
		},
		{
			name: "an empty identifier is refused",
			in:   accessIssue(func(in *token.Issue) { in.ID = "" }),
			assert: func(t *testing.T, got issued, err error) {
				t.Helper()

				require.ErrorIs(t, err, token.ErrNoTokenID)
				assert.Empty(t, got.raw)
			},
		},
		{
			name:   "no declared type is refused",
			in:     accessIssue(func(in *token.Issue) { in.Type = "" }),
			assert: refusedAsConfig,
		},
		{
			name:   "a blank declared type is refused",
			in:     accessIssue(func(in *token.Issue) { in.Type = "  " }),
			assert: refusedAsConfig,
		},
		{
			name:   "no audience is refused",
			in:     accessIssue(func(in *token.Issue) { in.Audience = nil }),
			assert: refusedAsConfig,
		},
		{
			name:   "a blank audience value is refused",
			in:     accessIssue(func(in *token.Issue) { in.Audience = []string{apiAudience, " "} }),
			assert: refusedAsConfig,
		},
		replaces("iss", "https://evil.example.com"),
		replaces("sub", "someone-else"),
		replaces("iat", 1),
		replaces("exp", 4102444800),
		replaces("jti", "other"),
		replaces("aud", "https://evil.example.com"),
		{
			name:   "a further claim that cannot be encoded is refused",
			in:     accessIssue(withClaim("x", make(chan int))),
			assert: refusedAsConfig,
		},
		{
			name:   "a further claim the claim set refuses is refused",
			in:     accessIssue(withClaim("nbf", "not a date")),
			assert: refusedAsConfig,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t)
			issuer, err := token.NewIssuer(keys, signingkey.RS256, issuerName, tc.opts...)
			require.NoError(t, err)

			raw, err := issuer.Issue(t.Context(), tc.in)
			tc.assert(t, issued{raw: raw, keys: keys}, err)
		})
	}
}

// testIssue is a row of TestIssuer. It has a name because a helper of the test
// builds some of its rows.
type testIssue struct {
	name   string
	opts   []token.Option
	in     token.Issue
	assert func(t *testing.T, got issued, err error)
}

// TestIssuer_Algorithm pins that an issuer signs with the algorithm it was built
// for and no other.
func TestIssuer_Algorithm(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		held   signingkey.Alg
		alg    signingkey.Alg
		assert func(t *testing.T, keys signingkey.KeySource, raw string, err error)
	}

	cases := []testCase{
		{
			name: "an issuer built for ES256 over a source holding it signs ES256",
			held: signingkey.ES256,
			alg:  signingkey.ES256,
			assert: func(t *testing.T, keys signingkey.KeySource, raw string, err error) {
				t.Helper()
				require.NoError(t, err)

				assert.Equal(t, "ES256", decodeHeader(t, raw)["alg"])
				_, verifyErr := verifierFor(t, keys, token.TypeAccessToken).Verify(t.Context(), raw)
				assert.NoError(t, verifyErr)
			},
		},
		{
			name: "a source without the algorithm is a missing key, with no fallback",
			held: signingkey.RS256,
			alg:  signingkey.ES256,
			assert: func(t *testing.T, _ signingkey.KeySource, raw string, err error) {
				t.Helper()

				require.ErrorIs(t, err, signingkey.ErrNoKey)
				assert.Empty(t, raw)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keys := newKeySource(t, tc.held)
			issuer, err := token.NewIssuer(keys, tc.alg, issuerName)
			require.NoError(t, err)

			raw, err := issuer.Issue(t.Context(), accessIssue())
			tc.assert(t, keys, raw, err)
		})
	}
}

// TestIssuer_KeySourceFailure pins how an issuer reports a key source that did
// not answer: as an outage behind fixed text, and never as a refused token.
func TestIssuer_KeySourceFailure(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context
		signer func(ctx context.Context, alg signingkey.Alg) (string, crypto.Signer, error)
		assert func(t *testing.T, raw string, err error)
	}

	cases := []testCase{
		{
			name: "a failing source stays reachable, and its text is not rendered",
			signer: func(context.Context, signingkey.Alg) (string, crypto.Signer, error) {
				return "", nil, errKeySourceFixture
			},
			assert: func(t *testing.T, raw string, err error) {
				t.Helper()

				require.ErrorIs(t, err, errKeySourceFixture)
				assert.NotErrorIs(t, err, token.ErrInvalid)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.Empty(t, raw)
			},
		},
		{
			name: "a source handing over no signer is an outage",
			signer: func(context.Context, signingkey.Alg) (string, crypto.Signer, error) {
				return "kid", nil, nil
			},
			assert: func(t *testing.T, raw string, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotErrorIs(t, err, token.ErrInvalid)
				assert.Empty(t, raw)
			},
		},
		{
			name: "the caller's context reaches the source",
			ctx: func(ctx context.Context) context.Context {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				return cancelled
			},
			signer: func(ctx context.Context, _ signingkey.Alg) (string, crypto.Signer, error) {
				return "", nil, ctx.Err()
			},
			assert: func(t *testing.T, raw string, err error) {
				t.Helper()

				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, raw)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			keys := NewMockKeySource(gomock.NewController(t))
			keys.EXPECT().Signer(gomock.Any(), signingkey.RS256).DoAndReturn(tc.signer)

			issuer, err := token.NewIssuer(keys, signingkey.RS256, issuerName)
			require.NoError(t, err)

			raw, err := issuer.Issue(ctx, accessIssue())
			tc.assert(t, raw, err)
		})
	}
}

// TestIssuer_RefusalAsksNoKey pins that a request refused for its own content
// never reaches the key source: no mock expectation is set, so a call fails it.
func TestIssuer_RefusalAsksNoKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   token.Issue
	}{
		{name: "a reserved claim", in: accessIssue(withClaim("iss", "x"))},
		{name: "a claim its registered type refuses", in: accessIssue(withClaim("nbf", "not a date"))},
		{name: "the first-party type", in: accessIssue(func(in *token.Issue) { in.Type = token.TypeFirstParty })},
		{name: "the first-party type, spelled with the prefix and other case", in: accessIssue(func(in *token.Issue) { in.Type = "Application/SCRTY+JWT" })},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			issuer, err := token.NewIssuer(NewMockKeySource(gomock.NewController(t)), signingkey.RS256, issuerName)
			require.NoError(t, err)

			got, err := issuer.Issue(t.Context(), tc.in)
			require.ErrorIs(t, err, token.ErrConfig)
			assert.Empty(t, got)
		})
	}
}

func TestNewIssuer(t *testing.T) {
	t.Parallel()

	refused := func(t *testing.T, issuer *token.Issuer, err error) {
		t.Helper()

		require.ErrorIs(t, err, token.ErrConfig)
		assert.Nil(t, issuer)
	}
	built := func(t *testing.T, issuer *token.Issuer, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, issuer)
	}

	var typedNil *signingkey.Keys

	type testCase struct {
		name   string
		keys   func(t *testing.T) signingkey.KeySource
		alg    signingkey.Alg
		issuer string
		opts   []token.Option
		assert func(t *testing.T, issuer *token.Issuer, err error)
	}

	cases := []testCase{
		{name: "a key source, an algorithm and an issuer are enough", assert: built},
		{name: "a nil option is skipped", opts: []token.Option{nil}, assert: built},
		{
			name:   "the lifetime and the clock are options",
			opts:   []token.Option{token.WithTokenLifetime(time.Minute), token.WithClock(fixedClock{at: time.Now()})},
			assert: built,
		},
		{
			name:   "no key source",
			keys:   func(*testing.T) signingkey.KeySource { return nil },
			assert: refused,
		},
		{
			name:   "a key source holding a nil pointer",
			keys:   func(*testing.T) signingkey.KeySource { return typedNil },
			assert: refused,
		},
		{name: "an algorithm that signs nothing", alg: "none", assert: refused},
		{name: "a symmetric algorithm", alg: "HS256", assert: refused},
		{name: "an empty issuer", issuer: "-", assert: refused},
		{name: "a blank issuer", issuer: " \n", assert: refused},
		{name: "a nil clock", opts: []token.Option{token.WithClock(nil)}, assert: refused},
		{
			name:   "a default lifetime past the key cap",
			opts:   []token.Option{token.WithTokenLifetime(24 * time.Hour)},
			assert: refused,
		},
		{name: "another issuer", opts: []token.Option{token.WithIssuer("https://other.example.com")}, assert: refused},
		{name: "the issuer waived", opts: []token.Option{token.WithoutIssuer()}, assert: refused},
		{name: "one audience for every token", opts: []token.Option{token.WithAudience("api")}, assert: refused},
		{name: "the audience waived", opts: []token.Option{token.WithoutAudience()}, assert: refused},
		{name: "another algorithm", opts: []token.Option{token.WithSigningAlg(signingkey.ES256)}, assert: refused},
		{name: "a username subject", opts: []token.Option{token.WithUsernameSubject()}, assert: refused},
		{name: "the same algorithm, named again", opts: []token.Option{token.WithSigningAlg(signingkey.RS256)}, assert: refused},
		{name: "the first-party type, named again", opts: []token.Option{token.WithTokenType(token.TypeFirstParty)}, assert: refused},
		{name: "one type for every token", opts: []token.Option{token.WithTokenType("app+jwt")}, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var keys signingkey.KeySource = newKeySource(t)
			if tc.keys != nil {
				keys = tc.keys(t)
			}
			alg := tc.alg
			if alg == "" {
				alg = signingkey.RS256
			}
			name := tc.issuer
			switch name {
			case "":
				name = issuerName
			case "-":
				name = ""
			}

			issuer, err := token.NewIssuer(keys, alg, name, tc.opts...)
			tc.assert(t, issuer, err)
		})
	}
}

// TestClaims_ReadsOfConsumerClaims pins what the two readers report for claims
// that came from no token of this package's own verification.
func TestClaims_ReadsOfConsumerClaims(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		claims *token.Claims
	}

	cases := []testCase{
		{name: "nil claims"},
		{name: "the zero value", claims: &token.Claims{}},
		{name: "a consumer verifier's claims", claims: token.NewClaims("u-1", "j-1")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Empty(t, tc.claims.Audience())
			value, ok := tc.claims.Claim("client_id")
			assert.False(t, ok)
			assert.Nil(t, value)
		})
	}
}
