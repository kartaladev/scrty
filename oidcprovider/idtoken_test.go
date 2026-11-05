package oidcprovider_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// tokenRow is one token request and what must come of it, for the tables about minting.
type tokenRow struct {
	name    string
	opts    func(*testing.T) []oidcprovider.Option
	ctx     func(context.Context) context.Context
	arrange func(*testing.T, *exchangeFixture) (issuedCode, oidcprovider.TokenRequest)
	assert  func(*testing.T, *exchangeFixture, issuedCode, *oidcprovider.TokenResponse, error)
}

func runTokenRows(t *testing.T, rows []tokenRow) {
	t.Helper()

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidcprovider.Option
			if tc.opts != nil {
				opts = tc.opts(t)
			}
			x := newExchangeFixture(t, opts...)
			c, req := tc.arrange(t, x)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			res, err := x.p.Token(ctx, req)
			tc.assert(t, x, c, res, err)

			if res != nil {
				for _, secret := range []string{res.AccessToken, res.IDToken, res.RefreshToken} {
					if secret != "" {
						assert.NotContains(t, x.logs.String(), secret, "no log line carries a token")
					}
				}
			}
			if err != nil {
				assert.NotContains(t, err.Error(), errOutage.Error())
			}
		})
	}
}

// decodeJWT reads a compact JWS's header and claims as JSON decodes them, without judging it.
func decodeJWT(t *testing.T, raw string) (header, claims map[string]any) {
	t.Helper()

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3, "a compact JWS")
	for i, into := range []*map[string]any{&header, &claims} {
		text, err := base64.RawURLEncoding.DecodeString(parts[i])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(text, into))
	}

	return header, claims
}

// verifyAs is what a relying party's verifier of one token type makes of raw.
func verifyAs(t *testing.T, x *exchangeFixture, typ, raw string) (*token.Claims, error) {
	t.Helper()

	verifier, err := token.NewVerifier(
		token.WithVerifyKeySource(x.keys),
		token.WithVerifyIssuer(issuer),
		token.WithoutVerifyAudience(),
		token.WithVerifyClock(x.clk),
		token.WithVerifyTokenType(typ),
	)
	require.NoError(t, err)

	return verifier.Verify(t.Context(), raw)
}

// unixOf is a time as a JWT's numeric claim decodes.
func unixOf(at time.Time) float64 { return float64(at.Unix()) }

// assertNothingWritten checks that a failed exchange left c as it found it.
func assertNothingWritten(t *testing.T, x *exchangeFixture, c issuedCode) {
	t.Helper()

	assertUnspent(t, x, c)
	_, err := x.p.GrantsForTest().Load(t.Context(), recordOf(t, x.parkFixture, c.code).GrantFamily)
	require.ErrorIs(t, err, oidcprovider.ErrNotFound, "no grant row is written")
	assert.Zero(t, x.p.LineageHeldForTest(), "no lineage is written")
}

func TestProvider_IDToken(t *testing.T) {
	t.Parallel()

	// issueWith is a billing-web code for openid and profile.
	issueWith := func(t *testing.T, x *exchangeFixture, change func(url.Values), adjust func(*oidcprovider.SignIn)) issuedCode {
		t.Helper()
		signIn := testSignIn(x.parkFixture, "u-1")
		if adjust != nil {
			adjust(&signIn)
		}

		return issueCodeFor(t, x.parkFixture, "billing-web", change, signIn, "openid", "profile")
	}
	withNonce := func(v url.Values) { v.Set("nonce", "n-1") }

	// signingFails is an exchange whose key source fails at signing, until the assertion
	// lets it recover.
	signingFails := func(name string, cause error) tokenRow {
		return tokenRow{
			name: name,
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.keys.failSigning(func(context.Context) error { return cause })

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)

				x.keys.failSigning(nil)
				res, err = x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err, "the same request succeeds once the keys are back")
				assert.NotEmpty(t, res.IDToken)
				assert.False(t, grantOf(t, x, c).Revoked, "the failed try was no replay")
			},
		}
	}
	// signingHangsUp is a caller leaving while its token is being signed.
	signingHangsUp := func() tokenRow {
		var leave context.CancelFunc

		return tokenRow{
			name: "a caller leaving at signing is a hang-up, with the code unspent",
			ctx: func(ctx context.Context) context.Context {
				left, cancel := context.WithCancelCause(ctx)
				leave = func() { cancel(nil) }

				return left
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				x.keys.failSigning(func(ctx context.Context) error {
					leave()

					return ctx.Err()
				})

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)
			},
		}
	}

	rows := []tokenRow{
		{
			name: "a password and TOTP sign-in's claims",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueWith(t, x, withNonce, nil)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				header, claims := decodeJWT(t, res.IDToken)
				assert.Equal(t, "JWT", header["typ"])
				assert.Equal(t, "RS256", header["alg"])
				assert.Equal(t, rsKid, header["kid"])

				assert.Equal(t, issuer, claims["iss"])
				assert.Equal(t, "u-1", claims["sub"])
				assert.Equal(t, "billing-web", claims["azp"])
				assert.Equal(t, unixOf(x.clk.Now()), claims["iat"])
				assert.Equal(t, unixOf(x.clk.Now().Add(5*time.Minute)), claims["exp"])
				assert.Equal(t, unixOf(c.signIn.AuthenticatedAt), claims["auth_time"])
				assert.Equal(t, "n-1", claims["nonce"])
				assert.Equal(t, []any{"pwd", "otp"}, claims["amr"])
				assert.Equal(t, "urn:example:mfa", claims["acr"])
				assert.Equal(t, c.signIn.Family.String(), claims["sid"])
				assert.NotEmpty(t, claims["jti"])

				verified, err := verifyAs(t, x, token.TypeIDToken, res.IDToken)
				require.NoError(t, err, "it verifies as an ID token")
				assert.Equal(t, []string{"billing-web"}, verified.Audience())
			},
		},
		{
			name: "H3: a sign-in at 10:00 exchanged at 10:04 carries 10:00",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueWith(t, x, nil, func(s *oidcprovider.SignIn) {
					s.AuthenticatedAt = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
				})
				x.clk.Advance(20 * time.Second)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				_, claims := decodeJWT(t, res.IDToken)
				assert.Equal(t, unixOf(time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)), claims["auth_time"])
				assert.Equal(t, unixOf(x.clk.Now()), claims["iat"])
			},
		},
		{
			name: "a request with no nonce, and a sign-in with no amr or acr, carry none",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueWith(t, x, nil, func(s *oidcprovider.SignIn) {
					s.AMR, s.ACR = nil, ""
				})

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				_, claims := decodeJWT(t, res.IDToken)
				for _, name := range []string{"nonce", "amr", "acr"} {
					assert.NotContains(t, claims, name)
				}
			},
		},
		{
			name: "sid is the sign-in's family, the same after it renews, and another's differs",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				_, first := decodeJWT(t, res.IDToken)

				// A renewal keeps the family and moves what it touches.
				renewed := issueWith(t, x, nil, func(s *oidcprovider.SignIn) {
					s.Family = c.signIn.Family
					s.AbsoluteExpiresAt = c.signIn.AbsoluteExpiresAt.Add(time.Hour)
				})
				res, err = x.p.Token(t.Context(), billingExchange(renewed, nil))
				require.NoError(t, err)
				_, again := decodeJWT(t, res.IDToken)
				assert.Equal(t, c.signIn.Family.String(), first["sid"])
				assert.Equal(t, first["sid"], again["sid"])

				other := x.issue(t)
				res, err = x.p.Token(t.Context(), billingExchange(other, nil))
				require.NoError(t, err)
				_, another := decodeJWT(t, res.IDToken)
				assert.NotEqual(t, first["sid"], another["sid"])
			},
		},
		{
			name: "a client set to ES256 and 10 minutes signs so and lasts so",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, tunedClient, func(v url.Values) {
					asClient(v, tunedClient, tunedRedirect)
				}, testSignIn(x.parkFixture, "u-1"), "openid", "profile")

				return c, confidentialExchange(tunedClient, tunedRedirect, c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				header, claims := decodeJWT(t, res.IDToken)
				assert.Equal(t, "ES256", header["alg"])
				assert.Equal(t, esKid, header["kid"])
				assert.Equal(t, unixOf(x.clk.Now().Add(10*time.Minute)), claims["exp"])
				_, err = verifyAs(t, x, token.TypeIDToken, res.IDToken)
				require.NoError(t, err)
			},
		},
		{
			name: "R6: a user known by a username keeps its identifier as sub",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				x.users.set(func(u *exchangeUsers) { u.username = "alice" })
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)

				_, idClaims := decodeJWT(t, res.IDToken)
				_, accessClaims := decodeJWT(t, res.AccessToken)
				assert.Equal(t, string(grantOf(t, x, c).User), idClaims["sub"])
				assert.Equal(t, "u-1", idClaims["sub"])
				assert.Equal(t, "u-1", accessClaims["sub"])
			},
		},
		{
			name: "a grant without openid gets no ID token",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, audienceClient, func(v url.Values) {
					asClient(v, audienceClient, audienceRedirect)
					v.Set("scope", "api.read")
				}, testSignIn(x.parkFixture, "u-1"), "api.read")

				return c, confidentialExchange(audienceClient, audienceRedirect, c, nil)
			},
			assert: func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, res.IDToken)
				assert.NotEmpty(t, res.AccessToken)
			},
		},
		signingFails("R18: a key source failing at signing leaves the code unspent and nothing written", errOutage),
		signingFails("R18: a key source holding no key is a dependency failure too",
			errors.Join(signingkey.ErrNoKey, errOutage)),
		signingHangsUp(),
		{
			name: "R18: a key source failing at the second signature, the ID token's, leaves the code unspent and nothing written",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				var signatures atomic.Int32
				x.keys.failSigning(func(context.Context) error {
					if signatures.Add(1) == 2 {
						return errOutage
					}

					return nil
				})

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)

				x.keys.failSigning(nil)
				res, err = x.p.Token(t.Context(), billingExchange(c, nil))
				require.NoError(t, err, "the same request succeeds once the keys are back")
				assert.NotEmpty(t, res.IDToken)
			},
		},
		{
			name: "every token has a jti of its own",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				again, err := x.p.Token(t.Context(), billingExchange(x.issue(t), nil))
				require.NoError(t, err)

				jtis := map[any]bool{}
				for _, raw := range []string{res.AccessToken, res.IDToken, again.AccessToken, again.IDToken} {
					_, claims := decodeJWT(t, raw)
					require.NotEmpty(t, claims["jti"])
					jtis[claims["jti"]] = true
				}
				assert.Len(t, jtis, 4, "no two of four tokens share a jti")
			},
		},
	}

	runTokenRows(t, rows)
}

// listingKeys is a key source that lists the algorithms it gives.
type listingKeys struct {
	*exchangeKeys

	algs []signingkey.Alg
}

func (k listingKeys) SupportedAlgs() []signingkey.Alg { return k.algs }

// TestProvider_IDToken_Construction pins what New asks of the keys it builds issuers over.
func TestProvider_IDToken_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		keys func(*testing.T) signingkey.KeySource
		// client changes the one client, which lasts 1 minute unless it says otherwise.
		client func(*oidcprovider.Client)
		// noClients registers none, so only the keys are judged.
		noClients bool
		assert    func(*testing.T, *oidcprovider.Provider, error)
	}

	cases := []testCase{
		{
			name: "keys that leave no usable window fail construction naming Keys, though no client is configured",
			keys: func(t *testing.T) signingkey.KeySource {
				t.Helper()

				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: time.Minute, rotate: time.Minute}
			},
			noClients: true,
			assert: func(t *testing.T, _ *oidcprovider.Provider, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "Keys")
			},
		},
		{
			name: "keys whose usable window is under the default lifetime build, since the clients fit it",
			keys: func(t *testing.T) signingkey.KeySource {
				t.Helper()

				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: 3 * time.Minute, rotate: time.Minute}
			},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name: "clients exactly at the keys' usable window build",
			keys: func(t *testing.T) signingkey.KeySource {
				t.Helper()

				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: 3 * time.Minute, rotate: time.Minute}
			},
			client: func(c *oidcprovider.Client) { c.IDTokenLifetime, c.AccessTokenLifetime = 2*time.Minute, 2*time.Minute },
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name: "a usable window that is not whole seconds builds",
			keys: func(t *testing.T) signingkey.KeySource {
				t.Helper()

				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: 3*time.Minute + 500*time.Millisecond, rotate: time.Minute}
			},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name: "a client over the keys' usable window fails construction, naming the client and the setting",
			keys: func(t *testing.T) signingkey.KeySource {
				t.Helper()

				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: 3 * time.Minute, rotate: time.Minute}
			},
			client: func(c *oidcprovider.Client) { c.AccessTokenLifetime = 3 * time.Minute },
			assert: func(t *testing.T, _ *oidcprovider.Provider, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "billing-web")
				assert.ErrorContains(t, err, "AccessTokenLifetime")
			},
		},
		{
			name: "keys that leave no usable window fail construction",
			keys: func(t *testing.T) signingkey.KeySource {
				t.Helper()

				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: time.Minute, rotate: time.Minute}
			},
			assert: func(t *testing.T, _ *oidcprovider.Provider, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.ErrorContains(t, err, "billing-web")
			},
		},
		{
			name: "keys whose window holds the default build",
			keys: func(t *testing.T) signingkey.KeySource {
				t.Helper()

				return reportingKeys{KeySource: newExchangeKeys(t), lifetime: 10 * time.Minute, rotate: time.Minute}
			},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
		{
			name: "an algorithm no client could register does not fail construction",
			keys: func(t *testing.T) signingkey.KeySource {
				t.Helper()

				return listingKeys{exchangeKeys: newExchangeKeys(t), algs: []signingkey.Alg{signingkey.RS256, "HS256"}}
			},
			assert: func(t *testing.T, p *oidcprovider.Provider, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps := validDeps(t)
			deps.Keys = tc.keys(t)
			client := webClient()
			client.IDTokenLifetime, client.AccessTokenLifetime = time.Minute, time.Minute
			if tc.client != nil {
				tc.client(&client)
			}
			deps.Clients = []oidcprovider.Client{client}
			if tc.noClients {
				registry, err := oidcprovider.NewMemoryRegistry(nil)
				require.NoError(t, err)
				deps.Clients, deps.Registry = nil, registry
			}

			p, err := oidcprovider.New(deps)
			tc.assert(t, p, err)
		})
	}
}
