package oidcprovider_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// A thumbprint of the shape httpsec computes: the verifier's RFC 7636 challenge is one.
const (
	boundJKT = authzChallenge
	boundX5T = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// issueAudience is an audience-app code for scope, with its authorization request's resources.
func issueAudience(t *testing.T, x *exchangeFixture, scope string, resources ...string) issuedCode {
	t.Helper()

	return issueCodeFor(t, x.parkFixture, audienceClient, func(v url.Values) {
		asClient(v, audienceClient, audienceRedirect)
		v.Set("scope", scope)
		if len(resources) > 0 {
			v["resource"] = resources
		}
	}, testSignIn(x.parkFixture, "u-1"), strings.Fields(scope)...)
}

// audienceExchange is c's exchange by audience-app, asking for resources.
func audienceExchange(c issuedCode, resources ...string) oidcprovider.TokenRequest {
	return confidentialExchange(audienceClient, audienceRedirect, c, func(v url.Values) {
		if len(resources) > 0 {
			v["resource"] = resources
		}
	})
}

// issueOpaque is an opaque-app code for openid.
func issueOpaque(t *testing.T, x *exchangeFixture) issuedCode {
	t.Helper()

	return issueCodeFor(t, x.parkFixture, opaqueClient, func(v url.Values) {
		asClient(v, opaqueClient, opaqueRedirect)
		v.Set("scope", "openid")
	}, testSignIn(x.parkFixture, "u-1"), "openid")
}

func opaqueExchange(c issuedCode) oidcprovider.TokenRequest {
	return confidentialExchange(opaqueClient, opaqueRedirect, c, nil)
}

// audienceOf is an access token's aud, as a verifier of access tokens reads it.
func audienceOf(t *testing.T, x *exchangeFixture, res *oidcprovider.TokenResponse) []string {
	t.Helper()

	claims, err := verifyAs(t, x, token.TypeAccessToken, res.AccessToken)
	require.NoError(t, err)

	return claims.Audience()
}

// opaqueParts splits an at.<id>.<secret> token.
func opaqueParts(t *testing.T, raw string) (id.ID, string) {
	t.Helper()

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3, "at.<id>.<secret>")
	require.Equal(t, "at", parts[0])
	tokenID, err := id.Parse(parts[1])
	require.NoError(t, err)

	return tokenID, parts[2]
}

func TestProvider_AccessToken(t *testing.T) {
	t.Parallel()

	// refusedThenExchanges is an exchange refused for what it asked, whose code stays unspent
	// and then exchanges.
	refusedThenExchanges := func(name, code string, resources ...string) tokenRow {
		return tokenRow{
			name: name,
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueAudience(t, x, "openid", ordersResource)

				return c, audienceExchange(c, resources...)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, code)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)

				res, err = x.p.Token(t.Context(), audienceExchange(c, ordersResource))
				require.NoError(t, err, "the refusal left the code unspent")
				assert.Equal(t, []string{ordersResource}, audienceOf(t, x, res))
			},
		}
	}
	// audience is an audience-app exchange and the aud it must get.
	audience := func(name, scope string, granted, asked, want []string) tokenRow {
		return tokenRow{
			name: name,
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueAudience(t, x, scope, granted...)

				return c, audienceExchange(c, asked...)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, want, audienceOf(t, x, res))
				assert.Equal(t, granted, nilIfEmpty(grantOf(t, x, c).Resources), "the grant stays whole, whatever a token narrowed to")
			},
		}
	}
	// bound is a billing-web exchange proving binding.
	bound := func(name string, binding oidcprovider.Binding, tokenType string, want map[string]any) tokenRow {
		return tokenRow{
			name: name,
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)
				req := billingExchange(c, nil)
				req.Binding = binding

				return c, req
			},
			assert: func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, tokenType, res.TokenType)
				_, claims := decodeJWT(t, res.AccessToken)
				if want == nil {
					assert.NotContains(t, claims, "cnf")

					return
				}
				assert.Equal(t, want, claims["cnf"])
			},
		}
	}
	// malformed is an exchange whose binding is no thumbprint httpsec would compute, which is
	// a failure of whatever filled it in. It answers a dependency failure with the code
	// unspent and nothing written, whichever kind of token or client.
	malformed := func(name string, issue func(*testing.T, *exchangeFixture) (issuedCode, oidcprovider.TokenRequest), binding oidcprovider.Binding) tokenRow {
		return tokenRow{
			name: name,
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c, req := issue(t, x)
				req.Binding = binding

				return c, req
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)
			},
		}
	}
	jwtClient := func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
		t.Helper()
		c := x.issue(t)

		return c, billingExchange(c, nil)
	}
	opaqueClientRequest := func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
		t.Helper()
		c := issueOpaque(t, x)

		return c, opaqueExchange(c)
	}
	publicClient := func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
		t.Helper()
		c := issueCodeFor(t, x.parkFixture, nativeClient, func(v url.Values) {
			asClient(v, nativeClient, nativeRedirect)
			v.Set("scope", "openid offline_access")
		}, testSignIn(x.parkFixture, "u-1"), "openid", "offline_access")

		return c, oidcprovider.TokenRequest{
			Form: exchangeForm(c, nativeRedirect, func(v url.Values) { v.Set("client_id", nativeClient) }),
		}
	}

	// opaqueStoreFailing has the provider's opaque token store refuse its write.
	opaqueStoreFailing := func(t *testing.T) []oidcprovider.Option {
		t.Helper()
		store := NewMockAccessTokenStore(gomock.NewController(t))
		store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage)

		return []oidcprovider.Option{oidcprovider.WithAccessTokenStore(store)}
	}

	rows := []tokenRow{
		{
			name: "a JWT typed at+jwt, with the RFC 9068 claims, gid and the sign-in's facts",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := x.issue(t)

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "Bearer", res.TokenType)
				assert.Equal(t, 300, res.ExpiresIn)

				header, claims := decodeJWT(t, res.AccessToken)
				assert.Equal(t, "at+jwt", header["typ"])
				assert.Equal(t, "RS256", header["alg"])
				assert.Equal(t, issuer, claims["iss"])
				assert.Equal(t, "u-1", claims["sub"])
				assert.Equal(t, "billing-web", claims["client_id"])
				assert.Equal(t, "openid profile", claims["scope"])
				assert.Equal(t, unixOf(x.clk.Now()), claims["iat"])
				assert.Equal(t, unixOf(x.clk.Now().Add(5*time.Minute)), claims["exp"])
				assert.NotEmpty(t, claims["jti"])
				assert.Equal(t, grantOf(t, x, c).Family.String(), claims["gid"], "R4: it names its grant")
				assert.Equal(t, unixOf(c.signIn.AuthenticatedAt), claims["auth_time"])
				assert.Equal(t, "urn:example:mfa", claims["acr"])
				assert.Equal(t, []any{"pwd", "otp"}, claims["amr"])
				assert.NotContains(t, claims, "cnf")
			},
		},
		{
			name: "a sign-in with no amr or acr carries none",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				signIn := testSignIn(x.parkFixture, "u-1")
				signIn.AMR, signIn.ACR = nil, ""
				c := issueCodeFor(t, x.parkFixture, "billing-web", nil, signIn, "openid", "profile")

				return c, billingExchange(c, nil)
			},
			assert: func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				_, claims := decodeJWT(t, res.AccessToken)
				assert.NotContains(t, claims, "amr")
				assert.NotContains(t, claims, "acr")
			},
		},
		{
			name: "AccessTokenLifetime of 15 minutes, signed with the client's algorithm",
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
				assert.Equal(t, 900, res.ExpiresIn)
				header, claims := decodeJWT(t, res.AccessToken)
				assert.Equal(t, "ES256", header["alg"])
				assert.Equal(t, unixOf(x.clk.Now().Add(15*time.Minute)), claims["exp"])
			},
		},
		audience("the default audience alone, without openid", "api.read", nil, nil, []string{defaultAudience}),
		audience("R4: the default audience plus the issuer, for an openid token", "openid", nil, nil, []string{defaultAudience, issuer}),
		audience("a resource the client may ask for, of a code granted none", "openid", nil,
			[]string{ordersResource}, []string{ordersResource}),
		audience("R15: a resource narrows to what is asked, and the grant stays whole", "openid",
			[]string{ordersResource, invoiceResource}, []string{invoiceResource}, []string{invoiceResource}),
		audience("several resources are all carried, a repeat once and an empty one not at all", "openid",
			[]string{ordersResource, invoiceResource},
			[]string{ordersResource, "", invoiceResource, ordersResource}, []string{ordersResource, invoiceResource}),
		audience("a resource given empty counts as omitted", "api.read", nil, []string{""}, []string{defaultAudience}),
		{
			name: "R4: a default audience already naming the issuer does not repeat it",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, issuerAudienceClient, func(v url.Values) {
					asClient(v, issuerAudienceClient, issuerAudienceRedirect)
					v.Set("scope", "openid")
				}, testSignIn(x.parkFixture, "u-1"), "openid")

				return c, confidentialExchange(issuerAudienceClient, issuerAudienceRedirect, c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, []string{issuer, defaultAudience}, audienceOf(t, x, res))
			},
		},
		{
			name: "none configured: the issuer, once",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueCodeFor(t, x.parkFixture, "code-only", func(v url.Values) {
					asClient(v, "code-only", "https://code-only.example.com/cb")
				}, testSignIn(x.parkFixture, "u-1"), "openid", "profile")

				return c, confidentialExchange("code-only", "https://code-only.example.com/cb", c, nil)
			},
			assert: func(t *testing.T, x *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, []string{issuer}, audienceOf(t, x, res))
			},
		},
		refusedThenExchanges("R18: a resource outside the allowlist is invalid_target, unspent",
			oidcprovider.CodeInvalidTarget, "https://nowhere.example.com"),
		refusedThenExchanges("R15: a resource allowed but not granted is invalid_target, unspent",
			oidcprovider.CodeInvalidTarget, otherResource),
		refusedThenExchanges("one bad resource among good ones is invalid_target, unspent",
			oidcprovider.CodeInvalidTarget, ordersResource, otherResource),
		refusedThenExchanges("more resources than are read is invalid_request, unspent",
			oidcprovider.CodeInvalidRequest, strings.Split(strings.Repeat(ordersResource+" ", 11), " ")[:11]...),
		{
			name: "a code granted none still holds a resource to the allowlist",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueAudience(t, x, "openid")

				return c, audienceExchange(c, "https://nowhere.example.com")
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidTarget)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)
			},
		},
		audience("R15: one resource granted, none named: exactly it, with no issuer, even for openid", "openid",
			[]string{ordersResource}, nil, []string{ordersResource}),
		audience("R15: one resource granted, none named, without openid: it, and not the default audience", "api.read",
			[]string{ordersResource}, nil, []string{ordersResource}),
		audience("R15: one resource granted, only empty values named: as if none were", "openid",
			[]string{ordersResource}, []string{""}, []string{ordersResource}),
		{
			name: "R15: several resources granted, none named, is invalid_target; the code stays unspent and naming one exchanges",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueAudience(t, x, "openid", ordersResource, invoiceResource)

				return c, audienceExchange(c)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidTarget)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)

				res, err = x.p.Token(t.Context(), audienceExchange(c, invoiceResource))
				require.NoError(t, err, "the refusal left the code unspent")
				assert.Equal(t, []string{invoiceResource}, audienceOf(t, x, res))
			},
		},
		{
			name: "R15: several resources granted may all be named at the token endpoint",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueAudience(t, x, "openid", ordersResource, invoiceResource)

				return c, audienceExchange(c, ordersResource, invoiceResource)
			},
			assert: func(t *testing.T, x *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, []string{ordersResource, invoiceResource}, audienceOf(t, x, res))
			},
		},
		{
			name: "exactly 10 resource values are read, repeats counting once",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueAudience(t, x, "openid")

				return c, audienceExchange(c, slices.Repeat([]string{ordersResource}, 10)...)
			},
			assert: func(t *testing.T, x *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, []string{ordersResource}, audienceOf(t, x, res))
			},
		},
		{
			name: "where two refusals compete, the bindings are judged before the resource",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueAudience(t, x, "openid")

				return c, confidentialExchange(audienceClient, audienceRedirect, c, func(v url.Values) {
					v.Set("redirect_uri", "https://elsewhere.example.com/cb")
					v["resource"] = []string{"https://nowhere.example.com"}
				})
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)
			},
		},
		{
			name: "where two refusals compete, the resource is judged before the sign-in's end",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				signIn := testSignIn(x.parkFixture, "u-1")
				signIn.AbsoluteExpiresAt = x.clk.Now().Add(30 * time.Second)
				c := issueCodeFor(t, x.parkFixture, audienceClient, func(v url.Values) {
					asClient(v, audienceClient, audienceRedirect)
					v.Set("scope", "openid")
				}, signIn, "openid")
				x.clk.Advance(45 * time.Second)

				return c, audienceExchange(c, "https://nowhere.example.com")
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidTarget)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)

				_, err = x.p.Token(t.Context(), audienceExchange(c))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			},
		},
		{
			name: "where two refusals compete, the resource is judged before a disabled user",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueAudience(t, x, "openid")
				x.users.set(func(u *exchangeUsers) { u.disabled["u-1"] = true })

				return c, audienceExchange(c, "https://nowhere.example.com")
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidTarget)
				assert.Nil(t, res)
				assertNothingWritten(t, x, c)

				_, err = x.p.Token(t.Context(), audienceExchange(c))
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
			},
		},
		malformed("a JWT client's malformed jkt", jwtClient, oidcprovider.Binding{JKT: "not-a-thumbprint"}),
		malformed("an opaque client's malformed jkt, as a JWT client's", opaqueClientRequest, oidcprovider.Binding{JKT: "not-a-thumbprint"}),
		malformed("an opaque client's malformed certificate thumbprint", opaqueClientRequest, oidcprovider.Binding{X5T: "short"}),
		malformed("a public client's malformed jkt is never kept as its grant's key", publicClient, oidcprovider.Binding{JKT: "not-a-thumbprint"}),
		bound("no binding is no cnf, and Bearer", oidcprovider.Binding{}, "Bearer", nil),
		bound("a proof's key is cnf.jkt, and DPoP", oidcprovider.Binding{JKT: boundJKT}, "DPoP", map[string]any{"jkt": boundJKT}),
		bound("a certificate is cnf.x5t#S256, and Bearer", oidcprovider.Binding{X5T: boundX5T}, "Bearer", map[string]any{"x5t#S256": boundX5T}),
		bound("a proof with a certificate is cnf.jkt alone", oidcprovider.Binding{JKT: boundJKT, X5T: boundX5T}, "DPoP", map[string]any{"jkt": boundJKT}),
		{
			name: "an opaque client gets at.<id>.<secret>, stored as a digest after the grant and lineage",
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueOpaque(t, x)
				req := opaqueExchange(c)
				req.Binding = oidcprovider.Binding{JKT: boundJKT}

				return c, req
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, "DPoP", res.TokenType)
				assert.Equal(t, 300, res.ExpiresIn)
				assert.NotEmpty(t, res.IDToken, "an opaque client's ID token is still a JWT")

				tokenID, secret := opaqueParts(t, res.AccessToken)
				raw, err := base64.RawURLEncoding.DecodeString(secret)
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(raw), 16, "at least 128 bits")

				record, err := x.p.AccessTokensForTest().Load(t.Context(), tokenID)
				require.NoError(t, err)
				digest := sha256.Sum256(raw)
				assert.Equal(t, digest[:], record.Digest, "the secret is held only as its digest")
				assert.Equal(t, grantOf(t, x, c).Family, record.GrantFamily)
				assert.Equal(t, opaqueClient, record.ClientID)
				assert.Equal(t, identity.UserID("u-1"), record.User)
				assert.Equal(t, []string{"openid"}, record.Scopes)
				assert.Equal(t, []string{issuer}, record.Audience)
				assert.Equal(t, map[string]string{"jkt": boundJKT}, record.Confirmation)
				assert.True(t, record.IssuedAt.Equal(x.clk.Now()))
				assert.True(t, record.ExpiresAt.Equal(x.clk.Now().Add(5*time.Minute)))
			},
		},
		{
			name: "R18: an opaque token that cannot be stored is a dependency failure, after the spend",
			opts: opaqueStoreFailing,
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueOpaque(t, x)

				return c, opaqueExchange(c)
			},
			assert: func(t *testing.T, x *exchangeFixture, c issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
				assertSpent(t, x, c)
				assert.False(t, grantOf(t, x, c).Revoked)
				assert.Equal(t, 1, x.p.LineageHeldForTest(), "the row and the lineage came first")
			},
		},
		{
			name: "R18: a grant that cannot be written stores no opaque token",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				grants := NewMockGrantStore(gomock.NewController(t))
				grants.EXPECT().UseCodes(gomock.Any()).Return(nil).AnyTimes()
				grants.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, oidcprovider.ErrNotFound).AnyTimes()
				grants.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage)

				store := NewMockAccessTokenStore(gomock.NewController(t))

				return []oidcprovider.Option{oidcprovider.WithGrantStore(grants), oidcprovider.WithAccessTokenStore(store)}
			},
			arrange: func(t *testing.T, x *exchangeFixture) (issuedCode, oidcprovider.TokenRequest) {
				t.Helper()
				c := issueOpaque(t, x)

				return c, opaqueExchange(c)
			},
			assert: func(t *testing.T, _ *exchangeFixture, _ issuedCode, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertDependencyFailure(t, err)
				assert.Nil(t, res)
			},
		},
	}

	runTokenRows(t, rows)
}

// nilIfEmpty reads an empty list as the nil a row writes for none.
func nilIfEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	return values
}

// failingRandom answers from crypto/rand until told to fail.
type failingRandom struct{ failing func() bool }

func (r failingRandom) Read(b []byte) (int, error) {
	if r.failing() {
		return 0, errOutage
	}

	return rand.Read(b)
}

// mintedFor is an access token signed under the provider's keys and issuer, as nothing but
// the provider should, for a row about what VerifyAccessToken makes of its claims.
func mintedFor(t *testing.T, x *exchangeFixture, typ string, change func(*token.Issue)) string {
	t.Helper()

	issuing, err := token.NewIssuer(x.keys, signingkey.RS256, issuer, token.WithClock(x.clk))
	require.NoError(t, err)
	in := token.Issue{
		Type: typ, Subject: "u-1", ID: "jti-1", Audience: []string{issuer},
		Claims: map[string]any{"client_id": "billing-web", "scope": "openid"},
	}
	change(&in)
	raw, err := issuing.Issue(t.Context(), in)
	require.NoError(t, err)

	return raw
}

// liveGrantFamily is the family of a live billing-web grant.
func liveGrantFamily(t *testing.T, x *exchangeFixture) id.ID {
	t.Helper()

	c := x.issue(t)
	_, err := x.p.Token(t.Context(), billingExchange(c, nil))
	require.NoError(t, err)

	return grantOf(t, x, c).Family
}

func TestProvider_AccessToken_Verify(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    func(*testing.T) []oidcprovider.Option
		ctx     func(context.Context) context.Context
		arrange func(*testing.T, *exchangeFixture) string
		assert  func(*testing.T, *exchangeFixture, *oidcprovider.AccessToken, error)
	}

	refused := func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
		t.Helper()
		assertRefused(t, err, oidcprovider.CodeInvalidToken)
		assert.Nil(t, at)
	}
	dependencyFailed := func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
		t.Helper()
		assertDependencyFailure(t, err)
		assert.NotErrorIs(t, err, context.Canceled)
		assert.Nil(t, at)
	}
	hungUp := func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
		t.Helper()
		require.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, oidcprovider.ErrDependency)
		assert.Nil(t, at)
	}
	cancelled := func(ctx context.Context) context.Context {
		ctx, cancel := context.WithCancel(ctx)
		cancel()

		return ctx
	}

	// exchanged is a live billing-web response.
	exchanged := func(t *testing.T, x *exchangeFixture) (*oidcprovider.TokenResponse, issuedCode) {
		t.Helper()
		c := x.issue(t)
		res, err := x.p.Token(t.Context(), billingExchange(c, nil))
		require.NoError(t, err)

		return res, c
	}
	// exchangedOpaque is a live opaque-app response.
	exchangedOpaque := func(t *testing.T, x *exchangeFixture) (*oidcprovider.TokenResponse, issuedCode) {
		t.Helper()
		c := issueOpaque(t, x)
		res, err := x.p.Token(t.Context(), opaqueExchange(c))
		require.NoError(t, err)

		return res, c
	}
	revoke := func(t *testing.T, x *exchangeFixture, c issuedCode) id.ID {
		t.Helper()
		family := grantOf(t, x, c).Family
		require.NoError(t, x.p.GrantsForTest().Revoke(t.Context(), family, oidcprovider.CauseCodeReplay, x.clk.Now()))

		return family
	}
	// sweep forgets every revoked grant, as the expiry task eventually does.
	sweep := func(t *testing.T, x *exchangeFixture) {
		t.Helper()
		_, err := x.p.GrantsForTest().DeleteExpired(t.Context(), x.clk.Now().Add(100*24*time.Hour), time.Second)
		require.NoError(t, err)
	}
	// withGrant is a token naming family, with any further change.
	withGrant := func(t *testing.T, x *exchangeFixture, family id.ID, change func(*token.Issue)) string {
		t.Helper()

		return mintedFor(t, x, token.TypeAccessToken, func(in *token.Issue) {
			in.Claims["gid"] = family.String()
			if change != nil {
				change(in)
			}
		})
	}
	// failingGrants is a grant store whose reads answer read.
	failingGrants := func(read func(context.Context) error) func(*testing.T) []oidcprovider.Option {
		return func(t *testing.T) []oidcprovider.Option {
			t.Helper()
			grants := NewMockGrantStore(gomock.NewController(t))
			grants.EXPECT().UseCodes(gomock.Any()).Return(nil).AnyTimes()
			grants.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, _ id.ID) (*oidcprovider.Grant, error) { return nil, read(ctx) },
			)

			return []oidcprovider.Option{oidcprovider.WithGrantStore(grants)}
		}
	}
	// failingTokens is an opaque token store whose reads answer read.
	failingTokens := func(read func(context.Context) error) func(*testing.T) []oidcprovider.Option {
		return func(t *testing.T) []oidcprovider.Option {
			t.Helper()
			store := NewMockAccessTokenStore(gomock.NewController(t))
			store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, _ id.ID) (*oidcprovider.AccessTokenRecord, error) { return nil, read(ctx) },
			)

			return []oidcprovider.Option{oidcprovider.WithAccessTokenStore(store)}
		}
	}
	anyGrant := func(t *testing.T, x *exchangeFixture) string {
		t.Helper()
		family, err := id.NewV7Generator().NewID()
		require.NoError(t, err)

		return withGrant(t, x, family, nil)
	}
	anyOpaque := func(t *testing.T, _ *exchangeFixture) string {
		t.Helper()
		family, err := id.NewV7Generator().NewID()
		require.NoError(t, err)

		return "at." + family.String() + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	}
	// storedOpaque writes a record straight to the store, and returns its token.
	storedOpaque := func(t *testing.T, x *exchangeFixture, family id.ID, change func(*oidcprovider.AccessTokenRecord)) string {
		t.Helper()
		tokenID, err := id.NewV7Generator().NewID()
		require.NoError(t, err)
		raw := make([]byte, 32)
		digest := sha256.Sum256(raw)
		record := &oidcprovider.AccessTokenRecord{
			ID: tokenID, Digest: digest[:], GrantFamily: family, ClientID: "billing-web", User: "u-1",
			Scopes: []string{"openid"}, Audience: []string{issuer},
			IssuedAt: x.clk.Now(), ExpiresAt: x.clk.Now().Add(time.Minute),
		}
		if change != nil {
			change(record)
		}
		require.NoError(t, x.p.AccessTokensForTest().Create(t.Context(), record))

		return "at." + tokenID.String() + "." + base64.RawURLEncoding.EncodeToString(raw)
	}
	literal := func(raw string) func(*testing.T, *exchangeFixture) string {
		return func(*testing.T, *exchangeFixture) string { return raw }
	}

	// crafted is a JWT signed as the provider signs, with every claim it always puts there,
	// for change to take away or alter: nothing but the provider should be able to make one.
	crafted := func(change func(claims map[string]any)) func(*testing.T, *exchangeFixture) string {
		return func(t *testing.T, x *exchangeFixture) string {
			t.Helper()

			return signedAccess(t, x, liveGrantFamily(t, x), change)
		}
	}
	// noLookup holds a token store that must not be asked, so a call fails the case.
	noLookup := func(t *testing.T) []oidcprovider.Option {
		t.Helper()

		return []oidcprovider.Option{oidcprovider.WithAccessTokenStore(NewMockAccessTokenStore(gomock.NewController(t)))}
	}
	// sized is a token of size bytes, within a few, whose request bounds are tight.
	sized := func(size int) func(*testing.T, *exchangeFixture) string {
		return func(t *testing.T, x *exchangeFixture) string {
			t.Helper()

			return tokenOfSize(t, x, liveGrantFamily(t, x), size)
		}
	}
	tightBounds := func(t *testing.T) []oidcprovider.Option {
		t.Helper()

		return []oidcprovider.Option{oidcprovider.WithRequestBounds(oidcprovider.RequestBounds{Resource: 256, Scope: 256})}
	}

	// leavingAtGrantRead is a caller leaving once the JWT has verified, during its grant's read.
	leavingAtGrantRead := func() testCase {
		var leave context.CancelFunc

		return testCase{
			name: "a caller leaving during the grant's read is a hang-up",
			opts: failingGrants(func(ctx context.Context) error {
				leave()

				return ctx.Err()
			}),
			ctx: func(ctx context.Context) context.Context {
				left, cancel := context.WithCancelCause(ctx)
				leave = func() { cancel(nil) }

				return left
			},
			arrange: anyGrant,
			assert:  hungUp,
		}
	}

	cases := []testCase{
		{
			name: "a JWT states what it was minted with",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				c := x.issue(t)
				req := billingExchange(c, nil)
				req.Binding = oidcprovider.Binding{JKT: boundJKT}
				res, err := x.p.Token(t.Context(), req)
				require.NoError(t, err)

				return res.AccessToken
			},
			assert: func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), at.Subject)
				assert.Equal(t, "billing-web", at.ClientID)
				assert.Equal(t, []string{"openid", "profile"}, at.Scopes)
				assert.Equal(t, []string{issuer}, at.Audience)
				assert.Equal(t, map[string]string{"jkt": boundJKT}, at.Confirmation)
				assert.False(t, at.Opaque)
				assert.NotEqual(t, id.Nil, at.GrantFamily)
			},
		},
		{
			name: "a JWT bound to a certificate names it, and an unbound one nothing",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				c := x.issue(t)
				req := billingExchange(c, nil)
				req.Binding = oidcprovider.Binding{X5T: boundX5T}
				res, err := x.p.Token(t.Context(), req)
				require.NoError(t, err)

				return res.AccessToken
			},
			assert: func(t *testing.T, x *exchangeFixture, at *oidcprovider.AccessToken, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"x5t#S256": boundX5T}, at.Confirmation)

				res, _ := exchanged(t, x)
				unbound, err := x.p.VerifyAccessToken(t.Context(), res.AccessToken)
				require.NoError(t, err)
				assert.Empty(t, unbound.Confirmation)
			},
		},
		{
			name: "an opaque token states what its record holds",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchangedOpaque(t, x)

				return res.AccessToken
			},
			assert: func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, identity.UserID("u-1"), at.Subject)
				assert.Equal(t, opaqueClient, at.ClientID)
				assert.Equal(t, []string{"openid"}, at.Scopes)
				assert.Equal(t, []string{issuer}, at.Audience)
				assert.True(t, at.Opaque)
				assert.NotEqual(t, id.Nil, at.GrantFamily)
			},
		},
		{
			name: "the largest token a request can ask for still verifies",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				family := liveGrantFamily(t, x)
				audiences := make([]string, 10)
				for i := range audiences {
					audiences[i] = fmt.Sprintf("https://%d.example.com/%s", i, strings.Repeat("a", 2000))
				}

				return withGrant(t, x, family, func(in *token.Issue) {
					in.Audience = audiences
					in.Claims["scope"] = strings.Repeat("s", 4096)
				})
			},
			assert: func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Len(t, at.Audience, 10)
			},
		},
		{name: "an empty value", arrange: literal(""), assert: refused},
		{name: "text that is no token", arrange: literal("not a token"), assert: refused},
		{
			name: "a value too large to look at",
			arrange: func(_ *testing.T, _ *exchangeFixture) string {
				return strings.Repeat("a", 1<<20) + ".b.c"
			},
			assert: refused,
		},
		{
			name: "an ID token",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchanged(t, x)

				return res.IDToken
			},
			assert: refused,
		},
		{
			name: "a refresh token",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchanged(t, x)
				require.NotEmpty(t, res.RefreshToken)

				return res.RefreshToken
			},
			assert: refused,
		},
		{
			name: "a code",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return x.issue(t).code
			},
			assert: refused,
		},
		{
			name: "a logout token under the same keys and claims",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				family := liveGrantFamily(t, x)

				return mintedFor(t, x, token.TypeLogoutToken, func(in *token.Issue) { in.Claims["gid"] = family.String() })
			},
			assert: refused,
		},
		{
			name: "a first-party token under the same keys and claims",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				family := liveGrantFamily(t, x)

				return signed(t, signingkey.RS256, testRSAKey(), map[string]any{"kid": rsKid, "typ": token.TypeFirstParty}, map[string]any{
					"iss": issuer, "sub": "u-1", "aud": issuer, "jti": "j", "client_id": "billing-web", "scope": "openid",
					"gid": family.String(), "exp": x.clk.Now().Add(time.Minute).Unix(), "iat": x.clk.Now().Unix(),
				})
			},
			assert: refused,
		},
		{
			name: "another issuer's token under the same keys",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				family := liveGrantFamily(t, x)
				other, err := token.NewIssuer(x.keys, signingkey.RS256, "https://elsewhere.example.com", token.WithClock(x.clk))
				require.NoError(t, err)
				raw, err := other.Issue(t.Context(), token.Issue{
					Type: token.TypeAccessToken, Subject: "u-1", ID: "j", Audience: []string{issuer},
					Claims: map[string]any{"client_id": "billing-web", "scope": "openid", "gid": family.String()},
				})
				require.NoError(t, err)

				return raw
			},
			assert: refused,
		},
		{
			name: "a JWT past its expiry",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchanged(t, x)
				x.clk.Advance(6 * time.Minute)

				return res.AccessToken
			},
			assert: refused,
		},
		{
			name: "a JWT naming no grant",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return mintedFor(t, x, token.TypeAccessToken, func(*token.Issue) {})
			},
			assert: refused,
		},
		{
			name: "a JWT whose gid is no identifier",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return mintedFor(t, x, token.TypeAccessToken, func(in *token.Issue) { in.Claims["gid"] = "nope" })
			},
			assert: refused,
		},
		{
			name: "a JWT whose gid is no identifier makes no lookup",
			opts: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				grants := NewMockGrantStore(gomock.NewController(t))
				grants.EXPECT().UseCodes(gomock.Any()).Return(nil).AnyTimes()

				return []oidcprovider.Option{oidcprovider.WithGrantStore(grants)}
			},
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return mintedFor(t, x, token.TypeAccessToken, func(in *token.Issue) { in.Claims["gid"] = "nope" })
			},
			assert: refused,
		},
		{
			name: "a JWT whose gid is not a string",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return mintedFor(t, x, token.TypeAccessToken, func(in *token.Issue) { in.Claims["gid"] = 7 })
			},
			assert: refused,
		},
		{
			name: "a JWT naming no client",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return withGrant(t, x, liveGrantFamily(t, x), func(in *token.Issue) { delete(in.Claims, "client_id") })
			},
			assert: refused,
		},
		{
			name: "a JWT whose scope is not a string",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return withGrant(t, x, liveGrantFamily(t, x), func(in *token.Issue) { in.Claims["scope"] = 7 })
			},
			assert: refused,
		},
		{
			name: "a JWT naming another client than its grant holds",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return withGrant(t, x, liveGrantFamily(t, x), func(in *token.Issue) { in.Claims["client_id"] = "code-only" })
			},
			assert: refused,
		},
		{
			name: "a JWT naming another user than its grant is for",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return withGrant(t, x, liveGrantFamily(t, x), func(in *token.Issue) { in.Subject = "u-2" })
			},
			assert: refused,
		},
		{
			name: "a JWT bound by a confirmation it cannot honour",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				family := liveGrantFamily(t, x)

				return signed(t, signingkey.RS256, testRSAKey(), map[string]any{"kid": rsKid, "typ": token.TypeAccessToken}, map[string]any{
					"iss": issuer, "sub": "u-1", "aud": issuer, "jti": "j", "client_id": "billing-web", "scope": "openid",
					"gid": family.String(), "exp": x.clk.Now().Add(time.Minute).Unix(), "iat": x.clk.Now().Unix(),
					"cnf": map[string]any{"kid": "someone-else"},
				})
			},
			assert: refused,
		},
		{
			name: "a JWT of a revoked grant",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, c := exchanged(t, x)
				revoke(t, x, c)

				return res.AccessToken
			},
			assert: refused,
		},
		{
			name: "a JWT whose grant row is gone, revoked and swept, though it has not expired",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, c := exchanged(t, x)
				family := revoke(t, x, c)
				sweep(t, x)
				_, err := x.p.GrantsForTest().Load(t.Context(), family)
				require.ErrorIs(t, err, oidcprovider.ErrNotFound)

				return res.AccessToken
			},
			assert: refused,
		},
		{
			name: "a JWT whose grant has expired",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				signIn := testSignIn(x.parkFixture, "u-1")
				signIn.AbsoluteExpiresAt = x.clk.Now().Add(2 * time.Minute)
				c := issueCodeFor(t, x.parkFixture, "code-only", func(v url.Values) {
					asClient(v, "code-only", "https://code-only.example.com/cb")
				}, signIn, "openid", "profile")
				res, err := x.p.Token(t.Context(), confidentialExchange("code-only", "https://code-only.example.com/cb", c, nil))
				require.NoError(t, err)
				x.clk.Advance(2 * time.Minute)

				return res.AccessToken
			},
			assert: refused,
		},
		{
			name: "an opaque token of a revoked grant",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, c := exchangedOpaque(t, x)
				revoke(t, x, c)

				return res.AccessToken
			},
			assert: refused,
		},
		{
			name: "an opaque token written after its grant was revoked",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				_, c := exchanged(t, x)

				return storedOpaque(t, x, revoke(t, x, c), nil)
			},
			assert: refused,
		},
		{
			name: "an opaque token whose grant row is gone",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, c := exchangedOpaque(t, x)
				revoke(t, x, c)
				sweep(t, x)

				return res.AccessToken
			},
			assert: refused,
		},
		{
			name: "an opaque token past its expiry",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchangedOpaque(t, x)
				x.clk.Advance(5 * time.Minute)

				return res.AccessToken
			},
			assert: refused,
		},
		{
			name: "an opaque token revoked alone",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchangedOpaque(t, x)
				tokenID, _ := opaqueParts(t, res.AccessToken)
				require.NoError(t, x.p.AccessTokensForTest().Revoke(t.Context(), tokenID))

				return res.AccessToken
			},
			assert: refused,
		},
		{
			name: "an opaque token naming another client than its grant holds",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()

				return storedOpaque(t, x, liveGrantFamily(t, x), func(r *oidcprovider.AccessTokenRecord) { r.ClientID = "code-only" })
			},
			assert: refused,
		},
		{
			name: "an opaque token with a secret never issued",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchangedOpaque(t, x)
				tokenID, _ := opaqueParts(t, res.AccessToken)

				return "at." + tokenID.String() + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			},
			assert: refused,
		},
		{name: "an opaque token no record holds", arrange: anyOpaque, assert: refused},
		{name: "an opaque form with no secret", arrange: anyOpaqueNoSecret, assert: refused},
		{name: "an opaque form with a bad identifier", arrange: literal("at.nope." + strings.Repeat("A", 43)), assert: refused},
		{
			name: "an opaque form whose secret is of no shape the provider mints",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchangedOpaque(t, x)
				tokenID, _ := opaqueParts(t, res.AccessToken)

				return "at." + tokenID.String() + ".short"
			},
			assert: refused,
		},
		{
			name: "an opaque token bound to a key states it",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				c := issueOpaque(t, x)
				req := opaqueExchange(c)
				req.Binding = oidcprovider.Binding{JKT: boundJKT}
				res, err := x.p.Token(t.Context(), req)
				require.NoError(t, err)

				return res.AccessToken
			},
			assert: func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, at.Opaque)
				assert.Equal(t, map[string]string{"jkt": boundJKT}, at.Confirmation, "read back bound, never as unbound")
			},
		},
		{
			name: "an opaque token bound to a certificate states it",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				c := issueOpaque(t, x)
				req := opaqueExchange(c)
				req.Binding = oidcprovider.Binding{X5T: boundX5T}
				res, err := x.p.Token(t.Context(), req)
				require.NoError(t, err)

				return res.AccessToken
			},
			assert: func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"x5t#S256": boundX5T}, at.Confirmation)
			},
		},
		{name: "control: a crafted JWT with every claim the provider puts there", arrange: crafted(nil), assert: func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, []string{issuer}, at.Audience)
		}},
		{name: "a JWT with no aud, which the provider always sets", arrange: crafted(func(c map[string]any) { delete(c, "aud") }), assert: refused},
		{name: "a JWT with an empty aud", arrange: crafted(func(c map[string]any) { c["aud"] = []string{} }), assert: refused},
		{name: "a JWT with no iat, which the provider always sets", arrange: crafted(func(c map[string]any) { delete(c, "iat") }), assert: refused},
		{name: "a JWT with no jti, which the provider always sets", arrange: crafted(func(c map[string]any) { delete(c, "jti") }), assert: refused},
		{name: "a JWT with no sub, which the provider always sets", arrange: crafted(func(c map[string]any) { delete(c, "sub") }), assert: refused},
		{
			name: "a JWT bound to a DPoP key and a certificate at once, one of which would be dropped",
			arrange: crafted(func(c map[string]any) {
				c["cnf"] = map[string]any{"jkt": boundJKT, "x5t#S256": boundX5T}
			}),
			assert: refused,
		},
		{
			name: "an opaque token with the identifier spelt in capitals is refused, as it has one spelling",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchangedOpaque(t, x)
				tokenID, secret := opaqueParts(t, res.AccessToken)
				capitals := strings.ToUpper(tokenID.String())
				require.NotEqual(t, tokenID.String(), capitals)

				return "at." + capitals + "." + secret
			},
			assert: refused,
		},
		{
			name:    "an opaque value with the identifier in capitals makes no lookup",
			opts:    noLookup,
			arrange: literal("at.0192F3A4-B5C6-7D8E-9FA0-B1C2D3E4F5A6." + strings.Repeat("A", 43)),
			assert:  refused,
		},
		{
			name:    "an opaque value with a bad identifier makes no lookup",
			opts:    noLookup,
			arrange: literal("at.nope." + strings.Repeat("A", 43)),
			assert:  refused,
		},
		{
			name:    "an opaque value with a secret of no shape the provider mints makes no lookup",
			opts:    noLookup,
			arrange: literal("at.0192f3a4-b5c6-7d8e-9fa0-b1c2d3e4f5a6.short"),
			assert:  refused,
		},
		{
			name:    "an opaque value with a secret too long makes no lookup",
			opts:    noLookup,
			arrange: literal("at.0192f3a4-b5c6-7d8e-9fa0-b1c2d3e4f5a6." + strings.Repeat("A", 44)),
			assert:  refused,
		},
		{
			name:    "an opaque value with no secret makes no lookup",
			opts:    noLookup,
			arrange: literal("at.0192f3a4-b5c6-7d8e-9fa0-b1c2d3e4f5a6."),
			assert:  refused,
		},
		{
			name:    "a token at the verifier's bound still verifies",
			opts:    tightBounds,
			arrange: sized(13824),
			assert: func(t *testing.T, _ *exchangeFixture, at *oidcprovider.AccessToken, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, at)
			},
		},
		{
			name:    "a token just past the verifier's bound is refused, whatever it is signed by",
			opts:    tightBounds,
			arrange: sized(13824 + 8),
			assert:  refused,
		},
		{
			name:    "a grant store failing is a dependency failure, not an invalid token",
			opts:    failingGrants(func(context.Context) error { return errOutage }),
			arrange: anyGrant,
			assert:  dependencyFailed,
		},
		leavingAtGrantRead(),
		{
			name:    "an opaque store failing is a dependency failure, not an invalid token",
			opts:    failingTokens(func(context.Context) error { return errOutage }),
			arrange: anyOpaque,
			assert:  dependencyFailed,
		},
		{
			name:    "a caller leaving during the opaque read is a hang-up",
			opts:    failingTokens(func(ctx context.Context) error { return ctx.Err() }),
			ctx:     cancelled,
			arrange: anyOpaque,
			assert:  hungUp,
		},
		{
			name: "a key source failing is a dependency failure, not an invalid token",
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchanged(t, x)
				x.keys.failVerifying(func(context.Context) error { return errOutage })

				return res.AccessToken
			},
			assert: dependencyFailed,
		},
		{
			name: "a caller leaving during the keys' read is a hang-up",
			ctx:  cancelled,
			arrange: func(t *testing.T, x *exchangeFixture) string {
				t.Helper()
				res, _ := exchanged(t, x)
				x.keys.failVerifying(func(ctx context.Context) error { return ctx.Err() })

				return res.AccessToken
			},
			assert: hungUp,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opts []oidcprovider.Option
			if tc.opts != nil {
				opts = tc.opts(t)
			}
			x := newExchangeFixture(t, opts...)
			raw := tc.arrange(t, x)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			at, err := x.p.VerifyAccessToken(ctx, raw)
			tc.assert(t, x, at, err)

			if err != nil && raw != "" {
				assert.NotContains(t, err.Error(), raw, "no error carries the token")
			}
			if raw != "" {
				assert.NotContains(t, x.logs.String(), raw, "no log line carries the token")
			}
		})
	}
}

// signedAccess is an access token signed as the provider signs one, claim by claim, so a row can
// take one away. It names family, and every claim the provider always sets.
func signedAccess(t *testing.T, x *exchangeFixture, family id.ID, change func(claims map[string]any)) string {
	t.Helper()

	claims := map[string]any{
		"iss": issuer, "sub": "u-1", "aud": []string{issuer}, "jti": "j", "client_id": "billing-web",
		"scope": "openid", "gid": family.String(),
		"exp": x.clk.Now().Add(time.Minute).Unix(), "iat": x.clk.Now().Unix(),
	}
	if change != nil {
		change(claims)
	}

	return signed(t, signingkey.RS256, testRSAKey(), map[string]any{"kid": rsKid, "typ": token.TypeAccessToken}, claims)
}

// tokenOfSize is a signed access token of the given size, give or take a few bytes below it,
// made by padding its scope. It converges on the size from the token's own length.
func tokenOfSize(t *testing.T, x *exchangeFixture, family id.ID, size int) string {
	t.Helper()

	pad := size / 2
	for range 20 {
		raw := signedAccess(t, x, family, func(c map[string]any) { c["scope"] = strings.Repeat("s", pad) })
		over := len(raw) - size
		if over <= 0 && over > -4 {
			return raw
		}
		// Base64 carries three bytes of JSON in four of token.
		step := over * 3 / 4
		if step == 0 {
			step = over / max(over, -over)
		}
		pad -= step
	}
	require.FailNow(t, "no token of the size", "wanted %d", size)

	return ""
}

// anyOpaqueNoSecret is the opaque form with its secret left out.
func anyOpaqueNoSecret(t *testing.T, _ *exchangeFixture) string {
	t.Helper()

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return "at." + family.String() + "."
}

// TestProvider_AccessToken_RandomFailure pins R18 for an opaque token, whose value is drawn
// from the random source: running dry before the spend leaves the code unspent.
func TestProvider_AccessToken_RandomFailure(t *testing.T) {
	t.Parallel()

	var failing bool
	x := newExchangeFixture(t, oidcprovider.WithRandom(failingRandom{failing: func() bool { return failing }}))
	c := issueOpaque(t, x)
	failing = true

	res, err := x.p.Token(t.Context(), opaqueExchange(c))
	assertDependencyFailure(t, err)
	assert.Nil(t, res)
	assertNothingWritten(t, x, c)

	failing = false
	_, err = x.p.Token(t.Context(), opaqueExchange(c))
	require.NoError(t, err)
}
