package httpsecconformance

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// subjectScenarios pin the token subject a real generator writes against a chain
// in its default mode, which the fixture generator the other rows use cannot:
// it is a stand-in chosen to agree with the bearer.
func subjectScenarios() []Scenario {
	return []Scenario{
		issuedTokensAuthenticate(),
		loginWithNoIdentifier("a default chain", defaultNoIdentifierSpec),
		loginWithNoIdentifier("a chain configured to use usernames", usernameNoIdentifierSpec),
		loginWithNoIdentifier("session references", referenceNoIdentifierSpec),
	}
}

// defaultGenerator is the library's own generator with its defaults.
func defaultGenerator(t *testing.T) *token.JWTGenerator {
	t.Helper()

	keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))

	return must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience()))
}

// signedTokenSpec is a default chain over the library's generator: form login
// through authn, session renewal and the signed bearer.
func signedTokenSpec(t *testing.T, authn authenticate.Authenticator) ChainSpec {
	t.Helper()

	effects := newEffects(t)
	gen := defaultGenerator(t)

	return ChainSpec{
		Options: []httpsec.Option{
			httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: authn, Sessions: effects.Sessions, Tokens: gen, Attempts: effects.Attempts,
			}),
			httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: fixtureUsers{}, Tokens: gen}),
			httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
				Verifier: gen, Sessions: effects.Sessions, Users: fixtureUsers{},
			}),
		},
		Effects: effects,
		Routes:  plainRoute(),
	}
}

// issuedTokensAuthenticate pins spec http-security-chain "Every issued token
// authenticates on a default chain" for the two endpoints every adapter can
// reach without further fixtures, login and renewal. The library's own suite
// walks all eight issuing endpoints through the same check.
func issuedTokensAuthenticate() Scenario {
	return Scenario{
		Name: "a token issued by login and by renewal authenticates on a default chain",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return signedTokenSpec(t, &fixtureAuthenticator{calls: new(atomic.Int64)})
		},
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			get := func(credential string) RequestSpec {
				return RequestSpec{
					Method:        http.MethodGet,
					Path:          RoutePath,
					Header:        map[string]string{"Authorization": "Bearer " + credential},
					ClientAddress: ClientAddress,
				}
			}

			login := send(formBody("username=" + Username + "&password=" + Password))
			require.NoError(t, login.Refusal)
			require.Equal(t, http.StatusOK, login.Status, "body: %q", login.Body)

			issued := issuedToken(t, login)

			admitted := send(get(issued))
			require.NoError(t, admitted.Refusal)
			assert.True(t, admitted.RouteRan, "the login's token reaches the route")

			renewed := send(formPost(httpsec.DefaultSessionRenewalPath, issued, url.Values{}))
			require.NoError(t, renewed.Refusal)
			require.Equal(t, http.StatusOK, renewed.Status, "body: %q", renewed.Body)

			admitted = send(get(issuedToken(t, renewed)))
			require.NoError(t, admitted.Refusal)
			assert.True(t, admitted.RouteRan, "the renewal's token reaches the route")
		},
	}
}

// unidentifiedAuthenticator is a consumer's provider resolving every credential
// to a principal with a username and no identifier.
type unidentifiedAuthenticator struct{}

func (unidentifiedAuthenticator) Authenticate(
	context.Context, identity.Credentials,
) (*authenticate.Authentication, error) {
	return &authenticate.Authentication{
		Principal: &identity.Principal{Username: Username},
		Time:      time.Now(),
	}, nil
}

// defaultNoIdentifierSpec is the default chain a principal with no identifier
// logs in on.
func defaultNoIdentifierSpec(t *testing.T) ChainSpec {
	t.Helper()

	return signedTokenSpec(t, unidentifiedAuthenticator{})
}

// usernameNoIdentifierSpec is a chain whose generator and bearer agree on
// usernames, on which such a principal could otherwise be issued a token.
func usernameNoIdentifierSpec(t *testing.T) ChainSpec {
	t.Helper()

	effects := newEffects(t)
	keys := must.Must(signingkey.New(t.Context(), signingkey.WithKeyStore(signingkey.NewMemoryKeyStore())))
	gen := must.Must(token.NewGenerator(keys, token.WithoutIssuer(), token.WithoutAudience(), token.WithUsernameSubject()))

	return ChainSpec{
		Options: []httpsec.Option{
			httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: unidentifiedAuthenticator{}, Sessions: effects.Sessions, Tokens: gen, Attempts: effects.Attempts,
			}),
			httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
				Verifier: gen, Sessions: effects.Sessions, Users: fixtureUsers{},
			}, httpsec.WithBearerUsernameSubject()),
		},
		Effects: effects,
		Routes:  plainRoute(),
	}
}

// referenceNoIdentifierSpec is a session-reference chain, which issues no token
// that could fail for want of a subject.
func referenceNoIdentifierSpec(t *testing.T) ChainSpec {
	t.Helper()

	effects := newEffects(t)

	return ChainSpec{
		Options: []httpsec.Option{
			httpsec.EnableFormLogin(httpsec.FormLoginDeps{
				Authenticator: unidentifiedAuthenticator{}, Sessions: effects.Sessions, Attempts: effects.Attempts,
			}),
			httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: effects.Sessions, Users: fixtureUsers{}}),
		},
		Effects: effects,
		Routes:  plainRoute(),
	}
}

// loginWithNoIdentifier pins spec http-security-chain "Login with a principal
// that has no identifier" on the chain build makes: a session could not name its
// user, so the login fails with the consumer's wiring as its cause, nothing is
// handed out and nothing is left stored.
func loginWithNoIdentifier(mode string, build func(t *testing.T) ChainSpec) Scenario {
	return Scenario{
		Name:    "a login whose principal has no identifier stores no session and hands out no credential, on " + mode,
		Build:   build,
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusInternalServerError, res.Status, "body: %q", res.Body)
			require.ErrorIs(t, res.Refusal, token.ErrNoSubject, "the login fails")
			assert.NotContains(t, res.Body, "access_token", "no credential is handed out")
			assert.False(t, res.RouteRan)

			stored, err := res.Effects.Store.CountActiveByUser(t.Context(), "")
			require.NoError(t, err)
			assert.Zero(t, stored, "no session is stored for a principal with no identifier")
			assert.Zero(t, res.Effects.ActiveSessions(t), "no session is stored for anyone else")
		},
	}
}
