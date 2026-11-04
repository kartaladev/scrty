package oidcprovider_test

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// issuedCode is a code as a row's resume answered it.
type issuedCode struct {
	code     string
	answer   url.Values
	location string
	signIn   oidcprovider.SignIn
	res      oidcprovider.ResumeResult
	parked   parked
}

// issueCodeFor parks a request and resumes it with consent already remembered for user.
func issueCodeFor(
	t *testing.T, f *parkFixture, clientID string, change func(url.Values), signIn oidcprovider.SignIn, scopes ...string,
) issuedCode {
	t.Helper()

	require.NoError(t, f.consents.Give(t.Context(), signIn.User, clientID, scopes, true, f.clk.Now()))
	r := park(t, f, change)
	res, err := f.p.Resume(t.Context(), r.input(&signIn))
	require.NoError(t, err)
	answer := queryOf(t, res.RedirectTo)
	require.NotEmpty(t, answer.Get("code"), res.RedirectTo)

	return issuedCode{
		code: answer.Get("code"), answer: answer, location: res.RedirectTo, signIn: signIn, res: res, parked: r,
	}
}

func TestProvider_IssueCode(t *testing.T) {
	t.Parallel()

	const dpopKey = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	params := func(v url.Values) {
		v.Set("nonce", "the-nonce")
		v.Set("scope", "openid profile offline_access")
		v.Set("resource", "https://api.example.com")
		v.Set("dpop_jkt", dpopKey)
	}
	scopes := []string{"openid", "profile", "offline_access"}

	type testCase struct {
		name   string
		opts   []oidcprovider.Option
		issue  func(*testing.T, *parkFixture) issuedCode
		assert func(*testing.T, *parkFixture, issuedCode)
	}
	billing := func(t *testing.T, f *parkFixture) issuedCode {
		t.Helper()

		return issueCodeFor(t, f, "billing-web", params, testSignIn(f, "u-1"), scopes...)
	}
	plain := func(t *testing.T, f *parkFixture) issuedCode {
		t.Helper()

		return issueCodeFor(t, f, "billing-web", nil, testSignIn(f, "u-1"), "openid", "profile")
	}
	dpop := []oidcprovider.Option{oidcprovider.WithDPoP()}

	cases := []testCase{
		{
			name:  "the code is an unbound one-time token of the code's purpose",
			issue: plain,
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				stored, err := f.p.CodeTokensForTest().FindByID(t.Context(), tokenIDOf(t, c.code))
				require.NoError(t, err)
				assert.Equal(t, "oidc-provider.code", stored.Purpose)
				assert.Nil(t, stored.BindingHash, "another client's code must count as used")
				assert.Equal(t, "u-1", stored.Subject)
				assert.Zero(t, stored.ConsumedAt)
				_, secret, _ := strings.Cut(c.code, ".")
				assert.GreaterOrEqual(t, len(secret), 22, "at least 128 bits")
			},
		},
		{
			name:  "the record holds every binding",
			opts:  dpop,
			issue: billing,
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				record := recordOf(t, f, c.code)
				assert.Equal(t, tokenIDOf(t, c.code), record.TokenID)
				assert.Equal(t, "billing-web", record.ClientID)
				assert.Equal(t, authzRedirect, record.RedirectURI)
				assert.Equal(t, authzChallenge, record.Challenge)
				assert.Equal(t, "the-nonce", record.Nonce)
				assert.Equal(t, dpopKey, record.DPoPJKT)
				assert.Equal(t, scopes, record.Scopes)
				assert.Equal(t, []string{"https://api.example.com"}, record.Resources)
				assert.True(t, record.Offline, "offline_access holds")
				assert.False(t, record.EndsWithSignIn, "this client outlives its sign-in")
				assert.NotEqual(t, id.Nil, record.GrantFamily)
				assert.NotEqual(t, c.signIn.Family, record.GrantFamily, "the grant is not the sign-in")
			},
		},
		{
			name: "the sign-in's facts are copied, and never read from the clock",
			issue: func(t *testing.T, f *parkFixture) issuedCode {
				t.Helper()
				signIn := testSignIn(f, "u-1")
				signIn.AuthenticatedAt = f.clk.Now().Add(-90 * time.Minute)

				return issueCodeFor(t, f, "billing-web", nil, signIn, "openid", "profile")
			},
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				record := recordOf(t, f, c.code)
				assert.Equal(t, c.signIn, record.SignIn)
				assert.True(t, record.SignIn.AuthenticatedAt.Before(f.clk.Now().Add(-time.Hour)))
				assert.Equal(t, "https://upstream.example.com", record.SignIn.ExternalIssuer)
				assert.Equal(t, "upstream-session", record.SignIn.ExternalSessionID)
			},
		},
		{
			name:  "a request without offline_access does not hold it",
			issue: plain,
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				assert.False(t, recordOf(t, f, c.code).Offline)
			},
		},
		{
			name: "a client tied to its sign-in says so on the record",
			issue: func(t *testing.T, f *parkFixture) issuedCode {
				t.Helper()

				return issueCodeFor(t, f, "public-spa", func(v url.Values) {
					asClient(v, "public-spa", "https://spa.example.com/cb")
					v.Set("scope", "openid")
				}, testSignIn(f, "u-1"), "openid")
			},
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				assert.True(t, recordOf(t, f, c.code).EndsWithSignIn)
			},
		},
		{
			name: "each code has a family of its own",
			issue: func(t *testing.T, f *parkFixture) issuedCode {
				t.Helper()
				first := plain(t, f)
				second := plain(t, f)
				require.NotEqual(t, recordOf(t, f, first.code).GrantFamily, recordOf(t, f, second.code).GrantFamily)

				return second
			},
			assert: func(*testing.T, *parkFixture, issuedCode) {},
		},
		{
			name:  "the record and the token expire 60 seconds after issue by default",
			issue: plain,
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				assert.Equal(t, f.clk.Now().Add(60*time.Second), recordOf(t, f, c.code).ExpiresAt)

				tokens, err := onetime.New("oidc-provider.code",
					onetime.WithStore(f.p.CodeTokensForTest()), onetime.WithClock(f.clk))
				require.NoError(t, err)

				f.clk.Advance(59 * time.Second)
				_, err = tokens.Check(t.Context(), c.code, "")
				require.NoError(t, err, "good within its lifetime, with any binding ignored")

				f.clk.Advance(time.Second)
				_, err = tokens.Check(t.Context(), c.code, "")
				require.ErrorIs(t, err, onetime.ErrInvalidToken)
			},
		},
		{
			name:  "WithCodeLifetime replaces the default",
			opts:  []oidcprovider.Option{oidcprovider.WithCodeLifetime(5 * time.Minute)},
			issue: plain,
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				assert.Equal(t, f.clk.Now().Add(5*time.Minute), recordOf(t, f, c.code).ExpiresAt)
				stored, err := f.p.CodeTokensForTest().FindByID(t.Context(), tokenIDOf(t, c.code))
				require.NoError(t, err)
				assert.Equal(t, f.clk.Now().Add(5*time.Minute), stored.ExpiresAt)
			},
		},
		{
			name:  "WithCodeLifetime reaches its 10 minute cap",
			opts:  []oidcprovider.Option{oidcprovider.WithCodeLifetime(10 * time.Minute)},
			issue: plain,
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				assert.Equal(t, f.clk.Now().Add(10*time.Minute), recordOf(t, f, c.code).ExpiresAt)
			},
		},
		{
			name: "a redirect URI's own query and an awkward state come back exact",
			issue: func(t *testing.T, f *parkFixture) issuedCode {
				t.Helper()

				return issueCodeFor(t, f, "tenant-web", func(v url.Values) {
					asClient(v, "tenant-web", "https://rp.example.com/cb?tenant=a")
					v.Set("scope", "openid")
					v.Set("state", "a&b=c #d")
				}, testSignIn(f, "u-1"), "openid")
			},
			assert: func(t *testing.T, _ *parkFixture, c issuedCode) {
				t.Helper()
				assert.True(t, strings.HasPrefix(c.location, "https://rp.example.com/cb?tenant=a&"), c.location)
				assert.Equal(t, "a", c.answer.Get("tenant"))
				assert.Equal(t, "a&b=c #d", c.answer.Get("state"))
				assert.Equal(t, issuer, c.answer.Get("iss"))
				assert.NotEmpty(t, c.answer.Get("code"))
			},
		},
		{
			name: "a request with no state gets none back",
			issue: func(t *testing.T, f *parkFixture) issuedCode {
				t.Helper()

				return issueCodeFor(t, f, "billing-web", func(v url.Values) { v.Del("state") }, testSignIn(f, "u-1"), "openid", "profile")
			},
			assert: func(t *testing.T, _ *parkFixture, c issuedCode) {
				t.Helper()
				assert.NotContains(t, c.answer, "state")
				assert.Equal(t, issuer, c.answer.Get("iss"))
			},
		},
		{
			name:  "the code's secret reaches nothing but the redirect",
			opts:  dpop,
			issue: billing,
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				_, secret, found := strings.Cut(c.code, ".")
				require.True(t, found)
				held := []any{recordOf(t, f, c.code)}

				stored, err := f.p.CodeTokensForTest().FindByID(t.Context(), tokenIDOf(t, c.code))
				require.NoError(t, err)
				held = append(held, stored)

				session, err := f.p.BrowserSessionStoreForTest().Load(t.Context(), digestOf(t, c.res.BrowserSessionSecret), f.clk.Now())
				require.NoError(t, err)
				held = append(held, session)

				pending, err := f.store.Load(t.Context(), handleDigestOf(t, c.parked.handle))
				require.NoError(t, err)
				held = append(held, pending)

				for _, value := range held {
					for _, text := range everyString(reflect.ValueOf(value)) {
						assert.NotContains(t, text, secret)
						assert.NotContains(t, text, c.parked.flow)
						assert.NotContains(t, text, c.res.BrowserSessionSecret)
					}
				}
				assert.NotContains(t, f.logs.String(), secret)
				assert.Contains(t, c.res.RedirectTo, url.QueryEscape(c.code))
				assert.NotContains(t, c.res.BrowserSessionSecret, secret)
			},
		},
		{
			name:  "the record names its user, so an end of the sign-in reaches the code",
			issue: plain,
			assert: func(t *testing.T, f *parkFixture, c issuedCode) {
				t.Helper()
				selected, err := f.p.CodesForTest().UnspentBySignIn(t.Context(),
					oidcprovider.SignInSelector{Family: c.signIn.Family}, false)
				require.NoError(t, err)
				assert.Equal(t, []id.ID{recordOf(t, f, c.code).GrantFamily}, selected)

				byUser, err := f.p.CodesForTest().UnspentByClient(t.Context(), identity.UserID("u-1"), "billing-web")
				require.NoError(t, err)
				assert.Len(t, byUser, 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newParkFixture(t, issuer+"/login", tc.opts...)
			tc.assert(t, f, tc.issue(t, f))
		})
	}
}

// TestProvider_IssueCode_RedirectURIUsed: a client registering two redirect URIs gets its
// code recorded against the one the request used.
func TestProvider_IssueCode_RedirectURIUsed(t *testing.T) {
	t.Parallel()

	for _, used := range []string{authzRedirect, otherRedirect} {
		t.Run(used, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			changeClient(t, f, func(c *oidcprovider.Client) { c.RedirectURIs = []string{authzRedirect, otherRedirect} })

			c := issueCodeFor(t, f, "billing-web", func(v url.Values) { v.Set("redirect_uri", used) },
				testSignIn(f, "u-1"), "openid", "profile")

			assert.Equal(t, used, recordOf(t, f, c.code).RedirectURI)
			assert.True(t, strings.HasPrefix(c.location, used), c.location)
		})
	}
}
