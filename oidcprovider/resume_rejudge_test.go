package oidcprovider_test

import (
	"encoding/base64"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

const otherRedirect = "https://rp.example.com/other"

// changeClient replaces billing-web after a request was parked.
func changeClient(t *testing.T, f *parkFixture, change func(*oidcprovider.Client)) {
	t.Helper()

	for _, c := range authzClients() {
		if c.ID == "billing-web" {
			change(&c)
			require.NoError(t, f.registry.Put(t.Context(), c))

			return
		}
	}
	t.Fatal("billing-web is not among the clients")
}

// rememberAll makes a login stage go straight to a code.
func rememberAll(t *testing.T, f *parkFixture) {
	t.Helper()

	require.NoError(t, f.consents.Give(t.Context(), "u-1", "billing-web",
		[]string{"openid", "profile", "offline_access"}, true, f.clk.Now()))
}

// TestProvider_Resume_ClientChangedAfterParking judges a parked request against the client
// as it is read at the resume, at both stages.
func TestProvider_Resume_ClientChangedAfterParking(t *testing.T) {
	t.Parallel()

	unregister := func(c *oidcprovider.Client) { c.RedirectURIs = []string{otherRedirect} }
	scopes := func(s ...string) func(*oidcprovider.Client) {
		return func(c *oidcprovider.Client) { c.Scopes = s }
	}
	withScope := func(s string) func(url.Values) { return func(v url.Values) { v.Set("scope", s) } }

	// unknown asserts the request was refused like an unknown handle, with nothing
	// redirected, issued or spent.
	unknown := func(stage oidcprovider.Stage) func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error) {
		return func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
			assert.Empty(t, res.RedirectTo, "no redirect, to a URI the client may have lost or any other")
			assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"), "no code")
			assert.Equal(t, stage, stageOf(t, f, r), "the handle is left unspent")
		}
	}
	record := func(t *testing.T, f *parkFixture, res oidcprovider.ResumeResult, err error) *oidcprovider.CodeRecord {
		t.Helper()
		require.NoError(t, err)
		code := queryOf(t, res.RedirectTo).Get("code")
		require.NotEmpty(t, code, res.RedirectTo)
		assert.True(t, strings.HasPrefix(res.RedirectTo, authzRedirect), res.RedirectTo)

		return recordOf(t, f, code)
	}

	type testCase struct {
		name   string
		params func(url.Values)
		change func(*oidcprovider.Client)
		answer *oidcprovider.ConsentAnswer // nil resumes the login stage
		assert func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error)
	}
	all := []string{"openid", "profile", "offline_access"}
	cases := []testCase{
		// The login stage.
		{
			name:   "login: a redirect URI since unregistered is an unknown handle",
			change: unregister,
			assert: unknown(oidcprovider.StageLogin),
		},
		{
			name: "login: a client that lost the code grant is an unknown handle",
			change: func(c *oidcprovider.Client) {
				c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantRefreshToken}
			},
			assert: unknown(oidcprovider.StageLogin),
		},
		{
			name:   "login: a scope since withdrawn is left out of the code",
			change: scopes("openid", "offline_access"),
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.Equal(t, []string{"openid"}, record(t, f, res, err).Scopes)
			},
		},
		{
			name:   "login: openid since withdrawn is an unknown handle",
			change: scopes("profile"),
			assert: unknown(oidcprovider.StageLogin),
		},
		{
			name:   "login: a request left with no scope is an unknown handle",
			params: withScope("api.read"),
			change: scopes("openid"),
			assert: unknown(oidcprovider.StageLogin),
		},
		{
			name:   "login: a request without openid keeps the scopes the client may still ask for",
			params: withScope("profile email"),
			change: scopes("openid", "profile"),
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.Equal(t, []string{"profile"}, record(t, f, res, err).Scopes)
			},
		},
		{
			name:   "login: a client that lost the refresh grant holds no offline access",
			params: withScope("openid profile offline_access"),
			change: func(c *oidcprovider.Client) {
				c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode}
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				rec := record(t, f, res, err)
				assert.Equal(t, []string{"openid", "profile"}, rec.Scopes)
				assert.False(t, rec.Offline)
			},
		},
		{
			name: "login: a resource since withdrawn is left out of the code",
			params: func(v url.Values) {
				v["resource"] = []string{"https://api.example.com", "https://data.example.com"}
			},
			change: func(c *oidcprovider.Client) { c.Resources = []string{"https://data.example.com"} },
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.Equal(t, []string{"https://data.example.com"}, record(t, f, res, err).Resources)
			},
		},

		// The consent stage.
		{
			name:   "consent: a redirect URI since unregistered is an unknown handle",
			change: unregister,
			answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}},
			assert: unknown(oidcprovider.StageConsent),
		},
		{
			name:   "consent: a denial is not redirected to a URI since unregistered",
			change: unregister,
			answer: &oidcprovider.ConsentAnswer{Deny: true},
			assert: unknown(oidcprovider.StageConsent),
		},
		{
			name: "consent: a client that lost the code grant is an unknown handle",
			change: func(c *oidcprovider.Client) {
				c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantRefreshToken}
			},
			answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}},
			assert: unknown(oidcprovider.StageConsent),
		},
		{
			name:   "consent: an answer naming a scope since withdrawn grants the rest",
			change: scopes("openid", "offline_access"),
			answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid", "profile"}},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.Equal(t, []string{"openid"}, record(t, f, res, err).Scopes)
			},
		},
		{
			name:   "consent: openid since withdrawn is an unknown handle",
			change: scopes("profile"),
			answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid", "profile"}},
			assert: unknown(oidcprovider.StageConsent),
		},
		{
			name:   "consent: openid since withdrawn is an unknown handle also for a denial",
			change: scopes("profile"),
			answer: &oidcprovider.ConsentAnswer{Deny: true},
			assert: unknown(oidcprovider.StageConsent),
		},
		{
			name:   "consent: a request left with no scope is an unknown handle",
			params: withScope("api.read"),
			change: scopes("openid"),
			answer: &oidcprovider.ConsentAnswer{Scopes: []string{"api.read"}},
			assert: unknown(oidcprovider.StageConsent),
		},
		{
			name:   "consent: a client that lost the refresh grant holds no offline access",
			params: withScope("openid profile offline_access"),
			change: func(c *oidcprovider.Client) {
				c.GrantTypes = []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode}
			},
			answer: &oidcprovider.ConsentAnswer{Scopes: all},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				rec := record(t, f, res, err)
				assert.Equal(t, []string{"openid", "profile"}, rec.Scopes)
				assert.False(t, rec.Offline)
			},
		},
		{
			name: "consent: a resource since withdrawn is left out of the code",
			params: func(v url.Values) {
				v["resource"] = []string{"https://api.example.com", "https://data.example.com"}
			},
			change: func(c *oidcprovider.Client) { c.Resources = []string{"https://data.example.com"} },
			answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid", "profile"}},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.Equal(t, []string{"https://data.example.com"}, record(t, f, res, err).Resources)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			signIn := testSignIn(f, "u-1")

			var r parked
			if tc.answer == nil {
				rememberAll(t, f)
				r = park(t, f, tc.params)
			} else {
				r, _ = atConsent(t, f, tc.params, signIn)
			}
			changeClient(t, f, tc.change)

			in := r.input(&signIn)
			in.Answer = tc.answer
			res, err := f.p.Resume(t.Context(), in)
			tc.assert(t, f, r, res, err)
		})
	}
}

// TestProvider_Resume_FutureAuthenticationTime refuses a sign-in that claims to have
// authenticated further ahead than clock skew between replicas explains.
func TestProvider_Resume_FutureAuthenticationTime(t *testing.T) {
	t.Parallel()

	const leeway = 60 * time.Second
	none := func(url.Values) {}
	promptLogin := func(v url.Values) { v.Set("prompt", "login") }
	maxAge := func(s string) func(url.Values) { return func(v url.Values) { v.Set("max_age", s) } }

	cases := []struct {
		name   string
		params func(url.Values)
		ahead  time.Duration
		assert func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error)
	}{
		{name: "exactly the leeway ahead counts as now", params: none, ahead: leeway, assert: proceedsToConsent},
		{name: "past the leeway is refused", params: none, ahead: leeway + time.Second, assert: reauthenticate},
		{name: "a year ahead is refused", params: none, ahead: 365 * 24 * time.Hour, assert: reauthenticate},
		{name: "prompt=login: exactly the leeway ahead counts as now", params: promptLogin, ahead: leeway, assert: proceedsToConsent},
		{name: "prompt=login: past the leeway is refused", params: promptLogin, ahead: leeway + time.Second, assert: reauthenticate},
		{name: "max_age=0: exactly the leeway ahead counts as now", params: maxAge("0"), ahead: leeway, assert: proceedsToConsent},
		{name: "max_age=0: past the leeway is refused", params: maxAge("0"), ahead: leeway + time.Second, assert: reauthenticate},
		{name: "max_age=300: exactly the leeway ahead counts as now", params: maxAge("300"), ahead: leeway, assert: proceedsToConsent},
		{name: "max_age=300: past the leeway is refused", params: maxAge("300"), ahead: leeway + time.Second, assert: reauthenticate},
	}
	for _, tc := range cases {
		t.Run("login: "+tc.name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			r := park(t, f, tc.params)

			signIn := testSignIn(f, "u-1")
			signIn.AuthenticatedAt = f.clk.Now().Add(tc.ahead)
			res, err := f.p.Resume(t.Context(), r.input(&signIn))
			tc.assert(t, f, r, res, err)
		})
	}

	t.Run("consent: past the leeway is refused, for an answer and for a denial", func(t *testing.T) {
		t.Parallel()
		for _, answer := range []*oidcprovider.ConsentAnswer{{Scopes: []string{"openid"}}, {Deny: true}} {
			f := newParkFixture(t, issuer+"/login")
			signIn := testSignIn(f, "u-1")
			r, _ := atConsent(t, f, nil, signIn)

			signIn.AuthenticatedAt = f.clk.Now().Add(leeway + time.Second)
			in := r.input(&signIn)
			in.Answer = answer
			res, err := f.p.Resume(t.Context(), in)
			reauthenticate(t, f, r, res, err)
		}
	})
}

func proceedsToConsent(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
	t.Helper()
	require.NoError(t, err)
	assert.NotEmpty(t, res.RedirectTo)
	assert.NotEqual(t, oidcprovider.StageLogin, stageOf(t, f, r))
}

func reauthenticate(t *testing.T, _ *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
	t.Helper()
	require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
	assert.Empty(t, res.RedirectTo)
}

// TestProvider_Resume_BrowserSessionUse covers what an answer through a browser session
// does to that session.
func TestProvider_Resume_BrowserSessionUse(t *testing.T) {
	t.Parallel()

	// Two sessions exist when the answer comes: the one answered through, and the one the
	// login stage of the answered request made. Both run out 15 minutes after they were
	// made. Five minutes on, the answer extends the first to its IdleTimeout of 40
	// minutes from then, which the second never gets.
	cases := []struct {
		name   string
		answer *oidcprovider.ConsentAnswer
	}{
		{name: "a grant extends the session by the IdleTimeout it names", answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}},
		{name: "a denial counts as a use too", answer: &oidcprovider.ConsentAnswer{Deny: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			secret := heldBrowserSession(t, f, consentSessionSignIn(f, "u-1"))
			r, _ := atConsent(t, f, nil, testSignIn(f, "u-1"))

			f.clk.Advance(5 * time.Minute)
			in := r.input(nil)
			in.BrowserSessionSecret = secret
			in.IdleTimeout = 40 * time.Minute
			in.Answer = tc.answer
			_, err := f.p.Resume(t.Context(), in)
			require.NoError(t, err)

			f.clk.Advance(35 * time.Minute)
			removed, err := f.p.BrowserSessionStoreForTest().DeleteExpired(t.Context(), f.clk.Now())
			require.NoError(t, err)
			assert.Equal(t, 1, removed, "only the session the answer did not rest on has run out")
		})
	}
}

// TestProvider_Resume_OldSessionKeptWhenSessionsAreOff: with browser sessions off nothing
// replaces the secret presented, so nothing deletes what it names.
func TestProvider_Resume_OldSessionKeptWhenSessionsAreOff(t *testing.T) {
	t.Parallel()

	f := newParkFixture(t, issuer+"/login", oidcprovider.WithoutBrowserSessions())
	sessions := f.p.BrowserSessionStoreForTest()
	secret := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	digest := digestOf(t, secret)
	signIn := testSignIn(f, "u-1")
	require.NoError(t, sessions.Put(t.Context(), &oidcprovider.BrowserSession{
		Digest: digest, SignIn: signIn,
		IdleExpiresAt: f.clk.Now().Add(time.Hour), AbsoluteExpiresAt: signIn.AbsoluteExpiresAt,
	}))

	r := park(t, f, nil)
	in := r.input(&signIn)
	in.BrowserSessionSecret = secret
	res, err := f.p.Resume(t.Context(), in)
	require.NoError(t, err)
	assert.Empty(t, res.BrowserSessionSecret)

	_, err = sessions.Load(t.Context(), digest, f.clk.Now())
	assert.NoError(t, err, "the session presented is still held")
}

// TestProvider_CodeTokens_UseTheProviderSettings: the code tokens draw their identifiers,
// secrets and log from the provider's own options.
func TestProvider_CodeTokens_UseTheProviderSettings(t *testing.T) {
	t.Parallel()

	codeFrom := func(t *testing.T) string {
		t.Helper()
		src := rand.NewChaCha8([32]byte{1, 2, 3})
		f := newParkFixture(t, issuer+"/login", oidcprovider.WithRandom(src))
		rememberAll(t, f)
		r := park(t, f, nil)
		signIn := testSignIn(f, "u-1")
		res, err := f.p.Resume(t.Context(), r.input(&signIn))
		require.NoError(t, err)

		return queryOf(t, res.RedirectTo).Get("code")
	}
	first, second := codeFrom(t), codeFrom(t)
	require.NotEmpty(t, first)
	identifier := func(code string) string { before, _, _ := strings.Cut(code, "."); return before }
	secret := func(code string) string { _, after, _ := strings.Cut(code, "."); return after }

	t.Run("the identifier comes from the provider's clock and random source", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, identifier(first), identifier(second))
	})
	t.Run("the secret comes from the provider's random source", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, secret(first), secret(second))
	})
	t.Run("the log is the provider's", func(t *testing.T) {
		t.Parallel()
		store := NewMockCodeTokenStore(gomock.NewController(t))
		store.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, errOutage)
		f := newParkFixture(t, issuer+"/login", oidcprovider.WithCodeTokenStore(store))

		tokens, err := f.p.CodeManagerForTest()
		require.NoError(t, err)
		presented := mustFamily(t).String() + ".c2VjcmV0"
		_, err = tokens.Check(t.Context(), presented, "")
		require.ErrorIs(t, err, onetime.ErrInvalidToken)
		assert.Contains(t, f.logs.String(), "reading the token store failed")
	})
}

func mustFamily(t *testing.T) id.ID {
	t.Helper()

	got, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	return got
}
