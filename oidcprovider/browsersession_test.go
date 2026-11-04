package oidcprovider_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/signingkey"
)

// sessionIdle is the idle timeout every row's session starts with, and sessionGap how long
// after that login a row's request comes. A session a row's request did not touch has
// sessionIdle-sessionGap left when its answer arrives.
const (
	sessionIdle = 15 * time.Minute
	sessionGap  = 5 * time.Minute
)

// sessionFixture is a parkFixture whose user loader a row can change, because a browser
// session is the one thing at the authorization endpoint that loads a user.
type sessionFixture struct {
	*parkFixture

	user      func(identity.UserID) (*identity.Details, error)
	userLoads int
}

func activeUser(user identity.UserID) (*identity.Details, error) {
	return &identity.Details{ID: user, Active: true}, nil
}

func newSessionFixture(t *testing.T, keys signingkey.KeySource, opts ...oidcprovider.Option) *sessionFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	store, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	consents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	registry, err := oidcprovider.NewMemoryRegistry(authzClients())
	require.NoError(t, err)
	logs := &bytes.Buffer{}

	f := &sessionFixture{user: activeUser}
	loader := NewMockUserLoader(gomock.NewController(t))
	loader.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			f.userLoads++

			return f.user(user)
		},
	).AnyTimes()

	base := []oidcprovider.Option{
		oidcprovider.WithClock(clk),
		oidcprovider.WithPendingRequestStore(store),
		oidcprovider.WithConsentStore(consents),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(logs, nil))),
	}
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         keys,
		Users:        loader,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, append(base, opts...)...)
	require.NoError(t, err)

	f.parkFixture = &parkFixture{p: p, store: store, consents: consents, registry: registry, clk: clk, logs: logs}

	return f
}

// sessionRow is what a row's browser holds when its request arrives.
type sessionRow struct {
	f      *sessionFixture
	signIn oidcprovider.SignIn
	secret string
}

// fixture is the row's parkFixture, for the helpers it shares with the resume tests.
func (r *sessionRow) fixture() *parkFixture { return r.f.parkFixture }

// touched reports whether the row's session has been extended: a session its request did
// not touch has run out by now plus the time it had left.
func (r *sessionRow) touched(t *testing.T) bool {
	t.Helper()

	return r.loads(t, r.f.clk.Now().Add(sessionIdle-sessionGap))
}

// loads reports whether the row's session would answer at a time.
func (r *sessionRow) loads(t *testing.T, at time.Time) bool {
	t.Helper()

	_, err := r.f.p.BrowserSessionStoreForTest().Load(t.Context(), digestOf(t, r.secret), at)
	if errors.Is(err, oidcprovider.ErrNotFound) {
		return false
	}
	require.NoError(t, err)

	return true
}

// consentAnswer answers a consent page from the browser session alone, as a browser that
// skipped the login page must.
func (r *sessionRow) consentAnswer(t *testing.T, res oidcprovider.AuthorizeResult, scopes ...string) (oidcprovider.ResumeResult, error) {
	t.Helper()

	return r.f.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle:               handleOf(t, res.Location),
		FlowSecret:           res.FlowSecret,
		BrowserSessionSecret: r.secret,
		IdleTimeout:          sessionIdle,
		Answer:               &oidcprovider.ConsentAnswer{Scopes: scopes},
	})
}

// endSignIn ends the row's sign-in as T3's selectors do, by its family.
func (r *sessionRow) endSignIn(t *testing.T) {
	t.Helper()

	removed, err := r.f.p.BrowserSessionStoreForTest().DeleteBySignIn(t.Context(),
		oidcprovider.SignInSelector{Family: r.signIn.Family})
	require.NoError(t, err)
	require.Equal(t, 1, removed)
}

// holdDirectly stores a session a login stage would have refused to make, so the row can
// see what the request does with what a store hands back.
func (r *sessionRow) holdDirectly(t *testing.T, change func(*oidcprovider.SignIn)) {
	t.Helper()

	change(&r.signIn)
	now := r.f.clk.Now()
	r.secret = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"
	require.NoError(t, r.f.p.BrowserSessionStoreForTest().Put(t.Context(), &oidcprovider.BrowserSession{
		Digest:            digestOf(t, r.secret),
		SignIn:            r.signIn,
		IdleExpiresAt:     now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}))
}

// codeOf asserts an authorization response carrying a code from the row's sign-in, with
// nothing parked, and returns its record.
func codeOf(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) *oidcprovider.CodeRecord {
	t.Helper()

	require.NoError(t, err)
	assert.Empty(t, res.FlowSecret, "nothing was parked")
	answer := queryOf(t, res.Location)
	require.NotEmpty(t, answer.Get("code"), res.Location)
	assert.Equal(t, authzState, answer.Get("state"))
	assert.Equal(t, issuer, answer.Get("iss"))
	assert.Empty(t, answer.Get("error"))
	assert.NotContains(t, res.Location, row.secret)

	record := recordOf(t, row.fixture(), answer.Get("code"))
	assert.Equal(t, row.signIn, record.SignIn, "the original sign-in's facts, and none from the present")

	return record
}

// answered is a code, and a session the answer extended.
func answered(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
	t.Helper()

	codeOf(t, row, res, err)
	assert.True(t, row.touched(t), "the session's use is recorded")
}

// refusedWith asserts a refusal at the redirect URI, with nothing issued, parked or
// extended.
func refusedWith(code string) func(*testing.T, *sessionRow, oidcprovider.AuthorizeResult, error) {
	return func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.Empty(t, res.FlowSecret, "nothing was parked")
		require.True(t, strings.HasPrefix(res.Location, authzRedirect+"?"), res.Location)
		answer := queryOf(t, res.Location)
		assert.Equal(t, code, answer.Get("error"))
		assert.Equal(t, authzState, answer.Get("state"))
		assert.Equal(t, issuer, answer.Get("iss"))
		assert.Empty(t, answer.Get("code"))
		assert.Zero(t, codesHeld(t, row.fixture(), row.signIn.User, "billing-web"))
		if row.secret != "" {
			assert.False(t, row.touched(t), "a request the session did not answer is no use of it")
		}
	}
}

// atLoginPage asserts a parked request waiting at the login page, as with no session.
func atLoginPage(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
	t.Helper()

	require.NoError(t, err)
	require.True(t, strings.HasPrefix(res.Location, issuer+"/login?"), res.Location)
	assert.NotEmpty(t, res.FlowSecret)
	assert.Equal(t, oidcprovider.StageLogin,
		stageOf(t, row.fixture(), parked{handle: handleOf(t, res.Location), flow: res.FlowSecret}))
	assert.Zero(t, codesHeld(t, row.fixture(), row.signIn.User, "billing-web"))
	if row.secret != "" {
		assert.False(t, row.touched(t), "a request the session did not answer is no use of it")
	}
}

// atConsentPage asserts a request parked at the consent stage for the session's sign-in.
func atConsentPage(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
	t.Helper()

	require.NoError(t, err)
	require.True(t, strings.HasPrefix(res.Location, issuer+"/consent?"), res.Location)
	assert.NotEmpty(t, res.FlowSecret)
	stored, loadErr := row.f.store.Load(t.Context(), handleDigestOf(t, handleOf(t, res.Location)))
	require.NoError(t, loadErr)
	assert.Equal(t, oidcprovider.StageConsent, stored.Stage)
	require.NotNil(t, stored.SignIn)
	assert.Equal(t, row.signIn, *stored.SignIn)
	assert.Zero(t, codesHeld(t, row.fixture(), row.signIn.User, "billing-web"))
	assert.True(t, row.touched(t), "the session's use is recorded")
}

// serverError asserts a validated request was answered at its redirect URI, as a 303 would
// carry it, with server_error, the state and the issuer, and no code.
func serverError(t *testing.T, res oidcprovider.AuthorizeResult, err error) {
	t.Helper()

	require.NoError(t, err)
	require.True(t, strings.HasPrefix(res.Location, authzRedirect+"?"), res.Location)
	answer := queryOf(t, res.Location)
	assert.Equal(t, "server_error", answer.Get("error"))
	assert.Equal(t, authzState, answer.Get("state"))
	assert.Equal(t, issuer, answer.Get("iss"))
	assert.Empty(t, answer.Get("code"))
	assert.NotContains(t, res.Location, errOutage.Error())
}

func forgetConsent(t *testing.T, row *sessionRow) {
	t.Helper()

	_, err := row.f.consents.Revoke(t.Context(), row.signIn.User, "billing-web")
	require.NoError(t, err)
}

func TestProvider_BrowserSession(t *testing.T) {
	t.Parallel()

	hints := newHintFixture(t)
	hintFor := func(sub string) string {
		return signed(t, "RS256", hints.private, map[string]any{"kid": publishedKid, "typ": "JWT"},
			hintClaims(map[string]any{"sub": sub}))
	}
	retiredHint := signed(t, "RS256", hints.foreign, map[string]any{"kid": "retired", "typ": "JWT"}, hintClaims(nil))

	loginRequired := refusedWith(oidcprovider.CodeLoginRequired)
	consentRequired := refusedWith(oidcprovider.CodeConsentRequired)
	silently := func(change func(url.Values)) func(url.Values) {
		return func(v url.Values) {
			v.Set("prompt", "none")
			if change != nil {
				change(v)
			}
		}
	}
	silent := silently(nil)
	both := func(a, b func(url.Values)) func(url.Values) {
		return func(v url.Values) { a(v); b(v) }
	}
	userIs := func(user func(identity.UserID) (*identity.Details, error)) func(*testing.T, *sessionRow) {
		return func(_ *testing.T, row *sessionRow) { row.f.user = user }
	}
	missing := userIs(func(identity.UserID) (*identity.Details, error) {
		return nil, fmt.Errorf("the loader's words: %w", identity.ErrUserNotFound)
	})
	disabled := userIs(func(user identity.UserID) (*identity.Details, error) {
		return &identity.Details{ID: user}, nil
	})
	someoneElse := userIs(func(identity.UserID) (*identity.Details, error) {
		return &identity.Details{ID: "u-2", Active: true}, nil
	})
	nobody := userIs(func(identity.UserID) (*identity.Details, error) {
		return nil, nil //nolint:nilnil // a loader that breaks its contract must still not answer for a session
	})
	userOutage := userIs(func(identity.UserID) (*identity.Details, error) { return nil, errOutage })
	outage := func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		serverError(t, res, err)
		assert.NotContains(t, row.f.logs.String(), errOutage.Error())
		assert.False(t, row.touched(t))
	}
	// pastIdle lets the row's session run out.
	pastIdle := func(_ *testing.T, row *sessionRow) { row.f.clk.Advance(sessionIdle) }
	sessionRanOut := func(t *testing.T, _ *sessionRow, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.Location, issuer+"/login?"), res.Location)
		assert.NotEmpty(t, res.FlowSecret)
	}
	silentlyRanOut := func(t *testing.T, _ *sessionRow, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		answer := queryOf(t, res.Location)
		assert.Equal(t, oidcprovider.CodeLoginRequired, answer.Get("error"))
		assert.Empty(t, answer.Get("code"))
		assert.Empty(t, res.FlowSecret)
	}
	wrongSignIn := func(change func(*sessionRow, *oidcprovider.SignIn)) func(*testing.T, *sessionRow) {
		return func(t *testing.T, row *sessionRow) {
			t.Helper()
			row.holdDirectly(t, func(s *oidcprovider.SignIn) { change(row, s) })
		}
	}
	future := wrongSignIn(func(row *sessionRow, s *oidcprovider.SignIn) {
		s.AuthenticatedAt = row.f.clk.Now().Add(61 * time.Second)
	})
	// holdingAnyway leaves a good session in the store, so a row is about the option, and
	// not about there being nothing to find.
	holdingAnyway := wrongSignIn(func(*sessionRow, *oidcprovider.SignIn) {})
	secretIs := func(secret string) func(*oidcprovider.AuthorizeInput) {
		return func(in *oidcprovider.AuthorizeInput) { in.BrowserSessionSecret = secret }
	}

	type testCase struct {
		name string
		opts []oidcprovider.Option
		// signIn replaces the sign-in the first login presents.
		signIn func(*parkFixture) oidcprovider.SignIn
		// noLogin leaves the browser holding no session.
		noLogin bool
		// noConsent leaves the user having given the client nothing.
		noConsent bool
		params    func(url.Values)
		prepare   func(*testing.T, *sessionRow)
		in        func(*oidcprovider.AuthorizeInput)
		ctx       func(context.Context) context.Context
		assert    func(*testing.T, *sessionRow, oidcprovider.AuthorizeResult, error)
	}

	cases := []testCase{
		{
			name:   "after a first login, prompt=none issues a code with the original auth_time, amr, acr and sid",
			params: silent,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				record := codeOf(t, row, res, err)
				assert.Equal(t, row.signIn.AuthenticatedAt, record.SignIn.AuthenticatedAt)
				assert.NotEqual(t, row.f.clk.Now(), record.SignIn.AuthenticatedAt)
				assert.Equal(t, row.signIn.AMR, record.SignIn.AMR)
				assert.Equal(t, row.signIn.ACR, record.SignIn.ACR)
				assert.Equal(t, row.signIn.Family, record.SignIn.Family)
				assert.True(t, row.touched(t))
			},
		},
		{
			name:    "after the sign-in ended, prompt=none answers login_required",
			params:  silent,
			prepare: func(t *testing.T, row *sessionRow) { t.Helper(); row.endSignIn(t) },
			assert:  loginRequired,
		},
		{
			name:   "with no prompt, a valid session skips the login page, and is touched",
			assert: answered,
		},
		{
			name:    "after the sign-in ended, with no prompt, the login page is shown",
			prepare: func(t *testing.T, row *sessionRow) { t.Helper(); row.endSignIn(t) },
			assert:  atLoginPage,
		},
		{
			name: "a second relying party in the same browser gets a code with no page",
			params: func(v url.Values) {
				asClient(v, "tenant-web", "https://rp.example.com/cb?tenant=a")
				v.Set("scope", "openid")
			},
			prepare: func(t *testing.T, row *sessionRow) {
				t.Helper()
				require.NoError(t, row.f.consents.Give(t.Context(), "u-1", "tenant-web", []string{"openid"}, false, row.f.clk.Now()))
			},
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.True(t, strings.HasPrefix(res.Location, "https://rp.example.com/cb?tenant=a&"), res.Location)
				record := recordOf(t, row.fixture(), queryOf(t, res.Location).Get("code"))
				assert.Equal(t, "tenant-web", record.ClientID)
				assert.Equal(t, row.signIn, record.SignIn)
			},
		},
		{
			name: "a code carries the request's bindings, and the scopes it asked for",
			opts: []oidcprovider.Option{oidcprovider.WithDPoP()},
			params: func(v url.Values) {
				v.Set("nonce", "n-1")
				v.Set("dpop_jkt", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
				v.Set("resource", "https://api.example.com")
			},
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				record := codeOf(t, row, res, err)
				assert.Equal(t, "billing-web", record.ClientID)
				assert.Equal(t, authzRedirect, record.RedirectURI)
				assert.Equal(t, authzChallenge, record.Challenge)
				assert.Equal(t, "n-1", record.Nonce)
				assert.Equal(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", record.DPoPJKT)
				assert.Equal(t, []string{"openid", "profile"}, record.Scopes)
				assert.Equal(t, []string{"https://api.example.com"}, record.Resources)
				assert.False(t, record.Offline)
				assert.False(t, record.EndsWithSignIn)
			},
		},
		{
			name:   "an offline code from a session is offline, and survives its sign-in's end",
			params: set("scope", "openid offline_access"),
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				record := codeOf(t, row, res, err)
				assert.True(t, record.Offline)
				assert.False(t, record.EndsWithSignIn)

				sel := oidcprovider.SignInSelector{Family: row.signIn.Family}
				families, listErr := row.f.p.CodesForTest().UnspentBySignIn(t.Context(), sel, false)
				require.NoError(t, listErr)
				assert.Empty(t, families, "an end of the sign-in spares it")
			},
		},
		{
			name:   "a code for a client tied to its sign-in ends with the sign-in, offline or not",
			params: set("scope", "openid offline_access"),
			prepare: func(t *testing.T, row *sessionRow) {
				t.Helper()
				changeClient(t, row.fixture(), func(c *oidcprovider.Client) { c.EndGrantsWithSignIn = true })
			},
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				record := codeOf(t, row, res, err)
				assert.True(t, record.Offline)
				assert.True(t, record.EndsWithSignIn)

				sel := oidcprovider.SignInSelector{Family: row.signIn.Family}
				families, listErr := row.f.p.CodesForTest().UnspentBySignIn(t.Context(), sel, false)
				require.NoError(t, listErr)
				assert.Equal(t, []id.ID{record.GrantFamily}, families, "an end of the sign-in reaches it")
			},
		},
		{
			name:      "consent needed, with no prompt, goes to the consent page",
			noConsent: true,
			assert:    atConsentPage,
		},
		{
			name:      "consent needed, the consent stage rests on the cookie, for the session's user and sign-in",
			noConsent: true,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				atConsentPage(t, row, res, err)

				view, viewErr := row.f.p.PendingRequest(t.Context(), handleOf(t, res.Location), res.FlowSecret)
				require.NoError(t, viewErr)
				assert.Equal(t, oidcprovider.StageConsent, view.Stage)

				answer, answerErr := row.consentAnswer(t, res, "openid", "profile")
				require.NoError(t, answerErr)
				record := recordOf(t, row.fixture(), queryOf(t, answer.RedirectTo).Get("code"))
				assert.Equal(t, row.signIn, record.SignIn)
				assert.Empty(t, answer.BrowserSessionSecret, "the consent stage makes no session")
			},
		},
		{
			name:      "a sign-in that ends while the consent page is open cannot answer it",
			noConsent: true,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				atConsentPage(t, row, res, err)
				row.endSignIn(t)

				answer, answerErr := row.consentAnswer(t, res, "openid", "profile")
				require.ErrorIs(t, answerErr, oidcprovider.ErrReauthenticate)
				assert.Equal(t, oidcprovider.ResumeResult{}, answer)
				assert.Zero(t, codesHeld(t, row.fixture(), "u-1", "billing-web"))
			},
		},
		{
			name:      "a user who is missing or disabled when the consent page answers counts as no session",
			noConsent: true,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				atConsentPage(t, row, res, err)

				for name, user := range map[string]func(identity.UserID) (*identity.Details, error){
					"disabled": func(u identity.UserID) (*identity.Details, error) { return &identity.Details{ID: u}, nil },
					"missing":  func(identity.UserID) (*identity.Details, error) { return nil, identity.ErrUserNotFound },
				} {
					row.f.user = user

					answer, answerErr := row.consentAnswer(t, res, "openid", "profile")
					require.ErrorIs(t, answerErr, oidcprovider.ErrReauthenticate, name)
					assert.Empty(t, answer.RedirectTo, name)
					assert.Zero(t, codesHeld(t, row.fixture(), "u-1", "billing-web"), name)
					stored, loadErr := row.f.store.Load(t.Context(), handleDigestOf(t, handleOf(t, res.Location)))
					require.NoError(t, loadErr)
					assert.Equal(t, oidcprovider.StageConsent, stored.Stage, "%s: the handle stays unspent", name)
					_, consentErr := row.f.consents.Load(t.Context(), "u-1", "billing-web")
					assert.ErrorIs(t, consentErr, oidcprovider.ErrNotFound, "%s: no consent remembered", name)
				}
			},
		},
		{
			name:      "the client is judged as it is now when the consent page answers: a scope withdrawn is left out",
			noConsent: true,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				atConsentPage(t, row, res, err)
				changeClient(t, row.fixture(), func(c *oidcprovider.Client) { c.Scopes = []string{"openid"} })

				answer, answerErr := row.consentAnswer(t, res, "openid", "profile")
				require.NoError(t, answerErr)
				record := recordOf(t, row.fixture(), queryOf(t, answer.RedirectTo).Get("code"))
				assert.Equal(t, []string{"openid"}, record.Scopes)
			},
		},
		{
			name:      "the client is judged as it is now when the consent page answers: a redirect URI withdrawn refuses",
			noConsent: true,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				atConsentPage(t, row, res, err)
				changeClient(t, row.fixture(), func(c *oidcprovider.Client) { c.RedirectURIs = []string{otherRedirect} })

				_, answerErr := row.consentAnswer(t, res, "openid", "profile")
				require.ErrorIs(t, answerErr, oidcprovider.ErrUnknownHandle)
				assert.Zero(t, codesHeld(t, row.fixture(), "u-1", "billing-web"))
			},
		},
		{
			name:      "the flow secret a browser holds is kept when a session parks its request",
			noConsent: true,
			in: func(in *oidcprovider.AuthorizeInput) {
				in.FlowSecret = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"
			},
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				atConsentPage(t, row, res, err)
				assert.Equal(t, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA", res.FlowSecret)
			},
		},
		{
			name:      "consent needed, prompt=none answers consent_required",
			noConsent: true,
			params:    silent,
			assert:    consentRequired,
		},
		{
			name:   "prompt=consent goes to the consent page, whatever is remembered",
			params: set("prompt", "consent"),
			assert: atConsentPage,
		},
		{
			name:   "offline_access not consented to, prompt=none answers consent_required",
			params: silently(set("scope", "openid offline_access")),
			prepare: func(t *testing.T, row *sessionRow) {
				t.Helper()
				forgetConsent(t, row)
				require.NoError(t, row.f.consents.Give(t.Context(), "u-1", "billing-web", []string{"openid"}, false, row.f.clk.Now()))
			},
			assert: consentRequired,
		},
		{
			name:   "prompt=select_account skips the session, and the consumer's page is shown it",
			params: set("prompt", "select_account"),
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				atLoginPage(t, row, res, err)

				view, viewErr := row.f.p.PendingRequest(t.Context(), handleOf(t, res.Location), res.FlowSecret)
				require.NoError(t, viewErr)
				assert.Equal(t, []string{"select_account"}, view.Prompt)
			},
		},
		{
			name:   "prompt=select_account, prompt=none, is refused as it is",
			params: func(v url.Values) { v.Set("prompt", "none select_account") },
			assert: func(t *testing.T, _ *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, queryOf(t, res.Location).Get("error"))
				assert.Empty(t, queryOf(t, res.Location).Get("code"))
			},
		},

		{
			name:   "prompt=login shows the login page, and a code comes only after authenticating again",
			params: set("prompt", "login"),
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				atLoginPage(t, row, res, err)
				r := parked{handle: handleOf(t, res.Location), flow: res.FlowSecret}

				old := row.signIn
				_, resumeErr := row.f.p.Resume(t.Context(), r.input(&old))
				require.ErrorIs(t, resumeErr, oidcprovider.ErrReauthenticate)

				row.f.clk.Advance(time.Second)
				again := testSignIn(row.fixture(), "u-1")
				resumed, resumeErr := row.f.p.Resume(t.Context(), r.input(&again))
				require.NoError(t, resumeErr)
				record := recordOf(t, row.fixture(), queryOf(t, resumed.RedirectTo).Get("code"))
				assert.Equal(t, again.Family, record.SignIn.Family)
			},
		},
		{name: "max_age=0 shows the login page", params: set("max_age", "0"), assert: atLoginPage},
		{name: "max_age unmet shows the login page", params: set("max_age", "299"), assert: atLoginPage},
		{name: "max_age met exactly is answered", params: set("max_age", "300"), assert: answered},
		{name: "max_age=0, prompt=none answers login_required", params: silently(set("max_age", "0")), assert: loginRequired},
		{name: "max_age unmet, prompt=none answers login_required", params: silently(set("max_age", "299")), assert: loginRequired},
		{name: "max_age met exactly, prompt=none is answered", params: silently(set("max_age", "300")), assert: answered},
		{
			name:    "a session past its idle deadline counts as none",
			prepare: pastIdle,
			assert:  sessionRanOut,
		},
		{
			name:    "a session past its idle deadline, prompt=none answers login_required",
			params:  silent,
			prepare: pastIdle,
			assert:  silentlyRanOut,
		},
		{
			name: "a session past its absolute deadline counts as none, however recently used",
			signIn: func(f *parkFixture) oidcprovider.SignIn {
				s := testSignIn(f, "u-1")
				s.AbsoluteExpiresAt = f.clk.Now().Add(sessionGap)

				return s
			},
			assert: sessionRanOut,
		},
		{
			name: "a touch does not reach past the absolute deadline",
			signIn: func(f *parkFixture) oidcprovider.SignIn {
				s := testSignIn(f, "u-1")
				s.AbsoluteExpiresAt = f.clk.Now().Add(sessionGap + time.Minute)

				return s
			},
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				codeOf(t, row, res, err)
				assert.True(t, row.loads(t, row.signIn.AbsoluteExpiresAt.Add(-time.Nanosecond)))
				assert.False(t, row.loads(t, row.signIn.AbsoluteExpiresAt))
			},
		},
		{
			name: "no idle timeout touches by a session manager's default",
			in:   func(in *oidcprovider.AuthorizeInput) { in.IdleTimeout = 0 },
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				codeOf(t, row, res, err)
				now := row.f.clk.Now()
				assert.True(t, row.loads(t, now.Add(30*time.Minute-time.Nanosecond)))
				assert.False(t, row.loads(t, now.Add(30*time.Minute)))
			},
		},
		{
			name: "the idle timeout the chain states is what a touch extends by",
			in:   func(in *oidcprovider.AuthorizeInput) { in.IdleTimeout = 40 * time.Minute },
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				codeOf(t, row, res, err)
				now := row.f.clk.Now()
				assert.True(t, row.loads(t, now.Add(40*time.Minute-time.Nanosecond)))
				assert.False(t, row.loads(t, now.Add(40*time.Minute)))
			},
		},
		{
			name: "a negative idle timeout is a wiring mistake",
			in:   func(in *oidcprovider.AuthorizeInput) { in.IdleTimeout = -time.Second },
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.Equal(t, oidcprovider.AuthorizeResult{}, res)
				assert.False(t, row.touched(t))
			},
		},
		{
			name:    "a sign-in authenticated further ahead than the leeway counts as no session",
			prepare: future,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.Location, issuer+"/login?"), res.Location)
				assert.Zero(t, row.f.userLoads, "nothing further is asked of a session already refused")
			},
		},
		{
			name:    "a sign-in authenticated further ahead than the leeway, prompt=none answers login_required",
			params:  silent,
			prepare: future,
			assert:  silentlyRanOut,
		},
		{
			name: "a sign-in authenticated ahead within the leeway counts as now",
			prepare: wrongSignIn(func(row *sessionRow, s *oidcprovider.SignIn) {
				s.AuthenticatedAt = row.f.clk.Now().Add(59 * time.Second)
			}),
			params: set("max_age", "1"),
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				codeOf(t, row, res, err)
			},
		},
		{
			name: "a sign-in within the leeway does not pass for a fresh one under prompt=login",
			prepare: wrongSignIn(func(row *sessionRow, s *oidcprovider.SignIn) {
				s.AuthenticatedAt = row.f.clk.Now().Add(59 * time.Second)
			}),
			params: set("prompt", "login"),
			assert: func(t *testing.T, _ *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.Location, issuer+"/login?"), res.Location)
			},
		},
		{
			name: "a sign-in within the leeway does not pass for a fresh one under max_age=0",
			prepare: wrongSignIn(func(row *sessionRow, s *oidcprovider.SignIn) {
				s.AuthenticatedAt = row.f.clk.Now().Add(59 * time.Second)
			}),
			params: set("max_age", "0"),
			assert: func(t *testing.T, _ *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.Location, issuer+"/login?"), res.Location)
			},
		},
		{
			name: "a stored sign-in past its own deadline counts as no session",
			prepare: wrongSignIn(func(row *sessionRow, s *oidcprovider.SignIn) {
				s.AbsoluteExpiresAt = row.f.clk.Now()
			}),
			assert: sessionRanOut,
		},
		{
			name:    "a stored sign-in with no family counts as no session, since no end could reach its code",
			prepare: wrongSignIn(func(_ *sessionRow, s *oidcprovider.SignIn) { s.Family = id.Nil }),
			assert:  sessionRanOut,
		},
		{
			name:    "a stored sign-in naming no user counts as no session",
			prepare: wrongSignIn(func(_ *sessionRow, s *oidcprovider.SignIn) { s.User = "" }),
			assert:  sessionRanOut,
		},

		{name: "a hint for the session's user proceeds", params: set("id_token_hint", hintFor("u-1")), assert: answered},
		{name: "a hint for the session's user, prompt=none, proceeds", params: silently(set("id_token_hint", hintFor("u-1"))), assert: answered},
		{name: "another subject's hint answers login_required", params: set("id_token_hint", hintFor("u-2")), assert: loginRequired},
		{name: "another subject's hint, prompt=none, answers login_required", params: silently(set("id_token_hint", hintFor("u-2"))), assert: loginRequired},
		{
			name:      "another subject's hint is judged before consent, so prompt=none never reveals a consent",
			noConsent: true,
			params:    silently(set("id_token_hint", hintFor("u-2"))),
			assert:    loginRequired,
		},
		{
			name:   "another subject's hint with prompt=login waits for whoever signs in",
			params: both(set("id_token_hint", hintFor("u-2")), set("prompt", "login")),
			assert: atLoginPage,
		},
		{
			name:    "another subject's hint with a disabled session user waits for whoever signs in",
			params:  set("id_token_hint", hintFor("u-2")),
			prepare: disabled,
			assert:  atLoginPage,
		},
		{name: "a retired key's hint counts as none", params: set("id_token_hint", retiredHint), assert: answered},
		{name: "a retired key's hint, prompt=none, answers login_required", params: silently(set("id_token_hint", retiredHint)), assert: loginRequired},

		{name: "a missing user counts as no session", prepare: missing, assert: atLoginPage},
		{name: "a missing user, prompt=none, answers login_required", params: silent, prepare: missing, assert: loginRequired},
		{name: "a disabled user counts as no session", prepare: disabled, assert: atLoginPage},
		{name: "a disabled user, prompt=none, answers login_required", params: silent, prepare: disabled, assert: loginRequired},
		{name: "a record for someone else counts as no session", prepare: someoneElse, assert: atLoginPage},
		{name: "a loader answering nothing counts as no session", prepare: nobody, assert: atLoginPage},
		{name: "a failing user store is no verdict on the session", prepare: userOutage, assert: outage},
		{name: "a failing user store gives no page under prompt=none", params: silent, prepare: userOutage, assert: outage},
		{
			name:    "a caller who left while the user loaded matches its own context",
			prepare: userIs(func(identity.UserID) (*identity.Details, error) { return nil, context.Canceled }),
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Equal(t, oidcprovider.AuthorizeResult{}, res)
			},
		},

		{
			name:    "WithoutBrowserSessions shows the login page, whatever a store holds, and looks at no one",
			opts:    []oidcprovider.Option{oidcprovider.WithoutBrowserSessions()},
			noLogin: true,
			prepare: holdingAnyway,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				sessionRanOut(t, row, res, err)
				assert.Zero(t, row.f.userLoads)
			},
		},
		{
			name:    "WithoutBrowserSessions, prompt=none always answers login_required",
			opts:    []oidcprovider.Option{oidcprovider.WithoutBrowserSessions()},
			noLogin: true,
			params:  silent,
			prepare: holdingAnyway,
			assert: func(t *testing.T, row *sessionRow, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				silentlyRanOut(t, row, res, err)
				assert.Zero(t, row.f.userLoads)
			},
		},
		{
			name:    "no session at all shows the login page",
			noLogin: true,
			assert:  atLoginPage,
		},
		{
			name:    "no session at all, prompt=none answers login_required",
			noLogin: true,
			params:  silent,
			assert:  loginRequired,
		},
		{
			name:   "a well-formed secret no session has counts as none",
			in:     secretIs("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"),
			assert: sessionRanOut,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			f := newSessionFixture(t, hints.keys, tc.opts...)
			row := &sessionRow{f: f, signIn: testSignIn(f.parkFixture, "u-1")}
			if tc.signIn != nil {
				row.signIn = tc.signIn(f.parkFixture)
			}
			if !tc.noLogin {
				row.secret = heldBrowserSession(t, f.parkFixture, row.signIn)
			}
			if !tc.noConsent {
				rememberAll(t, f.parkFixture)
			}
			f.clk.Advance(sessionGap)
			if tc.prepare != nil {
				tc.prepare(t, row)
			}

			params := authzParams()
			if tc.params != nil {
				tc.params(params)
			}
			in := oidcprovider.AuthorizeInput{Params: params, BrowserSessionSecret: row.secret, IdleTimeout: sessionIdle}
			if tc.in != nil {
				tc.in(&in)
			}
			res, err := f.p.Authorize(ctx, in)

			tc.assert(t, row, res, err)
		})
	}
}

// sessionSecret is the well-formed secret of the session a failure row's store holds.
const sessionSecret = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"

// TestProvider_BrowserSession_Failures fails what answering from a session depends on, in
// turn, through stores a row wires itself.
func TestProvider_BrowserSession_Failures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	held := &oidcprovider.BrowserSession{
		Digest: digestOf(t, sessionSecret),
		SignIn: oidcprovider.SignIn{
			User: "u-1", Family: family, AuthenticatedAt: now.Add(-time.Minute), AMR: []string{"pwd"},
			AbsoluteExpiresAt: now.Add(time.Hour),
		},
		IdleExpiresAt:     now.Add(time.Hour),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	sessionStore := func(t *testing.T) *MockBrowserSessionStore {
		t.Helper()

		return NewMockBrowserSessionStore(gomock.NewController(t))
	}
	holding := func(t *testing.T) *MockBrowserSessionStore {
		t.Helper()
		store := sessionStore(t)
		store.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).Return(held, nil)

		return store
	}
	silent := set("prompt", "none")
	failing := func(t *testing.T, f *sessionFixture, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		serverError(t, res, err)
		assert.Empty(t, res.FlowSecret, "nothing was parked that a page could resume")
		assert.NotContains(t, f.logs.String(), errOutage.Error())
		assert.Contains(t, f.logs.String(), "error_type")
	}
	loginPage := func(t *testing.T, _ *sessionFixture, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.Location, issuer+"/login?"), res.Location)
	}
	loginRequired := func(t *testing.T, _ *sessionFixture, res oidcprovider.AuthorizeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		answer := queryOf(t, res.Location)
		assert.Equal(t, oidcprovider.CodeLoginRequired, answer.Get("error"))
		assert.Empty(t, answer.Get("code"))
		assert.Empty(t, res.FlowSecret)
	}
	storeDown := func(t *testing.T) []oidcprovider.Option {
		t.Helper()
		store := sessionStore(t)
		store.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errOutage)

		return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(store)}
	}
	untouchedStore := func(t *testing.T) []oidcprovider.Option {
		t.Helper()

		return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(sessionStore(t))}
	}

	type testCase struct {
		name    string
		secret  string
		params  func(url.Values)
		consent bool
		wire    func(*testing.T) []oidcprovider.Option
		ctx     func(context.Context) context.Context
		assert  func(*testing.T, *sessionFixture, oidcprovider.AuthorizeResult, error)
	}

	cases := []testCase{
		{name: "the session store being down is a dependency failure, and not no session", consent: true, wire: storeDown, assert: failing},
		{name: "the session store being down gives no page under prompt=none", consent: true, params: silent, wire: storeDown, assert: failing},
		{
			name:    "a caller who left while the session loaded matches its own context",
			consent: true,
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := sessionStore(t)
				store.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, context.Canceled)

				return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(store)}
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, _ *sessionFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Equal(t, oidcprovider.AuthorizeResult{}, res)
			},
		},
		{
			name:    "the store is asked only by digest, and at the provider's time",
			consent: true,
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := sessionStore(t)
				store.EXPECT().Load(gomock.Any(), digestOf(t, sessionSecret), now).Return(nil, oidcprovider.ErrNotFound)

				return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(store)}
			},
			assert: loginPage,
		},
		{name: "prompt=login asks nothing of the store", params: set("prompt", "login"), wire: untouchedStore, assert: loginPage},
		{name: "max_age=0 asks nothing of the store", params: set("max_age", "0"), wire: untouchedStore, assert: loginPage},
		{name: "max_age=0, prompt=none, asks nothing of the store", params: func(v url.Values) {
			v.Set("prompt", "none")
			v.Set("max_age", "0")
		}, wire: untouchedStore, assert: loginRequired},
		{
			name:   "no secret asks nothing of the store",
			secret: "-",
			wire:   untouchedStore,
			assert: loginPage,
		},
		{
			name:   "a secret too short never reaches the store",
			secret: "BBBB",
			wire:   untouchedStore,
			assert: loginPage,
		},
		{
			name:   "a secret too long never reaches the store",
			secret: sessionSecret + "B",
			wire:   untouchedStore,
			assert: loginPage,
		},
		{
			name:   "a secret in padded base64 never reaches the store",
			secret: sessionSecret[:42] + "=",
			wire:   untouchedStore,
			assert: loginPage,
		},
		{
			name:   "a secret of another alphabet never reaches the store",
			secret: sessionSecret[:42] + "+",
			wire:   untouchedStore,
			assert: loginPage,
		},
		{
			name:   "a secret holding a line break never reaches the store",
			secret: sessionSecret[:21] + "\n" + sessionSecret[:21],
			wire:   untouchedStore,
			assert: loginPage,
		},
		{
			name:   "a secret of a second spelling never reaches the store",
			secret: sessionSecret[:42] + "B",
			wire:   untouchedStore,
			assert: loginPage,
		},
		{
			name:   "a malformed secret, prompt=none, answers login_required with no lookup",
			secret: "BBBB",
			params: silent,
			wire:   untouchedStore,
			assert: loginRequired,
		},
		{
			name:    "a touch failing costs no answer, and is logged without its words",
			consent: true,
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := holding(t)
				store.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).Return(errOutage)

				return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(store)}
			},
			assert: func(t *testing.T, f *sessionFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, queryOf(t, res.Location).Get("code"))
				assert.Contains(t, f.logs.String(), "browser session")
				assert.NotContains(t, f.logs.String(), errOutage.Error())
				assert.NotContains(t, f.logs.String(), sessionSecret)
			},
		},
		{
			name:    "a session ended while its code was written answers as no session, and the code never leaves",
			consent: true,
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := holding(t)
				store.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).Return(oidcprovider.ErrNotFound)

				return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(store)}
			},
			assert: loginPage,
		},
		{
			name:    "a session ended while its code was written, prompt=none, answers login_required",
			consent: true,
			params:  silent,
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := holding(t)
				store.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).Return(oidcprovider.ErrNotFound)

				return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(store)}
			},
			assert: loginRequired,
		},
		{
			name: "the session is touched by the idle timeout from the provider's time",
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := holding(t)
				store.EXPECT().Touch(gomock.Any(), digestOf(t, sessionSecret), now.Add(sessionIdle)).Return(nil)

				return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(store)}
			},
			consent: true,
			assert: func(t *testing.T, _ *sessionFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, queryOf(t, res.Location).Get("code"))
			},
		},
		{
			name:    "a code that cannot be stored fails, and touches nothing",
			consent: true,
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				codes := NewMockCodeStore(gomock.NewController(t))
				codes.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage)

				return []oidcprovider.Option{
					oidcprovider.WithBrowserSessionStore(holding(t)),
					oidcprovider.WithCodeStore(codes),
				}
			},
			assert: failing,
		},
		{
			name: "a remembered consent that cannot be read fails, and touches nothing",
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				consents := NewMockConsentStore(gomock.NewController(t))
				consents.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errOutage)

				return []oidcprovider.Option{
					oidcprovider.WithBrowserSessionStore(holding(t)),
					oidcprovider.WithConsentStore(consents),
				}
			},
			assert: failing,
		},
		{
			name: "a request that cannot be parked for consent fails, and touches nothing",
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				pending := NewMockPendingRequestStore(gomock.NewController(t))
				pending.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage)

				return []oidcprovider.Option{
					oidcprovider.WithBrowserSessionStore(holding(t)),
					oidcprovider.WithPendingRequestStore(pending),
				}
			},
			assert: failing,
		},
		{
			name: "a parked request that cannot move to consent fails, and touches nothing",
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				pending := NewMockPendingRequestStore(gomock.NewController(t))
				pending.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				pending.EXPECT().Advance(gomock.Any(), gomock.Any(), oidcprovider.StageLogin, oidcprovider.StageConsent, gomock.Any()).Return(errOutage)

				return []oidcprovider.Option{
					oidcprovider.WithBrowserSessionStore(holding(t)),
					oidcprovider.WithPendingRequestStore(pending),
				}
			},
			assert: failing,
		},
		{
			name: "a touch failing at the consent page costs no answer, and is logged",
			wire: func(t *testing.T) []oidcprovider.Option {
				t.Helper()
				store := holding(t)
				store.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).Return(errOutage)

				return []oidcprovider.Option{oidcprovider.WithBrowserSessionStore(store)}
			},
			assert: func(t *testing.T, f *sessionFixture, res oidcprovider.AuthorizeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.Location, issuer+"/consent?"), res.Location)
				assert.Contains(t, f.logs.String(), "browser session")
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

			f := newSessionFixture(t, plainKeys(t), tc.wire(t)...)
			if tc.consent {
				rememberAll(t, f.parkFixture)
			}

			params := authzParams()
			if tc.params != nil {
				tc.params(params)
			}
			secret := tc.secret
			switch secret {
			case "":
				secret = sessionSecret
			case "-":
				secret = ""
			}
			res, err := f.p.Authorize(ctx, oidcprovider.AuthorizeInput{Params: params, BrowserSessionSecret: secret, IdleTimeout: sessionIdle})

			tc.assert(t, f, res, err)
		})
	}
}

// TestProvider_BrowserSession_ConsentLooksBeforeItSpends proves the consent stage resting on
// the cookie looks at the session before its conditional write, so a session that ended
// releases no code and spends nothing.
func TestProvider_BrowserSession_ConsentLooksBeforeItSpends(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	reauthenticate := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
	}
	dependency := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		assert.NotContains(t, err.Error(), errOutage.Error())
	}

	cases := []struct {
		name   string
		touch  error
		assert func(*testing.T, error)
	}{
		{name: "a session that ended at the last look is no session", touch: oidcprovider.ErrNotFound, assert: reauthenticate},
		{name: "a failing session store is a dependency failure, also before the write", touch: errOutage, assert: dependency},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			family, err := id.NewV7Generator().NewID()
			require.NoError(t, err)
			held := &oidcprovider.BrowserSession{
				Digest: digestOf(t, sessionSecret),
				SignIn: oidcprovider.SignIn{
					User: "u-1", Family: family, AuthenticatedAt: now.Add(-time.Minute),
					AMR: []string{"pwd"}, AbsoluteExpiresAt: now.Add(time.Hour),
				},
				IdleExpiresAt:     now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(time.Hour),
			}
			store := NewMockBrowserSessionStore(gomock.NewController(t))
			store.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).Return(held, nil).AnyTimes()
			gomock.InOrder(
				store.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
				store.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).Return(tc.touch),
			)
			f := newSessionFixture(t, plainKeys(t), oidcprovider.WithBrowserSessionStore(store))

			res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{
				Params: authzParams(), BrowserSessionSecret: sessionSecret, IdleTimeout: sessionIdle,
			})
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(res.Location, issuer+"/consent?"), res.Location)

			answer, err := f.p.Resume(t.Context(), oidcprovider.ResumeInput{
				Handle: handleOf(t, res.Location), FlowSecret: res.FlowSecret, BrowserSessionSecret: sessionSecret,
				IdleTimeout: sessionIdle, Answer: &oidcprovider.ConsentAnswer{Scopes: []string{"openid", "profile"}},
			})

			tc.assert(t, err)
			assert.Empty(t, answer.RedirectTo, "no code is released")
			assert.Zero(t, codesHeld(t, f.parkFixture, "u-1", "billing-web"))
			stored, loadErr := f.store.Load(t.Context(), handleDigestOf(t, handleOf(t, res.Location)))
			require.NoError(t, loadErr)
			assert.Equal(t, oidcprovider.StageConsent, stored.Stage, "the handle stays unspent")
			_, consentErr := f.consents.Load(t.Context(), "u-1", "billing-web")
			assert.ErrorIs(t, consentErr, oidcprovider.ErrNotFound, "no consent remembered")
		})
	}
}

func TestProvider_BrowserSession_InputPrintsRedacted(t *testing.T) {
	t.Parallel()

	in := oidcprovider.AuthorizeInput{BrowserSessionSecret: sessionSecret, FlowSecret: sessionSecret}
	logs := &bytes.Buffer{}
	slog.New(slog.NewTextHandler(logs, nil)).Info("authorize", "input", in)
	for _, printed := range []string{fmt.Sprintf("%v", in), fmt.Sprintf("%+v", in), fmt.Sprintf("%#v", in), logs.String()} {
		assert.NotContains(t, printed, sessionSecret)
	}
}
