package oidcprovider_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// errOutage is a dependency failing, with text no answer may repeat.
var errOutage = errors.New("store secret text")

// testSignIn is a complete sign-in of user, which last authenticated at the fixture's
// present.
func testSignIn(f *parkFixture, user identity.UserID) oidcprovider.SignIn {
	family, err := id.NewV7Generator().NewID()
	if err != nil {
		panic(err)
	}

	return oidcprovider.SignIn{
		User:              user,
		Family:            family,
		AuthenticatedAt:   f.clk.Now(),
		AMR:               []string{"pwd", "otp"},
		ACR:               "urn:example:mfa",
		AbsoluteExpiresAt: f.clk.Now().Add(8 * time.Hour),
		ExternalIssuer:    "https://upstream.example.com",
		ExternalSessionID: "upstream-session",
	}
}

// parked is a request a row has parked: what a browser holds for it.
type parked struct {
	handle, flow string
}

func park(t *testing.T, f *parkFixture, change func(url.Values)) parked {
	t.Helper()

	params := authzParams()
	if change != nil {
		change(params)
	}
	res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: params})
	require.NoError(t, err)
	require.NotEmpty(t, res.FlowSecret, "the request was parked: %s", res.Location)

	return parked{handle: handleOf(t, res.Location), flow: res.FlowSecret}
}

func (r parked) input(signIn *oidcprovider.SignIn) oidcprovider.ResumeInput {
	return oidcprovider.ResumeInput{Handle: r.handle, FlowSecret: r.flow, SignIn: signIn, IdleTimeout: 15 * time.Minute}
}

// stageOf reads how far the request has come.
func stageOf(t *testing.T, f *parkFixture, r parked) oidcprovider.Stage {
	t.Helper()

	stored, err := f.store.Load(t.Context(), handleDigestOf(t, r.handle))
	require.NoError(t, err)

	return stored.Stage
}

func queryOf(t *testing.T, location string) url.Values {
	t.Helper()

	parsed, err := url.Parse(location)
	require.NoError(t, err)

	return parsed.Query()
}

// tokenIDOf reads the record identifier out of a code.
func tokenIDOf(t *testing.T, code string) id.ID {
	t.Helper()

	before, _, found := strings.Cut(code, ".")
	require.True(t, found, "a code is a token/onetime string")
	tokenID, err := id.Parse(before)
	require.NoError(t, err)

	return tokenID
}

func recordOf(t *testing.T, f *parkFixture, code string) *oidcprovider.CodeRecord {
	t.Helper()

	record, err := f.p.CodesForTest().Load(t.Context(), tokenIDOf(t, code))
	require.NoError(t, err)

	return record
}

// codesHeld counts the code records held for user at client.
func codesHeld(t *testing.T, f *parkFixture, user identity.UserID, clientID string) int {
	t.Helper()

	families, err := f.p.CodesForTest().UnspentByClient(t.Context(), user, clientID)
	require.NoError(t, err)

	return len(families)
}

// browserSessionsHeld counts what the store holds, and forgets it, so it is a row's last
// question.
func browserSessionsHeld(t *testing.T, f *parkFixture) int {
	t.Helper()

	held, err := f.p.BrowserSessionStoreForTest().DeleteExpired(t.Context(), f.clk.Now().Add(1000*time.Hour))
	require.NoError(t, err)

	return held
}

// resumesAfterReauthentication proves a refusal left the login stage unspent.
func resumesAfterReauthentication(t *testing.T, f *parkFixture, r parked) {
	t.Helper()

	assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r), "the refusal spent nothing")
	f.clk.Advance(time.Second)
	signIn := testSignIn(f, "u-1")
	res, err := f.p.Resume(t.Context(), r.input(&signIn))
	require.NoError(t, err, "the handle still resumes")
	assert.NotEmpty(t, res.RedirectTo)
}

// refusedUnspent asserts an exact refusal that issued nothing, and spent nothing.
func refusedUnspent(want error) func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error) {
	return func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, want)
		assert.Empty(t, res.RedirectTo)
		assert.Empty(t, res.BrowserSessionSecret)
		assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"))
		resumesAfterReauthentication(t, f, r)
	}
}

func TestProvider_ResumeLogin(t *testing.T) {
	t.Parallel()

	remember := func(t *testing.T, f *parkFixture) {
		t.Helper()
		require.NoError(t, f.consents.Give(t.Context(), "u-1", "billing-web", []string{"openid", "profile"}, false, f.clk.Now()))
	}
	unknownAlike := func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
		assert.Equal(t, oidcprovider.ErrUnknownHandle.Error(), err.Error(), "every refusal reads alike")
		assert.Equal(t, oidcprovider.ResumeResult{}, res)
		assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"))
		assert.Zero(t, browserSessionsHeld(t, f))
		resumesAfterReauthentication(t, f, r)
	}
	otherSecret := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	type testCase struct {
		name    string
		hint    bool
		opts    []oidcprovider.Option
		params  func(url.Values)
		prepare func(*testing.T, *parkFixture)
		in      func(*testing.T, *parkFixture, *oidcprovider.ResumeInput)
		ctx     func(context.Context) context.Context
		assert  func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error)
	}

	reauthenticate := refusedUnspent(oidcprovider.ErrReauthenticate)
	withSignIn := func(change func(*parkFixture, *oidcprovider.SignIn)) func(*testing.T, *parkFixture, *oidcprovider.ResumeInput) {
		return func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) { change(f, in.SignIn) }
	}
	aged := func(age time.Duration) func(*testing.T, *parkFixture, *oidcprovider.ResumeInput) {
		return withSignIn(func(f *parkFixture, s *oidcprovider.SignIn) {
			s.AuthenticatedAt = f.clk.Now().Add(-age)
		})
	}
	proceeds := func(t *testing.T, _ *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotEmpty(t, res.RedirectTo)
	}

	cases := []testCase{
		{
			name:   "another browser's flow secret refuses exactly as an unknown handle does",
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { in.FlowSecret = otherSecret },
			assert: unknownAlike,
		},
		{
			name:   "no flow secret refuses as an unknown handle",
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { in.FlowSecret = "" },
			assert: unknownAlike,
		},
		{
			name: "a handle of no valid shape refuses as an unknown handle",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.Handle = "rh.not-an-id." + otherSecret
			},
			assert: unknownAlike,
		},
		{
			name: "a well-formed handle no one parked refuses as an unknown handle",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.Handle = "rh.00000000-0000-7000-8000-000000000000." + otherSecret
			},
			assert: unknownAlike,
		},
		{
			name: "a second resume of the stage is an unknown handle, and the consent stage stands",
			assert: func(t *testing.T, f *parkFixture, r parked, _ oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)

				signIn := testSignIn(f, "u-1")
				again, err := f.p.Resume(t.Context(), r.input(&signIn))
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Equal(t, oidcprovider.ResumeResult{}, again)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))
			},
		},
		{
			name:    "a second resume after a code issues no second code",
			prepare: remember,
			assert: func(t *testing.T, f *parkFixture, r parked, _ oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.Equal(t, 1, codesHeld(t, f, "u-1", "billing-web"))

				signIn := testSignIn(f, "u-1")
				_, err = f.p.Resume(t.Context(), r.input(&signIn))
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Equal(t, 1, codesHeld(t, f, "u-1", "billing-web"))
			},
		},
		{
			name: "a consent answer at the login stage is refused, and the login stage stands",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.Answer = &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}
			},
			assert: refusedUnspent(oidcprovider.ErrUnknownHandle),
		},
		{
			name:   "no sign-in is refused, and leaves the handle unspent",
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { in.SignIn = nil },
			assert: reauthenticate,
		},
		{
			name: "a browser session never stands in at the login stage",
			in: func(t *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				t.Helper()
				in.SignIn = nil
				in.BrowserSessionSecret = heldBrowserSession(t, f, testSignIn(f, "u-1"))
			},
			assert: func(t *testing.T, f *parkFixture, r parked, _ oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
				assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r))
			},
		},
		{
			name: "a sign-in past its absolute deadline cannot resume",
			in: withSignIn(func(f *parkFixture, s *oidcprovider.SignIn) {
				s.AbsoluteExpiresAt = f.clk.Now().Add(-time.Nanosecond)
			}),
			assert: reauthenticate,
		},
		{
			name: "a sign-in at its absolute deadline cannot resume",
			in: withSignIn(func(f *parkFixture, s *oidcprovider.SignIn) {
				s.AbsoluteExpiresAt = f.clk.Now()
			}),
			assert: reauthenticate,
		},
		{
			name:   "a sign-in with no absolute deadline cannot resume",
			in:     withSignIn(func(_ *parkFixture, s *oidcprovider.SignIn) { s.AbsoluteExpiresAt = time.Time{} }),
			assert: reauthenticate,
		},
		{
			name:   "a sign-in with no authentication time cannot resume",
			in:     withSignIn(func(_ *parkFixture, s *oidcprovider.SignIn) { s.AuthenticatedAt = time.Time{} }),
			assert: reauthenticate,
		},
		{
			name:   "a sign-in with no family cannot resume",
			in:     withSignIn(func(_ *parkFixture, s *oidcprovider.SignIn) { s.Family = id.Nil }),
			assert: reauthenticate,
		},
		{
			name:   "max_age is judged by the authentication time",
			params: set("max_age", "300"),
			in:     aged(20 * time.Minute),
			assert: reauthenticate,
		},
		{
			name:   "max_age is met exactly at its boundary",
			params: set("max_age", "300"),
			in:     aged(300 * time.Second),
			assert: proceeds,
		},
		{
			name:   "max_age fails just past its boundary",
			params: set("max_age", "300"),
			in:     aged(300*time.Second + time.Nanosecond),
			assert: reauthenticate,
		},
		{
			name:   "max_age=0 refuses a sign-in from before parking, however recent",
			params: set("max_age", "0"),
			in:     aged(time.Nanosecond),
			assert: reauthenticate,
		},
		{
			name:   "max_age=0 refuses a sign-in at the very moment of parking",
			params: set("max_age", "0"),
			assert: reauthenticate,
		},
		{
			name:   "max_age=0 accepts one authenticated after parking, whatever its age",
			params: set("max_age", "0"),
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				in.SignIn.AuthenticatedAt = f.clk.Now().Add(time.Nanosecond)
				f.clk.Advance(9 * time.Minute)
			},
			assert: proceeds,
		},
		{
			name:   "prompt=login refuses a sign-in from before parking, even one renewed since",
			params: set("prompt", "login"),
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				f.clk.Advance(time.Minute)
				in.SignIn.AuthenticatedAt = f.clk.Now().Add(-2 * time.Minute)
				in.SignIn.AbsoluteExpiresAt = f.clk.Now().Add(8 * time.Hour)
			},
			assert: reauthenticate,
		},
		{
			name:   "prompt=login refuses a sign-in at the very moment of parking",
			params: set("prompt", "login"),
			assert: reauthenticate,
		},
		{
			name:   "prompt=login accepts a user who authenticated after parking",
			params: set("prompt", "login"),
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				f.clk.Advance(time.Second)
				in.SignIn.AuthenticatedAt = f.clk.Now()
			},
			assert: proceeds,
		},
		{
			name:   "prompt=login and an unmet max_age both have to be met",
			params: func(v url.Values) { v.Set("prompt", "login"); v.Set("max_age", "60") },
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				in.SignIn.AuthenticatedAt = f.clk.Now().Add(time.Second)
				f.clk.Advance(2 * time.Minute)
			},
			assert: reauthenticate,
		},
		{
			name: "a hint naming the sign-in's user proceeds",
			hint: true,
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, queryOf(t, res.RedirectTo).Get("error"))
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))
			},
		},
		{
			name: "a hint naming another subject answers login_required, and ends the request",
			hint: true,
			in:   withSignIn(func(_ *parkFixture, s *oidcprovider.SignIn) { s.User = "u-2" }),
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.RedirectTo, authzRedirect+"?"), res.RedirectTo)
				answer := queryOf(t, res.RedirectTo)
				assert.Equal(t, oidcprovider.CodeLoginRequired, answer.Get("error"))
				assert.Equal(t, authzState, answer.Get("state"))
				assert.Equal(t, issuer, answer.Get("iss"))
				assert.Empty(t, answer.Get("code"))
				assert.Empty(t, res.BrowserSessionSecret, "no session for a sign-in the request refused")
				assert.Zero(t, codesHeld(t, f, "u-2", "billing-web"))
				assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))
				assert.Zero(t, browserSessionsHeld(t, f))
			},
		},
		{
			name: "a principal with no identifier fails matching token.ErrNoSubject, and issues nothing",
			in:   withSignIn(func(_ *parkFixture, s *oidcprovider.SignIn) { s.User = "" }),
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, token.ErrNoSubject)
				require.NotErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
				assert.Zero(t, codesHeld(t, f, "", "billing-web"))
				assert.Zero(t, browserSessionsHeld(t, f))
				resumesAfterReauthentication(t, f, r)
			},
		},
		{
			name: "a wrong browser hears of an unknown handle before anything about its principal",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.FlowSecret = otherSecret
				in.SignIn.User = ""
			},
			assert: unknownAlike,
		},
		{
			name: "consent needed answers the consent URL with the same handle, and keeps the sign-in",
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, issuer+"/consent?req="+url.QueryEscape(r.handle), res.RedirectTo)
				assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"), "no code before consent")

				stored, loadErr := f.store.Load(t.Context(), handleDigestOf(t, r.handle))
				require.NoError(t, loadErr)
				assert.Equal(t, oidcprovider.StageConsent, stored.Stage)
				require.NotNil(t, stored.SignIn)
				assert.Equal(t, identity.UserID("u-1"), stored.SignIn.User)

				_, loadErr = f.consents.Load(t.Context(), "u-1", "billing-web")
				require.ErrorIs(t, loadErr, oidcprovider.ErrNotFound, "no consent before the user gave it")
			},
		},
		{
			name:    "consent not needed answers the redirect URI with code, state and iss",
			prepare: remember,
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.RedirectTo, authzRedirect+"?"), res.RedirectTo)
				answer := queryOf(t, res.RedirectTo)
				assert.NotEmpty(t, answer.Get("code"))
				assert.Equal(t, authzState, answer.Get("state"))
				assert.Equal(t, issuer, answer.Get("iss"))
				assert.Empty(t, answer.Get("error"))
				assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))
				assert.Equal(t, []string{"openid", "profile"}, recordOf(t, f, answer.Get("code")).Scopes)
			},
		},
		{
			name: "a client since removed refuses as an unknown handle",
			in: func(t *testing.T, f *parkFixture, _ *oidcprovider.ResumeInput) {
				t.Helper()
				require.NoError(t, f.registry.Delete(t.Context(), "billing-web"))
			},
			assert: func(t *testing.T, _ *parkFixture, _ parked, _ oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
			},
		},
		{
			name: "a negative idle timeout is a wiring mistake, and spends nothing",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.IdleTimeout = -time.Second
			},
			assert: func(t *testing.T, f *parkFixture, r parked, _ oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConfig)
				assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r))
			},
		},
		{
			name: "a successful resume records a browser session, held only as a digest",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.IdleTimeout = 5 * time.Minute
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotEmpty(t, res.BrowserSessionSecret)

				now := f.clk.Now()
				held, loadErr := f.p.BrowserSessionStoreForTest().Load(t.Context(), digestOf(t, res.BrowserSessionSecret), now)
				require.NoError(t, loadErr)
				assert.Equal(t, now.Add(5*time.Minute), held.IdleExpiresAt)
				assert.Equal(t, now.Add(8*time.Hour), held.AbsoluteExpiresAt, "the sign-in's own deadline")
				assert.Equal(t, identity.UserID("u-1"), held.SignIn.User)
				assert.Equal(t, []string{"pwd", "otp"}, held.SignIn.AMR)
				for _, text := range everyString(reflect.ValueOf(held)) {
					assert.NotContains(t, text, res.BrowserSessionSecret)
				}
			},
		},
		{
			name: "an idle timeout of zero takes a session manager's default",
			in:   func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { in.IdleTimeout = 0 },
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)

				manager, buildErr := session.New()
				require.NoError(t, buildErr)
				held, loadErr := f.p.BrowserSessionStoreForTest().Load(t.Context(), digestOf(t, res.BrowserSessionSecret), f.clk.Now())
				require.NoError(t, loadErr)
				assert.Equal(t, f.clk.Now().Add(manager.IdleTimeout()), held.IdleExpiresAt)
			},
		},
		{
			name: "a newer resume replaces the browser's session with a new secret",
			in: func(t *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				t.Helper()
				in.BrowserSessionSecret = heldBrowserSession(t, f, testSignIn(f, "u-1"))
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				require.NotEmpty(t, res.BrowserSessionSecret)
				assert.Equal(t, 1, browserSessionsHeld(t, f), "the old session is gone, and only the new one is left")
			},
		},
		{
			name: "a presented session secret of no valid shape deletes nothing, and fails nothing",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.BrowserSessionSecret = "not a secret"
			},
			assert: proceeds,
		},
		{
			name: "under WithoutBrowserSessions no session is recorded",
			opts: []oidcprovider.Option{oidcprovider.WithoutBrowserSessions()},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Empty(t, res.BrowserSessionSecret)
				assert.Zero(t, browserSessionsHeld(t, f))
			},
		},
		{
			name: "a caller who left before the load is no outage",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, f *parkFixture, r parked, _ oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var f *parkFixture
			change := tc.params
			if tc.hint {
				hints := newHintFixture(t)
				f = newParkFixtureKeys(t, issuer+"/login", hints.keys, tc.opts...)
				change = set("id_token_hint", hints.issued(t, token.TypeIDToken, issuer, f.clk.Now()))
			} else {
				f = newParkFixture(t, issuer+"/login", tc.opts...)
			}
			if tc.prepare != nil {
				tc.prepare(t, f)
			}
			r := park(t, f, change)

			signIn := testSignIn(f, "u-1")
			in := r.input(&signIn)
			if tc.in != nil {
				tc.in(t, f, &in)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
				f.p = cancelledLoadProvider(t, f)
			}

			res, err := f.p.Resume(ctx, in)
			tc.assert(t, f, r, res, err)
		})
	}
}

// cancelledLoadProvider rebuilds the fixture's provider over a store that notices its
// context, as a durable one does, keeping everything parked so far.
func cancelledLoadProvider(t *testing.T, f *parkFixture) *oidcprovider.Provider {
	t.Helper()

	store := passThroughPending(t, f.store)
	store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			return f.store.Load(ctx, digest)
		},
	).AnyTimes()
	store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(f.store.Advance).AnyTimes()

	return rebuilt(t, f, oidcprovider.WithPendingRequestStore(store))
}

// passThroughPending is a mock pending-request store whose Create reaches memory. A row
// states Load and Advance for itself.
func passThroughPending(t *testing.T, memory *oidcprovider.MemoryPendingRequestStore) *MockPendingRequestStore {
	t.Helper()

	store := NewMockPendingRequestStore(gomock.NewController(t))
	store.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memory.Create).AnyTimes()

	return store
}

// rebuilt builds another provider over the fixture's clock, stores and clients, with opts
// replacing what a row wants to fail.
func rebuilt(t *testing.T, f *parkFixture, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	base := []oidcprovider.Option{
		oidcprovider.WithClock(f.clk),
		oidcprovider.WithPendingRequestStore(f.store),
		oidcprovider.WithConsentStore(f.consents),
		oidcprovider.WithCodeStore(f.p.CodesForTest()),
		oidcprovider.WithCodeTokenStore(f.p.CodeTokensForTest()),
		oidcprovider.WithBrowserSessionStore(f.p.BrowserSessionStoreForTest()),
		oidcprovider.WithLogger(slog.New(slog.NewTextHandler(f.logs, nil))),
	}
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     f.registry,
		Keys:         plainKeys(t),
		Users:        activeUsers(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, append(base, opts...)...)
	require.NoError(t, err)

	return p
}

// heldBrowserSession stores a session as a login stage would, and returns its secret.
func heldBrowserSession(t *testing.T, f *parkFixture, signIn oidcprovider.SignIn) string {
	t.Helper()

	r := park(t, f, nil)
	res, err := f.p.Resume(t.Context(), r.input(&signIn))
	require.NoError(t, err)
	require.NotEmpty(t, res.BrowserSessionSecret)

	return res.BrowserSessionSecret
}

// TestProvider_ResumeLogin_WriteOrder fails each write a resume makes in turn: nothing
// before the stage is spent may leave it spent, and nothing after may lose the answer.
func TestProvider_ResumeLogin_WriteOrder(t *testing.T) {
	t.Parallel()

	failing := func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidcprovider.ErrDependency)
		require.NotErrorIs(t, err, oidcprovider.ErrUnknownHandle)
		assert.NotContains(t, err.Error(), errOutage.Error())
		assert.Equal(t, oidcprovider.ResumeResult{}, res, "nothing leaves")
		assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r), "the handle stays unspent")
	}

	cases := []struct {
		name    string
		wire    func(t *testing.T, f *parkFixture) oidcprovider.Option
		oldSess bool
		covered bool
		assert  func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error)
	}{
		{
			name:    "the code's token cannot be written",
			covered: true,
			wire: func(t *testing.T, _ *parkFixture) oidcprovider.Option {
				t.Helper()
				store := NewMockCodeTokenStore(gomock.NewController(t))
				store.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errOutage)

				return oidcprovider.WithCodeTokenStore(store)
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				failing(t, f, r, res, err)
				assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"), "no record without its token")
			},
		},
		{
			name:    "the code's record cannot be written",
			covered: true,
			wire: func(t *testing.T, _ *parkFixture) oidcprovider.Option {
				t.Helper()
				store := NewMockCodeStore(gomock.NewController(t))
				store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage)

				return oidcprovider.WithCodeStore(store)
			},
			assert: failing,
		},
		{
			name: "the browser session cannot be written",
			wire: func(t *testing.T, _ *parkFixture) oidcprovider.Option {
				t.Helper()
				store := NewMockBrowserSessionStore(gomock.NewController(t))
				store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errOutage)

				return oidcprovider.WithBrowserSessionStore(store)
			},
			assert: failing,
		},
		{
			name: "the stage cannot be spent",
			wire: func(t *testing.T, f *parkFixture) oidcprovider.Option {
				t.Helper()
				store := passThroughPending(t, f.store)
				store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(f.store.Load).AnyTimes()
				store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errOutage)

				return oidcprovider.WithPendingRequestStore(store)
			},
			assert: failing,
		},
		{
			name: "the remembered consent cannot be read",
			wire: func(t *testing.T, _ *parkFixture) oidcprovider.Option {
				t.Helper()
				store := NewMockConsentStore(gomock.NewController(t))
				store.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errOutage)

				return oidcprovider.WithConsentStore(store)
			},
			assert: failing,
		},
		{
			name: "the race for the stage is lost: an unknown handle, and nothing leaves",
			wire: func(t *testing.T, f *parkFixture) oidcprovider.Option {
				t.Helper()
				store := passThroughPending(t, f.store)
				store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(f.store.Load).AnyTimes()
				store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidcprovider.ErrNotFound)

				return oidcprovider.WithPendingRequestStore(store)
			},
			assert: func(t *testing.T, _ *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
			},
		},
		{
			name:    "a lost race leaves the browser's old session alone",
			oldSess: true,
			wire: func(t *testing.T, f *parkFixture) oidcprovider.Option {
				t.Helper()
				store := passThroughPending(t, f.store)
				store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(f.store.Load).AnyTimes()
				store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidcprovider.ErrNotFound)

				return oidcprovider.WithPendingRequestStore(store)
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, _ oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Equal(t, 2, browserSessionsHeld(t, f), "the old session, and the unshown secret's, which no one can load")
			},
		},
		{
			name:    "the old session cannot be deleted: the answer stands, and the failure is logged",
			oldSess: true,
			wire: func(t *testing.T, f *parkFixture) oidcprovider.Option {
				t.Helper()
				memory := f.p.BrowserSessionStoreForTest()
				store := NewMockBrowserSessionStore(gomock.NewController(t))
				store.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(memory.Put)
				store.EXPECT().Delete(gomock.Any(), gomock.Any()).Return(errOutage)

				return oidcprovider.WithBrowserSessionStore(store)
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, res.RedirectTo)
				assert.NotEmpty(t, res.BrowserSessionSecret)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))
				assert.Contains(t, f.logs.String(), "browser session")
				assert.NotContains(t, f.logs.String(), errOutage.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newParkFixture(t, issuer+"/login")
			if tc.covered {
				require.NoError(t, f.consents.Give(t.Context(), "u-1", "billing-web", []string{"openid", "profile"}, false, f.clk.Now()))
			}
			r := park(t, f, nil)
			signIn := testSignIn(f, "u-1")
			in := r.input(&signIn)
			if tc.oldSess {
				other := testSignIn(f, "u-1")
				in.BrowserSessionSecret = heldBrowserSession(t, f, other)
			}

			f.p = rebuilt(t, f, tc.wire(t, f))
			res, err := f.p.Resume(t.Context(), in)
			tc.assert(t, f, r, res, err)

			for _, secret := range []string{r.handle, r.flow, in.BrowserSessionSecret, res.BrowserSessionSecret} {
				if secret != "" {
					assert.NotContains(t, f.logs.String(), secret)
					if err != nil {
						assert.NotContains(t, err.Error(), secret)
					}
				}
			}
		})
	}
}

// TestProvider_ResumeLogin_Race holds racing resumes of one handle to one winner.
func TestProvider_ResumeLogin_Race(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		prepare func(*testing.T, *parkFixture)
		assert  func(t *testing.T, f *parkFixture, r parked, winner oidcprovider.ResumeResult)
	}{
		{
			name: "to the consent stage",
			assert: func(t *testing.T, f *parkFixture, r parked, winner oidcprovider.ResumeResult) {
				t.Helper()
				assert.Equal(t, issuer+"/consent?req="+url.QueryEscape(r.handle), winner.RedirectTo)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))
			},
		},
		{
			name: "to a code",
			prepare: func(t *testing.T, f *parkFixture) {
				t.Helper()
				require.NoError(t, f.consents.Give(t.Context(), "u-1", "billing-web", []string{"openid", "profile"}, false, f.clk.Now()))
			},
			assert: func(t *testing.T, f *parkFixture, r parked, winner oidcprovider.ResumeResult) {
				t.Helper()
				code := queryOf(t, winner.RedirectTo).Get("code")
				require.NotEmpty(t, code)
				assert.Equal(t, "billing-web", recordOf(t, f, code).ClientID)
				assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newParkFixture(t, issuer+"/login")
			if tc.prepare != nil {
				tc.prepare(t, f)
			}
			r := park(t, f, nil)

			winners := raceResumes(t, 32, func(int) oidcprovider.ResumeInput {
				signIn := testSignIn(f, "u-1")

				return r.input(&signIn)
			}, f.p)
			require.Len(t, winners, 1, "one winner")
			tc.assert(t, f, r, winners[0])
		})
	}
}

// raceResumes runs n resumes together, requires every loser to be an unknown handle with
// nothing in hand, and returns what the winners were answered.
func raceResumes(
	t *testing.T, n int, input func(int) oidcprovider.ResumeInput, p *oidcprovider.Provider,
) []oidcprovider.ResumeResult {
	t.Helper()

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		winners []oidcprovider.ResumeResult
		start   = make(chan struct{})
	)
	for i := range n {
		wg.Go(func() {
			<-start
			res, err := p.Resume(t.Context(), input(i))

			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners = append(winners, res)

				return
			}
			assert.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
			assert.Equal(t, oidcprovider.ResumeResult{}, res)
		})
	}
	close(start)
	wg.Wait()

	return winners
}

func TestResumeTypes_PrintRedacted(t *testing.T) {
	t.Parallel()

	const secret = "the-secret-value"
	signIn := oidcprovider.SignIn{User: "u-1"}
	cases := []struct {
		name  string
		value any
	}{
		{
			name: "the input",
			value: oidcprovider.ResumeInput{
				Handle: secret, FlowSecret: secret, BrowserSessionSecret: secret, SignIn: &signIn,
			},
		},
		{
			name:  "the result",
			value: oidcprovider.ResumeResult{RedirectTo: secret, BrowserSessionSecret: secret},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &bytes.Buffer{}
			slog.New(slog.NewTextHandler(logs, nil)).Info("resume", "value", tc.value)
			for _, printed := range []string{
				fmt.Sprintf("%v", tc.value), fmt.Sprintf("%+v", tc.value), fmt.Sprintf("%#v", tc.value),
				fmt.Sprintf("%s", tc.value), logs.String(),
			} {
				assert.NotContains(t, printed, secret)
			}
		})
	}
}

// atConsent parks a request and resumes its login stage with signIn, so the consent stage
// waits.
func atConsent(t *testing.T, f *parkFixture, change func(url.Values), signIn oidcprovider.SignIn) (parked, oidcprovider.ResumeResult) {
	t.Helper()

	r := park(t, f, change)
	res, err := f.p.Resume(t.Context(), r.input(&signIn))
	require.NoError(t, err)
	require.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))

	return r, res
}

func answerWith(in *oidcprovider.ResumeInput, scopes ...string) {
	in.Answer = &oidcprovider.ConsentAnswer{Scopes: scopes}
}

func TestProvider_ResumeConsent(t *testing.T) {
	t.Parallel()

	threeScopes := set("scope", "openid profile email")

	unspent := func(t *testing.T, f *parkFixture, r parked) {
		t.Helper()
		assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r), "the stage can still be answered")
		assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"), "no code")

		_, err := f.consents.Load(t.Context(), "u-1", "billing-web")
		require.ErrorIs(t, err, oidcprovider.ErrNotFound, "no consent")

		f.clk.Advance(time.Millisecond)
		signIn := testSignIn(f, "u-1")
		in := r.input(&signIn)
		answerWith(&in, "openid")
		res, err := f.p.Resume(t.Context(), in)
		require.NoError(t, err, "the stage still resumes")
		assert.NotEmpty(t, queryOf(t, res.RedirectTo).Get("code"))
	}
	refused := func(want error) func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error) {
		return func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
			t.Helper()
			require.ErrorIs(t, err, want)
			assert.Equal(t, want.Error(), err.Error())
			assert.Equal(t, oidcprovider.ResumeResult{}, res)
			unspent(t, f, r)
		}
	}
	malformed := refused(oidcprovider.ErrConsentMalformed)
	code := func(t *testing.T, res oidcprovider.ResumeResult, err error) string {
		t.Helper()
		require.NoError(t, err)
		value := queryOf(t, res.RedirectTo).Get("code")
		require.NotEmpty(t, value, res.RedirectTo)

		return value
	}

	type testCase struct {
		name   string
		opts   []oidcprovider.Option
		params func(url.Values)
		in     func(*testing.T, *parkFixture, *oidcprovider.ResumeInput)
		assert func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error)
	}

	cases := []testCase{
		{
			name:   "a partial grant binds the code to the scopes granted, not those requested",
			params: threeScopes,
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in, "openid", "profile") },
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				record := recordOf(t, f, code(t, res, err))
				assert.Equal(t, []string{"openid", "profile"}, record.Scopes)
				answer := queryOf(t, res.RedirectTo)
				assert.Equal(t, authzState, answer.Get("state"))
				assert.Equal(t, issuer, answer.Get("iss"))
				assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))
			},
		},
		{
			name:   "a repeated scope counts once, in the request's order",
			params: threeScopes,
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				answerWith(in, "profile", "openid", "profile")
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.Equal(t, []string{"openid", "profile"}, recordOf(t, f, code(t, res, err)).Scopes)
			},
		},
		{
			name: "a denial answers access_denied, state and iss, and records nothing",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.Answer = &oidcprovider.ConsentAnswer{Deny: true}
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.RedirectTo, authzRedirect+"?"), res.RedirectTo)
				answer := queryOf(t, res.RedirectTo)
				assert.Equal(t, oidcprovider.CodeAccessDenied, answer.Get("error"))
				assert.Equal(t, authzState, answer.Get("state"))
				assert.Equal(t, issuer, answer.Get("iss"))
				assert.Empty(t, answer.Get("code"))
				assert.NotContains(t, answer, "error_description")
				assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"))
				assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))

				_, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.ErrorIs(t, loadErr, oidcprovider.ErrNotFound)

				signIn := testSignIn(f, "u-1")
				in := r.input(&signIn)
				answerWith(&in, "openid")
				_, err = f.p.Resume(t.Context(), in)
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle, "a denial spends the stage")
			},
		},
		{
			name:   "a denial needs no fresh sign-in, because it grants nothing",
			params: set("max_age", "60"),
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				f.clk.Advance(5 * time.Minute)
				in.Answer = &oidcprovider.ConsentAnswer{Deny: true}
			},
			assert: func(t *testing.T, _ *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.CodeAccessDenied, queryOf(t, res.RedirectTo).Get("error"))
			},
		},
		{
			name: "a denial naming scopes contradicts itself",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.Answer = &oidcprovider.ConsentAnswer{Deny: true, Scopes: []string{"openid"}}
			},
			assert: malformed,
		},
		{
			name: "another user at the consent stage is an unknown handle, and spends nothing",
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				other := testSignIn(f, "u-2")
				in.SignIn = &other
				answerWith(in, "openid")
			},
			assert: refused(oidcprovider.ErrUnknownHandle),
		},
		{
			name: "another user's denial is refused too",
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				other := testSignIn(f, "u-2")
				in.SignIn = &other
				in.Answer = &oidcprovider.ConsentAnswer{Deny: true}
			},
			assert: refused(oidcprovider.ErrUnknownHandle),
		},
		{
			name: "another browser's answer is an unknown handle",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.FlowSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				answerWith(in, "openid")
			},
			assert: refused(oidcprovider.ErrUnknownHandle),
		},
		{
			name:   "a scope never requested is malformed",
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in, "openid", "admin") },
			assert: malformed,
		},
		{
			name:   "a scope the client may ask for but this request did not is malformed",
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in, "openid", "email") },
			assert: malformed,
		},
		{
			name:   "dropping openid when it was requested is malformed",
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in, "profile") },
			assert: malformed,
		},
		{
			name:   "a grant of nothing is malformed",
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in) },
			assert: malformed,
		},
		{
			name:   "a grant of nothing is malformed for a request without openid too",
			params: set("scope", "profile api.read"),
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in) },
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrConsentMalformed)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))
				assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"))
			},
		},
		{
			name:   "a request without openid may be granted without it",
			params: set("scope", "profile api.read"),
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in, "api.read") },
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.Equal(t, []string{"api.read"}, recordOf(t, f, code(t, res, err)).Scopes)
			},
		},
		{
			name:   "a grant is remembered once given, and offline access is not implied",
			params: threeScopes,
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in, "openid", "email") },
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.False(t, recordOf(t, f, code(t, res, err)).Offline)

				remembered, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.NoError(t, loadErr)
				assert.ElementsMatch(t, []string{"openid", "email"}, remembered.Scopes)
				assert.False(t, remembered.Offline)
				assert.Equal(t, f.clk.Now(), remembered.LastGivenAt)
			},
		},
		{
			name:   "offline access is recorded when it is explicitly given",
			params: set("scope", "openid offline_access"),
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				answerWith(in, "openid", "offline_access")
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.True(t, recordOf(t, f, code(t, res, err)).Offline)

				remembered, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.NoError(t, loadErr)
				assert.True(t, remembered.Offline)
			},
		},
		{
			name:   "offline access refused at consent is neither remembered nor held",
			params: set("scope", "openid offline_access"),
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in, "openid") },
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				record := recordOf(t, f, code(t, res, err))
				assert.False(t, record.Offline)
				assert.Equal(t, []string{"openid"}, record.Scopes)

				remembered, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.NoError(t, loadErr)
				assert.False(t, remembered.Offline)
			},
		},
		{
			name: "a second answer on a spent stage is an unknown handle, and no second code exists",
			in:   func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { answerWith(in, "openid") },
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				code(t, res, err)
				require.Equal(t, 1, codesHeld(t, f, "u-1", "billing-web"))

				signIn := testSignIn(f, "u-1")
				in := r.input(&signIn)
				answerWith(&in, "openid", "profile")
				again, err := f.p.Resume(t.Context(), in)
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Equal(t, oidcprovider.ResumeResult{}, again)
				assert.Equal(t, 1, codesHeld(t, f, "u-1", "billing-web"))

				remembered, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.NoError(t, loadErr)
				assert.Equal(t, []string{"openid"}, remembered.Scopes, "the refused answer records nothing")
			},
		},
		{
			name:   "no answer at the consent stage is an unknown handle, and spends nothing",
			in:     func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) { in.Answer = nil },
			assert: refused(oidcprovider.ErrUnknownHandle),
		},
		{
			name: "a sign-in naming no user fails matching token.ErrNoSubject",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.SignIn.User = ""
				answerWith(in, "openid")
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, token.ErrNoSubject)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
				unspent(t, f, r)
			},
		},
		{
			name: "a sign-in at its deadline must authenticate again",
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				in.SignIn.AbsoluteExpiresAt = f.clk.Now()
				answerWith(in, "openid")
			},
			assert: refused(oidcprovider.ErrReauthenticate),
		},
		{
			name:   "max_age is judged again at this stage, against the sign-in presented",
			params: set("max_age", "60"),
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				f.clk.Advance(61 * time.Second)
				in.SignIn.AuthenticatedAt = f.clk.Now().Add(-61 * time.Second)
				answerWith(in, "openid")
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))
				assert.Zero(t, codesHeld(t, f, "u-1", "billing-web"))
			},
		},
		{
			name: "a different sign-in of the same user is bound, with its own facts",
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				f.clk.Advance(time.Minute)
				newer := testSignIn(f, "u-1")
				newer.ACR = "urn:example:other"
				in.SignIn = &newer
				answerWith(in, "openid")
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				record := recordOf(t, f, code(t, res, err))
				assert.Equal(t, "urn:example:other", record.SignIn.ACR)
				assert.Equal(t, f.clk.Now(), record.SignIn.AuthenticatedAt)

				stored, loadErr := f.store.Load(t.Context(), handleDigestOf(t, r.handle))
				require.NoError(t, loadErr)
				assert.NotEqual(t, stored.SignIn.Family, record.SignIn.Family, "the login stage's sign-in is not the one bound")
			},
		},
		{
			name:   "a different sign-in of the same user must itself meet prompt=login",
			params: set("prompt", "login"),
			in: func(_ *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				older := testSignIn(f, "u-1")
				older.AuthenticatedAt = f.clk.Now().Add(-time.Hour)
				in.SignIn = &older
				answerWith(in, "openid")
			},
			assert: func(t *testing.T, f *parkFixture, r parked, _ oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))
			},
		},
		{
			name: "the browser session stands in for its user, and carries its own facts",
			in: func(t *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				t.Helper()
				in.SignIn = nil
				in.BrowserSessionSecret = heldBrowserSession(t, f, consentSessionSignIn(f, "u-1"))
				answerWith(in, "openid")
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				record := recordOf(t, f, code(t, res, err))
				assert.Equal(t, identity.UserID("u-1"), record.SignIn.User)
				assert.Equal(t, "urn:example:session", record.SignIn.ACR)
				assert.Empty(t, res.BrowserSessionSecret, "a consent answer mints no session")
			},
		},
		{
			name: "answering through the browser session counts as using it",
			in: func(t *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				t.Helper()
				in.SignIn = nil
				in.BrowserSessionSecret = heldBrowserSession(t, f, consentSessionSignIn(f, "u-1"))
				f.clk.Advance(5 * time.Minute)
				answerWith(in, "openid")
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				f.clk.Advance(14 * time.Minute)
				sessions := f.p.BrowserSessionStoreForTest()
				remaining, deleteErr := sessions.DeleteExpired(t.Context(), f.clk.Now())
				require.NoError(t, deleteErr)
				assert.Equal(t, 1, remaining, "only the login stage's own, unused session has run out")
				assert.NotEmpty(t, res.RedirectTo)
			},
		},
		{
			name: "another user's browser session is an unknown handle",
			in: func(t *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				t.Helper()
				in.SignIn = nil
				in.BrowserSessionSecret = heldBrowserSession(t, f, consentSessionSignIn(f, "u-2"))
				answerWith(in, "openid")
			},
			assert: refused(oidcprovider.ErrUnknownHandle),
		},
		{
			name: "a sign-in, when given, is used in place of the browser session",
			in: func(t *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				t.Helper()
				in.BrowserSessionSecret = heldBrowserSession(t, f, consentSessionSignIn(f, "u-2"))
				answerWith(in, "openid")
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				assert.Equal(t, identity.UserID("u-1"), recordOf(t, f, code(t, res, err)).SignIn.User)
			},
		},
		{
			name: "no sign-in and no browser session must authenticate",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.SignIn = nil
				answerWith(in, "openid")
			},
			assert: refused(oidcprovider.ErrReauthenticate),
		},
		{
			name: "a browser-session secret of no valid shape must authenticate",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.SignIn = nil
				in.BrowserSessionSecret = "not a secret"
				answerWith(in, "openid")
			},
			assert: refused(oidcprovider.ErrReauthenticate),
		},
		{
			name: "a browser session no longer held must authenticate",
			in: func(_ *testing.T, _ *parkFixture, in *oidcprovider.ResumeInput) {
				in.SignIn = nil
				in.BrowserSessionSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				answerWith(in, "openid")
			},
			assert: refused(oidcprovider.ErrReauthenticate),
		},
		{
			name: "under WithoutBrowserSessions, nothing stands in",
			opts: []oidcprovider.Option{oidcprovider.WithoutBrowserSessions()},
			in: func(t *testing.T, f *parkFixture, in *oidcprovider.ResumeInput) {
				t.Helper()
				const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				require.NoError(t, f.p.BrowserSessionStoreForTest().Put(t.Context(), &oidcprovider.BrowserSession{
					Digest: digestOf(t, secret), SignIn: testSignIn(f, "u-1"),
					IdleExpiresAt: f.clk.Now().Add(time.Hour), AbsoluteExpiresAt: f.clk.Now().Add(time.Hour),
				}))
				in.SignIn = nil
				in.BrowserSessionSecret = secret
				answerWith(in, "openid")
			},
			assert: refused(oidcprovider.ErrReauthenticate),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newParkFixture(t, issuer+"/login", tc.opts...)
			signIn := testSignIn(f, "u-1")
			if promptsLogin(tc.params) {
				f.clk.Advance(time.Millisecond)
				signIn = testSignIn(f, "u-1")
				r := park(t, f, tc.params)
				f.clk.Advance(time.Millisecond)
				signIn.AuthenticatedAt = f.clk.Now()
				res, err := f.p.Resume(t.Context(), r.input(&signIn))
				require.NoError(t, err)
				require.NotEmpty(t, res.RedirectTo)
				in := r.input(&signIn)
				tc.in(t, f, &in)
				got, err := f.p.Resume(t.Context(), in)
				tc.assert(t, f, r, got, err)

				return
			}

			r, _ := atConsent(t, f, tc.params, signIn)
			next := testSignIn(f, "u-1")
			next.AuthenticatedAt = signIn.AuthenticatedAt
			in := r.input(&next)
			tc.in(t, f, &in)

			res, err := f.p.Resume(t.Context(), in)
			tc.assert(t, f, r, res, err)
		})
	}
}

// promptsLogin reports a row whose request carries prompt=login, so its login stage
// needs a sign-in from after parking.
func promptsLogin(change func(url.Values)) bool {
	if change == nil {
		return false
	}
	params := url.Values{}
	change(params)

	return params.Get("prompt") == "login"
}

// consentSessionSignIn is the sign-in behind a browser session a consent row presents.
func consentSessionSignIn(f *parkFixture, user identity.UserID) oidcprovider.SignIn {
	signIn := testSignIn(f, user)
	signIn.ACR = "urn:example:session"

	return signIn
}

// TestProvider_ResumeConsent_WriteOrder fails the writes a grant makes, in order.
func TestProvider_ResumeConsent_WriteOrder(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		wire   func(t *testing.T, f *parkFixture) oidcprovider.Option
		assert func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error)
	}{
		{
			name: "the code's record cannot be written: the stage is unspent, and nothing is remembered",
			wire: func(t *testing.T, _ *parkFixture) oidcprovider.Option {
				t.Helper()
				store := NewMockCodeStore(gomock.NewController(t))
				store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errOutage)

				return oidcprovider.WithCodeStore(store)
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))

				_, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.ErrorIs(t, loadErr, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "the stage cannot be spent: nothing leaves, and nothing is remembered",
			wire: func(t *testing.T, f *parkFixture) oidcprovider.Option {
				t.Helper()
				store := passThroughPending(t, f.store)
				store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(f.store.Load).AnyTimes()
				store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errOutage)

				return oidcprovider.WithPendingRequestStore(store)
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.NotContains(t, err.Error(), errOutage.Error())
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))

				_, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.ErrorIs(t, loadErr, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "the race is lost: an unknown handle, and the answer that lost is not remembered",
			wire: func(t *testing.T, f *parkFixture) oidcprovider.Option {
				t.Helper()
				store := passThroughPending(t, f.store)
				store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(f.store.Load).AnyTimes()
				store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidcprovider.ErrNotFound)

				return oidcprovider.WithPendingRequestStore(store)
			},
			assert: func(t *testing.T, f *parkFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)

				_, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.ErrorIs(t, loadErr, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "the consent cannot be remembered: the user still gets the code, and the failure is logged",
			wire: func(t *testing.T, _ *parkFixture) oidcprovider.Option {
				t.Helper()
				store := NewMockConsentStore(gomock.NewController(t))
				store.EXPECT().Give(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errOutage)

				return oidcprovider.WithConsentStore(store)
			},
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, queryOf(t, res.RedirectTo).Get("code"))
				assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))
				assert.Contains(t, f.logs.String(), "consent")
				assert.NotContains(t, f.logs.String(), errOutage.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newParkFixture(t, issuer+"/login")
			f.p = rebuilt(t, f)
			signIn := testSignIn(f, "u-1")
			r, _ := atConsent(t, f, nil, signIn)

			in := r.input(&signIn)
			answerWith(&in, "openid")
			f.p = rebuilt(t, f, tc.wire(t, f))
			res, err := f.p.Resume(t.Context(), in)
			tc.assert(t, f, r, res, err)

			for _, secret := range []string{r.handle, r.flow} {
				assert.NotContains(t, f.logs.String(), secret)
				if err != nil {
					assert.NotContains(t, err.Error(), secret)
				}
			}
		})
	}
}

// TestProvider_ResumeConsent_Race races different answers to one consent stage: one wins,
// and what is remembered is what won.
func TestProvider_ResumeConsent_Race(t *testing.T) {
	t.Parallel()

	answers := [][]string{{"openid"}, {"openid", "profile"}, nil}
	f := newParkFixture(t, issuer+"/login")
	signIn := testSignIn(f, "u-1")
	r, _ := atConsent(t, f, nil, signIn)

	winners := raceResumes(t, 32, func(i int) oidcprovider.ResumeInput {
		in := r.input(&signIn)
		if scopes := answers[i%len(answers)]; scopes == nil {
			in.Answer = &oidcprovider.ConsentAnswer{Deny: true}
		} else {
			answerWith(&in, scopes...)
		}

		return in
	}, f.p)
	require.Len(t, winners, 1)
	assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))

	answer := queryOf(t, winners[0].RedirectTo)
	remembered, err := f.consents.Load(t.Context(), "u-1", "billing-web")
	if answer.Get("error") == oidcprovider.CodeAccessDenied {
		require.ErrorIs(t, err, oidcprovider.ErrNotFound, "a denial that won leaves nothing remembered")

		return
	}
	require.NoError(t, err)
	assert.Equal(t, recordOf(t, f, answer.Get("code")).Scopes, remembered.Scopes, "only the winner is remembered")
}
