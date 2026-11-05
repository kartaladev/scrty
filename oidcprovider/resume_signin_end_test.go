package oidcprovider_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// endingCodes runs before as a code is written.
type endingCodes struct {
	oidcprovider.CodeStore

	before atomic.Pointer[func()]
}

func (c *endingCodes) Create(ctx context.Context, record *oidcprovider.CodeRecord) error {
	if before := c.before.Swap(nil); before != nil {
		(*before)()
	}

	return c.CodeStore.Create(ctx, record)
}

// endingBrowsers runs after once a browser session's use has been recorded.
type endingBrowsers struct {
	oidcprovider.BrowserSessionStore

	after atomic.Pointer[func()]
}

func (b *endingBrowsers) Touch(ctx context.Context, digest []byte, idleExpiresAt time.Time) error {
	err := b.BrowserSessionStore.Touch(ctx, digest, idleExpiresAt)
	if after := b.after.Swap(nil); after != nil {
		(*after)()
	}

	return err
}

// A consent answered from a browser session rests on nothing the chain could read again, so the
// provider holds the line itself: the session is looked at last, once the code is written. An end
// before that look refuses the answer, and an end after it finds the code.
func TestProvider_ResumeConsent_BrowserSessionEndsMeanwhile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		arm    func(codes *endingCodes, browsers *endingBrowsers, end func())
		assert func(*testing.T, *exchangeFixture, parked, oidcprovider.ResumeResult, error)
	}

	cases := []testCase{
		{
			name: "an end before the code is written: the answer is refused, and nothing is handed out",
			arm:  func(codes *endingCodes, _ *endingBrowsers, end func()) { codes.before.Store(&end) },
			assert: func(t *testing.T, x *exchangeFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
				assert.Equal(t, oidcprovider.ResumeResult{}, res)
				assert.Equal(t, oidcprovider.StageConsent, stageOf(t, x.parkFixture, r))
			},
		},
		{
			name: "an end after the last look finds the code, which then makes no grant",
			arm:  func(_ *endingCodes, browsers *endingBrowsers, end func()) { browsers.after.Store(&end) },
			assert: func(t *testing.T, x *exchangeFixture, _ parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()

				require.NoError(t, err)
				code := queryOf(t, res.RedirectTo).Get("code")
				require.NotEmpty(t, code)

				_, exchangeErr := x.p.Token(t.Context(), billingExchange(issuedCode{code: code}, nil))
				assertRefused(t, exchangeErr, oidcprovider.CodeInvalidGrant)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(exchangeFixtureStart)
			codeStore, err := oidcprovider.NewMemoryCodeStore(oidcprovider.WithMemoryStoreClock(clk))
			require.NoError(t, err)
			browserStore, err := oidcprovider.NewMemoryBrowserSessionStore(oidcprovider.WithMemoryStoreClock(clk))
			require.NoError(t, err)

			codes := &endingCodes{CodeStore: codeStore}
			browsers := &endingBrowsers{BrowserSessionStore: browserStore}
			x := newExchangeFixtureOn(t, clk, oidcprovider.WithCodeStore(codes), oidcprovider.WithBrowserSessionStore(browsers))

			signIn := testSignIn(x.parkFixture, "u-1")
			r, _ := atConsent(t, x.parkFixture, nil, signIn)
			held := heldBrowserSession(t, x.parkFixture, signIn)

			tc.arm(codes, browsers, func() {
				_, endErr := x.p.EndSignIn(context.WithoutCancel(t.Context()), oidcprovider.SignInSelector{Family: signIn.Family})
				assert.NoError(t, endErr)
			})

			in := r.input(nil)
			in.BrowserSessionSecret = held
			answerWith(&in, "openid")

			res, err := x.p.Resume(t.Context(), in)
			tc.assert(t, x, r, res, err)
		})
	}
}

// midEndBrowsers lets a request land at a chosen point of an end, on the end's own goroutine, so that
// the interleaving is exact and no timing decides it.
type midEndBrowsers struct {
	oidcprovider.BrowserSessionStore

	beforeDelete atomic.Pointer[func()]
	aroundTouch  atomic.Pointer[func(touch func())]
}

func (b *midEndBrowsers) DeleteBySignIn(ctx context.Context, sel oidcprovider.SignInSelector) (int, error) {
	if before := b.beforeDelete.Swap(nil); before != nil {
		(*before)()
	}

	return b.BrowserSessionStore.DeleteBySignIn(ctx, sel)
}

func (b *midEndBrowsers) Touch(ctx context.Context, digest []byte, idleExpiresAt time.Time) error {
	around := b.aroundTouch.Swap(nil)
	if around == nil {
		return b.BrowserSessionStore.Touch(ctx, digest, idleExpiresAt)
	}

	var err error
	(*around)(func() { err = b.BrowserSessionStore.Touch(ctx, digest, idleExpiresAt) })

	return err
}

// midEndGrants runs beforeEnd as an end comes to sweep the grants and codes.
type midEndGrants struct {
	oidcprovider.GrantStore

	beforeEnd atomic.Pointer[func()]
}

func (g *midEndGrants) EndSignIns(ctx context.Context, sel oidcprovider.SignInSelector, at time.Time) ([]oidcprovider.Grant, error) {
	if before := g.beforeEnd.Swap(nil); before != nil {
		(*before)()
	}

	return g.GrantStore.EndSignIns(ctx, sel, at)
}

// midEndFixture is an exchange fixture with a sign-in, whose end a request can land inside.
type midEndFixture struct {
	*exchangeFixture

	browsers *midEndBrowsers
	grants   *midEndGrants
	signIn   oidcprovider.SignIn
}

func newMidEndFixture(t *testing.T) *midEndFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(exchangeFixtureStart)
	browserStore, err := oidcprovider.NewMemoryBrowserSessionStore(oidcprovider.WithMemoryStoreClock(clk))
	require.NoError(t, err)
	grantStore, err := oidcprovider.NewMemoryGrantStore(oidcprovider.WithMemoryStoreClock(clk))
	require.NoError(t, err)

	f := &midEndFixture{
		browsers: &midEndBrowsers{BrowserSessionStore: browserStore},
		grants:   &midEndGrants{GrantStore: grantStore},
	}
	f.exchangeFixture = newExchangeFixtureOn(t, clk,
		oidcprovider.WithBrowserSessionStore(f.browsers), oidcprovider.WithGrantStore(f.grants))
	f.signIn = testSignIn(f.parkFixture, "u-1")

	return f
}

// midEndRequest prepares a request resting on the browser session, and returns the session's secret
// and the call that asks, which answers where the browser is sent.
type midEndRequest func(*testing.T, *midEndFixture) (string, func() (string, error))

// resumeConsentRequest answers a consent page from the browser session.
func resumeConsentRequest(t *testing.T, f *midEndFixture) (string, func() (string, error)) {
	t.Helper()

	r, _ := atConsent(t, f.parkFixture, nil, f.signIn)
	held := heldBrowserSession(t, f.parkFixture, f.signIn)

	return held, func() (string, error) {
		in := r.input(nil)
		in.BrowserSessionSecret = held
		answerWith(&in, "openid")
		res, err := f.p.Resume(t.Context(), in)

		return res.RedirectTo, err
	}
}

// silentAuthorizeRequest asks with prompt=none, as a stolen cookie may, again and again.
func silentAuthorizeRequest(t *testing.T, f *midEndFixture) (string, func() (string, error)) {
	t.Helper()

	require.NoError(t, f.consents.Give(t.Context(), "u-1", "billing-web", []string{"openid", "profile"}, false, f.clk.Now()))
	held := heldBrowserSession(t, f.parkFixture, f.signIn)

	return held, func() (string, error) {
		params := authzParams()
		params.Set("prompt", "none")
		res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{
			Params: params, BrowserSessionSecret: held, IdleTimeout: sessionIdle,
		})

		return res.Location, err
	}
}

// TestProvider_EndSignIn_ReachesARequestInProgress lands a request at each point of an end. A code is
// written and the session then looked at, and an end deletes the session and then sweeps the codes, so
// whichever way they interleave, either the look refuses or the sweep finds the code.
func TestProvider_EndSignIn_ReachesARequestInProgress(t *testing.T) {
	t.Parallel()

	// justBeforeTheDelete: the look finds the session, so the code leaves, and the sweep must reach it.
	justBeforeTheDelete := func(f *midEndFixture, ask, end func()) {
		f.browsers.beforeDelete.Store(&ask)
		end()
	}
	// afterTheDelete: the request starts with the session gone and the codes not yet swept.
	afterTheDelete := func(f *midEndFixture, ask, end func()) {
		f.grants.beforeEnd.Store(&ask)
		end()
	}
	// lookingBetween: the request found the session and wrote its code, and its look falls between the
	// delete and the sweep.
	lookingBetween := func(f *midEndFixture, ask, end func()) {
		around := func(touch func()) {
			f.grants.beforeEnd.Store(&touch)
			end()
		}
		f.browsers.aroundTouch.Store(&around)
		ask()
	}
	// asIs needs no logout before the end.
	asIs := func(*testing.T, *midEndFixture, string) {}
	// firstPassDone runs a logout the browser asked for up to where its caller finishes it: the grants
	// are swept, and the browser session stands.
	firstPassDone := func(t *testing.T, f *midEndFixture, held string) {
		t.Helper()

		asked, err := f.p.EndSession(t.Context(), oidcprovider.EndSessionInput{BrowserSessionSecret: held})
		require.NoError(t, err)
		confirmed, err := f.p.ConfirmLogout(t.Context(), handleOf(t, asked.Location), asked.FlowSecret, held, true)
		require.NoError(t, err)
		require.Equal(t, &oidcprovider.SignInSelector{Family: f.signIn.Family}, confirmed.Ended)
	}
	// betweenThePasses lands after the first pass has swept, before the finish does anything.
	betweenThePasses := func(_ *midEndFixture, ask, end func()) {
		ask()
		end()
	}

	unexchangeable := func(t *testing.T, f *midEndFixture, location string, err error) {
		t.Helper()

		require.NoError(t, err)
		code := queryOf(t, location).Get("code")
		require.NotEmpty(t, code, location)
		tokens, exchangeErr := f.p.Token(t.Context(), billingExchange(issuedCode{code: code}, nil))
		assert.Nil(t, tokens, "a code overlapping the end makes no tokens")
		assertRefused(t, exchangeErr, oidcprovider.CodeInvalidGrant)
	}
	resumeRefused := func(t *testing.T, _ *midEndFixture, location string, err error) {
		t.Helper()

		require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
		assert.Empty(t, location, "no code is handed out")
	}
	silentRefused := func(t *testing.T, _ *midEndFixture, location string, err error) {
		t.Helper()

		require.NoError(t, err)
		answer := queryOf(t, location)
		assert.Equal(t, oidcprovider.CodeLoginRequired, answer.Get("error"))
		assert.Empty(t, answer.Get("code"), "no code is handed out")
	}

	type testCase struct {
		name    string
		request midEndRequest
		// before is what has happened by the time the end being raced starts.
		before func(*testing.T, *midEndFixture, string)
		land   func(f *midEndFixture, ask, end func())
		assert func(*testing.T, *midEndFixture, string, error)
	}

	cases := []testCase{
		{"consent answered just before the browser session goes: the sweep reaches its code", resumeConsentRequest, asIs, justBeforeTheDelete, unexchangeable},
		{"consent answered once the browser session has gone, before the sweep: refused", resumeConsentRequest, asIs, afterTheDelete, resumeRefused},
		{"consent whose last look falls between the delete and the sweep: the code is withheld", resumeConsentRequest, asIs, lookingBetween, resumeRefused},
		{"silent authorize just before the browser session goes: the sweep reaches its code", silentAuthorizeRequest, asIs, justBeforeTheDelete, unexchangeable},
		{"silent authorize once the browser session has gone, before the sweep: refused", silentAuthorizeRequest, asIs, afterTheDelete, silentRefused},
		{"silent authorize whose last look falls between the delete and the sweep: the code is withheld", silentAuthorizeRequest, asIs, lookingBetween, silentRefused},
		{"a logout's two passes, silent authorize between them: the finish's sweep reaches its code", silentAuthorizeRequest, firstPassDone, betweenThePasses, unexchangeable},
		{"a logout's two passes, silent authorize just before the finish deletes: the sweep reaches its code", silentAuthorizeRequest, firstPassDone, justBeforeTheDelete, unexchangeable},
		{"a logout's two passes, a last look between the finish's delete and sweep: the code is withheld", silentAuthorizeRequest, firstPassDone, lookingBetween, silentRefused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newMidEndFixture(t)
			held, request := tc.request(t, f)
			tc.before(t, f, held)

			var (
				location string
				askErr   error
				asked    bool
				ended    bool
			)
			tc.land(f, func() {
				asked = true
				location, askErr = request()
			}, func() {
				ended = true
				_, endErr := f.p.EndSignIn(t.Context(), oidcprovider.SignInSelector{Family: f.signIn.Family})
				assert.NoError(t, endErr)
			})

			require.True(t, asked, "the request landed")
			require.True(t, ended, "the end ran")
			tc.assert(t, f, location, askErr)
		})
	}
}
