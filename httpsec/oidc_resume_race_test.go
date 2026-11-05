package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// resumeRaceHook runs during, once, on a resume the chain has judged and the provider has yet to
// answer: what a request on another connection does in that moment.
type resumeRaceHook struct {
	during atomic.Pointer[func(*httpsec.Exchange) error]
}

func (h *resumeRaceHook) Intercept(ex *httpsec.Exchange, next httpsec.Next) error {
	if ex.Request.Path() == flowResumePath && ex.Session != nil {
		if during := h.during.Swap(nil); during != nil {
			if err := (*during)(ex); err != nil {
				return err
			}
		}
	}

	return next(ex)
}

func (h *resumeRaceHook) arm(during func(*httpsec.Exchange) error) { h.during.Store(&during) }

func (h *resumeRaceHook) option() httpsec.Option {
	return httpsec.RegisterInterceptor(h, httpsec.OrderOIDCProviderSession-10)
}

// listWatchingStore is a session store whose listing fails on demand, runs after on its way back,
// and counts itself.
type listWatchingStore struct {
	session.Store

	failing atomic.Bool
	after   atomic.Pointer[func()]
	lists   atomic.Int32
}

func (s *listWatchingStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*session.Session, error) {
	s.lists.Add(1)

	if s.failing.Load() {
		return nil, errors.New("the session store is out")
	}

	listed, err := s.Store.ListByUser(ctx, user, now)
	if after := s.after.Swap(nil); after != nil {
		(*after)()
	}

	return listed, err
}

// resumeRace is a sign-in's end or renewal landing beside a resume, on the provider's chain.
type resumeRace struct {
	*signInEnds

	hook  *resumeRaceHook
	store *listWatchingStore
	s     *session.Session
	// held is a grant the sign-in made earlier, which ends only if the sign-in does.
	held endsGrant
	// handle and flow are a request parked for a client the user has consented to.
	handle, flow string
}

func newResumeRace(t *testing.T) *resumeRace {
	t.Helper()

	r := &resumeRace{
		hook:  &resumeRaceHook{},
		store: &listWatchingStore{Store: must.Must(session.NewMemoryStore())},
	}
	r.signInEnds = newSignInEnds(t, endsSetup{
		sessions: r.store,
		chain:    func(*testing.T, *signInEnds) []httpsec.Option { return []httpsec.Option{r.hook.option()} },
	})
	r.s = r.signIn(t)
	r.held = r.grantFrom(t, r.s, endsOnlineScope)
	r.handle, r.flow = r.park(t, endsClient, func(v url.Values) { v.Set("scope", endsOnlineScope) })

	return r
}

func (r *resumeRace) resumeLogin(t *testing.T) flowAnswer {
	t.Helper()

	return r.resume(t, flowLoginBody(r.handle), flowBearer(r.s.ID), flowCookieOf(flowCookie, r.flow))
}

// usable is the check that the sign-in lives on, and that the resume left what it promised.
func (r *resumeRace) usable(t *testing.T, a flowAnswer) {
	t.Helper()

	require.Equal(t, http.StatusOK, a.status, a.body)
	assert.Empty(t, r.silentError(t, endsGrant{browser: a.sessionSecret(t)}), "the browser session answers")

	exchanged := r.atToken(t, exchangeOf(a.redirectTo(t).Query().Get("code")))
	assert.Equal(t, http.StatusOK, exchanged.status, exchanged.body)
	r.refreshWorks(t, r.held)
}

// nothingHandedOut is the check that the answer holds no code and no browser session.
func nothingHandedOut(t *testing.T, a flowAnswer) {
	t.Helper()

	assert.Nil(t, a.cookie(flowSession), "no browser session reaches the browser")
	assert.NotContains(t, a.body, "redirect_to")
	assert.NotContains(t, a.body, "code=")
}

// A resume writes a code and a browser session from a sign-in the chain read earlier, so an end
// landing between that read and those writes would never reach them. Reading the sign-in again once
// they are written closes that: an end before the read is caught by it, and one after finds them.
func TestOIDCResume_SignInEndsOrRenewsMeanwhile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		run  func(t *testing.T, r *resumeRace)
	}

	cases := []testCase{
		{
			name: "an end before the second read: refused, with nothing handed out and the sign-in's grants ended",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				r.hook.arm(func(ex *httpsec.Exchange) error {
					_, err := r.sessions.RevokeFamily(context.WithoutCancel(ex.Context()), ex.Session.FamilyID)

					return err
				})

				a := r.resumeLogin(t)
				require.ErrorIs(t, a.err, httpsec.ErrOIDCReauthenticate)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				nothingHandedOut(t, a)
				r.refreshRefused(t, r.held)
			},
		},
		{
			name: "an end after the second read finds the code and the browser session already written",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				after := func() {
					_, err := r.sessions.RevokeFamily(context.WithoutCancel(t.Context()), r.s.FamilyID)
					assert.NoError(t, err)
				}
				r.store.after.Store(&after)

				a := r.resumeLogin(t)
				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, "login_required", r.silentError(t, endsGrant{browser: a.sessionSecret(t)}),
					"the browser session ended with its sign-in")

				exchanged := r.atToken(t, exchangeOf(a.redirectTo(t).Query().Get("code")))
				assert.Equal(t, http.StatusBadRequest, exchanged.status, "the code ended with its sign-in: %s", exchanged.body)
			},
		},
		{
			name: "a renewal inside its window is no end: the superseded identifier's resume stands",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				r.hook.arm(func(ex *httpsec.Exchange) error {
					_, _, err := r.sessions.RotateWithGrace(ex.Context(), ex.Session, 30*time.Second)

					return err
				})

				r.usable(t, r.resumeLogin(t))
			},
		},
		{
			name: "a window closing before the second read is no reuse: nothing is revoked, and the resume stands",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				var next *session.Session

				r.hook.arm(func(ex *httpsec.Exchange) error {
					var err error
					next, _, err = r.sessions.RotateWithGrace(ex.Context(), ex.Session, 5*time.Second)
					r.clk.Advance(6 * time.Second)

					return err
				})

				r.usable(t, r.resumeLogin(t))
				assert.True(t, r.loads(t, next), "the family was not revoked as reuse")
			},
		},
		{
			name: "a strict rotation is no end, though the old identifier stops answering at once",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				r.hook.arm(func(ex *httpsec.Exchange) error {
					_, err := r.sessions.Rotate(ex.Context(), ex.Session)

					return err
				})

				r.usable(t, r.resumeLogin(t))
			},
		},
		{
			name: "a second read that fails fails closed: nothing is handed out, and the sign-in is not ended",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				r.store.failing.Store(true)

				a := r.resumeLogin(t)
				r.store.failing.Store(false)

				require.Error(t, a.err)
				assert.Equal(t, http.StatusInternalServerError, a.status)
				assert.Empty(t, a.header.Values("WWW-Authenticate"), "an outage is no refusal of the credential")
				nothingHandedOut(t, a)
				assert.True(t, r.loads(t, r.s), "an outage is no verdict on the sign-in")
				r.refreshWorks(t, r.held)
			},
		},
		{
			name: "an end the provider cannot carry out fails too, and hands nothing out",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				r.hook.arm(func(ex *httpsec.Exchange) error {
					_, err := r.sessions.RevokeFamily(context.WithoutCancel(ex.Context()), ex.Session.FamilyID)
					r.browsers.failing.Store(true)

					return err
				})

				a := r.resumeLogin(t)
				r.browsers.failing.Store(false)

				require.Error(t, a.err)
				assert.Equal(t, http.StatusInternalServerError, a.status)
				nothingHandedOut(t, a)
				assert.NotContains(t, a.err.Error(), endsOutageText)
			},
		},
		{
			name: "at the consent stage: a grant from a sign-in ended meanwhile is refused",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				handle, flow := r.park(t, endsClient, func(v url.Values) { v.Set("scope", endsOffline) })
				at := r.resume(t, flowLoginBody(handle), flowBearer(r.s.ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, at.status, at.body)
				require.Empty(t, at.redirectTo(t).Query().Get("code"), "the login stage led to the consent page")

				r.hook.arm(func(ex *httpsec.Exchange) error {
					_, err := r.sessions.RevokeFamily(context.WithoutCancel(ex.Context()), ex.Session.FamilyID)

					return err
				})

				a := r.resume(t, flowGrantBody(handle, strings.Fields(endsOffline)...),
					flowBearer(r.s.ID), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCReauthenticate)
				nothingHandedOut(t, a)
			},
		},
		{
			name: "at the consent stage: a denial grants nothing, and needs no second read",
			run: func(t *testing.T, r *resumeRace) {
				t.Helper()

				handle, flow := r.park(t, endsClient, func(v url.Values) { v.Set("scope", endsOffline) })
				at := r.resume(t, flowLoginBody(handle), flowBearer(r.s.ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, at.status, at.body)

				before := r.store.lists.Load()
				a := r.resume(t, flowDenyBody(handle), flowBearer(r.s.ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, "access_denied", a.redirectTo(t).Query().Get("error"))
				assert.Equal(t, before, r.store.lists.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, newResumeRace(t))
		})
	}
}

// A signed bearer loads its session by the token's jti, which a renewal leaves behind, so what is
// read again is the sign-in rather than the identifier. The fixture differs from the table above, in
// its bearer.
func TestOIDCResume_SignedBearerSignInEndsOrRenewsMeanwhile(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		during func(w *opFlow, ex *httpsec.Exchange) error
		assert func(t *testing.T, w *opFlow, a flowAnswer)
	}

	cases := []testCase{
		{
			name: "an end is refused",
			during: func(w *opFlow, ex *httpsec.Exchange) error {
				_, err := w.sessions.RevokeFamily(context.WithoutCancel(ex.Context()), ex.Session.FamilyID)

				return err
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrOIDCReauthenticate)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				nothingHandedOut(t, a)
			},
		},
		{
			name: "a renewal inside its window stands",
			during: func(w *opFlow, ex *httpsec.Exchange) error {
				_, _, err := w.sessions.RotateWithGrace(ex.Context(), ex.Session, 30*time.Second)

				return err
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.NotNil(t, a.cookie(flowSession))
			},
		},
		{
			name: "a strict rotation stands",
			during: func(w *opFlow, ex *httpsec.Exchange) error {
				_, err := w.sessions.Rotate(ex.Context(), ex.Session)

				return err
			},
			assert: func(t *testing.T, _ *opFlow, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.NotNil(t, a.cookie(flowSession))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hook := &resumeRaceHook{}
			w := newOPFlow(t, flowSetup{
				bearer: func(t *testing.T, w *opFlow) httpsec.Option {
					t.Helper()

					return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: flowGenerator(t, w), Sessions: w.sessions, Users: w.users,
					})
				},
				chain: func(*testing.T, *opFlow) []httpsec.Option { return []httpsec.Option{hook.option()} },
			})

			s := w.session(t)
			tok, err := flowGenerator(t, w).Generate(t.Context(), s.ID, &identity.Principal{ID: s.UserID, Username: string(s.UserID)})
			require.NoError(t, err)

			handle, flow := w.park(t, flowWeb)
			hook.arm(func(ex *httpsec.Exchange) error { return tc.during(w, ex) })

			tc.assert(t, w, w.resume(t, flowLoginBody(handle), flowBearer(tok), flowCookieOf(flowCookie, flow)))
		})
	}
}
