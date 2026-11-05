package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// faultySessions is a session store whose delete of a sign-in's family can be made to fail, and
// which, as a store on a network does, gives up on a context that has ended.
type faultySessions struct {
	session.Store

	failing atomic.Bool
}

func (s *faultySessions) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	if s.failing.Load() {
		return 0, errors.New(endsOutageText)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	return s.Store.DeleteFamily(ctx, family)
}

// firstPartyRefused is the check that a sign-in's first-party token no longer works.
func (f *signInEnds) firstPartyRefused(t *testing.T, s *session.Session) {
	t.Helper()

	a := f.consentsGET(t, consentsPath, flowBearer(s.ID))
	assert.Equal(t, http.StatusUnauthorized, a.status, "the first-party token is refused")
}

// logoutPath is one way a browser asks for a logout: what it sends, and how that is answered once
// the logout has finished.
type logoutPath struct {
	name string
	// prepare readies the request from the browser holding browser, ahead of any fault.
	prepare func(t *testing.T, f *signInEnds, s *session.Session, browser string) func(change ...flowChange) flowAnswer
	// answered checks the answer of a logout that finished.
	answered func(t *testing.T, a flowAnswer)
	// spent checks what asking the same way again answers, once it has.
	spent func(t *testing.T, again flowAnswer)
}

func logoutPaths() []logoutPath {
	return []logoutPath{
		{
			name: "a hint naming the browser's sign-in",
			prepare: func(t *testing.T, f *signInEnds, s *session.Session, browser string) func(...flowChange) flowAnswer {
				t.Helper()

				w := &logoutFlow{opFlow: f.opFlow}
				hint := w.logoutHint(t, s.FamilyID, func(i *token.Issue) { i.Audience = []string{endsClient} })

				return func(change ...flowChange) flowAnswer {
					return w.endSessionGET(t, logoutParams("id_token_hint", hint),
						append(change, flowCookieOf(flowSession, browser))...)
				}
			},
			answered: func(t *testing.T, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Equal(t, "/bye", a.location(t).Path)
			},
		},
		{
			name: "a confirmation of the same handle",
			prepare: func(t *testing.T, f *signInEnds, _ *session.Session, browser string) func(...flowChange) flowAnswer {
				t.Helper()

				w := &logoutFlow{opFlow: f.opFlow}
				parked := w.endSessionGET(t, url.Values{}, flowCookieOf(flowSession, browser))
				require.Equal(t, logoutPagePath, parked.location(t).Path)

				handle := parked.location(t).Query().Get(oidcprovider.HandleParam)
				flow := parked.cookie(flowCookie).Value

				return func(change ...flowChange) flowAnswer {
					return w.confirm(t, logoutConfirmed(handle),
						append(change, flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, browser))...)
				}
			},
			answered: func(t *testing.T, a flowAnswer) {
				t.Helper()

				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, "/bye", a.redirectTo(t).Path)
			},
			spent: func(t *testing.T, again flowAnswer) {
				t.Helper()

				require.ErrorIs(t, again.err, httpsec.ErrOIDCUnknownHandle, "the handle goes once all of it has")
			},
		},
	}
}

// newRetryFixture is a sign-in with a real grant, on a chain reporting its events, whose
// first-party store can fail as well as the provider's.
func newRetryFixture(t *testing.T) (*signInEnds, *session.Session, endsGrant, *faultySessions) {
	t.Helper()

	store := &faultySessions{Store: must.Must(session.NewMemoryStore())}
	f := newSignInEnds(t, endsSetup{
		sessions: store,
		chain: func(_ *testing.T, f *signInEnds) []httpsec.Option {
			return []httpsec.Option{httpsec.EnableSecurityEvents(f.events.sink)}
		},
	})
	s := f.signIn(t)

	return f, s, f.grantFrom(t, s, endsOnlineScope), store
}

// TestOIDCLogout_RetryFinishes pins RP-Initiated Logout section 2's MUST under a failure: an answer
// of success from a retry means the End-User is logged out. Whichever store fails, the browser keeps
// what lets it ask again, and asking again ends the grants and the first-party sessions, which real
// tokens being refused shows.
func TestOIDCLogout_RetryFinishes(t *testing.T) {
	t.Parallel()

	faults := []struct {
		name string
		flag func(f *signInEnds, store *faultySessions) *atomic.Bool
	}{
		{"the grant store", func(f *signInEnds, _ *faultySessions) *atomic.Bool { return &f.grants.failing }},
		{"the first-party store", func(_ *signInEnds, store *faultySessions) *atomic.Bool { return &store.failing }},
		{"the browser-session store", func(f *signInEnds, _ *faultySessions) *atomic.Bool { return &f.browsers.failing }},
	}

	for _, path := range logoutPaths() {
		for _, fault := range faults {
			t.Run(path.name+", "+fault.name+" failing", func(t *testing.T) {
				t.Parallel()

				f, s, grant, store := newRetryFixture(t)
				send := path.prepare(t, f, s, grant.browser)

				failing := fault.flag(f, store)
				failing.Store(true)

				first := send()
				require.Equal(t, http.StatusInternalServerError, first.status, first.body)
				assert.Nil(t, first.cookie(flowSession), "a failed logout leaves the browser what it retries with")

				failing.Store(false)
				assert.Empty(t, f.silentError(t, grant), "while it is failing, the browser session stays usable")

				a := send()
				path.answered(t, a)
				assertClearsBrowser(t, a)

				f.refreshRefused(t, grant)
				f.firstPartyRefused(t, s)
				assert.Equal(t, "login_required", f.silentError(t, grant), "the browser session has gone")

				logouts := f.events.named(event.SessionLogout)
				require.Len(t, logouts, 1, "reported once across the failure and the retry")
				assert.Equal(t, s.UserID, logouts[0].User)

				if path.spent != nil {
					path.spent(t, send())
				}
			})
		}
	}
}

// TestOIDCLogout_HangUpEndsAll pins that a client hanging up as a logout runs does not leave the
// sign-in's first-party sessions live: the grants have gone, and nothing may stop short of them.
func TestOIDCLogout_HangUpEndsAll(t *testing.T) {
	t.Parallel()

	for _, path := range logoutPaths() {
		t.Run(path.name, func(t *testing.T) {
			t.Parallel()

			f, s, grant, _ := newRetryFixture(t)
			send := path.prepare(t, f, s, grant.browser)

			ctx, hangUp := context.WithCancel(t.Context())
			defer hangUp()

			during := func() { hangUp() }
			f.grants.during.Store(&during)

			send(func(r *http.Request) { *r = *r.WithContext(ctx) })

			f.grants.during.Store(nil)
			f.refreshRefused(t, grant)
			f.firstPartyRefused(t, s)
		})
	}
}

// TestOIDCLogoutConfirm_RetryWithoutBrowserSessions pins the same for a provider keeping no browser
// sessions, where a valid hint is what names the sign-in, retry or no retry.
func TestOIDCLogoutConfirm_RetryWithoutBrowserSessions(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		flag func(w *logoutFlow, store *faultySessions) *atomic.Bool
	}

	cases := []testCase{
		{"the grant store failing", func(w *logoutFlow, _ *faultySessions) *atomic.Bool { return &w.grantsAt.outage }},
		{"the first-party store failing", func(_ *logoutFlow, store *faultySessions) *atomic.Bool { return &store.failing }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &faultySessions{Store: must.Must(session.NewMemoryStore())}
			w := newLogoutFlow(t, logoutSetup{
				withoutBrowsers: true,
				flowSetup:       flowSetup{sessions: []session.Option{session.WithStore(store)}},
			})
			in := w.signIn(t)
			handle, flow := w.asked(t, logoutParams("id_token_hint", w.logoutHint(t, in.session.FamilyID)), "")

			failing := tc.flag(w, store)
			failing.Store(true)

			first := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow))
			require.Equal(t, http.StatusInternalServerError, first.status)
			failing.Store(false)

			assertLogoutAnswer(t, w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow)), opIssuer+logoutByePath)
			w.assertEnded(t, in)

			logouts := w.events.named(event.SessionLogout)
			require.Len(t, logouts, 1)
			assert.Equal(t, in.session.UserID, logouts[0].User, "the parked sign-in's user is who the end is reported of")

			again := w.confirm(t, logoutConfirmed(handle), flowCookieOf(flowCookie, flow))
			require.ErrorIs(t, again.err, httpsec.ErrOIDCUnknownHandle)
		})
	}
}
