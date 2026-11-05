package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
)

// readsOutOf is a session store whose reads run out: once armed, it answers the
// reads allowed, which are what a bearer needs to admit a request, and every read
// after that fails.
type readsOutOf struct {
	session.Store

	armed   atomic.Bool
	allowed atomic.Int32
	reads   atomic.Int32
}

func (s *readsOutOf) Load(ctx context.Context, id string) (*session.Session, error) {
	if s.armed.Load() && s.reads.Add(1) > s.allowed.Load() {
		return nil, errors.New(endsOutageText)
	}

	return s.Store.Load(ctx, id)
}

// TestOIDCLogout_CompletesWhileSessionReadsFail pins that no logout depends on reading a session
// once its bearer has been admitted: RP-Initiated Logout section 2 says the provider must log out a
// user who said yes, so a session store that can write but not read still ends the sign-in. A manager
// with an end observer refuses a deletion it cannot read for, so a logout written against one would
// fail here.
func TestOIDCLogout_CompletesWhileSessionReadsFail(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// reads is how many session reads the request makes. The chain's logout is behind the
		// bearer, which reads once. End-session is served ahead of it and reads none.
		reads   int32
		prepare func(t *testing.T, f *signInEnds, s *session.Session, browser string) func(...flowChange) flowAnswer
		assert  func(t *testing.T, f *signInEnds, store *readsOutOf, s *session.Session, grant endsGrant, a flowAnswer)
	}

	// ended is what every row asks of a logout, whichever way answered says it is answered.
	ended := func(
		reads int32, answered func(t *testing.T, a flowAnswer),
	) func(*testing.T, *signInEnds, *readsOutOf, *session.Session, endsGrant, flowAnswer) {
		return func(t *testing.T, f *signInEnds, store *readsOutOf, s *session.Session, grant endsGrant, a flowAnswer) {
			t.Helper()

			answered(t, a)
			assert.EqualValues(t, reads, store.reads.Load(), "a logout reads no session past its bearer")

			f.refreshRefused(t, grant)
			f.firstPartyRefused(t, s)
			assert.Equal(t, "login_required", f.silentError(t, grant), "the browser session has gone")
			assert.Len(t, f.events.named(event.SessionLogout), 1)
			assert.Equal(t, []string{s.FamilyID.String()}, sidsOf(f.toldOf(t)), "the client is told once")
		}
	}

	cases := []testCase{{
		name:  "the chain's logout",
		reads: 1,
		prepare: func(t *testing.T, f *signInEnds, _ *session.Session, _ string) func(...flowChange) flowAnswer {
			t.Helper()

			return func(change ...flowChange) flowAnswer {
				r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+httpsec.DefaultLogoutPath, http.NoBody)
				require.NoError(t, err)

				return f.serve(t, r, change)
			}
		},
		assert: ended(1, func(t *testing.T, a flowAnswer) {
			t.Helper()

			require.Equal(t, http.StatusOK, a.status, "%s %v", a.body, a.err)
		}),
	}}
	for _, path := range logoutPaths() {
		cases = append(cases, testCase{
			name: "end-session, " + path.name, prepare: path.prepare, assert: ended(0, path.answered),
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &readsOutOf{Store: must.Must(session.NewMemoryStore())}
			f := newSignInEnds(t, endsSetup{
				sessions: store,
				chain: func(_ *testing.T, f *signInEnds) []httpsec.Option {
					return []httpsec.Option{httpsec.EnableSecurityEvents(f.events.sink)}
				},
			})
			s := f.signIn(t)
			grant := f.grantFrom(t, s, endsOnlineScope)
			send := tc.prepare(t, f, s, grant.browser)

			store.allowed.Store(tc.reads)
			store.armed.Store(true)

			a := send(flowBearer(s.ID))

			store.armed.Store(false)

			tc.assert(t, f, store, s, grant, a)
		})
	}
}
