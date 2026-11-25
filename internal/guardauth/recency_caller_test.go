package guardauth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/guardauth"
	"github.com/kartaladev/scrty/session"
)

// errSessionStale and errTokenStale stand for an adapter's two recency refusals: the session
// caller's (403) and the access-token caller's (401 with max_age).
var (
	errSessionStale = errors.New("session stale")
	errTokenStale   = errors.New("token stale")
)

// windowed is a refusal carrying the window it was built for.
type windowed struct {
	kind   error
	window time.Duration
}

func (w *windowed) Error() string        { return fmt.Sprintf("%v within %s", w.kind, w.window) }
func (w *windowed) Is(target error) bool { return target == w.kind }

// noAccessToken is a caller lookup for a request no resource server authenticated.
func noAccessToken(context.Context) (time.Time, bool) { return time.Time{}, false }

// accessTokenAt is a caller lookup for an access-token caller whose token carries at.
func accessTokenAt(at time.Time) guardauth.AccessTokenCaller {
	return func(context.Context) (time.Time, bool) { return at, true }
}

// testRefusals are an adapter's refusals, with caller telling an access-token caller apart.
func testRefusals(caller guardauth.AccessTokenCaller) guardauth.Refusals {
	return guardauth.Refusals{
		AccessTokenCaller: caller,
		Session:           func(w time.Duration) error { return &windowed{kind: errSessionStale, window: w} },
		AccessToken:       func(w time.Duration) error { return &windowed{kind: errTokenStale, window: w} },
	}
}

// TestRecency_Refuse pins the error choice every adapter takes from the judge (design 16): no
// refusal for a recent caller; for a stale one, the access-token refusal when a resource server
// authenticated the caller and the session refusal otherwise, each carrying the window judged.
// The default time source reads an access-token caller's token, never a session, and a token
// without an authentication time is stale. A consumer's time source still decides the time, and
// the caller still decides the refusal.
func TestRecency_Refuse(t *testing.T) {
	t.Parallel()

	const guardsWindow = 15 * time.Minute

	sessionAt := func(at time.Time) func(context.Context) (*session.Session, bool) {
		return func(context.Context) (*session.Session, bool) { return &session.Session{AuthenticatedAt: at}, true }
	}

	noSession := func(context.Context) (*session.Session, bool) { return nil, false }

	type testCase struct {
		name     string
		caller   guardauth.AccessTokenCaller
		authTime func(ctx context.Context) (time.Time, bool) // nil means the default source
		sessions func(ctx context.Context) (*session.Session, bool)
		window   time.Duration
		assert   func(t *testing.T, err error)
	}

	refusedWith := func(kind error, window time.Duration) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()

			var w *windowed
			require.ErrorAs(t, err, &w)
			assert.ErrorIs(t, err, kind)
			assert.Equal(t, window, w.window)
		}
	}

	passes := func(t *testing.T, err error) { t.Helper(); assert.NoError(t, err) }

	cases := []testCase{
		{
			name:     "a fresh session passes",
			caller:   noAccessToken,
			sessions: sessionAt(now.Add(-5 * time.Minute)),
			assert:   passes,
		},
		{
			name:     "a stale session gets the session refusal",
			caller:   noAccessToken,
			sessions: sessionAt(now.Add(-16 * time.Minute)),
			assert:   refusedWith(errSessionStale, guardsWindow),
		},
		{
			name:     "a caller with neither session nor token gets the session refusal",
			caller:   noAccessToken,
			sessions: noSession,
			assert:   refusedWith(errSessionStale, guardsWindow),
		},
		{
			name:     "a fresh access token passes",
			caller:   accessTokenAt(now.Add(-10 * time.Minute)),
			sessions: noSession,
			assert:   passes,
		},
		{
			name:     "a stale access token gets the access-token refusal",
			caller:   accessTokenAt(now.Add(-20 * time.Minute)),
			sessions: noSession,
			assert:   refusedWith(errTokenStale, guardsWindow),
		},
		{
			name:     "an access token without an authentication time is stale",
			caller:   accessTokenAt(time.Time{}),
			sessions: noSession,
			assert:   refusedWith(errTokenStale, guardsWindow),
		},
		{
			name:     "an access token is judged by its own time, never a session's",
			caller:   accessTokenAt(time.Time{}),
			sessions: sessionAt(now),
			assert:   refusedWith(errTokenStale, guardsWindow),
		},
		{
			name:     "a route's window is the one the access-token refusal carries",
			caller:   accessTokenAt(now.Add(-6 * time.Minute)),
			sessions: noSession,
			window:   5 * time.Minute,
			assert:   refusedWith(errTokenStale, 5*time.Minute),
		},
		{
			name:     "a consumer source reporting a fresh time lets an access-token caller pass",
			caller:   accessTokenAt(time.Time{}),
			authTime: authenticatedAt(now.Add(-time.Minute)),
			sessions: noSession,
			assert:   passes,
		},
		{
			name:     "a consumer source reporting none refuses an access-token caller with its refusal",
			caller:   accessTokenAt(now),
			authTime: func(context.Context) (time.Time, bool) { return time.Time{}, false },
			sessions: noSession,
			assert:   refusedWith(errTokenStale, guardsWindow),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			authTime := tc.authTime
			if authTime == nil {
				authTime = guardauth.CallerAuthenticationTime(tc.sessions, tc.caller)
			}

			r, reason := guardauth.NewRecency(guardsWindow, clockwork.NewFakeClockAt(now), authTime,
				testRefusals(tc.caller))
			require.Empty(t, reason)
			require.NotNil(t, r)

			tc.assert(t, r.Refuse(t.Context(), tc.window))
		})
	}
}

// TestNewRecency_Refusals pins that an adapter that wires its refusals incompletely is refused at
// construction, after the consumer's own settings, so no guard can answer a stale caller with
// nothing.
func TestNewRecency_Refusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		refusals func(r guardauth.Refusals) guardauth.Refusals
		assert   func(t *testing.T, r *guardauth.Recency, reason string)
	}

	refused := func(t *testing.T, r *guardauth.Recency, reason string) {
		t.Helper()
		assert.Nil(t, r)
		assert.Contains(t, reason, "recency refusals")
	}

	cases := []testCase{
		{
			name:     "no caller lookup",
			refusals: func(r guardauth.Refusals) guardauth.Refusals { r.AccessTokenCaller = nil; return r },
			assert:   refused,
		},
		{
			name:     "no session refusal",
			refusals: func(r guardauth.Refusals) guardauth.Refusals { r.Session = nil; return r },
			assert:   refused,
		},
		{
			name:     "no access-token refusal",
			refusals: func(r guardauth.Refusals) guardauth.Refusals { r.AccessToken = nil; return r },
			assert:   refused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, reason := guardauth.NewRecency(time.Minute, clockwork.NewFakeClockAt(now), authenticatedAt(now),
				tc.refusals(testRefusals(noAccessToken)))
			tc.assert(t, r, reason)
		})
	}
}

// TestCallerAuthenticationTime pins the default time source: an access-token caller's token's
// authentication time, none for a token without one, and the session's for any other caller.
func TestCallerAuthenticationTime(t *testing.T) {
	t.Parallel()

	at := now.Add(-time.Minute)

	type testCase struct {
		name     string
		caller   guardauth.AccessTokenCaller
		sessions func(ctx context.Context) (*session.Session, bool)
		assert   func(t *testing.T, got time.Time, ok bool)
	}

	cases := []testCase{
		{
			name:     "an access-token caller reports its token's time",
			caller:   accessTokenAt(at),
			sessions: func(context.Context) (*session.Session, bool) { return nil, false },
			assert: func(t *testing.T, got time.Time, ok bool) {
				assert.True(t, ok)
				assert.Equal(t, at, got)
			},
		},
		{
			name:     "an access token without a time reports none",
			caller:   accessTokenAt(time.Time{}),
			sessions: func(context.Context) (*session.Session, bool) { return &session.Session{AuthenticatedAt: at}, true },
			assert: func(t *testing.T, _ time.Time, ok bool) {
				assert.False(t, ok)
			},
		},
		{
			name:     "any other caller reports its session's time",
			caller:   noAccessToken,
			sessions: func(context.Context) (*session.Session, bool) { return &session.Session{AuthenticatedAt: at}, true },
			assert: func(t *testing.T, got time.Time, ok bool) {
				assert.True(t, ok)
				assert.Equal(t, at, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := guardauth.CallerAuthenticationTime(tc.sessions, tc.caller)(t.Context())
			tc.assert(t, got, ok)
		})
	}
}
