package httpsec_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// countingPolicy counts how often the pre-authentication phase asks it, and
// allows every request.
type countingPolicy struct{ calls atomic.Int64 }

func (*countingPolicy) Name() string { return "test: counting" }

func (*countingPolicy) Phases() []policy.Phase { return []policy.Phase{policy.PreAuthentication} }

func (p *countingPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	p.calls.Add(1)

	return policy.Decision{}
}

// barrierAttempts is an attempt store whose RecordFailure waits until want
// callers are inside it at once, or a short wait passes, so every login that
// can record concurrently does.
type barrierAttempts struct {
	policy.AttemptStore

	arrived chan struct{}
	release chan struct{}
}

func newBarrierAttempts(t *testing.T, want int) *barrierAttempts {
	t.Helper()

	inner, err := lockout.NewMemoryAttemptStore()
	require.NoError(t, err)

	b := &barrierAttempts{AttemptStore: inner, arrived: make(chan struct{}, 64), release: make(chan struct{})}

	go func() {
		for range want {
			select {
			case <-b.arrived:
			case <-time.After(5 * time.Second):
			}
		}
		close(b.release)
	}()

	return b
}

func (b *barrierAttempts) RecordFailure(ctx context.Context, username string, at time.Time) error {
	b.arrived <- struct{}{}

	select {
	case <-b.release:
	case <-time.After(100 * time.Millisecond):
	}

	return b.AttemptStore.RecordFailure(ctx, username, at)
}

// basicGuess presents the user's identifier and a wrong password to Basic.
func (w *eventsWorld) basicGuess(t *testing.T) served {
	t.Helper()

	cred := base64.StdEncoding.EncodeToString([]byte(e2eAddress + ":wrong guess"))

	return w.send(t, http.MethodGet, "/api/orders", "", nil, map[string]string{"Authorization": "Basic " + cred})
}

// lockRun is what a row of TestSecurityEvents_LockReportedOnce produced.
type lockRun struct {
	events []event.Event

	// withSink and withoutSink are how often pre-authentication ran, in a
	// world reporting to a sink and in one that does not, for the same
	// requests.
	withSink, withoutSink int64
}

// TestSecurityEvents_LockReportedOnce pins that a lock is reported where the
// lockout decides it: the failure that reaches the threshold reports
// authn_login_fail_max and authn_login_lock once, from the resolved client
// address and with the first factor, whatever the number of concurrent
// failures that cross it, and a sink does not change which policies run.
func TestSecurityEvents_LockReportedOnce(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T) lockRun
		assert func(t *testing.T, run lockRun)
	}

	// guesses posts n wrong passwords to form login, one after another.
	guesses := func(t *testing.T, w *eventsWorld, n int) {
		t.Helper()

		for range n {
			require.Error(t, w.login(t, "wrong guess").err)
		}
	}

	// lockedOnce asserts the run reported one lock carrying kind.
	lockedOnce := func(kind factor.Kind) func(t *testing.T, run lockRun) {
		return func(t *testing.T, run lockRun) {
			t.Helper()

			for _, name := range []string{event.AuthnLoginFailMax, event.AuthnLoginLock} {
				var got []event.Event
				for _, e := range run.events {
					if e.Name == name {
						got = append(got, e)
					}
				}

				require.Len(t, got, 1, "%s: events %v", name, namesOf(run.events))
				assert.Equal(t, event.OutcomeFailure, got[0].Outcome)
				assert.Equal(t, eventsClient, got[0].ClientIP, "the resolved client address")
				assert.Equal(t, kind, got[0].Factor)
				assert.Empty(t, got[0].User, "a lock names no user")
				assert.False(t, got[0].At.IsZero())
			}
		}
	}

	cases := []testCase{
		{
			name: "a sink does not change how often pre-authentication runs",
			run: func(t *testing.T) lockRun {
				var with, without countingPolicy

				guesses(t, newEventsWorldOf(t, eventsWorldSpec{policies: []policy.Policy{&with}}), 6)
				guesses(t, newEventsWorldOf(t, eventsWorldSpec{policies: []policy.Policy{&without}, noSink: true}), 6)

				return lockRun{withSink: with.calls.Load(), withoutSink: without.calls.Load()}
			},
			assert: func(t *testing.T, run lockRun) {
				assert.Positive(t, run.withoutSink)
				assert.Equal(t, run.withoutSink, run.withSink, "a sink ran pre-authentication again")
			},
		},
		{
			name: "failures below the threshold report only authn_login_fail",
			run: func(t *testing.T) lockRun {
				w := newEventsWorld(t)
				guesses(t, w, 4)

				return lockRun{events: w.rec.all()}
			},
			assert: func(t *testing.T, run lockRun) {
				assert.Equal(t, []string{
					event.AuthnLoginFail, event.AuthnLoginFail, event.AuthnLoginFail, event.AuthnLoginFail,
				}, namesOf(run.events))
			},
		},
		{
			name: "the form-login failure that reaches the threshold reports the lock once",
			run: func(t *testing.T) lockRun {
				w := newEventsWorld(t)
				guesses(t, w, 6)

				return lockRun{events: w.rec.all()}
			},
			assert: lockedOnce(factor.Password),
		},
		{
			name: "the Basic failure that reaches the threshold reports the lock once",
			run: func(t *testing.T) lockRun {
				w := newEventsWorld(t)
				for range 6 {
					require.Error(t, w.basicGuess(t).err)
				}

				return lockRun{events: w.rec.all()}
			},
			assert: lockedOnce(factor.Basic),
		},
		{
			name: "concurrent failures that cross the threshold together report the lock once",
			run: func(t *testing.T) lockRun {
				const concurrent = 4

				store := newBarrierAttempts(t, concurrent)
				for i := range 4 {
					require.NoError(t, store.AttemptStore.RecordFailure(t.Context(), e2eAddress,
						time.Date(2026, 11, 2, 8, 59, 0, 0, time.UTC).Add(time.Duration(i)*time.Second)))
				}

				w := newEventsWorldOf(t, eventsWorldSpec{lockout: []lockout.Option{lockout.WithAttemptStore(store)}})

				var wg sync.WaitGroup
				for range concurrent {
					wg.Go(func() { _ = w.login(t, "wrong guess") })
				}
				wg.Wait()

				return lockRun{events: w.rec.all()}
			},
			assert: lockedOnce(factor.Password),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}

// observerRun is what a row of TestSecurityEvents_Observers produced.
type observerRun struct {
	events []event.Event

	locks  []lockout.Report
	reuses []session.ReuseReport

	// token is the session reference that was reused, if one was.
	token string
}

// TestSecurityEvents_Observers pins that the lockout observer's report and the
// session-reuse observer's report also reach the chain's sink, as
// authn_login_lock and authn_token_reuse, that a configured observer is still
// called beside the sink, and that without a sink the observers alone are.
func TestSecurityEvents_Observers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		noSink bool
		act    func(t *testing.T, w *eventsWorld) string
		assert func(t *testing.T, run observerRun)
	}

	lock := func(t *testing.T, w *eventsWorld) string {
		for range 5 {
			require.Error(t, w.login(t, "wrong guess").err)
		}

		return ""
	}
	reuse := func(t *testing.T, w *eventsWorld) string {
		tok := w.signedIn(t)
		require.NoError(t, w.send(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, tok, nil, nil).err)

		w.clk.Advance(5 * time.Minute)
		require.ErrorIs(t, w.send(t, http.MethodGet, "/api/orders", tok, nil, nil).err, session.ErrReused)

		return tok
	}

	cases := []testCase{
		{
			name: "a lock reports authn_login_lock, and the lockout observer is still told",
			act:  lock,
			assert: func(t *testing.T, run observerRun) {
				var got []event.Event
				for _, e := range run.events {
					if e.Name == event.AuthnLoginLock {
						got = append(got, e)
					}
				}

				require.Len(t, got, 1, "events: %v", namesOf(run.events))
				assert.Equal(t, event.OutcomeFailure, got[0].Outcome)
				assert.Equal(t, eventsClient, got[0].ClientIP)
				assert.Equal(t, factor.Password, got[0].Factor)

				require.Len(t, run.locks, 1)
				assert.Equal(t, lockout.ReportLocked, run.locks[0].Kind)
			},
		},
		{
			name: "a reuse reports authn_token_reuse, and the reuse observer is still called",
			act:  reuse,
			assert: func(t *testing.T, run observerRun) {
				var got []event.Event
				for _, e := range run.events {
					if e.Name == event.AuthnTokenReuse {
						got = append(got, e)
					}
				}

				require.Len(t, got, 1, "events: %v", namesOf(run.events))
				assert.Equal(t, event.OutcomeFailure, got[0].Outcome)
				assert.Equal(t, eventsClient, got[0].ClientIP)
				assert.Equal(t, e2eUser, got[0].User)
				assert.Equal(t, factor.Password, got[0].Factor)
				assert.Equal(t, digestOf(run.token), got[0].Session, "the reused session's digest")

				require.Len(t, run.reuses, 1)
				assert.Equal(t, e2eUser, run.reuses[0].User)
			},
		},
		{
			name:   "without a sink the lockout observer alone is told",
			noSink: true,
			act:    lock,
			assert: func(t *testing.T, run observerRun) {
				assert.Empty(t, run.events)
				assert.Len(t, run.locks, 1)
			},
		},
		{
			name:   "without a sink the reuse observer alone is called",
			noSink: true,
			act:    reuse,
			assert: func(t *testing.T, run observerRun) {
				assert.Empty(t, run.events)
				assert.Len(t, run.reuses, 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				mu  sync.Mutex
				run observerRun
			)

			w := newEventsWorldOf(t, eventsWorldSpec{
				noSink: tc.noSink,
				lockout: []lockout.Option{lockout.WithObserver(func(_ context.Context, r lockout.Report) {
					mu.Lock()
					defer mu.Unlock()

					run.locks = append(run.locks, r)
				})},
				sessions: []session.Option{session.WithReuseObserver(func(_ context.Context, r session.ReuseReport) {
					mu.Lock()
					defer mu.Unlock()

					run.reuses = append(run.reuses, r)
				})},
			})

			run.token = tc.act(t, w)
			run.events = w.rec.all()

			mu.Lock()
			defer mu.Unlock()

			tc.assert(t, run)
		})
	}
}
