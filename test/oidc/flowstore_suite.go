package oidctest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/clock"
)

// flowSuiteStart is the store's clock at the start of every case. It is whole
// seconds so a durable store that truncates sub-second precision still
// compares equal.
var flowSuiteStart = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// flowSuiteTTL is how long after flowSuiteStart every suite flow expires.
const flowSuiteTTL = 10 * time.Minute

// flowSuiteRacers is how many concurrent completions of one flow the race row
// starts.
const flowSuiteRacers = 8

// flowSuiteFlow returns a flow for provider and state, expiring flowSuiteTTL
// after flowSuiteStart.
func flowSuiteFlow(provider, state string) oidc.Flow {
	return oidc.Flow{
		Provider:  provider,
		State:     state,
		Nonce:     "nonce-" + state,
		Verifier:  "verifier-" + state,
		Next:      "/next?of=" + state,
		ExpiresAt: flowSuiteStart.Add(flowSuiteTTL),
	}
}

// assertFlowSuiteFlow compares a completed flow with the one begun, reading the expiry
// by instant so a store that returns another location still conforms.
func assertFlowSuiteFlow(t *testing.T, want, got oidc.Flow) {
	t.Helper()

	assert.Equal(t, want.Provider, got.Provider)
	assert.Equal(t, want.State, got.State)
	assert.Equal(t, want.Nonce, got.Nonce)
	assert.Equal(t, want.Verifier, got.Verifier)
	assert.Equal(t, want.Next, got.Next, "next must round-trip unchanged")
	assert.True(t, want.ExpiresAt.Equal(got.ExpiresAt), "expires at %v, want %v", got.ExpiresAt, want.ExpiresAt)
}

// flowSuiteBegin stores f and returns its handle.
func flowSuiteBegin(ctx context.Context, t *testing.T, s oidc.FlowStore, f oidc.Flow) string {
	t.Helper()

	h, err := s.Begin(ctx, f)
	require.NoError(t, err)
	require.NotEmpty(t, h, "a handle must name the flow")

	return h
}

// flowSuiteCompletes requires the flow under h to complete with provider and state,
// and to be the flow begun.
func flowSuiteCompletes(ctx context.Context, t *testing.T, s oidc.FlowStore, h string, want oidc.Flow) {
	t.Helper()

	got, err := s.Complete(ctx, h, want.Provider, want.State)
	require.NoError(t, err, "the flow must still complete with its own provider and state")
	assertFlowSuiteFlow(t, want, got)
}

// flowSuiteRefused requires the call to be refused with ErrInvalidState.
func flowSuiteRefused(ctx context.Context, t *testing.T, s oidc.FlowStore, h, provider, state string) {
	t.Helper()

	_, err := s.Complete(ctx, h, provider, state)
	require.ErrorIs(t, err, oidc.ErrInvalidState)
}

// RunFlowStoreSuite checks a FlowStore against the contract the login
// callback relies on: a begun flow completes once, unchanged, with its own
// provider and state; an unknown handle, a wrong provider, a wrong or empty
// state, an expired flow and a completed flow are all ErrInvalidState, and
// every refusal leaves the flow completable; of eight callers racing to
// complete one flow exactly one succeeds; and DeleteExpired removes only flows
// expired before the cutoff, refusing a zero cutoff with
// ErrRetainSinceRequired and deleting nothing.
//
// newStore is called once per case and must return an empty store whose clock
// is now: Complete judges expiry by it, and the suite advances it to expire
// flows without sleeping. A flow is expired from its ExpiresAt instant on;
// the suite checks one second either side of it. DeleteExpired must judge
// expiry against the cutoff it is given alone.
//
// A consumer implementing FlowStore over their own storage calls this from a
// test in their own module:
//
//	func TestMyFlowStoreConformance(t *testing.T) {
//	    oidctest.RunFlowStoreSuite(t, func(t *testing.T, clk clock.Clock) oidc.FlowStore {
//	        return newMyFlowStore(t, clk)
//	    })
//	}
func RunFlowStoreSuite(t *testing.T, newStore func(t *testing.T, clk clock.Clock) oidc.FlowStore) {
	t.Helper()

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, s oidc.FlowStore, clock *clockwork.FakeClock)
	}

	victim := flowSuiteFlow("a", "state-victim")

	cases := []testCase{
		{
			name: "a begun flow completes unchanged",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				flowSuiteCompletes(ctx, t, s, flowSuiteBegin(ctx, t, s, victim), victim)
			},
		},
		{
			name: "two flows get distinct handles and each completes as its own",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				other := flowSuiteFlow("a", "state-other")
				h1 := flowSuiteBegin(ctx, t, s, victim)
				h2 := flowSuiteBegin(ctx, t, s, other)
				require.NotEqual(t, h1, h2)

				flowSuiteRefused(ctx, t, s, h1, other.Provider, other.State)
				flowSuiteRefused(ctx, t, s, h2, victim.Provider, victim.State)
				flowSuiteCompletes(ctx, t, s, h2, other)
				flowSuiteCompletes(ctx, t, s, h1, victim)
			},
		},
		{
			name: "an unknown handle is refused, and the flow still completes",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				h := flowSuiteBegin(ctx, t, s, victim)
				flowSuiteRefused(ctx, t, s, "unknown-handle", victim.Provider, victim.State)
				flowSuiteCompletes(ctx, t, s, h, victim)
			},
		},
		{
			name: "a wrong provider is refused, and the flow still completes through its own",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				h := flowSuiteBegin(ctx, t, s, victim)
				flowSuiteRefused(ctx, t, s, h, "b", victim.State)
				flowSuiteCompletes(ctx, t, s, h, victim)
			},
		},
		{
			name: "a wrong state is refused, and the flow still completes",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				h := flowSuiteBegin(ctx, t, s, victim)
				flowSuiteRefused(ctx, t, s, h, victim.Provider, "attacker")
				flowSuiteCompletes(ctx, t, s, h, victim)
			},
		},
		{
			name: "an empty state is refused, and the flow still completes",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				h := flowSuiteBegin(ctx, t, s, victim)
				flowSuiteRefused(ctx, t, s, h, victim.Provider, "")
				flowSuiteCompletes(ctx, t, s, h, victim)
			},
		},
		{
			name: "a flow completes one second before its expiry",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, clock *clockwork.FakeClock) {
				h := flowSuiteBegin(ctx, t, s, victim)
				clock.Advance(flowSuiteTTL - time.Second)
				flowSuiteCompletes(ctx, t, s, h, victim)
			},
		},
		{
			name: "a flow is refused one second after its expiry",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, clock *clockwork.FakeClock) {
				h := flowSuiteBegin(ctx, t, s, victim)
				clock.Advance(flowSuiteTTL + time.Second)
				flowSuiteRefused(ctx, t, s, h, victim.Provider, victim.State)
			},
		},
		{
			name: "a completed flow is refused the second time",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				h := flowSuiteBegin(ctx, t, s, victim)
				flowSuiteCompletes(ctx, t, s, h, victim)
				flowSuiteRefused(ctx, t, s, h, victim.Provider, victim.State)
			},
		},
		{
			name: "eight concurrent completions of one flow: exactly one succeeds",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				h := flowSuiteBegin(ctx, t, s, victim)

				var (
					start = make(chan struct{})
					wg    sync.WaitGroup
					errs  = make([]error, flowSuiteRacers)
				)
				for i := range flowSuiteRacers {
					wg.Go(func() {
						<-start
						_, errs[i] = s.Complete(ctx, h, victim.Provider, victim.State)
					})
				}
				close(start)
				wg.Wait()

				won, lost := 0, 0
				for i, err := range errs {
					switch {
					case err == nil:
						won++
					case errors.Is(err, oidc.ErrInvalidState):
						lost++
					default:
						t.Errorf("completion %d failed with %v, not ErrInvalidState", i, err)
					}
				}
				assert.Equal(t, 1, won,
					"exactly one racing completion may succeed: more means completion was decided by a read "+
						"another caller raced")
				assert.Equal(t, flowSuiteRacers-1, lost)
			},
		},
		{
			name: "deleting expired flows removes only those before the cutoff and reports the count",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				early := flowSuiteFlow("a", "state-early")
				early.ExpiresAt = flowSuiteStart.Add(-time.Minute)
				hEarly := flowSuiteBegin(ctx, t, s, early)
				hLate := flowSuiteBegin(ctx, t, s, victim)

				n, err := s.DeleteExpired(ctx, flowSuiteStart)
				require.NoError(t, err)
				assert.Equal(t, 1, n, "the count is of the flows removed")

				flowSuiteRefused(ctx, t, s, hEarly, early.Provider, early.State)
				flowSuiteCompletes(ctx, t, s, hLate, victim)
			},
		},
		{
			name: "a flow whose expiry equals the cutoff is not deleted, and still completes",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				atCutoff := flowSuiteFlow("a", "state-at-cutoff")
				h := flowSuiteBegin(ctx, t, s, atCutoff)

				n, err := s.DeleteExpired(ctx, atCutoff.ExpiresAt)
				require.NoError(t, err)
				assert.Zero(t, n, "a flow expiring exactly at the cutoff is not before it, "+
					"so DeleteExpired must leave it alone")

				flowSuiteCompletes(ctx, t, s, h, atCutoff)
			},
		},
		{
			name: "a zero cutoff is refused and deletes nothing; every flow still completes",
			assert: func(t *testing.T, ctx context.Context, s oidc.FlowStore, _ *clockwork.FakeClock) {
				other := flowSuiteFlow("a", "state-other")
				h1 := flowSuiteBegin(ctx, t, s, victim)
				h2 := flowSuiteBegin(ctx, t, s, other)

				n, err := s.DeleteExpired(ctx, time.Time{})
				require.ErrorIs(t, err, oidc.ErrRetainSinceRequired)
				assert.Zero(t, n)

				flowSuiteCompletes(ctx, t, s, h1, victim)
				flowSuiteCompletes(ctx, t, s, h2, other)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Helper()
			clk := clockwork.NewFakeClockAt(flowSuiteStart)
			tc.assert(t, t.Context(), newStore(t, clk), clk)
		})
	}
}
