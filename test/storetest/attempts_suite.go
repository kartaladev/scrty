package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// recordFailures records a failure for username at each instant.
func recordFailures(ctx context.Context, t *testing.T, s policy.AttemptStore, username string, at ...time.Time) {
	t.Helper()

	for _, when := range at {
		require.NoError(t, s.RecordFailure(ctx, username, when), "record a failure for %q at %v", username, when)
	}
}

// assertFailureCount requires username's failures strictly after since to
// number want.
func assertFailureCount(
	ctx context.Context, t *testing.T, s policy.AttemptStore, username string, since time.Time, want int,
) {
	t.Helper()

	n, err := s.FailureCount(ctx, username, since)
	require.NoError(t, err)
	assert.Equal(t, want, n, "failures of %q after %v", username, since)
}

// RunAttemptStoreSuite checks a policy.AttemptStore against the contract the
// account-lockout policy relies on: a failure count is exact and counts
// strictly after its since, so a failure exactly as old as the window is out
// of it; Reset clears one identifier and is not an error for one with no
// failures; identifiers are matched byte for byte, never folded; and one
// holding a NUL byte, which a PostgreSQL text column cannot hold, is either
// refused, with errors that do not echo it, or counted as given, and never
// altered into another.
//
// When the store also implements policy.AttemptReaper, the suite checks that a
// zero cutoff is refused and deletes nothing, and that a purge removes exactly
// the failures recorded strictly before its cutoff, whoever they belong to.
// For a store without a reaper, those cases log that they did not run and
// pass, since the reaper is optional in the contract; under RequireReaper
// they fail instead.
//
// newStore is called once per case and must return an empty store. The store
// takes every instant from its caller, so it needs no clock.
func RunAttemptStoreSuite(t *testing.T, newStore func(t *testing.T) policy.AttemptStore, opts ...SuiteOption) {
	t.Helper()

	cfg := newSuiteConfig(opts)
	since := suiteStart.Add(time.Hour)

	cases := []suiteCase[policy.AttemptStore]{
		{
			name: "the failure count is exact and excludes a failure recorded at since",
			assert: func(t *testing.T, ctx context.Context, s policy.AttemptStore, _ *clockwork.FakeClock) {
				recordFailures(ctx, t, s, "alice",
					since.Add(-time.Second), since, since.Add(time.Microsecond), since.Add(time.Minute))

				assertFailureCount(ctx, t, s, "alice", since, 2)
				assertFailureCount(ctx, t, s, "alice", suiteStart, 4)
				assertFailureCount(ctx, t, s, "alice", since.Add(time.Minute), 0)
			},
		},
		{
			name: "an identifier with no failures counts zero",
			assert: func(t *testing.T, ctx context.Context, s policy.AttemptStore, _ *clockwork.FakeClock) {
				recordFailures(ctx, t, s, "alice", since.Add(time.Minute))

				assertFailureCount(ctx, t, s, "bob", suiteStart, 0)
			},
		},
		{
			name: "a reset clears that identifier's failures and no other's",
			assert: func(t *testing.T, ctx context.Context, s policy.AttemptStore, _ *clockwork.FakeClock) {
				recordFailures(ctx, t, s, "alice", since.Add(time.Minute), since.Add(2*time.Minute))
				recordFailures(ctx, t, s, "bob", since.Add(time.Minute))

				require.NoError(t, s.Reset(ctx, "alice"))

				assertFailureCount(ctx, t, s, "alice", suiteStart, 0)
				assertFailureCount(ctx, t, s, "bob", suiteStart, 1)
			},
		},
		{
			name: "resetting an identifier with no failures is not an error",
			assert: func(t *testing.T, ctx context.Context, s policy.AttemptStore, _ *clockwork.FakeClock) {
				require.NoError(t, s.Reset(ctx, "nobody"))

				recordFailures(ctx, t, s, "nobody", since.Add(time.Minute))
				assertFailureCount(ctx, t, s, "nobody", suiteStart, 1)
			},
		},
		{
			name: "identifiers differing only in case or spacing are distinct",
			assert: func(t *testing.T, ctx context.Context, s policy.AttemptStore, _ *clockwork.FakeClock) {
				recordFailures(ctx, t, s, "alice", since.Add(time.Minute))
				recordFailures(ctx, t, s, "Alice", since.Add(time.Minute), since.Add(2*time.Minute))
				recordFailures(ctx, t, s, "alice ", since.Add(time.Minute), since.Add(2*time.Minute),
					since.Add(3*time.Minute))

				assertFailureCount(ctx, t, s, "alice", suiteStart, 1)
				assertFailureCount(ctx, t, s, "Alice", suiteStart, 2)
				assertFailureCount(ctx, t, s, "alice ", suiteStart, 3)

				require.NoError(t, s.Reset(ctx, "alice"))
				assertFailureCount(ctx, t, s, "alice", suiteStart, 0)
				assertFailureCount(ctx, t, s, "Alice", suiteStart, 2)
				assertFailureCount(ctx, t, s, "alice ", suiteStart, 3)
			},
		},
		{
			// The identifier is the caller's, matched exactly as given, but a
			// PostgreSQL text column cannot hold a NUL byte. A store may refuse
			// one, with errors that do not echo it, or keep it exactly; it may
			// never alter it into another identifier.
			name: "a username holding a NUL byte is refused or counted as given, never altered",
			assert: func(t *testing.T, ctx context.Context, s policy.AttemptStore, _ *clockwork.FakeClock) {
				const canary = "canary-3b8e"
				username := "alice\x00" + canary

				recordErr := s.RecordFailure(ctx, username, since.Add(time.Minute))
				n, countErr := s.FailureCount(ctx, username, suiteStart)
				if recordErr == nil {
					require.NoError(t, countErr, "a recorded identifier must be countable")
					assert.Equal(t, 1, n, "the recorded failure counts under the identifier given")
				} else {
					assert.NotContains(t, recordErr.Error(), canary, "the refusal must not echo the identifier")
					if countErr != nil {
						assert.NotContains(t, countErr.Error(), canary, "the refusal must not echo the identifier")
					} else {
						assert.Zero(t, n, "a refused failure must not count")
					}
				}

				for _, altered := range []string{"alice", canary, "alice" + canary, "alice " + canary} {
					assertFailureCount(ctx, t, s, altered, suiteStart, 0)
				}
			},
		},
		optionalCase(
			cfg.requireReaper,
			"a purge with a zero cutoff is refused and deletes nothing",
			func(t *testing.T, ctx context.Context, s policy.AttemptStore, reaper policy.AttemptReaper, _ *clockwork.FakeClock) {
				recordFailures(ctx, t, s, "alice", suiteStart, since)

				n, err := reaper.DeleteAttemptsBefore(ctx, time.Time{})
				require.ErrorIs(t, err, policy.ErrRetainSinceRequired)
				assert.Zero(t, n)
				assertFailureCount(ctx, t, s, "alice", suiteStart.Add(-time.Second), 2)
			},
		),
		optionalCase(
			cfg.requireReaper,
			"a purge removes exactly the failures recorded strictly before the cutoff, for every identifier",
			func(t *testing.T, ctx context.Context, s policy.AttemptStore, reaper policy.AttemptReaper, _ *clockwork.FakeClock) {
				recordFailures(ctx, t, s, "alice", since.Add(-time.Second), since, since.Add(time.Second))
				recordFailures(ctx, t, s, "bob", since.Add(-time.Minute))

				n, err := reaper.DeleteAttemptsBefore(ctx, since)
				require.NoError(t, err)
				assert.Equal(t, 2, n, "one failure of each identifier was before the cutoff")

				assertFailureCount(ctx, t, s, "alice", suiteStart, 2)
				assertFailureCount(ctx, t, s, "alice", since.Add(-time.Microsecond), 2)
				assertFailureCount(ctx, t, s, "bob", suiteStart, 0)
			},
		),
	}

	runSuite(t, cases, withoutClock(newStore))
}
