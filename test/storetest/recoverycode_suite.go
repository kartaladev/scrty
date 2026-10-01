package storetest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/recovery"
)

// recoveryHashes returns n distinct 32-byte hashes derived from label, so two
// sets built with different labels share none.
func recoveryHashes(label string, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		h := sha256.Sum256(fmt.Appendf(nil, "%s-%d", label, i))
		out[i] = h[:]
	}

	return out
}

// requireRemaining requires user to hold exactly want unspent codes.
func requireRemaining(ctx context.Context, t *testing.T, s recovery.CodeStore, user identity.UserID, want int) {
	t.Helper()

	n, err := s.Remaining(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, want, n, "unspent codes of %q", user)
}

// assertMatches requires each hash to match, or not, as want says.
func assertMatches(
	ctx context.Context, t *testing.T, s recovery.CodeStore, user identity.UserID, want bool, hashes ...[]byte,
) {
	t.Helper()

	for i, h := range hashes {
		matched, err := s.Match(ctx, user, h)
		require.NoError(t, err)
		assert.Equal(t, want, matched, "match of %q's hash %d", user, i)
	}
}

// requireSpend spends hash for user, requiring the outcome want.
func requireSpend(
	ctx context.Context, t *testing.T, s recovery.CodeStore, user identity.UserID, hash []byte, at time.Time, want bool,
) {
	t.Helper()

	ok, err := s.Spend(ctx, user, hash, at)
	require.NoError(t, err)
	require.Equal(t, want, ok, "spend by %q", user)
}

// RunRecoveryCodeStoreSuite checks a recovery.CodeStore against the contract
// the saved-code manager relies on: a set is replaced whole and only for its
// own user, an empty replacement leaves none, and the store keeps its own
// copies of the hashes; a match writes nothing; a code is spent by the write,
// once, of 8 concurrent spends exactly one succeeding; a hash matches only in
// its own user's set; an unknown code and a spent one are refused alike, with
// no error; the unspent count is exact; and deleting a user removes and counts
// every code, spent or not.
//
// newStore is called once per case and must return an empty store. The
// contract takes every time from the caller, so a store may ignore clk.
//
// Whether a refused spend keeps the first spending time is not visible
// through the contract, which exposes no spending time; a durable store's own
// tests check it on the stored row.
func RunRecoveryCodeStoreSuite(t *testing.T, newStore func(t *testing.T, clk clock.Clock) recovery.CodeStore) {
	t.Helper()

	type codeCase = suiteCase[recovery.CodeStore]

	at := suiteStart

	cases := []codeCase{
		{
			name: "concurrent spends: exactly one of 8 succeeds, the rest look like an unknown code",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				hashes := recoveryHashes("race", 10)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, at))

				const callers = 8

				var (
					start = make(chan struct{})
					wg    sync.WaitGroup
					mu    sync.Mutex
					spent int
					errs  []error
				)
				for range callers {
					wg.Go(func() {
						<-start
						ok, err := s.Spend(ctx, "u-1", hashes[0], at)

						mu.Lock()
						defer mu.Unlock()
						if err != nil {
							errs = append(errs, err)
						}
						if ok {
							spent++
						}
					})
				}
				close(start)
				wg.Wait()

				assert.Empty(t, errs, "a refused spend is false with no error")
				assert.Equal(t, 1, spent, "successful spends of one code")
				requireRemaining(ctx, t, s, "u-1", 9)
				assertMatches(ctx, t, s, "u-1", false, hashes[0])
			},
		},
		{
			name: "another user's hash is refused and the owner's code stays unspent",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				hashes := recoveryHashes("owner", 1)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, at))
				require.NoError(t, s.ReplaceSet(ctx, "u-2", recoveryHashes("other", 1), at))

				assertMatches(ctx, t, s, "u-2", false, hashes[0])
				requireSpend(ctx, t, s, "u-2", hashes[0], at, false)

				assertMatches(ctx, t, s, "u-1", true, hashes[0])
				requireRemaining(ctx, t, s, "u-1", 1)
				requireRemaining(ctx, t, s, "u-2", 1)
			},
		},
		{
			name: "replacement is whole: no old code, spent or not, survives",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				old := recoveryHashes("old", 10)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", old, at))
				for _, h := range old[:3] {
					requireSpend(ctx, t, s, "u-1", h, at, true)
				}

				fresh := recoveryHashes("new", 10)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", fresh, at.Add(time.Minute)))

				requireRemaining(ctx, t, s, "u-1", 10)
				assertMatches(ctx, t, s, "u-1", false, old...)
				for _, h := range old {
					requireSpend(ctx, t, s, "u-1", h, at, false)
				}
				assertMatches(ctx, t, s, "u-1", true, fresh...)
			},
		},
		{
			name: "replacement touches no other user's set",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				one := recoveryHashes("one", 3)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", one, at))
				require.NoError(t, s.ReplaceSet(ctx, "u-2", recoveryHashes("two", 5), at))
				require.NoError(t, s.ReplaceSet(ctx, "u-2", recoveryHashes("two-again", 4), at))

				requireRemaining(ctx, t, s, "u-1", 3)
				assertMatches(ctx, t, s, "u-1", true, one...)
				requireRemaining(ctx, t, s, "u-2", 4)
			},
		},
		{
			name: "replacing with an empty set leaves the user none",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				gone := recoveryHashes("gone", 4)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", gone, at))
				require.NoError(t, s.ReplaceSet(ctx, "u-1", nil, at))

				requireRemaining(ctx, t, s, "u-1", 0)
				assertMatches(ctx, t, s, "u-1", false, gone...)
			},
		},
		{
			name: "match writes nothing: three matches, then the code is still spendable",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				hashes := recoveryHashes("match", 3)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, at))

				for range 3 {
					assertMatches(ctx, t, s, "u-1", true, hashes[0])
				}

				requireRemaining(ctx, t, s, "u-1", 3)
				requireSpend(ctx, t, s, "u-1", hashes[0], at, true)
			},
		},
		{
			name: "a spent code neither matches nor spends again",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				hashes := recoveryHashes("spent", 2)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, at))
				requireSpend(ctx, t, s, "u-1", hashes[0], at, true)

				assertMatches(ctx, t, s, "u-1", false, hashes[0])
				requireSpend(ctx, t, s, "u-1", hashes[0], at.Add(time.Minute), false)
				requireRemaining(ctx, t, s, "u-1", 1)
				assertMatches(ctx, t, s, "u-1", true, hashes[1])
			},
		},
		{
			name: "an unknown code and an unknown user are refused without error",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				require.NoError(t, s.ReplaceSet(ctx, "u-1", recoveryHashes("known", 2), at))
				unknown := recoveryHashes("unknown", 1)[0]

				assertMatches(ctx, t, s, "u-1", false, unknown)
				requireSpend(ctx, t, s, "u-1", unknown, at, false)
				requireRemaining(ctx, t, s, "nobody", 0)
				assertMatches(ctx, t, s, "nobody", false, unknown)
				requireSpend(ctx, t, s, "nobody", unknown, at, false)
				requireRemaining(ctx, t, s, "u-1", 2)
			},
		},
		{
			name: "the caller's slices mutated after ReplaceSet leave the stored set unchanged",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				hashes := recoveryHashes("owned", 2)
				original := append([]byte(nil), hashes[0]...)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, at))

				hashes[0][0] ^= 0xFF
				hashes[1] = original // reusing the outer slice must not matter either

				assertMatches(ctx, t, s, "u-1", true, original)
				assertMatches(ctx, t, s, "u-1", false, hashes[0])
				requireRemaining(ctx, t, s, "u-1", 2)
			},
		},
		{
			name: "the presented hash slice mutated after a spend does not unspend the code",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				hashes := recoveryHashes("presented", 1)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, at))

				presented := append([]byte(nil), hashes[0]...)
				requireSpend(ctx, t, s, "u-1", presented, at, true)
				presented[0] ^= 0xFF

				requireSpend(ctx, t, s, "u-1", hashes[0], at, false)
			},
		},
		{
			name: "delete user removes every code, spent or not, and reports how many",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				hashes := recoveryHashes("delete", 4)
				require.NoError(t, s.ReplaceSet(ctx, "u-1", hashes, at))
				require.NoError(t, s.ReplaceSet(ctx, "u-2", recoveryHashes("kept", 2), at))
				requireSpend(ctx, t, s, "u-1", hashes[0], at, true)

				removed, err := s.DeleteUser(ctx, "u-1")
				require.NoError(t, err)
				assert.Equal(t, 4, removed, "codes removed, the spent one included")

				requireRemaining(ctx, t, s, "u-1", 0)
				assertMatches(ctx, t, s, "u-1", false, hashes...)
				requireRemaining(ctx, t, s, "u-2", 2)

				removed, err = s.DeleteUser(ctx, "u-1")
				require.NoError(t, err)
				assert.Zero(t, removed, "a second delete finds nothing")
			},
		},
		{
			name: "a user reference round-trips byte for byte, never folded or trimmed",
			assert: func(t *testing.T, ctx context.Context, s recovery.CodeStore, _ *clockwork.FakeClock) {
				hashes := recoveryHashes("case", 1)
				require.NoError(t, s.ReplaceSet(ctx, "Alice@Example.COM ", hashes, at))

				assertMatches(ctx, t, s, "Alice@Example.COM ", true, hashes[0])
				assertMatches(ctx, t, s, "alice@example.com", false, hashes[0])
				assertMatches(ctx, t, s, "Alice@Example.COM", false, hashes[0])
			},
		},
	}

	runSuite(t, cases, newStore)
}

// RunRecoveryCodeTx holds a durable saved-code store to replacing a set
// inside a transaction its caller owns, reading the result through a second
// store instance on its own connection pool (h.NewReplica), never through the
// transaction:
//   - a replacement inside a transaction attached with h.Begin that is rolled
//     back leaves the previous set whole: its unspent codes still match, its
//     spent code stays spent, and the new codes do not match;
//   - until that transaction commits, a reader outside it sees the previous
//     set and nothing of the new one, and after the commit only the new one;
//   - a store h.BeginResolved configured with a transaction resolver replaces
//     in that transaction, and its rollback leaves the previous set whole.
//
// Each case works on a user of its own, so the cases share one database with
// each other and with the race and ambient suites. It fails at once, naming
// every missing input, when h is missing one.
func RunRecoveryCodeTx[S recovery.CodeStore](t *testing.T, h DurableHarness[S]) {
	t.Helper()

	h.Require(t)

	at := suiteStart

	// seed stores user's previous set outside any transaction, spends its
	// first code, and returns it with the replacement set.
	seed := func(t *testing.T, user identity.UserID) (old, fresh [][]byte) {
		t.Helper()

		old = recoveryHashes(string(user)+"-old", 5)
		fresh = recoveryHashes(string(user)+"-new", 5)
		s := h.New(t)
		require.NoError(t, s.ReplaceSet(t.Context(), user, old, at))
		requireSpend(t.Context(), t, s, user, old[0], at, true)

		return old, fresh
	}
	// assertPrevious requires the previous set, read through a replica, to
	// be whole: its unspent codes match, its spent one does not, and the new
	// set is not there.
	assertPrevious := func(t *testing.T, reader S, user identity.UserID, old, fresh [][]byte) {
		t.Helper()

		ctx := t.Context()
		requireRemaining(ctx, t, reader, user, len(old)-1)
		assertMatches(ctx, t, reader, user, true, old[1:]...)
		assertMatches(ctx, t, reader, user, false, old[0])
		assertMatches(ctx, t, reader, user, false, fresh...)
	}

	runDurableCases(t, []durableCase{
		{
			name: "a replacement rolled back with the caller leaves the previous set whole",
			assert: func(t *testing.T) {
				const user identity.UserID = "recovery-tx-user-1"
				old, fresh := seed(t, user)

				ctx, _, rollback := h.Begin(t)
				t.Cleanup(func() { _ = rollback() })
				require.NoError(t, h.New(t).ReplaceSet(ctx, user, fresh, at.Add(time.Minute)))
				require.NoError(t, rollback())

				assertPrevious(t, h.NewReplica(t), user, old, fresh)
			},
		},
		{
			name: "a reader outside the caller's transaction sees the previous set until it commits",
			assert: func(t *testing.T) {
				const user identity.UserID = "recovery-tx-user-2"
				old, fresh := seed(t, user)
				reader := h.NewReplica(t)

				ctx, commit, rollback := h.Begin(t)
				t.Cleanup(func() { _ = rollback() })
				require.NoError(t, h.New(t).ReplaceSet(ctx, user, fresh, at.Add(time.Minute)))
				assertPrevious(t, reader, user, old, fresh)

				require.NoError(t, commit())
				requireRemaining(t.Context(), t, reader, user, len(fresh))
				assertMatches(t.Context(), t, reader, user, true, fresh...)
				assertMatches(t.Context(), t, reader, user, false, old...)
			},
		},
		{
			name: "a replacement through a configured resolver rolls back with its transaction",
			assert: func(t *testing.T) {
				const user identity.UserID = "recovery-tx-user-3"
				old, fresh := seed(t, user)

				s, ctx, _, rollback := h.BeginResolved(t)
				t.Cleanup(func() { _ = rollback() })
				require.NoError(t, s.ReplaceSet(ctx, user, fresh, at.Add(time.Minute)))
				require.NoError(t, rollback())

				assertPrevious(t, h.NewReplica(t), user, old, fresh)
			},
		},
		{
			name: "overlapping replacements of one user's set leave exactly one set",
			assert: func(t *testing.T) {
				const user identity.UserID = "recovery-tx-user-4"
				_, first := seed(t, user)
				second := recoveryHashes(string(user)+"-second", 5)

				// The first replacement runs in a caller's transaction left
				// open, so the second, on the other replica in a transaction
				// of its own, starts while the first is uncommitted.
				ctx, commit, rollback := h.Begin(t)
				t.Cleanup(func() { _ = rollback() })
				require.NoError(t, h.New(t).ReplaceSet(ctx, user, first, at.Add(time.Minute)))

				done := make(chan error, 1)
				go func() {
					done <- h.NewReplica(t).ReplaceSet(t.Context(), user, second, at.Add(2*time.Minute))
				}()

				// Commit only once the second replacement is waiting on the
				// first; committing earlier would let it run afterwards,
				// serialised by nothing but timing.
				requireReplacementWaiting(t, h.Raw)
				require.NoError(t, commit())
				require.NoError(t, <-done)

				reader := h.NewReplica(t)
				requireRemaining(t.Context(), t, reader, user, len(second))
				assertMatches(t.Context(), t, reader, user, true, second...)
				assertMatches(t.Context(), t, reader, user, false, first...)
			},
		},
	})
}

// requireReplacementWaiting waits, polling raw, until a backend is blocked on
// a lock inside a saved-code replacement: on the replacement's serialising
// lock, or on the rows its delete removes. It fails t after ten seconds.
func requireReplacementWaiting(t *testing.T, raw *sql.DB) {
	t.Helper()

	const blocked = `SELECT EXISTS (
  SELECT 1 FROM pg_stat_activity
  WHERE datname = current_database() AND wait_event_type = 'Lock'
    AND (query LIKE '%pg_advisory_xact_lock%' OR query LIKE 'DELETE FROM %recovery_codes%'))`

	require.Eventually(t, func() bool {
		var waiting bool
		return raw.QueryRowContext(t.Context(), blocked).Scan(&waiting) == nil && waiting
	}, 10*time.Second, 5*time.Millisecond, "the second replacement never waited on the first")
}
