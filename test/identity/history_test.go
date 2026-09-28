package identitytest_test

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	identitytest "github.com/kartaladev/scrty/test/identity"
)

// TestInMemoryHistoryConformance runs the password-history part of the suite
// against the in-memory history this package ships, one fresh instance per
// case.
func TestInMemoryHistoryConformance(t *testing.T) {
	t.Parallel()

	identitytest.RunPasswordHistory(t, func(t *testing.T) identitytest.HistoryHarness {
		t.Helper()

		return identitytest.NewInMemoryHistory()
	})
}

// TestInMemoryHistoryConformance_SharedInstance runs the whole part over one
// shared history, as a consumer running it against a single database would:
// every case writes to the same records, and stays independent because every
// user reference the suite generates is unique to its case.
func TestInMemoryHistoryConformance_SharedInstance(t *testing.T) {
	t.Parallel()

	shared := identitytest.NewInMemoryHistory()

	identitytest.RunPasswordHistory(t, func(t *testing.T) identitytest.HistoryHarness {
		t.Helper()

		return shared
	})
}

// TestHistory_ReadsInsideATransactionRacingItsCommitFinish checks the lock
// order of the in-memory history, and of the guard's broken history that
// mirrors it: reads made through a transaction's context, on users the
// transaction has not touched yet, race that transaction's commit. Were the
// two to take the transaction's lock and the shared records' lock in opposite
// orders, they would wait on each other for ever.
//
// It runs for a fixed time, not a fixed number of rounds, and fails if the
// rounds do not finish well after that time.
func TestHistory_ReadsInsideATransactionRacingItsCommitFinish(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		newHistory func() identitytest.HistoryHarness
		assert     func(t *testing.T, finished bool)
	}

	finishes := func(t *testing.T, finished bool) {
		assert.True(t, finished,
			"a read inside a transaction and that transaction's commit waited on each other")
	}

	cases := []testCase{
		{
			name:       "the in-memory history",
			newHistory: func() identitytest.HistoryHarness { return identitytest.NewInMemoryHistory() },
			assert:     finishes,
		},
		{
			name:       "the guard's history with no defect",
			newHistory: func() identitytest.HistoryHarness { return newBrokenHistory(historyDefectNone) },
			assert:     finishes,
		},
	}

	const (
		runFor  = 300 * time.Millisecond
		giveUp  = 20 * time.Second
		readers = 64
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			h := tc.newHistory()
			writer := identity.UserID("writer")

			done := make(chan struct{})

			go func() {
				defer close(done)

				for stop := time.Now().Add(runFor); time.Now().Before(stop); {
					txCtx, commit, rollback, err := h.Begin(ctx)
					if !assert.NoError(t, err) {
						return
					}

					// A write gives the commit something to apply.
					assert.NoError(t, h.RetirePassword(txCtx, writer, []byte("h"), 3))

					var wg sync.WaitGroup

					wg.Go(func() {
						for i := range readers {
							_, _ = h.RecentPasswords(txCtx, identity.UserID("reader-"+strconv.Itoa(i)), 1)
						}
					})
					wg.Go(func() { _ = commit() })
					wg.Wait()

					_ = rollback()
				}
			}()

			timer := time.NewTimer(giveUp)
			defer timer.Stop()

			select {
			case <-done:
				tc.assert(t, true)
			case <-timer.C:
				tc.assert(t, false)
			}
		})
	}
}

// TestInMemoryHistory_OverlappingWritersLoseNoEntry pins the in-memory
// model's answer to two transactions that each retire a hash for one user and
// overlap: both commit, and neither's entry is lost. A database may leave one
// entry beyond keep until the user's next retire; the model never keeps more
// than a database would, and never less.
func TestInMemoryHistory_OverlappingWritersLoseNoEntry(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	h := identitytest.NewInMemoryHistory()
	user := identity.UserID("overlapping-writers")

	require.NoError(t, h.RetirePassword(ctx, user, []byte("h0"), 3))

	txA, commitA, rollbackA, err := h.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rollbackA() })

	txB, commitB, rollbackB, err := h.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rollbackB() })

	require.NoError(t, h.RetirePassword(txA, user, []byte("a"), 3))
	require.NoError(t, h.RetirePassword(txB, user, []byte("b"), 3))

	require.NoError(t, commitA())
	require.NoError(t, commitB())

	got, err := h.RecentPasswords(ctx, user, 10)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("b"), []byte("a"), []byte("h0")}, got,
		"the second commit must add its entry to the first's, not replace the user's history")
}
