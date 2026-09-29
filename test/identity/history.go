package identitytest

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/pkg/id"
)

// HistoryHarness is what the password-history part of the suite needs: any
// implementation of [password.History], plus a way to begin a transaction the
// caller owns, so the ambient-rollback case can prove a retire that never
// commits leaves nothing behind.
//
// Begin is required, as every hook of [Fixture] is: a harness that cannot
// provide it returns [ErrHookUnsupported], and the run fails before any case.
type HistoryHarness interface {
	password.History

	// Begin starts a transaction owned by the caller, not by the
	// implementation, and returns a context carrying it with the functions
	// that commit and roll it back. The implementation under test must see the
	// transaction through that context. rollback must tolerate being called
	// after commit or a first rollback, the way [AmbientHarness.Begin]'s does:
	// the suite always calls it once a case ends.
	//
	// Some ambient cases call the implementation outside the transaction
	// Begin returned, on the same or another user, while that transaction is
	// still open, to check what the open transaction does and does not make
	// visible; those calls must not wait on it. A harness backed by a pooled
	// connection therefore needs more connections available than the number
	// of cases the suite runs at once, or such a case deadlocks instead of
	// failing on its assertion.
	Begin(ctx context.Context) (txCtx context.Context, commit, rollback func() error, err error)
}

// historyIDs mints the user references the suite hands the implementation
// under test: canonical UUIDv7 strings, so an implementation that parses the
// reference as a UUID (as the default identity store does) accepts every one
// the suite generates. It is package-level and shared across every case,
// which is safe: [id.V7Generator] is built for concurrent use.
var historyIDs = id.NewV7Generator()

// historyUser returns a user reference unique to the calling case: a fresh
// UUIDv7 draws its uniqueness from randomness and a monotonic counter, never
// from the case's name, so two cases can never collide even where
// RunPasswordHistory runs them in parallel over one shared implementation.
func historyUser(t *testing.T) identity.UserID {
	t.Helper()

	raw, err := historyIDs.NewID()
	require.NoError(t, err, "identitytest: could not mint a user reference for the case")

	return identity.UserID(raw.String())
}

// RunPasswordHistory checks any implementation of [password.History] against
// every rule the port names: newest-first order, the n bound, pruning to
// keep, the same-bytes rule, keeping zero, ForgetPasswords, the per-user
// boundary, ownership of the hashes passed in and returned, and the ambient
// transaction: a retire is seen only through the transaction until it
// commits, a commit keeps it, a rollback leaves nothing, and a transaction
// that only reads writes nothing.
//
// These are adapter-only, and not in the suite: a malformed user reference, a
// storage failure, ordering under a consumer's identifier generator, and the
// text of an error. The port promises only an error for a reference the store
// cannot read, so what counts as malformed, how a failure is provoked and how
// identifiers are minted belong to each store, whose own tests cover them.
//
// It is a separate part from [RunConformanceSuite]: password history is not
// an identity port. Running this part needs no [Fixture] hook, and running
// the identity-port suite needs none of HistoryHarness's.
//
// A consumer implementing [password.History] over their own storage calls it
// from their own test:
//
//	func TestMyHistoryConformance(t *testing.T) {
//	    identitytest.RunPasswordHistory(t, func(t *testing.T) identitytest.HistoryHarness {
//	        return newMyHistory(t)
//	    })
//	}
func RunPasswordHistory(t *testing.T, newHarness func(t *testing.T) HistoryHarness) {
	t.Helper()

	requireUsableHistoryHarness(t, newHarness)

	t.Run("Read", func(t *testing.T) { runHistoryReadCases(t, newHarness) })
	t.Run("TwoUsers", func(t *testing.T) { runHistoryTwoUserCases(t, newHarness) })
	t.Run("Ambient", func(t *testing.T) { runHistoryAmbientCases(t, newHarness) })
}

// requireUsableHistoryHarness fails the whole run, before any case, when the
// factory cannot produce a harness, or Begin is missing or returns no
// context, commit or rollback, so the reason is reported once rather than as
// a scatter of case failures.
func requireUsableHistoryHarness(t *testing.T, newHarness func(t *testing.T) HistoryHarness) {
	t.Helper()

	require.NotNil(t, newHarness,
		"the password-history part needs a factory to build the implementation under test")

	h := newHarness(t)
	require.NotNil(t, h, "the factory returned no harness, so no contract can be checked")

	txCtx, commit, rollback, err := h.Begin(t.Context())

	switch {
	case errors.Is(err, ErrHookUnsupported):
		t.Fatalf("identitytest: required hook Begin is missing")
	case err != nil:
		t.Fatalf("identitytest: the preflight could not begin a transaction: %v", err)
	}

	if rollback != nil {
		defer func() { _ = rollback() }()
	}

	require.NotNil(t, txCtx, "identitytest: hook Begin returned no transaction context")
	require.NotNil(t, commit, "identitytest: hook Begin returned no commit function")
	require.NotNil(t, rollback, "identitytest: hook Begin returned no rollback function")
}

// runHistoryReadCases checks the newest-first order, the n bound, pruning to
// keep (including when keep shrinks on a later retire), the same-bytes rule,
// keeping zero, and a user with no entries at all.
func runHistoryReadCases(t *testing.T, newHarness func(t *testing.T) HistoryHarness) {
	t.Helper()

	type testCase struct {
		name    string
		arrange func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID)
		n       int
		assert  func(t *testing.T, got [][]byte, err error)
	}

	h1, h2, h3, h4 := []byte("h1"), []byte("h2"), []byte("h3"), []byte("h4")

	retireFour := func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
		t.Helper()

		for _, hash := range [][]byte{h1, h2, h3, h4} {
			require.NoError(t, h.RetirePassword(ctx, user, hash, 3))
		}
	}

	cases := []testCase{
		{
			name:    "the newest 3 of 4 retired hashes come back newest first",
			arrange: retireFour,
			n:       3,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h4, h3, h2}, got)
			},
		},
		{
			name:    "reading more than the store holds returns the same newest entries",
			arrange: retireFour,
			n:       10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h4, h3, h2}, got,
					"keeping 3 must bound the store to 3 rows, so asking for more returns no more")
			},
		},
		{
			name:    "the n bound limits how many entries come back",
			arrange: retireFour,
			n:       2,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h4, h3}, got)
			},
		},
		{
			name: "retiring the same bytes as the newest entry twice adds nothing",
			arrange: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				require.NoError(t, h.RetirePassword(ctx, user, bytes.Clone(h1), 3))
				require.NoError(t, h.RetirePassword(ctx, user, bytes.Clone(h1), 3))
			},
			n: 10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got,
					"a retry retiring the same hash must not count the password twice")
			},
		},
		{
			name: "the same bytes as an older entry, but not the newest, are retired again",
			arrange: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				for _, hash := range [][]byte{h1, h2, h1} {
					require.NoError(t, h.RetirePassword(ctx, user, bytes.Clone(hash), 3))
				}
			},
			n: 10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1, h2, h1}, got,
					"only the newest entry decides the same-bytes rule: a password used again "+
						"after another one is a new entry")
			},
		},
		{
			name: "the history keeps its own copy of a retired hash",
			arrange: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				buf := bytes.Clone(h1)
				require.NoError(t, h.RetirePassword(ctx, user, buf, 3))
				clear(buf)
			},
			n: 10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got,
					"the caller reusing its buffer after a retire must not rewrite the stored entry")
			},
		},
		{
			name: "a hash read back is the caller's to change",
			arrange: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				require.NoError(t, h.RetirePassword(ctx, user, h1, 3))

				got, err := h.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				require.Len(t, got, 1)
				clear(got[0])
			},
			n: 10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got,
					"writing to a hash a read returned must not rewrite the stored entry")
			},
		},
		{
			name: "keeping zero records nothing and removes every entry",
			arrange: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				require.NoError(t, h.RetirePassword(ctx, user, h1, 3))
				require.NoError(t, h.RetirePassword(ctx, user, h2, 3))
				require.NoError(t, h.RetirePassword(ctx, user, h3, 0))
			},
			n: 10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Empty(t, got, "keep == 0 must leave the user with no entries at all")
			},
		},
		{
			name: "a same-bytes retire that adds nothing still prunes to a smaller keep",
			arrange: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				for _, hash := range [][]byte{[]byte("e1"), []byte("e2"), []byte("e3")} {
					require.NoError(t, h.RetirePassword(ctx, user, hash, 3))
				}

				require.NoError(t, h.RetirePassword(ctx, user, []byte("e3"), 1))
			},
			n: 10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{[]byte("e3")}, got,
					"a retire that matches the newest entry and adds nothing must still prune "+
						"to a keep that has since shrunk")
			},
		},
		{
			name: "a retire with a smaller keep prunes to the new bound",
			arrange: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				for _, hash := range [][]byte{[]byte("e1"), []byte("e2"), []byte("e3"), []byte("e4")} {
					require.NoError(t, h.RetirePassword(ctx, user, hash, 3))
				}

				require.NoError(t, h.RetirePassword(ctx, user, []byte("e5"), 1))
			},
			n: 10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{[]byte("e5")}, got,
					"lowering keep on a later retire must prune to the new bound, never "+
						"restoring what a larger keep had left in place")
			},
		},
		{
			name: "a user with no entries reads an empty slice and no error",
			n:    10,
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Empty(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			h := newHarness(t)
			user := historyUser(t)

			if tc.arrange != nil {
				tc.arrange(t, ctx, h, user)
			}

			got, err := h.RecentPasswords(ctx, user, tc.n)
			tc.assert(t, got, err)
		})
	}
}

// runHistoryTwoUserCases checks the per-user boundary: one user's retire
// never reaches another's history, and forgetting a user removes only that
// user's entries.
func runHistoryTwoUserCases(t *testing.T, newHarness func(t *testing.T) HistoryHarness) {
	t.Helper()

	type testCase struct {
		name    string
		act     func(t *testing.T, ctx context.Context, h HistoryHarness, userA, userB identity.UserID)
		assertA func(t *testing.T, got [][]byte)
		assertB func(t *testing.T, got [][]byte)
	}

	cases := []testCase{
		{
			name: "one user's retire is not visible in another's history",
			act: func(t *testing.T, ctx context.Context, h HistoryHarness, userA, userB identity.UserID) {
				t.Helper()

				require.NoError(t, h.RetirePassword(ctx, userA, []byte("a1"), 3))
				require.NoError(t, h.RetirePassword(ctx, userB, []byte("b1"), 3))
			},
			assertA: func(t *testing.T, got [][]byte) {
				assert.Equal(t, [][]byte{[]byte("a1")}, got)
			},
			assertB: func(t *testing.T, got [][]byte) {
				assert.Equal(t, [][]byte{[]byte("b1")}, got)
			},
		},
		{
			name: "forgetting a user removes only that user's entries",
			act: func(t *testing.T, ctx context.Context, h HistoryHarness, userA, userB identity.UserID) {
				t.Helper()

				require.NoError(t, h.RetirePassword(ctx, userA, []byte("a1"), 3))
				require.NoError(t, h.RetirePassword(ctx, userB, []byte("b1"), 3))
				require.NoError(t, h.ForgetPasswords(ctx, userA))
			},
			assertA: func(t *testing.T, got [][]byte) {
				assert.Empty(t, got, "a forgotten user must hold no entries")
			},
			assertB: func(t *testing.T, got [][]byte) {
				assert.Equal(t, [][]byte{[]byte("b1")}, got,
					"forgetting one user must leave another user's history unchanged")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			h := newHarness(t)
			userA, userB := historyUser(t), historyUser(t)

			tc.act(t, ctx, h, userA, userB)

			gotA, err := h.RecentPasswords(ctx, userA, 10)
			require.NoError(t, err)
			tc.assertA(t, gotA)

			gotB, err := h.RecentPasswords(ctx, userB, 10)
			require.NoError(t, err)
			tc.assertB(t, gotB)
		})
	}
}

// runHistoryAmbientCases checks the ambient transaction: a retire or a forget
// made inside a caller's transaction is seen through its context and nowhere
// else until it commits, a commit keeps it and a rollback leaves nothing
// behind, a transaction that only reads writes nothing when it commits, and a
// forget committed inside a transaction reaches only the user it named.
//
// Each case ends the transaction it began, then reads the user's history
// outside it; assert receives that read.
func runHistoryAmbientCases(t *testing.T, newHarness func(t *testing.T) HistoryHarness) {
	t.Helper()

	type testCase struct {
		name   string
		act    func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID)
		assert func(t *testing.T, got [][]byte, err error)
	}

	h1 := []byte("h1")

	cases := []testCase{
		{
			name: "a retire inside a rolled-back transaction leaves nothing stored",
			act: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				txCtx, _, rollback := beginHistoryTx(ctx, t, h)

				require.NoError(t, h.RetirePassword(txCtx, user, h1, 3))
				assertHistorySeenOnlyInside(ctx, txCtx, t, h, user, h1)
				require.NoError(t, rollback())
			},
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Empty(t, got, "a retire made inside a rolled-back transaction must leave no entry stored")
			},
		},
		{
			name: "a retire inside a committed transaction is stored",
			act: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				txCtx, commit, _ := beginHistoryTx(ctx, t, h)

				require.NoError(t, h.RetirePassword(txCtx, user, h1, 3))
				assertHistorySeenOnlyInside(ctx, txCtx, t, h, user, h1)
				require.NoError(t, commit())
			},
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got,
					"a retire made inside a committed transaction must be stored")
			},
		},
		{
			name: "a hash read inside a transaction is the caller's to change",
			act: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				txCtx, commit, _ := beginHistoryTx(ctx, t, h)

				require.NoError(t, h.RetirePassword(txCtx, user, h1, 3))

				got, err := h.RecentPasswords(txCtx, user, 10)
				require.NoError(t, err)
				require.Len(t, got, 1)
				clear(got[0])

				require.NoError(t, commit())
			},
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got,
					"writing to a hash read inside a transaction must not rewrite the entry it commits")
			},
		},
		{
			name: "a transaction that only reads writes nothing when it commits",
			act: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				txCtx, commit, _ := beginHistoryTx(ctx, t, h)

				got, err := h.RecentPasswords(txCtx, user, 10)
				require.NoError(t, err)
				require.Empty(t, got)

				require.NoError(t, h.RetirePassword(ctx, user, h1, 3),
					"a retire outside the transaction, committed while it is open")
				require.NoError(t, commit())
			},
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got,
					"committing a transaction that only read the user must not undo what "+
						"another writer committed meanwhile")
			},
		},
		{
			name: "a forget inside a committed transaction is seen only there until it commits, and " +
				"never touches another user",
			act: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				other := historyUser(t)
				require.NoError(t, h.RetirePassword(ctx, user, h1, 3))
				require.NoError(t, h.RetirePassword(ctx, other, h1, 3))

				txCtx, commit, _ := beginHistoryTx(ctx, t, h)

				require.NoError(t, h.ForgetPasswords(txCtx, user))

				inside, err := h.RecentPasswords(txCtx, user, 10)
				require.NoError(t, err)
				assert.Empty(t, inside, "a forget made inside a transaction must be seen through its own context")

				outside, err := h.RecentPasswords(ctx, user, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, outside,
					"an uncommitted forget must not be visible outside the caller's transaction")

				require.NoError(t, commit())

				gotOther, err := h.RecentPasswords(ctx, other, 10)
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, gotOther,
					"forgetting one user inside a transaction must not touch another user")
			},
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Empty(t, got, "a forget made inside a committed transaction must remove the user's entries")
			},
		},
		{
			name: "a forget inside a rolled-back transaction leaves the user's entries untouched",
			act: func(t *testing.T, ctx context.Context, h HistoryHarness, user identity.UserID) {
				t.Helper()

				require.NoError(t, h.RetirePassword(ctx, user, h1, 3))

				txCtx, _, rollback := beginHistoryTx(ctx, t, h)

				require.NoError(t, h.ForgetPasswords(txCtx, user))

				inside, err := h.RecentPasswords(txCtx, user, 10)
				require.NoError(t, err)
				assert.Empty(t, inside, "a forget made inside a transaction must be seen through its own context")

				require.NoError(t, rollback())
			},
			assert: func(t *testing.T, got [][]byte, err error) {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{h1}, got,
					"a forget made inside a rolled-back transaction must leave the user's entries untouched")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			h := newHarness(t)
			user := historyUser(t)

			tc.act(t, ctx, h, user)

			got, err := h.RecentPasswords(ctx, user, 10)
			tc.assert(t, got, err)
		})
	}
}

// assertHistorySeenOnlyInside checks, while the transaction txCtx carries is
// still open, that the user's history reads as want through it and as empty
// outside it.
func assertHistorySeenOnlyInside(
	ctx, txCtx context.Context, t *testing.T, h HistoryHarness, user identity.UserID, want ...[]byte,
) {
	t.Helper()

	inside, err := h.RecentPasswords(txCtx, user, 10)
	require.NoError(t, err)
	assert.Equal(t, want, inside, "a transaction must read its own uncommitted retire")

	outside, err := h.RecentPasswords(ctx, user, 10)
	require.NoError(t, err)
	assert.Empty(t, outside, "an uncommitted retire was visible outside the caller's transaction")
}

// beginHistoryTx begins a caller-owned transaction on h and rolls it back
// when the case ends, which the harness tolerates after a commit or a first
// rollback.
func beginHistoryTx(
	ctx context.Context, t *testing.T, h HistoryHarness,
) (txCtx context.Context, commit, rollback func() error) {
	t.Helper()

	txCtx, commit, rollback, err := h.Begin(ctx)
	require.NoError(t, err)
	require.NotNil(t, txCtx)

	t.Cleanup(func() { _ = rollback() })

	return txCtx, commit, rollback
}

// InMemoryHistory implements [password.History] and [HistoryHarness] over
// process memory. It is safe for concurrent use.
//
// A transaction begun with [InMemoryHistory.Begin] reads each user, on first
// touch, from the shared records into a private view, and sees its own writes
// there. Its retires and forgets are also logged, in order, and a commit
// replays that log against the shared records as they stand at commit. So:
//
//   - a rollback, or a transaction never committed, leaves the shared records
//     exactly as they were;
//   - a transaction that only reads writes nothing when it commits;
//   - two transactions that overlap and each retire a hash for one user both
//     keep their entry: the later commit adds its retire after the earlier's
//     and prunes to its own keep. A database may leave one entry beyond keep
//     until that user's next retire, which the default store's contract
//     allows; the model never loses an entry, and never keeps more than keep.
//
// A retired hash is copied in and every hash read is copied out, so a stored
// entry is never written in place and never shared with a caller. A
// transaction's lock is always taken before the shared records' lock, never
// the other way round.
type InMemoryHistory struct {
	mu     sync.Mutex
	byUser map[identity.UserID][][]byte // oldest first
}

// NewInMemoryHistory returns an empty history.
func NewInMemoryHistory() *InMemoryHistory {
	return &InMemoryHistory{byUser: make(map[identity.UserID][][]byte)}
}

// historyTxKey is the context key under which InMemoryHistory.Begin stores
// the transaction its methods read and write through.
type historyTxKey struct{}

// historyWrite is one retire or forget a transaction made, replayed on
// commit.
type historyWrite struct {
	user   identity.UserID
	forget bool
	hash   []byte
	keep   int
}

// historyTx is one transaction: its private view of the users it has touched
// so far, and the writes it will replay on commit.
type historyTx struct {
	base *InMemoryHistory

	mu     sync.Mutex
	view   map[identity.UserID][][]byte // a key is present once the user is touched
	writes []historyWrite
}

// historyTxFrom returns the transaction ctx carries, or nil outside one.
func historyTxFrom(ctx context.Context) *historyTx {
	tx, _ := ctx.Value(historyTxKey{}).(*historyTx)

	return tx
}

// viewLocked returns the transaction's view of user's entries, copying them
// from the shared records on first touch. The caller holds tx.mu, which is
// taken before base.mu.
func (tx *historyTx) viewLocked(user identity.UserID) [][]byte {
	entries, touched := tx.view[user]
	if !touched {
		tx.base.mu.Lock()
		entries = slices.Clone(tx.base.byUser[user])
		tx.base.mu.Unlock()

		tx.view[user] = entries
	}

	return entries
}

// writeLocked applies w to the transaction's view and logs it for commit.
// The caller holds tx.mu.
func (tx *historyTx) writeLocked(w historyWrite) {
	if w.forget {
		tx.view[w.user] = nil
	} else {
		tx.view[w.user] = retireHash(tx.viewLocked(w.user), w.hash, w.keep)
	}

	tx.writes = append(tx.writes, w)
}

// Begin implements HistoryHarness. The returned context carries the
// transaction every later call on h must be made with to see or extend its
// writes; commit replays its writes against the shared records, and rollback
// discards them. Calling either again, in any order, is a no-op: only the
// first call of the two decides the transaction's fate.
func (h *InMemoryHistory) Begin(
	ctx context.Context,
) (txCtx context.Context, commit, rollback func() error, err error) {
	tx := &historyTx{base: h, view: make(map[identity.UserID][][]byte)}
	txCtx = context.WithValue(ctx, historyTxKey{}, tx)

	var once sync.Once

	end := func(commitTx bool) func() error {
		return func() error {
			once.Do(func() {
				if !commitTx {
					return
				}

				tx.mu.Lock()
				defer tx.mu.Unlock()

				h.mu.Lock()
				defer h.mu.Unlock()

				for _, w := range tx.writes {
					h.writeLocked(w)
				}
			})

			return nil
		}
	}

	return txCtx, end(true), end(false), nil
}

// writeLocked applies w to the shared records. The caller holds h.mu.
func (h *InMemoryHistory) writeLocked(w historyWrite) {
	entries := h.byUser[w.user]
	if !w.forget {
		entries = retireHash(entries, w.hash, w.keep)
	}

	if w.forget || len(entries) == 0 {
		delete(h.byUser, w.user)

		return
	}

	h.byUser[w.user] = entries
}

// RecentPasswords implements password.History.
func (h *InMemoryHistory) RecentPasswords(
	ctx context.Context, user identity.UserID, n int,
) ([][]byte, error) {
	var entries [][]byte

	if tx := historyTxFrom(ctx); tx != nil {
		tx.mu.Lock()
		entries = slices.Clone(tx.viewLocked(user))
		tx.mu.Unlock()
	} else {
		h.mu.Lock()
		entries = slices.Clone(h.byUser[user])
		h.mu.Unlock()
	}

	if n <= 0 || len(entries) == 0 {
		return nil, nil
	}

	// Each hash is copied out, so the caller writing to one never reaches a
	// stored entry, committed or staged.
	out := make([][]byte, 0, min(n, len(entries)))
	for i := len(entries) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, bytes.Clone(entries[i]))
	}

	return out, nil
}

// RetirePassword implements password.History.
func (h *InMemoryHistory) RetirePassword(
	ctx context.Context, user identity.UserID, hash []byte, keep int,
) error {
	h.write(ctx, historyWrite{user: user, hash: bytes.Clone(hash), keep: keep})

	return nil
}

// ForgetPasswords implements password.History.
func (h *InMemoryHistory) ForgetPasswords(ctx context.Context, user identity.UserID) error {
	h.write(ctx, historyWrite{user: user, forget: true})

	return nil
}

// write applies w through the transaction ctx carries, or straight to the
// shared records outside one.
func (h *InMemoryHistory) write(ctx context.Context, w historyWrite) {
	if tx := historyTxFrom(ctx); tx != nil {
		tx.mu.Lock()
		defer tx.mu.Unlock()

		tx.writeLocked(w)

		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.writeLocked(w)
}

// retireHash returns entries, oldest first, with hash retired as the newest
// entry unless it holds the same bytes as the newest already, then pruned to
// the newest keep. keep <= 0 leaves none. entries itself is never modified.
func retireHash(entries [][]byte, hash []byte, keep int) [][]byte {
	if keep <= 0 {
		return nil
	}

	out := slices.Clone(entries)
	if len(out) == 0 || !bytes.Equal(out[len(out)-1], hash) {
		out = append(out, hash)
	}

	if len(out) > keep {
		out = out[len(out)-keep:]
	}

	return out
}

var (
	_ password.History = (*InMemoryHistory)(nil)
	_ HistoryHarness   = (*InMemoryHistory)(nil)
)
