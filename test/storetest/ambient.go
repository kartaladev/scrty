package storetest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// Ambient is what the ambient-transaction suite needs from one store: a
// write, an out-of-band check for it, and a refusal. Every field is required,
// and probes missing one fail the suite at once, naming it.
type Ambient[S any] struct {
	// Write makes the store write record i through ctx, which may carry a
	// caller's transaction. Each case writes records of its own i, so the
	// cases share one database without meeting.
	Write func(ctx context.Context, s S, i int) error

	// Present reports whether record i is committed, read through raw
	// (DurableHarness.Raw) and never through the store.
	Present func(t *testing.T, raw *sql.DB, i int) bool

	// Refuse makes the store refuse an operation through ctx, as a durable
	// store refuses: consuming a token that does not exist, say, or inserting
	// a link that does. It may write what it needs first, through the same
	// ctx, and must return an error matching Refusal.
	Refuse func(ctx context.Context, s S) error

	// Refusal is the sentinel Refuse's error must match through errors.Is,
	// such as onetime.ErrTokenNotFound. It is what tells a refusal apart from
	// a failed statement, which would abort the caller's transaction.
	Refusal error
}

// RunAmbientTx holds a durable store to taking part in a transaction its
// caller owns, checking what it wrote through h.Raw rather than through the
// store:
//   - a write inside a transaction attached with h.Begin is not visible until
//     the transaction ends, is discarded by a rollback and kept by a commit;
//   - a refusal inside the transaction leaves it usable: a write after it
//     succeeds, and a commit keeps the writes on both sides of it;
//   - a store h.BeginResolved configured with a transaction resolver writes
//     in that transaction, though the context carries none;
//   - a transaction h.BeginForeign attaches for another backend is ignored:
//     the store writes through its own handle, and the foreign rollback does
//     not take the write with it.
//
// It fails at once, naming every missing input, when h or a is missing one.
//
// The shared PostgreSQL rate limiter (sqlstore.Limiter and pgx.Limiter) does
// not run this suite: it ignores the caller's transaction by design, so a
// failure recorded in a request that rolls back still counts. Its own test
// pins that opposite guarantee.
func RunAmbientTx[S any](t *testing.T, h DurableHarness[S], a Ambient[S]) {
	t.Helper()

	requireAmbient(t, h, a)

	present := func(t *testing.T, i int) bool {
		t.Helper()
		return a.Present(t, h.Raw, i)
	}
	// begin and beginResolved roll the transaction back at cleanup, so a
	// case that fails part way never leaves it open. After a commit or a
	// rollback that rollback fails, and its error is ignored.
	begin := func(t *testing.T) (context.Context, func() error, func() error) {
		ctx, commit, rollback := h.Begin(t)
		t.Cleanup(func() { _ = rollback() })
		return ctx, commit, rollback
	}
	beginResolved := func(t *testing.T) (S, context.Context, func() error) {
		s, ctx, _, rollback := h.BeginResolved(t)
		t.Cleanup(func() { _ = rollback() })
		return s, ctx, rollback
	}

	runDurableCases(t, []durableCase{
		{
			name: "a write inside a rolled back transaction is discarded",
			assert: func(t *testing.T) {
				ctx, _, rollback := begin(t)
				require.NoError(t, a.Write(ctx, h.New(t), 1))
				assert.False(t, present(t, 1),
					"the write is visible before its transaction ended: the store did not write in it")

				require.NoError(t, rollback())
				assert.False(t, present(t, 1), "the write survived the rollback of its transaction")
			},
		},
		{
			name: "a write inside a committed transaction is kept",
			assert: func(t *testing.T) {
				ctx, commit, _ := begin(t)
				require.NoError(t, a.Write(ctx, h.New(t), 2))
				assert.False(t, present(t, 2),
					"the write is visible before its transaction ended: the store did not write in it")

				require.NoError(t, commit())
				assert.True(t, present(t, 2), "the write is missing after its transaction committed")
			},
		},
		{
			name: "a refusal inside a transaction leaves it usable",
			assert: func(t *testing.T) {
				ctx, commit, _ := begin(t)
				s := h.New(t)
				require.NoError(t, a.Write(ctx, s, 3))

				require.ErrorIs(t, a.Refuse(ctx, s), a.Refusal, "Refuse did not return the refusal")

				require.NoError(t, a.Write(ctx, s, 4), "a write after the refusal failed")
				require.NoError(t, commit(), "the transaction did not commit after the refusal")
				assert.True(t, present(t, 3), "the write before the refusal was not committed")
				assert.True(t, present(t, 4), "the write after the refusal was not committed")
			},
		},
		{
			name: "a configured resolver's transaction is used",
			assert: func(t *testing.T) {
				s, ctx, rollback := beginResolved(t)
				require.NoError(t, a.Write(ctx, s, 5))
				assert.False(t, present(t, 5),
					"the write is visible before the resolver's transaction ended: the store did not write in it")

				require.NoError(t, rollback())
				assert.False(t, present(t, 5), "the write survived the rollback of the resolver's transaction")
			},
		},
		{
			name: "a transaction attached for another backend is ignored",
			assert: func(t *testing.T) {
				ctx, rollback := h.BeginForeign(t)
				t.Cleanup(func() { _ = rollback() })
				require.NoError(t, a.Write(ctx, h.New(t), 6))
				assert.True(t, present(t, 6),
					"the write is not visible: the store wrote in another backend's transaction")

				require.NoError(t, rollback())
				assert.True(t, present(t, 6), "the write was rolled back with another backend's transaction")
			},
		},
	})
}

// requireAmbient fails t at once, naming every missing input, when h or a is
// missing one.
func requireAmbient[S any](t testing.TB, h DurableHarness[S], a Ambient[S]) {
	t.Helper()

	h.requireWith(t,
		input{"Ambient.Write", a.Write != nil},
		input{"Ambient.Present", a.Present != nil},
		input{"Ambient.Refuse", a.Refuse != nil},
		input{"Ambient.Refusal", a.Refusal != nil},
	)
}

// RunSessionFamilyAmbientTx holds a durable session store to taking its
// multi-statement operations, Supersede and DeleteFamily, into a transaction
// its caller owns, as RunAmbientTx holds a store's single writes. It checks
// what each case wrote through a store h.New returns, outside the caller's
// transaction:
//   - a supersession inside a transaction attached with h.Begin is not
//     visible until the transaction ends, and a rollback leaves neither the
//     successor nor the old session's supersession;
//   - a family revocation inside such a transaction is discarded by a
//     rollback, every member of the family still stored;
//   - a supersession refused as a renewal conflict leaves the transaction
//     usable, and a write after it commits;
//   - a supersession refused after its first write, because its successor's
//     identifier is already stored, leaves nothing of itself in the
//     transaction, which stays usable and commits the writes around it.
//
// It fails at once, naming every missing input, when h is missing one.
func RunSessionFamilyAmbientTx[S session.Store](t *testing.T, h DurableHarness[S]) {
	t.Helper()

	h.Require(t)

	// begin rolls the transaction back at cleanup, so a case that fails part
	// way never leaves it open.
	begin := func(t *testing.T) (context.Context, func() error, func() error) {
		ctx, commit, rollback := h.Begin(t)
		t.Cleanup(func() { _ = rollback() })
		return ctx, commit, rollback
	}
	// Every case names its sessions and families apart from every other's,
	// and from the other durable suites', so the cases share one database.
	sid := func(name string) string { return "ambient-family-" + name }
	rotation := func(old *session.Session, successorID string) session.Supersession {
		return session.Supersession{
			Old: old.ID, AcceptUntil: suiteStart.Add(30 * time.Second),
			Successor: successorOf(old, successorID, suiteStart), Now: suiteStart,
		}
	}
	// unsuperseded requires old to load, committed, with no supersession.
	unsuperseded := func(t *testing.T, s S, old *session.Session, msg string) {
		t.Helper()
		got, err := s.Load(t.Context(), old.ID)
		require.NoError(t, err, "the superseded session must still load")
		assert.True(t, got.SupersededAt.IsZero(), "%s: the old session is marked superseded", msg)
		assert.Empty(t, got.SuccessorDigest, "%s: the old session names a successor", msg)
	}
	missing := func(t *testing.T, s S, sessionID, msg string) {
		t.Helper()
		_, err := s.Load(t.Context(), sessionID)
		assert.ErrorIs(t, err, session.ErrSessionNotFound, msg)
	}
	loads := func(t *testing.T, s S, sessionID, msg string) {
		t.Helper()
		_, err := s.Load(t.Context(), sessionID)
		assert.NoError(t, err, msg)
	}

	runDurableCases(t, []durableCase{
		{
			name: "a supersession inside a rolled back transaction is discarded",
			assert: func(t *testing.T) {
				s := h.New(t)
				old := familySession(sid("rolled-back"), "ambient-family-u1", suiteID(2001))
				require.NoError(t, s.Create(t.Context(), old))

				ctx, _, rollback := begin(t)
				op := rotation(old, sid("rolled-back-successor"))
				require.NoError(t, s.Supersede(ctx, op))
				missing(t, s, op.Successor.ID,
					"the successor is visible before its transaction ended: the store did not supersede in it")
				unsuperseded(t, s, old, "before the transaction ended")

				require.NoError(t, rollback())
				missing(t, s, op.Successor.ID, "the successor survived the rollback of its transaction")
				unsuperseded(t, s, old, "after the rollback")
			},
		},
		{
			name: "a family revocation inside a rolled back transaction is discarded",
			assert: func(t *testing.T) {
				s := h.New(t)
				a := familySession(sid("family-a"), "ambient-family-u2", suiteID(2002))
				b := familySession(sid("family-b"), "ambient-family-u2", suiteID(2002))
				require.NoError(t, s.Create(t.Context(), a))
				require.NoError(t, s.Create(t.Context(), b))

				ctx, _, rollback := begin(t)
				n, err := s.DeleteFamily(ctx, suiteID(2002))
				require.NoError(t, err)
				require.Equal(t, 2, n)
				for _, sess := range []*session.Session{a, b} {
					loads(t, s, sess.ID,
						"a member is gone before its transaction ended: the store did not revoke in it")
				}

				require.NoError(t, rollback())
				for _, sess := range []*session.Session{a, b} {
					loads(t, s, sess.ID, "a member's removal survived the rollback of its transaction")
				}
			},
		},
		{
			name: "a supersession refused as a conflict leaves the transaction usable",
			assert: func(t *testing.T) {
				s := h.New(t)
				old := familySession(sid("conflict"), "ambient-family-u3", suiteID(2003))
				require.NoError(t, s.Create(t.Context(), old))
				require.NoError(t, s.Supersede(t.Context(), rotation(old, sid("conflict-first"))))

				ctx, commit, _ := begin(t)
				// Observing no successor is stale: the first rotation set one.
				require.ErrorIs(t, s.Supersede(ctx, rotation(old, sid("conflict-late"))),
					session.ErrSessionRenewalConflict)
				after := familySession(sid("conflict-after"), "ambient-family-u3", suiteID(2004))
				require.NoError(t, s.Create(ctx, after), "a write after the refusal failed")
				require.NoError(t, commit(), "the transaction did not commit after the refusal")

				loads(t, s, after.ID, "the write after the refusal was not committed")
				missing(t, s, sid("conflict-late"), "the refused successor was stored")
			},
		},
		{
			name: "a supersession refused after its first write leaves nothing of it in the transaction",
			assert: func(t *testing.T) {
				s := h.New(t)
				old := familySession(sid("taken"), "ambient-family-u4", suiteID(2005))
				taken := familySession(sid("taken-successor"), "ambient-family-u4", suiteID(2006))
				require.NoError(t, s.Create(t.Context(), old))
				require.NoError(t, s.Create(t.Context(), taken))

				ctx, commit, _ := begin(t)
				before := familySession(sid("taken-before"), "ambient-family-u4", suiteID(2007))
				require.NoError(t, s.Create(ctx, before))
				// The successor's identifier is stored already, which only the
				// insert, after the old session's update, can find.
				require.Error(t, s.Supersede(ctx, rotation(old, taken.ID)))
				after := familySession(sid("taken-after"), "ambient-family-u4", suiteID(2007))
				require.NoError(t, s.Create(ctx, after), "a write after the refusal failed")
				require.NoError(t, commit(), "the transaction did not commit after the refusal")

				unsuperseded(t, s, old, "after the refused supersession committed")
				got, err := s.Load(t.Context(), taken.ID)
				require.NoError(t, err)
				assert.Equal(t, suiteID(2006), got.FamilyID, "the stored session was replaced")
				loads(t, s, before.ID, "the write before the refusal was not committed")
				loads(t, s, after.ID, "the write after the refusal was not committed")
			},
		},
	})
}

// revocationWait bounds how long RunSessionFamilyRevocationRace waits for a
// family revocation, first to start waiting on the in-flight supersession's
// row lock, and then to return once that supersession commits. A healthy run
// takes milliseconds; the bound turns a hang into a failure.
const revocationWait = 15 * time.Second

// waitingRevocation counts the backends of the harness's database, other than
// the one asking, that are waiting on a lock while running a delete from
// sessions, whether the statement deletes directly or locks the rows it
// deletes first: the family revocation the race holds back.
const waitingRevocation = `SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND pid <> pg_backend_pid()
  AND wait_event_type = 'Lock' AND query ILIKE '%delete from%sessions%'`

// RunSessionFamilyRevocationRace holds a durable session store to revoking a
// family completely while a supersession of one of its members is in flight.
// For each case it creates a family member, supersedes it inside a
// transaction attached with h.Begin and leaves that transaction open, then
// revokes the family through a store h.NewReplica returns, from another
// goroutine. Once the revocation is waiting on the old member's row lock it
// commits the supersession, and requires the revocation to have removed both
// the old member and the successor that transaction inserted, and to count
// both.
//
// A single DELETE does not: under PostgreSQL's default READ COMMITTED
// isolation, a delete that waited on a row re-checks that row once the lock
// is released, but never sees a row inserted by the transaction it waited
// for, so the successor survives the revocation of its family.
//
// The revocation runs once on its own and once inside a transaction of its
// own attached with h.Begin, committed after it returns.
//
// It detects the waiting revocation through h.Raw, from PostgreSQL's
// pg_stat_activity, and so needs a PostgreSQL store. It fails at once, naming
// every missing input, when h is missing one.
func RunSessionFamilyRevocationRace[S session.Store](t *testing.T, h DurableHarness[S]) {
	t.Helper()

	h.Require(t)
	requirePool(t, h.PoolSize, 2)

	begin := func(t *testing.T) (context.Context, func() error) {
		ctx, commit, rollback := h.Begin(t)
		t.Cleanup(func() { _ = rollback() })
		return ctx, commit
	}

	type testCase struct {
		name string
		// family numbers the case's family apart from every other case's.
		family int
		// revokeIn returns the context the revocation runs in, and what
		// ends it once it has returned.
		revokeIn func(t *testing.T) (ctx context.Context, end func() error)
	}

	cases := []testCase{
		{
			name:   "a family revocation waiting on a supersession removes its successor",
			family: 2101,
			revokeIn: func(t *testing.T) (context.Context, func() error) {
				return t.Context(), func() error { return nil }
			},
		},
		{
			name:   "a family revocation in a transaction waiting on a supersession removes its successor",
			family: 2102,
			revokeIn: func(t *testing.T) (context.Context, func() error) {
				return begin(t)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := h.New(t)
			revoker := h.NewReplica(t)
			family := suiteID(tc.family)
			name := fmt.Sprintf("revocation-race-%d", tc.family)
			old := familySession(name, identity.UserID(name+"-user"), family)
			require.NoError(t, s.Create(t.Context(), old))

			// The supersession in flight: written, not yet committed.
			superseding, commitSupersession := begin(t)
			successor := successorOf(old, name+"-successor", suiteStart)
			require.NoError(t, s.Supersede(superseding, session.Supersession{
				Old: old.ID, AcceptUntil: suiteStart.Add(30 * time.Second), Successor: successor, Now: suiteStart,
			}))

			type outcome struct {
				n   int
				err error
			}
			revokeCtx, endRevocation := tc.revokeIn(t)
			revokeCtx, cancel := context.WithTimeout(revokeCtx, revocationWait)
			defer cancel()
			done := make(chan outcome, 1)
			go func() {
				n, err := revoker.DeleteFamily(revokeCtx, family)
				done <- outcome{n, err}
			}()

			awaitWaitingRevocation(t, h.Raw, done)
			require.NoError(t, commitSupersession(), "the supersession did not commit")

			var got outcome
			select {
			case got = <-done:
			case <-time.After(revocationWait):
				t.Fatal("the family revocation did not return after the supersession it waited on committed")
			}
			require.NoError(t, got.err)
			require.NoError(t, endRevocation(), "the revocation's transaction did not commit")

			for _, sessionID := range []string{old.ID, successor.ID} {
				_, err := s.Load(t.Context(), sessionID)
				assert.ErrorIs(t, err, session.ErrSessionNotFound,
					"%s is still stored after its family was revoked: the revocation did not see "+
						"the successor of the supersession it waited on", sessionID)
			}
			assert.Equal(t, 2, got.n, "the revocation did not count both the old member and its successor")
		})
	}
}

// awaitWaitingRevocation returns once raw shows a family revocation waiting on
// a lock, and fails t when the revocation returns first, as it could only by
// not waiting for the row the uncommitted supersession holds, or when none
// waits within revocationWait.
func awaitWaitingRevocation[O any](t *testing.T, raw *sql.DB, done <-chan O) {
	t.Helper()

	awaitWaiting(t, raw, waitingRevocation, done,
		"the family revocation returned while a supersession of a member was uncommitted: "+
			"it did not wait for the member's row",
		"no family revocation waited on the uncommitted supersession's row lock")
}

// awaitWaiting returns once query, run through raw, counts a backend waiting
// on a lock. It fails t with returned when done delivers first, and with none
// when nothing waits within revocationWait.
func awaitWaiting[O any](t *testing.T, raw *sql.DB, query string, done <-chan O, returned, none string) {
	t.Helper()

	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(revocationWait)
	for {
		var waiting int
		require.NoError(t, raw.QueryRowContext(t.Context(), query).Scan(&waiting))
		if waiting > 0 {
			return
		}

		select {
		case <-done:
			t.Fatal(returned)
		case <-deadline:
			t.Fatal(none)
		case <-tick.C:
		}
	}
}

// waitingSupersession counts the backends of the harness's database, other
// than the one asking, that are waiting on a lock while running a statement
// that reads or writes sessions other than a delete: the supersession
// RunSessionSuccessorAdvanceRace holds back, which may wait in its update of
// sessions or in a locking read of the rows it updates.
const waitingSupersession = `SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND pid <> pg_backend_pid()
  AND wait_event_type = 'Lock' AND query ILIKE '%sessions%' AND query NOT ILIKE '%delete from%'`

// RunSessionSuccessorAdvanceRace holds a durable session store to judging a
// supersession's observed successor in the same atomic step as the
// supersession, so that a successor moving on concurrently cannot slip
// between the judgement and the write.
//
// For each case it creates a family member and rotates it once, committed,
// then moves that first successor on inside a transaction attached with
// h.Begin and leaves the transaction open: it presents it, rotates it, or
// removes it. From another goroutine, through a store h.NewReplica returns,
// it supersedes the old member again observing the first successor, with
// Supersession.RequireUnpresentedSuccessor set where the case is the
// presentation. Once that supersession is waiting on a lock it commits the
// transaction, and requires the supersession to be refused with
// session.ErrSuccessorAdvanced, having written nothing: the late successor is
// not stored, and the old member still names the first successor.
//
// A store that reads the successor before taking its row lock reads the
// committed, unadvanced state, goes on to wait, and then supersedes a
// successor that moved on while it waited.
//
// It detects the waiting supersession through h.Raw, from PostgreSQL's
// pg_stat_activity, and so needs a PostgreSQL store. It fails at once, naming
// every missing input, when h is missing one.
func RunSessionSuccessorAdvanceRace[S session.Store](t *testing.T, h DurableHarness[S]) {
	t.Helper()

	h.Require(t)
	requirePool(t, h.PoolSize, 2)

	type testCase struct {
		name string
		// family numbers the case's family apart from every other case's.
		family int
		// requireUnpresented is the racing supersession's
		// RequireUnpresentedSuccessor.
		requireUnpresented bool
		// advance moves first on through ctx, which carries the open
		// transaction.
		advance func(ctx context.Context, t *testing.T, s S, first *session.Session)
	}

	cases := []testCase{
		{
			name:               "a supersession requiring an unpresented successor that waited on its presentation is refused",
			family:             2201,
			requireUnpresented: true,
			advance: func(ctx context.Context, t *testing.T, s S, first *session.Session) {
				require.NoError(t, s.MarkPresented(ctx, first.ID, suiteStart.Add(5*time.Second)))
			},
		},
		{
			name:   "a re-rotation that waited on its observed successor's own rotation is refused",
			family: 2202,
			advance: func(ctx context.Context, t *testing.T, s S, first *session.Session) {
				at := suiteStart.Add(5 * time.Second)
				require.NoError(t, s.Supersede(ctx, session.Supersession{
					Old: first.ID, AcceptUntil: at.Add(30 * time.Second),
					Successor: successorOf(first, first.ID+"-onward", at), Now: at,
				}))
			},
		},
		{
			name:   "a re-rotation that waited on its observed successor's removal is refused",
			family: 2203,
			advance: func(ctx context.Context, t *testing.T, s S, first *session.Session) {
				require.NoError(t, s.Delete(ctx, first.ID))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := h.New(t)
			superseder := h.NewReplica(t)
			name := fmt.Sprintf("successor-race-%d", tc.family)
			old := familySession(name, identity.UserID(name+"-user"), suiteID(tc.family))
			require.NoError(t, s.Create(t.Context(), old))
			first := successorOf(old, name+"-first", suiteStart)
			require.NoError(t, s.Supersede(t.Context(), session.Supersession{
				Old: old.ID, AcceptUntil: suiteStart.Add(30 * time.Second), Successor: first, Now: suiteStart,
			}))

			// The successor moving on: written, not yet committed.
			advancing, commitAdvance, rollbackAdvance := h.Begin(t)
			t.Cleanup(func() { _ = rollbackAdvance() })
			tc.advance(advancing, t, s, first)

			later := suiteStart.Add(time.Hour)
			late := successorOf(old, name+"-late", later)
			ctx, cancel := context.WithTimeout(t.Context(), revocationWait)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- superseder.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID),
					RequireUnpresentedSuccessor: tc.requireUnpresented,
					AcceptUntil:                 later.Add(30 * time.Second), Successor: late, Now: later,
				})
			}()

			awaitWaiting(t, h.Raw, waitingSupersession, done,
				"the supersession returned while its observed successor was moving on, uncommitted: "+
					"it did not wait for the successor's row",
				"no supersession waited on the uncommitted change to its observed successor")
			require.NoError(t, commitAdvance(), "the successor's change did not commit")

			var err error
			select {
			case err = <-done:
			case <-time.After(revocationWait):
				t.Fatal("the supersession did not return after the change it waited on committed")
			}
			require.ErrorIs(t, err, session.ErrSuccessorAdvanced,
				"the supersession went ahead over a successor that moved on while it waited: "+
					"it judged the successor before locking it")

			_, err = s.Load(t.Context(), late.ID)
			assert.ErrorIs(t, err, session.ErrSessionNotFound, "the refused supersession stored its successor")
			got, err := s.Load(t.Context(), old.ID)
			require.NoError(t, err)
			assert.Equal(t, sessionDigest(first.ID), got.SuccessorDigest,
				"the refused supersession changed the old member's successor")
			assert.True(t, got.SupersededAt.Equal(suiteStart),
				"the refused supersession changed the old member's supersession time: %v", got.SupersededAt)
		})
	}
}

// waitingOnSessions counts the backends of the harness's database, other than
// the one asking, that are waiting on a lock while running a statement on
// sessions.
const waitingOnSessions = `SELECT count(*) FROM pg_stat_activity
WHERE datname = current_database() AND pid <> pg_backend_pid()
  AND wait_event_type = 'Lock' AND query ILIKE '%sessions%'`

// awaitLockWaiters returns once raw shows at least n backends waiting on a
// lock on sessions, and fails t with none when that does not happen within
// revocationWait.
func awaitLockWaiters(t *testing.T, raw *sql.DB, n int, none string) {
	t.Helper()

	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(revocationWait)
	for {
		var waiting int
		require.NoError(t, raw.QueryRowContext(t.Context(), waitingOnSessions).Scan(&waiting))
		if waiting >= n {
			return
		}

		select {
		case <-deadline:
			t.Fatal(none)
		case <-tick.C:
		}
	}
}

// RunSessionExtendingRenewalLockOrder holds a durable session store to taking
// the row locks of a supersession that extends its family in an order no
// concurrent writer of the same family can meet in reverse.
//
// A supersession that gives its successor a later absolute deadline locks the
// session it supersedes and then every superseded member of the family it
// raises. Each case rotates a family member O into S1, committed, so that O is
// superseded and S1 is the family's head, and then holds S1's row in a
// transaction opened through h.Raw. Behind that lock, in this order, it
// queues a supersession of S1 extending the family, through the store
// h.New returns, and a competitor through a store h.NewReplica returns: a
// re-rotation of O observing S1, or a revocation of the family. Once both
// wait it releases S1, so the extending supersession takes S1 first and the
// competitor already holds or reaches for O.
//
// Both must return without a deadlock: the extending supersession succeeds,
// and the competitor is refused with session.ErrSuccessorAdvanced (the
// re-rotation) or removes the whole family, S1's new successor included (the
// revocation). A store that locks S1 and then O, while the competitor locks
// O and then S1, deadlocks, and PostgreSQL aborts one side.
//
// It detects waiting statements through h.Raw, from PostgreSQL's
// pg_stat_activity, and so needs a PostgreSQL store. It fails at once, naming
// every missing input, when h is missing one.
func RunSessionExtendingRenewalLockOrder[S session.Store](t *testing.T, h DurableHarness[S]) {
	t.Helper()

	h.Require(t)
	requirePool(t, h.PoolSize, 2)

	type testCase struct {
		name string
		// family numbers the case's family apart from every other case's.
		family int
		// compete runs the competitor through s, a replica, once the
		// extending supersession waits on S1, and returns its error.
		compete func(ctx context.Context, s S, old, first *session.Session) error
		// assert checks the competitor's error and what is stored after
		// both returned; extended is S1's successor.
		assert func(t *testing.T, s S, err error, old, first, extended *session.Session)
	}

	extendedAt := suiteStart.Add(time.Hour)
	cases := []testCase{
		{
			name:   "a re-rotation of a superseded member waiting behind an extending renewal does not deadlock",
			family: 2301,
			compete: func(ctx context.Context, s S, old, first *session.Session) error {
				late := successorOf(old, old.ID+"-late", extendedAt)
				late.AbsoluteExpiresAt = suiteStart.Add(30 * time.Hour)
				return s.Supersede(ctx, session.Supersession{
					Old: old.ID, ObservedSuccessor: sessionDigest(first.ID),
					AcceptUntil: extendedAt.Add(30 * time.Second), Successor: late, Now: extendedAt,
				})
			},
			assert: func(t *testing.T, s S, err error, old, _, extended *session.Session) {
				require.ErrorIs(t, err, session.ErrSuccessorAdvanced,
					"the re-rotation of the superseded member did not end in a refusal")
				_, err = s.Load(t.Context(), old.ID+"-late")
				assert.ErrorIs(t, err, session.ErrSessionNotFound, "the refused re-rotation stored its successor")
				got, err := s.Load(t.Context(), extended.ID)
				require.NoError(t, err, "the extending renewal's successor is not stored")
				assertTimeEqual(t, extended.AbsoluteExpiresAt, got.AbsoluteExpiresAt, "the successor's deadline")
			},
		},
		{
			name:   "a family revocation waiting behind an extending renewal does not deadlock",
			family: 2302,
			compete: func(ctx context.Context, s S, _, _ *session.Session) error {
				_, err := s.DeleteFamily(ctx, suiteID(2302))
				return err
			},
			assert: func(t *testing.T, s S, err error, old, first, extended *session.Session) {
				require.NoError(t, err, "the family revocation failed")
				for _, sessionID := range []string{old.ID, first.ID, extended.ID} {
					_, err := s.Load(t.Context(), sessionID)
					assert.ErrorIs(t, err, session.ErrSessionNotFound,
						"%s is still stored after its family was revoked", sessionID)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := h.New(t)
			competitor := h.NewReplica(t)
			name := fmt.Sprintf("lock-order-%d", tc.family)
			old := familySession(name, identity.UserID(name+"-user"), suiteID(tc.family))
			require.NoError(t, s.Create(t.Context(), old))
			first := successorOf(old, name+"-first", suiteStart)
			require.NoError(t, s.Supersede(t.Context(), session.Supersession{
				Old: old.ID, AcceptUntil: suiteStart.Add(30 * time.Second), Successor: first, Now: suiteStart,
			}))

			// Hold S1, so the racers queue behind it in a known order.
			holder, err := h.Raw.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			t.Cleanup(func() { _ = holder.Rollback() })
			_, err = holder.ExecContext(t.Context(), `SELECT 1 FROM sessions WHERE id_digest = $1 FOR UPDATE`,
				sessionDigest(first.ID))
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(t.Context(), revocationWait)
			defer cancel()

			extended := successorOf(first, name+"-extended", extendedAt)
			extended.AbsoluteExpiresAt = suiteStart.Add(20 * time.Hour)
			renewed := make(chan error, 1)
			go func() {
				renewed <- s.Supersede(ctx, session.Supersession{
					Old: first.ID, AcceptUntil: extendedAt.Add(30 * time.Second), Successor: extended, Now: extendedAt,
				})
			}()
			awaitLockWaiters(t, h.Raw, 1, "the extending renewal did not wait on the held successor")

			competed := make(chan error, 1)
			go func() { competed <- tc.compete(ctx, competitor, old, first) }()
			awaitLockWaiters(t, h.Raw, 2, "the competitor did not wait behind the extending renewal")

			require.NoError(t, holder.Rollback())

			var renewErr, competeErr error
			for range 2 {
				select {
				case renewErr = <-renewed:
				case competeErr = <-competed:
				case <-time.After(revocationWait):
					t.Fatal("the racers did not return after the held successor was released")
				}
			}
			require.False(t, deadlocked(renewErr),
				"PostgreSQL aborted the extending renewal as one side of a deadlock: %v", renewErr)
			require.False(t, deadlocked(competeErr),
				"PostgreSQL aborted the competitor as one side of a deadlock: %v", competeErr)
			require.NoError(t, renewErr, "the extending renewal failed")
			tc.assert(t, competitor, competeErr, old, first, extended)
		})
	}
}

// deadlocked reports whether err carries PostgreSQL's deadlock_detected
// failure (SQLSTATE 40P01), through errors.As, as both drivers' errors do.
func deadlocked(err error) bool {
	var coded interface{ SQLState() string }
	return errors.As(err, &coded) && coded.SQLState() == "40P01"
}

// DescendingIDs returns an id.Generator whose every identifier sorts before
// the one it returned before, for a durable store's row identifiers. A
// harness built on it stores each row with an id lower than every earlier
// row's, so the rows' id order is the reverse of the order they were
// inserted in, and of the order a scan of a family usually meets them in.
// RunSessionExtendingRenewalLockOrder run on such a harness holds a store to
// locking a family in id order on every path, rather than in whatever order
// a statement scans it. One generator is shared by every store of the
// harness, as one id sequence is shared by every replica.
func DescendingIDs() id.Generator {
	return &descendingIDs{}
}

type descendingIDs struct{ issued atomic.Uint64 }

func (g *descendingIDs) NewID() (id.ID, error) {
	return id.Parse(fmt.Sprintf("7fffffff-ffff-7fff-bfff-%012x", 0xffffffffffff-g.issued.Add(1)))
}
