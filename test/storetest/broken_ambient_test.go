package storetest_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/storetest"
)

// txDB is an in-process model of a database with transactions: committed rows,
// and transactions whose writes reach them only on commit. A transaction that
// saw a failed statement is aborted, as PostgreSQL aborts one, and its commit
// discards its writes and reports so.
type txDB struct {
	mu   sync.Mutex
	rows map[int]bool
}

type fakeTx struct {
	db      *txDB
	pending map[int]bool
	aborted bool
}

var (
	errTxAborted = errors.New("current transaction is aborted")
	errRefused   = errors.New("refused")
)

func (db *txDB) begin() *fakeTx { return &fakeTx{db: db, pending: map[int]bool{}} }

func (db *txDB) present(i int) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.rows[i]
}

func (tx *fakeTx) commit() error {
	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()
	if tx.aborted {
		return errTxAborted
	}
	for i, stored := range tx.pending {
		tx.db.rows[i] = stored
	}
	return nil
}

func (tx *fakeTx) rollback() error { return nil }

// txKey attaches a transaction for the fake's own backend; foreignTxKey
// attaches one for another backend.
type (
	txKey        struct{}
	foreignTxKey struct{}
)

type ambientDefect string

const (
	ambientConforming      ambientDefect = "conforming"
	ambientBypasses        ambientDefect = "bypasses-tx"
	ambientDeleteBypasses  ambientDefect = "delete-bypasses-tx"
	ambientIgnoresResolver ambientDefect = "ignores-resolver"
	ambientRefusalAborts   ambientDefect = "refusal-aborts"
	ambientJoinsForeign    ambientDefect = "joins-foreign-tx"
)

// ambientStore resolves its transaction as a durable adapter does: the
// resolver first, then its own context attachment, then the base handle.
type ambientStore struct {
	db       *txDB
	defect   ambientDefect
	resolver func(ctx context.Context) (*fakeTx, bool)
}

func (s *ambientStore) tx(ctx context.Context) (*fakeTx, bool) {
	if s.defect == ambientBypasses {
		return nil, false
	}
	if s.resolver != nil && s.defect != ambientIgnoresResolver {
		if tx, ok := s.resolver(ctx); ok {
			return tx, true
		}
	}
	if tx, ok := ctx.Value(txKey{}).(*fakeTx); ok {
		return tx, true
	}
	if s.defect == ambientJoinsForeign {
		if tx, ok := ctx.Value(foreignTxKey{}).(*fakeTx); ok {
			return tx, true
		}
	}
	return nil, false
}

func (s *ambientStore) write(ctx context.Context, i int) error {
	tx, ok := s.tx(ctx)
	if !ok {
		s.db.mu.Lock()
		defer s.db.mu.Unlock()
		s.db.rows[i] = true
		return nil
	}
	if tx.aborted {
		return errTxAborted
	}
	tx.pending[i] = true
	return nil
}

// remove deletes record i, in the transaction ctx resolves to. The defective
// store deletes on the base handle, whatever transaction ctx carries.
func (s *ambientStore) remove(ctx context.Context, i int) error {
	tx, ok := s.tx(ctx)
	if !ok || s.defect == ambientDeleteBypasses {
		s.db.mu.Lock()
		defer s.db.mu.Unlock()
		delete(s.db.rows, i)
		return nil
	}
	tx.pending[i] = false
	return nil
}

// refuse is a refusal. The conforming store refuses without a failed
// statement; the defective one refuses through one, aborting the
// transaction it ran in.
func (s *ambientStore) refuse(ctx context.Context) error {
	if tx, ok := s.tx(ctx); ok && s.defect == ambientRefusalAborts {
		tx.aborted = true
	}
	return errRefused
}

// ambientRun runs the ambient-transaction suite over the fake store carrying d.
// withRemove sets Ambient.Remove, the one optional field.
func ambientRun(d ambientDefect, withRemove bool) func(t *testing.T) {
	return func(t *testing.T) {
		db := &txDB{rows: map[int]bool{}}
		h := fakeHarness(func(*testing.T) *ambientStore { return &ambientStore{db: db, defect: d} })
		h.Begin = func(t *testing.T) (context.Context, func() error, func() error) {
			tx := db.begin()
			return context.WithValue(t.Context(), txKey{}, tx), tx.commit, tx.rollback
		}
		h.BeginResolved = func(t *testing.T) (*ambientStore, context.Context, func() error, func() error) {
			tx := db.begin()
			s := &ambientStore{db: db, defect: d, resolver: func(context.Context) (*fakeTx, bool) { return tx, true }}
			return s, t.Context(), tx.commit, tx.rollback
		}
		h.BeginForeign = func(t *testing.T) (context.Context, func() error) {
			tx := db.begin()
			return context.WithValue(t.Context(), foreignTxKey{}, tx), tx.rollback
		}

		a := storetest.Ambient[*ambientStore]{
			Write:   func(ctx context.Context, s *ambientStore, i int) error { return s.write(ctx, i) },
			Present: func(_ *testing.T, _ *sql.DB, i int) bool { return db.present(i) },
			Refuse:  func(ctx context.Context, s *ambientStore) error { return s.refuse(ctx) },
			Refusal: errRefused,
		}
		if withRemove {
			a.Remove = func(ctx context.Context, s *ambientStore, i int) error { return s.remove(ctx, i) }
		}
		storetest.RunAmbientTx(t, h, a)
	}
}

func ambientVariant(d ambientDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name:      "ambient-" + string(d),
		run:       ambientRun(d, true),
		failsCase: failsCase,
	}
}

// uncoveredDeleteVar names the child run of TestAmbientReportsAnUncoveredDelete.
const uncoveredDeleteVar = "STORETEST_UNCOVERED_DELETE_CHILD"

// TestAmbientUncoveredDeleteChild is the child half of
// TestAmbientReportsAnUncoveredDelete: the suite over a conforming store that
// leaves Ambient.Remove unset. Without the variable it skips.
func TestAmbientUncoveredDeleteChild(t *testing.T) {
	if _, child := os.LookupEnv(uncoveredDeleteVar); !child {
		t.Skipf("run through TestAmbientReportsAnUncoveredDelete (%s)", uncoveredDeleteVar)
	}
	ambientRun(ambientConforming, false)(t)
}

// TestAmbientReportsAnUncoveredDelete pins that a run leaving Ambient.Remove
// unset says in its output that deletes were not covered, rather than dropping
// the four delete cases without a word. The child runs in its own process, since
// a skip is visible only in the verbose output.
func TestAmbientReportsAnUncoveredDelete(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		env    string
		assert func(t *testing.T, output string, err error)
	}

	cases := []testCase{
		{
			name: "Remove unset reports the delete cases as not covered",
			env:  uncoveredDeleteVar + "=1",
			assert: func(t *testing.T, output string, err error) {
				require.NoError(t, err, output)
				assert.Contains(t, output, "--- SKIP: TestAmbientUncoveredDeleteChild/deletes_are_not_covered")
				assert.Contains(t, output, "Ambient.Remove is not set")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			//nolint:gosec // G204: this test binary re-executed with fixed arguments
			cmd := exec.CommandContext(t.Context(), os.Args[0],
				"-test.run=^TestAmbientUncoveredDeleteChild$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), tc.env)
			out, err := cmd.CombinedOutput()

			tc.assert(t, string(out), err)
		})
	}
}

var ambientVariants = []brokenVariant{
	ambientVariant(ambientConforming, ""),
	ambientVariant(ambientBypasses, "a write inside a rolled back transaction is discarded"),
	ambientVariant(ambientDeleteBypasses, "a delete inside a rolled back transaction is discarded"),
	ambientVariant(ambientIgnoresResolver, "a configured resolver's transaction is used"),
	ambientVariant(ambientRefusalAborts, "a refusal inside a transaction leaves it usable"),
	ambientVariant(ambientJoinsForeign, "a transaction attached for another backend is ignored"),
	{
		name: "ambient-missing-raw",
		// Wrapped in a subtest, as the narrow-pool race variant is, for the
		// guard to find the input check's failure by name.
		run: func(t *testing.T) {
			t.Run("missing raw", func(t *testing.T) {
				h := fakeHarness(func(*testing.T) *ambientStore { return nil })
				h.Raw = nil
				storetest.RunAmbientTx(t, h, storetest.Ambient[*ambientStore]{})
			})
		},
		failsCase: "missing raw",
		failsWith: "storetest: DurableHarness.Raw, Ambient.Write, Ambient.Present, Ambient.Refuse, " +
			"Ambient.Refusal are required",
	},
}

// familyDB is an in-process model of a database of sessions with
// transactions. Its committed state is a memory store, and the log of every
// write committed to it; a transaction works on a memory store of its own,
// rebuilt from that log when it begins, and its writes reach the committed
// store only on commit, replayed in order.
type familyDB struct {
	mu    sync.Mutex
	store *session.MemoryStore
	log   []familyWrite
}

// familyWrite is one write, replayed on a commit and on every later begin.
// Its error is the write's verdict when it first ran, and is ignored on
// replay, where the write meets the same state again.
type familyWrite func(s session.Store) error

// familyTx is a transaction of familyDB. A transaction aborted by a failed
// statement refuses every later write, and its commit discards its writes.
type familyTx struct {
	db      *familyDB
	store   *session.MemoryStore
	writes  []familyWrite
	aborted bool
}

func newFamilyDB() *familyDB { return &familyDB{store: must.Must(session.NewMemoryStore())} }

func (db *familyDB) begin() *familyTx {
	db.mu.Lock()
	defer db.mu.Unlock()

	tx := &familyTx{db: db, store: must.Must(session.NewMemoryStore())}
	for _, w := range db.log {
		_ = w(tx.store)
	}
	return tx
}

func (tx *familyTx) commit() error {
	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()

	if tx.aborted {
		return errTxAborted
	}
	for _, w := range tx.writes {
		_ = w(tx.db.store)
		tx.db.log = append(tx.db.log, w)
	}
	tx.writes = nil
	return nil
}

func (tx *familyTx) rollback() error {
	tx.writes = nil
	return nil
}

type familyDefect string

const (
	familyConforming          familyDefect = "conforming"
	familySupersedeOwnTx      familyDefect = "supersede-opens-own-tx"
	familyDeleteOwnTx         familyDefect = "delete-family-opens-own-tx"
	familyConflictAborts      familyDefect = "conflict-aborts-tx"
	familySupersedePartWrites familyDefect = "supersede-keeps-partial-write"
)

// familyStore is a session store over familyDB that resolves its
// transaction as a durable adapter does, from its own context attachment.
// It implements the operations RunSessionFamilyAmbientTx calls; the embedded
// Store is nil, so any other call panics.
type familyStore struct {
	session.Store

	db     *familyDB
	defect familyDefect
}

// tx is the transaction ctx carries, unless ownTx: a store that opens its
// own transaction for the operation ignores the caller's.
func (s *familyStore) tx(ctx context.Context, ownTx bool) (*familyTx, bool) {
	if ownTx {
		return nil, false
	}
	tx, ok := ctx.Value(txKey{}).(*familyTx)
	return tx, ok
}

// write runs w in the caller's transaction, or commits it at once outside
// one.
func (s *familyStore) write(ctx context.Context, ownTx bool, w familyWrite) error {
	if tx, ok := s.tx(ctx, ownTx); ok {
		if tx.aborted {
			return errTxAborted
		}
		err := w(tx.store)
		tx.writes = append(tx.writes, w)
		return err
	}

	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	err := w(s.db.store)
	s.db.log = append(s.db.log, w)
	return err
}

func (s *familyStore) Create(ctx context.Context, sess *session.Session) error {
	return s.write(ctx, false, func(st session.Store) error { return st.Create(ctx, sess) })
}

func (s *familyStore) Load(ctx context.Context, sid string) (*session.Session, error) {
	if tx, ok := s.tx(ctx, false); ok {
		return tx.store.Load(ctx, sid)
	}
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	return s.db.store.Load(ctx, sid)
}

func (s *familyStore) Supersede(ctx context.Context, op session.Supersession) error {
	tx, inTx := s.tx(ctx, false)
	if inTx && s.defect == familySupersedePartWrites && op.Successor != nil {
		if _, err := tx.store.Load(ctx, op.Successor.ID); err == nil {
			// The old session's update runs before the insert that fails,
			// and is kept: no savepoint undoes it.
			stray := *op.Successor
			stray.ID += "-partial"
			partial := op
			partial.Successor = &stray
			_ = s.write(ctx, false, func(st session.Store) error { return st.Supersede(ctx, partial) })
			return errors.New("the successor's identifier is already in use")
		}
	}

	err := s.write(ctx, s.defect == familySupersedeOwnTx, func(st session.Store) error {
		return st.Supersede(ctx, op)
	})
	if inTx && s.defect == familyConflictAborts && errors.Is(err, session.ErrRenewalConflict) {
		tx.aborted = true
	}
	return err
}

func (s *familyStore) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	var n int
	err := s.write(ctx, s.defect == familyDeleteOwnTx, func(st session.Store) error {
		var err error
		n, err = st.DeleteFamily(ctx, family)
		return err
	})
	return n, err
}

func familyAmbientVariant(d familyDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "session-family-ambient-" + string(d),
		run: func(t *testing.T) {
			db := newFamilyDB()
			h := fakeHarness(func(*testing.T) session.Store { return &familyStore{db: db, defect: d} })
			h.Begin = func(t *testing.T) (context.Context, func() error, func() error) {
				tx := db.begin()
				return context.WithValue(t.Context(), txKey{}, tx), tx.commit, tx.rollback
			}

			storetest.RunSessionFamilyAmbientTx(t, h)
		},
		failsCase: failsCase,
	}
}

var familyAmbientVariants = []brokenVariant{
	familyAmbientVariant(familyConforming, ""),
	familyAmbientVariant(familySupersedeOwnTx, "a supersession inside a rolled back transaction is discarded"),
	familyAmbientVariant(familyDeleteOwnTx, "a family revocation inside a rolled back transaction is discarded"),
	familyAmbientVariant(familyConflictAborts, "a supersession refused as a conflict leaves the transaction usable"),
	familyAmbientVariant(familySupersedePartWrites,
		"a supersession refused after its first write leaves nothing of it in the transaction"),
}
