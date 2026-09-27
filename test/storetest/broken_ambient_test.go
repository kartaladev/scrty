package storetest_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

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
	for i := range tx.pending {
		tx.db.rows[i] = true
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

// refuse is a refusal. The conforming store refuses without a failed
// statement; the defective one refuses through one, aborting the
// transaction it ran in.
func (s *ambientStore) refuse(ctx context.Context) error {
	if tx, ok := s.tx(ctx); ok && s.defect == ambientRefusalAborts {
		tx.aborted = true
	}
	return errRefused
}

func ambientVariant(d ambientDefect, failsCase string) brokenVariant {
	return brokenVariant{
		name: "ambient-" + string(d),
		run: func(t *testing.T) {
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

			storetest.RunAmbientTx(t, h, storetest.Ambient[*ambientStore]{
				Write:   func(ctx context.Context, s *ambientStore, i int) error { return s.write(ctx, i) },
				Present: func(_ *testing.T, _ *sql.DB, i int) bool { return db.present(i) },
				Refuse:  func(ctx context.Context, s *ambientStore) error { return s.refuse(ctx) },
				Refusal: errRefused,
			})
		},
		failsCase: failsCase,
	}
}

var ambientVariants = []brokenVariant{
	ambientVariant(ambientConforming, ""),
	ambientVariant(ambientBypasses, "a write inside a rolled back transaction is discarded"),
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
