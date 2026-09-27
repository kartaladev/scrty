package storetest_test

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/kartaladev/scrty/test/storetest"
)

// The durable suites' own engines are proven here without a database: each
// runs against in-process fakes, one conforming and one carrying the defect
// the suite exists to catch. The durable red runs, against PostgreSQL stores
// that carry those defects, belong to the adapters' tests.

// durableVariants are the durable suites' variants, run by the same
// re-execution guard as the portable suites'.
var durableVariants = slices.Concat(raceVariants, ambientVariants, sealedVariants)

// fakeHarness is a durable harness over an in-process fake. New and
// NewReplica both call newStore, so a fake whose instances share state gets
// replicas over one table. Raw is a
// placeholder the fakes never touch, and the transaction functions fail the
// test if a suite that does not use them calls them, so the harness passes the
// input check without pretending to be a database.
func fakeHarness[S any](newStore func(t *testing.T) S) storetest.DurableHarness[S] {
	return storetest.DurableHarness[S]{
		Harness:    storetest.Harness[S]{New: newStore},
		NewReplica: newStore,
		Raw:        &sql.DB{},
		Begin: func(t *testing.T) (context.Context, func() error, func() error) {
			noTransactions(t)
			return nil, nil, nil
		},
		BeginResolved: func(t *testing.T) (S, context.Context, func() error, func() error) {
			noTransactions(t)
			var zero S
			return zero, nil, nil, nil
		},
		BeginForeign: func(t *testing.T) (context.Context, func() error) {
			noTransactions(t)
			return nil, nil
		},
		PoolSize: 8,
	}
}

// noTransactions fails a test that begins a transaction on the fake harness.
func noTransactions(t *testing.T) {
	t.Helper()
	t.Fatal("the fake harness has no transactions")
}
