// Package storetest holds the conformance suites every scrty security-state
// store implementation must pass: sessions, one-time tokens, login attempts,
// signing keys, MFA enrolments and API keys.
//
// The portable suites (RunSessionStoreSuite, RunOneTimeStoreSuite,
// RunAttemptStoreSuite, RunSigningKeyStoreSuite, RunEnrolmentStoreSuite and
// RunAPIKeyStoreSuite) take a factory that returns an empty store and hold it
// to the contract its package documents. The in-memory defaults, the durable
// adapters and a consumer's own implementation all run the same suites, so a
// behaviour that differs between them fails for the one that differs.
//
// Every case runs in its own subtest on a store the factory built for that
// case alone, and asserts exact counts and exact records.
//
// A suite names its cases through t.Run and never the backend: the caller
// does, by wrapping each suite call in a subtest named after its backend,
// t.Run("pgx", func(t *testing.T) { storetest.RunSessionStoreSuite(t, newStore) }),
// so a failure reads TestX/<backend>/<case>. scrty's own runs name theirs
// memory, sqlstore, pgx and gorm.
//
// Time is never waited for: a suite that needs the store's clock hands the
// factory one it advances itself.
package storetest

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// Harness builds the store a portable suite runs against.
type Harness[S any] struct {
	// New returns an empty store holding state no other call shares.
	New func(t *testing.T) S
}

// DurableHarness is what the durable suites (races, ambient transactions,
// sealed columns) need beyond a store: a view of the same database that does
// not go through the store, a way to begin a transaction the caller owns, and
// how wide the connection pool is. Every field is required, and a suite given
// a harness with one missing fails at once, naming it, rather than running
// fewer cases.
type DurableHarness[S any] struct {
	Harness[S]

	// NewReplica returns a second store instance on the same database as
	// the store Harness.New returns, holding its own connection pool (its
	// own *sql.DB or pgxpool.Pool), as a second replica of the application
	// would. The race suites split their racers between the two, because a
	// store that serialises in Go, under a lock of one instance, passes a
	// race confined to that instance. A lock shared by the whole process is
	// not caught, since both instances run in the test's process. It is
	// required.
	NewReplica func(t *testing.T) S

	// Raw reaches the store's database out of band.
	Raw *sql.DB

	// Begin starts a caller-owned transaction and returns a context carrying
	// it, attached the way the backend under test attaches one.
	Begin func(t *testing.T) (ctx context.Context, commit, rollback func() error)

	// BeginResolved starts a caller-owned transaction and returns a store
	// configured with a resolver that reports it. The context returned does
	// not carry the transaction.
	BeginResolved func(t *testing.T) (s S, ctx context.Context, commit, rollback func() error)

	// BeginForeign attaches to the context a transaction of a different
	// backend, which the store under test must ignore.
	//
	// The suites call a transaction's rollback again at cleanup, after it
	// has committed or rolled back, so a case that fails part way never
	// leaves it open; that call's error is ignored.
	BeginForeign func(t *testing.T) (ctx context.Context, rollback func() error)

	// PoolSize is how many connections the store can hold open at once. It
	// must be the store's real maximum (its sql.DB's MaxOpenConns, or the
	// pool's max size), not a wish: the race suites check it against their
	// racer count, and a harness that declares more than the store can open
	// passes that check while its racers still queue for connections.
	PoolSize int
}

// Require fails t immediately when any field of h is missing, naming every
// one that is.
func (h DurableHarness[S]) Require(t testing.TB) {
	t.Helper()

	h.requireWith(t)
}

// requireWith fails t immediately, once, naming every field of h that is
// missing and every one of a suite's own inputs that is not present.
func (h DurableHarness[S]) requireWith(t testing.TB, suite ...input) {
	t.Helper()

	failMissing(t, append(h.missing(), missingInputs(suite...)...))
}

// missing names the fields of h that are missing, in declaration order.
func (h DurableHarness[S]) missing() []string {
	return missingInputs(
		input{"Harness.New", h.New != nil},
		input{"DurableHarness.NewReplica", h.NewReplica != nil},
		input{"DurableHarness.Raw", h.Raw != nil},
		input{"DurableHarness.Begin", h.Begin != nil},
		input{"DurableHarness.BeginResolved", h.BeginResolved != nil},
		input{"DurableHarness.BeginForeign", h.BeginForeign != nil},
		input{"DurableHarness.PoolSize", h.PoolSize > 0},
	)
}

// input is one input a suite requires, and whether its caller supplied it.
type input struct {
	name    string
	present bool
}

// missingInputs names the inputs that are not present, in the order given.
func missingInputs(inputs ...input) []string {
	var missing []string
	for _, in := range inputs {
		if !in.present {
			missing = append(missing, in.name)
		}
	}
	return missing
}

// failMissing fails t immediately, once, naming every missing input, and
// does nothing when none is missing.
func failMissing(t testing.TB, missing []string) {
	t.Helper()

	switch len(missing) {
	case 0:
	case 1:
		t.Fatalf("storetest: %s is required", missing[0])
	default:
		t.Fatalf("storetest: %s are required", strings.Join(missing, ", "))
	}
}

// requirePool fails t immediately when a pool of pool connections is too
// narrow for racers concurrent callers to reach the database together.
//
// Racers queueing for a connection on the client side arrive at the database
// one after another, and a read-then-write store passes a race it never ran.
//
// pool is taken on trust from DurableHarness.PoolSize: the check is only as
// good as that declaration, and over-declaring defeats it.
func requirePool(t testing.TB, pool, racers int) {
	t.Helper()

	if pool < racers {
		t.Fatalf("storetest: a pool of %d connections cannot exercise a race of %d racers", pool, racers)
	}
}

// durableCase is one case of a durable suite: a name the failure reports, and
// the check it runs.
type durableCase struct {
	name   string
	assert func(t *testing.T)
}

// runDurableCases runs each case in its own subtest, in order.
func runDurableCases(t *testing.T, cases []durableCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, tc.assert)
	}
}
