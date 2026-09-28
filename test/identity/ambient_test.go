package identitytest

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// This file checks RunAmbientTx itself. The in-memory store has no
// transactions, so the harnesses below model one: a transaction is a private
// copy of the committed records, and committing it copies the records it
// created or changed into the committed ones. It lives in the package, not
// beside the other self-tests, because copying the records needs the store's
// internals.

// ambientHarnessVar selects the harness the child test runs RunAmbientTx
// against, one per process, so the verdict is attributable to it alone.
const ambientHarnessVar = "SCRTY_IDENTITY_AMBIENT_HARNESS"

// The harness variants a child can run, beside "" (a correct harness) and
// "missing-<hook>" (a harness lacking that hook).
const (
	// ignoresTx names the harness whose store ignores the caller's
	// transaction: it writes straight to the committed records, and a failed
	// grant write leaves the user it already wrote.
	ignoresTx = "ignores-tx"
	// doomsTx names the harness whose failed grant write aborts the caller's
	// whole transaction, as a PostgreSQL statement failing with no savepoint
	// around it does: the caller's commit then fails and its earlier writes
	// are lost.
	doomsTx = "dooms-tx"
	// secondGrant names a correct harness whose FailGrantWrites fails only the
	// second grant of a Provision, as a consumer identifier generator that
	// repeats the first grant's identifier would. A Provision naming one role
	// is not affected.
	secondGrant = "second-grant"
)

var (
	errGrantWrite = errors.New("identitytest: grant write failed")
	errTxAborted  = errors.New("identitytest: transaction is aborted, commands ignored until end of block")
)

type txKey struct{}

// memDB is the committed state several harnesses share, as several fixtures
// share one database.
type memDB struct {
	mu        sync.Mutex
	committed *InMemoryStore
	unrelated map[string]bool
}

func newMemDB() *memDB {
	return &memDB{committed: NewInMemoryStore(), unrelated: make(map[string]bool)}
}

// memTx is one caller-owned transaction over a private copy of the records.
type memTx struct {
	store *InMemoryStore
	// begun is the records as the transaction first saw them, so the commit
	// can tell what the transaction wrote from what it only carried.
	begun     *InMemoryStore
	unrelated map[string]bool
	doomed    bool
}

// memAmbientHarness implements AmbientHarness over the in-memory store.
type memAmbientHarness struct {
	variant string
	db      *memDB
	// base is this harness's view of the committed records, with fault hooks
	// of its own, so a fault one case injects stays with that case.
	base *InMemoryStore

	mu         sync.Mutex
	failGrants bool
}

func newMemAmbientHarness(variant string) *memAmbientHarness {
	return newMemAmbientHarnessOn(newMemDB(), variant)
}

func newMemAmbientHarnessOn(db *memDB, variant string) *memAmbientHarness {
	return &memAmbientHarness{variant: variant, db: db, base: db.committed.Share()}
}

func (h *memAmbientHarness) lacks(hook string) bool { return h.variant == "missing-"+hook }

func (h *memAmbientHarness) tx(ctx context.Context) *memTx {
	if h.variant == ignoresTx {
		return nil
	}

	tx, _ := ctx.Value(txKey{}).(*memTx)

	return tx
}

// store returns the records a call made with ctx reads and writes.
func (h *memAmbientHarness) store(ctx context.Context) *InMemoryStore {
	if tx := h.tx(ctx); tx != nil {
		return tx.store
	}

	return h.base
}

func (h *memAmbientHarness) Begin(
	ctx context.Context,
) (context.Context, func() error, func() error, error) {
	if h.lacks("Begin") {
		return nil, nil, nil, ErrHookUnsupported
	}

	if h.variant == ignoresTx {
		noop := func() error { return nil }

		return ctx, noop, noop, nil
	}

	store := h.db.committed.copyRecords()
	tx := &memTx{store: store, begun: store.copyRecords(), unrelated: make(map[string]bool)}

	commit := func() error {
		if tx.doomed {
			return errTxAborted
		}

		h.db.committed.applyWrites(tx.store, tx.begun)

		h.db.mu.Lock()
		defer h.db.mu.Unlock()

		for k := range tx.unrelated {
			h.db.unrelated[k] = true
		}

		return nil
	}
	rollback := func() error { return nil }

	return context.WithValue(ctx, txKey{}, tx), commit, rollback, nil
}

func (h *memAmbientHarness) WriteUnrelated(txCtx context.Context, key string) error {
	if h.lacks("WriteUnrelated") {
		return ErrHookUnsupported
	}

	if tx := h.tx(txCtx); tx != nil {
		tx.unrelated[key] = true

		return nil
	}

	h.db.mu.Lock()
	defer h.db.mu.Unlock()

	h.db.unrelated[key] = true

	return nil
}

func (h *memAmbientHarness) UnrelatedStored(_ context.Context, key string) (bool, error) {
	if h.lacks("UnrelatedStored") {
		return false, ErrHookUnsupported
	}

	h.db.mu.Lock()
	defer h.db.mu.Unlock()

	return h.db.unrelated[key], nil
}

func (h *memAmbientHarness) FailGrantWrites() {
	if h.lacks("FailGrantWrites") {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.failGrants = true
}

// Provision fails partway when FailGrantWrites asked it to. A store honouring
// the transaction undoes its own writes, as a savepoint would; one ignoring it
// has already written the user when the grant write fails; one with no
// savepoint dooms the caller's transaction.
func (h *memAmbientHarness) Provision(
	ctx context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	grants := len(identity.ApplyUserOptions(opts...).Roles)

	h.mu.Lock()
	fail := h.failGrants && (h.variant != secondGrant || grants >= 2)
	if fail {
		h.failGrants = false
	}
	h.mu.Unlock()

	if !fail {
		return h.store(ctx).Provision(ctx, username, opts...)
	}

	switch tx := h.tx(ctx); {
	case h.variant == ignoresTx:
		_, _ = h.store(ctx).Provision(ctx, username, opts...)
	case h.variant == doomsTx && tx != nil:
		tx.doomed = true
	}

	return nil, errGrantWrite
}

func (h *memAmbientHarness) Update(
	ctx context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	return h.store(ctx).Update(ctx, username, opts...)
}

func (h *memAmbientHarness) LoadByUsername(ctx context.Context, username string) (*identity.Details, error) {
	return h.store(ctx).LoadByUsername(ctx, username)
}

func (h *memAmbientHarness) LoadByUserID(ctx context.Context, id identity.UserID) (*identity.Details, error) {
	return h.store(ctx).LoadByUserID(ctx, id)
}

func (h *memAmbientHarness) LoadPrivileges(
	ctx context.Context, role string,
) ([]*identity.ResourcePrivileges, error) {
	return h.store(ctx).LoadPrivileges(ctx, role)
}

func (h *memAmbientHarness) Required(ctx context.Context, id identity.UserID) (bool, error) {
	return h.store(ctx).Required(ctx, id)
}

func (h *memAmbientHarness) SeedRole(
	ctx context.Context, role string, p []*identity.ResourcePrivileges,
) error {
	return h.store(ctx).SeedRole(ctx, role, p)
}

func (h *memAmbientHarness) SeedMFARequired(ctx context.Context, id identity.UserID, required bool) error {
	return h.store(ctx).SeedMFARequired(ctx, id, required)
}

func (h *memAmbientHarness) SeedRoleGrants(
	ctx context.Context, username string, grants []*identity.AssignedRole,
) error {
	return h.store(ctx).SeedRoleGrants(ctx, username, grants)
}

func (h *memAmbientHarness) SeedOrganization(ctx context.Context, org *identity.Organization) error {
	return h.store(ctx).SeedOrganization(ctx, org)
}

func (h *memAmbientHarness) FailUserLoads(err error) { h.base.FailUserLoads(err) }

func (h *memAmbientHarness) FailMFALookups(err error) { h.base.FailMFALookups(err) }

var _ AmbientHarness = (*memAmbientHarness)(nil)

// copyRecords returns a store holding a deep copy of s's records.
func (s *InMemoryStore) copyRecords() *InMemoryStore {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := NewInMemoryStore()
	c.seq = s.seq

	for k, d := range s.byName {
		c.byName[k] = cloneDetails(d)
	}

	for k, p := range s.privs {
		c.privs[k] = clonePrivileges(p)
	}

	for k, v := range s.mfa {
		c.mfa[k] = v
	}

	for k, o := range s.orgs {
		c.orgs[k] = cloneOrg(o)
	}

	return c
}

// applyWrites is the commit of the model: it copies into s every record of
// from that the transaction created or changed, judged against begun, the
// records as the transaction first saw them. The ambient part creates and
// updates records inside a transaction but never deletes one, so this carries
// every write the transaction made, and leaves the records it only carried as
// other harnesses committed them meanwhile.
func (s *InMemoryStore) applyWrites(from, begun *InMemoryStore) {
	from.mu.Lock()
	defer from.mu.Unlock()

	begun.mu.Lock()
	defer begun.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, d := range from.byName {
		if prev, ok := begun.byName[k]; !ok || !reflect.DeepEqual(prev, d) {
			s.byName[k] = cloneDetails(d)
		}
	}

	for k, p := range from.privs {
		if prev, ok := begun.privs[k]; !ok || !reflect.DeepEqual(prev, p) {
			s.privs[k] = clonePrivileges(p)
		}
	}

	for k, v := range from.mfa {
		if prev, ok := begun.mfa[k]; !ok || prev != v {
			s.mfa[k] = v
		}
	}

	for k, o := range from.orgs {
		if prev, ok := begun.orgs[k]; !ok || !reflect.DeepEqual(prev, o) {
			s.orgs[k] = cloneOrg(o)
		}
	}
}

// TestMemAmbientHarness_TransactionAndCommittedMintDistinctIDs checks the model
// itself: a user created inside a transaction and one created outside it while
// it is open never share an identifier, as two rows drawing on one database
// sequence never do. Were they to share one, a lookup by reference outside the
// transaction would find the committed user and read the uncommitted one as
// stored.
func TestMemAmbientHarness_TransactionAndCommittedMintDistinctIDs(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	h := newMemAmbientHarness("")

	txCtx, _, rollback, err := h.Begin(ctx)
	require.NoError(t, err)

	defer func() { _ = rollback() }()

	outside, err := h.Provision(ctx, "outside", identity.WithUserRoles("admin"))
	require.NoError(t, err)

	inside, err := h.Provision(txCtx, "inside", identity.WithUserRoles("admin"))
	require.NoError(t, err)

	assert.NotEqual(t, outside.ID, inside.ID, "the two users share an identifier")
	assert.NotEqual(t, outside.Roles[0].ID, inside.Roles[0].ID, "the two grants share an identifier")
}

// TestMemAmbientHarness_CommitKeepsAnUpdate checks the model's commit: an
// update made inside a transaction to a user committed before it began is
// stored once the transaction commits, as a database commit would store it.
func TestMemAmbientHarness_CommitKeepsAnUpdate(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	h := newMemAmbientHarness("")

	_, err := h.Provision(ctx, "updated-in-tx", identity.WithUserName("Before"))
	require.NoError(t, err)

	txCtx, commit, rollback, err := h.Begin(ctx)
	require.NoError(t, err)

	defer func() { _ = rollback() }()

	_, err = h.Update(txCtx, "updated-in-tx", identity.WithUserName("After"))
	require.NoError(t, err)
	require.NoError(t, commit())

	got, err := h.LoadByUsername(ctx, "updated-in-tx")
	require.NoError(t, err)
	assert.Equal(t, "After", got.Name, "the commit dropped an update made inside the transaction")
}

// TestRunAmbientTx_ConformingHarnessesPass runs the ambient part against
// harnesses whose store honours the caller's transaction. A suite that failed
// them would be proving nothing about the harnesses below that break it.
func TestRunAmbientTx_ConformingHarnessesPass(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		variant string
	}

	cases := []testCase{
		{name: "a transactional harness", variant: ""},
		{
			// FailGrantWrites promises a failure after the user row is written,
			// not a failure of the first grant; the preflight must accept a
			// harness that fails the second.
			name:    "a harness that fails only the second grant",
			variant: secondGrant,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			RunAmbientTx(t, func(t *testing.T) AmbientHarness {
				t.Helper()

				return newMemAmbientHarness(tc.variant)
			})
		})
	}
}

// TestSuiteParts_ConformanceThenAmbientOverOneStore runs the conformance suite
// and then the ambient part under one *testing.T over one shared store, as an
// adapter's test does over one database. Each part runs its own preflight, and
// the second must not meet the first one's probe.
func TestSuiteParts_ConformanceThenAmbientOverOneStore(t *testing.T) {
	t.Parallel()

	db := newMemDB()

	RunConformanceSuite(t, func(t *testing.T) Fixture {
		t.Helper()

		return newMemAmbientHarnessOn(db, "")
	})
	RunAmbientTx(t, func(t *testing.T) AmbientHarness {
		t.Helper()

		return newMemAmbientHarnessOn(db, "")
	})
}

// TestAmbientHarnessChild runs the ambient part against the harness named by the
// environment, and is the child half of TestRunAmbientTx_IsLoadBearing.
func TestAmbientHarnessChild(t *testing.T) {
	variant, named := os.LookupEnv(ambientHarnessVar)
	if !named {
		t.Skipf("no harness named in %s; run through TestRunAmbientTx_IsLoadBearing", ambientHarnessVar)
	}

	RunAmbientTx(t, func(t *testing.T) AmbientHarness {
		t.Helper()

		return newMemAmbientHarness(variant)
	})
}

// TestRunAmbientTx_RequiresEveryHook checks that a harness lacking a hook the
// ambient part adds fails the run before any case, naming the hook.
func TestRunAmbientTx_RequiresEveryHook(t *testing.T) {
	t.Parallel()

	for _, hook := range []string{"Begin", "WriteUnrelated", "UnrelatedStored", "FailGrantWrites"} {
		t.Run(hook, func(t *testing.T) {
			t.Parallel()

			output, err := runAmbientChild(t, "missing-"+hook, "-test.v")

			require.Error(t, err, "a harness without %s passed the ambient part", hook)
			assert.True(t, strings.Contains(output, "identitytest: required hook "+hook+" is missing"),
				"the failure must name the missing hook %s", hook)
			assert.Zero(t, strings.Count(output, "=== RUN   TestAmbientHarnessChild/"),
				"cases ran although the required hook %s was missing", hook)
		})
	}
}

// runAmbientChild re-executes this test binary, running only the child test
// against the harness named, and returns its combined output.
func runAmbientChild(t *testing.T, harness string, flags ...string) (string, error) {
	t.Helper()

	args := append([]string{
		"-test.run=^TestAmbientHarnessChild$", "-test.count=1", "-test.timeout=5m",
	}, flags...)

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)
	cmd.Env = append(os.Environ(), ambientHarnessVar+"="+harness)

	out, err := cmd.CombinedOutput()
	require.NotContains(t, string(out), "--- SKIP", "the child skipped, so nothing was checked")

	return string(out), err
}

// TestRunAmbientTx_IsLoadBearing checks that the ambient part fails, by the
// named case's assertion, against each harness that breaks the caller's
// transaction.
func TestRunAmbientTx_IsLoadBearing(t *testing.T) {
	t.Parallel()

	const (
		seenInside   = "rows_written_inside_the_transaction_are_seen_only_through_its_context"
		failedUsable = "a_failed_provision_leaves_the_transaction_usable_and_its_earlier_writes_intact"
		rolledBack   = "a_rollback_takes_the_provisioned_user_with_it"
		updateUndone = "a_rollback_undoes_an_update_made_inside_the_transaction"
	)

	type testCase struct {
		name    string
		variant string
		// catching lists the cases that must each fail against the harness.
		catching []string
	}

	cases := []testCase{
		{
			name:     "a store that ignores the caller's transaction",
			variant:  ignoresTx,
			catching: []string{seenInside, failedUsable, rolledBack, updateUndone},
		},
		{
			name:     "a store whose failure dooms the caller's transaction",
			variant:  doomsTx,
			catching: []string{failedUsable},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runAmbientChild(t, tc.variant)

			require.Error(t, err, "the ambient part passed %s", tc.name)
			assert.NotContains(t, output, "identitytest: required hook",
				"the preflight stopped the run, so no case was shown to catch %s:\n%s", tc.name, output)

			for _, c := range tc.catching {
				assert.True(t, strings.Contains(output, "--- FAIL: TestAmbientHarnessChild/"+c),
					"case %q passed %s:\n%s", c, tc.name, output)
			}
		})
	}
}
