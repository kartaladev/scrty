package identitytest

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// This file checks RunAmbientTx itself. The in-memory store has no
// transactions, so the harnesses below model one: a transaction is a private
// copy of the committed records, and committing it replaces them. It lives in
// the package, not beside the other self-tests, because copying the records
// needs the store's internals.

// ambientHarnessVar selects the harness the child test runs RunAmbientTx
// against, one per process, so the verdict is attributable to it alone.
const ambientHarnessVar = "SCRTY_IDENTITY_AMBIENT_HARNESS"

// ignoresTx names the harness whose store ignores the caller's transaction: it
// writes straight to the committed records, and a failed grant write leaves the
// user it already wrote.
const ignoresTx = "ignores-tx"

var errGrantWrite = errors.New("identitytest: grant write failed")

type txKey struct{}

// memTx is one caller-owned transaction over a private copy of the records.
type memTx struct {
	store     *InMemoryStore
	unrelated map[string]bool
}

// memAmbientHarness implements AmbientHarness over the in-memory store.
type memAmbientHarness struct {
	ignoresTx bool
	// missing names a hook this harness lacks: Begin answers
	// ErrHookUnsupported, FailGrantWrites does nothing.
	missing string

	mu         sync.Mutex
	committed  *InMemoryStore
	unrelated  map[string]bool
	failGrants bool
}

func newMemAmbientHarness(ignores bool) *memAmbientHarness {
	return newMemAmbientHarnessLacking(ignores, "")
}

func newMemAmbientHarnessLacking(ignores bool, missing string) *memAmbientHarness {
	return &memAmbientHarness{
		ignoresTx: ignores,
		missing:   missing,
		committed: NewInMemoryStore(),
		unrelated: make(map[string]bool),
	}
}

func (h *memAmbientHarness) tx(ctx context.Context) *memTx {
	if h.ignoresTx {
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

	h.mu.Lock()
	defer h.mu.Unlock()

	return h.committed
}

func (h *memAmbientHarness) Begin(
	ctx context.Context,
) (context.Context, func() error, func() error, error) {
	if h.missing == "Begin" {
		return nil, nil, nil, ErrHookUnsupported
	}

	if h.ignoresTx {
		noop := func() error { return nil }

		return ctx, noop, noop, nil
	}

	h.mu.Lock()
	tx := &memTx{store: h.committed.copyRecords(), unrelated: make(map[string]bool)}
	h.mu.Unlock()

	commit := func() error {
		h.mu.Lock()
		defer h.mu.Unlock()

		h.committed = tx.store
		for k := range tx.unrelated {
			h.unrelated[k] = true
		}

		return nil
	}
	rollback := func() error { return nil }

	return context.WithValue(ctx, txKey{}, tx), commit, rollback, nil
}

func (h *memAmbientHarness) WriteUnrelated(txCtx context.Context, key string) error {
	if tx := h.tx(txCtx); tx != nil {
		tx.unrelated[key] = true

		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.unrelated[key] = true

	return nil
}

func (h *memAmbientHarness) UnrelatedStored(_ context.Context, key string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.unrelated[key], nil
}

func (h *memAmbientHarness) FailGrantWrites() {
	if h.missing == "FailGrantWrites" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.failGrants = true
}

// Provision fails partway when FailGrantWrites asked it to. A store honouring
// the transaction undoes its own writes, as a savepoint would; one ignoring it
// has already written the user when the grant write fails.
func (h *memAmbientHarness) Provision(
	ctx context.Context, username string, opts ...identity.UserOption,
) (*identity.Details, error) {
	h.mu.Lock()
	fail := h.failGrants
	h.failGrants = false
	h.mu.Unlock()

	if fail {
		if h.ignoresTx {
			_, _ = h.store(ctx).Provision(ctx, username, opts...)
		}

		return nil, errGrantWrite
	}

	return h.store(ctx).Provision(ctx, username, opts...)
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

func (h *memAmbientHarness) FailUserLoads(err error) {
	h.store(context.Background()).FailUserLoads(err)
}

func (h *memAmbientHarness) FailMFALookups(err error) {
	h.store(context.Background()).FailMFALookups(err)
}

var _ AmbientHarness = (*memAmbientHarness)(nil)

// copyRecords returns a store holding a deep copy of s's records.
func (s *InMemoryStore) copyRecords() *InMemoryStore {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := NewInMemoryStore()
	c.nextID = s.nextID

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

// TestRunAmbientTx_TransactionalHarnessPasses runs the ambient part against a
// harness whose store honours the caller's transaction. A suite that failed it
// would be proving nothing about the harness below that ignores one.
func TestRunAmbientTx_TransactionalHarnessPasses(t *testing.T) {
	t.Parallel()

	RunAmbientTx(t, func(t *testing.T) AmbientHarness {
		t.Helper()

		return newMemAmbientHarness(false)
	})
}

// TestAmbientHarnessChild runs the ambient part against the harness named by the
// environment, and is the child half of TestRunAmbientTx_IsLoadBearing.
func TestAmbientHarnessChild(t *testing.T) {
	name, named := os.LookupEnv(ambientHarnessVar)
	if !named {
		t.Skipf("no harness named in %s; run through TestRunAmbientTx_IsLoadBearing", ambientHarnessVar)
	}

	RunAmbientTx(t, func(t *testing.T) AmbientHarness {
		t.Helper()

		return newMemAmbientHarnessLacking(name == ignoresTx, strings.TrimPrefix(name, "missing-"))
	})
}

// TestRunAmbientTx_RequiresEveryHook checks that a harness lacking a hook the
// ambient part adds fails the run before any case, naming the hook.
func TestRunAmbientTx_RequiresEveryHook(t *testing.T) {
	t.Parallel()

	for _, hook := range []string{"Begin", "FailGrantWrites"} {
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

// TestRunAmbientTx_IsLoadBearing checks that each case of the ambient part fails
// against a store that ignores the caller's transaction.
func TestRunAmbientTx_IsLoadBearing(t *testing.T) {
	t.Parallel()

	output, err := runAmbientChild(t, ignoresTx)

	require.Error(t, err, "the ambient part passed a store that ignores the caller's transaction")

	for _, c := range []string{
		"rows_written_inside_the_transaction_are_seen_only_through_its_context",
		"a_failed_provision_leaves_the_transaction_usable_and_its_earlier_writes_intact",
		"a_rollback_takes_the_provisioned_user_with_it",
	} {
		assert.True(t, strings.Contains(output, "--- FAIL: TestAmbientHarnessChild/"+c),
			"case %q passed a store that ignores the caller's transaction", c)
	}
}
