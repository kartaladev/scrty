package identitytest

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// AmbientHarness is what the ambient-transaction part of the suite needs beyond
// a Fixture: a way to begin a transaction the caller owns, a table outside the
// identity ports to write to inside it, and a fault that makes a grant write
// fail partway through a Provision.
//
// Every hook is required, as on Fixture. The seeding hooks of the embedded
// Fixture must write through the transaction the context carries, as the ports
// do, so that state seeded inside a transaction is as uncommitted as state
// provisioned there.
type AmbientHarness interface {
	Fixture

	// Begin starts a transaction owned by the caller, not by the store, and
	// returns a context carrying it with the functions that commit and roll it
	// back. The store under test must see the transaction through that context,
	// either directly or through a transaction resolver the consumer configured
	// it with — which is how a consumer with their own transaction manager
	// proves the store joins it. A harness that cannot begin one returns
	// ErrHookUnsupported, which fails the run.
	//
	// The suite also calls rollback when a case ends, so that a failed case
	// leaves no transaction open; rollback must therefore tolerate being called
	// after commit or a first rollback, and the suite ignores its error then.
	Begin(ctx context.Context) (txCtx context.Context, commit, rollback func() error, err error)

	// WriteUnrelated writes one row keyed by key, outside every identity table,
	// inside the transaction txCtx carries. It stands in for the caller's own
	// work in the same transaction.
	WriteUnrelated(txCtx context.Context, key string) error

	// UnrelatedStored reports whether the row WriteUnrelated wrote under key is
	// stored, read outside any transaction.
	UnrelatedStored(ctx context.Context, key string) (bool, error)

	// FailGrantWrites makes the next Provision that names two or more roles
	// fail while writing its role grants, after the user row was written. The
	// suite provisions two roles after setting it, so a harness may fail the
	// first grant or the second.
	//
	// The failure must be a statement the backend itself refuses, inside the
	// store's own work — not an error returned from a wrapper before the
	// statement runs. That is what the case after it tests: on PostgreSQL a
	// refused statement aborts the whole transaction, so a store with no
	// savepoint around its own writes turns the caller's commit into a rollback
	// of the caller's earlier work. A failure the backend never saw leaves the
	// transaction healthy, and such a store would pass.
	//
	// The recommended way is the store's own identifier generator: configure
	// the store under test with a generator that, once FailGrantWrites is set,
	// repeats an identifier it has already issued, so the second grant's insert
	// is refused with a primary-key violation. Do not use a trigger on the grant
	// table: it fails every fixture over the same database at once, while the
	// suite runs its cases in parallel over one database and a fault must stay
	// with the harness it was set on.
	//
	// An adapter that joins a caller's transaction both through its own context
	// value and through a consumer transaction resolver runs RunAmbientTx once
	// for each: once with Begin placing the transaction where the adapter's
	// WithTx does, and once through a store configured with a resolver that
	// returns the consumer's own transaction handle.
	FailGrantWrites()
}

// RunAmbientTx checks that an implementation takes part in the caller's
// transaction: its reads see what the transaction wrote, a Provision that fails
// inside it undoes only its own writes and leaves the transaction usable, and a
// rollback takes the store's writes with it, an Update's as well as a
// Provision's.
//
// It is a separate part from RunConformanceSuite because a consumer's store may
// have no notion of an ambient transaction; one that has must pass it.
//
// Like RunConformanceSuite, it fails before any case when a hook is missing,
// including Begin and FailGrantWrites. Every name it uses is unique to its case
// and to the run, so the factory may hand every case a harness over one shared
// database, including one that outlives the run.
func RunAmbientTx(t *testing.T, newHarness func(t *testing.T) AmbientHarness) {
	t.Helper()

	require.NotNil(t, newHarness, "the ambient part needs a factory to build the harness under test")

	h := newHarness(t)
	require.NotNil(t, h, "the factory returned no harness, so no contract can be checked")

	requireEveryAmbientHook(t, h)
	requireEveryHook(t, newHarness(t))

	type testCase struct {
		name string
		// act works inside and around a caller-owned transaction, checking what
		// it must see while that transaction is open.
		act func(t *testing.T, ctx context.Context, h AmbientHarness, user, key string)
		// assert checks what is stored once the transaction is over.
		assert func(t *testing.T, ctx context.Context, h AmbientHarness, user, key string)
	}

	cases := []testCase{
		{
			name: "rows written inside the transaction are seen only through its context",
			act: func(t *testing.T, ctx context.Context, h AmbientHarness, user, _ string) {
				t.Helper()

				txCtx, _, rollback := begin(ctx, t, h)
				role := user + "-role"

				created, err := h.Provision(txCtx, user, identity.WithUserRoles(role))
				require.NoError(t, err)
				require.NoError(t, h.SeedRole(txCtx, role, []*identity.ResourcePrivileges{{
					Group: "billing", Resource: "invoice",
					Privileges: []identity.Privilege{{Name: "read", Granted: true}},
				}}))
				require.NoError(t, h.SeedMFARequired(txCtx, created.ID, true))

				inside, err := h.LoadByUsername(txCtx, user)
				require.NoError(t, err, "the loader must read through the caller's transaction")
				require.Len(t, inside.Roles, 1)
				assert.Equal(t, role, inside.Roles[0].Name)

				privs, err := h.LoadPrivileges(txCtx, role)
				require.NoError(t, err, "the role loader must read through the caller's transaction")
				assert.Len(t, privs, 1)

				required, err := h.Required(txCtx, created.ID)
				require.NoError(t, err, "the lookup must read through the caller's transaction")
				assert.True(t, required)

				assertNotStored(ctx, t, h, user, role, created.ID,
					"an uncommitted write was visible outside the caller's transaction")

				require.NoError(t, rollback())
			},
			assert: func(t *testing.T, ctx context.Context, h AmbientHarness, user, _ string) {
				t.Helper()

				_, err := h.LoadByUsername(ctx, user)
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "a failed provision leaves the transaction usable and its earlier writes intact",
			act: func(t *testing.T, ctx context.Context, h AmbientHarness, user, key string) {
				t.Helper()

				txCtx, commit, _ := begin(ctx, t, h)
				require.NoError(t, h.WriteUnrelated(txCtx, key))

				h.FailGrantWrites()

				_, err := h.Provision(txCtx, user, identity.WithUserRoles("admin", "viewer"))
				require.Error(t, err, "FailGrantWrites made the grant write fail, so Provision must too")

				require.NoError(t, commit(),
					"a store's own failure must not doom the caller's transaction")
			},
			assert: func(t *testing.T, ctx context.Context, h AmbientHarness, user, key string) {
				t.Helper()

				stored, err := h.UnrelatedStored(ctx, key)
				require.NoError(t, err)
				assert.True(t, stored,
					"the caller's own write, made before the failed provision, was lost with it")

				_, err = h.LoadByUsername(ctx, user)
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"a failed provision left part of its user behind")
			},
		},
		{
			name: "a rollback takes the provisioned user with it",
			act: func(t *testing.T, ctx context.Context, h AmbientHarness, user, _ string) {
				t.Helper()

				txCtx, _, rollback := begin(ctx, t, h)

				_, err := h.Provision(txCtx, user, identity.WithUserRoles("admin"))
				require.NoError(t, err)
				require.NoError(t, rollback())
			},
			assert: func(t *testing.T, ctx context.Context, h AmbientHarness, user, _ string) {
				t.Helper()

				_, err := h.LoadByUsername(ctx, user)
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"the store wrote outside the transaction the caller rolled back")
			},
		},
		{
			name: "a rollback undoes an update made inside the transaction",
			act: func(t *testing.T, ctx context.Context, h AmbientHarness, user, _ string) {
				t.Helper()

				// Stored before the transaction, so only the update is the
				// transaction's own work.
				_, err := h.Provision(ctx, user, identity.WithUserName("Before"), identity.WithUserRoles("admin"))
				require.NoError(t, err)

				txCtx, _, rollback := begin(ctx, t, h)

				_, err = h.Update(txCtx, user, identity.WithUserName("After"), identity.WithUserRoles("viewer"))
				require.NoError(t, err)

				inside, err := h.LoadByUsername(txCtx, user)
				require.NoError(t, err)
				assert.Equal(t, "After", inside.Name,
					"the update must be visible through the caller's transaction")

				outside, err := h.LoadByUsername(ctx, user)
				require.NoError(t, err)
				assert.Equal(t, "Before", outside.Name,
					"an uncommitted update was visible outside the caller's transaction")

				require.NoError(t, rollback())
			},
			assert: func(t *testing.T, ctx context.Context, h AmbientHarness, user, _ string) {
				t.Helper()

				d, err := h.LoadByUsername(ctx, user)
				require.NoError(t, err)
				assert.Equal(t, "Before", d.Name,
					"the store wrote the update outside the transaction the caller rolled back")
				require.Len(t, d.Roles, 1, "and the grants it rebuilt stay rolled back with it")
				assert.Equal(t, "admin", d.Roles[0].Name)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			h := newHarness(t)
			user := uniqueName(t, "ambient", i)
			key := uniqueName(t, "unrelated", i)

			tc.act(t, ctx, h, user, key)
			tc.assert(t, ctx, h, user, key)
		})
	}
}

// begin starts a caller-owned transaction, failing the case if it cannot.
func begin(
	ctx context.Context, t *testing.T, h AmbientHarness,
) (txCtx context.Context, commit, rollback func() error) {
	t.Helper()

	txCtx, commit, rollback, err := h.Begin(ctx)
	require.NoError(t, err)
	require.NotNil(t, txCtx)

	// Whatever the case does, the transaction does not outlive it. After a
	// commit or an explicit rollback this is a no-op whose error is irrelevant.
	t.Cleanup(func() { _ = rollback() })

	return txCtx, commit, rollback
}

// assertNotStored checks that nothing of an uncommitted user is visible through
// ctx: the user, its role's privileges, and its MFA requirement. Outside the
// transaction the user is unknown, so the MFA lookup must refuse it as not
// found: answering "not required" or "required" would both read a user that
// does not exist.
func assertNotStored(
	ctx context.Context, t *testing.T, h AmbientHarness,
	user, role string, id identity.UserID, msg string,
) {
	t.Helper()

	_, err := h.LoadByUsername(ctx, user)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, msg)

	_, err = h.LoadPrivileges(ctx, role)
	assert.ErrorIs(t, err, identity.ErrPrivilegesNotFound, msg)

	required, err := h.Required(ctx, id)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, msg)
	assert.False(t, required, msg)
}

// requireEveryAmbientHook probes the hooks AmbientHarness adds to Fixture, and
// fails the run naming each one that is missing. Begin and the unrelated-row
// hooks are missing when they answer ErrHookUnsupported; FailGrantWrites is
// missing when a Provision of two roles after it succeeds.
func requireEveryAmbientHook(t *testing.T, h AmbientHarness) {
	t.Helper()

	missing := func(name string, err error) {
		t.Helper()

		switch {
		case errors.Is(err, ErrHookUnsupported):
			t.Errorf("identitytest: required hook %s is missing", name)
		case err != nil:
			t.Errorf("identitytest: required hook %s failed on the preflight probe: %v", name, err)
		}
	}

	ctx := t.Context()

	txCtx, _, rollback, err := h.Begin(ctx)
	if err != nil {
		missing("Begin", err)
		t.FailNow()
	}

	// Fresh on every call, as in requireEveryHook: two parts under one
	// *testing.T over one database must not meet each other's probe.
	key := probeName(t, "ambprobe", rand.Text())
	missing("WriteUnrelated", h.WriteUnrelated(txCtx, key))

	_, err = h.UnrelatedStored(ctx, key)
	missing("UnrelatedStored", err)

	h.FailGrantWrites()

	// Two roles, as the case that relies on the fault provisions: a harness may
	// fail the second grant rather than the first.
	if _, err := h.Provision(txCtx, key, identity.WithUserRoles("probe", "probe-second")); err == nil {
		t.Errorf("identitytest: required hook FailGrantWrites is missing")
	}

	if rollback != nil {
		missing("Begin", rollback())
	}

	if t.Failed() {
		t.FailNow()
	}
}
