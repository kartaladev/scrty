package identitytest

import (
	"context"
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

	// FailGrantWrites makes the next Provision fail while writing its role
	// grants, after the user itself was written. It needs no backend support: a
	// harness can wrap the store's grant write, or fail on the grant table with a
	// trigger, so long as the failure happens inside the store's own work.
	FailGrantWrites()
}

// RunAmbientTx checks that an implementation takes part in the caller's
// transaction: its reads see what the transaction wrote, a Provision that fails
// inside it undoes only its own writes and leaves the transaction usable, and a
// rollback takes the store's writes with it.
//
// It is a separate part from RunConformanceSuite because a consumer's store may
// have no notion of an ambient transaction; one that has must pass it.
//
// Like RunConformanceSuite, it fails before any case when a hook is missing,
// including Begin and FailGrantWrites. Every name it uses is unique to its case,
// so the factory may hand every case a harness over one shared database.
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

				txCtx, _, rollback := begin(t, ctx, h)
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

				assertNotStored(t, ctx, h, user, role, created.ID,
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

				txCtx, commit, _ := begin(t, ctx, h)
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

				txCtx, _, rollback := begin(t, ctx, h)

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
	t *testing.T, ctx context.Context, h AmbientHarness,
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
// ctx: the user, its role's privileges, and its MFA requirement. An unknown user
// may be answered as not required or as not found, never as required.
func assertNotStored(
	t *testing.T, ctx context.Context, h AmbientHarness,
	user, role string, id identity.UserID, msg string,
) {
	t.Helper()

	_, err := h.LoadByUsername(ctx, user)
	assert.ErrorIs(t, err, identity.ErrUserNotFound, msg)

	_, err = h.LoadPrivileges(ctx, role)
	assert.ErrorIs(t, err, identity.ErrPrivilegesNotFound, msg)

	required, err := h.Required(ctx, id)
	if err != nil {
		assert.ErrorIs(t, err, identity.ErrUserNotFound, msg)
	}

	assert.False(t, required, msg)
}

// requireEveryAmbientHook probes the hooks AmbientHarness adds to Fixture, and
// fails the run naming each one that is missing. Begin and the unrelated-row
// hooks are missing when they answer ErrHookUnsupported; FailGrantWrites is
// missing when the Provision after it succeeds.
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

	key := uniqueName(t, "ambprobe", 0)
	missing("WriteUnrelated", h.WriteUnrelated(txCtx, key))

	_, err = h.UnrelatedStored(ctx, key)
	missing("UnrelatedStored", err)

	h.FailGrantWrites()

	if _, err := h.Provision(txCtx, key, identity.WithUserRoles("probe")); err == nil {
		t.Errorf("identitytest: required hook FailGrantWrites is missing")
	}

	if rollback != nil {
		missing("Begin", rollback())
	}

	if t.Failed() {
		t.FailNow()
	}
}
