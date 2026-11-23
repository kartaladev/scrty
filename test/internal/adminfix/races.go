package adminfix

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/identity"
)

// callResult is what one concurrent call returned.
type callResult struct{ err error }

// runRetireRacesDelete checks that a password retire and a soft deletion of
// one user serialise on the user's row (D13, F76), in either order, so no
// history entry outlives the deletion. A password change reads the user, the
// policy retires the replaced hash, then the store writes the new one; a
// deletion committing in between must leave no history behind.
//
// Caller B holds one of the two operations open in its own transaction, the
// other runs concurrently and must wait for B; B then commits.
func runRetireRacesDelete(t *testing.T, h Harness) {
	t.Helper()

	hist, ok := h.Users.(password.History)
	require.True(t, ok, "the identity store implements password.History")

	type testCase struct {
		name string
		// held runs inside caller B's transaction, which stays open.
		held func(ctx context.Context, id identity.UserID, version int64) error
		// waiting runs concurrently, outside B, and must wait for B.
		waiting func(ctx context.Context, id identity.UserID, version int64) error
		assert  func(t *testing.T, waitingErr error)
	}

	retire := func(ctx context.Context, id identity.UserID, _ int64) error {
		return hist.RetirePassword(ctx, id, []byte("$old-hash"), 5)
	}
	remove := func(ctx context.Context, id identity.UserID, version int64) error {
		return h.Users.DeleteUser(ctx, id, version)
	}

	cases := []testCase{
		{
			name: "a retire waiting on a deletion finds the user deleted and records nothing",
			held: remove, waiting: retire,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"a retire for a user deleted while it waited is refused as not found")
				assert.ErrorIs(t, err, admin.ErrNotFound, "and matches the administration ports' not-found")
				noValues(t, err, "$old-hash")
			},
		},
		{
			name: "a deletion waiting on a retire removes what the retire recorded",
			held: retire, waiting: remove,
			assert: func(t *testing.T, err error) {
				require.NoError(t, err, "the deletion goes ahead once the retire commits")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			u := create(t, h, admin.NewUser{Username: uniq("retire")})

			ctxB, pidB, commitB, _ := h.Ambient(ctx, t)
			require.NoError(t, tc.held(ctxB, u.ID, u.Version))

			done := make(chan callResult, 1)
			ctxA, cancelA := context.WithTimeout(ctx, importQueueBound)
			defer cancelA()
			go func() { done <- callResult{tc.waiting(ctxA, u.ID, u.Version)} }()

			waitBlockedBy(t, h.DB, pidB, done)
			require.NoError(t, commitB())

			select {
			case r := <-done:
				tc.assert(t, r.err)
			case <-time.After(importQueueBound):
				require.Fail(t, "the waiting call never finished")
			}

			assert.Equal(t, 0, count(t, h.DB, `SELECT count(*) FROM scrty_password_history WHERE user_id = $1`,
				string(u.ID)), "a deleted user keeps no password history")
			assert.Equal(t, 1, count(t, h.DB,
				`SELECT count(*) FROM scrty_users WHERE id = $1 AND deleted_at IS NOT NULL`, string(u.ID)),
				"the user is deleted")
		})
	}
}

// runImportCollisionField checks that an import changing both the username
// and the email names the field that actually collided, when the collision is
// only seen by the database's unique index: caller B, a writer that takes none
// of the store's identifier locks (the consumer's own SQL), inserts a user
// holding the email and leaves it uncommitted, so the import's check does not
// see it and its write waits on the index. B commits, and the write fails on
// the email alone: the new username is free.
func runImportCollisionField(t *testing.T, h Harness, newImported func(t *testing.T, roles ...string) admin.ImportedUser) {
	t.Parallel()

	ctx := t.Context()
	in := newImported(t)
	out, err := h.Imports.ImportUser(ctx, in)
	require.NoError(t, err)
	require.Equal(t, admin.ImportCreated, out)

	taken := uniq("raced") + "@example.com"

	txB, err := h.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = txB.Rollback() })
	var pidB int
	require.NoError(t, txB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pidB))
	_, err = txB.ExecContext(ctx, `INSERT INTO scrty_users (id, name, username, password, role, email, created_at,
  updated_at) VALUES ($1, 'Raced', $2, '\x01', '', $3, now(), now())`, string(newID(t)), uniq("raced"), taken)
	require.NoError(t, err)

	changed := in
	changed.Username = uniq("free")
	changed.Email = taken

	done := make(chan importResult, 1)
	ctxA, cancelA := context.WithTimeout(ctx, importQueueBound)
	defer cancelA()
	go func() {
		o, err := h.Imports.ImportUser(ctxA, changed)
		done <- importResult{o, err}
	}()

	waitBlockedBy(t, h.DB, pidB, done)
	require.NoError(t, txB.Commit())

	select {
	case a := <-done:
		requireExists(t, a.err, admin.FieldEmail)
		noValues(t, a.err, changed.Username, changed.Email)
	case <-time.After(importQueueBound):
		require.Fail(t, "the waiting import never finished")
	}

	got, err := h.Users.GetUser(ctx, in.ID)
	require.NoError(t, err)
	assert.Equal(t, in.Username, got.Username, "the refused import changed nothing")
	assert.Equal(t, in.Email, got.Email, "the refused import changed nothing")
}
