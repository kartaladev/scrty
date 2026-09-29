package gormstore_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
)

// TestIdentityReuse_GuardOverStore runs the reuse guard end to end over the
// gorm store, which backs both the user and the history: a change
// made inside one caller's transaction stores the new password, the retired
// hash and the change time together, or none of them.
func TestIdentityReuse_GuardOverStore(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	store := newIdentityStore(t, d.db)

	enc, err := password.NewBcryptEncoder()
	require.NoError(t, err)

	// PostgreSQL keeps microseconds, so the fixed time is one it stores as is.
	now := time.Date(2033, 4, 5, 6, 7, 8, 123456000, time.UTC)
	guard, err := password.NewReuseGuard(store, enc, 3,
		password.WithReuseClock(clockwork.NewFakeClockAt(now)))
	require.NoError(t, err)

	write, err := password.ProvisionerWrite(store)
	require.NoError(t, err)

	type testCase struct {
		name     string
		username string
		commit   bool
		assert   func(t *testing.T, before, after *identity.Details, history [][]byte)
	}

	cases := []testCase{
		{
			name:     "a change rolled back with the caller's transaction stores nothing",
			username: "reuse-rolled-back",
			assert: func(t *testing.T, _, after *identity.Details, history [][]byte) {
				assert.True(t, enc.Match("p1", after.Password), "the password is still p1")
				assert.False(t, enc.Match("p2", after.Password))
				assert.Empty(t, history, "the retired hash rolled back with the change")
				assert.True(t, after.PasswordChangedAt.IsZero(), "the time rolled back with the change")
			},
		},
		{
			name:     "a change committed with the caller's transaction stores all three",
			username: "reuse-committed",
			commit:   true,
			assert: func(t *testing.T, before, after *identity.Details, history [][]byte) {
				assert.True(t, enc.Match("p2", after.Password), "the password is now p2")
				assert.Equal(t, [][]byte{before.Password}, history, "the history holds p1's hash")
				assert.True(t, now.Equal(after.PasswordChangedAt),
					"the time is the guard clock's: want %v, got %v", now, after.PasswordChangedAt)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			p1, err := enc.Encode("p1")
			require.NoError(t, err)
			_, err = store.Provision(ctx, tc.username, identity.WithUserPassword(p1))
			require.NoError(t, err)
			before, err := store.LoadByUsername(ctx, tc.username)
			require.NoError(t, err)

			tx := beginGorm(ctx, t, d.db)

			require.NoError(t, guard.Change(gormstore.WithTx(ctx, tx), before, "p2", write))
			if tc.commit {
				require.NoError(t, tx.Commit().Error)
			} else {
				require.NoError(t, tx.Rollback().Error)
			}

			after, err := store.LoadByUsername(ctx, tc.username)
			require.NoError(t, err)
			history, err := store.RecentPasswords(ctx, before.ID, 10)
			require.NoError(t, err)

			tc.assert(t, before, after, history)
		})
	}
}
