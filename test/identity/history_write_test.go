package identitytest_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/password"
	identitytest "github.com/kartaladev/scrty/test/identity"
)

// TestReuseGuardChange_WriteIgnoringTimeLeavesPasswordChangedAtUnchanged pins
// the "write that ignores the time" scenario (password-encoding spec) end to
// end, over identitytest.InMemoryStore and identitytest.InMemoryHistory: a
// consumer WriteFunc that stores only the new password hash, and never names
// the changed time, must still let the change through, and must leave the
// stored password-changed-at time exactly as it was recorded before.
func TestReuseGuardChange_WriteIgnoringTimeLeavesPasswordChangedAtUnchanged(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := identitytest.NewInMemoryStore()
	history := identitytest.NewInMemoryHistory()

	recorded := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	username := "reuse-write-ignores-time"

	created, err := store.Provision(ctx, username,
		identity.WithUserPasswordChange([]byte("H1"), recorded))
	require.NoError(t, err)

	enc := fastEncoder(t)

	guard, err := password.NewReuseGuard(history, enc, 3)
	require.NoError(t, err)

	// The consumer's own write records only the hash, never the time. Ignoring
	// changedAt is not a mistake the guard refuses: it is the write that a
	// consumer storing their own users, outside the default identity store,
	// might build without thinking about password-age policy at all.
	write := func(ctx context.Context, user *identity.Details, hash []byte, _ time.Time) error {
		_, err := store.Update(ctx, user.Username, identity.WithUserPassword(hash))

		return err
	}

	const candidate = "a completely new password"

	require.NoError(t, guard.Change(ctx, created, candidate, write))

	got, err := store.LoadByUsername(ctx, username)
	require.NoError(t, err)

	// The write ran: the stored password is the candidate's new hash, and the
	// old one was retired. Without these, a write that stored nothing would
	// pass the time check below as well.
	assert.NotEqual(t, []byte("H1"), got.Password, "the write did not store a new password")
	assert.True(t, enc.Match(candidate, got.Password),
		"the stored password is not the candidate's hash")

	retired, err := history.RecentPasswords(ctx, created.ID, 10)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("H1")}, retired, "the old hash was not retired")

	assert.True(t, recorded.Equal(got.PasswordChangedAt),
		"a write that ignores the changed time must leave the stored time as it was; "+
			"want %v, got %v", recorded, got.PasswordChangedAt)
}

// fastEncoder is Argon2id at its parameter floor, to keep this test's
// derivation short: the scenario is about the write, not the encoding cost.
func fastEncoder(t *testing.T) password.Encoder {
	t.Helper()

	enc, err := password.NewArgon2idEncoder(
		password.WithArgon2idIterations(2),
		password.WithArgon2idMemory(19*1024),
		password.WithArgon2idThreads(1),
	)
	require.NoError(t, err)

	return enc
}
