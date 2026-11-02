package identitytest

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// runConditionalPasswordCases checks an update made conditional on the stored
// password hash (identity.WithUserPasswordIf).
//
// The library's ready-made rehash write relies on it: a login that verified
// the old password can finish after a password change stored a new hash, and
// writing the re-encoded old password then would undo the change. A store that
// ignores the condition puts the old password back; one that reports the miss
// as a storage failure or as an unknown user makes the caller log an outage
// that did not happen.
func runConditionalPasswordCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name string
		// arrange prepares user and returns the username the update names.
		arrange func(t *testing.T, ctx context.Context, f Fixture, user string) string
		opts    []identity.UserOption
		assert  func(t *testing.T, ctx context.Context, f Fixture, user string, got *identity.Details, err error)
	}

	isNotUpdated := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err, "an update conditional on a hash that is no longer stored must not succeed")
		assert.ErrorIs(t, err, identity.ErrNotUpdated,
			"a stored hash that changed meanwhile is reported as not-updated, so the caller can tell "+
				"it from a storage failure")
		assert.NotErrorIs(t, err, identity.ErrUserNotFound,
			"the user is there; reporting it missing would read as a deleted account")
	}

	cases := []testCase{
		{
			name: "hash unchanged is replaced",
			arrange: func(t *testing.T, ctx context.Context, f Fixture, user string) string {
				mustProvision(ctx, t, f, user, identity.WithUserPasswordChange([]byte("H1"), passwordChangedAt))
				return user
			},
			opts: []identity.UserOption{
				identity.WithUserPasswordIf([]byte("H1")),
				identity.WithUserPassword([]byte("H2")),
			},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, got *identity.Details, err error) {
				require.NoError(t, err, "the stored hash was the expected one, so the update must write")
				require.NotNil(t, got)
				assert.Equal(t, []byte("H2"), got.Password)

				stored := mustLoad(ctx, t, f, user)
				assert.Equal(t, []byte("H2"), stored.Password,
					"the conditional update reported success but did not store the new hash")
				assert.True(t, passwordChangedAt.Equal(stored.PasswordChangedAt),
					"a conditional update that did not name the password-changed time moved it to %v",
					stored.PasswordChangedAt)
			},
		},
		{
			name: "hash changed meanwhile stays and nothing is written",
			arrange: func(t *testing.T, ctx context.Context, f Fixture, user string) string {
				mustProvision(ctx, t, f, user, identity.WithUserName("Before"),
					identity.WithUserPassword([]byte("H1")))
				mustUpdate(ctx, t, f, user, identity.WithUserPassword([]byte("H3")))
				return user
			},
			opts: []identity.UserOption{
				identity.WithUserPasswordIf([]byte("H1")),
				identity.WithUserPassword([]byte("H2")),
				identity.WithUserName("After"),
			},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, _ *identity.Details, err error) {
				isNotUpdated(t, err)

				stored := mustLoad(ctx, t, f, user)
				assert.Equal(t, []byte("H3"), stored.Password,
					"the conditional-update check failed: the store wrote over a password changed "+
						"meanwhile, so a rehash would put the old password back")
				assert.Equal(t, "Before", stored.Name,
					"a refused conditional update must write none of the fields it named")
			},
		},
		{
			name: "a user with no password matches an empty expected hash",
			arrange: func(t *testing.T, ctx context.Context, f Fixture, user string) string {
				mustProvision(ctx, t, f, user)
				return user
			},
			opts: []identity.UserOption{
				identity.WithUserPasswordIf(nil),
				identity.WithUserPassword([]byte("H2")),
			},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, _ *identity.Details, err error) {
				require.NoError(t, err, "a user stored with no password matches an empty expected hash")
				assert.Equal(t, []byte("H2"), mustLoad(ctx, t, f, user).Password)
			},
		},
		{
			name: "an unknown user is not found, not not-updated",
			arrange: func(t *testing.T, _ context.Context, _ Fixture, user string) string {
				return user + "-absent"
			},
			opts: []identity.UserOption{
				identity.WithUserPasswordIf([]byte("H1")),
				identity.WithUserPassword([]byte("H2")),
			},
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ string, _ *identity.Details, err error) {
				assert.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.NotErrorIs(t, err, identity.ErrNotUpdated,
					"a user who is not there has no stored hash to differ")
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "condpw", i)

			target := tc.arrange(t, ctx, f, user)
			got, err := f.Update(ctx, target, tc.opts...)
			tc.assert(t, ctx, f, user, got, err)
		})
	}
}

// runConditionalPasswordRaceCase checks that two updates conditional on the
// same stored hash, released together, cannot both write: exactly one wins and
// the other reports not-updated. A store that decides the condition by a read
// before its write lets both through, and the later one silently replaces the
// earlier. The case releases the two updates together over several rounds, so
// against a consumer store with no lock between its read and its write it
// catches the race only when the two interleave; it is deterministic against a
// store that holds its read open, as the suite's own guard does.
func runConditionalPasswordRaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	const rounds = 4

	for round := range rounds {
		ctx := t.Context()
		f := newFixture(t)
		user := uniqueName(t, "condrace", round)

		mustProvision(ctx, t, f, user, identity.WithUserPassword([]byte("H1")))

		hashes := [2][]byte{
			[]byte("H2-a-" + strconv.Itoa(round)),
			[]byte("H2-b-" + strconv.Itoa(round)),
		}

		var (
			wg    sync.WaitGroup
			errs  [2]error
			start = make(chan struct{})
		)

		wg.Add(len(hashes))

		for i, h := range hashes {
			go func() {
				defer wg.Done()

				<-start

				_, errs[i] = f.Update(ctx, user,
					identity.WithUserPasswordIf([]byte("H1")),
					identity.WithUserPassword(h),
				)
			}()
		}

		close(start)
		wg.Wait()

		won := -1
		for i, err := range errs {
			switch {
			case err == nil:
				assert.Equal(t, -1, won,
					"round %d: the conditional-update check failed: both updates conditional on the "+
						"same hash wrote, so the condition was decided by a read the other raced", round)
				won = i
			case errors.Is(err, identity.ErrNotUpdated):
			default:
				t.Errorf("round %d: the losing conditional update must report not-updated, got %v", round, err)
			}
		}

		require.NotEqual(t, -1, won, "round %d: one of two conditional updates on the stored hash must win", round)
		assert.Equal(t, hashes[won], mustLoad(ctx, t, f, user).Password,
			"round %d: the stored hash must be the winner's", round)
	}
}
