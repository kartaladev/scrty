package passkey_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/onetime"
)

// The purposes and subject the manager's challenges are stored under, as its
// godoc names them.
const (
	expiryLoginPurpose        = "passkey-login"
	expiryLoginSubject        = "passkey-login"
	expiryRegistrationPurpose = "passkey-registration"
)

// storedChallenges counts the challenges of purpose and subject still held by
// store, spent or not.
func storedChallenges(t *testing.T, store onetime.Store, purpose, subject string) int {
	t.Helper()

	n, err := store.CountRecentBySubject(t.Context(), purpose, subject, time.Time{})
	require.NoError(t, err)

	return n
}

// expiryTask returns the task of tasks with the given name.
func expiryTask(t *testing.T, tasks []expiry.Task, name string) expiry.Task {
	t.Helper()

	for _, task := range tasks {
		if task.Name == name {
			return task
		}
	}
	require.Failf(t, "no such task", "%q not among the manager's tasks", name)

	return expiry.Task{}
}

// noReapStore hides MemoryStore's Reaper, as a durable store with no purge
// would.
type noReapStore struct{ onetime.Store }

// TestManager_ExpiryTasks uses a run closure rather than assert: each case seeds
// and calls the tasks differently, so no single call shape is shared.
func TestManager_ExpiryTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// run wires a manager over env, seeds challenges, runs its tasks and
		// asserts what is left.
		run func(t *testing.T, env *loginEnv)
	}

	cases := []testCase{
		{
			name: "names in order and no interval",
			run: func(t *testing.T, env *loginEnv) {
				tasks := env.manager(t).ExpiryTasks()

				require.Len(t, tasks, 2)
				assert.Equal(t, "passkey-registration-challenges", tasks[0].Name)
				assert.Equal(t, "passkey-login-challenges", tasks[1].Name)
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
					assert.NotNil(t, task.Run, task.Name)
				}
			},
		},
		{
			name: "strangers' expired login challenges go and one inside its window stays",
			run: func(t *testing.T, env *loginEnv) {
				m := env.manager(t)
				// Two passwordless begins, as anyone may make with no session.
				env.begin(t)
				env.begin(t)
				// A third, two minutes on: the inline purge is not yet due.
				env.f.clock.Advance(2 * time.Minute)
				env.begin(t)
				// Six minutes after the first two: they are expired and past
				// their issuance window; the third is expired by neither.
				env.f.clock.Advance(4 * time.Minute)
				require.Equal(t, 3, storedChallenges(t, env.challenges, expiryLoginPurpose, expiryLoginSubject))

				removed, err := expiryTask(t, m.ExpiryTasks(), "passkey-login-challenges").Run(t.Context())

				require.NoError(t, err)
				assert.Equal(t, 2, removed)
				assert.Equal(t, 1, storedChallenges(t, env.challenges, expiryLoginPurpose, expiryLoginSubject))
			},
		},
		{
			name: "each task sweeps only its own ceremony",
			run: func(t *testing.T, env *loginEnv) {
				m := env.manager(t)
				env.begin(t)
				// A registration challenge in the same store, issued by a
				// manager of the registration purpose.
				reg, err := onetime.NewManager(expiryRegistrationPurpose,
					onetime.WithStore(env.challenges), onetime.WithClock(env.f.clock))
				require.NoError(t, err)
				_, _, err = reg.Issue(t.Context(), "u-1")
				require.NoError(t, err)
				// Past both lifetimes and the hour-long registration window.
				env.f.clock.Advance(2 * time.Hour)
				tasks := m.ExpiryTasks()

				removed, err := expiryTask(t, tasks, "passkey-login-challenges").Run(t.Context())
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.Equal(t, 1, storedChallenges(t, env.challenges, expiryRegistrationPurpose, "u-1"),
					"the login task must not sweep registration challenges")

				removed, err = expiryTask(t, tasks, "passkey-registration-challenges").Run(t.Context())
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.Zero(t, storedChallenges(t, env.challenges, expiryRegistrationPurpose, "u-1"))
			},
		},
		{
			name: "a challenge store that cannot purge says so",
			run: func(t *testing.T, env *loginEnv) {
				env.f.deps.Challenges = noReapStore{env.challenges}

				for _, task := range env.manager(t).ExpiryTasks() {
					removed, err := task.Run(t.Context())

					require.ErrorIs(t, err, expiry.ErrPurgeUnsupported, task.Name)
					require.ErrorIs(t, err, onetime.ErrReapUnsupported, task.Name)
					assert.Zero(t, removed, task.Name)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, newLoginEnv(t, nil))
		})
	}
}
