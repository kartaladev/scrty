package recovery_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/recovery"
)

// taskNames returns the names of tasks, in order.
func taskNames(tasks []expiry.Task) []string {
	names := make([]string, 0, len(tasks))
	for _, task := range tasks {
		names = append(names, task.Name)
	}

	return names
}

// namedTask returns the task of tasks with the given name.
func namedTask(t *testing.T, tasks []expiry.Task, name string) expiry.Task {
	t.Helper()

	for _, task := range tasks {
		if task.Name == name {
			return task
		}
	}
	require.Failf(t, "no such task", "%q not among %v", name, taskNames(tasks))

	return expiry.Task{}
}

// noIssuedProofs enables saved codes and the password, and no issued codes.
var noIssuedProofs = recovery.WithProofs(recovery.ProofSaved, recovery.ProofPassword)

func TestRecoverer_ExpiryTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// opts are the options beyond the env's, which enable every proof
		// kind and no hold.
		opts func(e *completeEnv) []recovery.Option
		// defaultStore builds the recoverer with no issued-code store, so
		// the one it makes for itself is under test.
		defaultStore bool
		// assert runs against the recoverer built from opts.
		assert func(t *testing.T, e *completeEnv, r *recovery.Recoverer)
	}

	cases := []testCase{
		{
			name: "issued codes and no hold give the issued-code task only",
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				tasks := r.ExpiryTasks()

				assert.Equal(t, []string{"recovery-issued-codes"}, taskNames(tasks))
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
				}
			},
		},
		{
			name: "holds add the finish and cancel token tasks",
			opts: func(*completeEnv) []recovery.Option { return holdFor(time.Hour) },
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				tasks := r.ExpiryTasks()

				assert.Equal(t,
					[]string{"recovery-issued-codes", "recovery-finish-tokens", "recovery-cancel-tokens"},
					taskNames(tasks))
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
				}
			},
		},
		{
			name: "holds without issued codes give the hold token tasks only",
			opts: func(*completeEnv) []recovery.Option {
				return append(holdFor(time.Hour), noIssuedProofs)
			},
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				assert.Equal(t, []string{"recovery-finish-tokens", "recovery-cancel-tokens"}, taskNames(r.ExpiryTasks()))
			},
		},
		{
			name: "neither issued codes nor holds give no tasks",
			opts: func(*completeEnv) []recovery.Option { return []recovery.Option{noIssuedProofs} },
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				tasks := r.ExpiryTasks()

				require.NotNil(t, tasks)
				assert.Empty(t, tasks)
			},
		},
		{
			name:         "an expired issued code goes and a live one stays",
			defaultStore: true,
			assert:       assertExpiredIssuedCodeGoes,
		},
		{
			name:         "the default issued-code store follows a clock ahead of the system clock",
			defaultStore: true,
			assert: func(t *testing.T, e *completeEnv, r *recovery.Recoverer) {
				e.clock.Advance(time.Until(time.Now().Add(365 * 24 * time.Hour)))

				assertExpiredIssuedCodeGoes(t, e, r)
			},
		},
		{
			name: "each hold token task sweeps only its own tokens",
			opts: func(e *completeEnv) []recovery.Option {
				return append(holdFor(time.Hour),
					recovery.WithHoldTokenStore(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(e.clock))))
			},
			assert: func(t *testing.T, e *completeEnv, r *recovery.Recoverer) {
				ctx := t.Context()
				heldRecovery(ctx, t, r, recovery.Request{Username: anaUsername, Saved: e.saved[0], Password: []byte(anaPassword)})
				tasks := r.ExpiryTasks()
				// Inside the hold and its completion window, nothing goes.
				for _, name := range []string{"recovery-finish-tokens", "recovery-cancel-tokens"} {
					removed, err := namedTask(t, tasks, name).Run(ctx)
					require.NoError(t, err)
					assert.Zero(t, removed, name)
				}
				// Past the hold, the 24-hour window and the issuance window.
				e.clock.Advance(27 * time.Hour)

				for _, name := range []string{"recovery-finish-tokens", "recovery-cancel-tokens"} {
					removed, err := namedTask(t, tasks, name).Run(ctx)
					require.NoError(t, err)
					assert.Equal(t, 1, removed, name)
				}
			},
		},
		{
			name: "an issued-code store that cannot purge says so",
			opts: func(e *completeEnv) []recovery.Option {
				return []recovery.Option{recovery.WithIssuedCodeStore(struct{ onetime.Store }{e.tokens})}
			},
			assert: func(t *testing.T, _ *completeEnv, r *recovery.Recoverer) {
				removed, err := namedTask(t, r.ExpiryTasks(), "recovery-issued-codes").Run(t.Context())

				require.ErrorIs(t, err, expiry.ErrPurgeUnsupported)
				require.ErrorIs(t, err, onetime.ErrReapUnsupported)
				assert.Zero(t, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := newCompleteEnv(t)
			var opts []recovery.Option
			if tc.opts != nil {
				opts = tc.opts(e)
			}
			if tc.defaultStore {
				// The env's own options name a store, so build from the fixture's.
				r, err := recovery.NewRecoverer(e.completeDeps(),
					e.fixture.opts(append([]recovery.Option{recovery.WithMessages(e.capturingMessages())}, opts...)...)...)
				require.NoError(t, err)
				tc.assert(t, e, r)

				return
			}

			tc.assert(t, e, e.recoverer(t, opts...))
		})
	}
}

// assertExpiredIssuedCodeGoes issues two codes an expiry apart and checks that
// the issued-code task removes the expired one and leaves the live one.
func assertExpiredIssuedCodeGoes(t *testing.T, e *completeEnv, r *recovery.Recoverer) {
	t.Helper()

	ctx := t.Context()
	// Start is open to anyone who knows a username.
	r.Start(ctx, anaUsername)
	// Past the code's lifetime and the hour-long issuance window.
	e.clock.Advance(2 * time.Hour)
	r.Start(ctx, anaUsername)
	require.Len(t, e.out.messages(), 2, "both starts must have issued a code")

	removed, err := namedTask(t, r.ExpiryTasks(), "recovery-issued-codes").Run(ctx)

	require.NoError(t, err)
	assert.Equal(t, 1, removed)
	removed, err = namedTask(t, r.ExpiryTasks(), "recovery-issued-codes").Run(ctx)
	require.NoError(t, err)
	assert.Zero(t, removed, "the live code must stay")
}
