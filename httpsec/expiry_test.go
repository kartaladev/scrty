package httpsec_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
)

// expiryTaskNames returns the names of tasks, in order.
func expiryTaskNames(tasks []expiry.Task) []string {
	names := make([]string, 0, len(tasks))
	for _, task := range tasks {
		names = append(names, task.Name)
	}

	return names
}

// runExpiryTask runs the task of tasks with the given name.
func runExpiryTask(t *testing.T, tasks []expiry.Task, name string) (int, error) {
	t.Helper()

	for _, task := range tasks {
		if task.Name == name {
			return task.Run(t.Context())
		}
	}
	require.Failf(t, "no such task", "%q not among %v", name, expiryTaskNames(tasks))

	return 0, nil
}

// namedChallengeStubs returns challenge methods with the given names, each
// one the user is enrolled on.
func namedChallengeStubs(names ...string) []mfa.Method {
	methods := make([]mfa.Method, 0, len(names))
	for _, name := range names {
		stub := newChallengeStub()
		stub.name = name
		methods = append(methods, stub)
	}

	return methods
}

// expiryMFAHarness is the MFA harness with its TOTP method double wired for a
// chain that begins challenges and verifies nothing, configured after it with
// extra.
func expiryMFAHarness(t *testing.T, extra ...mfa.Method) *mfaHarness {
	t.Helper()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
	h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(false, nil).AnyTimes()
	h.extra = extra

	return h
}

// expiryRecoveryHarness is the recovery harness, whose core and default stores
// share its fake clock, with MFA over methods when there are any.
func expiryRecoveryHarness(t *testing.T, methods ...mfa.Method) *recoveryHarness {
	t.Helper()

	h := newRecoveryHarness(t)

	if len(methods) > 0 {
		h.chainOpts = append(h.chainOpts, httpsec.EnableMFA(methods, httpsec.WithMFATokens(h.tokens)))
	}

	return h
}

// TestChain_ExpiryTasks pins which tasks a chain returns for the one-time state
// of the components it builds, and that each task sweeps the state those
// components issued while serving requests, not a copy of it.
//
// Every case moves time on its harness's fake clock, which the chain reads
// through WithClock.
func TestChain_ExpiryTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// chain builds the chain and issues, through it, whatever the case
		// sweeps.
		chain  func(t *testing.T) *httpsec.Chain
		assert func(t *testing.T, tasks []expiry.Task)
	}

	cases := []testCase{
		{
			name:  "nothing enabled gives no tasks",
			chain: func(t *testing.T) *httpsec.Chain { c, err := httpsec.New(); require.NoError(t, err); return c },
			assert: func(t *testing.T, tasks []expiry.Task) {
				require.NotNil(t, tasks)
				assert.Empty(t, tasks)

				_, err := expiry.NewRunner(tasks)
				require.ErrorIs(t, err, expiry.ErrNoTasks)
			},
		},
		{
			// A method with no begin step keeps no pending challenge, so
			// there is nothing of it to sweep.
			name:  "a method with no challenge step contributes no task",
			chain: func(t *testing.T) *httpsec.Chain { return expiryMFAHarness(t).bearerChain(t) },
			assert: func(t *testing.T, tasks []expiry.Task) {
				require.NotNil(t, tasks)
				assert.Empty(t, tasks)
			},
		},
		{
			name: "a challenge method contributes its task and recovery none",
			chain: func(t *testing.T) *httpsec.Chain {
				return expiryMFAHarness(t, namedChallengeStubs("passkey")...).bearerChain(t)
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				assert.Equal(t, []string{"mfa-challenges:passkey"}, expiryTaskNames(tasks))
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
				}
			},
		},
		{
			name: "challenge methods come in their configured order",
			chain: func(t *testing.T) *httpsec.Chain {
				return expiryMFAHarness(t, namedChallengeStubs("zeta", "alpha", "mid", "beta", "omega", "kappa")...).bearerChain(t)
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				assert.Equal(t, []string{
					"mfa-challenges:zeta", "mfa-challenges:alpha", "mfa-challenges:mid",
					"mfa-challenges:beta", "mfa-challenges:omega", "mfa-challenges:kappa",
				}, expiryTaskNames(tasks))
			},
		},
		{
			name:  "recovery without holds contributes its issued-code task",
			chain: func(t *testing.T) *httpsec.Chain { return expiryRecoveryHarness(t).build(t).chain },
			assert: func(t *testing.T, tasks []expiry.Task) {
				assert.Equal(t, []string{"recovery-issued-codes"}, expiryTaskNames(tasks))
			},
		},
		{
			name: "MFA tasks come before the recovery tasks",
			chain: func(t *testing.T) *httpsec.Chain {
				h := expiryRecoveryHarness(t, namedChallengeStubs("passkey")...)
				h.withHold()

				return h.build(t).chain
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				assert.Equal(t, []string{
					"mfa-challenges:passkey",
					"recovery-issued-codes", "recovery-finish-tokens", "recovery-cancel-tokens",
				}, expiryTaskNames(tasks))
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
				}
			},
		},
		{
			name: "the MFA task sweeps a challenge begun through the chain",
			chain: func(t *testing.T) *httpsec.Chain {
				h := expiryMFAHarness(t, namedChallengeStubs("passkey")...)
				c := h.bearerChain(t)
				s := h.pendingSession(t, factor.Password)

				out := serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID)))
				require.NoError(t, out.err)
				require.Equal(t, http.StatusOK, out.rec.Code, "the begin issued a challenge")

				// Past the challenge's lifetime and the hour-long issuance
				// window, with no begin since to sweep it inline.
				h.clock.Advance(httpsec.DefaultMFAChallengeTTL + time.Hour + time.Second)

				return c
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				removed, err := runExpiryTask(t, tasks, "mfa-challenges:passkey")
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "the issued-code task sweeps a code a start issued through the chain",
			chain: func(t *testing.T) *httpsec.Chain {
				h := expiryRecoveryHarness(t).build(t)
				h.issued(t)
				// Past the code's lifetime and the hour-long issuance window.
				h.clock.Advance(2 * time.Hour)

				return h.chain
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				removed, err := runExpiryTask(t, tasks, "recovery-issued-codes")
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "the hold token tasks sweep the tokens of a hold made through the chain",
			chain: func(t *testing.T) *httpsec.Chain {
				h := expiryRecoveryHarness(t)
				h.withHold()
				h.build(t).hold(t)
				// Past the hold, its 24-hour completion window and the
				// issuance window.
				h.clock.Advance(recoveryHoldDelay + 26*time.Hour)

				return h.chain
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				for _, name := range []string{"recovery-finish-tokens", "recovery-cancel-tokens"} {
					removed, err := runExpiryTask(t, tasks, name)
					require.NoError(t, err)
					assert.Equal(t, 1, removed, name)
				}
			},
		},
	}

	for _, tc := range cases {
		run := func(t *testing.T) {
			tc.assert(t, tc.chain(t).ExpiryTasks())
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			run(t)
		})
	}
}
