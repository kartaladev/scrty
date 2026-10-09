package httpsec_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestLockoutCapWiring pins that a chain refuses to build when a capped
// lockout policy's view is bypassed by a password login, since only the view
// advances the consecutive count, and that every other wiring still builds.
func TestLockoutCapWiring(t *testing.T) {
	t.Parallel()

	// wiring is the policies the engine holds and the store each login is
	// given; a nil store leaves that login out.
	type wiring struct {
		lockouts    []*policy.AccountLockoutPolicy
		form, basic policy.AttemptStore
	}

	type testCase struct {
		name   string
		wire   func(t *testing.T) wiring
		assert func(t *testing.T, err error)
	}

	capped := func(t *testing.T, store policy.AttemptStore) *policy.AccountLockoutPolicy {
		t.Helper()

		p, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(store), policy.WithLockoutCap(20))
		require.NoError(t, err)

		return p
	}

	refusedNaming := func(field string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), field)
			assert.Contains(t, err.Error(), `"account-lockout"`, "the requiring policy is named")
			assert.Contains(t, err.Error(), "Attempts()")
		}
	}

	refusedDifferentViews := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "different")
		assert.Equal(t, 2, strings.Count(err.Error(), `"account-lockout"`), "both policies are named")
		assert.Contains(t, err.Error(), "only one store")
	}

	lockouts := func(ps ...*policy.AccountLockoutPolicy) []*policy.AccountLockoutPolicy { return ps }

	builds := func(t *testing.T, err error) {
		t.Helper()

		require.NoError(t, err)
	}

	cases := []testCase{
		{
			name: "Raw store with a cap: form login is refused",
			wire: func(t *testing.T) wiring {
				store := policy.NewMemoryAttemptStore()

				return wiring{lockouts: lockouts(capped(t, store)), form: store}
			},
			assert: refusedNaming("FormLoginDeps.Attempts"),
		},
		{
			name: "Raw store with a cap: Basic is refused",
			wire: func(t *testing.T) wiring {
				store := policy.NewMemoryAttemptStore()
				p := capped(t, store)

				return wiring{lockouts: lockouts(p), form: p.Attempts(), basic: store}
			},
			assert: refusedNaming("BasicAuthDeps.Attempts"),
		},
		{
			name: "View with a cap: both logins given the view build",
			wire: func(t *testing.T) wiring {
				p := capped(t, policy.NewMemoryAttemptStore())

				return wiring{lockouts: lockouts(p), form: p.Attempts(), basic: p.Attempts()}
			},
			assert: builds,
		},
		{
			name: "Raw store without a cap: Basic given the store builds",
			wire: func(t *testing.T) wiring {
				store := policy.NewMemoryAttemptStore()
				p, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(store))
				require.NoError(t, err)

				return wiring{lockouts: lockouts(p), basic: store}
			},
			assert: builds,
		},
		{
			name: "a cap with no password login builds",
			wire: func(t *testing.T) wiring {
				return wiring{lockouts: lockouts(capped(t, policy.NewMemoryAttemptStore()))}
			},
			assert: builds,
		},
		{
			name: "Two capped policies: Basic given the first's view is refused",
			wire: func(t *testing.T) wiring {
				first, second := capped(t, policy.NewMemoryAttemptStore()), capped(t, policy.NewMemoryAttemptStore())

				return wiring{lockouts: lockouts(first, second), basic: first.Attempts()}
			},
			assert: refusedDifferentViews,
		},
		{
			name: "Two capped policies: Basic given the second's view is refused",
			wire: func(t *testing.T) wiring {
				first, second := capped(t, policy.NewMemoryAttemptStore()), capped(t, policy.NewMemoryAttemptStore())

				return wiring{lockouts: lockouts(first, second), basic: second.Attempts()}
			},
			assert: refusedDifferentViews,
		},
		{
			name: "Two capped policies, no password login: builds",
			wire: func(t *testing.T) wiring {
				first, second := capped(t, policy.NewMemoryAttemptStore()), capped(t, policy.NewMemoryAttemptStore())

				return wiring{lockouts: lockouts(first, second)}
			},
			assert: builds,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := tc.wire(t)
			ctrl := gomock.NewController(t)

			sessions, err := session.NewManager(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			opts := []httpsec.Option{httpsec.WithPolicyEngine(engineOf(t, lockoutPolicies(w.lockouts)...))}

			if w.form != nil {
				opts = append(opts, httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: NewMockAuthenticator(ctrl), Sessions: sessions,
					Tokens: NewMockGenerator(ctrl), Attempts: w.form,
				}))
			}

			if w.basic != nil {
				opts = append(opts, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
					Authenticator: NewMockAuthenticator(ctrl), Attempts: w.basic,
				}))
			}

			_, err = httpsec.New(opts...)
			tc.assert(t, err)
		})
	}
}

// lockoutPolicies widens lockout policies to the policy.Policy values an
// engine takes.
func lockoutPolicies(ps []*policy.AccountLockoutPolicy) []policy.Policy {
	out := make([]policy.Policy, 0, len(ps))
	for _, p := range ps {
		out = append(out, p)
	}

	return out
}
