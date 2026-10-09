package httpsecconformance

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
)

// lockoutScenarios is every lockout behaviour that must be identical on every
// adapter.
func lockoutScenarios() []Scenario {
	return []Scenario{unknownAndKnownUsernamesLockAlike()}
}

// unknownAndKnownUsernamesLockAlike pins that a lock reveals nothing about
// whether a username names an account: the sixth wrong-password login is
// refused identically for a name with an account and one without.
func unknownAndKnownUsernamesLockAlike() Scenario {
	const unknown = "nobody"

	return Scenario{
		Name: "an unknown username is locked exactly like a known one",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(effects.Attempts))
			require.NoError(t, err)
			engine, err := policy.NewEngine(lockout)
			require.NoError(t, err)

			return ChainSpec{
				Options: append(formLoginOptions(effects), httpsec.WithPolicyEngine(engine)),
				Effects: effects,
			}
		},
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			sixth := map[string]Result{}

			for _, user := range []string{Username, unknown} {
				for range 5 {
					res := send(formBody("username=" + user + "&password=wrong"))
					require.ErrorIs(t, res.Refusal, authenticate.ErrAuthenticationFailed)
					require.NotErrorIs(t, res.Refusal, policy.ErrAccountLocked, "five failures are still free")
				}

				sixth[user] = send(formBody("username=" + user + "&password=wrong"))
			}

			known, other := sixth[Username], sixth[unknown]
			assert.Equal(t, known.Status, other.Status)
			assert.Equal(t, http.StatusUnauthorized, other.Status)
			require.ErrorIs(t, known.Refusal, policy.ErrAccountLocked)
			require.ErrorIs(t, other.Refusal, policy.ErrAccountLocked)
			assert.Equal(t, known.Refusal.Error(), other.Refusal.Error())
			assert.Equal(t, 10, known.Effects.AuthenticatorCalls(),
				"the sixth request of each was refused before any password was checked")
		},
	}
}
