package httpsecconformance

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// ChallengeScenarios is every automation-challenge behaviour that must be
// identical on every adapter. Scenarios leaves them out: each adapter's suite
// runs them on their own, by name (TestChallenge*), through RunScenarios, and
// that is the only place they run.
func ChallengeScenarios() []Scenario {
	return []Scenario{
		challengeRefusesLogin(),
		challengePassesLogin(),
		challengeVerifierOutage(),
		challengeFlowNotSelected(),
		challengeRefusesBasic(),
	}
}

// challengeAnswer is a fixture verifier: it answers every request with
// decision and err, and counts how often it was asked.
type challengeAnswer struct {
	decision httpsec.ChallengeDecision
	err      error
	asked    *atomic.Int32
}

func (v challengeAnswer) Verify(context.Context, httpsec.Request, httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
	v.asked.Add(1)

	return v.decision, v.err
}

// errChallengeServiceDown is a verifier's own failure, worded with something
// no response may repeat.
var errChallengeServiceDown = errors.New("challenge service: connection refused (secret=sk-live-123)")

// challengeLogin is the chain a login challenge scenario is built over: form
// login, with the verifier answering decision and err.
func challengeLogin(
	t *testing.T,
	decision httpsec.ChallengeDecision,
	err error,
	opts ...httpsec.ChallengeOption,
) (ChainSpec, *atomic.Int32) {
	t.Helper()

	effects := newEffects(t)
	asked := new(atomic.Int32)

	return ChainSpec{
		Options: append(formLoginOptions(effects),
			httpsec.EnableAutomationChallenge(challengeAnswer{decision: decision, err: err, asked: asked}, opts...)),
		Effects: effects,
	}, asked
}

func challengeRefusesLogin() Scenario {
	var asked *atomic.Int32

	return Scenario{
		Name: "challenge: a login the verifier refuses is 403, before any account is looked up",
		Build: func(t *testing.T) ChainSpec {
			spec, n := challengeLogin(t, httpsec.ChallengeRefuse, nil)
			asked = n

			return spec
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			assert.Empty(t, res.Body, "a refusal carries no error text")
			require.ErrorIs(t, res.Refusal, httpsec.ErrChallengeRequired)
			assert.Equal(t, int32(1), asked.Load())

			assert.Zero(t, res.Effects.AuthenticatorCalls(), "no account was looked up")
			assert.Zero(t, res.Effects.RecordedFailures(t), "no lockout failure was recorded")
			assert.Zero(t, res.Effects.ActiveSessions(t))
		},
	}
}

func challengePassesLogin() Scenario {
	return Scenario{
		Name: "challenge: a login the verifier passes proceeds",
		Build: func(t *testing.T) ChainSpec {
			spec, _ := challengeLogin(t, httpsec.ChallengePass, nil)

			return spec
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusOK, res.Status)
			assert.NoError(t, res.Refusal)
			assert.Equal(t, 1, res.Effects.ActiveSessions(t), "the login opened its session")
		},
	}
}

func challengeVerifierOutage() Scenario {
	return Scenario{
		Name: "challenge: a verifier that fails is a 500 with fixed text, and no account is looked up",
		Build: func(t *testing.T) ChainSpec {
			spec, _ := challengeLogin(t, 0, errChallengeServiceDown)

			return spec
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusInternalServerError, res.Status)
			assert.NotContains(t, res.Body, "sk-live-123")
			require.ErrorIs(t, res.Refusal, httpsec.ErrChallengeUnavailable)
			require.NotErrorIs(t, res.Refusal, httpsec.ErrChallengeRequired)
			assert.NotContains(t, res.Refusal.Error(), "sk-live-123")

			assert.Zero(t, res.Effects.AuthenticatorCalls(), "no account was looked up")
			assert.Zero(t, res.Effects.RecordedFailures(t))
		},
	}
}

func challengeFlowNotSelected() Scenario {
	var asked *atomic.Int32

	return Scenario{
		Name: "challenge: a login is not asked about when only Basic requests are selected",
		Build: func(t *testing.T) ChainSpec {
			spec, n := challengeLogin(t, httpsec.ChallengeRefuse, nil,
				httpsec.WithChallengeFlows(httpsec.ChallengeFlowBasicAuth))
			asked = n

			// A selection names flows the chain enables, so Basic is enabled
			// beside form login, and only it is asked.
			spec.Options = append(spec.Options, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
				Authenticator: &fixtureAuthenticator{calls: &spec.Effects.authCalls},
				Attempts:      spec.Effects.Attempts,
			}))

			return spec
		},
		Request: sending(formBody("username=" + Username + "&password=" + Password)),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusOK, res.Status)
			assert.NoError(t, res.Refusal)
			assert.Zero(t, asked.Load(), "the verifier was not asked")
		},
	}
}

func challengeRefusesBasic() Scenario {
	var asked *atomic.Int32

	return Scenario{
		Name: "challenge: a Basic request the verifier refuses is 403, without a Basic challenge",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)
			asked = new(atomic.Int32)

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
						Authenticator: &fixtureAuthenticator{calls: &effects.authCalls},
						Attempts:      effects.Attempts,
					}),
					httpsec.EnableAutomationChallenge(challengeAnswer{decision: httpsec.ChallengeRefuse, asked: asked}),
				},
				Effects: effects,
				Routes:  plainRoute(),
			}
		},
		Request: sending(RequestSpec{
			Method: http.MethodGet,
			Path:   RoutePath,
			Header: map[string]string{
				"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(Username+":"+Password)),
			},
			ClientAddress: ClientAddress,
		}),
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			assert.Empty(t, res.Header.Get("WWW-Authenticate"), "a 403 carries no Basic challenge")
			require.ErrorIs(t, res.Refusal, httpsec.ErrChallengeRequired)
			assert.False(t, res.RouteRan)
			assert.Equal(t, int32(1), asked.Load())

			assert.Zero(t, res.Effects.AuthenticatorCalls(), "no account was looked up")
			assert.Zero(t, res.Effects.RecordedFailures(t))
		},
	}
}
