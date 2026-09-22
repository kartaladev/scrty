package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// A stateless first factor has no later phase to refuse in: it turns the
// phase's decision into its own error and returns that. A deny carrying no
// reason therefore hands it nil, which every caller in Go reads as success, and
// the request the policy meant to refuse is served.
//
// The engine substitutes ErrPolicyDenied so that this cannot happen, whichever
// policy did the denying — closing it once here rather than asking every policy
// that will ever be written to remember.
func TestADenyAlwaysCarriesAReason(t *testing.T) {
	t.Parallel()

	reasonless := stubPolicy{
		name:     "reasonless",
		phases:   []policy.Phase{policy.StatelessAuthentication},
		decision: policy.Decision{Outcome: policy.Deny}, // Reason left nil.
	}

	e, err := policy.NewEngine(reasonless)
	require.NoError(t, err)

	d := e.EvaluatePhase(t.Context(), policy.StatelessAuthentication, &policy.Input{})
	require.Equal(t, policy.Deny, d.Outcome)
	require.Error(t, d.Reason,
		"a deny with no reason is indistinguishable from success to the caller that reports it")
	assert.ErrorIs(t, d.Reason, policy.ErrPolicyDenied)
}

// TestADenyCarriesItsOwnReasonUnchanged pins the other half: the substitution
// is a floor, not a replacement. A policy that explained its refusal keeps that
// explanation, or a consumer could no longer tell an account lockout from a
// failed second factor.
func TestADenyCarriesItsOwnReasonUnchanged(t *testing.T) {
	t.Parallel()

	explained := stubPolicy{
		name:     "explained",
		phases:   []policy.Phase{policy.StatelessAuthentication},
		decision: policy.Decision{Outcome: policy.Deny, Reason: errDenied},
	}

	e, err := policy.NewEngine(explained)
	require.NoError(t, err)

	d := e.EvaluatePhase(t.Context(), policy.StatelessAuthentication, &policy.Input{})
	require.Equal(t, policy.Deny, d.Outcome)
	assert.ErrorIs(t, d.Reason, errDenied, "the policy's own reason was replaced")
	assert.NotErrorIs(t, d.Reason, policy.ErrPolicyDenied,
		"a policy that explained itself was reported as an unexplained refusal")
}
