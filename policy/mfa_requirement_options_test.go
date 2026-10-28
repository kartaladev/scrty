package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/policy"
)

func TestFederatedAssuranceModeString(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mode   policy.FederatedAssuranceMode
		assert func(t *testing.T, s string)
	}

	named := func(want string) func(t *testing.T, s string) {
		return func(t *testing.T, s string) { assert.Equal(t, want, s) }
	}

	cases := []testCase{
		{name: "challenge", mode: policy.FederatedAssuranceChallenge, assert: named("FederatedAssuranceChallenge")},
		{name: "refuse", mode: policy.FederatedAssuranceRefuse, assert: named("FederatedAssuranceRefuse")},
		{name: "exempt", mode: policy.FederatedAssuranceExempt, assert: named("FederatedAssuranceExempt")},
		{
			name: "an unnamed value is printed as a number, never as a mode",
			mode: policy.FederatedAssuranceMode(9), assert: named("FederatedAssuranceMode(9)"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.mode.String())
		})
	}
}
