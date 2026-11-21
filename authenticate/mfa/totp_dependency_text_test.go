package mfa_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errDependencyText = errors.New("hsm slot u-123 offline")

// TestTOTPBeginEnrolment_DependencyErrorTextIsFixed pins that an error from the
// consumer's random source or id generator reaches the caller behind the
// library's own text, the dependency's error still reachable by identity.
func TestTOTPBeginEnrolment_DependencyErrorTextIsFixed(t *testing.T) {
	tests := []struct {
		name   string
		site   ptotpEnrolSite
		assert func(t *testing.T, out ptotpOutcome)
	}{
		{
			name: "random source fails",
			site: ptotpRandom,
			assert: func(t *testing.T, out ptotpOutcome) {
				require.Error(t, out.err)
				assert.NotContains(t, out.err.Error(), "u-123")
				assert.ErrorIs(t, out.err, errDependencyText)
			},
		},
		{
			name: "id generator fails",
			site: ptotpNewID,
			assert: func(t *testing.T, out ptotpOutcome) {
				require.Error(t, out.err)
				assert.NotContains(t, out.err.Error(), "u-123")
				assert.ErrorIs(t, out.err, errDependencyText)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, runPtotpEnrolSite(t.Context(), t, tc.site, errDependencyText))
		})
	}
}
