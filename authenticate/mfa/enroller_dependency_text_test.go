package mfa_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProveDevice_DependencyErrorTextIsFixed pins that an error from the
// consumer's random source reaches the caller behind the library's own text,
// the dependency's error still reachable by identity.
func TestProveDevice_DependencyErrorTextIsFixed(t *testing.T) {
	tests := []struct {
		name   string
		site   penrSite
		assert func(t *testing.T, out ptotpOutcome)
	}{
		{
			name: "emailed code's random source fails",
			site: penrRandom,
			assert: func(t *testing.T, out ptotpOutcome) {
				require.Error(t, out.err)
				assert.NotContains(t, out.err.Error(), "u-123")
				assert.ErrorIs(t, out.err, errDependencyText)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, runPenrSite(t, t.Context(), tc.site, errDependencyText))
		})
	}
}
