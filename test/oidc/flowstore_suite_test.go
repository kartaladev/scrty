package oidctest_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/clock"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// TestFlowStoreSuiteMemoryConformance runs the flow store suite against the
// in-memory store the manager uses by default, with the suite's clock.
func TestFlowStoreSuiteMemoryConformance(t *testing.T) {
	t.Parallel()

	oidctest.RunFlowStoreSuite(t, func(t *testing.T, clk clock.Clock) oidc.FlowStore {
		t.Helper()
		s, err := oidc.NewMemoryFlowStore(oidc.WithMemoryFlowStoreClock(clk))
		require.NoError(t, err)
		return s
	})
}
