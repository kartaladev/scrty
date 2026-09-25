package oidctest_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// TestFlowStoreSuiteMemoryConformance runs the flow store suite against the
// in-memory store the manager uses by default, with the suite's clock.
func TestFlowStoreSuiteMemoryConformance(t *testing.T) {
	t.Parallel()

	oidctest.RunFlowStoreSuite(t, func(t *testing.T, now func() time.Time) oidc.FlowStore {
		t.Helper()
		s, err := oidc.NewMemoryFlowStore(oidc.WithMemoryFlowStoreClock(now))
		require.NoError(t, err)
		return s
	})
}
