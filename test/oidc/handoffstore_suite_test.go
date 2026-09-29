package oidctest_test

import (
	"testing"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/clock"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// TestMemoryHandoffStoreConformance runs the handoff store suite against the
// library's in-memory store.
func TestMemoryHandoffStoreConformance(t *testing.T) {
	t.Parallel()

	oidctest.RunHandoffStoreSuite(t, func(t *testing.T, _ clock.Clock) oidc.HandoffStore {
		t.Helper()
		return oidc.NewMemoryHandoffStore()
	})
}
