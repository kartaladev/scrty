package oidctest_test

import (
	"testing"
	"time"

	"github.com/kartaladev/scrty/oidc"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// TestMemoryHandoffStoreConformance runs the handoff store suite against the
// library's in-memory store.
func TestMemoryHandoffStoreConformance(t *testing.T) {
	t.Parallel()

	oidctest.RunHandoffStoreSuite(t, func(t *testing.T, _ func() time.Time) oidc.HandoffStore {
		t.Helper()
		return oidc.NewMemoryHandoffStore()
	})
}
