package oidctest_test

import (
	"testing"

	"github.com/kartaladev/scrty/oidc"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// TestMemoryLinkStoreConformance runs the link store suite against the
// in-memory store the broker uses by default.
func TestMemoryLinkStoreConformance(t *testing.T) {
	t.Parallel()

	oidctest.RunLinkStoreSuite(t, func(t *testing.T) oidc.LinkStore {
		t.Helper()
		return oidc.NewMemoryLinkStore()
	})
}
