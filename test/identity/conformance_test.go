package identitytest_test

import (
	"testing"

	identitytest "github.com/kartaladev/scrty/test/identity"
)

// TestInMemoryStoreConformance runs scrty's identity port conformance suite
// against the in-memory store this package ships.
//
// It is the suite's own proof: a consumer implementing the ports over their own
// tables calls RunConformanceSuite the same way, so a contract that the suite
// fails to check here is a contract no consumer's implementation is checked
// against either.
func TestInMemoryStoreConformance(t *testing.T) {
	t.Parallel()

	identitytest.RunConformanceSuite(t, func(t *testing.T) identitytest.Fixture {
		t.Helper()

		return identitytest.NewInMemoryStore()
	})
}
