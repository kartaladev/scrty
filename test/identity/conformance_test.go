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

// TestInMemoryStoreConformance_SharedStore runs the whole suite over one shared
// store, as a consumer running it against a single database would. Each case
// gets its own fixture over the shared records, so a fault one case injects
// stays with that case.
func TestInMemoryStoreConformance_SharedStore(t *testing.T) {
	t.Parallel()

	shared := identitytest.NewInMemoryStore()

	identitytest.RunConformanceSuite(t, func(t *testing.T) identitytest.Fixture {
		t.Helper()

		return shared.Share()
	})
}
