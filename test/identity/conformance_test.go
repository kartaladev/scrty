package identitytest_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

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

// TestSuiteParts_ShareOneTestAndOneStore runs two parts of the suite under one
// *testing.T over one shared store, as an adapter's test does when it calls
// RunUserLoaderSuite and then RunRoleLoaderSuite against one database. Each
// part runs its own preflight, and the second must not meet the first one's
// probe.
func TestSuiteParts_ShareOneTestAndOneStore(t *testing.T) {
	t.Parallel()

	type part func(t *testing.T, newFixture identitytest.Factory)

	type testCase struct {
		name  string
		parts []part
	}

	cases := []testCase{
		{
			name:  "the user loader part then the role loader part",
			parts: []part{identitytest.RunUserLoaderSuite, identitytest.RunRoleLoaderSuite},
		},
		{
			name:  "the whole suite then the MFA lookup part",
			parts: []part{identitytest.RunConformanceSuite, identitytest.RunMFALookupSuite},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			shared := identitytest.NewInMemoryStore()
			newFixture := func(t *testing.T) identitytest.Fixture {
				t.Helper()

				return shared.Share()
			}

			for _, run := range tc.parts {
				run(t, newFixture)
			}
		})
	}
}

// persisted outlives a single run of the suite, as a consumer's database does:
// under go test -count=2, the second run finds every row the first one wrote.
var persisted = identitytest.NewInMemoryStore()

// TestInMemoryStoreConformance_PersistedStore runs the whole suite over records
// that survive from one run to the next. Run once, it is the shared-store case
// again; run repeatedly in one process, every run after the first meets the rows
// of the runs before it, and passes only if the suite's names are unique to the
// run and not merely to the case.
func TestInMemoryStoreConformance_PersistedStore(t *testing.T) {
	t.Parallel()

	identitytest.RunConformanceSuite(t, func(t *testing.T) identitytest.Fixture {
		t.Helper()

		return persisted.Share()
	})
}

// TestConformanceSuiteSurvivesRepeatedRuns re-executes this test binary to run
// TestInMemoryStoreConformance_PersistedStore twice in one process, so that a
// plain go test -count=1 still checks that a second run over a persisted store
// collides with nothing the first one left behind.
func TestConformanceSuiteSurvivesRepeatedRuns(t *testing.T) {
	t.Parallel()

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestInMemoryStoreConformance_PersistedStore$", "-test.count=2", "-test.timeout=5m")

	out, err := cmd.CombinedOutput()
	require.NoError(t, err,
		"a second run over the first run's records failed, so a consumer re-running the suite "+
			"against a long-lived database would see collisions rather than their store's faults:\n%s", out)
}
