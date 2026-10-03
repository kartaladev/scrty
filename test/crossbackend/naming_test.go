package crossbackend_test

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/sqlstore"
	"github.com/kartaladev/scrty/test"
	oidctest "github.com/kartaladev/scrty/test/oidc"
)

// zeroConsumptionHandoffStore wraps a real sqlstore.HandoffStore, replacing
// any non-nil consumption time a find returns with the zero time, so it
// diverges from every other backend in exactly the one way "Backend diverges"
// describes.
type zeroConsumptionHandoffStore struct{ *sqlstore.HandoffStore }

func (s zeroConsumptionHandoffStore) FindByTokenID(ctx context.Context, tokenID string) (*oidc.HandoffRecord, error) {
	rec, err := s.HandoffStore.FindByTokenID(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	if rec.ConsumedAt != nil {
		var zero time.Time
		rec.ConsumedAt = &zero
	}

	return rec, nil
}

// namingBrokenVar names the environment variable that tells
// TestNamingBrokenHandoffStore to run: without it named, it skips, so it never
// runs except as the child half of TestNamingGuardCatchesBackendDiverges.
const namingBrokenVar = "CROSSBACKEND_NAMING_BROKEN"

// TestNamingBrokenHandoffStore is the child half of
// TestNamingGuardCatchesBackendDiverges: it runs oidctest.RunHandoffStoreSuite
// against a handoff store variant that returns a zero consumption time,
// wrapped in t.Run("sqlstore", ...) the way every scrty run names its
// backend (design D11). Without namingBrokenVar named it skips, so it does
// nothing when collected by an ordinary `go test ./...`.
func TestNamingBrokenHandoffStore(t *testing.T) {
	if os.Getenv(namingBrokenVar) == "" {
		t.Skipf("no run named in %s; run through TestNamingGuardCatchesBackendDiverges", namingBrokenVar)
	}

	conn := migratedConn(t)

	t.Run("sqlstore", func(t *testing.T) {
		oidctest.RunHandoffStoreSuite(t, func(t *testing.T, _ clock.Clock) oidc.HandoffStore {
			t.Helper()

			s, err := sqlstore.NewHandoffStore(conn.DB)
			require.NoError(t, err)
			// Every case runs against an empty table: the suite's cases run
			// one after another and each inserts its own records.
			_, execErr := conn.DB.ExecContext(t.Context(), "TRUNCATE oidc_handoffs")
			require.NoError(t, execErr)

			return zeroConsumptionHandoffStore{s}
		})
	})
}

// failedNamingCase matches a failed case of the child's run, capturing the
// full subtest path.
var failedNamingCase = regexp.MustCompile(`--- FAIL: (\S+)`)

// TestNamingGuardCatchesBackendDiverges proves "Backend diverges": when a
// backend's handoff store returns a consumed handoff's consumption time as
// zero while the contract requires it kept, the handoff store suite fails,
// and the failure names both the suite case that caught it and the backend
// under test, because the caller (never the suite) wraps its call in
// t.Run("sqlstore", ...) (design D11).
//
// The child runs in its own process, because a failing suite reports through
// its own *testing.T and would fail this test with it.
func TestNamingGuardCatchesBackendDiverges(t *testing.T) {
	t.Parallel()

	// The child wants PostgreSQL: start the server it will inherit.
	test.EnsureTestPostgresServer(t)

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestNamingBrokenHandoffStore$", "-test.count=1", "-test.v", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), namingBrokenVar+"=1")
	out, err := cmd.CombinedOutput()
	output := string(out)

	// The child names its variant, so it skips only when RunTestPostgres
	// does: Docker is unavailable outside CI.
	if strings.Contains(output, "--- SKIP: TestNamingBrokenHandoffStore") {
		t.Skipf("the child skipped, so nothing was checked:\n%s", output)
	}
	require.Error(t, err, "the suite passed a handoff store that returns a zero consumption time:\n%s", output)

	var failed []string
	for _, m := range failedNamingCase.FindAllStringSubmatch(output, -1) {
		failed = append(failed, m[1])
	}
	t.Logf("failed subtest paths: %v", failed)

	found := false
	for _, path := range failed {
		if strings.Contains(path, "/sqlstore/") &&
			strings.Contains(path, "consuming_an_unconsumed_record_succeeds_and_records_when") {
			found = true
			break
		}
	}
	assert.True(t, found,
		"no failure names both the sqlstore backend and the consumption-time case:\n%s", output)
}
