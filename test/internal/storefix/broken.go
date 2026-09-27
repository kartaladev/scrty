package storefix

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BrokenVariant is a durable store carrying one deliberate defect, the run
// that must fail, and the case of it that must catch the defect.
type BrokenVariant struct {
	Name      string
	Run       func(t *testing.T)
	FailsCase string
	// FailsWith, when set, is text the child's output must carry.
	FailsWith string
}

// RunBrokenChild runs the variant named by the environment variable envVar,
// and is the child half of the guard test parent. Without a variant named it
// skips.
func RunBrokenChild(t *testing.T, envVar, parent string, variants []BrokenVariant) {
	t.Helper()

	name, named := os.LookupEnv(envVar)
	if !named {
		t.Skipf("no variant named in %s; run through %s", envVar, parent)
	}

	for _, v := range variants {
		if v.Name == name {
			t.Logf("variant under test: %q", name)
			v.Run(t)
			return
		}
	}
	t.Fatalf("no broken variant is named %q", name)
}

// CatchBrokenVariants checks that each variant's run fails at the case
// guarding its defect. It re-executes this test binary once per variant,
// running only the child test child with envVar naming the variant, and reads
// the failed cases under child/backend from its output. Each variant runs in
// its own process, because a failing suite reports through its own
// *testing.T and would fail this test with it.
func CatchBrokenVariants(t *testing.T, envVar, child, backend string, variants []BrokenVariant) {
	t.Helper()

	failedCase := regexp.MustCompile(`--- FAIL: ` + regexp.QuoteMeta(child+"/"+backend+"/") + `(\S+)`)

	for _, v := range variants {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()

			//nolint:gosec // G204: this test binary re-executed with fixed arguments
			cmd := exec.CommandContext(t.Context(), os.Args[0],
				"-test.run=^"+child+"$", "-test.count=1", "-test.v", "-test.timeout=5m")
			cmd.Env = append(os.Environ(), envVar+"="+v.Name)
			out, err := cmd.CombinedOutput()
			output := string(out)

			// The child names its variant, so it skips only when
			// RunTestPostgres does: Docker is unavailable outside CI.
			if strings.Contains(output, "--- SKIP: "+child) {
				t.Skipf("the child skipped, so nothing was checked:\n%s", output)
			}
			require.Error(t, err, "the suite passed a store carrying the %s defect:\n%s", v.Name, output)

			var failed []string
			for _, m := range failedCase.FindAllStringSubmatch(output, -1) {
				failed = append(failed, m[1])
			}
			t.Logf("cases failed by %s: %v", v.Name, failed)
			assert.Contains(t, failed, strings.ReplaceAll(v.FailsCase, " ", "_"),
				"the suite failed, but not at the case that guards this defect:\n%s", output)
			if v.FailsWith != "" {
				assert.Contains(t, output, v.FailsWith, "the failure does not report the violation")
			}
		})
	}
}
