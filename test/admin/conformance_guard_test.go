//go:build admin_stub

package admintest_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	admintest "github.com/kartaladev/scrty/test/admin"
)

// defectVar names the environment variable that selects the defect the toy
// store carries in the child process, and partVar the part of the suite the
// child runs.
const (
	defectVar = "SCRTY_ADMIN_DEFECT"
	partVar   = "SCRTY_ADMIN_PART"
)

// TestBrokenAdminStore runs the suite against the toy store carrying the
// defect named by the environment. It is the child half of
// TestAdminSuiteIsLoadBearing; without a defect named it skips.
func TestBrokenAdminStore(t *testing.T) {
	d, named := os.LookupEnv(defectVar)
	if !named {
		t.Skipf("no defect named in %s; run through TestAdminSuiteIsLoadBearing", defectVar)
	}

	t.Logf("defect under test: %q", d)

	factory := func(t *testing.T) admintest.Fixture {
		t.Helper()

		return newToyFixture(defect(d))
	}

	switch os.Getenv(partVar) {
	case "users":
		admintest.RunUserSuite(t, factory)
	case "import":
		admintest.RunImportSuite(t, factory)
	case "roles":
		admintest.RunRoleSuite(t, factory)
	default:
		admintest.RunConformanceSuite(t, factory)
	}
}

// guard is one run of the suite against the toy store: the defect it
// carries, the part and the case it runs, and the case that must fail.
type guard struct {
	defect defect
	// part is "users", "import" or "roles" to run one part, empty for the
	// whole suite.
	part string
	// run is the -test.run pattern below TestBrokenAdminStore, empty for
	// every case of the part.
	run string
	// failing is the subtest path, below TestBrokenAdminStore, that must
	// fail; empty means the run must pass.
	failing string
}

// guards pairs every defect with the case written to catch it. Each runs only
// that case, so a failure is attributable to it, and the conforming store
// passing the whole suite shows the case fails for the defect and nothing
// else.
var guards = []guard{
	{defect: defectUnlockedCreate, run: "Users/CreateRace", failing: "Users/CreateRace"},
	{defect: defectUnlockedGrantReplace, run: "Roles/ConcurrentGrantReplace", failing: "Roles/ConcurrentGrantReplace"},
	{defect: defectUnlockedAssignment, run: "Roles/ConcurrentAssignment", failing: "Roles/ConcurrentAssignment"},
	{defect: defectUnlockedImport, run: "Import/ImportRace", failing: "Import/ImportRace"},
	{defect: defectImportRaceReportsUpdated, run: "Import/ImportRace", failing: "Import/ImportRace"},
	{defect: defectImportComparesNameOnly, run: "Import/ImportIdempotent", failing: "Import/ImportIdempotent/email"},
	{defect: defectImportComparesRoleCount, run: "Roles/ImportRoles", failing: "Roles/ImportRoles/role_swapped_for_another"},
	{defect: defectImportFoldsIdentifier, run: "Import/ImportIdentifierAsGiven", failing: "Import/ImportIdentifierAsGiven/an_upper-case_UUID"},
	{defect: defectImportRestoresDeleted, run: "Import/ImportDeletedUserRefused", failing: "Import/ImportDeletedUserRefused"},
	{defect: defectHandsPrimaryToLast, run: "Roles/RemovePrimaryHandsOver", failing: "Roles/RemovePrimaryHandsOver"},
	{defect: defectHandsPrimaryToLast, run: "Roles/ForcedRoleDelete", failing: "Roles/ForcedRoleDelete"},
	{defect: defectForcedDeleteKeepsVersions, run: "Roles/ForcedRoleDelete", failing: "Roles/ForcedRoleDelete"},
	{defect: defectSuperRoleStaysOnGrants, run: "Roles/SuperRoleReachesHolders", failing: "Roles/SuperRoleReachesHolders"},
	{defect: defectSuperRoleKeepsVersions, run: "Roles/SuperRoleReachesHolders", failing: "Roles/SuperRoleReachesHolders"},
	{defect: defectCountsDeletedHolders, run: "Roles/RoleHeldOnlyByDeletedUsers", failing: "Roles/RoleHeldOnlyByDeletedUsers"},
	{defect: defectIgnoresVersionOnUpdate, run: "Users/StaleUpdate", failing: "Users/StaleUpdate/UpdateUser"},
	{defect: defectNoopSetActiveSkipsVersion, run: "Users/StaleUpdate", failing: "Users/StaleUpdate/SetActive_to_the_flag_it_already_has"},
	{defect: defectDropsOrganizationOnCreate, run: "Users/OrganizationRoundTrip", failing: "Users/OrganizationRoundTrip"},
	{defect: defectKeepsOrganizationOnClear, run: "Users/OrganizationRoundTrip", failing: "Users/OrganizationRoundTrip"},
	{defect: defectDropsStartDate, run: "Roles/RemovePrimaryHandsOver", failing: "Roles/RemovePrimaryHandsOver"},
	{defect: defectUndatedUserRoles, run: "Roles/RemovePrimaryHandsOver", failing: "Roles/RemovePrimaryHandsOver"},
	{defect: defectIgnoresForgedCursor, run: "Users/ForgedIdentifiers", failing: "Users/ForgedIdentifiers/a_cursor's_identifier"},
	{defect: defectIgnoresForgedOrganization, run: "Users/ForgedIdentifiers", failing: "Users/ForgedIdentifiers/an_organization_on_create"},
	{defect: defectIgnoresForgedOrganization, run: "Users/ForgedIdentifiers", failing: "Users/ForgedIdentifiers/an_organization_on_update"},
	{defect: defectPagesByBytes, run: "Users/ListPagingOrder", failing: "Users/ListPagingOrder"},
	{defect: defectSetPasswordRecordsHistory, run: "Users/SetPasswordRecordsChange", failing: "Users/SetPasswordRecordsChange"},
	{defect: defectDeleteKeepsHistory, run: "Users/SoftDelete", failing: "Users/SoftDelete"},
	{defect: defectBlindEmailLoader, run: "Users/SoftDelete", failing: "Users/SoftDelete"},
	{defect: defectExactResourceOnReplace, run: "Roles/GrantNames", failing: "Roles/GrantNames/an_empty_list_for_another_spelling_of_a_resource_removes_its_grants"},
	{defect: defectDeletedWritable + "UpdateUser", run: "Users/DeletedUserWrites", failing: "Users/DeletedUserWrites/UpdateUser"},
	{defect: defectDeletedWritable + "SetActive", run: "Users/DeletedUserWrites", failing: "Users/DeletedUserWrites/SetActive"},
	{defect: defectDeletedWritable + "SetPassword", run: "Users/DeletedUserWrites", failing: "Users/DeletedUserWrites/SetPassword"},
	{defect: defectDeletedWritable + "CurrentPasswordHash", run: "Users/DeletedUserWrites", failing: "Users/DeletedUserWrites/CurrentPasswordHash"},
	{defect: defectDeletedWritable + "DeleteUser", run: "Users/DeletedUserWrites", failing: "Users/DeletedUserWrites/DeleteUser"},
	{defect: defectDeletedWritable + "RetirePassword", run: "Users/RetireAfterDeletion", failing: "Users/RetireAfterDeletion"},
	{defect: defectDeletedWritable + "ListAssignments", run: "Roles/DeletedUserAssignments", failing: "Roles/DeletedUserAssignments/ListAssignments"},
	{defect: defectDeletedWritable + "AddAssignment", run: "Roles/DeletedUserAssignments", failing: "Roles/DeletedUserAssignments/AddAssignment"},
	{defect: defectDeletedWritable + "RemoveAssignment", run: "Roles/DeletedUserAssignments", failing: "Roles/DeletedUserAssignments/RemoveAssignment"},
	{defect: defectDeletedWritable + "SetPrimary", run: "Roles/DeletedUserAssignments", failing: "Roles/DeletedUserAssignments/SetPrimary"},
}

// TestAdminSuiteIsLoadBearing checks the suite itself: the conforming toy
// store passes the whole suite, each part runs with only the ports it needs,
// and for every defect above the case written for it fails by assertion.
// Each run is its own process, because a failing suite reports through its
// own *testing.T.
func TestAdminSuiteIsLoadBearing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		guard  guard
		assert func(t *testing.T, err error, output string)
	}

	passes := func(why string) func(t *testing.T, err error, output string) {
		return func(t *testing.T, err error, output string) {
			t.Helper()
			require.NoError(t, err, "%s:\n%s", why, output)
			assert.NotContains(t, output, "--- FAIL", "%s:\n%s", why, output)
		}
	}

	cases := []testCase{
		{
			name:   "a conforming store passes the whole suite",
			guard:  guard{defect: defectNone},
			assert: passes("the suite rejected a conforming store, so every defect below may fail for the wrong reason"),
		},
		{
			name:  "the user part runs without role, grant, assignment or import ports",
			guard: guard{defect: variantUserPortsOnly, part: "users"},
			assert: passes("RunUserSuite required a port only the role or import part uses, so a store " +
				"implementing the user port alone cannot run it"),
		},
		{
			name:  "the import part runs without role, grant, assignment or provisioner ports",
			guard: guard{defect: variantImportPortsOnly, part: "import"},
			assert: passes("RunImportSuite required a port only the user or role part uses, so a store " +
				"implementing the import port alone cannot run it"),
		},
		{
			name:  "the role part refuses a fixture without role ports at the preflight",
			guard: guard{defect: variantUserPortsOnly, part: "roles"},
			assert: func(t *testing.T, err error, output string) {
				t.Helper()
				require.Error(t, err, "RunRoleSuite ran without the role ports:\n%s", output)
				assert.Contains(t, output, "admintest: the fixture returned no Roles port", output)
				assert.NotContains(t, output, "=== RUN   TestBrokenAdminStore/", "cases ran without the role ports")
			},
		},
	}

	for _, g := range guards {
		cases = append(cases, testCase{
			name:  string(g.defect) + " is caught by " + g.failing,
			guard: g,
			assert: func(t *testing.T, err error, output string) {
				t.Helper()
				require.Error(t, err, "the suite passed a store whose %s defect breaks a contract:\n%s", g.defect, output)
				assert.NotContains(t, output, "admintest: required hook",
					"the %s defect stopped the run at the preflight, so no case was shown to catch it", g.defect)
				assert.Contains(t, output, "--- FAIL: TestBrokenAdminStore/"+g.failing,
					"the case written for the %s defect did not fail by assertion:\n%s", g.defect, output)
				assert.NotContains(t, output, "panic:", "the run panicked rather than failing by assertion")
			},
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			output, err := runSuiteInProcess(t, tc.guard)
			tc.assert(t, err, output)
		})
	}
}

// runSuiteInProcess re-executes this test binary, running only the child test
// against the toy store carrying g's defect, and returns its combined output.
func runSuiteInProcess(t *testing.T, g guard) (string, error) {
	t.Helper()

	pattern := "^TestBrokenAdminStore$"
	if g.run != "" {
		parts := strings.Split(g.run, "/")
		for i, p := range parts {
			parts[i] = "^" + p + "$"
		}

		pattern += "/" + strings.Join(parts, "/")
	}

	//nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run="+pattern, "-test.count=1", "-test.v",
		"-test.timeout=5m")
	cmd.Env = append(os.Environ(), defectVar+"="+string(g.defect), partVar+"="+g.part)

	out, err := cmd.CombinedOutput()

	assert.NotContains(t, string(out), "--- SKIP: TestBrokenAdminStore ",
		"the child skipped rather than running the suite, so nothing was checked")
	assert.NotContains(t, string(out), "testing: warning: no tests to run",
		"the child's run pattern matched no case, so nothing was checked")

	return string(out), err
}
