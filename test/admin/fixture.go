// Package admintest holds the conformance suite for scrty's administration
// ports: admin.UserStore, admin.ImportStore, admin.RoleStore, admin.GrantStore
// and admin.AssignmentStore.
//
// It lives in scrty's test module, not in the admin package, so that no
// consumer's module graph gains it. A consumer implementing the ports over
// their own tables calls RunConformanceSuite from their own test, and the
// suite checks every contract the administration services rely on but cannot
// enforce themselves: versions, serialisation of concurrent writes, soft
// deletion, username and email uniqueness, import idempotence and the
// all-or-nothing grant replacement. RunUserSuite, RunImportSuite and
// RunRoleSuite run one part each.
//
// Every port and hook a part uses is required by that part. A hook the
// implementation cannot provide returns ErrHookUnsupported, and the run fails
// before any case, naming the hook; a case is never skipped for want of one.
// A port or hook only another part uses may be nil or unsupported, so an
// implementation of the user port alone runs RunUserSuite.
//
// One database may host a whole run, and cases run in parallel over it: every
// username, email, role name, attribute and search text the suite uses is
// unique to its case and to the run.
package admintest

import (
	"context"
	"errors"
	"testing"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

// Fixture is what an implementation offers the administration conformance
// suite: the five administration ports and the identity ports over the same
// records, plus the hooks the suite needs to observe state the ports do not
// return and to cause faults the ports cannot.
//
// Each Run function's godoc names the ports and hooks its part requires; a
// port no part being run uses may return nil.
//
// The hooks are the suite's requirement, not scrty's. A consumer's
// implementation satisfies them however its own storage allows.
//
// Faults injected through a hook must stay with the role they name, so that
// one case's fault is not every case's; the suite names a role unique to the
// case. A fixture removes whatever a hook installed when its test ends
// (t.Cleanup).
type Fixture interface {
	// Users returns the user administration port under test.
	Users() admin.UserStore
	// Importer returns the import port under test.
	Importer() admin.ImportStore
	// Roles returns the role administration port under test.
	Roles() admin.RoleStore
	// Grants returns the grant administration port under test.
	Grants() admin.GrantStore
	// Assignments returns the assignment port under test.
	Assignments() admin.AssignmentStore
	// Loader returns the identity user loader over the same records. The
	// suite checks through it that a deleted user loads as not found and that
	// a password change records its time.
	Loader() identity.UserLoader

	// Provisioner returns the identity provisioner over the same records. The
	// suite calls its Update as a login does, to check that a login-time
	// write moves the version an administrator read (StaleAfterLoginUpdate).
	// The user part requires it.
	Provisioner() identity.UserProvisioner

	// UserResidue reads what the store keeps of the user with the
	// identifier, live or soft-deleted, bypassing the deletion filter every
	// port applies. An identifier no record has returns a Residue with Exists
	// false and no error. The suite reads it to check what soft deletion
	// keeps and removes, and that a password change records no history of
	// its own. The user and import parts require it.
	UserResidue(ctx context.Context, id identity.UserID) (Residue, error)

	// FailGrantWrite makes every later ReplaceGrants for role fail as a
	// storage failure would, at the moment it writes the new grants of
	// group/resource: after it has removed that resource's old grants and
	// written every resource listed before it, inside its transaction. The
	// suite checks the role's grants and version are then exactly as before
	// (failure mode F3). A SQL fixture can install a trigger that raises on
	// an insert for that role and resource. The role part requires it.
	FailGrantWrite(ctx context.Context, role, group, resource string) error

	// SeedOrganization records an organization, so that a user referring to
	// it by identifier reads back with it. The administration ports refer to
	// organizations but never create one: the consumer's own administration
	// owns them. The suite seeds organizations whose identifiers are
	// canonical lower-case UUIDs, and, in the forged-identifier case, one
	// that is not: a fixture whose store cannot hold that identifier returns
	// an error, which the suite then expects the user port to refuse as
	// invalid input. The user part requires it.
	SeedOrganization(ctx context.Context, org *identity.Organization) error

	// StallGrantWrite makes the next ReplaceGrants for role block at the
	// moment it writes the new grants of group/resource, inside its
	// transaction, until that call's context is cancelled. The returned
	// channel is closed once the call is blocked there. The suite then
	// cancels the context and checks the call returns the context's error
	// and the role's grants and version are exactly as before (F33). A SQL
	// fixture can install a trigger that sleeps on that insert, and close the
	// channel once the session shows it waiting. The role part requires it.
	StallGrantWrite(ctx context.Context, role, group, resource string) (<-chan struct{}, error)
}

// HistorySeeder is the hook the user part seeds password history with, to
// check that soft deletion removes it. It is optional: a fixture that does not
// offer it is seeded through its user store's RetirePassword when that store
// implements password.History, and the user part fails its preflight, naming
// SeedPasswordHistory, when neither is offered. Either way, retiring a hash
// for a soft-deleted user must fail and record nothing.
//
// A password change does not record history through the user port: the
// password policy's reuse rule retires the replaced hash through the
// consumer's password.History, so the suite cannot obtain history any other
// way.
type HistorySeeder interface {
	// SeedPasswordHistory records hash as the newest retired password hash
	// of the live user with the identifier. For a soft-deleted user it
	// returns an error and records nothing, as a store's RetirePassword must:
	// a retire racing a deletion never writes history back (RetireAfterDeletion).
	SeedPasswordHistory(ctx context.Context, id identity.UserID, hash []byte) error
}

// Residue is what a store keeps of one user record, read by
// Fixture.UserResidue whether the user is live or soft-deleted.
type Residue struct {
	// Exists reports whether any record, live or deleted, has the identifier.
	Exists bool
	// Deleted reports whether the record is soft-deleted.
	Deleted bool
	// Active is the stored active flag.
	Active bool
	// Username is the stored username.
	Username string
	// Email is the stored email, empty when none.
	Email string
	// Attributes is the number of profile attributes stored for the user.
	Attributes int
	// PasswordHistory holds the hashes in the user's password history, in
	// any order: the retired hashes password.History records.
	PasswordHistory [][]byte
}

// Factory returns a Fixture for one case.
//
// The suite calls it per case. It may return a fresh, empty store each time,
// or a fixture over one database shared by the whole run, or by several runs:
// every case uses names unique to it and to the run.
type Factory func(t *testing.T) Fixture

// ErrHookUnsupported is what a hook returns when the implementation under
// test cannot provide it. The suite treats it as a missing hook and fails the
// run before any case, naming the hook, when a part being run uses it.
var ErrHookUnsupported = errors.New("admintest: hook not supported")
