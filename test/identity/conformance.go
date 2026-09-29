package identitytest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// The password-changed times the suite names through the ports. They are whole
// seconds in UTC, because a store may keep less than nanosecond precision, and
// the suite compares them with time.Time.Equal.
var (
	passwordChangedAt      = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	passwordChangedAtLater = time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC)
)

// The validity window the suite seeds on a role grant. No identity port sets
// these, which is why a rebuild must carry them across rather than mint them.
var (
	grantStart      = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	grantValidUntil = time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
)

// Fixture is what an implementation offers the conformance suite: the four
// identity ports, plus the hooks the suite needs to arrange state the ports
// cannot create and faults they cannot cause.
//
// The hooks are the suite's requirement, not scrty's. A consumer's
// implementation satisfies them however its own storage allows — an insert, a
// fixture file, a migration — so long as a later read through the ports sees the
// seeded state.
//
// Every hook is required. Before any case runs, the suite calls each hook once
// on a probe fixture; a seeding hook that returns ErrHookUnsupported, or a fault
// hook after which the port answers exactly as it does with no fault set, fails
// the run with a message naming the hook. How the port reports a fault that did
// reach it — as an error, not as a miss or as "not required" — is left to the
// named cases, so a store that swallows a fault fails the case written for it.
//
// A skipped case would be green in CI, and the implementations most likely to
// get a rule wrong are the ones most likely to leave out its hook.
//
// Every identifier the suite seeds — organization, group and grant — is a
// canonical lowercase UUID string, and every username, role name and
// identifier is unique to the case that uses it and to the run: each run draws
// its own random nonce into them. A factory may therefore hand every case a
// fixture over one shared database, and the cases still run in parallel; the
// database may also outlive the run, as a long-lived development database or
// one reused under go test -count=2 does, without a later run colliding with
// the rows an earlier one left behind. Faults injected through a fault hook
// must then stay with the fixture they were injected on, so that one case's
// outage is not every case's.
type Fixture interface {
	identity.UserProvisioner
	identity.UserLoader
	identity.RoleLoader
	identity.MFARequirementLookup

	// SeedRole records the privileges a role grants. It is required.
	SeedRole(ctx context.Context, role string, p []*identity.ResourcePrivileges) error

	// SeedMFARequired records whether a user must use a second factor. It is
	// required: no identity port writes the flag, because the consumer's own
	// user management owns it.
	SeedMFARequired(ctx context.Context, id identity.UserID, required bool) error

	// SeedRoleGrants replaces a user's role grants outright.
	//
	// A grant's identifier, super-role flag and validity window are set by the
	// consumer's own administration, never by an identity port: Provision creates
	// grants carrying only a name, an order and the primary flag. The suite seeds
	// them so that "the rebuild kept this grant's attributes" compares real
	// values rather than two zero values. It is required.
	SeedRoleGrants(ctx context.Context, username string, grants []*identity.AssignedRole) error

	// SeedOrganization records an organization and, when it has one, its group,
	// so that a user provisioned or updated with
	// identity.WithUserOrganization(&identity.Organization{ID: org.ID}) loads
	// the full organization.
	//
	// The suite treats an organization as a reference held by the user and
	// resolved by its identifier when the user is loaded: no identity port
	// creates one, because a consumer's own administration owns organizations.
	// A reference that names no seeded organization loads as no organization.
	// It is required.
	SeedOrganization(ctx context.Context, org *identity.Organization) error

	// FailUserLoads makes every later user load on this fixture fail with an
	// error matching err under errors.Is, so the suite can check that a backend
	// failure is distinguishable from "no such user". It is required.
	//
	// A fault hook needs no support from the backend: a fixture wraps its store
	// and, once the fault is set, returns err from LoadByUsername and
	// LoadByUserID instead of calling the store.
	FailUserLoads(err error)

	// FailMFALookups makes every later MFA requirement lookup on this fixture
	// fail with an error matching err under errors.Is, so the suite can check
	// that a lookup failure is reported as an error rather than as "not
	// required". It is required, and is satisfied the same way as FailUserLoads:
	// the fixture returns err from Required instead of calling the store.
	FailMFALookups(err error)
}

// Factory returns a Fixture for one case.
//
// The suite calls it per case. It may return a fresh, empty store each time, or
// a fixture over one database shared by the whole run, or by several runs:
// every case uses names unique to it and to the run, so no case sees state
// another case, or an earlier run, left behind. Faults injected
// through a fixture's fault hooks must not reach the fixtures of other cases.
type Factory func(t *testing.T) Fixture

// RunConformanceSuite checks an implementation of scrty's identity ports against
// every contract the library relies on.
//
// A consumer implementing the ports over their own user tables calls it from
// their own test:
//
//	func TestMyStoreConformance(t *testing.T) {
//	    identitytest.RunConformanceSuite(t, func(t *testing.T) identitytest.Fixture {
//	        return newMyStore(t)
//	    })
//	}
func RunConformanceSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture)

	t.Run("UserLoader", func(t *testing.T) { runUserLoaderSuite(t, newFixture) })
	t.Run("RoleLoader", func(t *testing.T) { runRoleLoaderSuite(t, newFixture) })
	t.Run("Provisioner", func(t *testing.T) { runProvisionerSuite(t, newFixture) })
	t.Run("MFALookup", func(t *testing.T) { runMFALookupSuite(t, newFixture) })
}

// requireUsableFixture fails the whole run, before any case, when the factory
// cannot produce a fixture or the fixture lacks a hook, so the reason is
// reported once and clearly rather than as a scatter of case failures.
func requireUsableFixture(t *testing.T, newFixture Factory) {
	t.Helper()

	require.NotNil(t, newFixture, "the suite needs a factory to build the implementation under test")

	f := newFixture(t)
	require.NotNil(t, f, "the factory returned no fixture, so no contract can be checked")

	requireEveryHook(t, f)
}

// errProbeFault is the fault the preflight injects through each fault hook.
var errProbeFault = errors.New("identitytest: probe fault")

// errFaultNotReached reports a fault hook after which the port answered
// exactly as it does with no fault set.
var errFaultNotReached = errors.New("the port answered as if no fault was set, so the fault did not reach it")

// requireEveryHook calls each hook of f once and fails the run, naming every
// hook that is missing. A seeding hook is missing when it answers
// ErrHookUnsupported; a fault hook is missing when the port call after it gives
// the answer it gives with no fault set. The fault hooks are probed last,
// because they leave f failing.
func requireEveryHook(t *testing.T, f Fixture) {
	t.Helper()

	ctx := t.Context()
	// Fresh names on every call: two parts run under one *testing.T over one
	// database each run this preflight, and must not meet each other's probe.
	salt := rand.Text()
	user := probeName(t, "probe", salt)

	probe, err := f.Provision(ctx, user)
	require.NoError(t, err, "identitytest: the preflight could not provision its probe user")
	require.NotNil(t, probe, "identitytest: the preflight's probe user was provisioned as nothing")

	hooks := []struct {
		name string
		call func() error
	}{
		{"SeedOrganization", func() error {
			return f.SeedOrganization(ctx, &identity.Organization{ID: uniqueID(t, "probe-org-"+salt), Name: "probe"})
		}},
		{"SeedRole", func() error {
			return f.SeedRole(ctx, probeName(t, "probe-role", salt), []*identity.ResourcePrivileges{{
				Group: "probe", Resource: "probe", Privileges: []identity.Privilege{{Name: "read", Granted: true}},
			}})
		}},
		{"SeedRoleGrants", func() error {
			return f.SeedRoleGrants(ctx, user, []*identity.AssignedRole{
				{ID: uniqueID(t, "probe-grant-"+salt), Name: "probe", Primary: true},
			})
		}},
		{"SeedMFARequired", func() error { return f.SeedMFARequired(ctx, probe.ID, true) }},
		// A fault hook is present when the port no longer gives its unfaulted
		// answer. Whether the port reports the fault correctly — as an error,
		// and not as a miss or as "not required" — is a contract of its own,
		// checked by a named case; judged here, a fail-open store would be
		// reported as a missing hook and the case written for it would never run.
		{"FailUserLoads", func() error {
			f.FailUserLoads(errProbeFault)
			// Unfaulted, the probe user loads.
			if _, err := f.LoadByUsername(ctx, user); err == nil {
				return errFaultNotReached
			}

			return nil
		}},
		{"FailMFALookups", func() error {
			f.FailMFALookups(errProbeFault)
			// Unfaulted, the probe user was seeded as required above.
			if required, err := f.Required(ctx, probe.ID); err == nil && required {
				return errFaultNotReached
			}

			return nil
		}},
	}

	for _, h := range hooks {
		switch err := h.call(); {
		case errors.Is(err, ErrHookUnsupported):
			t.Errorf("identitytest: required hook %s is missing", h.name)
		case errors.Is(err, errFaultNotReached):
			t.Errorf("identitytest: required hook %s is missing: %v", h.name, err)
		case err != nil:
			t.Errorf("identitytest: required hook %s failed on the preflight probe: %v", h.name, err)
		}
	}

	if t.Failed() {
		t.FailNow()
	}
}

// ErrHookUnsupported is what a seeding hook returns when the implementation
// under test cannot provide it. The suite treats it as a missing hook and fails
// the run before any case, naming the hook: every hook is required.
var ErrHookUnsupported = errors.New("identitytest: hook not supported")

// errBackendUnreachable stands in for a fault that is not a lookup miss.
var errBackendUnreachable = errors.New("identitytest: backend unreachable")

// RunUserLoaderSuite checks the user loader contract. Like RunConformanceSuite,
// it fails before any case when a hook is missing.
func RunUserLoaderSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture)
	runUserLoaderSuite(t, newFixture)
}

func runUserLoaderSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("Lookup", func(t *testing.T) { runUserLoaderCases(t, newFixture) })
	t.Run("Record", func(t *testing.T) { runLoadRecordCases(t, newFixture) })
	t.Run("Ownership", func(t *testing.T) { runLoadOwnershipCase(t, newFixture) })
	t.Run("LoadByUserID", func(t *testing.T) { runLoadByUserIDCases(t, newFixture) })
}

// runLoadOwnershipCase checks that a loaded record belongs to the caller.
//
// The library hands a loaded record onward — to the principal mapper, to a
// password check, to application code — and those callers treat it as a value
// of their own: they rewrite a field, wipe the password buffer once it has been
// verified, or keep the record in a cache. An implementation that returns a
// handle on its own state turns each of those into a write to the store, so
// verifying a password can destroy the stored hash and reading a record can
// move its user into another organization.
//
// The check is therefore a round trip: mutate everything the returned record
// reaches, then read the user again through the port and require the stored
// state to be exactly as it was.
func runLoadOwnershipCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	user := uniqueName(t, "owner", 0)

	org := fullOrganization(t)
	require.NoError(t, f.SeedOrganization(ctx, org))

	_, err := f.Provision(ctx, user,
		identity.WithUserName("Alice"),
		identity.WithUserPassword([]byte("H1")),
		identity.WithUserRoles("admin"),
		identity.WithUserOrganization(&identity.Organization{ID: org.ID}),
	)
	require.NoError(t, err)

	loaded, err := f.LoadByUsername(ctx, user)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	require.Len(t, loaded.Roles, 1)
	require.NotEmpty(t, loaded.Password)
	require.NotNil(t, loaded.Organization)
	require.NotNil(t, loaded.Organization.Group,
		"the suite needs a group to write through, so the record must carry the one provisioned")

	// A caller does with the record what a caller may: rewrite it, and wipe the
	// password buffer it has finished verifying.
	loaded.Name = "Rewritten"
	loaded.Roles[0].SuperRole = true
	loaded.Organization.ID = "o-victim"
	loaded.Organization.Group.Internal = false
	clear(loaded.Password)

	again, err := f.LoadByUsername(ctx, user)
	require.NoError(t, err)
	require.NotNil(t, again)

	assert.Equal(t, "Alice", again.Name,
		"a caller rewriting the record it was handed rewrote the stored user")
	assert.Equal(t, []byte("H1"), again.Password,
		"wiping the password buffer after verifying it destroyed the stored hash, so the user "+
			"can never sign in again")

	require.Len(t, again.Roles, 1)
	assert.False(t, again.Roles[0].SuperRole,
		"a caller made its own grant a super role by writing through the record it was handed")

	require.NotNil(t, again.Organization)
	assert.Equal(t, org.ID, again.Organization.ID,
		"a caller moved the stored user into another organization")

	require.NotNil(t, again.Organization.Group)
	assert.True(t, again.Organization.Group.Internal,
		"and rewrote the stored group")
}

// runLoadRecordCases checks that a loaded user carries the complete stored
// record, and that its organization is a reference resolved at load time.
//
// Authentication and authorization read what the loader returns and nothing
// else: a grant, validity window or group the loader leaves out is a rule the
// rest of the library silently stops applying. The grants are seeded with the
// primary one second, so a loader returning grants in stored order alone puts
// a non-primary role where callers look for the active one.
func runLoadRecordCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name    string
		arrange func(t *testing.T, ctx context.Context, f Fixture, user string)
		assert  func(t *testing.T, d *identity.Details)
	}

	cases := []testCase{
		{
			name: "a fully populated user loads every stored value, primary grant first",
			arrange: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				t.Helper()

				org := fullOrganization(t)
				require.NoError(t, f.SeedOrganization(ctx, org))

				mustProvision(ctx, t, f, user,
					identity.WithUserName("Ada"),
					identity.WithUserPasswordChange([]byte("H1"), passwordChangedAt),
					identity.WithUserRoles("auditor", "admin"),
					identity.WithUserOrganization(&identity.Organization{ID: org.ID}),
				)
				require.NoError(t, f.SeedRoleGrants(ctx, user, []*identity.AssignedRole{
					{ID: uniqueID(t, "grant-auditor"), Name: "auditor"},
					{
						ID:         uniqueID(t, "grant-admin"),
						Name:       "admin",
						Primary:    true,
						SuperRole:  true,
						StartDate:  grantStart,
						ValidUntil: grantValidUntil,
					},
				}))
			},
			assert: func(t *testing.T, d *identity.Details) {
				t.Helper()

				assert.NotEmpty(t, d.ID)
				assert.Equal(t, "Ada", d.Name)
				assert.Equal(t, []byte("H1"), d.Password, "the hash is returned byte for byte")
				assert.True(t, d.Active)
				assert.True(t, passwordChangedAt.Equal(d.PasswordChangedAt),
					"want the stored password-changed time %v, got %v",
					passwordChangedAt, d.PasswordChangedAt)

				require.Len(t, d.Roles, 2)

				primary := d.Roles[0]
				assert.Equal(t, "admin", primary.Name,
					"the primary grant is listed first, whatever its stored position: callers "+
						"take the first primary grant as the active role")
				assert.Equal(t, uniqueID(t, "grant-admin"), primary.ID)
				assert.True(t, primary.Primary)
				assert.True(t, primary.SuperRole)
				assert.True(t, grantStart.Equal(primary.StartDate),
					"want start date %v, got %v", grantStart, primary.StartDate)
				assert.True(t, grantValidUntil.Equal(primary.ValidUntil),
					"the store returns a validity window as stored; authorization decides "+
						"what it means. Want %v, got %v", grantValidUntil, primary.ValidUntil)

				other := d.Roles[1]
				assert.Equal(t, "auditor", other.Name)
				assert.Equal(t, uniqueID(t, "grant-auditor"), other.ID)
				assert.False(t, other.Primary)
				assert.False(t, other.SuperRole)

				assert.Equal(t, fullOrganization(t), d.Organization,
					"the organization is resolved from the reference, with its group")
			},
		},
		{
			name: "an organization without a group loads with no group",
			arrange: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				t.Helper()

				org := &identity.Organization{ID: uniqueID(t, "org"), Name: "solo"}
				require.NoError(t, f.SeedOrganization(ctx, org))
				mustProvision(ctx, t, f, user, identity.WithUserOrganization(&identity.Organization{ID: org.ID}))
			},
			assert: func(t *testing.T, d *identity.Details) {
				t.Helper()

				require.NotNil(t, d.Organization)
				assert.Equal(t, uniqueID(t, "org"), d.Organization.ID)
				assert.Equal(t, "solo", d.Organization.Name)
				assert.Nil(t, d.Organization.Group,
					"an organization in no group is not given an empty one")
			},
		},
		{
			name: "an organization reference that resolves to nothing loads as no organization",
			arrange: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				t.Helper()

				mustProvision(ctx, t, f, user,
					identity.WithUserOrganization(&identity.Organization{ID: uniqueID(t, "dangling")}))
			},
			assert: func(t *testing.T, d *identity.Details) {
				t.Helper()

				assert.Nil(t, d.Organization,
					"a reference naming no stored organization is not an organization: a "+
						"record carrying a bare identifier would read as a real, nameless one")
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "record", i)

			tc.arrange(t, ctx, f, user)

			d := mustLoad(ctx, t, f, user)
			assert.Equal(t, user, d.Username)
			tc.assert(t, d)
		})
	}
}

// fullOrganization is an organization in a group, with identifiers unique to
// the calling case.
func fullOrganization(t *testing.T) *identity.Organization {
	t.Helper()

	return &identity.Organization{
		ID:   uniqueID(t, "org"),
		Name: "acme",
		Group: &identity.Group{
			ID:       uniqueID(t, "group"),
			Name:     "partners",
			Internal: true,
		},
	}
}

func runUserLoaderCases(t *testing.T, newFixture Factory) {
	t.Helper()

	// Each case receives a username unique to it; seed and lookup derive the
	// names they provision and load from it.
	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture, user string)
		lookup func(user string) string
		assert func(t *testing.T, user string, d *identity.Details, err error)
	}

	same := func(user string) string { return user }

	cases := []testCase{
		{
			name: "the username reaches the loader exactly as presented",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				_, err := f.Provision(ctx, " "+user+"@Example.COM")
				require.NoError(t, err)
			},
			lookup: func(user string) string { return " " + user + "@Example.COM" },
			assert: func(t *testing.T, user string, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.Equal(t, " "+user+"@Example.COM", d.Username,
					"the username is never trimmed or case-folded on the way in or out")
			},
		},
		{
			name: "a username differing only in case is a different user",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				_, err := f.Provision(ctx, "abc-"+user)
				require.NoError(t, err)
			},
			lookup: func(user string) string { return strings.ToUpper("abc-" + user) },
			assert: func(t *testing.T, _ string, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"case-folding the lookup would let one user sign in as another")
				assert.Nil(t, d)
			},
		},
		{
			name: "a username provisioned capitalised is not found in lower case",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				_, err := f.Provision(ctx, "Alice-"+user)
				require.NoError(t, err)
			},
			lookup: func(user string) string { return "alice-" + user },
			assert: func(t *testing.T, _ string, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"the store matches exactly as given; normalising a username is the "+
						"consumer's decision, made before it calls the store")
				assert.Nil(t, d)
			},
		},
		{
			name:   "an unknown username is identifiable as a miss",
			lookup: same,
			assert: func(t *testing.T, _ string, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, d)
			},
		},
		{
			name: "a backend failure is not reported as a miss",
			seed: func(_ *testing.T, _ context.Context, f Fixture, _ string) {
				f.FailUserLoads(errBackendUnreachable)
			},
			lookup: same,
			assert: func(t *testing.T, _ string, d *identity.Details, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound,
					"a store that is down must not read as 'no such user': the caller would "+
						"treat an outage as a failed login and count it against the user")
				assert.Nil(t, d)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "lookup", i)

			if tc.seed != nil {
				tc.seed(t, ctx, f, user)
			}

			d, err := f.LoadByUsername(ctx, tc.lookup(user))
			tc.assert(t, user, d, err)
		})
	}
}

// runLoadByUserIDCases checks the load-by-reference contract: a reference is
// opaque and matched byte for byte, never trimmed or case-folded.
func runLoadByUserIDCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		lookup func(created identity.UserID) identity.UserID
		assert func(t *testing.T, created identity.UserID, d *identity.Details, err error)
	}

	cases := []testCase{
		{
			name:   "an existing reference loads details carrying exactly that reference",
			lookup: func(created identity.UserID) identity.UserID { return created },
			assert: func(t *testing.T, created identity.UserID, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.Equal(t, created, d.ID, "the reference is returned byte for byte")
			},
		},
		{
			name:   "an unknown reference is user not found",
			lookup: func(identity.UserID) identity.UserID { return "no-such-user" },
			assert: func(t *testing.T, _ identity.UserID, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
		{
			name: "a case-folded reference is user not found",
			lookup: func(created identity.UserID) identity.UserID {
				return identity.UserID(swapCase(string(created)))
			},
			assert: func(t *testing.T, _ identity.UserID, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"a reference is opaque: one that differs only in case names another user")
			},
		},
		{
			name:   "a reference with a trailing space is not trimmed",
			lookup: func(created identity.UserID) identity.UserID { return created + " " },
			assert: func(t *testing.T, _ identity.UserID, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			created, err := f.Provision(t.Context(), uniqueName(t, "byid", i)+"@example.com")
			require.NoError(t, err)

			d, err := f.LoadByUserID(t.Context(), tc.lookup(created.ID))
			tc.assert(t, created.ID, d, err)
		})
	}
}

// swapCase inverts the case of every letter in s, so the result differs from s
// wherever s has letters to invert. A generated reference that carries no
// letters at all would leave a naive swap unchanged, which would make the
// "case-folded" row indistinguishable from the "existing reference" row and
// prove nothing; appending a letter-bearing suffix in that case keeps the
// result different from s while still asserting the not-found outcome.
func swapCase(s string) string {
	out := []rune(s)
	changed := false

	for i, r := range out {
		switch {
		case unicode.IsUpper(r):
			out[i] = unicode.ToLower(r)
			changed = true
		case unicode.IsLower(r):
			out[i] = unicode.ToUpper(r)
			changed = true
		}
	}

	if !changed {
		return s + "X"
	}

	return string(out)
}

// RunRoleLoaderSuite checks the role loader contract. Like RunConformanceSuite,
// it fails before any case when a hook is missing.
func RunRoleLoaderSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture)
	runRoleLoaderSuite(t, newFixture)
}

func runRoleLoaderSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("Privileges", func(t *testing.T) { runRoleLoaderCases(t, newFixture) })
	t.Run("Ownership", func(t *testing.T) { runPrivilegesOwnershipCase(t, newFixture) })
}

// runPrivilegesOwnershipCase checks that loaded privileges belong to the caller.
//
// Privileges are read on the request path and cached, so a reader that is
// handed the store's own rows can grant itself a privilege the role was refused,
// or repoint a row at another resource, for every later request in the process.
func runPrivilegesOwnershipCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	role := uniqueName(t, "clerk", 0)

	require.NoError(t, f.SeedRole(ctx, role, []*identity.ResourcePrivileges{{
		Group:    "billing",
		Resource: "invoice",
		Privileges: []identity.Privilege{
			{Name: "read", Granted: true},
			{Name: "delete", Granted: false},
		},
	}}))

	got, err := f.LoadPrivileges(ctx, role)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].Privileges, 2,
		"the suite needs the refused privilege to write through, so it must be carried")

	// No order is promised inside a group, so each entry is rewritten by what
	// it is rather than where it sits: the granted one renamed, the refused one
	// granted.
	got[0].Resource = "payment"

	for i := range got[0].Privileges {
		if got[0].Privileges[i].Granted {
			got[0].Privileges[i].Name = "write"
		} else {
			got[0].Privileges[i].Granted = true
		}
	}

	again, err := f.LoadPrivileges(ctx, role)
	require.NoError(t, err)
	require.Len(t, again, 1)

	assert.Equal(t, "invoice", again[0].Resource,
		"a reader rewrote which resource the stored row is about")
	assert.ElementsMatch(t, []identity.Privilege{
		{Name: "read", Granted: true},
		{Name: "delete", Granted: false},
	}, again[0].Privileges,
		"a reader renamed a privilege on the stored row, or granted itself one the role is refused")
}

func runRoleLoaderCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture, role string)
		assert func(t *testing.T, p []*identity.ResourcePrivileges, err error)
	}

	cases := []testCase{
		{
			name: "a role returns the privileges it grants, including the ones it is refused",
			seed: func(t *testing.T, ctx context.Context, f Fixture, role string) {
				require.NoError(t, f.SeedRole(ctx, role, []*identity.ResourcePrivileges{{
					Group:    "billing",
					Resource: "invoice",
					Privileges: []identity.Privilege{
						{Name: "read", Granted: true},
						{Name: "delete", Granted: false},
					},
				}}))
			},
			assert: func(t *testing.T, p []*identity.ResourcePrivileges, err error) {
				require.NoError(t, err)
				require.Len(t, p, 1)
				assert.Equal(t, "billing", p[0].Group)
				assert.Equal(t, "invoice", p[0].Resource)
				// No order is promised inside a group.
				assert.ElementsMatch(t, []identity.Privilege{
					{Name: "read", Granted: true},
					{Name: "delete", Granted: false},
				}, p[0].Privileges,
					"a privilege that is not granted is carried as refused rather than filtered "+
						"away, so a caller can tell 'refused' apart from 'not mentioned'; a loader "+
						"that drops it makes the two indistinguishable")
			},
		},
		{
			// Seeded out of order, so a loader returning stored order fails.
			name: "privileges are grouped by resource group, then by resource",
			seed: func(t *testing.T, ctx context.Context, f Fixture, role string) {
				require.NoError(t, f.SeedRole(ctx, role, []*identity.ResourcePrivileges{
					{
						Group: "billing", Resource: "invoice",
						Privileges: []identity.Privilege{
							{Name: "read", Granted: true},
							{Name: "export", Granted: false},
						},
					},
					{
						Group: "accounts", Resource: "ledger",
						Privileges: []identity.Privilege{{Name: "read", Granted: true}},
					},
					{
						Group: "accounts", Resource: "journal",
						Privileges: []identity.Privilege{{Name: "read", Granted: true}},
					},
				}))
			},
			assert: func(t *testing.T, p []*identity.ResourcePrivileges, err error) {
				require.NoError(t, err)

				got := make([]string, 0, len(p))
				for _, e := range p {
					got = append(got, e.Group+"/"+e.Resource)
				}

				assert.Equal(t, []string{"accounts/journal", "accounts/ledger", "billing/invoice"}, got,
					"groups are ordered by resource group and then resource, so two stores "+
						"answer the same role alike")
			},
		},
		{
			name: "a role granting nothing is identifiable as such",
			assert: func(t *testing.T, p []*identity.ResourcePrivileges, err error) {
				require.ErrorIs(t, err, identity.ErrPrivilegesNotFound)
				assert.Empty(t, p)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			role := uniqueName(t, "role", i)

			if tc.seed != nil {
				tc.seed(t, ctx, f, role)
			}

			p, err := f.LoadPrivileges(ctx, role)
			tc.assert(t, p, err)
		})
	}
}

// RunProvisionerSuite checks the create-only and amend contracts. Like
// RunConformanceSuite, it fails before any case when a hook is missing.
func RunProvisionerSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture)
	runProvisionerSuite(t, newFixture)
}

func runProvisionerSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	t.Run("Provision", func(t *testing.T) { runProvisionCases(t, newFixture) })
	t.Run("Concurrent", func(t *testing.T) { runProvisionRaceCase(t, newFixture) })
	t.Run("Update", func(t *testing.T) { runUpdateCases(t, newFixture) })
	t.Run("Roles", func(t *testing.T) { runRoleRebuildCases(t, newFixture) })
	t.Run("ConcurrentRoles", func(t *testing.T) { runRoleRebuildRaceCase(t, newFixture) })
	t.Run("ProvisionOwnership", func(t *testing.T) { runProvisionOwnershipCase(t, newFixture) })
	t.Run("UpdateOwnership", func(t *testing.T) { runUpdateOwnershipCase(t, newFixture) })
	t.Run("PasswordChangedAt", func(t *testing.T) { runPasswordChangedAtCases(t, newFixture) })
}

// runPasswordChangedAtCases checks that the password-changed time is written
// only when the caller names it, through the ports alone.
//
// The time is what password-age policy reads. A store that stamps it whenever a
// password is written lets a password mirrored from an identity provider on
// every login keep its user fresh forever; a store that ignores a named time
// leaves a local change unrecorded, and the policy inert. Each case sets the
// time through the ports, so a store that never writes it fails the cases that
// read it back rather than comparing zero with zero.
func runPasswordChangedAtCases(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		act    func(t *testing.T, ctx context.Context, f Fixture, user string) *identity.Details
		assert func(t *testing.T, got *identity.Details)
	}

	isRecorded := func(t *testing.T, got *identity.Details) {
		t.Helper()
		assert.True(t, passwordChangedAt.Equal(got.PasswordChangedAt),
			"want the recorded time %v, got %v", passwordChangedAt, got.PasswordChangedAt)
	}
	isLater := func(t *testing.T, got *identity.Details) {
		t.Helper()
		assert.True(t, passwordChangedAtLater.Equal(got.PasswordChangedAt),
			"want the named time %v, got %v", passwordChangedAtLater, got.PasswordChangedAt)
	}
	isZero := func(t *testing.T, got *identity.Details) {
		t.Helper()
		assert.True(t, got.PasswordChangedAt.IsZero(),
			"want no password-changed time, got %v", got.PasswordChangedAt)
	}
	// isLaterWithPassword and isZeroWithPassword also check the stored password.
	// The time and the password travel in one write, so a store could get the
	// time right and lose the password (or the reverse); checking the time alone
	// would let that store pass.
	isLaterWithPassword := func(want []byte) func(t *testing.T, got *identity.Details) {
		return func(t *testing.T, got *identity.Details) {
			t.Helper()
			isLater(t, got)
			assert.Equal(t, want, got.Password,
				"want the stored password %q, got %q", want, got.Password)
		}
	}
	isZeroWithPassword := func(want []byte) func(t *testing.T, got *identity.Details) {
		return func(t *testing.T, got *identity.Details) {
			t.Helper()
			isZero(t, got)
			assert.Equal(t, want, got.Password,
				"want the stored password %q, got %q", want, got.Password)
		}
	}

	cases := []testCase{
		{
			name: "provision naming only the password leaves the time zero",
			act: func(t *testing.T, ctx context.Context, f Fixture, user string) *identity.Details {
				return mustProvision(ctx, t, f, user, identity.WithUserPassword([]byte("H1")))
			},
			assert: isZero,
		},
		{
			name: "provision naming the password and the time records the time",
			act: func(t *testing.T, ctx context.Context, f Fixture, user string) *identity.Details {
				return mustProvision(ctx, t, f, user,
					identity.WithUserPasswordChange([]byte("H1"), passwordChangedAtLater))
			},
			assert: isLaterWithPassword([]byte("H1")),
		},
		{
			name: "update naming only the password leaves a recorded time",
			act: func(t *testing.T, ctx context.Context, f Fixture, user string) *identity.Details {
				mustProvision(ctx, t, f, user, identity.WithUserPasswordChange([]byte("H1"), passwordChangedAt))
				return mustUpdate(ctx, t, f, user, identity.WithUserPassword([]byte("H2")))
			},
			assert: isRecorded,
		},
		{
			// A store that stamps the time whenever it is unset rather than only
			// when the caller names it — for example a SQL default of
			// COALESCE(password_changed_at, now()) — would pass every case above,
			// because each of them provisions with a time already recorded. This
			// case starts from no recorded time at all, so such a store stamps a
			// time the caller never named.
			name: "update naming only the password on a user with no recorded time leaves it zero",
			act: func(t *testing.T, ctx context.Context, f Fixture, user string) *identity.Details {
				mustProvision(ctx, t, f, user, identity.WithUserPassword([]byte("H1")))
				return mustUpdate(ctx, t, f, user, identity.WithUserPassword([]byte("H2")))
			},
			assert: isZeroWithPassword([]byte("H2")),
		},
		{
			name: "update naming the password and the time records the time",
			act: func(t *testing.T, ctx context.Context, f Fixture, user string) *identity.Details {
				mustProvision(ctx, t, f, user, identity.WithUserPasswordChange([]byte("H1"), passwordChangedAt))
				return mustUpdate(ctx, t, f, user,
					identity.WithUserPasswordChange([]byte("H2"), passwordChangedAtLater))
			},
			assert: isLaterWithPassword([]byte("H2")),
		},
		{
			name: "update naming the zero time clears it",
			act: func(t *testing.T, ctx context.Context, f Fixture, user string) *identity.Details {
				mustProvision(ctx, t, f, user, identity.WithUserPasswordChange([]byte("H1"), passwordChangedAt))
				return mustUpdate(ctx, t, f, user, identity.WithUserPasswordChangedAt(time.Time{}))
			},
			assert: isZero,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "pwtime", i)

			got := tc.act(t, ctx, f, user)
			tc.assert(t, got)
			// The stored value, not only the one handed back.
			tc.assert(t, mustLoad(ctx, t, f, user))
		})
	}
}

// mustProvision creates user through the port, failing the case on an error.
func mustProvision(ctx context.Context, t *testing.T, f Fixture, user string, opts ...identity.UserOption) *identity.Details {
	t.Helper()

	d, err := f.Provision(ctx, user, opts...)
	require.NoError(t, err)
	require.NotNil(t, d)

	return d
}

// mustUpdate amends user through the port, failing the case on an error.
func mustUpdate(ctx context.Context, t *testing.T, f Fixture, user string, opts ...identity.UserOption) *identity.Details {
	t.Helper()

	d, err := f.Update(ctx, user, opts...)
	require.NoError(t, err)
	require.NotNil(t, d)

	return d
}

// atUTC returns a copy of d with every time in UTC, so that two records holding
// the same instants compare equal whatever location each was read in: the
// contracts store an instant, and a store may report it in its session's zone.
func atUTC(d *identity.Details) *identity.Details {
	if d == nil {
		return nil
	}

	out := *d
	out.PasswordChangedAt = d.PasswordChangedAt.UTC()
	out.Roles = make([]*identity.AssignedRole, 0, len(d.Roles))

	for _, r := range d.Roles {
		rc := *r
		rc.StartDate = r.StartDate.UTC()
		rc.ValidUntil = r.ValidUntil.UTC()
		out.Roles = append(out.Roles, &rc)
	}

	return &out
}

// mustLoad reads user back through the loader, failing the case on an error.
func mustLoad(ctx context.Context, t *testing.T, f Fixture, user string) *identity.Details {
	t.Helper()

	d, err := f.LoadByUsername(ctx, user)
	require.NoError(t, err)
	require.NotNil(t, d)

	return d
}

// uniqueName returns a username no other case uses, in this run or any other,
// short enough to fit a consumer's own username column — the suite runs over
// the consumer's own tables, which may be no wider than varchar(64).
//
// The full test name is not usable directly: nested subtests make it grow
// past 100 characters, so instead the name is built from prefix (kept to 12
// characters or fewer by its caller), a 12-hex-character fingerprint of the
// case, and the case's own index. The fingerprint keeps cases independent even
// when several share a store and run in parallel or as nested subtests,
// without the result growing with nesting depth; the bound is prefix (<=12) +
// "-" + 12 hex characters + "-" + the index, well under 64 characters for any i
// this suite generates.
func uniqueName(t *testing.T, prefix string, i int) string {
	t.Helper()

	sum := caseFingerprint(t, "")

	return prefix + "-" + hex.EncodeToString(sum[:])[:12] + "-" + strconv.Itoa(i)
}

// probeName returns a name for a preflight probe, unique to the preflight call
// that drew salt as well as to the case and run: a test that runs two parts of
// the suite under one *testing.T runs two preflights with one test name and one
// run nonce. It has the length bound of uniqueName.
func probeName(t *testing.T, prefix, salt string) string {
	t.Helper()

	sum := caseFingerprint(t, salt)

	return prefix + "-" + hex.EncodeToString(sum[:])[:12]
}

// blankName returns a username of spaces and tabs only, unique to the calling
// case and run: the bits of the case's fingerprint choose between the two, so
// the username stays blank while no other case can produce it.
func blankName(t *testing.T) string {
	t.Helper()

	sum := caseFingerprint(t, "")

	var b strings.Builder

	for _, c := range sum[:5] {
		for bit := range 8 {
			if c&(1<<bit) != 0 {
				b.WriteByte('\t')
			} else {
				b.WriteByte(' ')
			}
		}
	}

	return b.String()
}

// uniqueID returns an identifier for a seeded organization, group or grant that
// no other case uses, in this run or any other, formatted as a canonical
// lowercase UUID string so a store keying those rows on a UUID column can hold
// it. The same test and label give the same identifier for as long as the test
// runs, so a case can compute it again when it asserts.
func uniqueID(t *testing.T, label string) string {
	t.Helper()

	sum := caseFingerprint(t, label)
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x80 // version 8: a name-derived identifier
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 9562 variant

	h := hex.EncodeToString(b)

	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// caseFingerprint hashes the case's full test name, a nonce drawn for this run
// of the test, and label.
//
// The test name alone is the same on every run, so a factory handing the suite
// a database that outlives the run — a long-lived development database, or any
// database under go test -count=2 — would meet the previous run's rows under
// the same names: user-already-exists where the case expects a fresh user, and
// another run's grants. A nonce per process is not enough either, because
// -count=2 repeats every test inside one process. So the nonce belongs to the
// *testing.T: every run of every test draws its own, and a case sees the same
// one for as long as it runs.
func caseFingerprint(t *testing.T, label string) [sha256.Size]byte {
	t.Helper()

	return sha256.Sum256([]byte(runNonce(t) + "\x00" + t.Name() + "\x00" + label))
}

// runNonces holds the nonce of each running test, keyed by its *testing.T and
// removed when the test ends.
var runNonces sync.Map

// runNonce returns the nonce of this run of t, drawing it from crypto/rand on
// first use.
func runNonce(t *testing.T) string {
	t.Helper()

	if n, ok := runNonces.Load(t); ok {
		return n.(string)
	}

	n, loaded := runNonces.LoadOrStore(t, rand.Text())
	if !loaded {
		t.Cleanup(func() { runNonces.Delete(t) })
	}

	return n.(string)
}

// runProvisionOwnershipCase checks that a created user is the store's own copy
// in both directions.
//
// A caller hands Provision a password hash and an organization it built, and
// goes on using both: it wipes the hash buffer once the credential has been
// used, and reuses the organization value for the next user. A store that keeps
// those pointers is rewritten by every such use — a routine wipe destroys the
// stored hash, so the user can never sign in. In the other direction, the
// record Provision returns is the caller's to amend before handing it on.
func runProvisionOwnershipCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	user := uniqueName(t, "owner", 0)

	hash := []byte("argon2id$hash")
	org := fullOrganization(t)
	orgID := org.ID
	require.NoError(t, f.SeedOrganization(ctx, org))

	created, err := f.Provision(ctx, user,
		identity.WithUserPassword(hash),
		identity.WithUserOrganization(org),
		identity.WithUserRoles("admin"),
	)
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Len(t, created.Roles, 1)

	// The caller wipes the buffer it owns, as credential hygiene requires, and
	// reuses the organization value it built.
	clear(hash)
	org.ID = "o-victim"

	// And amends the record it was handed.
	created.Name = "Rewritten"
	created.Roles[0].SuperRole = true

	require.NotNil(t, created.Organization,
		"Provision returns the complete stored record, and the user was created in a seeded "+
			"organization")
	created.Organization.ID = "o-rewritten"

	stored, err := f.LoadByUsername(ctx, user)
	require.NoError(t, err)
	require.NotNil(t, stored)

	assert.Equal(t, []byte("argon2id$hash"), stored.Password,
		"the caller wiping its own buffer wiped the stored hash, so the user can never sign in")
	assert.Empty(t, stored.Name,
		"amending the returned record rewrote the stored user; the record a write returns is "+
			"the caller's, not a handle on the store")

	require.Len(t, stored.Roles, 1)
	assert.False(t, stored.Roles[0].SuperRole,
		"and made the stored grant a super role")

	require.NotNil(t, stored.Organization)
	assert.Equal(t, orgID, stored.Organization.ID,
		"the caller reusing the organization value it built moved the stored user")
}

// runUpdateOwnershipCase checks the same ownership rule for an amendment: the
// values the caller named stay the caller's, and the record returned is a copy.
func runUpdateOwnershipCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	ctx := t.Context()
	f := newFixture(t)
	user := uniqueName(t, "owner", 0)

	_, err := f.Provision(ctx, user, identity.WithUserRoles("admin"))
	require.NoError(t, err)

	hash := []byte("argon2id$new")
	org := fullOrganization(t)
	orgID := org.ID
	require.NoError(t, f.SeedOrganization(ctx, org))

	updated, err := f.Update(ctx, user,
		identity.WithUserName("Alice"),
		identity.WithUserPassword(hash),
		identity.WithUserOrganization(org),
	)
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.Len(t, updated.Roles, 1,
		"the update named no roles, so the record returned carries the stored grant")

	clear(hash)
	org.ID = "o-victim"

	updated.Name = "Rewritten"
	updated.Roles[0].SuperRole = true

	if updated.Organization != nil {
		updated.Organization.ID = "o-rewritten"
	}

	stored, err := f.LoadByUsername(ctx, user)
	require.NoError(t, err)
	require.NotNil(t, stored)

	assert.Equal(t, []byte("argon2id$new"), stored.Password,
		"the caller wiping its own buffer wiped the stored hash")
	assert.Equal(t, "Alice", stored.Name,
		"amending the returned record rewrote the stored user")

	require.Len(t, stored.Roles, 1)
	assert.False(t, stored.Roles[0].SuperRole,
		"and made the stored grant a super role")

	require.NotNil(t, stored.Organization)
	assert.Equal(t, orgID, stored.Organization.ID,
		"the caller reusing the organization value it named moved the stored user")
}

// runRoleRebuildRaceCase checks that concurrent updates of one user are
// serialized.
//
// Rebuilding grants is a read-modify-write: read the stored grants, work out
// which survive, write the new set. Two callers doing that at once against the
// same user can interleave so that each decides from the state it read, and the
// loser's decision is computed from grants that no longer exist. The visible
// result is a merge that neither caller asked for — both roles present, or
// neither — which is a privilege change nobody requested.
//
// One update revokes admin in favour of viewer while another re-asserts admin.
// Either outcome is correct, because either caller may win; a blend of the two
// is not.
//
// Counting the surviving grants cannot tell the two apart: each caller asks for
// exactly one role, so every interleaving leaves exactly one grant. What
// distinguishes them is the surviving grant's own attributes. Under any
// serialized ordering the second write rebuilds from the first write's result,
// which holds only the other caller's role, so the surviving grant is minted
// fresh: it carries neither the seeded identifier, nor the seeded validity
// window, nor the super-role flag. A grant that comes back still carrying them
// was rebuilt from a state the other caller had already replaced — a lost
// update, or a revoked super role restored — and no serialized ordering can
// produce it.
//
// The race is run several times over a fresh user, so a window that opens only
// sometimes is still found; run the suite with -race -count=10 to widen it
// further.
func runRoleRebuildRaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	const rounds = 4

	for round := range rounds {
		ctx := t.Context()
		f := newFixture(t)
		user := uniqueName(t, "race", round)

		// The identifiers seeded on each grant, so that "the survivor was minted
		// fresh" compares real values rather than two zero values.
		seeded := map[string]string{
			"admin":  uniqueID(t, "grant-admin-"+strconv.Itoa(round)),
			"viewer": uniqueID(t, "grant-viewer-"+strconv.Itoa(round)),
		}

		_, err := f.Provision(ctx, user)
		require.NoError(t, err, "round %d", round)
		require.NoError(t, f.SeedRoleGrants(ctx, user, []*identity.AssignedRole{
			{
				ID:         seeded["admin"],
				Name:       "admin",
				Primary:    true,
				SuperRole:  true,
				StartDate:  grantStart,
				ValidUntil: grantValidUntil,
			},
			{
				ID:         seeded["viewer"],
				Name:       "viewer",
				StartDate:  grantStart,
				ValidUntil: grantValidUntil,
			},
		}), "round %d", round)

		var wg sync.WaitGroup

		start := make(chan struct{})

		wg.Add(2)

		go func() {
			defer wg.Done()

			<-start

			_, _ = f.Update(ctx, user, identity.WithUserRoles("viewer"))
		}()

		go func() {
			defer wg.Done()

			<-start

			_, _ = f.Update(ctx, user, identity.WithUserRoles("admin"))
		}()

		close(start)
		wg.Wait()

		final, err := f.LoadByUsername(ctx, user)
		require.NoError(t, err, "round %d", round)
		require.Len(t, final.Roles, 1,
			"round %d: each caller asked for exactly one role, so the final grants must be one "+
				"caller's set and not a blend", round)

		got := final.Roles[0]

		require.Contains(t, seeded, got.Name,
			"round %d: the surviving grant must be one of the two that were requested", round)
		assert.True(t, got.Primary,
			"round %d: the surviving grant is the first of its caller's list, so it carries the "+
				"primary flag", round)

		assert.NotEqual(t, seeded[got.Name], got.ID,
			"round %d: %q survived carrying the identifier it held before either caller wrote, so "+
				"its rebuild read grants the other caller had already replaced: a serialized "+
				"second write finds no grant of that name and mints a new one",
			round, got.Name)
		assert.False(t, got.SuperRole,
			"round %d: %q survived as a super role although the other caller had revoked it; no "+
				"serialized ordering restores a revoked grant's privileges",
			round, got.Name)
		assert.True(t, got.StartDate.IsZero(),
			"round %d: %q survived carrying the validity window seeded before either caller "+
				"wrote, so the losing caller's decision was computed from grants that no longer "+
				"existed", round, got.Name)
		assert.True(t, got.ValidUntil.IsZero(),
			"round %d: %q survived carrying the valid-until date seeded before either caller "+
				"wrote", round, got.Name)
	}
}

func runRoleRebuildCases(t *testing.T, newFixture Factory) {
	t.Helper()

	// opts, when set, replaces the update the case makes, which is otherwise
	// one naming roles.
	type testCase struct {
		name   string
		seed   func(t *testing.T, ctx context.Context, f Fixture, user string)
		roles  []string
		opts   []identity.UserOption
		assert func(t *testing.T, d *identity.Details, err error)
	}

	// seedGranted gives the user a super-role admin with a validity window, and a
	// plain viewer. Neither the identifier, the super-role flag nor the dates can
	// be set through an identity port, which is exactly why a rebuild must carry
	// them across instead of minting fresh grants.
	seedGranted := func(t *testing.T, ctx context.Context, f Fixture, user string) {
		t.Helper()

		_, err := f.Provision(ctx, user)
		require.NoError(t, err)
		require.NoError(t, f.SeedRoleGrants(ctx, user, []*identity.AssignedRole{
			{
				ID:         uniqueID(t, "grant-admin"),
				Name:       "admin",
				Primary:    true,
				SuperRole:  true,
				StartDate:  grantStart,
				ValidUntil: grantValidUntil,
			},
			{ID: uniqueID(t, "grant-viewer"), Name: "viewer"},
		}))
	}

	// assertUntouched checks the grants seedGranted wrote, attribute by
	// attribute: a caller naming no usable role asked for no change, so a store
	// that re-mints the grants it keeps has still changed them.
	assertUntouched := func(t *testing.T, d *identity.Details, err error) {
		t.Helper()

		require.NoError(t, err)
		require.Len(t, d.Roles, 2,
			"nothing can strip every grant through Update: a caller that named no usable role "+
				"asked for no change, not for the user to lose all access")

		admin, viewer := d.Roles[0], d.Roles[1]
		assert.Equal(t, "admin", admin.Name)
		assert.Equal(t, uniqueID(t, "grant-admin"), admin.ID,
			"a grant re-minted under a new identifier breaks every reference to the old one")
		assert.True(t, admin.Primary, "admin is still the primary role")
		assert.True(t, admin.SuperRole)
		assert.True(t, grantStart.Equal(admin.StartDate),
			"the validity window is untouched: want start %v, got %v", grantStart, admin.StartDate)
		assert.True(t, grantValidUntil.Equal(admin.ValidUntil),
			"want valid-until %v, got %v", grantValidUntil, admin.ValidUntil)

		assert.Equal(t, "viewer", viewer.Name)
		assert.Equal(t, uniqueID(t, "grant-viewer"), viewer.ID)
		assert.False(t, viewer.Primary)
		assert.False(t, viewer.SuperRole)
	}

	cases := []testCase{
		{
			name: "an update that does not name roles keeps every grant as stored",
			seed: seedGranted,
			opts: []identity.UserOption{identity.WithUserName("Renamed")},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2)

				admin, viewer := d.Roles[0], d.Roles[1]
				assert.Equal(t, uniqueID(t, "grant-admin"), admin.ID,
					"grants the caller did not name are not rebuilt, so their identifiers stand")
				assert.Equal(t, "admin", admin.Name)
				assert.True(t, admin.Primary)
				assert.True(t, admin.SuperRole, "and neither are their super-role flags")
				assert.True(t, grantStart.Equal(admin.StartDate), "nor their validity windows")
				assert.True(t, grantValidUntil.Equal(admin.ValidUntil))

				assert.Equal(t, uniqueID(t, "grant-viewer"), viewer.ID)
				assert.Equal(t, "viewer", viewer.Name)
				assert.False(t, viewer.Primary)
			},
		},
		{
			name:   "an empty role list leaves the stored grants untouched",
			seed:   seedGranted,
			roles:  []string{},
			assert: assertUntouched,
		},
		{
			name:   "a list of only empty names leaves the stored grants untouched",
			seed:   seedGranted,
			roles:  []string{"", ""},
			assert: assertUntouched,
		},
		{
			name:  "surviving names rebuild in the order given, with the first primary",
			seed:  seedGranted,
			roles: []string{"viewer", "admin"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2)

				assert.Equal(t, "viewer", d.Roles[0].Name)
				assert.True(t, d.Roles[0].Primary, "the first name given becomes the primary role")
				assert.Equal(t, "admin", d.Roles[1].Name)
				assert.False(t, d.Roles[1].Primary,
					"the previous primary loses the flag, or two grants claim it")
			},
		},
		{
			name:  "a repeated name collapses to its first occurrence",
			seed:  seedGranted,
			roles: []string{"viewer", "viewer", "admin"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2, "Update deduplicates; Provision records each occurrence")
				assert.Equal(t, "viewer", d.Roles[0].Name)
				assert.Equal(t, "admin", d.Roles[1].Name)
			},
		},
		{
			name: "empty names are skipped and a repeat collapses, among names that survive",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				t.Helper()

				mustProvision(ctx, t, f, user)
				require.NoError(t, f.SeedRoleGrants(ctx, user, []*identity.AssignedRole{
					{ID: uniqueID(t, "grant-admin"), Name: "admin", Primary: true},
				}))
			},
			roles: []string{"", "viewer", "viewer", ""},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 1,
					"an empty name is skipped whether or not a real name survives beside it: a "+
						"grant named \"\" is a role nobody can have meant")
				assert.Equal(t, "viewer", d.Roles[0].Name)
				assert.True(t, d.Roles[0].Primary, "the first surviving name is primary")
			},
		},
		{
			name:  "a surviving name keeps the stored grant's identifier, flag and dates",
			seed:  seedGranted,
			roles: []string{"viewer", "admin"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2)

				admin := d.Roles[1]
				assert.Equal(t, uniqueID(t, "grant-admin"), admin.ID,
					"a rebuilt grant that mints a new identifier breaks every reference to the old one")
				assert.True(t, admin.SuperRole,
					"re-asserting a role by name must not silently demote it")
				assert.True(t, grantStart.Equal(admin.StartDate),
					"want start %v, got %v", grantStart, admin.StartDate)
				assert.True(t, grantValidUntil.Equal(admin.ValidUntil),
					"nor silently extend a grant that was due to expire: want valid-until %v, got %v",
					grantValidUntil, admin.ValidUntil)
			},
		},
		{
			name: "a newly named role is a new grant that inherits nothing",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				t.Helper()

				mustProvision(ctx, t, f, user)
				require.NoError(t, f.SeedRoleGrants(ctx, user, []*identity.AssignedRole{{
					ID:         uniqueID(t, "grant-admin"),
					Name:       "admin",
					Primary:    true,
					SuperRole:  true,
					StartDate:  grantStart,
					ValidUntil: grantValidUntil,
				}}))
			},
			roles: []string{"admin", "editor"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2)
				require.Equal(t, "editor", d.Roles[1].Name)

				editor := d.Roles[1]
				assert.NotEmpty(t, editor.ID, "a new grant is given an identifier of its own")
				assert.NotEqual(t, uniqueID(t, "grant-admin"), editor.ID,
					"and not the identifier of a grant the user already holds")
				assert.False(t, editor.Primary)
				assert.False(t, editor.SuperRole,
					"a role named alongside a super role must not become one: that would escalate "+
						"privilege through a role list")
				assert.True(t, editor.StartDate.IsZero(), "nor inherit another grant's validity window")
				assert.True(t, editor.ValidUntil.IsZero())
			},
		},
		{
			name: "where the stored grants repeat a name, the first stored grant is kept",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				t.Helper()

				_, err := f.Provision(ctx, user)
				require.NoError(t, err)
				require.NoError(t, f.SeedRoleGrants(ctx, user, []*identity.AssignedRole{
					{
						ID:         uniqueID(t, "grant-first"),
						Name:       "admin",
						Primary:    true,
						SuperRole:  true,
						StartDate:  grantStart,
						ValidUntil: grantValidUntil,
					},
					{ID: uniqueID(t, "grant-second"), Name: "admin"},
				}))
			},
			roles: []string{"admin"},
			assert: func(t *testing.T, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 1)

				kept := d.Roles[0]
				assert.Equal(t, uniqueID(t, "grant-first"), kept.ID,
					"the choice is defined rather than left to map order, so two stores agree")
				assert.True(t, kept.SuperRole,
					"the kept grant carries the first grant's own super-role flag, not a later "+
						"duplicate's")
				assert.True(t, grantStart.Equal(kept.StartDate),
					"and its own validity window: want start %v, got %v", grantStart, kept.StartDate)
				assert.True(t, grantValidUntil.Equal(kept.ValidUntil),
					"want valid-until %v, got %v", grantValidUntil, kept.ValidUntil)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			user := uniqueName(t, "rebuild", i)

			if tc.seed != nil {
				tc.seed(t, ctx, f, user)
			}

			opts := tc.opts
			if opts == nil {
				opts = []identity.UserOption{identity.WithUserRoles(tc.roles...)}
			}

			d, err := f.Update(ctx, user, opts...)
			tc.assert(t, d, err)
		})
	}
}

func runUpdateCases(t *testing.T, newFixture Factory) {
	t.Helper()

	// username, when set, derives the username the case updates from its
	// unique one; assert receives the username that was updated.
	type testCase struct {
		name     string
		seed     func(t *testing.T, ctx context.Context, f Fixture, user string)
		username func(user string) string
		opts     []identity.UserOption
		assert   func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error)
	}

	// seedUser gives every case a user with something in each field, so an
	// assertion that a field survived is meaningful rather than comparing two
	// zero values.
	seedUser := func(t *testing.T, ctx context.Context, f Fixture, user string) {
		t.Helper()

		org := &identity.Organization{ID: uniqueID(t, "org"), Name: "acme"}
		require.NoError(t, f.SeedOrganization(ctx, org))

		_, err := f.Provision(ctx, user,
			identity.WithUserName("First"),
			identity.WithUserPassword([]byte("H1")),
			identity.WithUserRoles("viewer"),
			identity.WithUserOrganization(&identity.Organization{ID: org.ID}),
		)
		require.NoError(t, err)
	}

	cases := []testCase{
		{
			name: "a field the caller did not name is left as the store holds it",
			seed: seedUser,
			opts: []identity.UserOption{identity.WithUserPassword([]byte("H2"))},
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ string, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("H2"), d.Password)

				require.NotNil(t, d.Organization,
					"an unnamed organization must survive a password-only update")
				assert.Equal(t, "acme", d.Organization.Name)
				assert.Equal(t, "First", d.Name)
			},
		},
		{
			name: "naming a field with an empty value clears it",
			seed: seedUser,
			opts: []identity.UserOption{identity.WithUserName("")},
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ string, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Empty(t, d.Name,
					"the write follows IsSet, so naming a field with an empty value clears it; "+
						"an implementation keyed on the value being non-empty could never clear one")

				require.NotNil(t, d.Organization, "and only the named field is touched")
				assert.Equal(t, "acme", d.Organization.Name)
			},
		},
		{
			name: "naming a nil organization clears it and touches nothing else",
			seed: seedUser,
			opts: []identity.UserOption{identity.WithUserOrganization(nil)},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Nil(t, d.Organization,
					"a named nil organization clears it; a store keyed on the value being "+
						"non-nil could never take a user out of an organization")

				stored := mustLoad(ctx, t, f, user)
				assert.Nil(t, stored.Organization, "the cleared organization must be the stored one")
				assert.Equal(t, "First", stored.Name, "and only the named field is touched")
				assert.Equal(t, []byte("H1"), stored.Password)
				require.Len(t, stored.Roles, 1)
				assert.Equal(t, "viewer", stored.Roles[0].Name)
			},
		},
		{
			name: "an unknown username is refused and creates nothing",
			opts: []identity.UserOption{identity.WithUserName("Nobody")},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound)
				assert.Nil(t, d)

				_, loadErr := f.LoadByUsername(ctx, user)
				assert.ErrorIs(t, loadErr, identity.ErrUserNotFound,
					"Update never creates: that is what makes Provision the only way in")
			},
		},
		{
			name:     "an empty username is refused, as neither a miss nor a collision",
			username: func(string) string { return "" },
			opts:     []identity.UserOption{identity.WithUserName("Nobody")},
			assert: func(t *testing.T, ctx context.Context, f Fixture, _ string, d *identity.Details, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, identity.ErrUserNotFound,
					"an empty username is refused as a username: reported as a miss, a caller "+
						"would read it as a user who was deleted")
				assert.NotErrorIs(t, err, identity.ErrUserExists)
				assert.Nil(t, d)

				_, loadErr := f.LoadByUsername(ctx, "")
				assert.ErrorIs(t, loadErr, identity.ErrUserNotFound, "a refused update writes nothing")
			},
		},
		{
			name: "an update naming nothing changes nothing and returns the complete record",
			seed: seedUser,
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)

				assert.Equal(t, "First", d.Name)
				assert.Equal(t, []byte("H1"), d.Password)
				require.Len(t, d.Roles, 1)
				assert.Equal(t, "viewer", d.Roles[0].Name)
				require.NotNil(t, d.Organization)
				assert.Equal(t, "acme", d.Organization.Name)

				assert.Equal(t, atUTC(d), atUTC(mustLoad(ctx, t, f, user)),
					"an update that names nothing writes nothing, and returns what is stored")
			},
		},
		{
			name: "the complete stored record is returned, not only the amended fields",
			seed: seedUser,
			opts: []identity.UserOption{identity.WithUserName("Alice A.")},
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ string, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Equal(t, "Alice A.", d.Name)
				assert.Len(t, d.Roles, 1, "the returned record carries the roles it did not touch")
				assert.NotNil(t, d.Organization)
				assert.Equal(t, []byte("H1"), d.Password)
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			user := uniqueName(t, "update", i)

			if tc.seed != nil {
				tc.seed(t, ctx, f, user)
			}

			if tc.username != nil {
				user = tc.username(user)
			}

			d, err := f.Update(ctx, user, tc.opts...)
			tc.assert(t, ctx, f, user, d, err)
		})
	}
}

// runProvisionRaceCase checks that the username collision is decided by the write
// itself.
//
// This is the case a pre-flight read cannot pass. An implementation that asks
// "does this username exist?" and then inserts has a window between the two in
// which another caller does the same, so both see no user and both create one —
// leaving two accounts on one username, or one account silently overwritten. The
// check has to be the write: a unique constraint, an INSERT ... ON CONFLICT DO
// NOTHING that reports zero rows, or an insert under the same lock that answered
// the question.
//
// Concurrency is what makes it visible, so this runs several callers at once and
// releases them together. Run the suite with -race -count=10 to give the window
// a chance to open.
func runProvisionRaceCase(t *testing.T, newFixture Factory) {
	t.Helper()
	t.Parallel()

	const attempts = 8

	ctx := t.Context()
	f := newFixture(t)
	user := uniqueName(t, "race", 0)

	var (
		mu      sync.Mutex
		created int
		refused int
		other   []error
		wg      sync.WaitGroup
	)

	start := make(chan struct{})

	wg.Add(attempts)

	for range attempts {
		go func() {
			defer wg.Done()

			<-start

			_, err := f.Provision(ctx, user)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case err == nil:
				created++
			case errors.Is(err, identity.ErrUserExists):
				refused++
			default:
				other = append(other, err)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Empty(t, other,
		"a losing caller must be refused with ErrUserExists, not with an incidental failure")
	assert.Equal(t, 1, created,
		"exactly one concurrent Provision may create the user: more than one means the collision "+
			"was decided by a read that another caller raced")
	assert.Equal(t, attempts-1, refused,
		"every caller that did not create the user is refused")
}

func runProvisionCases(t *testing.T, newFixture Factory) {
	t.Helper()

	// Each case receives a username unique to it. A case whose point is the
	// shape of the username (empty, blank, an email address) derives its own
	// through username; otherwise the unique one is provisioned. assert receives
	// the username that was provisioned.
	type testCase struct {
		name     string
		seed     func(t *testing.T, ctx context.Context, f Fixture, user string)
		username func(t *testing.T, user string) string
		opts     func(t *testing.T, user string) []identity.UserOption
		assert   func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error)
	}

	cases := []testCase{
		{
			name: "provisioning with every field returns the complete stored record",
			seed: func(t *testing.T, ctx context.Context, f Fixture, _ string) {
				t.Helper()

				require.NoError(t, f.SeedOrganization(ctx, fullOrganization(t)))
			},
			opts: func(t *testing.T, _ string) []identity.UserOption {
				return []identity.UserOption{
					identity.WithUserName("Ada"),
					identity.WithUserRoles("admin", "auditor"),
					identity.WithUserOrganization(&identity.Organization{ID: uniqueID(t, "org")}),
					identity.WithUserPassword([]byte("H1")),
				}
			},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)

				// Every check reads the record Provision returned: the caller acts
				// on it without loading the user again.
				assert.NotEmpty(t, d.ID)
				assert.Equal(t, user, d.Username)
				assert.Equal(t, "Ada", d.Name, "the returned record carries the name it was given")
				assert.Equal(t, []byte("H1"), d.Password)
				assert.True(t, d.Active)
				assert.True(t, d.PasswordChangedAt.IsZero(),
					"no time was named, so none is recorded: got %v", d.PasswordChangedAt)
				assert.Equal(t, fullOrganization(t), d.Organization,
					"the returned record carries the organization, resolved with its group")

				require.Len(t, d.Roles, 2)
				assert.Equal(t, "admin", d.Roles[0].Name)
				assert.True(t, d.Roles[0].Primary, "the first role named is primary")
				assert.Equal(t, "auditor", d.Roles[1].Name)
				assert.False(t, d.Roles[1].Primary)

				for _, r := range d.Roles {
					assert.False(t, r.SuperRole, "a provisioned grant is never a super role")
					assert.True(t, r.StartDate.IsZero() && r.ValidUntil.IsZero(),
						"a provisioned grant has no validity window: got %v to %v", r.StartDate, r.ValidUntil)
				}

				required, reqErr := f.Required(ctx, d.ID)
				require.NoError(t, reqErr)
				assert.False(t, required, "a created user is not required to use a second factor")
			},
		},
		{
			name: "provisioning with no password stores an empty hash",
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.Empty(t, d.Password, "no password was given, so the returned record holds none")

				loaded, loadErr := f.LoadByUsername(ctx, user)
				require.NoError(t, loadErr)
				assert.Empty(t, loaded.Password,
					"no password was given, so an empty hash is stored, never a placeholder")
			},
		},
		{
			name: "a created user is active",
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ string, d *identity.Details, err error) {
				require.NoError(t, err)
				require.NotNil(t, d)
				assert.True(t, d.Active,
					"a user created through provisioning can sign in without a second step")
			},
		},
		{
			name: "a created user is readable through the loader",
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.NoError(t, err)

				loaded, loadErr := f.LoadByUsername(ctx, user)
				require.NoError(t, loadErr, "a provisioned user must be visible to the loader")
				assert.Equal(t, d.ID, loaded.ID)
			},
		},
		{
			name:     "an empty username is refused",
			username: func(*testing.T, string) string { return "" },
			assert: func(t *testing.T, ctx context.Context, f Fixture, _ string, d *identity.Details, err error) {
				require.Error(t, err, "a user with no username could never be loaded again")
				assert.NotErrorIs(t, err, identity.ErrUserExists,
					"an empty username is refused as a username, not reported as taken")
				assert.NotErrorIs(t, err, identity.ErrUserNotFound,
					"an empty username is refused as a username, not reported as a miss")
				assert.Nil(t, d)

				_, loadErr := f.LoadByUsername(ctx, "")
				assert.ErrorIs(t, loadErr, identity.ErrUserNotFound, "a refused provision writes nothing")
			},
		},
		{
			name: "the first role name is primary and the rest are not",
			opts: func(*testing.T, string) []identity.UserOption {
				return []identity.UserOption{identity.WithUserRoles("editor", "viewer")}
			},
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ string, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2)

				assert.Equal(t, "editor", d.Roles[0].Name)
				assert.True(t, d.Roles[0].Primary)
				assert.Equal(t, "viewer", d.Roles[1].Name)
				assert.False(t, d.Roles[1].Primary,
					"exactly one grant is primary, or the active role is ambiguous")
			},
		},
		{
			name: "a repeated role name creates one grant per occurrence",
			opts: func(*testing.T, string) []identity.UserOption {
				return []identity.UserOption{identity.WithUserRoles("viewer", "viewer")}
			},
			assert: func(t *testing.T, _ context.Context, _ Fixture, _ string, d *identity.Details, err error) {
				require.NoError(t, err)
				require.Len(t, d.Roles, 2,
					"Provision records what the caller asked for; deduplication is Update's rule")

				assert.NotEqual(t, d.Roles[0].ID, d.Roles[1].ID,
					"each occurrence is its own grant, so each carries its own identifier")
				assert.True(t, d.Roles[0].Primary)
				assert.False(t, d.Roles[1].Primary, "only the first occurrence is primary")
			},
		},
		{
			name: "the password hash is stored exactly as given",
			opts: func(*testing.T, string) []identity.UserOption {
				return []identity.UserOption{identity.WithUserPassword([]byte("H"))}
			},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.NoError(t, err)
				assert.Equal(t, []byte("H"), d.Password)

				loaded, loadErr := f.LoadByUsername(ctx, user)
				require.NoError(t, loadErr)
				assert.Equal(t, []byte("H"), loaded.Password,
					"a store that re-hashed here would make every stored credential unverifiable")
			},
		},
		{
			name:     "a username that is only whitespace is opaque and creates a user",
			username: func(t *testing.T, _ string) string { return blankName(t) },
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.NoError(t, err,
					"only an empty username is refused: the username is opaque, so an "+
						"implementation that trims before deciding refuses one the contract allows")
				require.NotNil(t, d)

				loaded, loadErr := f.LoadByUsername(ctx, user)
				require.NoError(t, loadErr, "and the user it created is loadable by that username")
				assert.Equal(t, d.ID, loaded.ID)
			},
		},
		{
			name: "the email is never a lookup key",
			opts: func(_ *testing.T, user string) []identity.UserOption {
				return []identity.UserOption{identity.WithUserEmail(user + "@example.com")}
			},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, _ *identity.Details, err error) {
				require.NoError(t, err)

				_, loadErr := f.LoadByUsername(ctx, user+"@example.com")
				require.ErrorIs(t, loadErr, identity.ErrUserNotFound,
					"matching on email would let a caller claim an address and take over the account")
			},
		},
		{
			name: "a taken username is refused and the existing user is untouched",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				_, err := f.Provision(ctx, user, identity.WithUserName("First"), identity.WithUserRoles("admin"))
				require.NoError(t, err)
			},
			opts: func(*testing.T, string) []identity.UserOption {
				return []identity.UserOption{identity.WithUserName("Second"), identity.WithUserRoles("root")}
			},
			assert: func(t *testing.T, ctx context.Context, f Fixture, user string, d *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserExists)
				assert.Nil(t, d)

				stored, loadErr := f.LoadByUsername(ctx, user)
				require.NoError(t, loadErr)
				assert.Equal(t, "First", stored.Name,
					"the existing account is never adopted or overwritten by a second create")

				require.Len(t, stored.Roles, 1,
					"a refused create must not add its grants to the existing user: that would hand "+
						"the refused caller's roles to someone else's account")
				assert.Equal(t, "admin", stored.Roles[0].Name)
				assert.True(t, stored.Roles[0].Primary)
			},
		},
		{
			name: "the collision error does not quote the username",
			seed: func(t *testing.T, ctx context.Context, f Fixture, user string) {
				_, err := f.Provision(ctx, user+"@example.com")
				require.NoError(t, err)
			},
			username: func(_ *testing.T, user string) string { return user + "@example.com" },
			assert: func(t *testing.T, _ context.Context, _ Fixture, user string, _ *identity.Details, err error) {
				require.ErrorIs(t, err, identity.ErrUserExists)
				assert.NotContains(t, err.Error(), user,
					"on just-in-time provisioning the username is an email address, and the error "+
						"reaches logs and sometimes the caller")
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)

			user := uniqueName(t, "provision", i)

			if tc.seed != nil {
				tc.seed(t, ctx, f, user)
			}

			username := user
			if tc.username != nil {
				username = tc.username(t, user)
			}

			var opts []identity.UserOption
			if tc.opts != nil {
				opts = tc.opts(t, user)
			}

			d, err := f.Provision(ctx, username, opts...)
			tc.assert(t, ctx, f, username, d, err)
		})
	}
}

// RunMFALookupSuite checks the multi-factor requirement contract. Like
// RunConformanceSuite, it fails before any case when a hook is missing.
func RunMFALookupSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	requireUsableFixture(t, newFixture)
	runMFALookupSuite(t, newFixture)
}

func runMFALookupSuite(t *testing.T, newFixture Factory) {
	t.Helper()

	type testCase struct {
		name   string
		setup  func(t *testing.T, ctx context.Context, f Fixture, user string) identity.UserID
		assert func(t *testing.T, required bool, err error)
	}

	provisionRequired := func(t *testing.T, ctx context.Context, f Fixture, user string) identity.UserID {
		t.Helper()

		d, err := f.Provision(ctx, user)
		require.NoError(t, err)
		require.NoError(t, f.SeedMFARequired(ctx, d.ID, true))

		return d.ID
	}

	cases := []testCase{
		{
			name: "an unknown user is refused, never answered as not required",
			setup: func(t *testing.T, _ context.Context, _ Fixture, _ string) identity.UserID {
				t.Helper()

				// Well formed, so a store keyed on UUIDs reaches its query, and
				// unique to the case, so no stored user can hold it.
				return identity.UserID(uniqueID(t, "unknown-user"))
			},
			assert: func(t *testing.T, required bool, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"the reference comes from an authenticated principal, so an unknown user "+
						"means it was deleted or the loader disagrees: answered as not required, "+
						"the lookup fails open and waves the user past their second factor")
				assert.False(t, required)
			},
		},
		{
			name: "a reference the store cannot parse is refused as an unknown user",
			setup: func(_ *testing.T, _ context.Context, _ Fixture, _ string) identity.UserID {
				return "not-a-uuid"
			},
			assert: func(t *testing.T, required bool, err error) {
				require.ErrorIs(t, err, identity.ErrUserNotFound,
					"a reference no stored user can hold names no user, whatever the store's "+
						"key format, and is neither 'not required' nor a driver error")
				assert.False(t, required)
			},
		},
		{
			name: "a stored user with no requirement recorded is not required",
			setup: func(t *testing.T, ctx context.Context, f Fixture, user string) identity.UserID {
				t.Helper()

				d, err := f.Provision(ctx, user)
				require.NoError(t, err)

				return d.ID
			},
			assert: func(t *testing.T, required bool, err error) {
				require.NoError(t, err,
					"a user who exists but was never marked is a legitimate answer of false: "+
						"refusing it would deny every user nobody has configured")
				assert.False(t, required)
			},
		},
		{
			name:  "a user marked as requiring a second factor is reported as required",
			setup: provisionRequired,
			assert: func(t *testing.T, required bool, err error) {
				require.NoError(t, err)
				assert.True(t, required)
			},
		},
		{
			name: "the requirement is answered by user reference",
			setup: func(t *testing.T, ctx context.Context, f Fixture, user string) identity.UserID {
				t.Helper()

				provisionRequired(t, ctx, f, user)

				other, err := f.Provision(ctx, user+"-other")
				require.NoError(t, err)

				return other.ID
			},
			assert: func(t *testing.T, required bool, err error) {
				require.NoError(t, err)
				assert.False(t, required,
					"the answer is keyed on the reference asked about, not on whichever user "+
						"happens to be marked: otherwise one user's requirement challenges another")
			},
		},
		{
			name: "the requirement survives a change to the user",
			setup: func(t *testing.T, ctx context.Context, f Fixture, user string) identity.UserID {
				t.Helper()

				id := provisionRequired(t, ctx, f, user)

				// Stands in for losing an enrolment: the requirement lives with the
				// user, so rewriting the user's own record must not clear it.
				_, err := f.Update(ctx, user,
					identity.WithUserRoles("viewer"),
					identity.WithUserPassword([]byte("H2")),
				)
				require.NoError(t, err)

				return id
			},
			assert: func(t *testing.T, required bool, err error) {
				require.NoError(t, err)
				assert.True(t, required,
					"a requirement held inside the user record would be rebuilt away by an "+
						"update, silently dropping a user's second factor")
			},
		},
		{
			name: "a lookup failure is an error, not 'not required'",
			setup: func(t *testing.T, ctx context.Context, f Fixture, user string) identity.UserID {
				t.Helper()

				id := provisionRequired(t, ctx, f, user)
				f.FailMFALookups(errBackendUnreachable)

				return id
			},
			assert: func(t *testing.T, required bool, err error) {
				require.Error(t, err,
					"a lookup that cannot answer must say so: reported as 'not required', an "+
						"outage would wave every user past their second factor")
				assert.NotErrorIs(t, err, identity.ErrUserNotFound,
					"an outage is not a missing user: reported as one, a caller treats every "+
						"authenticated principal as deleted and cannot tell the backend is down")
				assert.False(t, required, "and it fails closed rather than guessing true")
			},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			f := newFixture(t)
			id := tc.setup(t, ctx, f, uniqueName(t, "mfa", i))

			required, err := f.Required(ctx, id)
			tc.assert(t, required, err)
		})
	}
}
