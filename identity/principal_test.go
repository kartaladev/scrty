package identity_test

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// storedHash stands in for a stored password hash. No principal may hold it.
const storedHash = "argon2id$65536$1$4$c2FsdA$a2V5"

// The validity window the role fixtures use. Package vars rather than parsed
// strings, matching pkg/id and pkg/logsample, so the fixture and the assertion
// read off one source and cannot drift apart.
var (
	roleStart      = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	roleValidUntil = time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
)

// maxWalkDepth bounds the walks below. The principal's type graph is far
// shallower than this, so hitting the bound means the graph grew a level the
// walk never inspected, which is reported rather than passed over.
const maxWalkDepth = 12

// assertNoPasswordHash fails if hash is reachable from p, as text or as bytes.
//
// It walks the value instead of rendering it. Under %#v only the top level is
// expanded: Roles, ActiveRole and Organization print as bare addresses, so a
// hash parked behind any of them is invisible to a rendered check, and a []byte
// field's contents never appear in a comparable form at all. Both are exactly
// where a leak would sit.
func assertNoPasswordHash(t *testing.T, p identity.Principal, hash []byte) {
	t.Helper()

	assertValueHidesSecret(t, reflect.ValueOf(p), "Principal", string(hash), 0)
}

// assertValueHidesSecret walks v and fails on any reachable string or byte
// slice that contains secret.
//
// It follows pointers, interfaces, slices, arrays and maps, and reads exported
// struct fields only: an unexported field of some other package's type is not
// reachable by application code, and nothing in this package can populate one.
func assertValueHidesSecret(t *testing.T, v reflect.Value, path, secret string, depth int) {
	t.Helper()

	require.Less(t, depth, maxWalkDepth,
		"%s: the walk hit its depth limit, so part of the principal went uninspected", path)

	switch v.Kind() {
	case reflect.String:
		assert.NotContains(t, v.String(), secret, "%s holds the password hash as text", path)
	case reflect.Slice, reflect.Array:
		if isByteSlice(v.Type()) {
			assert.NotContains(t, string(v.Bytes()), secret,
				"%s holds the password hash as bytes", path)

			return
		}

		for i := range v.Len() {
			assertValueHidesSecret(t, v.Index(i), fmt.Sprintf("%s[%d]", path, i), secret, depth+1)
		}
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return
		}

		assertValueHidesSecret(t, v.Elem(), path, secret, depth+1)
	case reflect.Map:
		for _, k := range v.MapKeys() {
			assertValueHidesSecret(t, k, path+" key", secret, depth+1)
			assertValueHidesSecret(t, v.MapIndex(k), path+" value", secret, depth+1)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}

			assertValueHidesSecret(t, v.Field(i), path+"."+f.Name, secret, depth+1)
		}
	default:
	}
}

// isByteSlice reports whether typ is a slice of bytes, whatever that slice type
// is named.
//
// It compares kinds rather than typ == reflect.TypeFor[[]byte](): a declared
// type such as `type Secret []byte` is a different reflect.Type, and an
// equality check would wave it past while it carries exactly the same bytes.
func isByteSlice(typ reflect.Type) bool {
	return typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8
}

// TestDetailsCarriesNoMFARequirement pins that the multi-factor requirement is
// looked up by user reference and never rides along on the user record.
//
// It matters because the two have different lifetimes: a user record is rewritten
// whenever anything about the user changes, so a requirement stored on it can be
// rebuilt away by an unrelated update, silently dropping a user's second factor.
// Keeping it out of Details is what makes that impossible rather than merely
// unlikely.
func TestDetailsCarriesNoMFARequirement(t *testing.T) {
	t.Parallel()

	forbidden := []string{"MFA", "SecondFactor", "TwoFactor", "Requires"}

	for f := range reflect.TypeFor[identity.Details]().Fields() {
		for _, fragment := range forbidden {
			assert.NotContains(t, f.Name, fragment,
				"Details.%s looks like a multi-factor requirement; that is looked up by "+
					"reference through MFARequirementLookup, not carried on the record", f.Name)
		}
	}
}

// TestPrincipalCarriesNoRawSecretMaterial is the structural half of the no-leak
// guarantee: whatever a mapper puts there, the outward identity has nowhere to
// put raw secret material in the first place. It is a whole-type invariant, so
// it runs once rather than once per table row.
//
// It walks every type reachable from Principal rather than its top-level fields
// alone, because the principal reaches AssignedRole, Organization and Group
// through pointers, and a hash parked on any of them is just as reachable by a
// caller as one parked on the principal itself.
func TestPrincipalCarriesNoRawSecretMaterial(t *testing.T) {
	t.Parallel()

	assertTypeCarriesNoBytes(t, reflect.TypeFor[identity.Principal](), "Principal", 0,
		make(map[reflect.Type]bool))
}

// assertTypeCarriesNoBytes fails on any type reachable from typ that is a slice
// of bytes, following pointers, slices, arrays and maps, and descending through
// exported struct fields.
//
// seen stops a recursive type from looping; the depth bound reports a graph that
// outgrew the walk rather than silently truncating it.
func assertTypeCarriesNoBytes(
	t *testing.T, typ reflect.Type, path string, depth int, seen map[reflect.Type]bool,
) {
	t.Helper()

	require.Less(t, depth, maxWalkDepth,
		"%s: the walk hit its depth limit, so part of the type went uninspected", path)

	assert.False(t, isByteSlice(typ),
		"%s is a slice of bytes (%s); the outward identity carries no raw secret material, "+
			"whatever the slice type is named", path, typ)

	if seen[typ] {
		return
	}

	seen[typ] = true

	switch typ.Kind() {
	case reflect.Pointer:
		assertTypeCarriesNoBytes(t, typ.Elem(), path, depth+1, seen)
	case reflect.Slice, reflect.Array:
		assertTypeCarriesNoBytes(t, typ.Elem(), path+"[]", depth+1, seen)
	case reflect.Map:
		assertTypeCarriesNoBytes(t, typ.Key(), path+" key", depth+1, seen)
		assertTypeCarriesNoBytes(t, typ.Elem(), path+" value", depth+1, seen)
	case reflect.Struct:
		for f := range typ.Fields() {
			if !f.IsExported() {
				continue
			}

			assertTypeCarriesNoBytes(t, f.Type, path+"."+f.Name, depth+1, seen)
		}
	default:
	}
}

func TestPrincipalFromDetails(t *testing.T) {
	t.Parallel()

	// The assert closure receives the record the principal was built from as
	// well as the principal, so a case can write through the principal and then
	// require the record it came from to be untouched.
	type testCase struct {
		name    string
		details *identity.Details
		assert  func(t *testing.T, d *identity.Details, p *identity.Principal)
	}

	cases := []testCase{
		{
			name: "an opaque reference round trips byte for byte",
			details: &identity.Details{
				ID:       "Tenant-7/ÅSA:0042 ",
				Username: "asa",
			},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("Tenant-7/ÅSA:0042 "), p.ID,
					"the reference is never parsed, trimmed or case-folded")
			},
		},
		{
			name:    "a reference differing only in case is a different user",
			details: &identity.Details{ID: "ABC", Username: "abc"},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				assert.NotEqual(t, identity.UserID("abc"), p.ID)
			},
		},
		{
			name: "the display name and username are carried",
			details: &identity.Details{
				ID:       "u-0",
				Name:     "Alice Álvarez",
				Username: "alice",
			},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				assert.Equal(t, "Alice Álvarez", p.Name,
					"the spec requires the display name to reach the principal")
				assert.Equal(t, "alice", p.Username)
			},
		},
		{
			// The record carries a role and an organization as well as the hash,
			// so the walk has somewhere to look behind each of the principal's
			// pointers rather than only at its top level.
			name: "the password hash is dropped",
			details: &identity.Details{
				ID:       "u-1",
				Username: "alice",
				Password: []byte(storedHash),
				Roles:    []*identity.AssignedRole{{ID: "r-1", Name: "viewer", Primary: true}},
				Organization: &identity.Organization{
					ID:    "o-1",
					Name:  "acme",
					Group: &identity.Group{ID: "g-1", Name: "external"},
				},
			},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				assertNoPasswordHash(t, *p, []byte(storedHash))
			},
		},
		{
			name: "the active role defaults to the primary role",
			details: &identity.Details{
				ID:       "u-2",
				Username: "bob",
				Roles: []*identity.AssignedRole{
					{ID: "r-1", Name: "viewer"},
					{ID: "r-2", Name: "admin", Primary: true},
				},
			},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				require.NotNil(t, p.ActiveRole)
				assert.Equal(t, "admin", p.ActiveRole.Name)
			},
		},
		{
			name: "a role's attributes are carried unchanged",
			details: &identity.Details{
				ID:       "u-3",
				Username: "carol",
				Roles: []*identity.AssignedRole{{
					ID:        "r-9",
					Name:      "ops",
					SuperRole: true,
				}},
			},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				require.Len(t, p.Roles, 1)

				got := p.Roles[0]
				assert.Equal(t, "ops", got.Name)
				assert.Equal(t, "r-9", got.ID)
				assert.True(t, got.SuperRole, "the identity model carries this, it does not decide from it")
			},
		},
		{
			name: "a role's validity window is carried unchanged",
			details: &identity.Details{
				ID:       "u-4",
				Username: "dana",
				Roles: []*identity.AssignedRole{{
					Name:       "ops",
					StartDate:  roleStart,
					ValidUntil: roleValidUntil,
				}},
			},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				require.Len(t, p.Roles, 1)

				got := p.Roles[0]
				assert.Equal(t, roleStart, got.StartDate)
				assert.Equal(t, roleValidUntil, got.ValidUntil)
			},
		},
		{
			name:    "no organization is supplied by default",
			details: &identity.Details{ID: "u-5", Username: "erin"},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				assert.Nil(t, p.Organization, "the library supplies no default organization")
			},
		},
		{
			name: "an organization and its group are carried unchanged",
			details: &identity.Details{
				ID:       "u-6",
				Username: "frank",
				Organization: &identity.Organization{
					ID:    "o-1",
					Name:  "acme",
					Group: &identity.Group{ID: "g-1", Name: "internal", Internal: true},
				},
			},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				require.NotNil(t, p.Organization)
				assert.Equal(t, "acme", p.Organization.Name)
				require.NotNil(t, p.Organization.Group)
				assert.True(t, p.Organization.Group.Internal)
			},
		},
		{
			name: "writing through a role does not rewrite the record",
			details: &identity.Details{
				ID:       "u-7",
				Username: "gina",
				Roles: []*identity.AssignedRole{
					{ID: "r-1", Name: "viewer", Primary: true},
				},
			},
			assert: func(t *testing.T, d *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				require.Len(t, p.Roles, 1)
				require.NotNil(t, p.ActiveRole)

				// Application code holding the principal escalates its own grant.
				p.Roles[0].SuperRole = true
				p.Roles[0].Name = "admin"
				p.ActiveRole.Primary = false

				assert.False(t, d.Roles[0].SuperRole,
					"a handler escalated its grant to a super role through the principal it was "+
						"handed; where that record came from a cache, the store escalated with it")
				assert.Equal(t, "viewer", d.Roles[0].Name,
					"the grant's name is the record's, not the principal's to rewrite")
				assert.True(t, d.Roles[0].Primary,
					"the active role is a view of the record, not a handle on it")
			},
		},
		{
			name: "writing through the organization does not rewrite the record",
			details: &identity.Details{
				ID:       "u-8",
				Username: "hana",
				Organization: &identity.Organization{
					ID:    "o-1",
					Name:  "acme",
					Group: &identity.Group{ID: "g-1", Name: "external"},
				},
			},
			assert: func(t *testing.T, d *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				require.NotNil(t, p.Organization)
				require.NotNil(t, p.Organization.Group)

				p.Organization.ID = "o-victim"
				p.Organization.Group.Internal = true

				assert.Equal(t, "o-1", d.Organization.ID,
					"a handler moved its user into another organization through the principal")
				assert.False(t, d.Organization.Group.Internal,
					"and marked the record's group internal")
			},
		},
		{
			name: "appending to the role set does not rewrite the record",
			details: &identity.Details{
				ID:       "u-9",
				Username: "ivan",
				Roles: []*identity.AssignedRole{
					{ID: "r-1", Name: "viewer", Primary: true},
					{ID: "r-2", Name: "editor"},
				},
			},
			assert: func(t *testing.T, d *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				require.Len(t, p.Roles, 2)

				p.Roles = p.Roles[:1]
				p.Roles = append(p.Roles, &identity.AssignedRole{Name: "admin", SuperRole: true})

				require.Len(t, d.Roles, 2)
				assert.Equal(t, "editor", d.Roles[1].Name,
					"appending to the principal's roles overwrote a grant in the record, because "+
						"the two share one backing array")
			},
		},
		{
			name: "a nil grant in the record is skipped",
			details: &identity.Details{
				ID:       "u-10",
				Username: "jana",
				Roles: []*identity.AssignedRole{
					nil,
					{ID: "r-1", Name: "viewer", Primary: true},
				},
			},
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				require.NotNil(t, p)
				require.Len(t, p.Roles, 1,
					"there is no grant to carry, and a principal holding a nil one panics in the "+
						"first caller that reads its roles")
				assert.Equal(t, "viewer", p.Roles[0].Name)
			},
		},
		{
			name:    "absent details yield no principal",
			details: nil,
			assert: func(t *testing.T, _ *identity.Details, p *identity.Principal) {
				assert.Nil(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.details, identity.PrincipalFromDetails(tc.details))
		})
	}
}

func TestPrincipalKind(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		principal identity.Principal
		assert    func(t *testing.T, p identity.Principal)
	}

	cases := []testCase{
		{
			name:      "a principal built without a kind is a human user",
			principal: identity.Principal{ID: "u-1", Username: "alice"},
			assert: func(t *testing.T, p identity.Principal) {
				assert.Equal(t, identity.KindUser, p.Kind,
					"the zero value is a human user, so an unset kind is never a service")
				assert.False(t, p.IsService())
			},
		},
		{
			name: "a service principal reports itself and carries its scopes",
			principal: identity.Principal{
				ID:       "svc-1",
				Username: "reporter",
				Kind:     identity.KindService,
				Scopes:   []string{"reports:read"},
			},
			assert: func(t *testing.T, p identity.Principal) {
				assert.True(t, p.IsService())
				assert.Equal(t, []string{"reports:read"}, p.Scopes)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.principal)
		})
	}
}

func TestDetailsActive(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		details identity.Details
		assert  func(t *testing.T, active bool)
	}

	cases := []testCase{
		{
			name:    "details a loader never marked active report inactive",
			details: identity.Details{ID: "u-1", Username: "alice"},
			assert: func(t *testing.T, active bool) {
				assert.False(t, active,
					"a user is active only when the loader marks them active explicitly")
			},
		},
		{
			name:    "details the loader marked active report active",
			details: identity.Details{ID: "u-2", Username: "bob", Active: true},
			assert: func(t *testing.T, active bool) {
				assert.True(t, active)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.details.Active)
		})
	}
}

// TestDetailsActiveIsNotInverted guards the field's sense, not its value. Reading
// a false zero value proves nothing on its own, since a bool is false whatever
// the code does. The risk is a rename: an Inactive or Disabled flag would make
// the zero value mean *active*, so a user the loader never vouched for would be
// treated as enabled.
func TestDetailsActiveIsNotInverted(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[identity.Details]()

	active, ok := typ.FieldByName("Active")
	require.True(t, ok, "Details must carry Active, so the zero value means inactive")
	assert.Equal(t, reflect.TypeFor[bool](), active.Type)

	for _, inverted := range []string{"Inactive", "Disabled", "Suspended"} {
		_, found := typ.FieldByName(inverted)
		assert.False(t, found,
			"Details.%s inverts the zero value: a user would be active until explicitly marked otherwise",
			inverted)
	}
}
