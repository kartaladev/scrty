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

// assertNoPasswordHash fails if p holds hash as text.
//
// It catches a string-typed leak only, and deliberately does not try to catch a
// []byte one. Under %#v a []byte field renders as []uint8{0x61, ...}, so neither
// the hash's own characters nor its standalone %#v rendering — which prints
// []byte{...}, not []uint8{...} — ever appears in the haystack. An assertion
// comparing those two renderings looks like a byte check, always passes, and is
// dead. The []byte case is caught structurally instead, by
// TestPrincipalCarriesNoRawSecretMaterial.
func assertNoPasswordHash(t *testing.T, p identity.Principal, hash []byte) {
	t.Helper()

	assert.NotContains(t, fmt.Sprintf("%#v", p), string(hash), "the hash leaked as text")
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
// guarantee, and the only thing that catches a []byte-typed leak, since no
// rendered check can see one. It is a whole-type invariant, so it runs once
// rather than once per table row.
func TestPrincipalCarriesNoRawSecretMaterial(t *testing.T) {
	t.Parallel()

	for f := range reflect.TypeFor[identity.Principal]().Fields() {
		assert.NotEqual(t, reflect.TypeFor[[]byte](), f.Type,
			"Principal.%s is a []byte; the outward identity carries no raw secret material", f.Name)
	}
}

func TestPrincipalFromDetails(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		details *identity.Details
		assert  func(t *testing.T, p *identity.Principal)
	}

	cases := []testCase{
		{
			name: "an opaque reference round trips byte for byte",
			details: &identity.Details{
				ID:       "Tenant-7/ÅSA:0042 ",
				Username: "asa",
			},
			assert: func(t *testing.T, p *identity.Principal) {
				require.NotNil(t, p)
				assert.Equal(t, identity.UserID("Tenant-7/ÅSA:0042 "), p.ID,
					"the reference is never parsed, trimmed or case-folded")
			},
		},
		{
			name:    "a reference differing only in case is a different user",
			details: &identity.Details{ID: "ABC", Username: "abc"},
			assert: func(t *testing.T, p *identity.Principal) {
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
			assert: func(t *testing.T, p *identity.Principal) {
				require.NotNil(t, p)
				assert.Equal(t, "Alice Álvarez", p.Name,
					"the spec requires the display name to reach the principal")
				assert.Equal(t, "alice", p.Username)
			},
		},
		{
			name: "the password hash is dropped",
			details: &identity.Details{
				ID:       "u-1",
				Username: "alice",
				Password: []byte(storedHash),
			},
			assert: func(t *testing.T, p *identity.Principal) {
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
			assert: func(t *testing.T, p *identity.Principal) {
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
			assert: func(t *testing.T, p *identity.Principal) {
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
			assert: func(t *testing.T, p *identity.Principal) {
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
			assert: func(t *testing.T, p *identity.Principal) {
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
			assert: func(t *testing.T, p *identity.Principal) {
				require.NotNil(t, p)
				require.NotNil(t, p.Organization)
				assert.Equal(t, "acme", p.Organization.Name)
				require.NotNil(t, p.Organization.Group)
				assert.True(t, p.Organization.Group.Internal)
			},
		},
		{
			name:    "absent details yield no principal",
			details: nil,
			assert: func(t *testing.T, p *identity.Principal) {
				assert.Nil(t, p)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, identity.PrincipalFromDetails(tc.details))
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
