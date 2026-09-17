package identity_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// TestPrivilegeShapeCanExpressARefusal pins that these types can still express
// the contract the role loader port relies on: a privilege that is not granted
// is carried as refused rather than omitted, so a caller can tell "refused"
// apart from "not mentioned".
//
// It guards the shape, not the behaviour, and says so deliberately. Privilege
// and ResourcePrivileges are data carriers — this package exposes no function
// that reads one, so there is nothing here to call: a test that built a literal
// and read its fields back would assert its own input and hold however the
// package changed. Whether a loader really returns a refusal is the
// implementation's behaviour, and it is checked against a real implementation by
// the conformance suite in scrty's test module, which seeds a refused privilege
// and requires the loader to carry it.
//
// What a change could still break without breaking the build is the shape: a
// list of granted names, or an inverted flag, could not express a refusal at
// all, and every caller would then read "refused" as "not mentioned" — which is
// how a revoked privilege becomes a privilege nobody decided.
func TestPrivilegeShapeCanExpressARefusal(t *testing.T) {
	t.Parallel()

	privilege := reflect.TypeFor[identity.Privilege]()

	granted, ok := privilege.FieldByName("Granted")
	require.True(t, ok, "Privilege must keep a granted flag for authorization to read")
	assert.Equal(t, reflect.TypeFor[bool](), granted.Type,
		"the granted flag is a bool: a privilege is granted or it is not")

	for _, inverted := range []string{"Refused", "Denied", "Revoked", "Forbidden"} {
		_, found := privilege.FieldByName(inverted)
		assert.False(t, found,
			"Privilege.%s inverts the zero value: a privilege nobody vouched for would read as "+
				"granted, and two flags disagreeing leaves no answer at all", inverted)
	}

	entry := reflect.TypeFor[identity.ResourcePrivileges]()

	privileges, ok := entry.FieldByName("Privileges")
	require.True(t, ok, "a resource entry must carry the privileges it is about")
	assert.Equal(t, reflect.TypeFor[[]identity.Privilege](), privileges.Type,
		"the entry carries every named privilege with its own flag; a list of granted names "+
			"could not carry a refusal, so a caller could never tell one from silence")

	for _, filtering := range []string{"GrantedOnly", "Allowed", "Effective", "Filtered"} {
		_, found := entry.FieldByName(filtering)
		assert.False(t, found,
			"ResourcePrivileges.%s suggests the entry carries a selection rather than what the "+
				"role holds: a row that filters its refusals away hides them from every caller",
			filtering)
	}
}
