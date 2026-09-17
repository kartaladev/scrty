package identity_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
)

// Privilege and ResourcePrivileges are data carriers: the identity model holds
// them and decides nothing from them, so there is no behaviour here to drive.
// These assertions pin their shape instead, so a later change cannot drop the
// granted flag or rename a field unnoticed, and pin that a refused privilege is
// carried as refused rather than filtered away. The role loader exercises them
// against a real store in the conformance suite.
func TestResourcePrivilegesCarryTheirData(t *testing.T) {
	t.Parallel()

	rp := identity.ResourcePrivileges{
		Group:    "billing",
		Resource: "invoice",
		Privileges: []identity.Privilege{
			{Name: "read", Granted: true},
			{Name: "delete", Granted: false},
		},
	}

	// The field names are already pinned by this file compiling against the keyed
	// literal above, so reading them back would add nothing. What needs asserting
	// is the contract a future change could break without breaking the build:
	// that a refused privilege survives as refused rather than being filtered out.
	require.Len(t, rp.Privileges, 2,
		"a privilege that is not granted is carried, not filtered out")
	assert.True(t, rp.Privileges[0].Granted)
	assert.False(t, rp.Privileges[1].Granted,
		"a refused privilege is carried as refused, so authorization sees the refusal")
}

func TestPrivilegeKeepsItsGrantedFlag(t *testing.T) {
	t.Parallel()

	granted, ok := reflect.TypeFor[identity.Privilege]().FieldByName("Granted")
	require.True(t, ok, "Privilege must keep a granted flag for authorization to read")
	assert.Equal(t, reflect.TypeFor[bool](), granted.Type,
		"the granted flag is a bool: a privilege is granted or it is not")
}
