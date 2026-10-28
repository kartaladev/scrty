package fibersec_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
)

// ownedByAnyone is a checker that is never reached: the cases here fail at wiring.
func ownedByAnyone(context.Context, *identity.Principal, string) (bool, error) { return true, nil }

// TestFiber_OwnershipGuardWithNilCheckerFailsAtWiring pins that a guard built without what it
// cannot work without panics when it is wired, naming the missing dependency,
// instead of refusing every request once traffic arrives.
func TestFiber_OwnershipGuardWithNilCheckerFailsAtWiring(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "fibersec: ResourceOwnerships needs a non-nil checker", func() {
		fibersec.ResourceOwnerships[string](fibersec.NewGuards(nil), "orders", "order", nil)
	})
}

func TestFiber_OwnershipGuardWithNilExtractorFailsAtWiring(t *testing.T) {
	t.Parallel()

	owned := fibersec.ResourceOwnerships[string](fibersec.NewGuards(nil), "orders", "order", ownedByAnyone)

	assert.PanicsWithValue(t, "fibersec: ForResource needs a non-nil extractor", func() {
		owned.ForResource(nil)
	})
}

func TestFiber_GuardsBuildersWithNilGuardsFailAtWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func()
		panics string
	}

	cases := []testCase{
		{
			name:   "RequireAuthenticated",
			build:  func() { (*fibersec.Guards)(nil).RequireAuthenticated() },
			panics: "fibersec: RequireAuthenticated needs non-nil Guards",
		},
		{
			name:   "ResourcePrivileges",
			build:  func() { (*fibersec.Guards)(nil).ResourcePrivileges("orders", "order") },
			panics: "fibersec: ResourcePrivileges needs non-nil Guards",
		},
		{
			name: "ResourceOwnerships",
			build: func() {
				fibersec.ResourceOwnerships[string](nil, "orders", "order", ownedByAnyone)
			},
			panics: "fibersec: ResourceOwnerships needs non-nil Guards",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.PanicsWithValue(t, tc.panics, tc.build)
		})
	}
}
