package ginsec_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
)

// ownedByAnyone is a checker that is never reached: the cases here fail at wiring.
func ownedByAnyone(context.Context, *identity.Principal, string) (bool, error) { return true, nil }

// TestGin_OwnershipGuardWithNilCheckerFailsAtWiring pins that a guard built without what it
// cannot work without panics when it is wired, naming the missing dependency,
// instead of refusing every request once traffic arrives.
func TestGin_OwnershipGuardWithNilCheckerFailsAtWiring(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "ginsec: ResourceOwnerships needs a non-nil checker", func() {
		ginsec.ResourceOwnerships[string](ginsec.NewGuards(nil), "orders", "order", nil)
	})
}

func TestGin_OwnershipGuardWithNilExtractorFailsAtWiring(t *testing.T) {
	t.Parallel()

	owned := ginsec.ResourceOwnerships[string](ginsec.NewGuards(nil), "orders", "order", ownedByAnyone)

	assert.PanicsWithValue(t, "ginsec: ForResource needs a non-nil extractor", func() {
		owned.ForResource(nil)
	})
}

func TestGin_GuardsBuildersWithNilGuardsFailAtWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func()
		panics string
	}

	cases := []testCase{
		{
			name:   "RequireAuthenticated",
			build:  func() { (*ginsec.Guards)(nil).RequireAuthenticated() },
			panics: "ginsec: RequireAuthenticated needs non-nil Guards",
		},
		{
			name:   "ResourcePrivileges",
			build:  func() { (*ginsec.Guards)(nil).ResourcePrivileges("orders", "order") },
			panics: "ginsec: ResourcePrivileges needs non-nil Guards",
		},
		{
			name: "ResourceOwnerships",
			build: func() {
				ginsec.ResourceOwnerships[string](nil, "orders", "order", ownedByAnyone)
			},
			panics: "ginsec: ResourceOwnerships needs non-nil Guards",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.PanicsWithValue(t, tc.panics, tc.build)
		})
	}
}
