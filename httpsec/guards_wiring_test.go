package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
)

// TestOwnershipGuard_WiringPanics pins that an ownership guard with no
// question to ask, or no way to find the record, fails when the consumer wires
// it, before any traffic, rather than refusing every request it ever sees.
func TestOwnershipGuard_WiringPanics(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		wire   func(g *httpsec.Guards)
		assert func(t *testing.T, wire func())
	}

	panics := func(msg string) func(t *testing.T, wire func()) {
		return func(t *testing.T, wire func()) {
			t.Helper()
			assert.PanicsWithValue(t, msg, wire)
		}
	}

	cases := []testCase{
		{
			name: "ResourceOwnerships on a nil Guards",
			wire: func(*httpsec.Guards) {
				httpsec.ResourceOwnerships(nil, "admin", "user", recordOwner(true, nil))
			},
			assert: panics("httpsec: ResourceOwnerships needs non-nil Guards"),
		},
		{
			name: "ResourcePrivileges on a nil Guards",
			wire: func(*httpsec.Guards) {
				var g *httpsec.Guards
				g.ResourcePrivileges("admin", "user")
			},
			assert: panics("httpsec: ResourcePrivileges needs non-nil Guards"),
		},
		{
			name: "RequireAuthenticated on a nil Guards",
			wire: func(*httpsec.Guards) {
				var g *httpsec.Guards
				g.RequireAuthenticated()
			},
			assert: panics("httpsec: RequireAuthenticated needs non-nil Guards"),
		},
		{
			name: "a nil checker",
			wire: func(g *httpsec.Guards) {
				httpsec.ResourceOwnerships[string](g, "admin", "user", nil)
			},
			assert: panics("httpsec: ResourceOwnerships needs a non-nil checker"),
		},
		{
			name: "a nil extractor",
			wire: func(g *httpsec.Guards) {
				httpsec.ResourceOwnerships(g, "admin", "user", recordOwner(true, nil)).ForResource(nil)
			},
			assert: panics("httpsec: ForResource needs a non-nil extractor"),
		},
		{
			name: "a checker and an extractor wire without a panic",
			wire: func(g *httpsec.Guards) {
				httpsec.ResourceOwnerships(g, "admin", "user", recordOwner(true, nil)).ForResource(recordID(nil))
			},
			assert: func(t *testing.T, wire func()) {
				t.Helper()
				assert.NotPanics(t, wire)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := httpsec.NewGuards(authorize.NewOwnershipAuthorizer())
			tc.assert(t, func() { tc.wire(g) })
		})
	}
}
