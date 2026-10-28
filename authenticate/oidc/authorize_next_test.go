package oidc_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/oidc"
)

func TestAuthorize_BoundsUntrustedNextLength(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		next   string
		assert func(t *testing.T, recorded string)
	}

	recorded := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()

			assert.Equal(t, want, got)
		}
	}

	atBound := "/" + strings.Repeat("a", 2047)

	cases := []testCase{
		{name: "a next of exactly 2048 bytes is recorded", next: atBound, assert: recorded(atBound)},
		{name: "a next of 2049 bytes is not recorded", next: atBound + "a", assert: recorded("")},
		{name: "a next of 1 MiB is not recorded", next: "/" + strings.Repeat("a", 1<<20), assert: recorded("")},
		{name: "a short next is recorded verbatim", next: "/after?x=1", assert: recorded("/after?x=1")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			reg, err := oidc.NewRegistry(p.Provider("corp"))
			require.NoError(t, err)

			m, err := oidc.NewRelyingParty(reg, stubBroker{}, oidc.WithOutboundClient(p.Outbound(t)))
			require.NoError(t, err)

			got, err := m.Authorize(t.Context(), "corp", tc.next)
			require.NoError(t, err, "an over-long next never fails the login")

			tc.assert(t, authorizeFlow(t, m, got.Handle).Next)
		})
	}
}
