package oidc_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
)

func TestAuthorize_BoundsUntrustedNextLength(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		next string
		want string
	}

	atBound := "/" + strings.Repeat("a", 2047)

	cases := []testCase{
		{name: "a next of exactly 2048 bytes is recorded", next: atBound, want: atBound},
		{name: "a next of 2049 bytes is not recorded", next: atBound + "a", want: ""},
		{name: "a next of 1 MiB is not recorded", next: "/" + strings.Repeat("a", 1<<20), want: ""},
		{name: "a short next is recorded verbatim", next: "/after?x=1", want: "/after?x=1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			reg, err := oidc.NewRegistry(p.Provider("corp"))
			require.NoError(t, err)

			m, err := oidc.NewManager(reg, stubBroker{}, oidc.WithOutboundClient(p.Outbound(t)))
			require.NoError(t, err)

			got, err := m.Authorize(t.Context(), "corp", tc.next)
			require.NoError(t, err, "an over-long next never fails the login")

			assert.Equal(t, tc.want, authorizeFlow(t, m, got.Handle).Next)
		})
	}
}
