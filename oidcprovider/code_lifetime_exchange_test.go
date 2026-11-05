package oidcprovider_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
)

// A code lives as long as the consumer set, and the exchange judges it by that.
func TestProvider_ExchangeCode_HonoursTheCodeLifetime(t *testing.T) {
	t.Parallel()

	const idleBeforeExchange = 2 * time.Minute

	type testCase struct {
		name   string
		opts   []oidcprovider.Option
		assert func(t *testing.T, res *oidcprovider.TokenResponse, err error)
	}

	cases := []testCase{
		{
			name: "the default 60 seconds refuses a code two minutes old",
			assert: func(t *testing.T, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				assertRefused(t, err, oidcprovider.CodeInvalidGrant)
				assert.Nil(t, res)
			},
		},
		{
			name: "a consumer lengthening it to 5 minutes has the exchange proceed",
			opts: []oidcprovider.Option{oidcprovider.WithCodeLifetime(5 * time.Minute)},
			assert: func(t *testing.T, res *oidcprovider.TokenResponse, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotEmpty(t, res.AccessToken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			x := newExchangeFixture(t, tc.opts...)
			c := x.issue(t)
			x.clk.Advance(idleBeforeExchange)

			res, err := x.p.Token(t.Context(), byOwner(c))
			tc.assert(t, res, err)
		})
	}
}
