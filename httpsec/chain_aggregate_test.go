package httpsec_test

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// TestChain_IPv6Aggregate_Construction pins that an aggregate that cannot take
// effect fails at construction, naming the option, whatever order the options
// came in, and that the default is skipped when the source prefix is already
// as wide as the aggregate.
func TestChain_IPv6Aggregate_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(option string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), option, "the error names the option to change")
		}
	}

	accepted := func(t *testing.T, err error) { require.NoError(t, err) }

	cases := []testCase{
		{
			name:   "aggregate no wider than the source",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(48), httpsec.WithIPv6Aggregate(56, 4)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "aggregate as wide as the source",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(56), httpsec.WithIPv6Aggregate(56, 4)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "zero multiplier",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(56, 0)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "multiplier that overflows the flow's limit",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(56, 1<<62+1)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "bits 0",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(0, 4)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "bits 128",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(128), httpsec.WithIPv6Aggregate(128, 4)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "both",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(56, 4), httpsec.WithoutIPv6Aggregate()},
			assert: refused("WithoutIPv6Aggregate"),
		},
		{
			name:   "both, the other way round",
			opts:   []httpsec.Option{httpsec.WithoutIPv6Aggregate(), httpsec.WithIPv6Aggregate(56, 4)},
			assert: refused("WithoutIPv6Aggregate"),
		},
		{
			name:   "wide source skips the default",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(48)},
			assert: accepted,
		},
		{
			name:   "order independent",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(48, 2), httpsec.WithIPv6SourcePrefix(64)},
			assert: accepted,
		},
		{
			name:   "defaults",
			assert: accepted,
		},
		{
			name:   "turned off beside a wide source",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(48), httpsec.WithoutIPv6Aggregate()},
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)

			_, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableAPIKey(h.keys),
			}, tc.opts...)...)
			tc.assert(t, err)
		})
	}
}

// TestChain_IPv6Aggregate_Throttles pins, through real requests, that the
// chain's source guards also count IPv6 clients by the aggregate: a client
// rotating through the /64s of one allocation is throttled once the aggregate
// is spent, by default, by a consumer's own aggregate, and not when it is
// turned off.
func TestChain_IPv6Aggregate_Throttles(t *testing.T) {
	t.Parallel()

	// failFrom spends the API-key default of 20 a minute from addr.
	failFrom := func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain, addr string) {
		t.Helper()

		for range 20 {
			require.True(t, presentUnknownKey(t, h, c, addr),
				"the source's own allowance is 20, so %s is not throttled yet", addr)
		}
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain)
	}

	cases := []testCase{
		{
			name: "default aggregate",
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				for i := 1; i <= 4; i++ {
					failFrom(t, h, c, fmt.Sprintf("2001:db8:1:%d::1", i))
				}

				assert.False(t, presentUnknownKey(t, h, c, "2001:db8:1:5::1"),
					"four times the limit is spent across the /56, so a fifth /64 is refused as throttled")
				assert.True(t, presentUnknownKey(t, h, c, "2001:db8:2:1::1"),
					"another /56 has its own aggregate")
			},
		},
		{
			name: "consumer aggregate",
			opts: []httpsec.Option{httpsec.WithIPv6Aggregate(48, 2)},
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				failFrom(t, h, c, "2001:db8:1:1::1")
				failFrom(t, h, c, "2001:db8:1:200::1")

				assert.False(t, presentUnknownKey(t, h, c, "2001:db8:1:300::1"),
					"twice the limit is spent across the /48, so a third /64, in another /56, is refused")
			},
		},
		{
			name: "aggregate turned off",
			opts: []httpsec.Option{httpsec.WithoutIPv6Aggregate()},
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				for i := 1; i <= 4; i++ {
					failFrom(t, h, c, fmt.Sprintf("2001:db8:1:%d::1", i))
				}

				assert.True(t, presentUnknownKey(t, h, c, "2001:db8:1:5::1"),
					"with no aggregate, every /64 has its own allowance")
			},
		},
		{
			name: "default prefix",
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				failFrom(t, h, c, "2001:db8:1:1::1")

				assert.True(t, presentUnknownKey(t, h, c, "2001:db8:1:2::1"),
					"one /64 spending its own allowance does not throttle its neighbour")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)

			c, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableAPIKey(h.keys),
			}, tc.opts...)...)
			require.NoError(t, err)

			tc.assert(t, h, c)
		})
	}
}
