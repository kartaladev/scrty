package ratelimit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

// TestSourcesAreCanonicalisedBeforeTheyBecomeKeys pins the shape of the key an
// address turns into. Keying an IPv6 address per address would let one ordinary
// allocation spend an unbounded number of keys, and unmapping is what stops the
// same IPv4 client holding two allowances depending on how it reached the
// process.
func TestSourcesAreCanonicalisedBeforeTheyBecomeKeys(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []ratelimit.KeyerOption
		addr   string
		assert func(t *testing.T, key string, err error)
	}

	keysAs := func(want string) func(t *testing.T, key string, err error) {
		return func(t *testing.T, key string, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want, key)
		}
	}
	refusedAs := func(want error) func(t *testing.T, key string, err error) {
		return func(t *testing.T, key string, err error) {
			t.Helper()
			require.ErrorIs(t, err, want)
			require.ErrorIs(t, err, ratelimit.ErrSourceUnattributable,
				"the refusal did not carry the reason callers match on")
			assert.Empty(t, key, "a refused address still produced a key to count under")
		}
	}

	cases := []testCase{
		{
			name:   "IPv4 keys per address",
			addr:   "198.51.100.7",
			assert: keysAs("198.51.100.7"),
		},
		{
			name:   "an IPv4-mapped address is unmapped",
			addr:   "::ffff:198.51.100.7",
			assert: keysAs("198.51.100.7"),
		},
		{
			name:   "IPv6 keys by its /64 prefix",
			addr:   "2001:db8:1:2:3:4:5:6",
			assert: keysAs("2001:db8:1:2::/64"),
		},
		{
			name:   "two addresses in one /64 share a key",
			addr:   "2001:db8:1:2:ffff:ffff:ffff:9",
			assert: keysAs("2001:db8:1:2::/64"),
		},
		{
			name:   "the IPv6 zone is dropped",
			addr:   "fe80::1%eth0",
			assert: keysAs("fe80::/64"),
		},
		{
			name:   "a custom prefix is honoured",
			opts:   []ratelimit.KeyerOption{ratelimit.WithIPv6SourcePrefix(48)},
			addr:   "2001:db8:1:2:3:4:5:6",
			assert: keysAs("2001:db8:1::/48"),
		},
		{
			name:   "a custom prefix masks the bits it keeps",
			opts:   []ratelimit.KeyerOption{ratelimit.WithIPv6SourcePrefix(56)},
			addr:   "2001:db8:1:299::1",
			assert: keysAs("2001:db8:1:200::/56"),
		},
		{
			name:   "a custom prefix does not change IPv4 keys",
			opts:   []ratelimit.KeyerOption{ratelimit.WithIPv6SourcePrefix(48)},
			addr:   "198.51.100.7",
			assert: keysAs("198.51.100.7"),
		},
		{
			name:   "an empty address is unattributable",
			addr:   "",
			assert: refusedAs(ratelimit.ErrSourceEmpty),
		},
		{
			name:   "a host and port is not a single IP",
			addr:   "example.com:443",
			assert: refusedAs(ratelimit.ErrSourceNotAnIP),
		},
		{
			name:   "a forwarding list is not a single IP",
			addr:   "198.51.100.1, 203.0.113.9",
			assert: refusedAs(ratelimit.ErrSourceNotAnIP),
		},
		{
			name:   "an address with surrounding space is not a single IP",
			addr:   " 198.51.100.7 ",
			assert: refusedAs(ratelimit.ErrSourceNotAnIP),
		},
		{
			name:   "the unspecified IPv4 address is refused",
			addr:   "0.0.0.0",
			assert: refusedAs(ratelimit.ErrSourceUnspecified),
		},
		{
			name:   "the unspecified IPv6 address is refused",
			addr:   "::",
			assert: refusedAs(ratelimit.ErrSourceUnspecified),
		},
		{
			name:   "the unspecified address is refused once unmapped",
			addr:   "::ffff:0.0.0.0",
			assert: refusedAs(ratelimit.ErrSourceUnspecified),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keyer, err := ratelimit.NewSourceKeyer(tc.opts...)
			require.NoError(t, err)

			key, err := keyer.Key(tc.addr)
			tc.assert(t, key, err)
		})
	}
}

// TestNewSourceKeyerRefusesAPrefixItCannotMask pins the bounds of the prefix
// option. A prefix of zero would key every IPv6 source in the world under one
// bucket, which is the pooling the keyer exists to prevent.
func TestNewSourceKeyerRefusesAPrefixItCannotMask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		bits   int
		assert func(t *testing.T, keyer *ratelimit.SourceKeyer, err error)
	}

	refused := func(t *testing.T, keyer *ratelimit.SourceKeyer, err error) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.Nil(t, keyer, "a refused configuration still handed back a keyer")
	}
	accepted := func(t *testing.T, keyer *ratelimit.SourceKeyer, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.NotNil(t, keyer)
	}

	cases := []testCase{
		{name: "a prefix of 0 pools every IPv6 source", bits: 0, assert: refused},
		{name: "a negative prefix cannot mask", bits: -1, assert: refused},
		{name: "a prefix of 129 is wider than an address", bits: 129, assert: refused},
		{name: "a prefix of 1 is accepted", bits: 1, assert: accepted},
		{name: "a prefix of 128 keys per address", bits: 128, assert: accepted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keyer, err := ratelimit.NewSourceKeyer(ratelimit.WithIPv6SourcePrefix(tc.bits))
			tc.assert(t, keyer, err)
		})
	}
}

// TestSourceKeyer_IPv6Prefix pins the accessor a guard reads to check that an
// aggregate is wider than the source, including against a keyer the consumer
// built.
func TestSourceKeyer_IPv6Prefix(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []ratelimit.KeyerOption
		assert func(t *testing.T, bits int)
	}

	cases := []testCase{
		{
			name: "the default is a /64",
			assert: func(t *testing.T, bits int) {
				t.Helper()
				assert.Equal(t, 64, bits)
			},
		},
		{
			name: "a custom prefix is reported",
			opts: []ratelimit.KeyerOption{ratelimit.WithIPv6SourcePrefix(56)},
			assert: func(t *testing.T, bits int) {
				t.Helper()
				assert.Equal(t, 56, bits)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keyer, err := ratelimit.NewSourceKeyer(tc.opts...)
			require.NoError(t, err)

			tc.assert(t, keyer.IPv6Prefix())
		})
	}
}

// TestSourceKeyer_Aggregate pins the enclosing prefix an IPv6 source is also
// counted under. A mapped IPv4 address must not grow an aggregate just because
// of how it was spelled, and a zone must not split one aggregate into one per
// interface.
func TestSourceKeyer_Aggregate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		addr   string
		bits   int
		assert func(t *testing.T, source, aggregate string, err error)
	}

	keysAs := func(wantSource, wantAggregate string) func(t *testing.T, source, aggregate string, err error) {
		return func(t *testing.T, source, aggregate string, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, wantSource, source, "source key")
			assert.Equal(t, wantAggregate, aggregate, "aggregate key")
		}
	}

	cases := []testCase{
		{
			name:   "an IPv6 source is aggregated by its enclosing /56",
			addr:   "2001:db8:1:2::1",
			bits:   56,
			assert: keysAs("2001:db8:1:2::/64", "2001:db8:1::/56"),
		},
		{
			name:   "a source in another /56 aggregates apart",
			addr:   "2001:db8:1:100::1",
			bits:   56,
			assert: keysAs("2001:db8:1:100::/64", "2001:db8:1:100::/56"),
		},
		{
			name:   "the zone is dropped from the aggregate",
			addr:   "fe80::1%eth0",
			bits:   56,
			assert: keysAs("fe80::/64", "fe80::/56"),
		},
		{
			name:   "an IPv4-mapped address has no aggregate",
			addr:   "::ffff:203.0.113.7",
			bits:   56,
			assert: keysAs("203.0.113.7", ""),
		},
		{
			name:   "IPv4 has no aggregate",
			addr:   "203.0.113.7",
			bits:   56,
			assert: keysAs("203.0.113.7", ""),
		},
		{
			name:   "no aggregate is keyed when none is asked for",
			addr:   "2001:db8:1:2::1",
			bits:   0,
			assert: keysAs("2001:db8:1:2::/64", ""),
		},
		{
			name: "an unattributable address keys neither",
			addr: "",
			bits: 56,
			assert: func(t *testing.T, source, aggregate string, err error) {
				t.Helper()
				require.ErrorIs(t, err, ratelimit.ErrSourceEmpty)
				assert.Empty(t, source)
				assert.Empty(t, aggregate)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			keyer, err := ratelimit.NewSourceKeyer()
			require.NoError(t, err)

			source, aggregate, err := ratelimit.SourceKeys(keyer, tc.addr, tc.bits)
			tc.assert(t, source, aggregate, err)
		})
	}
}
