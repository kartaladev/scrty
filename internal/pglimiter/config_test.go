package pglimiter_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pglimiter"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
)

// typedNilClock is a consumer's clock type; (*typedNilClock)(nil) is the typed
// nil a plain `== nil` check misses.
type typedNilClock struct{}

func (*typedNilClock) Now() time.Time { return time.Time{} }

// refusedWith asserts a configuration error whose whole message is
// ratelimit.ErrConfig's followed by want.
func refusedWith(want string) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrConfig)
		assert.EqualError(t, err, ratelimit.ErrConfig.Error()+": "+want)
	}
}

func accepted(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err)
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	got := pglimiter.DefaultConfig()
	want := unavailable.DefaultConfig()

	assert.Nil(t, got.Clock, "the database's clock is the default")
	assert.False(t, got.ClockSet)
	assert.Equal(t, want.Mode, got.Unavailable.Mode)
	assert.Equal(t, want.Timeout, got.Unavailable.Timeout)
	assert.Equal(t, want.ProbeInterval, got.Unavailable.ProbeInterval)
	assert.Equal(t, want.LogInterval, got.Unavailable.LogInterval)
	assert.Same(t, want.Logger, got.Unavailable.Logger)
	assert.NotNil(t, got.Unavailable.Clock)
	require.NoError(t, got.Validate())
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tooLong := time.Duration(pgschema.LimiterMaxLockTimeoutMS+1) * time.Millisecond

	type testCase struct {
		name   string
		cfg    func(c pglimiter.Config) pglimiter.Config
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "default",
			cfg:    func(c pglimiter.Config) pglimiter.Config { return c },
			assert: accepted,
		},
		{
			name: "application clock",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				clk := clockwork.NewFakeClock()
				c.Clock, c.ClockSet, c.Unavailable.Clock = clk, true, clk
				return c
			},
			assert: accepted,
		},
		{
			name: "operation timeout at the lock_timeout ceiling",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c.Unavailable.Timeout = time.Duration(pgschema.LimiterMaxLockTimeoutMS) * time.Millisecond
				return c
			},
			assert: accepted,
		},
		{
			name: "operation timeout above the lock_timeout ceiling",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c.Unavailable.Timeout = tooLong
				return c
			},
			assert: refusedWith("an operation timeout of " + tooLong.String() +
				" is above the lock_timeout PostgreSQL accepts, at most 2147483647ms"),
		},
		{
			name: "nil clock given",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c.Clock, c.ClockSet, c.Unavailable.Clock = nil, true, nil
				return c
			},
			assert: refusedWith("the limiter clock is nil"),
		},
		{
			name: "typed nil clock given",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				var clk clock.Clock = (*typedNilClock)(nil)
				c.Clock, c.ClockSet, c.Unavailable.Clock = clk, true, clk
				return c
			},
			assert: refusedWith("the limiter clock is nil"),
		},
		{
			name: "ceiling checked before the clock",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c.Clock, c.ClockSet, c.Unavailable.Clock = nil, true, nil
				c.Unavailable.Timeout = tooLong
				return c
			},
			assert: refusedWith("an operation timeout of " + tooLong.String() +
				" is above the lock_timeout PostgreSQL accepts, at most 2147483647ms"),
		},
		{
			name: "nil logger, through the decorator's rules",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c.Unavailable.Logger = nil
				return c
			},
			assert: refusedWith("the logger is nil, so outage records would be lost"),
		},
		{
			name: "zero operation timeout, through the decorator's rules",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c.Unavailable.Timeout = 0
				return c
			},
			assert: refusedWith("an operation timeout of 0s bounds nothing"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.cfg(pglimiter.DefaultConfig()).Validate())
		})
	}
}

func TestValidatePolicy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		namespace string
		limit     int
		window    time.Duration
		assert    func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "valid policy", namespace: "mfa-verify", limit: 5, window: time.Minute,
			assert: accepted,
		},
		{
			name: "widest policy", namespace: strings.Repeat("n", pgschema.LimiterMaxNamespace),
			limit: pgschema.LimiterMaxLimit, window: time.Microsecond,
			assert: accepted,
		},
		{
			name: "empty namespace", namespace: "", limit: 5, window: time.Minute,
			assert: refusedWith("the namespace is empty, so this limiter would share buckets with every other"),
		},
		{
			name: "namespace with a colon", namespace: "mfa:verify", limit: 5, window: time.Minute,
			assert: refusedWith(`the namespace "mfa:verify" contains a colon, which separates it from the key`),
		},
		{
			name: "namespace with a NUL byte", namespace: "mfa\x00verify", limit: 5, window: time.Minute,
			assert: refusedWith("the namespace must be valid UTF-8 without NUL bytes, which PostgreSQL's text type cannot store"),
		},
		{
			name: "namespace with invalid UTF-8", namespace: "mfa\xffverify", limit: 5, window: time.Minute,
			assert: refusedWith("the namespace must be valid UTF-8 without NUL bytes, which PostgreSQL's text type cannot store"),
		},
		{
			name: "namespace of 65 bytes", namespace: strings.Repeat("n", 65), limit: 5, window: time.Minute,
			assert: refusedWith("the namespace is 65 bytes, longer than the 64 bytes a bucket's row holds"),
		},
		{
			// 65 bytes with a colon and invalid UTF-8: the colon is named first.
			name: "colon is refused before invalid UTF-8 and length", namespace: "a:\xff" + strings.Repeat("n", 62),
			limit: 5, window: time.Minute,
			assert: refusedWith(`the namespace "a:\xffnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" contains a colon, ` +
				"which separates it from the key"),
		},
		{
			// 65 bytes with invalid UTF-8: the encoding is named before the length.
			name: "invalid UTF-8 is refused before length", namespace: "a\xff" + strings.Repeat("n", 63),
			limit: 5, window: time.Minute,
			assert: refusedWith("the namespace must be valid UTF-8 without NUL bytes, which PostgreSQL's text type cannot store"),
		},
		{
			name: "limit of zero", namespace: "mfa-verify", limit: 0, window: time.Minute,
			assert: refusedWith("a limit of 0 throttles every source from its first attempt"),
		},
		{
			name: "limit of 401", namespace: "mfa-verify", limit: 401, window: time.Minute,
			assert: refusedWith("a limit of 401 is above 400, the most failure stamps a bucket's row holds"),
		},
		{
			name: "window of 999ns", namespace: "mfa-verify", limit: 5, window: 999 * time.Nanosecond,
			assert: refusedWith("a window of 999ns is shorter than the microsecond stamps are stored in"),
		},
		{
			name: "namespace checked before limit and window", namespace: "", limit: 0, window: 0,
			assert: refusedWith("the namespace is empty, so this limiter would share buckets with every other"),
		},
		{
			name: "limit checked before window", namespace: "mfa-verify", limit: 0, window: 0,
			assert: refusedWith("a limit of 0 throttles every source from its first attempt"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, pglimiter.ValidatePolicy(tc.namespace, tc.limit, tc.window))
		})
	}
}

func TestLockTimeout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		d      time.Duration
		assert func(t *testing.T, got string)
	}

	is := func(want string) func(t *testing.T, got string) {
		return func(t *testing.T, got string) {
			t.Helper()
			assert.Equal(t, want, got)
		}
	}

	cases := []testCase{
		{name: "zero is at least one millisecond", d: 0, assert: is("1ms")},
		{name: "whole milliseconds", d: 250 * time.Millisecond, assert: is("250ms")},
		{name: "a fraction is dropped", d: 1500 * time.Microsecond, assert: is("1ms")},
		{name: "below a millisecond is one", d: 999 * time.Microsecond, assert: is("1ms")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, pglimiter.LockTimeout(tc.d))
		})
	}
}

func TestNow(t *testing.T) {
	t.Parallel()

	zone := time.FixedZone("UTC+7", 7*60*60)
	at := time.Date(2026, 10, 10, 19, 0, 0, 123456789, zone)

	type testCase struct {
		name   string
		clk    clock.Clock
		assert func(t *testing.T, got any)
	}

	cases := []testCase{
		{
			name: "database clock is a nil parameter",
			clk:  nil,
			assert: func(t *testing.T, got any) {
				assert.Nil(t, got)
			},
		},
		{
			name: "application clock in UTC whole microseconds",
			clk:  clockwork.NewFakeClockAt(at),
			assert: func(t *testing.T, got any) {
				require.IsType(t, time.Time{}, got)
				ts := got.(time.Time)
				assert.Equal(t, time.UTC, ts.Location())
				assert.True(t, ts.Equal(time.Date(2026, 10, 10, 12, 0, 0, 123456000, time.UTC)), "got %s", ts)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, pglimiter.Now(tc.clk))
		})
	}
}
