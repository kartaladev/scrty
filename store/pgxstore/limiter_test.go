package pgxstore_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/store/pgxstore"
)

// typedNilClock is a consumer's clock type; (*typedNilClock)(nil) is the typed
// nil a plain `== nil` check misses.
type typedNilClock struct{}

func (*typedNilClock) Now() time.Time { return time.Time{} }

func TestNewLimiter(t *testing.T) {
	t.Parallel()

	// The pool is built on a config that never dials: construction performs no
	// I/O, so a constructor that touched it would fail these cases.
	db := newIdlePool(t)

	accepted := func(t *testing.T, l *pgxstore.Limiter, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, l)
	}
	refused := func(want ...string) func(t *testing.T, l *pgxstore.Limiter, err error) {
		return func(t *testing.T, l *pgxstore.Limiter, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			for _, w := range want {
				assert.Contains(t, err.Error(), w)
			}
			assert.Nil(t, l)
		}
	}

	type testCase struct {
		name      string
		db        *pgxpool.Pool
		namespace string
		limit     int
		window    time.Duration
		opts      []pgxstore.LimiterOption
		assert    func(t *testing.T, l *pgxstore.Limiter, err error)
	}

	cases := []testCase{
		{name: "defaults accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute, assert: accepted},
		{name: "nil handle", db: nil, namespace: "api-key", limit: 20, window: time.Minute, assert: refused("nil")},
		{name: "typed nil handle", db: (*pgxpool.Pool)(nil), namespace: "api-key", limit: 20, window: time.Minute, assert: refused("nil")},
		{name: "empty namespace", db: db, namespace: "", limit: 20, window: time.Minute, assert: refused("namespace")},
		{name: "colon in namespace", db: db, namespace: "a:b", limit: 20, window: time.Minute, assert: refused("colon")},
		{name: "NUL in namespace", db: db, namespace: "a\x00b", limit: 20, window: time.Minute, assert: refused("UTF-8", "NUL")},
		{name: "invalid UTF-8 in namespace", db: db, namespace: "a\xffb", limit: 20, window: time.Minute, assert: refused("UTF-8", "NUL")},
		{name: "64-byte namespace accepted", db: db, namespace: strings.Repeat("n", 64), limit: 20, window: time.Minute, assert: accepted},
		{name: "65-byte namespace", db: db, namespace: strings.Repeat("n", 65), limit: 20, window: time.Minute, assert: refused("64")},
		{
			name: "64 bytes of multi-byte UTF-8 accepted", db: db, namespace: strings.Repeat("é", 32), limit: 20, window: time.Minute,
			assert: accepted,
		},
		{
			name: "65 bytes of multi-byte UTF-8 refused", db: db, namespace: strings.Repeat("é", 32) + "x", limit: 20, window: time.Minute,
			assert: refused("64"),
		},
		{name: "zero limit", db: db, namespace: "api-key", limit: 0, window: time.Minute, assert: refused("limit")},
		{name: "negative limit", db: db, namespace: "api-key", limit: -1, window: time.Minute, assert: refused("limit")},
		{name: "limit 401", db: db, namespace: "api-key", limit: 401, window: time.Minute, assert: refused("400")},
		{name: "limit 400 accepted", db: db, namespace: "api-key", limit: 400, window: time.Minute, assert: accepted},
		{name: "sub-microsecond window", db: db, namespace: "api-key", limit: 20, window: 999 * time.Nanosecond, assert: refused("microsecond")},
		{name: "one-microsecond window accepted", db: db, namespace: "api-key", limit: 20, window: time.Microsecond, assert: accepted},
		{
			name: "clock accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterClock(clockwork.NewFakeClock())}, assert: accepted,
		},
		{
			name: "nil clock", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterClock(nil)}, assert: refused("clock"),
		},
		{
			name: "typed nil clock", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterClock((*typedNilClock)(nil))}, assert: refused("clock"),
		},
		{
			name: "nil logger", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterLogger(nil)}, assert: refused("logger"),
		},
		{
			name: "unknown mode", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterOnUnavailable(99)}, assert: refused("mode"),
		},
		{
			name: "fall-back mode accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []pgxstore.LimiterOption{pgxstore.WithLimiterOnUnavailable(ratelimit.UnavailableFallbackToLocal)},
			assert: accepted,
		},
		{
			name: "zero timeout", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterOperationTimeout(0)}, assert: refused("timeout"),
		},
		{
			name: "negative timeout", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterOperationTimeout(-time.Second)}, assert: refused("timeout"),
		},
		{
			name: "timeout at the lock_timeout maximum accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []pgxstore.LimiterOption{pgxstore.WithLimiterOperationTimeout(2147483647 * time.Millisecond)},
			assert: accepted,
		},
		{
			name: "timeout above the lock_timeout maximum", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []pgxstore.LimiterOption{pgxstore.WithLimiterOperationTimeout(2147483648 * time.Millisecond)},
			assert: refused("timeout", "at most 2147483647ms"),
		},
		{
			name: "zero probe interval", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterProbeInterval(0)}, assert: refused("probe"),
		},
		{
			name: "zero log interval accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{pgxstore.WithLimiterUnavailableLogInterval(0)}, assert: accepted,
		},
		{
			name: "nil option skipped", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []pgxstore.LimiterOption{nil}, assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := pgxstore.NewLimiter(tc.db, tc.namespace, tc.limit, tc.window, tc.opts...)
			tc.assert(t, l, err)
		})
	}
}

func TestLimiter_Policy(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		window time.Duration
		assert func(t *testing.T, limit int, window time.Duration)
	}

	cases := []testCase{
		{
			name: "whole window reported as given", window: time.Minute,
			assert: func(t *testing.T, limit int, window time.Duration) {
				assert.Equal(t, 7, limit)
				assert.Equal(t, time.Minute, window)
			},
		},
		{
			name: "sub-microsecond part dropped", window: time.Minute + 999*time.Nanosecond,
			assert: func(t *testing.T, limit int, window time.Duration) {
				assert.Equal(t, 7, limit)
				assert.Equal(t, time.Minute, window)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := pgxstore.NewLimiter(newIdlePool(t), "api-key", 7, tc.window)
			require.NoError(t, err)
			limit, window := l.Policy()
			tc.assert(t, limit, window)
		})
	}
}

// TestLimiter_VerifyErrorsStartWithThePrefix pins the adapter's prefix on the
// shared core's errors: the idle pool's address refuses every connection.
func TestLimiter_VerifyErrorsStartWithThePrefix(t *testing.T) {
	t.Parallel()

	l, err := pgxstore.NewLimiter(newIdlePool(t), "api-key", 3, time.Minute)
	require.NoError(t, err)

	err = l.Verify(t.Context())
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "pgxstore: "), "got %q", err)
}
