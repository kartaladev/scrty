package sqlstore_test

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/sqlstore"
)

// typedNilClock is a consumer's clock type; (*typedNilClock)(nil) is the typed
// nil a plain `== nil` check misses.
type typedNilClock struct{}

func (*typedNilClock) Now() time.Time { return time.Time{} }

func TestNewLimiter(t *testing.T) {
	t.Parallel()

	// A zero *sql.DB is never used: construction performs no I/O, and would
	// panic here if it tried.
	db := new(sql.DB)

	accepted := func(t *testing.T, l *sqlstore.Limiter, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, l)
	}
	refused := func(want ...string) func(t *testing.T, l *sqlstore.Limiter, err error) {
		return func(t *testing.T, l *sqlstore.Limiter, err error) {
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
		db        *sql.DB
		namespace string
		limit     int
		window    time.Duration
		opts      []sqlstore.LimiterOption
		assert    func(t *testing.T, l *sqlstore.Limiter, err error)
	}

	cases := []testCase{
		{name: "defaults accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute, assert: accepted},
		{name: "nil handle", db: nil, namespace: "api-key", limit: 20, window: time.Minute, assert: refused("nil")},
		{name: "empty namespace", db: db, namespace: "", limit: 20, window: time.Minute, assert: refused("namespace")},
		{name: "colon in namespace", db: db, namespace: "a:b", limit: 20, window: time.Minute, assert: refused("colon")},
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
		{name: "limit 129", db: db, namespace: "api-key", limit: 129, window: time.Minute, assert: refused("128")},
		{name: "limit 128 accepted", db: db, namespace: "api-key", limit: 128, window: time.Minute, assert: accepted},
		{name: "sub-microsecond window", db: db, namespace: "api-key", limit: 20, window: 999 * time.Nanosecond, assert: refused("microsecond")},
		{name: "one-microsecond window accepted", db: db, namespace: "api-key", limit: 20, window: time.Microsecond, assert: accepted},
		{
			name: "clock accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterClock(clockwork.NewFakeClock())}, assert: accepted,
		},
		{
			name: "nil clock", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterClock(nil)}, assert: refused("clock"),
		},
		{
			name: "typed nil clock", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterClock((*typedNilClock)(nil))}, assert: refused("clock"),
		},
		{
			name: "nil logger", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterLogger(nil)}, assert: refused("logger"),
		},
		{
			name: "unknown mode", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOnUnavailable(99)}, assert: refused("mode"),
		},
		{
			name: "fall-back mode accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []sqlstore.LimiterOption{sqlstore.WithLimiterOnUnavailable(ratelimit.UnavailableFallBackToLocal)},
			assert: accepted,
		},
		{
			name: "zero timeout", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(0)}, assert: refused("timeout"),
		},
		{
			name: "negative timeout", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(-time.Second)}, assert: refused("timeout"),
		},
		{
			name: "timeout at the lock_timeout maximum accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(2147483647 * time.Millisecond)},
			assert: accepted,
		},
		{
			name: "timeout above the lock_timeout maximum", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts:   []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(2147483648 * time.Millisecond)},
			assert: refused("timeout", "at most 2147483647ms"),
		},
		{
			name: "zero probe interval", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterProbeInterval(0)}, assert: refused("probe"),
		},
		{
			name: "zero log interval accepted", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{sqlstore.WithLimiterUnavailableLogInterval(0)}, assert: accepted,
		},
		{
			name: "nil option skipped", db: db, namespace: "api-key", limit: 20, window: time.Minute,
			opts: []sqlstore.LimiterOption{nil}, assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			l, err := sqlstore.NewLimiter(tc.db, tc.namespace, tc.limit, tc.window, tc.opts...)
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

			l, err := sqlstore.NewLimiter(new(sql.DB), "api-key", 7, tc.window)
			require.NoError(t, err)
			limit, window := l.Policy()
			tc.assert(t, limit, window)
		})
	}
}

func TestNewLimiterFactory(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		db     *sql.DB
		opts   []sqlstore.LimiterOption
		assert func(t *testing.T, f *sqlstore.LimiterFactory, err error)
	}

	accepted := func(t *testing.T, f *sqlstore.LimiterFactory, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, f)
	}
	refused := func(want string) func(t *testing.T, f *sqlstore.LimiterFactory, err error) {
		return func(t *testing.T, f *sqlstore.LimiterFactory, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.Contains(t, err.Error(), want)
			assert.Nil(t, f)
		}
	}

	cases := []testCase{
		{name: "defaults accepted", db: new(sql.DB), assert: accepted},
		{name: "nil handle", db: nil, assert: refused("nil")},
		{name: "nil clock", db: new(sql.DB), opts: []sqlstore.LimiterOption{sqlstore.WithLimiterClock(nil)}, assert: refused("clock")},
		{name: "nil logger", db: new(sql.DB), opts: []sqlstore.LimiterOption{sqlstore.WithLimiterLogger(nil)}, assert: refused("logger")},
		{name: "unknown mode", db: new(sql.DB), opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOnUnavailable(99)}, assert: refused("mode")},
		{
			name: "zero timeout", db: new(sql.DB), opts: []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(0)},
			assert: refused("timeout"),
		},
		{
			name: "zero probe interval", db: new(sql.DB), opts: []sqlstore.LimiterOption{sqlstore.WithLimiterProbeInterval(0)},
			assert: refused("probe"),
		},
		{
			name: "timeout at the lock_timeout maximum accepted", db: new(sql.DB),
			opts:   []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(2147483647 * time.Millisecond)},
			assert: accepted,
		},
		{
			name: "timeout above the lock_timeout maximum", db: new(sql.DB),
			opts:   []sqlstore.LimiterOption{sqlstore.WithLimiterOperationTimeout(2147483648 * time.Millisecond)},
			assert: refused("at most 2147483647ms"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, err := sqlstore.NewLimiterFactory(tc.db, tc.opts...)
			tc.assert(t, f, err)
		})
	}
}

func TestLimiterFactory_NewLimiter(t *testing.T) {
	t.Parallel()

	type request struct {
		namespace string
		limit     int
		window    time.Duration
	}

	type testCase struct {
		name string
		// before runs against the factory first, when set.
		before func(t *testing.T, f *sqlstore.LimiterFactory)
		ask    request
		assert func(t *testing.T, l ratelimit.Limiter, err error)
	}

	refused := func(want ...string) func(t *testing.T, l ratelimit.Limiter, err error) {
		return func(t *testing.T, l ratelimit.Limiter, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			for _, w := range want {
				assert.Contains(t, err.Error(), w)
			}
			assert.Nil(t, l)
		}
	}
	accepted := func(limit int, window time.Duration) func(t *testing.T, l ratelimit.Limiter, err error) {
		return func(t *testing.T, l ratelimit.Limiter, err error) {
			t.Helper()
			require.NoError(t, err)
			require.NotNil(t, l)
			p, ok := l.(ratelimit.PolicyReporter)
			require.True(t, ok, "the limiter does not report its policy")
			gotLimit, gotWindow := p.Policy()
			assert.Equal(t, limit, gotLimit)
			assert.Equal(t, window, gotWindow)
		}
	}

	built := func(r request) func(t *testing.T, f *sqlstore.LimiterFactory) {
		return func(t *testing.T, f *sqlstore.LimiterFactory) {
			t.Helper()
			_, err := f.NewLimiter(r.namespace, r.limit, r.window)
			require.NoError(t, err)
		}
	}

	cases := []testCase{
		{name: "first request", ask: request{"api-key", 3, time.Minute}, assert: accepted(3, time.Minute)},
		{
			name: "same namespace and policy again", before: built(request{"api-key", 3, time.Minute}),
			ask: request{"api-key", 3, time.Minute}, assert: accepted(3, time.Minute),
		},
		{
			name: "same namespace and policy differing below a microsecond", before: built(request{"api-key", 3, time.Minute}),
			ask: request{"api-key", 3, time.Minute + 500*time.Nanosecond}, assert: accepted(3, time.Minute),
		},
		{
			name: "same namespace with another limit", before: built(request{"api-key", 3, time.Minute}),
			ask: request{"api-key", 5, time.Minute}, assert: refused(`"api-key"`, "3 per 1m0s", "5 per 1m0s"),
		},
		{
			name: "same namespace with another window", before: built(request{"api-key", 3, time.Minute}),
			ask: request{"api-key", 3, time.Hour}, assert: refused("3 per 1m0s", "3 per 1h0m0s"),
		},
		{
			name: "another namespace with another policy", before: built(request{"api-key", 3, time.Minute}),
			ask: request{"magic-link", 5, time.Hour}, assert: accepted(5, time.Hour),
		},
		{name: "65-byte namespace", ask: request{strings.Repeat("n", 65), 3, time.Minute}, assert: refused("64")},
		{name: "limit 129", ask: request{"api-key", 129, time.Minute}, assert: refused("128")},
		{
			name: "a refused request does not claim the namespace",
			before: func(t *testing.T, f *sqlstore.LimiterFactory) {
				t.Helper()
				_, err := f.NewLimiter("api-key", 0, time.Minute)
				require.ErrorIs(t, err, ratelimit.ErrConfig)
			},
			ask: request{"api-key", 5, time.Minute}, assert: accepted(5, time.Minute),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, err := sqlstore.NewLimiterFactory(new(sql.DB))
			require.NoError(t, err)
			if tc.before != nil {
				tc.before(t, f)
			}
			l, err := f.NewLimiter(tc.ask.namespace, tc.ask.limit, tc.ask.window)
			tc.assert(t, l, err)
		})
	}
}
