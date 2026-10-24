package pglimiter_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/pglimiter"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/ratelimit"
)

// serverError is a driver error carrying a SQLSTATE, as *pgconn.PgError does,
// with server text no limiter error may repeat.
type serverError struct {
	state string
	text  string
}

func (e *serverError) Error() string    { return e.text }
func (e *serverError) SQLState() string { return e.state }

var (
	errDenied     = &serverError{state: "42501", text: "permission denied for table rate_limit_buckets"}
	errTerminated = &serverError{state: "57P01", text: "terminating connection due to administrator command"}
)

// testAt is the fake clock's time; testNow is the now parameter it gives.
var (
	testAt  = time.Date(2026, 10, 10, 12, 0, 0, 123456789, time.UTC)
	testNow = testAt.Truncate(time.Microsecond)
)

// rowScanning returns a row whose Scan stores values into its destinations, in
// order, or fails with err when err is not nil.
func rowScanning(ctrl *gomock.Controller, err error, values ...any) *MockRow {
	row := NewMockRow(ctrl)
	row.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest ...any) error {
		if err != nil {
			return err
		}
		for i, v := range values {
			switch d := dest[i].(type) {
			case *bool:
				*d = v.(bool)
			case *int:
				*d = v.(int)
			case *string:
				*d = v.(string)
			case *time.Time:
				*d = v.(time.Time)
			default:
				panic("unexpected scan destination")
			}
		}
		return nil
	})
	return row
}

// uncounted is an Exec result whose RowsAffected may not be called: the
// record and the probe's statements succeed on Exec's error alone, as a
// database/sql driver that reports no row count requires.
func uncounted(ctrl *gomock.Controller) pglimiter.Result { return NewMockResult(ctrl) }

func factsRow(ctrl *gomock.Controller, f pglimiter.Facts) *MockRow {
	return rowScanning(ctrl, nil, f.InRecovery, f.Version, f.Encoding, f.Persistence)
}

var healthyFacts = pglimiter.Facts{Version: 180006, Encoding: "UTF8", Persistence: "p"}

// withClock gives cfg the fake clock at testAt, as WithLimiterClock does.
func withClock(cfg pglimiter.Config) pglimiter.Config {
	clk := clockwork.NewFakeClockAt(testAt)
	cfg.Clock, cfg.ClockSet, cfg.Unavailable.Clock = clk, true, clk
	return cfg
}

// probeKey matches the probe's random key and remembers the first one it
// sees, so the later steps can be held to the same key.
type probeKey struct{ key string }

func (p *probeKey) first() gomock.Matcher {
	return gomock.Cond(func(k string) bool {
		if !strings.HasPrefix(k, "verify-") || len(k) != len("verify-")+32 {
			return false
		}
		p.key = k
		return true
	})
}

func (p *probeKey) same() gomock.Matcher {
	return gomock.Cond(func(k string) bool { return k == p.key })
}

// expectProbe scripts the facts read and the probe up to the step that fails
// with stepErr (record, check or delete); an empty step lets every step pass.
func expectProbe(ctrl *gomock.Controller, r *MockRunner, now any, lockTimeout, failing string, stepErr error) {
	key := &probeKey{}
	errAt := func(step string) error {
		if step == failing {
			return stepErr
		}
		return nil
	}

	calls := []any{
		r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterServerFacts).Return(factsRow(ctrl, healthyFacts)),
		r.EXPECT().ExecReadCommitted(gomock.Any(), pgschema.LimiterRecord, "", key.first(), 1, int64(1), now, lockTimeout).
			Return(errAt("record")),
	}
	if failing != "record" {
		calls = append(calls, r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterCheck, "", key.same(), int64(1), now).
			Return(rowScanning(ctrl, errAt("check"), 1)))
	}
	if failing != "record" && failing != "check" {
		calls = append(calls, r.EXPECT().Exec(gomock.Any(), pgschema.LimiterDeleteKey, "", key.same()).
			Return(uncounted(ctrl), errAt("delete")))
	}
	gomock.InOrder(calls...)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	roleRefused := func(step string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.EqualError(t, err, "ratelimit: invalid configuration: the role may not run the limiter's "+step+
				" statement on rate_limit_buckets; grant it SELECT, INSERT, UPDATE and DELETE on the table")
			assert.ErrorIs(t, err, errDenied, "the cause is kept")
			assert.NotContains(t, err.Error(), errDenied.text)
		}
	}
	notConfig := func(text string, cause error) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.Error(t, err)
			assert.NotErrorIs(t, err, ratelimit.ErrConfig)
			assert.EqualError(t, err, text)
			assert.ErrorIs(t, err, cause, "the cause is kept")
		}
	}

	type testCase struct {
		name   string
		prefix string
		cfg    func(c pglimiter.Config) pglimiter.Config
		ctx    func(ctx context.Context) context.Context
		script func(ctrl *gomock.Controller, r *MockRunner)
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "healthy server passes the probe on one key, with the database clock",
			prefix: "sqlstore",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "", nil)
			},
			assert: accepted,
		},
		{
			name:   "probe runs with the application clock and the operation timeout's lock timeout",
			prefix: "pgx",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c = withClock(c)
				c.Unavailable.Timeout = 1500 * time.Millisecond
				return c
			},
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, testNow, "1500ms", "", nil)
			},
			assert: accepted,
		},
		{
			name:   "refused facts stop before the probe",
			prefix: "pgx",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterServerFacts).
					Return(factsRow(ctrl, pglimiter.Facts{InRecovery: true, Version: 180006, Encoding: "UTF8", Persistence: "p"})).
					Times(1)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, ratelimit.ErrConfig)
				assert.Contains(t, err.Error(), "the server is a standby")
			},
		},
		{
			name:   "unreadable facts have fixed text",
			prefix: "sqlstore",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterServerFacts).Return(rowScanning(ctrl, errTerminated))
			},
			assert: notConfig("sqlstore: verify: the server's state could not be read", errTerminated),
		},
		{
			name:   "role refused the record is a configuration error naming record",
			prefix: "pgx",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "record", errDenied)
			},
			assert: roleRefused("record"),
		},
		{
			name:   "role refused the check names check",
			prefix: "pgx",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "check", errDenied)
			},
			assert: roleRefused("check"),
		},
		{
			name:   "role refused the delete names delete",
			prefix: "sqlstore",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "delete", errDenied)
			},
			assert: roleRefused("delete"),
		},
		{
			name:   "any other record error has fixed text",
			prefix: "sqlstore",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "record", errTerminated)
			},
			assert: notConfig("sqlstore: verify: the limiter's record statement could not run on a probe key", errTerminated),
		},
		{
			name:   "any other check error has fixed text",
			prefix: "pgx",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "check", errTerminated)
			},
			assert: notConfig("pgx: verify: the limiter's check statement could not run on a probe key", errTerminated),
		},
		{
			name:   "any other delete error has fixed text",
			prefix: "sqlstore",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "delete", errTerminated)
			},
			assert: func(t *testing.T, err error) {
				notConfig("sqlstore: verify: the limiter's delete statement could not run on a probe key", errTerminated)(t, err)
				assert.NotContains(t, err.Error(), errTerminated.text)
			},
		},
		{
			name:   "ended context is not a configuration error",
			prefix: "pgx",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterServerFacts).
					DoAndReturn(func(ctx context.Context, _ string, _ ...any) pglimiter.Row {
						return rowScanning(ctrl, ctx.Err())
					})
			},
			assert: notConfig("pgx: verify: the server's state could not be read", context.Canceled),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			cfg := pglimiter.DefaultConfig()
			if tc.cfg != nil {
				cfg = tc.cfg(cfg)
			}
			ctrl := gomock.NewController(t)
			r := NewMockRunner(ctrl)
			tc.script(ctrl, r)

			tc.assert(t, pglimiter.Verify(ctx, r, tc.prefix, cfg))
		})
	}
}

const (
	backendNamespace = "mfa-verify"
	backendLimit     = 3
	backendWindow    = 90 * time.Second
	backendWindowUS  = int64(90_000_000)
)

func TestBackend_Exceeded(t *testing.T) {
	t.Parallel()

	longKey := strings.Repeat("k", 600)
	errCheck := errors.New("conn reset")

	exceeded := func(want bool) func(t *testing.T, got bool, err error) {
		return func(t *testing.T, got bool, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, want, got)
		}
	}

	type testCase struct {
		name   string
		prefix string
		key    string
		ctx    func(ctx context.Context) context.Context
		script func(ctrl *gomock.Controller, r *MockRunner, key string)
		assert func(t *testing.T, exceeded bool, err error)
	}

	expectCount := func(n int, err error) func(ctrl *gomock.Controller, r *MockRunner, key string) {
		return func(ctrl *gomock.Controller, r *MockRunner, key string) {
			r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterCheck,
				backendNamespace, pgschema.LimiterKey(key), backendWindowUS, testNow).
				Return(rowScanning(ctrl, err, n))
		}
	}

	cases := []testCase{
		{name: "below the limit", prefix: "pgx", key: "k", script: expectCount(2, nil), assert: exceeded(false)},
		{name: "at the limit", prefix: "pgx", key: "k", script: expectCount(3, nil), assert: exceeded(true)},
		{name: "above the limit", prefix: "pgx", key: "k", script: expectCount(5, nil), assert: exceeded(true)},
		{name: "a long key is checked in its stored form", prefix: "pgx", key: longKey,
			script: expectCount(0, nil), assert: exceeded(false)},
		{
			name: "a check error answers exceeded, wrapped with the prefix", prefix: "sqlstore", key: "k",
			script: expectCount(0, errCheck),
			assert: func(t *testing.T, got bool, err error) {
				assert.True(t, got)
				require.ErrorIs(t, err, errCheck)
				assert.EqualError(t, err, "sqlstore: rate-limit check: conn reset")
			},
		},
		{
			name: "an ended context answers exceeded", prefix: "pgx", key: "k",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			script: func(ctrl *gomock.Controller, r *MockRunner, _ string) {
				r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterCheck, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ string, _ ...any) pglimiter.Row {
						return rowScanning(ctrl, ctx.Err())
					})
			},
			assert: func(t *testing.T, got bool, err error) {
				assert.True(t, got)
				require.ErrorIs(t, err, context.Canceled)
				assert.EqualError(t, err, "pgx: rate-limit check: context canceled")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			ctrl := gomock.NewController(t)
			r := NewMockRunner(ctrl)
			tc.script(ctrl, r, tc.key)
			b := pglimiter.NewBackend(r, tc.prefix, backendNamespace, backendLimit, backendWindow,
				withClock(pglimiter.DefaultConfig()))

			got, err := b.Exceeded(ctx, tc.key)
			tc.assert(t, got, err)
		})
	}
}

func TestBackend_RecordFailure(t *testing.T) {
	t.Parallel()

	errRecord := errors.New("canceling statement due to lock timeout")

	type testCase struct {
		name   string
		prefix string
		cfg    func(c pglimiter.Config) pglimiter.Config
		script func(ctrl *gomock.Controller, r *MockRunner)
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "records with the limit, window, application clock and lock timeout", prefix: "pgx",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c = withClock(c)
				c.Unavailable.Timeout = 400 * time.Millisecond
				return c
			},
			script: func(_ *gomock.Controller, r *MockRunner) {
				r.EXPECT().ExecReadCommitted(gomock.Any(), pgschema.LimiterRecord,
					backendNamespace, pgschema.LimiterKey("k"), backendLimit, backendWindowUS, testNow, "400ms").
					Return(nil)
			},
			assert: accepted,
		},
		{
			name: "the database clock is a nil now", prefix: "sqlstore",
			script: func(_ *gomock.Controller, r *MockRunner) {
				r.EXPECT().ExecReadCommitted(gomock.Any(), pgschema.LimiterRecord,
					backendNamespace, pgschema.LimiterKey("k"), backendLimit, backendWindowUS, gomock.Nil(), "250ms").
					Return(nil)
			},
			assert: accepted,
		},
		{
			name: "a record error is wrapped with the prefix", prefix: "sqlstore",
			script: func(_ *gomock.Controller, r *MockRunner) {
				r.EXPECT().ExecReadCommitted(gomock.Any(), pgschema.LimiterRecord, gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any(), gomock.Any()).Return(errRecord)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errRecord)
				assert.EqualError(t, err, "sqlstore: rate-limit record: canceling statement due to lock timeout")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := pglimiter.DefaultConfig()
			if tc.cfg != nil {
				cfg = tc.cfg(cfg)
			}
			ctrl := gomock.NewController(t)
			r := NewMockRunner(ctrl)
			tc.script(ctrl, r)
			b := pglimiter.NewBackend(r, tc.prefix, backendNamespace, backendLimit, backendWindow, cfg)

			tc.assert(t, b.RecordFailure(t.Context(), "k"))
		})
	}
}
