package pglimiter_test

import (
	"context"
	"errors"
	"fmt"
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
			prefix: "pgxstore",
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
			prefix: "pgxstore",
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
			prefix: "pgxstore",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "record", errDenied)
			},
			assert: roleRefused("record"),
		},
		{
			name:   "role refused the check names check",
			prefix: "pgxstore",
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
			prefix: "pgxstore",
			script: func(ctrl *gomock.Controller, r *MockRunner) {
				expectProbe(ctrl, r, gomock.Nil(), "250ms", "check", errTerminated)
			},
			assert: notConfig("pgxstore: verify: the limiter's check statement could not run on a probe key", errTerminated),
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
			prefix: "pgxstore",
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
			assert: notConfig("pgxstore: verify: the server's state could not be read", context.Canceled),
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
		{name: "below the limit", prefix: "pgxstore", key: "k", script: expectCount(2, nil), assert: exceeded(false)},
		{name: "at the limit", prefix: "pgxstore", key: "k", script: expectCount(3, nil), assert: exceeded(true)},
		{name: "above the limit", prefix: "pgxstore", key: "k", script: expectCount(5, nil), assert: exceeded(true)},
		{name: "a long key is checked in its stored form", prefix: "pgxstore", key: longKey,
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
			name: "an ended context answers exceeded", prefix: "pgxstore", key: "k",
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
				assert.EqualError(t, err, "pgxstore: rate-limit check: context canceled")
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
			name: "records with the limit, window, application clock and lock timeout", prefix: "pgxstore",
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

func TestBackend_Charge(t *testing.T) {
	t.Parallel()

	longKey := strings.Repeat("k", 600)
	stamp := testNow.Add(-time.Microsecond)
	errCharge := errors.New("canceling statement due to lock timeout")

	type testCase struct {
		name   string
		prefix string
		key    string
		cfg    func(c pglimiter.Config) pglimiter.Config
		script func(ctrl *gomock.Controller, r *MockRunner, key string)
		assert func(t *testing.T, r ratelimit.Receipt, exceeded bool, err error)
	}

	// expectCharge scripts the charge statement with the application clock
	// and the default lock timeout, answering recorded and at.
	expectCharge := func(recorded bool, at time.Time, err error) func(ctrl *gomock.Controller, r *MockRunner, key string) {
		return func(ctrl *gomock.Controller, r *MockRunner, key string) {
			r.EXPECT().QueryRowReadCommitted(gomock.Any(), pgschema.LimiterCharge,
				backendNamespace, pgschema.LimiterKey(key), backendLimit, backendWindowUS, testNow, "250ms").
				Return(rowScanning(ctrl, err, recorded, at))
		}
	}

	cases := []testCase{
		{
			name: "an accepted charge returns the stored stamp under the caller's key", prefix: "pgxstore", key: "k",
			cfg: withClock, script: expectCharge(true, stamp, nil),
			assert: func(t *testing.T, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Equal(t, ratelimit.NewReceipt("k", stamp), r)
			},
		},
		{
			name: "a refused charge returns the zero receipt", prefix: "pgxstore", key: "k",
			cfg: withClock, script: expectCharge(false, stamp, nil),
			assert: func(t *testing.T, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
				assert.Zero(t, r)
			},
		},
		{
			name: "a long key is charged in its stored form, and its receipt keeps the caller's key", prefix: "sqlstore",
			key: longKey, cfg: withClock, script: expectCharge(true, stamp, nil),
			assert: func(t *testing.T, r ratelimit.Receipt, _ bool, err error) {
				require.NoError(t, err)
				assert.Equal(t, longKey, r.Key())
			},
		},
		{
			name: "the database clock is a nil now, and the operation timeout the lock timeout", prefix: "sqlstore", key: "k",
			cfg: func(c pglimiter.Config) pglimiter.Config {
				c.Unavailable.Timeout = 400 * time.Millisecond
				return c
			},
			script: func(ctrl *gomock.Controller, r *MockRunner, key string) {
				r.EXPECT().QueryRowReadCommitted(gomock.Any(), pgschema.LimiterCharge,
					backendNamespace, pgschema.LimiterKey(key), backendLimit, backendWindowUS, gomock.Nil(), "400ms").
					Return(rowScanning(ctrl, nil, true, stamp))
			},
			assert: func(t *testing.T, r ratelimit.Receipt, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.True(t, stamp.Equal(r.Stamp()))
			},
		},
		{
			name: "a charge error refuses, wrapped with the prefix", prefix: "sqlstore", key: "k",
			cfg: withClock, script: expectCharge(false, time.Time{}, errCharge),
			assert: func(t *testing.T, r ratelimit.Receipt, exceeded bool, err error) {
				assert.True(t, exceeded)
				assert.Zero(t, r)
				require.ErrorIs(t, err, errCharge)
				assert.EqualError(t, err, "sqlstore: rate-limit charge: canceling statement due to lock timeout")
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
			tc.script(ctrl, r, tc.key)
			b := pglimiter.NewBackend(r, tc.prefix, backendNamespace, backendLimit, backendWindow, cfg)

			receipt, exceeded, err := b.Charge(t.Context(), tc.key)
			tc.assert(t, receipt, exceeded, err)
		})
	}
}

func TestBackend_Refund(t *testing.T) {
	t.Parallel()

	stamp := testNow.Add(-time.Second)
	errRefund := errors.New("conn reset")

	type testCase struct {
		name    string
		prefix  string
		receipt ratelimit.Receipt
		cfg     func(c pglimiter.Config) pglimiter.Config
		script  func(r *MockRunner)
		assert  func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "refunds the receipt's stamp from its key's stored form", prefix: "pgxstore",
			receipt: ratelimit.NewReceipt(strings.Repeat("k", 600), stamp), cfg: withClock,
			script: func(r *MockRunner) {
				r.EXPECT().ExecReadCommitted(gomock.Any(), pgschema.LimiterRefund,
					backendNamespace, pgschema.LimiterKey(strings.Repeat("k", 600)), stamp, backendWindowUS, testNow, "250ms").
					Return(nil)
			},
			assert: accepted,
		},
		{
			name: "the database clock is a nil now", prefix: "sqlstore", receipt: ratelimit.NewReceipt("k", stamp),
			script: func(r *MockRunner) {
				r.EXPECT().ExecReadCommitted(gomock.Any(), pgschema.LimiterRefund,
					backendNamespace, "k", stamp, backendWindowUS, gomock.Nil(), "250ms").Return(nil)
			},
			assert: accepted,
		},
		{
			name: "the zero receipt runs nothing", prefix: "sqlstore",
			script: func(*MockRunner) {}, // any call fails the mock
			assert: accepted,
		},
		{
			name: "a refund error is wrapped with the prefix", prefix: "sqlstore", receipt: ratelimit.NewReceipt("k", stamp),
			script: func(r *MockRunner) {
				r.EXPECT().ExecReadCommitted(gomock.Any(), pgschema.LimiterRefund, gomock.Any(), gomock.Any(), gomock.Any(),
					gomock.Any(), gomock.Any(), gomock.Any()).Return(errRefund)
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errRefund)
				assert.EqualError(t, err, "sqlstore: rate-limit refund: conn reset")
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
			r := NewMockRunner(gomock.NewController(t))
			tc.script(r)
			b := pglimiter.NewBackend(r, tc.prefix, backendNamespace, backendLimit, backendWindow, cfg)

			tc.assert(t, b.Refund(t.Context(), tc.receipt))
		})
	}
}

// TestFactsCheck pins the order Verify refuses a server's facts in, their
// messages, and the version floor, which no supported server can be made to
// fail.
func TestFactsCheck(t *testing.T) {
	t.Parallel()

	healthy := pglimiter.Facts{InRecovery: false, Version: 150000, Encoding: "UTF8", Persistence: "p"}

	const (
		standby = "the server is a standby (in recovery); the limiter must run on the primary, " +
			"because a standby lags, so it undercounts, and refuses writes"
		missing = "the table rate_limit_buckets does not resolve through the connection's search_path; " +
			"apply the security-state migration set (migrate.SecurityState) to this database"
		encoding = "the database's server encoding is %s; the limiter needs UTF8, " +
			"the encoding every key and namespace is stored in"
		temporary = "the table rate_limit_buckets resolves to a temporary table, which shadows the migration's " +
			"and lasts only for its session; drop it"
		unlogged = "the table rate_limit_buckets is unlogged, so a crash or a failover would reset every limit to zero; " +
			"make it logged again with ALTER TABLE rate_limit_buckets SET LOGGED"
	)

	type testCase struct {
		name   string
		facts  func(f pglimiter.Facts) pglimiter.Facts
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "PostgreSQL 15 primary",
			facts:  func(f pglimiter.Facts) pglimiter.Facts { return f },
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "PostgreSQL 18 primary",
			facts:  func(f pglimiter.Facts) pglimiter.Facts { f.Version = 180006; return f },
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:  "PostgreSQL 14",
			facts: func(f pglimiter.Facts) pglimiter.Facts { f.Version = 140013; return f },
			assert: refusedWith("the server's server_version_num is 140013, older than PostgreSQL 15 (150000), " +
				"the oldest the limiter supports"),
		},
		{
			name: "standby before everything else",
			facts: func(pglimiter.Facts) pglimiter.Facts {
				return pglimiter.Facts{InRecovery: true, Version: 140000}
			},
			assert: refusedWith(standby),
		},
		{
			name: "version before the table",
			facts: func(pglimiter.Facts) pglimiter.Facts {
				return pglimiter.Facts{Version: 140000}
			},
			assert: refusedWith("the server's server_version_num is 140000, older than PostgreSQL 15 (150000), " +
				"the oldest the limiter supports"),
		},
		{
			name: "missing table",
			facts: func(f pglimiter.Facts) pglimiter.Facts {
				f.Persistence = ""
				return f
			},
			assert: refusedWith(missing),
		},
		{
			name:   "LATIN1 database",
			facts:  func(f pglimiter.Facts) pglimiter.Facts { f.Encoding = "LATIN1"; return f },
			assert: refusedWith(fmt.Sprintf(encoding, "LATIN1")),
		},
		{
			name:   "SQL_ASCII database",
			facts:  func(f pglimiter.Facts) pglimiter.Facts { f.Encoding = "SQL_ASCII"; return f },
			assert: refusedWith(fmt.Sprintf(encoding, "SQL_ASCII")),
		},
		{
			name: "encoding before the missing table",
			facts: func(pglimiter.Facts) pglimiter.Facts {
				return pglimiter.Facts{Version: 150000, Encoding: "LATIN1"}
			},
			assert: refusedWith(fmt.Sprintf(encoding, "LATIN1")),
		},
		{
			name: "temporary table",
			facts: func(f pglimiter.Facts) pglimiter.Facts {
				f.Persistence = "t"
				return f
			},
			assert: refusedWith(temporary),
		},
		{
			name:   "unlogged table",
			facts:  func(f pglimiter.Facts) pglimiter.Facts { f.Persistence = "u"; return f },
			assert: refusedWith(unlogged),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.facts(healthy).Check())
		})
	}
}

// dbNow is the time the database clock reports to a prune.
var dbNow = time.Date(2026, 10, 10, 12, 0, 0, 654321000, time.UTC)

// counted is an Exec result reporting n rows affected.
func counted(ctrl *gomock.Controller, n int64) pglimiter.Result {
	res := NewMockResult(ctrl)
	res.EXPECT().RowsAffected().Return(n, nil)
	return res
}

// expectClock scripts the one read of the database clock a prune makes.
func expectClock(ctrl *gomock.Controller, r *MockRunner) any {
	return r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterClock).Return(rowScanning(ctrl, nil, dbNow)).Times(1)
}

// expectBatches scripts one prune batch per count, in order, each with now
// and batch as its arguments.
func expectBatches(ctrl *gomock.Controller, r *MockRunner, now any, batch int, counts ...int64) []any {
	calls := make([]any, 0, len(counts))
	for _, n := range counts {
		calls = append(calls, r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, now, batch).Return(counted(ctrl, n), nil))
	}
	return calls
}

func TestPrune(t *testing.T) {
	t.Parallel()

	errBatch := errors.New("server says secret-xyz")
	errClock := errors.New("server says secret-abc")
	errCount := errors.New("driver says secret-rows")

	type testCase struct {
		name     string
		batch    int
		appClock bool
		// script receives the cancel of the ctx Prune runs with.
		script func(ctrl *gomock.Controller, r *MockRunner, cancel context.CancelFunc)
		assert func(t *testing.T, removed int, err error)
	}

	cases := []testCase{
		{
			name:  "empty table",
			batch: 1000,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(append([]any{expectClock(ctrl, r)}, expectBatches(ctrl, r, dbNow, 1000, 0)...)...)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Zero(t, removed)
			},
		},
		{
			name:  "short first batch stops",
			batch: 1000,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(append([]any{expectClock(ctrl, r)}, expectBatches(ctrl, r, dbNow, 1000, 400)...)...)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 400, removed)
			},
		},
		{
			name:  "full batches then short",
			batch: 2,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(append([]any{expectClock(ctrl, r)}, expectBatches(ctrl, r, dbNow, 2, 2, 2, 1)...)...)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 5, removed)
			},
		},
		{
			name:     "application clock",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				// No QueryRow is expected: the database clock is not read.
				expectBatches(ctrl, r, testNow, 2, 1)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name:  "database clock read once",
			batch: 2,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(append([]any{expectClock(ctrl, r)}, expectBatches(ctrl, r, dbNow, 2, 2, 0)...)...)
			},
			assert: func(t *testing.T, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 2, removed)
			},
		},
		{
			name:     "cancelled during first batch",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, cancel context.CancelFunc) {
				r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).
					DoAndReturn(func(context.Context, string, ...any) (pglimiter.Result, error) {
						cancel() // the batch commits, and ctx ends before the next
						return counted(ctrl, 2), nil
					})
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Equal(t, 2, removed, "the committed batch is counted")
				require.ErrorIs(t, err, context.Canceled)
				assert.EqualError(t, err, "pgxstore: rate-limit prune: stopped after 2 keys: context canceled")
			},
		},
		{
			name:     "failed second batch",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(
					r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(counted(ctrl, 2), nil),
					r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(nil, errBatch),
				)
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Equal(t, 2, removed, "the first batch's keys are counted")
				require.Error(t, err)
				assert.EqualError(t, err, "pgxstore: rate-limit prune: a batch could not be deleted")
				assert.NotContains(t, err.Error(), "secret-xyz")
				assert.ErrorIs(t, err, errBatch, "the cause is kept")
			},
		},
		{
			name:     "batch whose Exec hits the deadline keeps the cause and the earlier count",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				gomock.InOrder(
					r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(counted(ctrl, 2), nil),
					r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(nil, context.DeadlineExceeded),
				)
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Equal(t, 2, removed, "the committed batch is counted")
				require.Error(t, err)
				assert.ErrorIs(t, err, context.DeadlineExceeded, "the cause is kept")
			},
		},
		{
			name:     "unreadable row count fails the batch",
			batch:    2,
			appClock: true,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				res := NewMockResult(ctrl)
				res.EXPECT().RowsAffected().Return(int64(0), errCount)
				r.EXPECT().Exec(gomock.Any(), pgschema.LimiterPrune, testNow, 2).Return(res, nil)
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Zero(t, removed)
				require.Error(t, err)
				assert.EqualError(t, err, "pgxstore: rate-limit prune: a batch's row count could not be read")
				assert.NotContains(t, err.Error(), "secret-rows")
				assert.ErrorIs(t, err, errCount, "the cause is kept")
			},
		},
		{
			name:  "clock read fails",
			batch: 2,
			script: func(ctrl *gomock.Controller, r *MockRunner, _ context.CancelFunc) {
				r.EXPECT().QueryRow(gomock.Any(), pgschema.LimiterClock).Return(rowScanning(ctrl, errClock))
			},
			assert: func(t *testing.T, removed int, err error) {
				assert.Zero(t, removed)
				require.Error(t, err)
				assert.EqualError(t, err, "pgxstore: rate-limit prune: the database clock could not be read")
				assert.NotContains(t, err.Error(), "secret-abc")
				assert.ErrorIs(t, err, errClock, "the cause is kept")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cfg := pglimiter.DefaultConfig()
			if tc.appClock {
				cfg = withClock(cfg)
			}
			cfg.PruneBatchSize = tc.batch
			ctrl := gomock.NewController(t)
			r := NewMockRunner(ctrl)
			tc.script(ctrl, r, cancel)

			removed, err := pglimiter.Prune(ctx, r, "pgxstore", cfg)
			tc.assert(t, removed, err)
		})
	}
}
