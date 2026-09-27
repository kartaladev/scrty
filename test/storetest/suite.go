package storetest

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/pkg/id"
)

// suiteStart is where every suite's clock starts, and the instant its records
// are dated from. It is whole seconds, so a durable store that keeps
// microseconds reads back exactly what was written.
var suiteStart = time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)

// preciseStart is suiteStart with a sub-millisecond, sub-microsecond part
// that rounds up, so truncating and rounding it to the microsecond differ.
// The precision cases date their records from it: a store must hand it back
// exactly, or truncated or rounded to the microsecond, and never coarser.
var preciseStart = suiteStart.Add(123456789 * time.Nanosecond)

// suiteID returns the n-th identifier a suite uses. Identifiers of different
// n differ, and none is id.Nil.
func suiteID(n int) id.ID {
	return id.MustParse(fmt.Sprintf("01926a4e-0000-7000-8000-%012x", n))
}

// fakeClock is the store clock a suite hands its factory and advances itself,
// so no case ever waits for time to pass.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(at time.Time) *fakeClock { return &fakeClock{now: at} }

// Now is the clock the factory builds the store on.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

// Set moves the clock to at.
func (c *fakeClock) Set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = at
}

// suiteCase is one row of a suite: a name the failure reports, and the check
// it runs on a store of its own.
type suiteCase[S any] struct {
	name   string
	assert func(t *testing.T, ctx context.Context, s S, clock *fakeClock)
}

// optionalCase is a case for a capability the contract leaves optional, such
// as a reaper: it runs assert on the store as an R. For a store that is not
// one it fails when required, and otherwise logs that the case did not run
// and passes.
func optionalCase[S, R any](
	required bool, name string, assert func(t *testing.T, ctx context.Context, s S, r R, clock *fakeClock),
) suiteCase[S] {
	return suiteCase[S]{
		name: name,
		assert: func(t *testing.T, ctx context.Context, s S, clock *fakeClock) {
			r, ok := any(s).(R)
			switch {
			case ok:
				assert(t, ctx, s, r, clock)
			case required:
				t.Fatalf("store does not implement %v, which RequireReaper demands", reflect.TypeFor[R]())
			default:
				t.Logf("store does not implement %v: case not run", reflect.TypeFor[R]())
			}
		},
	}
}

// runSuite runs each case in its own subtest, on a store the factory builds
// for that case alone over a clock starting at suiteStart.
func runSuite[S any](t *testing.T, cases []suiteCase[S], newStore func(t *testing.T, now func() time.Time) S) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock(suiteStart)
			tc.assert(t, t.Context(), newStore(t, clock.Now), clock)
		})
	}
}

// withoutClock adapts a factory for a store that takes no clock.
func withoutClock[S any](newStore func(t *testing.T) S) func(t *testing.T, _ func() time.Time) S {
	return func(t *testing.T, _ func() time.Time) S { return newStore(t) }
}

// assertTimeEqual compares instants, so a store that returns another location
// still conforms.
func assertTimeEqual(t *testing.T, want, got time.Time, field string) {
	t.Helper()

	assert.True(t, want.Equal(got), "%s is %v, want %v", field, got, want)
}

// assertTimeMicro requires got to be want exactly, or want truncated or
// rounded to the microsecond: stored times round-trip at microsecond
// precision, so a store may drop nanoseconds either way (pgx truncates,
// PostgreSQL rounds text-format input), but nothing coarser.
func assertTimeMicro(t *testing.T, want, got time.Time, field string) {
	t.Helper()

	assert.True(t,
		got.Equal(want) || got.Equal(want.Truncate(time.Microsecond)) || got.Equal(want.Round(time.Microsecond)),
		"%s is %v, want %v at microsecond precision or finer", field, got, want)
}

// assertTimePtrEqual compares optional instants: both absent, or both present
// and equal.
func assertTimePtrEqual(t *testing.T, want, got *time.Time, field string) {
	t.Helper()

	if want == nil {
		assert.Nil(t, got, "%s must be absent", field)
		return
	}
	if assert.NotNil(t, got, "%s must be present", field) {
		assertTimeEqual(t, *want, *got, field)
	}
}

// SuiteOption configures a portable suite that takes options.
type SuiteOption func(*suiteConfig)

// suiteConfig is what the options set. Its zero value is the default.
type suiteConfig struct {
	requireReaper bool
}

func newSuiteConfig(opts []SuiteOption) suiteConfig {
	var cfg suiteConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// RequireReaper makes a suite's reaper cases fail, naming the missing
// interface, for a store that does not implement the reaper of its contract
// (onetime.Reaper, policy.AttemptReaper).
//
// By default the reaper is not required: the contract leaves it optional, so
// a store without one has those cases logged as not run, and passes. A store
// that is meant to carry a reaper passes this option, so that losing it fails
// the suite rather than silently running fewer cases. scrty's own durable
// adapters pass it; a consumer's store passes it when it implements the
// reaper, and may leave it out when it does not.
func RequireReaper() SuiteOption {
	return func(c *suiteConfig) { c.requireReaper = true }
}
