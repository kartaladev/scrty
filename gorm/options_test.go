package gorm

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/pkg/id"
)

// fixedGenerator is a consumer's generator, compared by identity only.
type fixedGenerator struct{}

func (*fixedGenerator) NewID() (id.ID, error) { return id.ID{}, nil }

// nilClock is a consumer's clock type; (*nilClock)(nil) is the typed nil that
// a plain `== nil` check misses but nilcheck.IsNil catches.
type nilClock struct{}

func (*nilClock) Now() time.Time { return time.Time{} }

// fixedClock is a consumer's own clock with only Now, proving WithClock takes
// any type with that signature, not only a clockwork fake.
type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

// refusedWith pins the whole error text of a refused configuration: it names
// the first problem only, and never a configured value.
func refusedWith(problem string) func(t *testing.T, c *config, err error) {
	return func(t *testing.T, c *config, err error) {
		t.Helper()
		require.ErrorIs(t, err, ErrConfig)
		require.EqualError(t, err, "gorm: invalid configuration: "+problem)
		assert.Nil(t, c)
	}
}

func TestNewConfig(t *testing.T) {
	t.Parallel()

	// A zero *gorm.DB is never used: construction must not touch the database,
	// and would panic here if it tried.
	base := new(gormdb.DB)
	errBegin := errors.New("begin failed")
	errored := &gormdb.DB{Error: errBegin}
	gen := &fixedGenerator{}
	fixed := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)

	type testCase struct {
		name    string
		base    *gormdb.DB
		opts    []Option
		honours []optionKind
		assert  func(t *testing.T, c *config, err error)
	}

	cases := []testCase{
		{
			name: "defaults need no options",
			base: base,
			assert: func(t *testing.T, c *config, err error) {
				require.NoError(t, err)
				assert.Same(t, base, c.base)
				assert.Nil(t, c.resolver)
				assert.IsType(t, &id.V7Generator{}, c.ids)
				require.NotNil(t, c.clock)
				assert.WithinDuration(t, time.Now(), c.clock.Now(), time.Minute)
				assert.True(t, c.resealOnRead, "re-sealing on read is on by default")
			},
		},
		{
			name:    "options replace every default",
			base:    base,
			honours: []optionKind{optIDGenerator, optClock, optResealOnRead},
			opts: []Option{
				WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return nil, false }),
				WithIDGenerator(gen),
				WithClock(clockwork.NewFakeClockAt(fixed)),
				WithResealOnRead(false),
			},
			assert: func(t *testing.T, c *config, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NotNil(t, c.resolver)
				assert.Same(t, gen, c.ids)
				assert.True(t, fixed.Equal(c.clock.Now()))
				assert.False(t, c.resealOnRead)
			},
		},
		{
			// A Now-only consumer type: `time-source` "Third-party fake clock
			// passed directly" — no adapter is needed for any type with Now.
			name:    "a consumer clock with only Now is accepted",
			base:    base,
			honours: []optionKind{optClock},
			opts:    []Option{WithClock(fixedClock{at: fixed})},
			assert: func(t *testing.T, c *config, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.True(t, fixed.Equal(c.clock.Now()))
			},
		},
		{
			name:   "a nil database handle is refused",
			base:   nil,
			assert: refusedWith("the database handle is nil"),
		},
		{
			name: "a database handle that already carries an error is refused, wrapping it",
			base: errored,
			assert: func(t *testing.T, c *config, err error) {
				t.Helper()
				require.ErrorIs(t, err, ErrConfig)
				assert.ErrorIs(t, err, errBegin)
				assert.Nil(t, c)
			},
		},
		{
			name:   "a nil option is refused",
			base:   base,
			opts:   []Option{nil},
			assert: refusedWith("an option is nil"),
		},
		{
			name:   "a nil transaction resolver is refused",
			base:   base,
			opts:   []Option{WithTxResolver(nil)},
			assert: refusedWith("the transaction resolver is nil"),
		},
		{
			name:    "a nil id generator is refused",
			base:    base,
			honours: []optionKind{optIDGenerator},
			opts:    []Option{WithIDGenerator(nil)},
			assert:  refusedWith("the id generator is nil"),
		},
		{
			name:    "a typed-nil id generator is refused",
			base:    base,
			honours: []optionKind{optIDGenerator},
			opts:    []Option{WithIDGenerator((*id.V7Generator)(nil))},
			assert:  refusedWith("the id generator is nil"),
		},
		{
			name:    "a nil clock is refused",
			base:    base,
			honours: []optionKind{optClock},
			opts:    []Option{WithClock(nil)},
			assert:  refusedWith("the clock is nil"),
		},
		{
			name:    "a typed-nil clock is refused",
			base:    base,
			honours: []optionKind{optClock},
			opts:    []Option{WithClock((*nilClock)(nil))},
			assert:  refusedWith("the clock is nil"),
		},
		{
			name: "a later valid option does not clear an earlier nil one",
			base: base,
			opts: []Option{
				WithTxResolver(nil),
				WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return nil, false }),
			},
			assert: refusedWith("the transaction resolver is nil"),
		},
		{
			name:    "of several invalid options the first is named",
			base:    base,
			honours: []optionKind{optIDGenerator, optClock},
			opts:    []Option{WithClock(nil), WithIDGenerator(nil)},
			assert:  refusedWith("the clock is nil"),
		},
		{
			name:    "a nil option after an invalid one does not displace it",
			base:    base,
			honours: []optionKind{optClock},
			opts:    []Option{WithClock(nil), nil},
			assert:  refusedWith("the clock is nil"),
		},
		{
			name:    "a nil option before an invalid one is named",
			base:    base,
			honours: []optionKind{optClock},
			opts:    []Option{nil, WithClock(nil)},
			assert:  refusedWith("an option is nil"),
		},
		{
			name:   "an option the store does not honour is refused before its value is judged",
			base:   base,
			opts:   []Option{WithClock(nil)},
			assert: refusedWith("WithClock does not apply to this store"),
		},
		{
			name:   "a nil id generator given to a store that does not honour it is refused as not applying",
			base:   base,
			opts:   []Option{WithIDGenerator(nil)},
			assert: refusedWith("WithIDGenerator does not apply to this store"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := newConfig(tc.base, tc.opts, tc.honours...)
			tc.assert(t, c, err)
		})
	}
}

// TestNewConfigHonouredOptions pins which options each store accepts: an option
// a store does not honour is a configuration error naming the option, never
// silently ignored.
func TestNewConfigHonouredOptions(t *testing.T) {
	t.Parallel()

	base := new(gormdb.DB)

	// What each store will declare to newConfig. WithTxResolver is honoured by
	// every store without being declared.
	stores := []struct {
		name    string
		honours []optionKind
	}{
		{"session", []optionKind{optIDGenerator, optClock}},
		{"one-time token", []optionKind{optClock}},
		{"login attempt", []optionKind{optIDGenerator}},
		{"signing key", []optionKind{optIDGenerator, optResealOnRead}},
		{"MFA enrolment", []optionKind{optIDGenerator, optResealOnRead}},
		{"API key", nil},
		{"OIDC link", nil},
		{"OIDC flow", []optionKind{optIDGenerator, optClock}},
		{"OIDC handoff", nil},
	}

	options := []struct {
		name string
		kind optionKind // zero for an option every store honours
		opt  Option
	}{
		{"WithTxResolver", 0, WithTxResolver(func(context.Context) (*gormdb.DB, bool) { return nil, false })},
		{"WithIDGenerator", optIDGenerator, WithIDGenerator(&fixedGenerator{})},
		{"WithClock", optClock, WithClock(clockwork.NewRealClock())},
		{"WithResealOnRead", optResealOnRead, WithResealOnRead(false)},
	}

	type testCase struct {
		name    string
		honours []optionKind
		opt     Option
		assert  func(t *testing.T, c *config, err error)
	}

	var cases []testCase
	for _, s := range stores {
		for _, o := range options {
			if o.kind == 0 || slices.Contains(s.honours, o.kind) {
				cases = append(cases, testCase{
					name:    "the " + s.name + " store accepts " + o.name,
					honours: s.honours,
					opt:     o.opt,
					assert: func(t *testing.T, c *config, err error) {
						t.Helper()
						require.NoError(t, err)
						assert.NotNil(t, c)
					},
				})
				continue
			}
			cases = append(cases, testCase{
				name:    "the " + s.name + " store refuses " + o.name,
				honours: s.honours,
				opt:     o.opt,
				assert:  refusedWith(o.name + " does not apply to this store"),
			})
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := newConfig(base, []Option{tc.opt}, tc.honours...)
			tc.assert(t, c, err)
		})
	}
}
