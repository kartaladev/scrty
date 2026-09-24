package httpsec_test

import (
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// errDeepRefusal is what a recording interceptor refuses with, so a test can
// assert the very error it registered is the one the chain's caller receives.
var errDeepRefusal = errors.New("chain_test: refused deep in the chain")

// chainBuilder registers recording interceptors and remembers the order they
// were entered and left in. The trace is mutex-guarded because every frame of
// the assembled fold writes to the one slice, which is what -race is pointed
// at here.
type chainBuilder struct {
	mu      sync.Mutex
	records []string
	opts    []httpsec.Option
}

func newChainBuilder() *chainBuilder { return &chainBuilder{} }

func (b *chainBuilder) record(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.records = append(b.records, name)
}

func (b *chainBuilder) trace() []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return slices.Clone(b.records)
}

// at registers an interceptor that records its name, continues, and records
// again once everything inside it has returned.
func (b *chainBuilder) at(order httpsec.Order, name string) {
	b.register(order, func(ex *httpsec.Exchange, next httpsec.Next) error {
		b.record(name)
		err := next(ex)
		b.record(name + "-after")
		return err
	})
}

// stopAt registers an interceptor that records its name and returns without
// continuing, which must stop the request where it stands.
func (b *chainBuilder) stopAt(order httpsec.Order, name string) {
	b.register(order, func(_ *httpsec.Exchange, _ httpsec.Next) error {
		b.record(name)
		return nil
	})
}

// failAt registers an interceptor that refuses with err without continuing.
func (b *chainBuilder) failAt(order httpsec.Order, name string, err error) {
	b.register(order, func(_ *httpsec.Exchange, _ httpsec.Next) error {
		b.record(name)
		return err
	})
}

func (b *chainBuilder) register(order httpsec.Order, fn httpsec.InterceptorFunc) {
	b.opts = append(b.opts, httpsec.RegisterInterceptor(fn, order))
}

// run assembles the registered interceptors around a terminal that records
// "handler", and passes one exchange through the result.
func (b *chainBuilder) run(t *testing.T) error {
	t.Helper()

	chain, err := httpsec.New(b.opts...)
	require.NoError(t, err)

	run := chain.Assemble(func(_ *httpsec.Exchange) error {
		b.record("handler")
		return nil
	})

	return run(httpsec.NewExchange(t.Context(), stubRequest{}, &stubWriter{}))
}

func TestChainAssemble(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		register func(b *chainBuilder)
		assert   func(t *testing.T, trace []string, err error)
	}

	cases := []testCase{
		{
			name: "ascending slot order, lowest outermost",
			register: func(b *chainBuilder) {
				b.at(500, "five")
				b.at(100, "one")
				b.at(300, "three")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"one", "three", "five", "handler",
					"five-after", "three-after", "one-after",
				}, trace)
			},
		},
		{
			name: "equal slots keep registration order",
			register: func(b *chainBuilder) {
				b.at(400, "first")
				b.at(400, "second")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"first", "second", "handler", "second-after", "first-after",
				}, trace)
			},
		},
		{
			name: "equal slots keep registration order even when a lower slot was registered between them",
			register: func(b *chainBuilder) {
				b.at(400, "first")
				b.at(100, "outer")
				b.at(400, "second")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"outer", "first", "second", "handler",
					"second-after", "first-after", "outer-after",
				}, trace)
			},
		},
		{
			name: "Before and After bracket a named slot",
			register: func(b *chainBuilder) {
				b.at(httpsec.OrderBearerToken, "bearer")
				b.at(httpsec.After(httpsec.OrderBearerToken), "audit")
				b.at(httpsec.Before(httpsec.OrderBearerToken), "pre")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"pre", "bearer", "audit", "handler",
					"audit-after", "bearer-after", "pre-after",
				}, trace)
			},
		},
		{
			name:     "no interceptors leaves the handler reachable",
			register: func(_ *chainBuilder) {},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"handler"}, trace)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newChainBuilder()
			tc.register(b)

			err := b.run(t)
			tc.assert(t, b.trace(), err)
		})
	}
}

func TestChainContinuation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		register func(b *chainBuilder)
		assert   func(t *testing.T, trace []string, err error)
	}

	cases := []testCase{
		{
			name: "an interceptor that does not continue stops the request",
			register: func(b *chainBuilder) {
				b.at(100, "outer")
				b.stopAt(300, "gate")
				b.at(500, "inner")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"outer", "gate", "outer-after"}, trace)
				assert.NotContains(t, trace, "inner")
				assert.NotContains(t, trace, "handler")
			},
		},
		{
			name: "an error propagates outward unchanged",
			register: func(b *chainBuilder) {
				b.at(100, "outer")
				b.failAt(900, "deep", errDeepRefusal)
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.ErrorIs(t, err, errDeepRefusal)
				assert.Equal(t, []string{"outer", "deep", "outer-after"}, trace)
			},
		},
		{
			name: "the post-handler step runs after the handler returned",
			register: func(b *chainBuilder) {
				b.at(httpsec.OrderSessionTouch, "touch")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"touch", "handler", "touch-after"}, trace)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newChainBuilder()
			tc.register(b)

			err := b.run(t)
			tc.assert(t, b.trace(), err)
		})
	}
}
