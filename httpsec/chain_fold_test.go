package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// foldRecorder collects the names of the steps a run reached, in order. It is
// safe for concurrent use because the concurrent case shares one chain.
type foldRecorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *foldRecorder) record(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.steps = append(r.steps, step)
}

func (r *foldRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.steps...)
}

// foldChain builds a chain with one consumer interceptor, at a slot clear of
// every built-in.
func foldChain(t *testing.T, interceptor httpsec.InterceptorFunc) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(httpsec.RegisterInterceptor(interceptor, httpsec.Order(100)))
	require.NoError(t, err)

	return c
}

func foldExchange(t *testing.T) *httpsec.Exchange {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)

	return httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(r),
		httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
}

// TestAssemble_TerminalPerRun pins that the step a chain runs innermost is the
// terminal of the run it belongs to: the one Assemble was given for this
// exchange, and no other.
func TestAssemble_TerminalPerRun(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// run builds whatever the case needs, runs it, and returns the error
		// the outermost step returned, with what the run recorded.
		run    func(t *testing.T) (steps []string, err error)
		assert func(t *testing.T, steps []string, err error)
	}

	cases := []testCase{
		{
			name: "foreign exchange",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}
				c := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					return next(httpsec.NewExchange(ex.Context(), ex.Request, ex.Writer))
				})

				err := c.Assemble(func(*httpsec.Exchange) error {
					rec.record("A-terminal")
					return nil
				})(foldExchange(t))

				return rec.recorded(), err
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Equal(t, []string{"A-int"}, steps, "the terminal ran for an exchange the chain is not running")
			},
		},
		{
			name: "nested different chain",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}
				b := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("B-int")
					return next(ex)
				})
				a := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					return b.Assemble(next)(ex)
				})

				err := a.Assemble(func(*httpsec.Exchange) error {
					rec.record("A-terminal")
					return nil
				})(foldExchange(t))

				return rec.recorded(), err
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"A-int", "B-int", "A-terminal"}, steps)
			},
		},
		{
			// The nested run is for another path, as an in-process forward
			// is, so the chain runs it in full on the same exchange.
			name: "nested same chain",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}

				var c *httpsec.Chain

				nested := false
				c = foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					if nested {
						return next(ex)
					}

					nested = true
					ex.Request = httpsec.NewHTTPRequest(
						httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/other", nil))

					return c.Assemble(next)(ex)
				})

				err := c.Assemble(func(*httpsec.Exchange) error {
					rec.record("A-terminal")
					return nil
				})(foldExchange(t))

				return rec.recorded(), err
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"A-int", "A-int", "A-terminal"}, steps)
			},
		},
		{
			name: "nested same chain on the same request passes through",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}

				var c *httpsec.Chain

				c = foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					return c.Assemble(next)(ex)
				})

				err := c.Assemble(func(*httpsec.Exchange) error {
					rec.record("A-terminal")
					return nil
				})(foldExchange(t))

				return rec.recorded(), err
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"A-int", "A-terminal"}, steps)
			},
		},
		{
			name: "more nested chains than the inline entries hold",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}

				// Chain i nests chain i+1, four deep, so two entries spill past
				// the exchange's inline array.
				const depth = 4

				chains := make([]*httpsec.Chain, depth)
				for i := depth - 1; i >= 0; i-- {
					name := "C" + strconv.Itoa(i) + "-int"
					c := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
						rec.record(name)
						if i+1 < depth {
							return chains[i+1].Assemble(next)(ex)
						}

						return next(ex)
					})
					chains[i] = c
				}

				ex := foldExchange(t)

				for range 2 {
					err := chains[0].Assemble(func(*httpsec.Exchange) error {
						rec.record("terminal")
						return nil
					})(ex)
					if err != nil {
						return rec.recorded(), err
					}
				}

				return rec.recorded(), nil
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.NoError(t, err)

				once := []string{"C0-int", "C1-int", "C2-int", "C3-int", "terminal"}
				assert.Equal(t, append(append([]string(nil), once...), once...), steps,
					"the second run on the same exchange should find the stack as the first did")
			},
		},
		{
			name: "next twice",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}
				c := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					if err := next(ex); err != nil {
						return err
					}

					return next(ex)
				})

				err := c.Assemble(func(*httpsec.Exchange) error {
					rec.record("A-terminal")
					return nil
				})(foldExchange(t))

				return rec.recorded(), err
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"A-int", "A-terminal", "A-terminal"}, steps)
			},
		},
		{
			name: "next twice after the stack reallocated inside the first",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}

				// A, B and C nest on one exchange, so C's entry is the first
				// to spill past the inline array. While C's first next is in
				// progress, D starts a run on the same exchange and grows the
				// spilled entries, moving C's. C's second next must still find
				// its run free again.
				d := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("D-int")
					return next(ex)
				})
				cc := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("C-int")
					if err := next(ex); err != nil {
						return err
					}

					return next(ex)
				})
				b := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("B-int")
					return next(ex)
				})
				a := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					return next(ex)
				})

				ranD := false
				cTerminal := func(ex *httpsec.Exchange) error {
					rec.record("C-terminal")

					if ranD {
						return nil
					}

					ranD = true

					return d.Assemble(func(*httpsec.Exchange) error {
						rec.record("D-terminal")
						return nil
					})(ex)
				}
				bTerminal := func(ex *httpsec.Exchange) error { return cc.Assemble(cTerminal)(ex) }
				aTerminal := func(ex *httpsec.Exchange) error { return b.Assemble(bTerminal)(ex) }

				err := a.Assemble(aTerminal)(foldExchange(t))

				return rec.recorded(), err
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"A-int", "B-int", "C-int", "C-terminal", "D-int", "D-terminal", "C-terminal",
				}, steps)
			},
		},
		{
			name: "terminal calls next of its own run",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}

				var kept httpsec.Next

				c := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					kept = next

					return next(ex)
				})

				reentered := false
				err := c.Assemble(func(ex *httpsec.Exchange) error {
					rec.record("A-terminal")

					if reentered {
						return nil
					}

					reentered = true

					return kept(ex)
				})(foldExchange(t))

				return rec.recorded(), err
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Equal(t, []string{"A-int", "A-terminal"}, steps,
					"the terminal ran again from inside itself")
			},
		},
		{
			name: "next kept past its run",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}

				var kept httpsec.Next

				c := foldChain(t, func(_ *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					kept = next

					return nil
				})

				ex := foldExchange(t)

				err := c.Assemble(func(*httpsec.Exchange) error {
					rec.record("stale-terminal")
					return nil
				})(ex)
				if err != nil {
					return rec.recorded(), err
				}

				return rec.recorded(), kept(ex)
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Equal(t, []string{"A-int"}, steps, "a step called after its run ended reached that run's terminal")
			},
		},
		{
			name: "panic in an interceptor leaves no entry behind",
			run: func(t *testing.T) ([]string, error) {
				rec := &foldRecorder{}

				var kept httpsec.Next

				c := foldChain(t, func(_ *httpsec.Exchange, next httpsec.Next) error {
					rec.record("A-int")
					kept = next

					panic("interceptor failed")
				})

				ex := foldExchange(t)

				func() {
					defer func() { _ = recover() }()

					_ = c.Assemble(func(*httpsec.Exchange) error {
						rec.record("stale-terminal")
						return nil
					})(ex)
				}()

				// The run that panicked is over, so its terminal must be gone
				// from the exchange: a step of the chain reached on it now finds
				// no terminal rather than the stale one.
				return rec.recorded(), kept(ex)
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Equal(t, []string{"A-int"}, steps)
			},
		},
		{
			name: "concurrent",
			run: func(t *testing.T) ([]string, error) {
				const goroutines = 64

				c := foldChain(t, func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) })

				var (
					wg   sync.WaitGroup
					mu   sync.Mutex
					errs []error
				)

				seen := make([]string, goroutines)
				start := make(chan struct{})

				for i := range goroutines {
					wg.Go(func() {
						<-start

						mine := strconv.Itoa(i)
						err := c.Assemble(func(*httpsec.Exchange) error {
							seen[i] = mine
							return nil
						})(foldExchange(t))
						if err != nil {
							mu.Lock()
							errs = append(errs, err)
							mu.Unlock()
						}
					})
				}

				close(start)
				wg.Wait()

				for i, s := range seen {
					if s != strconv.Itoa(i) {
						return seen, errors.New("goroutine " + strconv.Itoa(i) + " saw terminal " + s)
					}
				}

				return seen, errors.Join(errs...)
			},
			assert: func(t *testing.T, steps []string, err error) {
				require.NoError(t, err)
				assert.Len(t, steps, 64)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			steps, err := tc.run(t)
			tc.assert(t, steps, err)
		})
	}
}
