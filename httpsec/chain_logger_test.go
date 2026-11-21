package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// TestChainLogger_Nested pins where a record lands for a request through one
// chain, or through one chain mounted inside another: the logger of the
// innermost chain given WithLogger, read from the request's context, else
// slog.Default() at record time. A chain given no logger answers none, so an
// enclosing chain's logger is found past it. Each row checks two writers: a
// component's routing logger in the handler (handler), and the inner chain's
// own record of a refusal whose classification aborted (chain).
func TestChainLogger_Nested(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type sinks struct{ outer, inner, def *capturingHandler }

	type testCase struct {
		name        string
		outer       *bool // nil: a single chain; else whether the outer chain is given WithLogger
		innerLogger bool
		assert      func(t *testing.T, s sinks, carried *slog.Logger)
	}

	yes, no := true, false

	// landsOn asserts every record of both writers landed on want and nowhere
	// else, and what From read on the handler's context.
	landsOn := func(want func(s sinks) *capturingHandler, wantCarried func(s sinks) *capturingHandler) func(t *testing.T, s sinks, carried *slog.Logger) {
		return func(t *testing.T, s sinks, carried *slog.Logger) {
			t.Helper()

			target := want(s)

			var handler, aborted int

			for _, r := range target.records() {
				switch r.Message {
				case "handler":
					handler++
				case msgClassificationAborted:
					aborted++
				}
			}

			assert.Equal(t, 1, handler, "the handler's record did not land on the expected logger")
			assert.Positive(t, aborted, "the inner chain's abort record did not land on the expected logger")

			for _, other := range []*capturingHandler{s.outer, s.inner, s.def} {
				if other != target {
					assert.Empty(t, other.records(), "a record landed on another logger")
				}
			}

			if wantCarried == nil {
				assert.Nil(t, carried, "the context carries a logger")
			} else {
				require.NotNil(t, carried)
				assert.Same(t, wantCarried(s), carried.Handler())
			}
		}
	}

	outerSink := func(s sinks) *capturingHandler { return s.outer }
	innerSink := func(s sinks) *capturingHandler { return s.inner }
	defSink := func(s sinks) *capturingHandler { return s.def }

	cases := []testCase{
		{
			name:        "a single configured chain answers its logger",
			innerLogger: true,
			assert:      landsOn(innerSink, innerSink),
		},
		{
			name:   "a single unconfigured chain answers no logger",
			assert: landsOn(defSink, nil),
		},
		{
			name:   "inner unconfigured reaches the outer logger",
			outer:  &yes,
			assert: landsOn(outerSink, outerSink),
		},
		{
			name:        "both configured gives the inner logger",
			outer:       &yes,
			innerLogger: true,
			assert:      landsOn(innerSink, innerSink),
		},
		{
			name:   "neither configured gives the default",
			outer:  &no,
			assert: landsOn(defSink, nil),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := sinks{outer: &capturingHandler{}, inner: &capturingHandler{}, def: &capturingHandler{}}

			component := ctxlog.Routing()

			var carried *slog.Logger

			handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				carried = ctxlog.From(r.Context())
				component.InfoContext(r.Context(), "handler")
			})

			// The inner chain lets the request reach the handler, then refuses
			// it with an error whose classification aborts, so the chain
			// writes a record of its own.
			innerOpts := []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
				func(ex *httpsec.Exchange, next httpsec.Next) error {
					if err := next(ex); err != nil {
						return err
					}

					return &cycleOne{}
				}), httpsec.OrderBearerToken)}
			if tc.innerLogger {
				innerOpts = append(innerOpts, httpsec.WithLogger(slog.New(s.inner)))
			}

			inner, err := httpsec.New(innerOpts...)
			require.NoError(t, err)

			h := inner.Middleware()(handler)

			if tc.outer != nil {
				var outerOpts []httpsec.Option
				if *tc.outer {
					outerOpts = append(outerOpts, httpsec.WithLogger(slog.New(s.outer)))
				}

				outer, err := httpsec.New(outerOpts...)
				require.NoError(t, err)

				h = outer.Middleware()(h)
			}

			// Swapped after the chains are built: the default is read when a
			// record is written.
			prev := slog.Default()
			slog.SetDefault(slog.New(s.def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/x", nil))

			tc.assert(t, s, carried)
		})
	}
}
