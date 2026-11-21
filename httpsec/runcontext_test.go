package httpsec_test

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/guardauth"
)

var errRunContextRefusal = errors.New("refused before the terminal")

// TestRunContext pins the module-internal record of an exchange's run that the
// adapters read, through guardauth.RunContext, to answer a refusal made before
// their route ran: the context of the outermost run made on the exchange,
// which still answers the chain's status lookup and logger after the step has
// put the exchange's own context back.
func TestRunContext(t *testing.T) {
	t.Parallel()

	loggerOf := func(t *testing.T, name string) (*httpsec.Chain, *slog.Logger) {
		t.Helper()

		l := slog.New(slog.DiscardHandler).With("chain", name)
		refuse := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
			func(*httpsec.Exchange, httpsec.Next) error { return errRunContextRefusal }), httpsec.OrderAuthorizer)

		c, err := httpsec.New(httpsec.WithLogger(l), refuse)
		require.NoError(t, err)

		return c, l
	}

	type testCase struct {
		name string
		// run runs chains on ex and returns the logger the run context must
		// answer, nil when no run was made.
		run    func(t *testing.T, ex *httpsec.Exchange) *slog.Logger
		assert func(t *testing.T, ex *httpsec.Exchange, want *slog.Logger)
	}

	answers := func(t *testing.T, ex *httpsec.Exchange, want *slog.Logger) {
		t.Helper()

		runCtx := guardauth.RunContext(ex)
		require.NotNil(t, runCtx, "no run context after the run")
		assert.Same(t, want, runCtx.Value(ctxlog.Key{}), "the run context answers another chain's logger")
		assert.NotNil(t, runCtx.Value(guardauth.LookupKey{}), "the run context answers no status lookup")
		assert.Nil(t, ex.Context().Value(guardauth.LookupKey{}), "the exchange's context was not put back")
	}

	cases := []testCase{
		{
			name: "no run made",
			run:  func(*testing.T, *httpsec.Exchange) *slog.Logger { return nil },
			assert: func(t *testing.T, ex *httpsec.Exchange, _ *slog.Logger) {
				t.Helper()
				assert.Nil(t, guardauth.RunContext(ex))
			},
		},
		{
			name: "a run refused before its terminal",
			run: func(t *testing.T, ex *httpsec.Exchange) *slog.Logger {
				t.Helper()

				c, l := loggerOf(t, "only")
				require.ErrorIs(t, c.Assemble(okTerminal)(ex), errRunContextRefusal)

				return l
			},
			assert: answers,
		},
		{
			name: "a run nested on the exchange leaves the outermost run's",
			run: func(t *testing.T, ex *httpsec.Exchange) *slog.Logger {
				t.Helper()

				inner, _ := loggerOf(t, "inner")
				outerLogger := slog.New(slog.DiscardHandler).With("chain", "outer")
				nesting := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						return inner.Assemble(next)(ex)
					}), httpsec.OrderAuthorizer)

				outer, err := httpsec.New(httpsec.WithLogger(outerLogger), nesting)
				require.NoError(t, err)
				require.ErrorIs(t, outer.Assemble(okTerminal)(ex), errRunContextRefusal)

				return outerLogger
			},
			assert: answers,
		},
		{
			name: "an exchange run again records the later run's",
			run: func(t *testing.T, ex *httpsec.Exchange) *slog.Logger {
				t.Helper()

				first, _ := loggerOf(t, "first")
				second, l := loggerOf(t, "second")
				require.ErrorIs(t, first.Assemble(okTerminal)(ex), errRunContextRefusal)
				require.ErrorIs(t, second.Assemble(okTerminal)(ex), errRunContextRefusal)

				return l
			},
			assert: answers,
		},
		{
			name: "not an exchange",
			run:  func(*testing.T, *httpsec.Exchange) *slog.Logger { return nil },
			assert: func(t *testing.T, _ *httpsec.Exchange, _ *slog.Logger) {
				t.Helper()
				assert.Nil(t, guardauth.RunContext("not an exchange"))
				assert.Nil(t, guardauth.RunContext((*httpsec.Exchange)(nil)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ex := foldExchange(t)
			want := tc.run(t, ex)
			tc.assert(t, ex, want)
		})
	}
}

// okTerminal is a terminal a refused run never reaches.
func okTerminal(*httpsec.Exchange) error { return nil }
