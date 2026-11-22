package passkey_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// summaryFor counts the summaries in out written for sampler key.
func summaryFor(out, key string) int {
	n := 0

	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, `"msg":"passkey: records suppressed"`) &&
			strings.Contains(line, `"key":"`+key+`"`) {
			n++
		}
	}

	return n
}

// TestLogRoute_PasskeysSummaryPerKey pins that each key's summary goes to the
// chain that key's records went to, never to another chain's log. It swaps the
// default logger, so it does not run in parallel.
func TestLogRoute_PasskeysSummaryPerKey(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	const (
		unknownKey   = "refused|unknown-credential"
		malformedKey = "refused|malformed"
	)

	type testCase struct {
		name string
		own  bool
		// run writes refusals through refuse(ctx, malformed): the unknown
		// credential key when false, the malformed key when true.
		run    func(bare, a, b context.Context, refuse func(context.Context, bool))
		assert func(t *testing.T, a, b, def, own string)
	}

	three := func(ctx context.Context, refuse func(context.Context, bool), malformed bool) {
		for range 3 {
			refuse(ctx, malformed)
		}
	}

	cases := []testCase{
		{
			name: "two chains: each summary stays on its own chain",
			run: func(_, a, b context.Context, refuse func(context.Context, bool)) {
				three(a, refuse, false)
				three(b, refuse, true)
			},
			assert: func(t *testing.T, a, b, def, _ string) {
				assert.Equal(t, 1, summaryFor(a, unknownKey))
				assert.Zero(t, summaryFor(a, malformedKey))
				assert.Equal(t, 1, summaryFor(b, malformedKey))
				assert.Zero(t, summaryFor(b, unknownKey))
				assert.Empty(t, def)
			},
		},
		{
			name: "key written under A then suppressed under B: summary on A only",
			run: func(_, a, b context.Context, refuse func(context.Context, bool)) {
				three(a, refuse, false)
				three(b, refuse, false)
			},
			assert: func(t *testing.T, a, b, def, _ string) {
				assert.Equal(t, 1, summaryFor(a, unknownKey))
				assert.Empty(t, b)
				assert.Empty(t, def)
			},
		},
		{
			name: "no chain: the default logger",
			run: func(bare, _, _ context.Context, refuse func(context.Context, bool)) {
				three(bare, refuse, false)
			},
			assert: func(t *testing.T, a, b, def, _ string) {
				assert.Equal(t, 1, summaryFor(def, unknownKey))
				assert.Empty(t, a)
				assert.Empty(t, b)
			},
		},
		{
			name: "own option wins",
			own:  true,
			run: func(_, a, _ context.Context, refuse func(context.Context, bool)) {
				three(a, refuse, false)
			},
			assert: func(t *testing.T, a, _, def, own string) {
				assert.Equal(t, 1, summaryFor(own, unknownKey))
				assert.Empty(t, a)
				assert.Empty(t, def)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chainA, chainB, def, own := &logBuffer{}, &logBuffer{}, &logBuffer{}, &logBuffer{}

			previous := slog.Default()
			slog.SetDefault(def.logger())
			t.Cleanup(func() { slog.SetDefault(previous) })

			e := newLoginEnv(t, nil)

			var opts []passkey.Option
			if tc.own {
				opts = append(opts, passkey.WithLogger(own.logger()))
			}

			e.m = e.f.manager(t, opts...)

			refuse := func(ctx context.Context, malformed bool) {
				body := assertion(e.begin(t), func(b *assertionBody) { b.ID = "nobody's key" }) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
				if malformed {
					body = []byte("not an assertion")
				}

				_, err := e.m.Authenticate(ctx, body, e.binding)
				require.Error(t, err)
			}

			tc.run(t.Context(), ctxlog.With(t.Context(), chainA.logger()), ctxlog.With(t.Context(), chainB.logger()), refuse)

			require.NoError(t, e.m.FlushRefusalLogs())
			tc.assert(t, chainA.String(), chainB.String(), def.String(), own.String())
		})
	}
}
