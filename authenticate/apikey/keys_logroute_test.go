package apikey_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/internal/ctxlog"
)

// TestLogRoute_Keys pins where a verification record goes: the manager's own
// logger when given, else the logger of the chain handling the request, else
// slog.Default() as it is when the record is written. It swaps the default
// logger, so it does not run in parallel.
func TestLogRoute_Keys(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		opts   func(own *slog.Logger) []apikey.Option
		chain  bool
		assert func(t *testing.T, err error, own, chain, def *bytes.Buffer)
	}

	const msg = "apikey: verification failed"

	cases := []testCase{
		{
			name:  "no option, inside a configured chain",
			chain: true,
			assert: func(t *testing.T, err error, _, chain, def *bytes.Buffer) {
				require.NoError(t, err)
				assert.Contains(t, chain.String(), msg)
				assert.Empty(t, def.String(), "the default logger must see nothing")
			},
		},
		{
			name:  "own option wins",
			opts:  func(own *slog.Logger) []apikey.Option { return []apikey.Option{apikey.WithLogger(own)} },
			chain: true,
			assert: func(t *testing.T, err error, own, chain, def *bytes.Buffer) {
				require.NoError(t, err)
				assert.Contains(t, own.String(), msg)
				assert.Empty(t, chain.String())
				assert.Empty(t, def.String())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, err error, _, _, def *bytes.Buffer) {
				require.NoError(t, err)
				assert.Contains(t, def.String(), msg, "the default as swapped at record time")
			},
		},
		{
			name: "nil option",
			opts: func(*slog.Logger) []apikey.Option { return []apikey.Option{apikey.WithLogger(nil)} },
			assert: func(t *testing.T, err error, _, _, _ *bytes.Buffer) {
				require.ErrorIs(t, err, apikey.ErrConfig)
				assert.ErrorContains(t, err, "WithLogger")
			},
		},
	}

	debug := func(w *bytes.Buffer) *slog.Logger {
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var own, chain, def bytes.Buffer

			previous := slog.Default()
			slog.SetDefault(debug(&def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			var opts []apikey.Option
			if tc.opts != nil {
				opts = tc.opts(debug(&own))
			}

			m, err := apikey.New(opts...)
			if err != nil {
				tc.assert(t, err, &own, &chain, &def)

				return
			}

			// A well-formed key of another manager names an identifier this
			// manager's empty store does not hold.
			issuer, err := apikey.New()
			require.NoError(t, err)
			presented, _, err := issuer.Issue(t.Context(), "svc", "k", nil, 0)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, debug(&chain))
			}

			_, _, verifyErr := m.Verify(ctx, presented)
			require.ErrorIs(t, verifyErr, apikey.ErrVerificationFailed)

			tc.assert(t, nil, &own, &chain, &def)
		})
	}
}
