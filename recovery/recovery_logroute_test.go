package recovery_test

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/recovery"
)

// lrRow is one row of the log-routing tables below.
type lrRow struct {
	name string
	// own gives the component its own logger option.
	own bool
	// chain places a chain logger on the request's context.
	chain bool
	// nilOption gives the logger option nil.
	nilOption bool
	assert    func(t *testing.T, err error, own, chain, def *syncBuffer)
}

// lrRows are the rows both components share, over the record each one writes
// at Error level for a plain outage of one of its ports.
func lrRows() []lrRow {
	return []lrRow{
		{
			name: "no option, inside a configured chain", chain: true,
			assert: func(t *testing.T, err error, _, chain, def *syncBuffer) {
				require.NoError(t, err)
				assert.Contains(t, chain.String(), `"level":"ERROR"`, "the chain's logger takes the record")
				assert.Empty(t, def.String(), "the default logger must see nothing")
			},
		},
		{
			name: "own option wins", own: true, chain: true,
			assert: func(t *testing.T, err error, own, chain, def *syncBuffer) {
				require.NoError(t, err)
				assert.Contains(t, own.String(), `"level":"ERROR"`)
				assert.Empty(t, chain.String())
				assert.Empty(t, def.String())
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, err error, _, _, def *syncBuffer) {
				require.NoError(t, err)
				assert.Contains(t, def.String(), `"level":"ERROR"`, "the default as swapped at record time")
			},
		},
		{
			name: "nil option", nilOption: true,
			assert: func(t *testing.T, err error, _, _, _ *syncBuffer) {
				require.ErrorIs(t, err, recovery.ErrConfig)
			},
		},
	}
}

func lrJSON(w *syncBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestLogRoute_Recoverer pins where the recoverer's records go: its own
// logger when given, else the logger of the chain handling the request, else
// slog.Default() as it is when the record is written. It swaps the default
// logger, so it does not run in parallel.
func TestLogRoute_Recoverer(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	for _, tc := range lrRows() {
		t.Run(tc.name, func(t *testing.T) {
			own, chain, def := &syncBuffer{}, &syncBuffer{}, &syncBuffer{}

			previous := slog.Default()
			t.Cleanup(func() { slog.SetDefault(previous) })

			f := newFixture(t)
			opts := []recovery.Option{
				recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
				recovery.WithRepudiationContact(repudiation),
				recovery.WithAuthenticatorKinds(f.kind),
				recovery.WithClock(f.clock),
			}

			switch {
			case tc.nilOption:
				opts = append(opts, recovery.WithLogger(nil))
			case tc.own:
				opts = append(opts, recovery.WithLogger(lrJSON(own)))
			}

			r, err := recovery.NewRecoverer(f.deps(), opts...)
			if err != nil {
				tc.assert(t, err, own, chain, def)
				assert.ErrorContains(t, err, "WithLogger")

				return
			}

			slog.SetDefault(lrJSON(def))

			f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(nil, errors.New("store unreachable"))

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, lrJSON(chain))
			}

			r.Start(ctx, anaUsername)

			tc.assert(t, nil, own, chain, def)
		})
	}
}

// TestLogRoute_Codes is TestLogRoute_Recoverer for the saved-code manager,
// over a code store that is down.
func TestLogRoute_Codes(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	for _, tc := range lrRows() {
		t.Run(tc.name, func(t *testing.T) {
			own, chain, def := &syncBuffer{}, &syncBuffer{}, &syncBuffer{}

			previous := slog.Default()
			t.Cleanup(func() { slog.SetDefault(previous) })

			flt := newFaults()
			flt.arm(faultCodesReplaceSet, errors.New("store unreachable"))

			opts := []recovery.CodesOption{
				recovery.WithCodesStore(faultyCodeStore{CodeStore: recovery.NewMemoryCodeStore(), f: flt}),
			}

			switch {
			case tc.nilOption:
				opts = append(opts, recovery.WithCodesLogger(nil))
			case tc.own:
				opts = append(opts, recovery.WithCodesLogger(lrJSON(own)))
			}

			c, err := recovery.NewCodes(opts...)
			if err != nil {
				tc.assert(t, err, own, chain, def)
				assert.ErrorContains(t, err, "WithCodesLogger")

				return
			}

			slog.SetDefault(lrJSON(def))

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, lrJSON(chain))
			}

			_, genErr := c.Generate(ctx, anaID)
			require.Error(t, genErr)

			tc.assert(t, nil, own, chain, def)
		})
	}
}
