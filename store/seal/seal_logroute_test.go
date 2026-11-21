package seal_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.
//
// Nothing in this package has a logger option: each site reports an error it
// cannot walk to the logger of the chain handling the request, else to
// slog.Default() when the record is written. The rows run every site the
// port-error tests already name, with one hostile error.

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/ctxlog"
)

func TestLogRoute_Seal(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		chain  bool
		assert func(t *testing.T, sites int, chain, def *cpeRecorder)
	}

	cases := []testCase{
		{
			name:  "inside a configured chain",
			chain: true,
			assert: func(t *testing.T, sites int, chain, def *cpeRecorder) {
				assert.Equal(t, sites, chain.aborts(), "the chain's logger receives one record per site")
				assert.Zero(t, def.aborts(), "slog.Default() receives none")
			},
		},
		{
			name: "no chain",
			assert: func(t *testing.T, sites int, chain, def *cpeRecorder) {
				assert.Equal(t, sites, def.aborts(), "slog.Default(), as set when the record is written")
				assert.Zero(t, chain.aborts())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
			chain, def := new(cpeRecorder), new(cpeRecorder)

			prev := slog.Default()
			slog.SetDefault(slog.New(def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctx := t.Context()
			if tc.chain {
				ctx = ctxlog.With(ctx, slog.New(chain))
			}

			var sites int

			for _, site := range cpeSites() {
				site.run(t, ctx, gomock.NewController(t), &cpeCycleOne{})

				sites++
			}

			for _, site := range mpeSites() {
				ctrl := gomock.NewController(t)
				inner := NewMockEnrolmentStore(ctrl)
				site.run(t, ctx, inner, mpeStore(t, inner), &cpeCycleOne{})

				sites++
			}

			for _, site := range skeSites() {
				site.run(t, ctx, &cpeCycleOne{})

				sites++
			}

			require.NotZero(t, sites)
			tc.assert(t, sites, chain, def)
		})
	}
}
