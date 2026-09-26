package ratelimit_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/ratelimit"
)

// limiterKeyText is the key a consumer's own limiter might quote in its own
// error — in a format the guard itself never produces, since a dependency's
// text is not something the library controls.
const limiterKeyText = "magic-link|203.0.113.7"

// errLimiterFixture is the dependency error every leak row proves against: a
// limiter's own text, quoting its key, an address and a user reference the
// record must never repeat.
var errLimiterFixture = fmt.Errorf(
	"limiter: key %s: store: Key (username)=(alice@example.com) for user u-123", limiterKeyText)

// TestGuardFailureRecords pins the diagnostic-redaction requirement: a
// limiter's own failure is recorded by a fixed reason and the error's Go
// type, never by the limiter's own text, while the deliberate fields — the
// flow and the throttled source's address — are kept.
//
// Each row's call sequence differs — a check that cannot consult the
// limiter, a check that is throttled, a recording the limiter fails — so each
// is a run closure rather than a shared call shape.
func TestGuardFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T) (*logRecorder, error)
		assert func(t *testing.T, recs []map[string]any, rendered string)
	}

	cases := []testCase{
		{
			name: "the limiter cannot say whether a source is over its limit",
			run: func(t *testing.T) (*logRecorder, error) {
				t.Helper()

				ctrl := gomock.NewController(t)
				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errLimiterFixture)

				recorder, logger := newLogRecorder()
				g, err := ratelimit.NewSourceGuard("magic-link", l, ratelimit.WithSourceGuardLogger(logger))
				require.NoError(t, err)

				_, checkErr := g.Check(t.Context(), "203.0.113.7")

				return recorder, checkErr
			},
			assert: func(t *testing.T, recs []map[string]any, rendered string) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, "magic-link", recs[0]["flow"])
				assert.Equal(t, "limiter", recs[0]["reason"])
				assert.NotEmpty(t, recs[0]["error_type"])
				assert.NotContains(t, rendered, limiterKeyText, "the limiter's own key text leaked")
			},
		},
		{
			name: "a throttled source still writes its record with the deliberate source field",
			run: func(t *testing.T) (*logRecorder, error) {
				t.Helper()

				ctrl := gomock.NewController(t)
				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil)

				recorder, logger := newLogRecorder()
				g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
				require.NoError(t, err)

				_, checkErr := g.Check(t.Context(), testSource)

				return recorder, checkErr
			},
			assert: func(t *testing.T, recs []map[string]any, _ string) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, testFlow, recs[0]["flow"])
				assert.Equal(t, testSource, recs[0]["source"], "the deliberate throttle field is kept")
			},
		},
		{
			// Found while reading guard.go alongside the named site above: the
			// same limiter dependency's error also reaches RecordFailure's own
			// failure record unredacted. It shares the fix, since it is the
			// same defect in the same file.
			name: "recording a failure the limiter cannot count",
			run: func(t *testing.T) (*logRecorder, error) {
				t.Helper()

				ctrl := gomock.NewController(t)
				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)
				l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errLimiterFixture)

				recorder, logger := newLogRecorder()
				g, err := ratelimit.NewSourceGuard(testFlow, l, ratelimit.WithSourceGuardLogger(logger))
				require.NoError(t, err)

				src, err := g.Check(t.Context(), testSource)
				require.NoError(t, err)

				g.RecordFailure(t.Context(), src)

				return recorder, nil
			},
			assert: func(t *testing.T, recs []map[string]any, rendered string) {
				t.Helper()

				require.Len(t, recs, 1)
				assert.Equal(t, "limiter", recs[0]["reason"])
				assert.NotEmpty(t, recs[0]["error_type"])
				assert.NotContains(t, rendered, limiterKeyText, "the limiter's own key text leaked")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recorder, _ := tc.run(t)
			rendered := recorder.String()

			assert.NotContains(t, rendered, "alice@example.com", "a written record leaked the fixture address")
			assert.NotContains(t, rendered, "u-123", "a written record leaked the fixture user reference")

			tc.assert(t, logRecords(t, recorder), rendered)
		})
	}
}
