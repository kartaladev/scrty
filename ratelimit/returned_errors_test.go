package ratelimit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/ratelimit"
)

// TestGuardReturnedErrors pins the diagnostic-redaction requirement for
// SourceGuard.Check's own returned error (design decision 8): a limiter
// failure comes back as fixed library text, with ErrThrottled and the
// limiter's own error both still reachable by identity, and the status this
// error maps to (httpsec.StatusForError, which keys on ErrThrottled) is
// therefore unchanged.
func TestGuardReturnedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		run    func(t *testing.T) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "the limiter cannot say whether a source is over its limit",
			run: func(t *testing.T) error {
				t.Helper()

				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errLimiterFixture)

				g, err := ratelimit.NewSourceGuard(testFlow, l)
				require.NoError(t, err)

				_, checkErr := g.Check(t.Context(), testSource)

				return checkErr
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.NotContains(t, err.Error(), "alice@example.com",
					"the returned error quoted the limiter's own text")
				assert.NotContains(t, err.Error(), "u-123",
					"the returned error quoted the limiter's own text")
				assert.NotContains(t, err.Error(), limiterKeyText,
					"the returned error quoted the limiter's own key")
				assert.ErrorIs(t, err, errLimiterFixture, "the limiter's own error is no longer reachable")
				assert.ErrorIs(t, err, ratelimit.ErrThrottled, "the throttle sentinel is no longer reachable")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}
