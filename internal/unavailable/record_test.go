package unavailable_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

// writesFailReadsSucceed is a backend out of memory under noeviction: every
// record fails and every check answers "not exceeded".
func (h *harness) writesFailReadsSucceed() {
	h.backend.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(errDown).AnyTimes()
	h.backend.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
}

// recordN records n failures for key and returns what each record returned.
func (h *harness) recordN(t *testing.T, key string, n int) []error {
	t.Helper()

	errs := make([]error, n)
	for i := range n {
		errs[i] = h.limiter.RecordFailure(t.Context(), key)
	}

	return errs
}

// TestUnavailable_RecordErrors covers task 4.3, scenario "Writes fail while
// reads succeed": in refuse mode a failure that could not be recorded holds its
// key as refused on this instance for one window, even once checks reach the
// backend again; in fall-back mode it is counted locally and either count
// exceeds; in allow mode it is dropped. Every case ends with one check of
// testKey.
func TestUnavailable_RecordErrors(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		mode    ratelimit.UnavailableMode
		arrange func(t *testing.T, h *harness)
		assert  func(t *testing.T, h *harness, exceeded bool, err error)
	}

	cases := []testCase{
		{
			name: "refuse: a key whose record failed is refused after reads succeed again",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				for _, err := range h.recordN(t, testKey, 1) {
					require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
				}

				// The probe on another key succeeds and closes the breaker.
				h.clock.Advance(defaultInterval)
				exceeded, err := h.limiter.Exceeded(t.Context(), otherKey)
				require.NoError(t, err)
				require.False(t, exceeded)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)

				exceeded, err = h.limiter.Exceeded(t.Context(), otherKey)
				require.NoError(t, err)
				assert.False(t, exceeded, "a key that never failed a record was held too")
			},
		},
		{
			name: "refuse: the hold lasts until one window has passed",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				h.recordN(t, testKey, 1)
				h.clock.Advance(testWindow - time.Nanosecond)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
			},
		},
		{
			name: "refuse: the hold ends once one window has passed",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				h.recordN(t, testKey, 1)
				h.clock.Advance(testWindow)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "refuse: a record the open breaker turns away is held too",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), otherKey).Return(errDown)
				require.ErrorIs(t, h.limiter.RecordFailure(t.Context(), otherKey), ratelimit.ErrBackendUnavailable)

				// The breaker is open, so this record never reaches the backend.
				require.ErrorIs(t, h.limiter.RecordFailure(t.Context(), testKey), ratelimit.ErrBackendUnavailable)

				h.clock.Advance(defaultInterval)
				h.backend.EXPECT().Exceeded(gomock.Any(), "probe").Return(false, nil)
				_, err := h.limiter.Exceeded(t.Context(), "probe")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				refusedUnavailable(t, exceeded, err)
			},
		},
		{
			name: "refuse: held keys are swept once their window has passed",
			mode: ratelimit.UnavailableRefuse,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				h.recordN(t, testKey, 1)
				h.recordN(t, otherKey, 1)
				require.Equal(t, 2, unavailable.HeldLen(h.limiter))

				h.clock.Advance(testWindow)
			},
			assert: func(t *testing.T, h *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
				assert.Zero(t, unavailable.HeldLen(h.limiter),
					"held keys outlived their window, including one never looked up again")
			},
		},
		{
			name: "fall back: failed records reaching the limit locally exceed once reads succeed",
			mode: ratelimit.UnavailableFallBackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				for _, err := range h.recordN(t, testKey, testLimit) {
					require.NoError(t, err, "fall-back mode returned a record error")
				}
				h.clock.Advance(defaultInterval)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded, "the local count was ignored once the backend answered")
			},
		},
		{
			name: "fall back: failed records short of the limit do not exceed",
			mode: ratelimit.UnavailableFallBackToLocal,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				h.recordN(t, testKey, testLimit-1)
				h.clock.Advance(defaultInterval)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
		{
			name: "fall back: the shared count exceeds on its own",
			mode: ratelimit.UnavailableFallBackToLocal,
			arrange: func(_ *testing.T, h *harness) {
				h.backend.EXPECT().Exceeded(gomock.Any(), testKey).Return(true, nil)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.True(t, exceeded)
			},
		},
		{
			name: "allow: failed records are dropped and the check follows the backend",
			mode: ratelimit.UnavailableAllow,
			arrange: func(t *testing.T, h *harness) {
				h.writesFailReadsSucceed()
				for _, err := range h.recordN(t, testKey, testLimit) {
					require.NoError(t, err, "allow mode returned a record error")
				}
				h.clock.Advance(defaultInterval)
			},
			assert: func(t *testing.T, _ *harness, exceeded bool, err error) {
				require.NoError(t, err)
				assert.False(t, exceeded)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, tc.mode)
			tc.arrange(t, h)

			exceeded, err := h.limiter.Exceeded(t.Context(), testKey)
			tc.assert(t, h, exceeded, err)
		})
	}
}
