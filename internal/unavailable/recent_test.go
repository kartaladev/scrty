package unavailable_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

// reportingBackend is a backend limiter that also answers
// ratelimit.RecentFailureReporter, built from the two generated mocks. The
// mocks' own methods are reached through their embedded fields.
type reportingBackend struct {
	*MockLimiter
	*MockRecentFailureReporter
}

// recentHarness is a wrapped limiter over a mock backend that does, or does
// not, report recent failures.
type recentHarness struct {
	*harness
	reporter *MockRecentFailureReporter
}

// newRecentHarness wraps a backend that reports recent failures when
// reporting is set, and one that does not otherwise.
func newRecentHarness(t *testing.T, mode ratelimit.UnavailableMode, reporting bool) *recentHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	h := &harness{
		backend: NewMockLimiter(ctrl),
		clock:   clockwork.NewFakeClockAt(epoch),
		logs:    &recorder{},
	}

	cfg := unavailable.DefaultConfig()
	cfg.Mode = mode
	cfg.Clock = h.clock
	cfg.Logger = slog.New(h.logs)

	rh := &recentHarness{harness: h}
	var backend ratelimit.Limiter = h.backend
	if reporting {
		rh.reporter = NewMockRecentFailureReporter(ctrl)
		backend = reportingBackend{MockLimiter: h.backend, MockRecentFailureReporter: rh.reporter}
	}

	l, err := unavailable.Wrap(backend, testNamespace, testLimit, testWindow, cfg)
	require.NoError(t, err)
	h.limiter = l

	return rh
}

// ask puts the question the guard puts to a limiter: a type assertion, then
// the call. A limiter that cannot be asked fails the case.
func (h *recentHarness) ask(t *testing.T, key string) (bool, error) {
	t.Helper()

	r, ok := h.limiter.(ratelimit.RecentFailureReporter)
	require.True(t, ok, "the wrapped limiter does not implement ratelimit.RecentFailureReporter")

	return r.HasRecentFailures(t.Context(), key)
}

// TestUnavailable_HasRecentFailures covers task 12.5's wrapper rows: the
// backend's answer is forwarded, and every answer the wrapper cannot take from
// the backend, or cannot trust, is "has failures".
func TestUnavailable_HasRecentFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		mode      ratelimit.UnavailableMode
		reporting bool
		key       string
		endedCtx  bool // ask with a context that has ended
		arrange   func(t *testing.T, h *recentHarness)
		assert    func(t *testing.T, h *recentHarness, has bool, err error)
	}

	trueWithUnavailable := func(t *testing.T, _ *recentHarness, has bool, err error) {
		t.Helper()
		require.ErrorIs(t, err, ratelimit.ErrBackendUnavailable)
		assert.True(t, has, "an answer the wrapper could not get must read as having failures")
	}

	cases := []testCase{
		{
			name: "forwards a clean answer", mode: ratelimit.UnavailableRefuse, reporting: true, key: testKey,
			arrange: func(_ *testing.T, h *recentHarness) {
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name: "forwards a failure", mode: ratelimit.UnavailableRefuse, reporting: true, key: testKey,
			arrange: func(_ *testing.T, h *recentHarness) {
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), testKey).Return(true, nil)
			},
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.NoError(t, err)
				assert.True(t, has)
			},
		},
		{
			name: "a backend without the interface cannot say", mode: ratelimit.UnavailableRefuse, reporting: false, key: testKey,
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.Error(t, err)
				assert.True(t, has)
			},
		},
		{
			name: "a backend error reads as having failures", mode: ratelimit.UnavailableRefuse, reporting: true, key: testKey,
			arrange: func(_ *testing.T, h *recentHarness) {
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), testKey).Return(false, errDown)
			},
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				trueWithUnavailable(t, nil, has, err)
				require.ErrorIs(t, err, errDown)
				assert.NotContains(t, err.Error(), errDown.Error(), "the backend's text must not reach the caller")
			},
		},
		{
			name: "a backend error opens the breaker for the checks that follow", mode: ratelimit.UnavailableRefuse, reporting: true, key: testKey,
			arrange: func(t *testing.T, h *recentHarness) {
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), otherKey).Return(false, errDown)
				_, _ = h.ask(t, otherKey)
			},
			assert: trueWithUnavailable,
		},
		{
			name: "refuse mode while unavailable", mode: ratelimit.UnavailableRefuse, reporting: true, key: testKey,
			arrange: func(t *testing.T, h *recentHarness) { h.openBreaker(t) },
			assert:  trueWithUnavailable,
		},
		{
			name: "fall-back mode while unavailable", mode: ratelimit.UnavailableFallbackToLocal, reporting: true, key: testKey,
			arrange: func(t *testing.T, h *recentHarness) { h.openBreaker(t) },
			assert:  trueWithUnavailable,
		},
		{
			name: "allow mode while unavailable", mode: ratelimit.UnavailableAllow, reporting: true, key: testKey,
			arrange: func(t *testing.T, h *recentHarness) { h.openBreaker(t) },
			assert:  trueWithUnavailable,
		},
		{
			name: "the backend is asked again once the probe interval has passed", mode: ratelimit.UnavailableRefuse, reporting: true, key: testKey,
			arrange: func(t *testing.T, h *recentHarness) {
				h.openBreaker(t)
				h.clock.Advance(defaultInterval)
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name: "an ended context is an error with true, and the backend is not asked", mode: ratelimit.UnavailableRefuse, reporting: true, key: testKey,
			endedCtx: true,
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.True(t, has)
			},
		},
		{
			name: "refuse mode: a failure it could not record counts, whatever the backend says", mode: ratelimit.UnavailableRefuse, reporting: true, key: testKey,
			arrange: func(t *testing.T, h *recentHarness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), testKey).Return(errDown)
				require.Error(t, h.limiter.RecordFailure(t.Context(), testKey))
				h.clock.Advance(defaultInterval)
			},
			assert: trueWithUnavailable,
		},
		{
			name: "refuse mode: a key whose record failed is the only one held", mode: ratelimit.UnavailableRefuse, reporting: true, key: otherKey,
			arrange: func(t *testing.T, h *recentHarness) {
				h.backend.EXPECT().RecordFailure(gomock.Any(), testKey).Return(errDown)
				require.Error(t, h.limiter.RecordFailure(t.Context(), testKey))
				h.clock.Advance(defaultInterval)
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), otherKey).Return(false, nil)
			},
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name: "fall-back mode: a failure counted locally during the outage counts once the backend is back", mode: ratelimit.UnavailableFallbackToLocal, reporting: true, key: testKey,
			arrange: func(t *testing.T, h *recentHarness) {
				h.openBreaker(t)
				require.NoError(t, h.limiter.RecordFailure(t.Context(), testKey))
				h.clock.Advance(defaultInterval)
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.NoError(t, err)
				assert.True(t, has, "the failure counted locally was lost when the backend answered clean")
			},
		},
		{
			name: "fall-back mode: a key with no local failure is the backend's to decide", mode: ratelimit.UnavailableFallbackToLocal, reporting: true, key: otherKey,
			arrange: func(t *testing.T, h *recentHarness) {
				h.openBreaker(t)
				require.NoError(t, h.limiter.RecordFailure(t.Context(), testKey))
				h.clock.Advance(defaultInterval)
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), otherKey).Return(false, nil)
			},
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
		{
			name: "fall-back mode: a full local count does not overrule a healthy backend", mode: ratelimit.UnavailableFallbackToLocal, reporting: true, key: testKey,
			arrange: func(t *testing.T, h *recentHarness) {
				local, err := ratelimit.NewMemoryLimiter(testLimit, testWindow,
					ratelimit.WithMemoryLimiterClock(h.clock),
					ratelimit.WithMemoryLimiterMaxKeys(1),
					ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
				require.NoError(t, err)
				require.NoError(t, local.RecordFailure(t.Context(), "filler"))
				unavailable.ReplaceLocal(h.limiter, local)
				h.reporter.EXPECT().HasRecentFailures(gomock.Any(), testKey).Return(false, nil)
			},
			assert: func(t *testing.T, _ *recentHarness, has bool, err error) {
				require.NoError(t, err)
				assert.False(t, has)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecentHarness(t, tc.mode, tc.reporting)
			if tc.arrange != nil {
				tc.arrange(t, h)
			}

			var (
				has bool
				err error
			)
			if tc.endedCtx {
				r, ok := h.limiter.(ratelimit.RecentFailureReporter)
				require.True(t, ok, "the wrapped limiter does not implement ratelimit.RecentFailureReporter")
				has, err = r.HasRecentFailures(cancelled(t.Context()), tc.key)
			} else {
				has, err = h.ask(t, tc.key)
			}
			tc.assert(t, h, has, err)
		})
	}
}
