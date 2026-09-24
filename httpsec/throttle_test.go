package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
)

// TestSourceAddressRefusal pins which client addresses may key a rate-limit
// bucket. An address that names more than one client, or none, must be refused
// rather than pooled: a shared bucket lets any one of the clients behind it
// spend the allowance every other one depends on.
func TestSourceAddressRefusal(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		addr   string
		assert func(t *testing.T, reason string, ok bool)
	}

	accepted := func(t *testing.T, reason string, ok bool) {
		t.Helper()

		assert.True(t, ok, "the address names one client, so it may key a bucket")
		assert.Empty(t, reason, "an accepted address has nothing to report")
	}
	refused := func(want string) func(t *testing.T, reason string, ok bool) {
		return func(t *testing.T, reason string, ok bool) {
			t.Helper()

			assert.False(t, ok, "the address must never key a bucket")
			assert.Equal(t, want, reason, "the reason names which refusal an operator is seeing")
		}
	}

	cases := []testCase{
		{name: "an ordinary IPv4 peer", addr: "198.51.100.7", assert: accepted},
		{name: "an ordinary IPv6 peer", addr: "2001:db8::1", assert: accepted},
		{name: "an IPv4-mapped ordinary peer", addr: "::ffff:198.51.100.7", assert: accepted},
		{name: "empty", addr: "", assert: refused("no-client-address")},
		{
			name:   "a list, as a forwarding header yields",
			addr:   "203.0.113.9, 198.51.100.7",
			assert: refused("not-single-ip"),
		},
		{name: "a hostname", addr: "proxy.internal", assert: refused("not-single-ip")},
		{name: "host and port", addr: "198.51.100.7:51234", assert: refused("not-single-ip")},
		{name: "IPv4 unspecified", addr: "0.0.0.0", assert: refused("unspecified-address")},
		{name: "IPv6 unspecified", addr: "::", assert: refused("unspecified-address")},
		{
			// IsUnspecified alone is false for the mapped form, so an address
			// written this way would otherwise pool every non-TCP peer that
			// reports it into one bucket.
			name:   "IPv4-mapped unspecified",
			addr:   "::ffff:0.0.0.0",
			assert: refused("unspecified-address"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reason, ok := httpsec.ClassifyAddressForTest(tc.addr)
			tc.assert(t, reason, ok)
		})
	}
}

// throttleGuard mirrors the seam the throttle helpers take, so one table field
// carries either a guard over a mocked limiter or a spy that only records what
// it was handed.
type throttleGuard interface {
	Check(ctx context.Context, clientAddr string) (ratelimit.Source, error)
	RecordFailure(ctx context.Context, s ratelimit.Source)
}

// discardLogger keeps a test's own output clean: what these tests pin is the
// refusal, and the records themselves are pinned in refusallog_test.go.
func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// guardOver builds a real source guard over limiter, which is what every chain
// is wired with, so the tests exercise the same canonicalisation and the same
// refusal shapes production does.
func guardOver(t *testing.T, limiter ratelimit.Limiter) *ratelimit.SourceGuard {
	t.Helper()

	g, err := ratelimit.NewSourceGuard("login", limiter,
		ratelimit.WithSourceGuardLogger(discardLogger()))
	require.NoError(t, err)

	return g
}

func limiterAllowing(t *testing.T) *MockLimiter {
	t.Helper()

	m := NewMockLimiter(gomock.NewController(t))
	m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)

	return m
}

func limiterThrottling(t *testing.T) *MockLimiter {
	t.Helper()

	m := NewMockLimiter(gomock.NewController(t))
	m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil)

	return m
}

// errLimiterDown is the outage a limiter reports when it cannot answer at all.
var errLimiterDown = errors.New("limiter: store unreachable")

func limiterFailing(t *testing.T) *MockLimiter {
	t.Helper()

	m := NewMockLimiter(gomock.NewController(t))
	m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, errLimiterDown)

	return m
}

// limiterNeverAsked has no expectation at all, so gomock fails the test if the
// seam consults it. It is how the rows for an unattributable address assert
// that no bucket was even reached, let alone keyed.
func limiterNeverAsked(t *testing.T) *MockLimiter {
	t.Helper()

	return NewMockLimiter(gomock.NewController(t))
}

// TestSourceThrottle pins what the check before the guarded work returns. Every
// refusal must read to the client as an ordinary failed attempt, and no refusal
// may hand back a source that a failure could then be charged to.
func TestSourceThrottle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		addr    string
		limiter func(t *testing.T) *MockLimiter
		ctx     func(ctx context.Context) context.Context // nil means identity
		assert  func(t *testing.T, src ratelimit.Source, err error)
	}

	cases := []testCase{
		{
			name:    "an allowed source passes and carries its key",
			addr:    "198.51.100.7",
			limiter: limiterAllowing,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, src.Key(), "a failure must have a source to be charged to")
			},
		},
		{
			name:    "a throttled source is refused as throttled",
			addr:    "198.51.100.7",
			limiter: limiterThrottling,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
				assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a source over its limit is not a wrong credential")
				assert.Empty(t, src.Key(), "a refused check hands back no source")
			},
		},
		{
			name:    "a limiter failure refuses too",
			addr:    "198.51.100.7",
			limiter: limiterFailing,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a limiter outage must read to the client as an ordinary failed attempt")
				assert.Empty(t, src.Key())
			},
		},
		{
			name:    "an unspecified address is refused before the limiter is asked",
			addr:    "0.0.0.0",
			limiter: limiterNeverAsked,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Empty(t, src.Key(), "no bucket may be keyed on an unattributable address")
			},
		},
		{
			name:    "a list-valued address is refused before the limiter is asked",
			addr:    "203.0.113.9, 198.51.100.7",
			limiter: limiterNeverAsked,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Empty(t, src.Key())
			},
		},
		{
			name:    "an empty address is refused before the limiter is asked",
			addr:    "",
			limiter: limiterNeverAsked,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Empty(t, src.Key())
			},
		},
		{
			name: "a request that ended before the limiter answered is refused",
			addr: "198.51.100.7",
			limiter: func(t *testing.T) *MockLimiter {
				t.Helper()

				m := NewMockLimiter(gomock.NewController(t))
				m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ string) (bool, error) {
						return true, ctx.Err()
					})

				return m
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a check that could not be made never admits the request")
				assert.Empty(t, src.Key())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			src, err := httpsec.SourceThrottledForTest(ctx, guardOver(t, tc.limiter(t)),
				tc.addr, "login", nil, discardLogger(), time.Now())
			tc.assert(t, src, err)
		})
	}
}

// recordingGuard observes what the recording seam hands a guard. It stands in
// for the real guard so the promise this package makes — that a recording is
// not carrying the client's cancellation — is pinned at this package's own
// boundary, not only inside ratelimit.
type recordingGuard struct {
	recordedErr  error
	recordedCall int
}

func (g *recordingGuard) Check(context.Context, string) (ratelimit.Source, error) {
	return ratelimit.Source{}, nil
}

func (g *recordingGuard) RecordFailure(ctx context.Context, _ ratelimit.Source) {
	g.recordedCall++
	g.recordedErr = ctx.Err()
}

// TestRecordSourceFailureSurvivesDisconnect pins the guarantee behind the
// "client disconnects after guessing" scenario: the attempt was made, so it is
// counted, whether or not the client waited for the answer.
func TestRecordSourceFailureSurvivesDisconnect(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		build func(t *testing.T) (guard throttleGuard, src ratelimit.Source, verify func(t *testing.T))
	}

	cases := []testCase{
		{
			name: "the recording does not carry the client's cancellation",
			build: func(t *testing.T) (throttleGuard, ratelimit.Source, func(t *testing.T)) {
				t.Helper()

				g := &recordingGuard{}

				return g, ratelimit.Source{}, func(t *testing.T) {
					assert.Equal(t, 1, g.recordedCall, "the failure was not recorded at all")
					assert.NoError(t, g.recordedErr,
						"the recording saw the client's cancellation, so hanging up after a "+
							"wrong guess evades the limit")
				}
			},
		},
		{
			name: "the failure reaches the limiter under the source's own key",
			build: func(t *testing.T) (throttleGuard, ratelimit.Source, func(t *testing.T)) {
				t.Helper()

				ctrl := gomock.NewController(t)
				limiter := NewMockLimiter(ctrl)
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)

				g := guardOver(t, limiter)
				src, err := httpsec.SourceThrottledForTest(t.Context(), g,
					"198.51.100.7", "login", nil, discardLogger(), time.Now())
				require.NoError(t, err)
				require.NotEmpty(t, src.Key())

				limiter.EXPECT().RecordFailure(gomock.Any(), src.Key()).Times(1).
					DoAndReturn(func(ctx context.Context, _ string) error {
						assert.NoError(t, ctx.Err(),
							"the limiter was asked to count on a context that had already ended")

						return nil
					})

				return g, src, func(*testing.T) {}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			guard, src, verify := tc.build(t)

			ctx, cancel := context.WithCancel(t.Context())
			cancel() // the client hangs up before the response

			httpsec.RecordSourceFailureForTest(ctx, guard, src)
			verify(t)
		})
	}
}
