package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
)

// TestChain_IPv6Aggregate_Construction pins that an aggregate that cannot take
// effect fails at construction, naming the option, whatever order the options
// came in, and that the default is skipped when the source prefix is already
// as wide as the aggregate.
func TestChain_IPv6Aggregate_Construction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(option string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), option, "the error names the option to change")
		}
	}

	accepted := func(t *testing.T, err error) { require.NoError(t, err) }

	cases := []testCase{
		{
			name:   "aggregate no wider than the source",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(48), httpsec.WithIPv6Aggregate(56, 4)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "aggregate as wide as the source",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(56), httpsec.WithIPv6Aggregate(56, 4)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "zero multiplier",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(56, 0)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "multiplier that overflows the flow's limit",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(56, 1<<62+1)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "bits 0",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(0, 4)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "bits 128",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(128), httpsec.WithIPv6Aggregate(128, 4)},
			assert: refused("WithIPv6Aggregate"),
		},
		{
			name:   "both",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(56, 4), httpsec.WithoutIPv6Aggregate()},
			assert: refused("WithoutIPv6Aggregate"),
		},
		{
			name:   "both, the other way round",
			opts:   []httpsec.Option{httpsec.WithoutIPv6Aggregate(), httpsec.WithIPv6Aggregate(56, 4)},
			assert: refused("WithoutIPv6Aggregate"),
		},
		{
			name:   "wide source skips the default",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(48)},
			assert: accepted,
		},
		{
			name:   "order independent",
			opts:   []httpsec.Option{httpsec.WithIPv6Aggregate(48, 2), httpsec.WithIPv6SourcePrefix(64)},
			assert: accepted,
		},
		{
			name:   "defaults",
			assert: accepted,
		},
		{
			name:   "turned off beside a wide source",
			opts:   []httpsec.Option{httpsec.WithIPv6SourcePrefix(48), httpsec.WithoutIPv6Aggregate()},
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)

			_, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableAPIKey(h.keys),
			}, tc.opts...)...)
			tc.assert(t, err)
		})
	}
}

// TestChain_IPv6Aggregate_Throttles pins, through real requests, that the
// chain's source guards also count IPv6 clients by the aggregate: a client
// rotating through the /64s of one allocation is throttled once the aggregate
// is spent, by default, by a consumer's own aggregate, and not when it is
// turned off.
func TestChain_IPv6Aggregate_Throttles(t *testing.T) {
	t.Parallel()

	// failFrom spends the API-key default of 20 a minute from addr.
	failFrom := func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain, addr string) {
		t.Helper()

		for range 20 {
			require.True(t, presentUnknownKey(t, h, c, addr),
				"the source's own allowance is 20, so %s is not throttled yet", addr)
		}
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain)
	}

	cases := []testCase{
		{
			name: "default aggregate",
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				for i := 1; i <= 4; i++ {
					failFrom(t, h, c, fmt.Sprintf("2001:db8:1:%d::1", i))
				}

				assert.False(t, presentUnknownKey(t, h, c, "2001:db8:1:5::1"),
					"four times the limit is spent across the /56, so a fifth /64 is refused as throttled")
				assert.True(t, presentUnknownKey(t, h, c, "2001:db8:2:1::1"),
					"another /56 has its own aggregate")
			},
		},
		{
			name: "consumer aggregate",
			opts: []httpsec.Option{httpsec.WithIPv6Aggregate(48, 2)},
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				failFrom(t, h, c, "2001:db8:1:1::1")
				failFrom(t, h, c, "2001:db8:1:200::1")

				assert.False(t, presentUnknownKey(t, h, c, "2001:db8:1:300::1"),
					"twice the limit is spent across the /48, so a third /64, in another /56, is refused")
			},
		},
		{
			name: "aggregate turned off",
			opts: []httpsec.Option{httpsec.WithoutIPv6Aggregate()},
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				for i := 1; i <= 4; i++ {
					failFrom(t, h, c, fmt.Sprintf("2001:db8:1:%d::1", i))
				}

				assert.True(t, presentUnknownKey(t, h, c, "2001:db8:1:5::1"),
					"with no aggregate, every /64 has its own allowance")
			},
		},
		{
			name: "default prefix",
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				failFrom(t, h, c, "2001:db8:1:1::1")

				assert.True(t, presentUnknownKey(t, h, c, "2001:db8:1:2::1"),
					"one /64 spending its own allowance does not throttle its neighbour")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)

			c, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableAPIKey(h.keys),
			}, tc.opts...)...)
			require.NoError(t, err)

			tc.assert(t, h, c)
		})
	}
}

// TestChain_IPv6Aggregate_FlowLimiter pins that a flow's aggregate is sized
// from the flow's own limiter when it was given one: four times the limit that
// limiter reports, over its window, so the default aggregate never tightens a
// limit the consumer chose. A limiter that cannot report its policy gets no
// default aggregate and one warning, and an explicit aggregate over it is a
// configuration error.
func TestChain_IPv6Aggregate_FlowLimiter(t *testing.T) {
	t.Parallel()

	const noPolicyWarning = "httpsec: no IPv6 aggregate for a flow whose limiter does not report its limit and window"

	memLimiter := func(t *testing.T, limit int, window time.Duration) ratelimit.Limiter {
		t.Helper()

		l, err := ratelimit.NewMemoryLimiter(limit, window,
			ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
		require.NoError(t, err)

		return l
	}

	// noPolicy is a limiter that does not implement ratelimit.PolicyReporter.
	// Construction must not consult it.
	noPolicy := func(t *testing.T) ratelimit.Limiter {
		t.Helper()

		return NewMockLimiter(gomock.NewController(t))
	}

	// reporting is a limiter that reports a fixed policy, whatever it counts.
	// Construction must not consult it beyond Policy.
	reporting := func(t *testing.T, limit int, window time.Duration) ratelimit.Limiter {
		t.Helper()

		return fixedPolicyLimiter{Limiter: noPolicy(t), limit: limit, window: window}
	}

	// refusedFlowLimiter asserts the chain was refused as a configuration
	// error naming the api-key flow and every text in names.
	refusedFlowLimiter := func(names ...string) func(*testing.T, *apiKeyHarness, *httpsec.Chain, error, *capturingHandler) {
		return func(t *testing.T, _ *apiKeyHarness, c *httpsec.Chain, err error, _ *capturingHandler) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), "api-key", "the error names the flow")

			for _, n := range names {
				assert.Contains(t, err.Error(), n)
			}

			assert.Nil(t, c)
		}
	}

	type testCase struct {
		name string
		// factory is the chain's factory, holding the row's expectations.
		factory func(t *testing.T) *MockLimiterFactory
		// opts are the row's options beside the logger, the factory and
		// EnableAPIKey; apiKey are EnableAPIKey's own.
		opts   []httpsec.Option
		apiKey func(t *testing.T) []httpsec.APIKeyOption
		assert func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain, err error, logs *capturingHandler)
	}

	// apiKeyWarnings returns the WARN records that name the API-key flow.
	apiKeyWarnings := func(logs *capturingHandler) []slog.Record {
		var out []slog.Record
		for _, r := range logs.records() {
			if r.Level != slog.LevelWarn {
				continue
			}
			if v, ok := attrValue(r, "flow"); ok && v.String() == "api-key" {
				out = append(out, r)
			}
		}

		return out
	}

	cases := []testCase{
		{
			name: "aggregate follows a consumer limiter",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t, limiterAsked{"api-key-ipv6-aggregate", 800, time.Minute})
			},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(memLimiter(t, 200, time.Minute))}
			},
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain, err error, _ *capturingHandler) {
				require.NoError(t, err)

				for i := 1; i <= 200; i++ {
					require.True(t, presentUnknownKey(t, h, c, "2001:db8:1:1::1"),
						"attempt %d is within the consumer's 200 a minute, and the aggregate allows 800", i)
				}
			},
		},
		{
			name: "consumer limiter reports a longer window",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t, limiterAsked{"api-key-ipv6-aggregate", 120, time.Hour})
			},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(memLimiter(t, 30, time.Hour))}
			},
			assert: func(t *testing.T, _ *apiKeyHarness, _ *httpsec.Chain, err error, _ *capturingHandler) {
				require.NoError(t, err)
			},
		},
		{
			name: "consumer limiter that reports no policy",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t)
			},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(noPolicy(t))}
			},
			assert: func(t *testing.T, _ *apiKeyHarness, c *httpsec.Chain, err error, logs *capturingHandler) {
				require.NoError(t, err)
				require.NotNil(t, c)

				warnings := apiKeyWarnings(logs)
				require.Len(t, warnings, 1, "one warning at construction names the flow")
				assert.Equal(t, noPolicyWarning, warnings[0].Message)
			},
		},
		{
			name: "explicit aggregate over a limiter that reports no policy",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t)
			},
			opts: []httpsec.Option{httpsec.WithIPv6Aggregate(48, 4)},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(noPolicy(t))}
			},
			assert: func(t *testing.T, _ *apiKeyHarness, c *httpsec.Chain, err error, _ *capturingHandler) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "WithIPv6Aggregate", "the error names the aggregate option")
				assert.Contains(t, err.Error(), "api-key", "the error names the flow")
				assert.Nil(t, c)
			},
		},
		{
			name: "consumer limiter reports an unusable policy",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t)
			},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(reporting(t, 0, 0))}
			},
			assert: refusedFlowLimiter(),
		},
		{
			name: "consumer limiter reports a negative window",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t)
			},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(reporting(t, 10, -time.Second))}
			},
			assert: refusedFlowLimiter(),
		},
		{
			name: "consumer limit too large for the default aggregate",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t)
			},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(reporting(t, math.MaxInt, time.Minute))}
			},
			assert: refusedFlowLimiter("WithoutIPv6Aggregate", "WithIPv6Aggregate"),
		},
		{
			name: "explicit aggregate over a reporting limiter",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t, limiterAsked{"api-key-ipv6-aggregate", 60, time.Hour})
			},
			opts: []httpsec.Option{httpsec.WithIPv6Aggregate(48, 2)},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(reporting(t, 30, time.Hour))}
			},
			assert: func(t *testing.T, _ *apiKeyHarness, _ *httpsec.Chain, err error, _ *capturingHandler) {
				require.NoError(t, err)
			},
		},
		{
			name: "no warning when the aggregate is off",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t)
			},
			opts: []httpsec.Option{httpsec.WithoutIPv6Aggregate()},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(noPolicy(t))}
			},
			assert: func(t *testing.T, _ *apiKeyHarness, _ *httpsec.Chain, err error, logs *capturingHandler) {
				require.NoError(t, err)
				assert.Empty(t, apiKeyWarnings(logs))
			},
		},
		{
			name: "no warning when the source prefix is wide",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t)
			},
			opts: []httpsec.Option{httpsec.WithIPv6SourcePrefix(48)},
			apiKey: func(t *testing.T) []httpsec.APIKeyOption {
				return []httpsec.APIKeyOption{httpsec.WithAPIKeyLimiter(noPolicy(t))}
			},
			assert: func(t *testing.T, _ *apiKeyHarness, _ *httpsec.Chain, err error, logs *capturingHandler) {
				require.NoError(t, err)
				assert.Empty(t, apiKeyWarnings(logs))
			},
		},
		{
			name: "default flow unchanged",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t,
					limiterAsked{"api-key", 20, time.Minute},
					limiterAsked{"api-key-ipv6-aggregate", 80, time.Minute})
			},
			apiKey: func(*testing.T) []httpsec.APIKeyOption { return nil },
			assert: func(t *testing.T, _ *apiKeyHarness, _ *httpsec.Chain, err error, logs *capturingHandler) {
				require.NoError(t, err)
				assert.Empty(t, apiKeyWarnings(logs), "a flow the chain builds the limiter for is not warned about")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)
			logs := &capturingHandler{}

			c, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(slog.New(logs)),
				httpsec.WithRateLimiterFactory(tc.factory(t)),
				httpsec.EnableAPIKey(h.keys, tc.apiKey(t)...),
			}, tc.opts...)...)

			tc.assert(t, h, c, err, logs)
		})
	}
}

// fixedPolicyLimiter is a limiter that reports a fixed policy through
// ratelimit.PolicyReporter. The embedded limiter does the counting.
type fixedPolicyLimiter struct {
	ratelimit.Limiter

	limit  int
	window time.Duration
}

func (l fixedPolicyLimiter) Policy() (int, time.Duration) { return l.limit, l.window }

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
	Flush()
}

func limiterAllowing(t *testing.T) *MockLimiter {
	t.Helper()

	m := NewMockLimiter(gomock.NewController(t))
	m.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil)

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

// Flush holds nothing to report: the spy samples no refusals.
func (g *recordingGuard) Flush() {}

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

// oneFailurePerMinute is an API-key limiter a single wrong key exhausts.
func oneFailurePerMinute(t *testing.T) ratelimit.Limiter {
	t.Helper()

	l, err := ratelimit.NewMemoryLimiter(1, time.Minute,
		ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	return l
}

// TestChain_IPv6SourcePrefixReachesSourceGuards pins that the chain's IPv6
// prefix is what every guard the chain builds groups IPv6 clients by.
func TestChain_IPv6SourcePrefixReachesSourceGuards(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, secondReachedStore bool)
	}

	cases := []testCase{
		{
			name: "chain prefix groups a wider allocation",
			opts: []httpsec.Option{httpsec.WithIPv6SourcePrefix(48)},
			assert: func(t *testing.T, secondReachedStore bool) {
				assert.False(t, secondReachedStore,
					"a /64 inside the throttled /48 is the same source, so it is refused as throttled")
			},
		},
		{
			name: "default prefix keeps two /64s apart",
			assert: func(t *testing.T, secondReachedStore bool) {
				assert.True(t, secondReachedStore,
					"with the default /64, a neighbouring /64 is another source")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)

			c, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableAPIKey(h.keys, httpsec.WithAPIKeyLimiter(oneFailurePerMinute(t))),
			}, tc.opts...)...)
			require.NoError(t, err)

			require.True(t, presentUnknownKey(t, h, c, "2001:db8:1:1::1"), "the first attempt is not throttled")

			tc.assert(t, presentUnknownKey(t, h, c, "2001:db8:1:2::1"))
		})
	}
}

// TestChain_ThrottleRecordSampledPerCanonicalSource pins that addresses grouped
// into one source share one throttled-source record per window, and that a
// refused attempt is recorded once, not by both the guard and the chain.
func TestChain_ThrottleRecordSampledPerCanonicalSource(t *testing.T) {
	t.Parallel()

	logs := &capturingHandler{}
	h := newAPIKeyHarness(t)

	c, err := httpsec.New(
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableAPIKey(h.keys, httpsec.WithAPIKeyLimiter(oneFailurePerMinute(t))),
	)
	require.NoError(t, err)

	require.True(t, presentUnknownKey(t, h, c, "2001:db8:1:1::1"))

	for i := range 50 {
		require.False(t, presentUnknownKey(t, h, c, fmt.Sprintf("2001:db8:1:1::%x", i+2)),
			"every address in the throttled /64 is refused")
	}

	var throttled int

	for _, r := range logs.records() {
		if r.Message == guardThrottledMsg {
			throttled++
		}
	}

	assert.Equal(t, 1, throttled, "one throttled-source record per flow and canonical source per window")
}

// factoryExpecting is a consumer factory that must be asked for exactly the
// limiters in asked, once each, and for nothing else; each is built in memory.
func factoryExpecting(t *testing.T, asked ...limiterAsked) *MockLimiterFactory {
	t.Helper()

	f := NewMockLimiterFactory(gomock.NewController(t))
	memory := ratelimit.MemoryLimiterFactory(
		ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))

	for _, a := range asked {
		f.EXPECT().NewLimiter(a.namespace, a.limit, a.window).
			DoAndReturn(memory.NewLimiter).Times(1)
	}

	return f
}

// errFactoryRefused is what a consumer's factory refuses a namespace with.
var errFactoryRefused = errors.New("factory: backend refused the namespace")

// TestChain_RateLimiterFactoryReachesFlows pins that the chain's factory builds
// the limiter of every flow the chain builds one for, each with that flow's own
// namespace, limit and window, unless the flow was given its own limiter, and
// that a factory refusing a namespace fails construction.
func TestChain_RateLimiterFactoryReachesFlows(t *testing.T) {
	t.Parallel()

	discard := httpsec.WithLogger(slog.New(slog.DiscardHandler))

	type testCase struct {
		name string
		// factory is the consumer's factory, holding the row's expectations:
		// gomock fails the row on any call it did not expect.
		factory func(t *testing.T) *MockLimiterFactory
		// opts builds the chain's options around the factory option.
		opts   func(t *testing.T, factory httpsec.Option) []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()
		require.NoError(t, err)
		require.NotNil(t, c)
	}

	cases := []testCase{
		{
			name: "api key flow",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t,
					limiterAsked{"api-key", 20, time.Minute},
					limiterAsked{"api-key-ipv6-aggregate", 80, time.Minute})
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				return []httpsec.Option{discard, factory, httpsec.EnableAPIKey(newAPIKeyHarness(t).keys)}
			},
			assert: built,
		},
		{
			name: "magic link flow",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t,
					limiterAsked{"magic-link-redeem", 10, 15 * time.Minute},
					limiterAsked{"magic-link-redeem-ipv6-aggregate", 40, 15 * time.Minute})
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				lh := newMagicLinkHarness(t)

				return []httpsec.Option{discard, factory, httpsec.EnableMagicLink(lh.manager, lh.options()...)}
			},
			assert: built,
		},
		{
			name: "oidc handoff flow",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t,
					limiterAsked{"oidc.handoff", 10, 5 * time.Minute},
					limiterAsked{"oidc.handoff-ipv6-aggregate", 40, 5 * time.Minute})
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				h := newOIDCHarness(t)

				handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)))
				require.NoError(t, err)

				return []httpsec.Option{discard, factory, httpsec.EnableOIDCLogin(h.manager, handoffs,
					httpsec.WithOIDCTokens(h.tokens), httpsec.WithOIDCSessions(h.sessions))}
			},
			assert: built,
		},
		{
			name: "account recovery flow, including the per-user limiter the chain builds",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t,
					limiterAsked{"account-recovery", 10, 15 * time.Minute},
					limiterAsked{"account-recovery-ipv6-aggregate", 40, 15 * time.Minute},
					limiterAsked{"account-recovery-start", 10, time.Hour},
					limiterAsked{"account-recovery-start-ipv6-aggregate", 40, time.Hour},
					limiterAsked{"recovery-user", 5, 15 * time.Minute},
					// The harness enables form login, whose password-login guard
					// comes from the same factory.
					limiterAsked{"password-login", 50, 15 * time.Minute},
					limiterAsked{"password-login-ipv6-aggregate", 200, 15 * time.Minute})
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				rh := newRecoveryHarness(t)
				rh.chainOpts = append(rh.chainOpts, discard, factory)

				return rh.options(t)
			},
			assert: built,
		},
		{
			// The second factor guards by user, not by source, so it has no
			// aggregate; only the passwordless begin flow does.
			name: "second factor, enrolment and passwordless flows",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t,
					limiterAsked{"mfa-verify", 5, 15 * time.Minute},
					limiterAsked{"mfa-enrol-begin", 5, time.Hour},
					limiterAsked{"mfa-enrol-confirm", 5, 15 * time.Minute},
					limiterAsked{"passkey-login", 30, 15 * time.Minute},
					limiterAsked{"passkey-login-ipv6-aggregate", 120, 15 * time.Minute})
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				ph := newPasskeyHarness(t)
				ph.withPasswordless()
				ph.extra = append(ph.extra, discard, factory)

				return ph.chainOptions(t, nil)
			},
			assert: built,
		},
		{
			name: "flow option wins over the factory",
			// Only the aggregates are asked for: a flow given its own limiter
			// never asks the factory for it, but its IPv6 aggregate has no
			// option of its own, so the chain's factory still builds that,
			// sized from the policy the flow's own limiter reports (one a
			// minute, so four a minute) rather than from the flow's default.
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t,
					limiterAsked{"api-key-ipv6-aggregate", 4, time.Minute},
					limiterAsked{"passkey-login-ipv6-aggregate", 4, time.Minute})
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				ph := newPasskeyHarness(t)
				ph.pkOpts = append(ph.pkOpts, passkey.WithOptionalRecoveryCodes())
				ph.mfaOpts = append(ph.mfaOpts, httpsec.WithMFAVerifyLimiter(oneFailurePerMinute(t)))
				ph.enrolOpts = append(ph.enrolOpts,
					httpsec.WithEnrolmentBeginLimiter(oneFailurePerMinute(t)),
					httpsec.WithEnrolmentConfirmLimiter(oneFailurePerMinute(t)))
				ph.passkeyOpts = append(ph.passkeyOpts, httpsec.WithPasskeyPasswordlessLogin(
					httpsec.PasswordlessTokens(ph.tokens), httpsec.PasswordlessLimiter(oneFailurePerMinute(t))))
				ph.extra = append(ph.extra, discard, factory,
					httpsec.EnableAPIKey(newAPIKeyHarness(t).keys, httpsec.WithAPIKeyLimiter(oneFailurePerMinute(t))))

				return ph.chainOptions(t, nil)
			},
			assert: built,
		},
		{
			name: "a factory refusing the aggregate namespace fails construction",
			factory: func(t *testing.T) *MockLimiterFactory {
				f := NewMockLimiterFactory(gomock.NewController(t))
				memory := ratelimit.MemoryLimiterFactory(
					ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
				f.EXPECT().NewLimiter("api-key", 20, time.Minute).DoAndReturn(memory.NewLimiter)
				f.EXPECT().NewLimiter("api-key-ipv6-aggregate", 80, time.Minute).Return(nil, errFactoryRefused)

				return f
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				return []httpsec.Option{discard, factory, httpsec.EnableAPIKey(newAPIKeyHarness(t).keys)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableAPIKey", "the error names the option to change")
				assert.Contains(t, err.Error(), `"api-key-ipv6-aggregate"`, "the error names the namespace")
				assert.Contains(t, err.Error(), errFactoryRefused.Error(), "the error carries the factory's reason")
				assert.Nil(t, c)
			},
		},
		{
			name: "no aggregate is asked for when the chain turns it off",
			factory: func(t *testing.T) *MockLimiterFactory {
				return factoryExpecting(t, limiterAsked{"api-key", 20, time.Minute})
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				return []httpsec.Option{discard, factory, httpsec.WithoutIPv6Aggregate(),
					httpsec.EnableAPIKey(newAPIKeyHarness(t).keys)}
			},
			assert: built,
		},
		{
			name: "a factory refusing a namespace fails construction",
			factory: func(t *testing.T) *MockLimiterFactory {
				f := NewMockLimiterFactory(gomock.NewController(t))
				f.EXPECT().NewLimiter("api-key", 20, time.Minute).Return(nil, errFactoryRefused)

				return f
			},
			opts: func(t *testing.T, factory httpsec.Option) []httpsec.Option {
				return []httpsec.Option{discard, factory, httpsec.EnableAPIKey(newAPIKeyHarness(t).keys)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Contains(t, err.Error(), "EnableAPIKey", "the error names the option to change")
				assert.Contains(t, err.Error(), `"api-key"`, "the error names the namespace")
				assert.Contains(t, err.Error(), errFactoryRefused.Error(), "the error carries the factory's reason")
				assert.Nil(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts(t, httpsec.WithRateLimiterFactory(tc.factory(t)))...)
			tc.assert(t, c, err)
		})
	}
}

// TestChain_RateLimiterFactoryCountsFailures pins that the limiter the factory
// built is the one a flow's failures are counted through, and that without a
// factory each flow keeps its own in-memory default.
func TestChain_RateLimiterFactoryCountsFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain)
	}

	cases := []testCase{
		{
			name: "chain factory reaches a flow",
			opts: func(t *testing.T) []httpsec.Option {
				ctrl := gomock.NewController(t)

				// The source is checked, and the wrong key recorded, through
				// the limiter the factory built: once each, under the flow.
				l := NewMockLimiter(ctrl)
				l.EXPECT().Exceeded(gomock.Any(), "api-key:"+apiKeySource).Return(false, nil).Times(1)
				l.EXPECT().RecordFailure(gomock.Any(), "api-key:"+apiKeySource).Return(nil).Times(1)

				f := NewMockLimiterFactory(ctrl)
				f.EXPECT().NewLimiter("api-key", 20, time.Minute).Return(l, nil).Times(1)

				// The chain's IPv6 aggregate is built from the same factory;
				// apiKeySource is not IPv6, so it is never consulted.
				memory := ratelimit.MemoryLimiterFactory(
					ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
				f.EXPECT().NewLimiter("api-key-ipv6-aggregate", 80, time.Minute).
					DoAndReturn(memory.NewLimiter).Times(1)

				return []httpsec.Option{httpsec.WithRateLimiterFactory(f)}
			},
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				assert.True(t, presentUnknownKey(t, h, c, apiKeySource))
			},
		},
		{
			name: "default unchanged",
			opts: func(*testing.T) []httpsec.Option { return nil },
			assert: func(t *testing.T, h *apiKeyHarness, c *httpsec.Chain) {
				for range 20 {
					require.True(t, presentUnknownKey(t, h, c, apiKeySource),
						"the in-memory default allows 20 failures a minute")
				}

				assert.False(t, presentUnknownKey(t, h, c, apiKeySource),
					"the 21st attempt within the minute is throttled")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAPIKeyHarness(t)

			c, err := httpsec.New(append(tc.opts(t),
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableAPIKey(h.keys))...)
			require.NoError(t, err)

			tc.assert(t, h, c)
		})
	}
}
