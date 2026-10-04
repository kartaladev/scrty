package httpsec_test

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/ratelimit"
)

// unknownAPIKey is well formed but names no issued key, so presenting it reaches
// the store and is counted as a failure against its source.
//
//nolint:gosec // G101: a fixture naming no issued key, not a credential
const unknownAPIKey = "sk_0199a0e1-0000-7000-8000-000000000000.Z3Vlc3M"

// guardThrottledMsg is the record a source guard writes for a source over its
// limit: the one throttled-source record a refused attempt produces.
const guardThrottledMsg = "ratelimit: refusing an attempt from a source over its limit"

// presentUnknownKey sends an unknown API key from addr, which may be IPv6, and
// reports whether the attempt reached the key store; a throttled source is
// refused before it does.
func presentUnknownKey(t *testing.T, h *apiKeyHarness, c *httpsec.Chain, addr string) (reachedStore bool) {
	t.Helper()

	before := h.store.reads.Load()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/invoices", nil)
	req.RemoteAddr = net.JoinHostPort(addr, "51000")
	req.Header.Set("Authorization", httpsec.DefaultAPIKeyScheme+unknownAPIKey)

	out := serve(t, c, req)
	require.Error(t, out.err, "an unknown key never authenticates")

	return h.store.reads.Load() > before
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

// limiterAsked is one limiter a flow asks the chain's factory for.
type limiterAsked struct {
	namespace string
	limit     int
	window    time.Duration
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

				handoffs, err := oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)))
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
					limiterAsked{"recovery-user", 5, 15 * time.Minute})
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
				ph.passkeyOpts = append(ph.passkeyOpts, httpsec.WithPasswordlessLogin(
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
