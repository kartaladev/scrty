package httpsec_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// stubSessionManager and stubUserLoader stand in for the collaborators an
// Enable* option is handed. Nothing calls them: construction validation only
// asks whether they are there.
type stubSessionManager struct{}

type stubUserLoader struct{}

func TestNewRefusesWiring(t *testing.T) {
	t.Parallel()

	noop := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		return next(ex)
	})

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "an enabled built-in missing a dependency",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableTestBuiltIn(httpsec.TestBuiltInDeps{
						Users: &stubUserLoader{},
						// Sessions deliberately absent.
					}),
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c, "no usable chain may be returned alongside a configuration error")
				assert.Contains(t, err.Error(), "EnableTestBuiltIn")
				assert.Contains(t, err.Error(), "session manager")
			},
		},
		{
			name: "a nil interceptor",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(nil, httpsec.OrderBearerToken)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
			},
		},
		{
			name: "an absent rate-limiter factory",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRateLimiterFactory(nil)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithRateLimiterFactory")
				assert.Contains(t, err.Error(), "rate-limiter factory")
			},
		},
		{
			name: "a nil refusal log reporter",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogReporter(nil)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithRefusalLogReporter")
				assert.Contains(t, err.Error(), "reporter")
			},
		},
		{
			name: "a nil policy engine",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithPolicyEngine(nil)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithPolicyEngine")
				assert.Contains(t, err.Error(), "policy engine")
			},
		},
		{
			name: "a nil logger",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(nil)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithLogger")
				assert.Contains(t, err.Error(), "logger")
			},
		},
		{
			name: "an IPv6 source prefix above the address width",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithIPv6SourcePrefix(129)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithIPv6SourcePrefix")
				assert.Contains(t, err.Error(), "129")
			},
		},
		{
			name: "an IPv6 source prefix of zero",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithIPv6SourcePrefix(0)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithIPv6SourcePrefix")
			},
		},
		{
			name: "the minimum wiring succeeds",
			opts: func(_ *testing.T) []httpsec.Option { return nil },
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "a consumer who wires nothing must still get a usable chain")
				assert.NotNil(t, c)
			},
		},
		{
			name: "a nil option in the list is skipped rather than refused",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{
					nil,
					httpsec.RegisterInterceptor(noop, httpsec.OrderBearerToken),
					nil,
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "a consumer building the option slice conditionally need not filter it")
				assert.NotNil(t, c)
			},
		},
		{
			name: "a refusal log interval of zero disables sampling rather than failing",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogInterval(0)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "a disabled interval is a documented choice, not a wiring fault")
				assert.NotNil(t, c)
			},
		},
		{
			name: "every dependency present builds",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableTestBuiltIn(httpsec.TestBuiltInDeps{
						Sessions: &stubSessionManager{},
						Users:    &stubUserLoader{},
					}),
					httpsec.WithRateLimiterFactory(ratelimit.MemoryLimiterFactory()),
					httpsec.WithLogger(slog.New(slog.DiscardHandler)),
					httpsec.WithIPv6SourcePrefix(48),
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts(t)...)
			tc.assert(t, c, err)
		})
	}
}

// TestNewRejectsTypedNil covers the nil a plain == comparison misses: an
// interface that is not nil because it carries a type, but holds a nil pointer.
// It is the shape an unchecked constructor error hands over, and without the
// reflective check it panics on the first request instead of failing here.
func TestNewRejectsTypedNil(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "a dependency present but holding a typed nil",
			opts: []httpsec.Option{
				httpsec.EnableTestBuiltIn(httpsec.TestBuiltInDeps{
					Sessions: &stubSessionManager{},
					Users:    (*stubUserLoader)(nil),
				}),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "EnableTestBuiltIn")
				assert.Contains(t, err.Error(), "user loader")
			},
		},
		{
			name: "an interceptor holding a typed nil",
			opts: []httpsec.Option{
				httpsec.RegisterInterceptor((*nilInterceptor)(nil), httpsec.OrderBearerToken),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
			},
		},
		{
			name: "a rate-limiter factory holding a typed nil",
			opts: []httpsec.Option{
				httpsec.WithRateLimiterFactory((*MockLimiterFactory)(nil)),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithRateLimiterFactory")
				assert.Contains(t, err.Error(), "rate-limiter factory")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts...)
			tc.assert(t, c, err)
		})
	}
}

// TestNewDefaults pins what a consumer gets with no configuration at all, and
// that each of those defaults is replaceable by the option that names it. The
// rate-limit settings are pinned by what they do, in chain_ratelimit_test.go.
func TestNewDefaults(t *testing.T) {
	t.Parallel()

	engine, err := policy.NewEngine()
	require.NoError(t, err)

	consumerLogger := slog.New(slog.DiscardHandler)

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, s httpsec.ChainSettings)
	}

	cases := []testCase{
		{
			name: "no options: the safe defaults",
			opts: func(_ *testing.T) []httpsec.Option { return nil },
			assert: func(t *testing.T, s httpsec.ChainSettings) {
				assert.Nil(t, s.PolicyEngine, "with no engine every phase allows")
				assert.Same(t, slog.Default(), s.Logger)
				assert.Equal(t, time.Minute, s.RefusalLogInterval)
				assert.Nil(t, s.RefusalLogReporter, "the default summary reporter is supplied where the sampler is built")
			},
		},
		{
			name: "the consumer replaces the policy engine",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithPolicyEngine(engine)}
			},
			assert: func(t *testing.T, s httpsec.ChainSettings) {
				assert.Same(t, engine, s.PolicyEngine)
			},
		},
		{
			name: "the consumer replaces the logger",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(consumerLogger)}
			},
			assert: func(t *testing.T, s httpsec.ChainSettings) {
				assert.Same(t, consumerLogger, s.Logger)
			},
		},
		{
			name: "the consumer replaces the refusal log interval and reporter",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithRefusalLogInterval(5 * time.Second),
					httpsec.WithRefusalLogReporter(func(_ string, _ int) {}),
				}
			},
			assert: func(t *testing.T, s httpsec.ChainSettings) {
				assert.Equal(t, 5*time.Second, s.RefusalLogInterval)
				assert.NotNil(t, s.RefusalLogReporter)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts(t)...)
			require.NoError(t, err)
			require.NotNil(t, c)

			tc.assert(t, httpsec.Settings(c))
		})
	}
}
