package redisstore_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/ratelimit/redisstore"
)

func TestNewLimiter_DecoratorConfig(t *testing.T) {
	t.Parallel()

	fake := clockwork.NewFakeClock()
	logger := quietLogger()

	type testCase struct {
		name   string
		opts   []redisstore.Option
		assert func(t *testing.T, cfg unavailable.Config)
	}

	cases := []testCase{
		{
			// A Config built by hand would leave LogInterval at zero, which
			// turns allow mode's log sampling off.
			name: "starts from the decorator's defaults",
			assert: func(t *testing.T, cfg unavailable.Config) {
				def := unavailable.DefaultConfig()
				assert.Equal(t, def.Mode, cfg.Mode)
				assert.Equal(t, def.Timeout, cfg.Timeout)
				assert.Equal(t, def.ProbeInterval, cfg.ProbeInterval)
				assert.Equal(t, ratelimit.DefaultLogInterval, cfg.LogInterval)
				assert.Same(t, slog.Default(), cfg.Logger)
				assert.NotNil(t, cfg.Clock)
			},
		},
		{
			name: "options reach the decorator",
			opts: []redisstore.Option{
				redisstore.WithOnUnavailable(ratelimit.UnavailableAllow),
				redisstore.WithOperationTimeout(time.Second),
				redisstore.WithProbeInterval(3 * time.Second),
				redisstore.WithClock(fake),
				redisstore.WithLogger(logger),
			},
			assert: func(t *testing.T, cfg unavailable.Config) {
				assert.Equal(t, ratelimit.UnavailableAllow, cfg.Mode)
				assert.Equal(t, time.Second, cfg.Timeout)
				assert.Equal(t, 3*time.Second, cfg.ProbeInterval)
				assert.Equal(t, clock.Clock(fake), cfg.Clock)
				assert.Same(t, logger, cfg.Logger)
				assert.Equal(t, ratelimit.DefaultLogInterval, cfg.LogInterval)
			},
		},
		{
			name: "log interval override reaches the decorator",
			opts: []redisstore.Option{redisstore.WithUnavailableLogInterval(10 * time.Second)},
			assert: func(t *testing.T, cfg unavailable.Config) {
				assert.Equal(t, 10*time.Second, cfg.LogInterval)
			},
		},
		{
			// Zero writes every allow-mode record, for a consumer whose own
			// handler samples.
			name: "zero log interval turns sampling off",
			opts: []redisstore.Option{redisstore.WithUnavailableLogInterval(0)},
			assert: func(t *testing.T, cfg unavailable.Config) {
				assert.Zero(t, cfg.LogInterval)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, redisstore.DecoratorConfig(tc.opts...))
		})
	}
}
