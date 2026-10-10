package unavailable_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/unavailable"
	"github.com/kartaladev/scrty/ratelimit"
)

// TestValidateConfig pins that the validation-only entry point refuses what
// Wrap refuses in a configuration, with Wrap's messages, and accepts the
// defaults.
func TestValidateConfig(t *testing.T) {
	t.Parallel()

	refused := func(want string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.Contains(t, err.Error(), want)
		}
	}

	type testCase struct {
		name   string
		cfg    func(c unavailable.Config) unavailable.Config
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name: "default",
			cfg:  func(c unavailable.Config) unavailable.Config { return c },
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:   "unknown mode",
			cfg:    func(c unavailable.Config) unavailable.Config { c.Mode = 99; return c },
			assert: refused("unknown unavailable mode 99"),
		},
		{
			name:   "zero timeout",
			cfg:    func(c unavailable.Config) unavailable.Config { c.Timeout = 0; return c },
			assert: refused("bounds nothing"),
		},
		{
			name:   "zero probe interval",
			cfg:    func(c unavailable.Config) unavailable.Config { c.ProbeInterval = 0; return c },
			assert: refused("probe interval"),
		},
		{
			name:   "nil clock",
			cfg:    func(c unavailable.Config) unavailable.Config { c.Clock = nil; return c },
			assert: refused("the clock is nil"),
		},
		{
			name:   "nil logger",
			cfg:    func(c unavailable.Config) unavailable.Config { c.Logger = nil; return c },
			assert: refused("the logger is nil"),
		},
		{
			name: "mode checked before timeout",
			cfg: func(c unavailable.Config) unavailable.Config {
				c.Mode, c.Timeout = 99, 0
				return c
			},
			assert: refused("unknown unavailable mode 99"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, unavailable.ValidateConfig(tc.cfg(unavailable.DefaultConfig())))
		})
	}
}
