package signingkey_test

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/signingkey"
)

func TestNewKeyManagerValidation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []signingkey.Option
		assert func(t *testing.T, km *signingkey.KeyManager, err error)
	}

	refused := func(mentions string) func(t *testing.T, km *signingkey.KeyManager, err error) {
		return func(t *testing.T, km *signingkey.KeyManager, err error) {
			require.ErrorIs(t, err, signingkey.ErrConfig,
				"a wiring mistake is a configuration error, identifiable without matching text")
			assert.Nil(t, km, "a refused configuration yields no manager")
			assert.Contains(t, err.Error(), mentions, "the error names what is wrong")
		}
	}

	accepted := func(t *testing.T, km *signingkey.KeyManager, err error) {
		require.NoError(t, err)
		require.NotNil(t, km)
		_, _, ok := km.GetSigner(signingkey.RS256)
		assert.True(t, ok)
	}

	cases := []testCase{
		{
			name:   "defaults need no configuration",
			assert: accepted,
		},
		{
			name: "a consistent consumer configuration is accepted",
			opts: []signingkey.Option{
				signingkey.WithRotateInterval(6 * time.Hour),
				signingkey.WithReloadInterval(10 * time.Second),
				signingkey.WithLifetime(48 * time.Hour),
				signingkey.WithHousekeepingInterval(30 * time.Minute),
			},
			assert: accepted,
		},
		{
			name: "a lifetime no longer than the rotate interval",
			opts: []signingkey.Option{
				signingkey.WithLifetime(30 * time.Minute),
				signingkey.WithRotateInterval(time.Hour),
			},
			assert: refused("lifetime"),
		},
		{
			name: "a lifetime exactly the rotate interval",
			opts: []signingkey.Option{
				signingkey.WithLifetime(time.Hour),
				signingkey.WithRotateInterval(time.Hour),
			},
			assert: refused("lifetime"),
		},
		{
			name: "a reload interval no shorter than the rotate interval",
			opts: []signingkey.Option{
				signingkey.WithReloadInterval(2 * time.Hour),
				signingkey.WithRotateInterval(time.Hour),
			},
			assert: refused("reload interval"),
		},
		{
			name: "a reload interval exactly the rotate interval",
			opts: []signingkey.Option{
				signingkey.WithReloadInterval(time.Hour),
				signingkey.WithRotateInterval(time.Hour),
			},
			assert: refused("reload interval"),
		},
		{
			name:   "a zero reload interval",
			opts:   []signingkey.Option{signingkey.WithReloadInterval(0)},
			assert: refused("reload interval must be positive"),
		},
		{
			name:   "a negative lifetime",
			opts:   []signingkey.Option{signingkey.WithLifetime(-time.Second)},
			assert: refused("lifetime must be positive"),
		},
		{
			name:   "a zero rotate interval",
			opts:   []signingkey.Option{signingkey.WithRotateInterval(0)},
			assert: refused("rotate interval must be positive"),
		},
		{
			name:   "a negative housekeeping interval",
			opts:   []signingkey.Option{signingkey.WithHousekeepingInterval(-time.Minute)},
			assert: refused("housekeeping interval must be positive"),
		},
		{
			name:   "no algorithms at all",
			opts:   []signingkey.Option{signingkey.WithAlgs()},
			assert: refused("at least one algorithm"),
		},
		{
			name:   "a nil logger",
			opts:   []signingkey.Option{signingkey.WithLogger(nil)},
			assert: refused("logger must not be nil"),
		},
		{
			name:   "a nil clock",
			opts:   []signingkey.Option{signingkey.WithClock(nil)},
			assert: refused("clock must not be nil"),
		},
		{
			name:   "a typed-nil clock",
			opts:   []signingkey.Option{signingkey.WithClock((*clockwork.FakeClock)(nil))},
			assert: refused("clock must not be nil"),
		},
		{
			name:   "a nil key store",
			opts:   []signingkey.Option{signingkey.WithKeyStore(nil)},
			assert: refused("key store must not be nil"),
		},
		{
			name:   "an unsupported algorithm",
			opts:   []signingkey.Option{signingkey.WithAlgs(signingkey.RS256, "HS256")},
			assert: refused("HS256"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]signingkey.Option{
				signingkey.WithKeyStore(signingkey.NewInMemoryKeyStore()),
			}, tc.opts...)

			km, err := signingkey.NewKeyManager(t.Context(), opts...)
			tc.assert(t, km, err)
		})
	}
}
