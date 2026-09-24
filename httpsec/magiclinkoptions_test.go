package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/ratelimit"
)

// TestEnableMagicLink pins what the chain refuses to be built with. Each row is
// a configuration that would otherwise fail at the worst moment: a limiter that
// counts nothing, a cookie with no name, or two endpoints answering on one
// path, where the first registered would silently swallow the second.
func TestEnableMagicLink(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		manager func(h *magicLinkHarness) *magiclink.Manager
		opts    []httpsec.MagicLinkOption
		drop    func(h *magicLinkHarness)
		assert  func(t *testing.T, c *httpsec.Chain, err error)
	}

	configured := func(h *magicLinkHarness) *magiclink.Manager { return h.manager }

	configError := func(t *testing.T, c *httpsec.Chain, err error) {
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Nil(t, c, "a chain that cannot be configured is not half-built")
	}

	built := func(t *testing.T, c *httpsec.Chain, err error) {
		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{name: "the defaults", manager: configured, assert: built},
		{
			name:    "a consumer's paths, cookie name and limiter",
			manager: configured,
			opts: []httpsec.MagicLinkOption{
				httpsec.WithMagicLinkRequestPath("/auth/link"),
				httpsec.WithMagicLinkConsumePath("/auth/link/consume"),
				httpsec.WithBindingCookieName("binding"),
				httpsec.WithMagicLinkCountRefusals(false),
			},
			assert: built,
		},
		{
			name:    "a nil manager",
			manager: func(*magicLinkHarness) *magiclink.Manager { return nil },
			assert:  configError,
		},
		{
			name:    "a nil limiter",
			manager: configured,
			opts:    []httpsec.MagicLinkOption{httpsec.WithMagicLinkLimiter(nil)},
			assert:  configError,
		},
		{
			name:    "a limiter interface holding a nil pointer",
			manager: configured,
			opts: []httpsec.MagicLinkOption{
				httpsec.WithMagicLinkLimiter((*ratelimit.MemoryLimiter)(nil)),
			},
			assert: configError,
		},
		{
			name:    "an empty cookie name",
			manager: configured,
			opts:    []httpsec.MagicLinkOption{httpsec.WithBindingCookieName("")},
			assert:  configError,
		},
		{
			name:    "an empty request path",
			manager: configured,
			opts:    []httpsec.MagicLinkOption{httpsec.WithMagicLinkRequestPath("")},
			assert:  configError,
		},
		{
			name:    "an empty consume path",
			manager: configured,
			opts:    []httpsec.MagicLinkOption{httpsec.WithMagicLinkConsumePath("")},
			assert:  configError,
		},
		{
			// Not in the spec, but a contradictory configuration: one path
			// cannot both ask for a link and redeem one, and whichever branch
			// matched first would silently swallow the other endpoint.
			name:    "the request and consume paths collide",
			manager: configured,
			opts: []httpsec.MagicLinkOption{
				httpsec.WithMagicLinkRequestPath("/login/magic"),
				httpsec.WithMagicLinkConsumePath("/login/magic"),
			},
			assert: configError,
		},
		{
			name:    "a nil token generator",
			manager: configured,
			opts:    []httpsec.MagicLinkOption{httpsec.WithMagicLinkTokens(nil)},
			assert:  configError,
		},
		{
			name:    "a token generator interface holding a nil pointer",
			manager: configured,
			opts: []httpsec.MagicLinkOption{
				httpsec.WithMagicLinkTokens((*MockGenerator)(nil)),
			},
			assert: configError,
		},
		{
			name:    "no token generator",
			manager: configured,
			drop:    func(h *magicLinkHarness) { h.tokens = nil },
			assert:  configError,
		},
		{
			name:    "no session manager anywhere on the chain",
			manager: configured,
			drop:    func(h *magicLinkHarness) { h.sessions = nil },
			assert:  configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			h.linkOpts = tc.opts

			manager := tc.manager(h)
			if tc.drop != nil {
				tc.drop(h)
			}

			opts := h.options()
			c, err := httpsec.New(httpsec.EnableMagicLink(manager, opts...))
			tc.assert(t, c, err)
		})
	}
}
