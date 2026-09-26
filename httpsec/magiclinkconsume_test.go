package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// errMagicLinkDenied is what a consumer's policy refuses these redemptions
// with, so a test can tell the policy's own reason from a generic one.
var errMagicLinkDenied = errors.New("magiclink_test: must enrol in MFA")

// TestMagicLinkConsumeEndpoint pins that only a POST redeems a link. A mail
// scanner and a link previewer both fetch with GET or HEAD, and a link they
// spent is a login its owner never got to make.
func TestMagicLinkConsumeEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		request func(ctx context.Context, token string) *http.Request
	}

	unread := []testCase{
		{
			name: "a GET with a valid token in the query",
			request: func(ctx context.Context, token string) *http.Request {
				return getFrom(ctx, httpsec.DefaultMagicLinkConsumePath+
					"?token="+url.QueryEscape(token), magicLinkSource)
			},
		},
		{
			name: "a HEAD with a valid token in the query",
			request: func(ctx context.Context, token string) *http.Request {
				req := httptest.NewRequestWithContext(ctx, http.MethodHead,
					httpsec.DefaultMagicLinkConsumePath+"?token="+url.QueryEscape(token), nil)
				req.RemoteAddr = magicLinkSource + ":51000"

				return req
			},
		},
	}

	for _, tc := range unread {
		t.Run(tc.name+" spends nothing", func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			c := h.chain(t)

			token, nonce := h.link(t, c)

			out := serve(t, c, tc.request(t.Context(), token))
			require.NoError(t, out.err)
			assert.True(t, out.handlerRan, "it passes through to the application")
			assert.Zero(t, h.activeSessions(t), "and authenticates nobody")

			// The link survived, which is the point.
			later := h.redeem(t, c, token, nonce)
			require.NoError(t, later.err, "a later POST still succeeds")
			assert.Equal(t, 1, h.activeSessions(t))
		})
	}

	t.Run("a successful redemption suppresses the referrer", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		c := h.chain(t)

		token, nonce := h.link(t, c)

		out := h.redeem(t, c, token, nonce)

		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.rec.Code)
		assert.False(t, out.handlerRan, "the redemption is this library's own endpoint")
		assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"),
			"the URL the browser came from carries the token")
	})

	t.Run("a spent link cannot be spent again", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		c := h.chain(t)

		token, nonce := h.link(t, c)

		require.NoError(t, h.redeem(t, c, token, nonce).err)

		again := h.redeem(t, c, token, nonce)
		require.ErrorIs(t, again.err, magiclink.ErrInvalidLink)
	})
}

// TestBindingFollowsManager pins that the interceptor asks the manager whether
// links are bound, so the cookie it emits and the binding the manager checks
// can never disagree.
func TestBindingFollowsManager(t *testing.T) {
	t.Parallel()

	t.Run("with binding disabled no cookie is set and another device redeems", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t, magiclink.WithSameDeviceBinding(false))
		c := h.chain(t)

		out := h.requestLink(t, c, magicLinkKnown)
		require.NoError(t, out.err)
		assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultBindingCookieName),
			"a cookie for a binding nothing checks would be a lie")

		// Another device holds no cookie, and redemption does not need one.
		redeemed := h.redeem(t, c, h.sender.lastToken(t), "")
		require.NoError(t, redeemed.err)
		assert.Equal(t, 1, h.activeSessions(t))
	})

	t.Run("with binding enabled a redemption without the cookie fails", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		c := h.chain(t)

		token, nonce := h.link(t, c)
		require.NotEmpty(t, nonce)

		out := h.redeem(t, c, token, "")
		require.ErrorIs(t, out.err, magiclink.ErrInvalidLink)
		assert.Zero(t, h.activeSessions(t))

		// And the link is still there for the device that asked for it.
		require.NoError(t, h.redeem(t, c, token, nonce).err)
	})
}

// TestMagicLinkPolicyCheck pins what the post-authentication phase decides at
// redemption, and what each decision costs the holder of the link.
func TestMagicLinkPolicyCheck(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine
		opts   []httpsec.Option
		assert func(t *testing.T, h *magicLinkHarness, c *httpsec.Chain, token, nonce string, out served)
	}

	cases := []testCase{
		{
			name: "a deny refuses and leaves the link redeemable",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingEngine(t, errMagicLinkDenied)
			},
			assert: func(t *testing.T, h *magicLinkHarness, _ *httpsec.Chain, token, nonce string, out served) {
				require.ErrorIs(t, out.err, errMagicLinkDenied,
					"the policy's own reason, not a generic one")
				assert.Zero(t, h.activeSessions(t), "no session is created")
				assert.Zero(t, h.issued.Load(), "and no token is issued")

				// The link survived the refusal, so the user who enrols today
				// can still use the link they were sent.
				allowing := newMagicLinkChainFor(t, h)
				require.NoError(t, h.redeem(t, allowing, token, nonce).err)
			},
		},
		{
			name: "a deny with no reason refuses with the generic one",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingEngine(t, nil)
			},
			assert: func(t *testing.T, h *magicLinkHarness, _ *httpsec.Chain, _, _ string, out served) {
				require.ErrorIs(t, out.err, policy.ErrPolicyDenied,
					"a nil reason would read as no refusal and spend the link")
				assert.Zero(t, h.activeSessions(t))
			},
		},
		{
			name: "a challenge still spends the link and creates the session",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingEngine(t, policy.ChallengeMFA)
			},
			opts: []httpsec.Option{httpsec.EnableGateForTest(policy.ChallengeMFA)},
			assert: func(t *testing.T, h *magicLinkHarness, c *httpsec.Chain, token, nonce string, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)

				require.NotNil(t, ch.Session)
				assert.Equal(t, factor.MagicLink, ch.Session.FirstFactor)
				assert.Equal(t, session.MFAPending, ch.Session.MFA)
				assert.NotEmpty(t, ch.Token, "the credential the prompt will be answered with")

				assert.ErrorIs(t, h.redeem(t, c, token, nonce).err, magiclink.ErrInvalidLink,
					"the link was spent")
			},
		},
		{
			name:   "an allow creates the session with the magic-link first factor",
			engine: func(*testing.T) *policy.Engine { return nil },
			assert: func(t *testing.T, h *magicLinkHarness, _ *httpsec.Chain, _, _ string, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, 1, h.activeSessions(t))
				assert.Equal(t, int64(1), h.issued.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)

			// The link is asked for on a chain with no policy, so the case's
			// policy judges the redemption alone.
			requesting := h.chain(t)
			token, nonce := h.link(t, requesting)

			h.engine = tc.engine(t)
			h.chainOpts = tc.opts
			out := h.redeem(t, h.chain(t), token, nonce)

			tc.assert(t, h, requesting, token, nonce, out)
		})
	}
}

// newMagicLinkChainFor builds a second chain over the same harness with no
// policy at all, which is how a test shows that a refused link still works once
// whatever refused it stops.
func newMagicLinkChainFor(t *testing.T, h *magicLinkHarness) *httpsec.Chain {
	t.Helper()

	engine := h.engine
	h.engine = nil

	defer func() { h.engine = engine }()

	return h.chain(t)
}
