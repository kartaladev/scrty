package httpsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/policy"
)

// TestRedeemerGuard pins what the endpoint does when the redemption it was
// given cannot be trusted. Redeemer is an interface, so a consumer's
// implementation may run the checks and ignore them, or never run them at all;
// the guard is what makes the requirement true either way.
func TestRedeemerGuard(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		redeemer func(h *magicLinkHarness) httpsec.Redeemer
		engine   func(t *testing.T) *policy.Engine
		assert   func(t *testing.T, h *magicLinkHarness, out served)
	}

	// discardsTheDeny runs the check it was handed, sees the refusal and
	// reports success regardless.
	discardsTheDeny := func(*magicLinkHarness) httpsec.Redeemer {
		return redeemerFunc(func(
			ctx context.Context,
			_, _ string,
			checks ...magiclink.Check,
		) (magiclink.Redemption, error) {
			p := identity.Principal{ID: magicLinkUserID, Username: magicLinkKnown}
			for _, check := range checks {
				_ = check(ctx, p, time.Time{})
			}

			return magiclink.Redemption{Principal: p}, nil
		})
	}

	// neverChecks reports success without running anything.
	neverChecks := func(*magicLinkHarness) httpsec.Redeemer {
		return redeemerFunc(func(
			context.Context,
			string, string,
			...magiclink.Check,
		) (magiclink.Redemption, error) {
			return magiclink.Redemption{
				Principal: identity.Principal{ID: magicLinkUserID, Username: magicLinkKnown},
			}, nil
		})
	}

	establishedNothing := func(t *testing.T, h *magicLinkHarness) {
		t.Helper()

		assert.Zero(t, h.activeSessions(t), "no session is established")
		assert.Zero(t, h.issued.Load(), "and no token is issued")
	}

	cases := []testCase{
		{
			// The policy denies the check and would allow afterwards, so the
			// only thing that can refuse this redemption is the guard reading
			// what the check decided. A policy that simply kept denying would
			// be refused by the login tail's own evaluation, and this row
			// would pass with the guard deleted.
			name:     "a redeemer that runs the check, sees the deny and reports success anyway",
			redeemer: discardsTheDeny,
			engine:   deniesOnceThenAllows,
			assert: func(t *testing.T, h *magicLinkHarness, out served) {
				require.ErrorIs(t, out.err, errMagicLinkDenied,
					"the policy's own reason, not a generic one")
				establishedNothing(t, h)
			},
		},
		{
			name:     "a redeemer that never runs the checks",
			redeemer: neverChecks,
			engine:   func(*testing.T) *policy.Engine { return nil },
			assert: func(t *testing.T, h *magicLinkHarness, out served) {
				require.ErrorIs(t, out.err, policy.ErrPolicyDenied,
					"a check that never ran is not an allow")
				establishedNothing(t, h)
			},
		},
		{
			name:     "the built-in redeemer with an allowing policy succeeds",
			redeemer: func(*magicLinkHarness) httpsec.Redeemer { return nil },
			engine:   func(*testing.T) *policy.Engine { return nil },
			assert: func(t *testing.T, h *magicLinkHarness, out served) {
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

			// The link is real in every case, so the only difference between
			// the rows is what the redeemer does with it.
			token, nonce := h.link(t, h.chain(t))

			if r := tc.redeemer(h); r != nil {
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkRedeemer(r))
			}

			h.engine = tc.engine(t)

			tc.assert(t, h, h.redeem(t, h.chain(t), token, nonce))
		})
	}
}

// deniesOnceThenAllows refuses the first evaluation and allows every later
// one, which is how a test isolates the guard from the login tail's own
// evaluation of the same phase.
func deniesOnceThenAllows(t *testing.T) *policy.Engine {
	t.Helper()

	var evaluated atomic.Int64

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("magiclink_test: denies once").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, *policy.Input) policy.Decision {
			if evaluated.Add(1) == 1 {
				return policy.Decision{Outcome: policy.Deny, Reason: errMagicLinkDenied}
			}

			return policy.Decision{Outcome: policy.Allow}
		})

	return engineOf(t, p)
}

// TestMagicLinkSuccess pins what a redeemed link leaves behind: a session that
// records how it was established, an access token the caller can present, and
// a response that neither leaks the token through the referrer nor invents a
// redirect the consumer never allowed.
func TestMagicLinkSuccess(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		allowed   []string
		submitted string
		next      string
	}

	cases := []testCase{
		{
			name:      "an allowed redirect target survives to the response",
			allowed:   []string{"/dashboard"},
			submitted: "/dashboard",
			next:      "/dashboard",
		},
		{
			name:      "a target nothing allowed becomes the root",
			submitted: "/dashboard",
			next:      "/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			h.linkOpts = []httpsec.MagicLinkOption{httpsec.WithAllowedRedirects(tc.allowed...)}

			c := h.chain(t)

			out := serve(t, c, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath,
				magicLinkSource, url.Values{"email": {magicLinkKnown}, "next": {tc.submitted}}))
			require.NoError(t, out.err)

			nonce := cookieNamed(out.rec, httpsec.DefaultBindingCookieName).Value
			token := h.sender.lastToken(t)

			redeemed := serve(t, c, consumeWithNext(t, token, nonce, tc.submitted))
			require.NoError(t, redeemed.err)

			assert.Equal(t, http.StatusOK, redeemed.rec.Code)
			assert.Equal(t, "no-referrer", redeemed.rec.Header().Get("Referrer-Policy"))

			var body magicLinkBody
			require.NoError(t, json.Unmarshal(redeemed.rec.Body.Bytes(), &body))
			assert.Equal(t, "issued-token", body.AccessToken, "an access token is issued")
			assert.Equal(t, tc.next, body.Next, "the response lands where the allowlist says")

			assert.Equal(t, 1, h.activeSessions(t))

			opened := h.openedSession(t)
			assert.Equal(t, factor.MagicLink, opened.FirstFactor,
				"the session records how it was established")
			assert.Equal(t, magicLinkUserID, opened.UserID)
		})
	}
}

// magicLinkBody is the success document, read back the way a client would.
type magicLinkBody struct {
	AccessToken string `json:"access_token"`
	Next        string `json:"next"`
}
