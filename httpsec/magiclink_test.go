package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
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

// TestMagicLinkRefusalStatus pins that a refused redemption, whether the token
// is wrong or the source is throttled, is answered 401 by the default error
// mapping rather than falling through to 500.
func TestMagicLinkRefusalStatus(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		redeem func(t *testing.T, h *magicLinkHarness, c *httpsec.Chain, token, nonce string) served
		assert func(t *testing.T, out served)
	}

	refused := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, magiclink.ErrInvalidLink)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
	}

	tests := []testCase{
		{
			name: "an invalid token",
			redeem: func(t *testing.T, h *magicLinkHarness, c *httpsec.Chain, _, nonce string) served {
				return h.redeem(t, c, "wrong-token", nonce)
			},
			assert: refused,
		},
		{
			name: "a throttled source",
			redeem: func(t *testing.T, h *magicLinkHarness, c *httpsec.Chain, token, nonce string) served {
				for range 10 {
					require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, "wrong-token", nonce).err,
						magiclink.ErrInvalidLink)
				}

				return h.redeemFrom(t, c, magicLinkSource, token, nonce)
			},
			assert: refused,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			c := h.chain(t)
			token, nonce := h.link(t, c)

			tc.assert(t, tc.redeem(t, h, c, token, nonce))
		})
	}
}

// TestBindingFollowsManager pins that the interceptor asks the manager whether
// links are bound, so the cookie it emits and the binding the manager checks
// can never disagree.
//
// Its cases stay subtests rather than rows: each builds its harness with its
// own binding setting and redeems through its own sequence of requests.
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
				require.ErrorIs(t, out.err, policy.ErrDenied,
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

// errMagicLinkCheckRefused is what a consumer's own refusal check refuses with.
var errMagicLinkCheckRefused = errors.New("magiclink_test: terms not accepted")

// countingRedeemer forwards to the real redemption and counts how often it was
// reached, which is how a test pins that a throttled source never gets that
// far.
type countingRedeemer struct {
	inner httpsec.Redeemer
	calls atomic.Int64
}

func (r *countingRedeemer) Redeem(
	ctx context.Context,
	token, nonce string,
	checks ...magiclink.Check,
) (magiclink.Redemption, error) {
	r.calls.Add(1)

	return r.inner.Redeem(ctx, token, nonce, checks...)
}

// switchable is a policy a test turns from denying to allowing, standing in for
// the user who goes and does whatever the policy wanted.
type switchable struct {
	allow atomic.Bool
}

func (s *switchable) engine(t *testing.T) *policy.Engine {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("magiclink_test: switchable").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, *policy.Input) policy.Decision {
			if s.allow.Load() {
				return policy.Decision{Outcome: policy.Allow}
			}

			return policy.Decision{Outcome: policy.Deny, Reason: errMagicLinkDenied}
		})

	return engineOf(t, p)
}

// TestMagicLinkSourceAccounting pins that refused redemptions of a valid link
// cost the source its allowance. Without that, one link the policy refuses is
// an unlimited supply of store reads and policy evaluations for as long as it
// lives.
//
// Not rows of TestMagicLinkRefusalStatus: its cases assert what reached the
// redeemer or the session store, which that table's rows, handed only the
// response, cannot see.
func TestMagicLinkSourceAccounting(t *testing.T) {
	t.Parallel()

	t.Run("ten policy-denied redemptions throttle the eleventh", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		counting := &countingRedeemer{inner: h.manager}
		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkRedeemer(counting))
		h.engine = denyingEngine(t, errMagicLinkDenied)

		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
				errMagicLinkDenied)
		}

		out := h.redeemFrom(t, c, magicLinkSource, token, nonce)
		assert.ErrorIs(t, out.err, magiclink.ErrInvalidLink,
			"a throttled source is refused with the uniform error")
		assert.Equal(t, int64(10), counting.calls.Load(),
			"and the eleventh never reaches the redeemer")
	})

	t.Run("an unattributable source is refused without redeeming", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		counting := &countingRedeemer{inner: h.manager}
		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkRedeemer(counting))

		out := h.redeemFrom(t, h.chain(t), "", token, nonce)

		assert.ErrorIs(t, out.err, magiclink.ErrInvalidLink)
		assert.Zero(t, counting.calls.Load(),
			"an address that names no single client keys no bucket, so it is refused outright")
	})

	t.Run("another source is unaffected", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		c := h.chain(t)

		token, nonce := h.link(t, c)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, "wrong-token", nonce).err,
				magiclink.ErrInvalidLink)
		}

		require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
			magiclink.ErrInvalidLink, "the guessing source is throttled")

		require.NoError(t, h.redeemFrom(t, c, "198.51.100.4", token, nonce).err,
			"a source that guessed at nothing still redeems")
		assert.Equal(t, 1, h.activeSessions(t))
	})
}

// TestMagicLinkCountRefusalsOptOut pins what the opt-out exempts, and — more
// importantly — what it does not.
//
// Not rows of TestMagicLinkRefusalStatus: each case rewires the harness's
// policy, options or redeemer before a run of ten redemptions, and asserts what
// the run cost.
func TestMagicLinkCountRefusalsOptOut(t *testing.T) {
	t.Parallel()

	t.Run("policy refusals stop counting", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		gate := &switchable{}
		h.engine = gate.engine(t)
		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkCountRefusals(false))

		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
				errMagicLinkDenied)
		}

		gate.allow.Store(true)

		require.NoError(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
			"the source was never counted, so it is not throttled")
	})

	t.Run("consumer check refusals stop counting too", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		var accepted atomic.Bool

		h.linkOpts = append(h.linkOpts,
			httpsec.WithMagicLinkCountRefusals(false),
			httpsec.WithMagicLinkChecks(
				func(context.Context, identity.Principal, time.Time) error {
					if accepted.Load() {
						return nil
					}

					return errMagicLinkCheckRefused
				}))

		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
				errMagicLinkCheckRefused, "the consumer's error reaches them unchanged")
		}

		accepted.Store(true)

		require.NoError(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err)
	})

	t.Run("invalid tokens still count", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkCountRefusals(false))
		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, "wrong-token", nonce).err,
				magiclink.ErrInvalidLink)
		}

		assert.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
			magiclink.ErrInvalidLink, "the source is throttled")
		assert.Zero(t, h.activeSessions(t))
	})

	t.Run("a redeemer that discarded the deny and failed otherwise still counts", func(t *testing.T) {
		t.Parallel()

		h := newMagicLinkHarness(t)
		token, nonce := h.link(t, h.chain(t))

		other := errors.New("magiclink_test: dial tcp: connection refused")

		h.engine = denyingEngine(t, errMagicLinkDenied)
		h.linkOpts = append(h.linkOpts,
			httpsec.WithMagicLinkCountRefusals(false),
			httpsec.WithMagicLinkRedeemer(redeemerFunc(func(
				ctx context.Context,
				_, _ string,
				checks ...magiclink.Check,
			) (magiclink.Redemption, error) {
				for _, check := range checks {
					_ = check(ctx, identity.Principal{ID: magicLinkUserID}, time.Time{})
				}

				return magiclink.Redemption{}, other
			})))

		c := h.chain(t)

		for range 10 {
			require.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err, other)
		}

		assert.ErrorIs(t, h.redeemFrom(t, c, magicLinkSource, token, nonce).err,
			magiclink.ErrInvalidLink,
			"the opt-out exempts exactly the refusal the check produced, nothing else")
	})
}

// TestMagicLinkThrottleLogSampling pins that a source hammering the endpoint
// cannot also flood the log, and that what is written carries none of what was
// presented.
//
// Stands alone: it sends five hundred redemptions through one chain built with
// its own logger.
func TestMagicLinkThrottleLogSampling(t *testing.T) {
	t.Parallel()

	h := newMagicLinkHarness(t)
	token, nonce := h.link(t, h.chain(t))

	logs := &capturingHandler{}

	c, err := httpsec.New(
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableMagicLink(h.manager, h.options()...),
	)
	require.NoError(t, err)

	for range 500 {
		_ = h.redeemFrom(t, c, magicLinkSource, "wrong-token", nonce)
	}

	var throttled int

	for _, r := range logs.records() {
		if r.Message == guardThrottledMsg {
			throttled++
		}

		r.Attrs(func(a slog.Attr) bool {
			value := a.Value.String()
			assert.NotContains(t, value, token, "no record carries a presented token")
			assert.NotContains(t, value, nonce, "nor a binding value")
			assert.NotContains(t, value, magicLinkKnown, "nor a submitted address")

			return true
		})

		assert.NotContains(t, r.Message, token)
		assert.NotContains(t, r.Message, magicLinkKnown)
	}

	assert.Equal(t, 1, throttled,
		"one record stands for every refusal in the window")
	assert.NotContains(t, strings.Join(messagesOf(logs.records()), "\n"), nonce)
}

// messagesOf is every message the handler captured, for the assertions that are
// about the stream rather than one record.
func messagesOf(recs []slog.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Message)
	}

	return out
}

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
				require.ErrorIs(t, out.err, policy.ErrDenied,
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
			h.linkOpts = []httpsec.MagicLinkOption{httpsec.WithMagicLinkAllowedRedirects(tc.allowed...)}

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

// TestMagicLinkRequestEndpoint pins that asking for a link tells the caller
// nothing. Every body shape — a known address, an unknown one, none at all, a
// JSON document and two that do not parse — has to produce the same status,
// the same body and a cookie with the same attributes, because any difference
// between them is a way to ask whether an address has an account.
//
// The cases are not parallel: each is compared against the first, which is the
// baseline the uniformity is measured from.
func TestMagicLinkRequestEndpoint(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		body func() (contentType string, body io.Reader)
	}

	form := func(values url.Values) func() (string, io.Reader) {
		return func() (string, io.Reader) {
			return "application/x-www-form-urlencoded", strings.NewReader(values.Encode())
		}
	}

	cases := []testCase{
		{
			name: "a known address",
			body: form(url.Values{"email": {magicLinkKnown}, "next": {"/dashboard"}}),
		},
		{name: "an unknown address", body: form(url.Values{"email": {magicLinkUnknown}})},
		{name: "no address at all", body: form(url.Values{})},
		{
			name: "a JSON body",
			body: func() (string, io.Reader) {
				return "application/json",
					strings.NewReader(`{"email":"` + magicLinkKnown + `","next":"/dashboard"}`)
			},
		},
		{
			name: "an unparsable body",
			body: func() (string, io.Reader) {
				return "application/json", strings.NewReader(`{{{not json`)
			},
		},
		{
			name: "an unparsable form body",
			body: func() (string, io.Reader) {
				return "application/x-www-form-urlencoded", strings.NewReader("%%%")
			},
		},
	}

	type answer struct {
		status int
		body   string
		cookie *http.Cookie
	}

	var baseline answer

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newMagicLinkHarness(t)

			contentType, body := tc.body()
			out := serve(t, h.chain(t),
				postBody(t.Context(), httpsec.DefaultMagicLinkRequestPath, contentType, body))

			require.NoError(t, out.err)
			assert.False(t, out.handlerRan,
				"the request endpoint is this library's own, so the application never sees it")
			assert.Equal(t, http.StatusAccepted, out.rec.Code)

			cookie := cookieNamed(out.rec, httpsec.DefaultBindingCookieName)
			require.NotNil(t, cookie, "the cookie is set whatever the outcome")

			got := answer{status: out.rec.Code, body: out.rec.Body.String(), cookie: cookie}

			if i == 0 {
				baseline = got

				return
			}

			assert.Equal(t, baseline.status, got.status)
			assert.Equal(t, baseline.body, got.body)
			assert.Equal(t, baseline.cookie.Name, got.cookie.Name)
			assert.Equal(t, baseline.cookie.Path, got.cookie.Path)
			assert.Equal(t, baseline.cookie.MaxAge, got.cookie.MaxAge)
			assert.Equal(t, baseline.cookie.HttpOnly, got.cookie.HttpOnly)
			assert.Equal(t, baseline.cookie.Secure, got.cookie.Secure)
			assert.Equal(t, baseline.cookie.SameSite, got.cookie.SameSite)
			assert.Len(t, got.cookie.Value, len(baseline.cookie.Value),
				"a decoy is the same shape as the real thing")
		})
	}
}

// TestMagicLinkRequestMethodAndPath pins that only a POST on the request path
// is a link request. Everything else is the application's.
func TestMagicLinkRequestMethodAndPath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		request func(ctx context.Context) *http.Request
	}

	cases := []testCase{
		{
			name: "a GET on the request path",
			request: func(ctx context.Context) *http.Request {
				return getFrom(ctx, httpsec.DefaultMagicLinkRequestPath, magicLinkSource)
			},
		},
		{
			name: "a POST on another path",
			request: func(ctx context.Context) *http.Request {
				return postValues(ctx, "/orders", magicLinkSource,
					url.Values{"email": {magicLinkKnown}})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)

			out := serve(t, h.chain(t), tc.request(t.Context()))

			require.NoError(t, out.err)
			assert.True(t, out.handlerRan, "the request continues to the application untouched")
			assert.Zero(t, h.sender.count(), "and no link is sent")
			assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultBindingCookieName))
		})
	}
}

// TestBindingCookieIsConstant pins the cookie's attributes and that its
// presence says nothing. A response that carries a cookie only when a link went
// out would answer the question the whole endpoint refuses to answer.
//
// Not rows of TestMagicLinkRequestEndpoint: it compares the cookies of two
// requests through one chain, attribute by attribute.
func TestBindingCookieIsConstant(t *testing.T) {
	t.Parallel()

	h := newMagicLinkHarness(t)
	c := h.chain(t)

	known := h.requestLink(t, c, magicLinkKnown)
	unknown := h.requestLink(t, c, magicLinkUnknown)

	require.NoError(t, known.err)
	require.NoError(t, unknown.err)

	a := cookieNamed(known.rec, httpsec.DefaultBindingCookieName)
	b := cookieNamed(unknown.rec, httpsec.DefaultBindingCookieName)

	require.NotNil(t, a)
	require.NotNil(t, b)

	assert.Equal(t, a.Name, b.Name)
	assert.Len(t, b.Value, len(a.Value))
	assert.NotEqual(t, a.Value, b.Value, "the decoy is random, not a fixed string")

	assert.True(t, a.HttpOnly, "script cannot read the binding")
	assert.True(t, a.Secure)
	assert.Equal(t, http.SameSiteLaxMode, a.SameSite)
	assert.Equal(t, httpsec.DefaultMagicLinkConsumePath, a.Path,
		"the cookie is scoped to the redemption endpoint")
	assert.Equal(t, int(magicLinkTTL/time.Second), a.MaxAge,
		"the lifetime comes from configuration, never from the result")
}

// errMagicLinkResponder is what a consumer's responder refuses with, so a test
// can assert the chain returned that error and not one of its own.
var errMagicLinkResponder = errors.New("magiclinkresponder_test: the client cannot be answered")

// TestMagicLinkResponder pins what writes the response to a successful
// redemption, and what happens when it will not.
func TestMagicLinkResponder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.MagicLinkOption
		assert func(t *testing.T, out served, buildErr error)
	}

	// seen is what the consumer's responder of the "consumer responder" row
	// was handed.
	var seen httpsec.MagicLinkResult

	cases := []testCase{
		{
			// A regression pin on what already shipped, not a new claim: this
			// document is a documented contract and the responder must not
			// have moved it.
			name: "the default document is unchanged",
			assert: func(t *testing.T, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				var got map[string]any
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &got))
				assert.NotEmpty(t, got["access_token"])
				assert.Equal(t, "", got["refresh_token"], "present and empty, never absent")
				assert.NotEmpty(t, got["valid_until"])
				assert.Equal(t, "/", got["next"])
			},
		},
		{
			name: "a responder error refuses the request",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(
				func(*httpsec.Exchange, httpsec.MagicLinkResult) error {
					return errMagicLinkResponder
				},
			)},
			assert: func(t *testing.T, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.ErrorIs(t, out.err, errMagicLinkResponder,
					"the consumer's error is the refusal, unchanged")
			},
		},
		{
			name: "a nil responder is a configuration error",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(nil)},
			assert: func(t *testing.T, _ served, buildErr error) {
				require.ErrorIs(t, buildErr, httpsec.ErrConfig,
					"a responder that is not there would leave the caller with no credential")
			},
		},
		{
			// A consumer's responder replaces the default entirely and is
			// handed the session the redemption opened.
			name: "consumer responder",
			opts: []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(
				func(ex *httpsec.Exchange, r httpsec.MagicLinkResult) error {
					seen = r
					ex.Writer.SetCookie(&http.Cookie{
						Name:     "session",
						Value:    r.Token,
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteLaxMode,
					})

					return nil
				})},
			assert: func(t *testing.T, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.NoError(t, out.err)

				assert.Empty(t, out.rec.Body.String(),
					"the consumer's responder replaces the default entirely")
				assert.Empty(t, out.rec.Header().Get("Cache-Control"), "a consumer responder owns its headers")
				assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"),
					"and cannot forget the header that keeps the token out of the referrer")

				require.NotNil(t, seen.Session)
				assert.Equal(t, factor.MagicLink, seen.Session.FirstFactor)
				assert.Equal(t, magicLinkUserID, seen.Session.UserID)
				assert.Equal(t, "issued-token", seen.Token)

				cookie := cookieNamed(out.rec, "session")
				require.NotNil(t, cookie, "and its own response reached the client")
				assert.Equal(t, seen.Token, cookie.Value)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			h.linkOpts = tc.opts

			c, buildErr := h.build()
			if buildErr != nil {
				tc.assert(t, served{}, buildErr)

				return
			}

			token, nonce := h.link(t, c)

			tc.assert(t, h.redeem(t, c, token, nonce), nil)
		})
	}
}

// TestMagicLinkResponderSeesResolvedTarget pins the constraint that is not
// cosmetic: a responder receives the target the allowlist resolved, never the
// one the caller submitted. Handing over the submitted value would let the
// obvious redirect in a consumer's responder reopen exactly what the allowlist
// refused.
//
// Not a row of TestMagicLinkResponder: it requests and redeems a link with a
// submitted target, where that table's rows redeem the harness's plain link.
func TestMagicLinkResponderSeesResolvedTarget(t *testing.T) {
	t.Parallel()

	var seen httpsec.MagicLinkResult

	// No WithMagicLinkAllowedRedirects, so every submitted target resolves to "/".
	h := newMagicLinkHarness(t)
	h.linkOpts = []httpsec.MagicLinkOption{httpsec.WithMagicLinkResponder(
		func(_ *httpsec.Exchange, r httpsec.MagicLinkResult) error {
			seen = r

			return nil
		})}

	c := h.chain(t)

	out := serve(t, c, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath,
		magicLinkSource, urlValues("email", magicLinkKnown, "next", "/dashboard")))
	require.NoError(t, out.err)

	nonce := cookieNamed(out.rec, httpsec.DefaultBindingCookieName).Value

	redeemed := serve(t, c, consumeWithNext(t, h.sender.lastToken(t), nonce, "/dashboard"))
	require.NoError(t, redeemed.err)

	assert.Equal(t, "/", seen.Next,
		"a responder receives the resolved target; handing it the submitted one would "+
			"reopen the redirect the allowlist refused")
}

// TestMagicLinkRedirects pins which redirect targets survive a link request.
// A target that reaches the browser is a target an attacker would like to
// choose, so a submitted one is used only when it exactly equals something the
// consumer configured, and everything else becomes "/".
//
// The target is read back off the emailed link, which is where it actually
// matters, rather than out of the interceptor's own state.
func TestMagicLinkRedirects(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name      string
		allowed   []string
		origins   []string
		submitted string
		assert    func(t *testing.T, resolved string, buildErr error)
	}

	configErrorNaming := func(entry string) func(*testing.T, string, error) {
		return func(t *testing.T, _ string, buildErr error) {
			t.Helper()

			require.Error(t, buildErr)
			require.ErrorIs(t, buildErr, httpsec.ErrConfig)
			assert.Contains(t, buildErr.Error(), entry, "the error names the entry at fault")
		}
	}

	resolvesTo := func(want string) func(*testing.T, string, error) {
		return func(t *testing.T, resolved string, buildErr error) {
			t.Helper()

			require.NoError(t, buildErr)
			assert.Equal(t, want, resolved)
		}
	}

	cases := []testCase{
		{name: "the default allowlist is empty", submitted: "/dashboard", assert: resolvesTo("/")},
		{
			name:      "an exact host-relative match",
			allowed:   []string{"/dashboard"},
			submitted: "/dashboard",
			assert:    resolvesTo("/dashboard"),
		},
		{
			name:      "a prefix is not a match",
			allowed:   []string{"/dashboard"},
			submitted: "/dashboard.evil.example",
			assert:    resolvesTo("/"),
		},
		{
			name:      "protocol-relative is not a match",
			allowed:   []string{"/dashboard"},
			submitted: "//evil.example/dashboard",
			assert:    resolvesTo("/"),
		},
		{
			name:      "a trailing slash is not a match",
			allowed:   []string{"/dashboard"},
			submitted: "/dashboard/",
			assert:    resolvesTo("/"),
		},
		{name: "an empty entry", allowed: []string{""}, assert: configErrorNaming("WithMagicLinkAllowedRedirects")},
		{
			name:    "an undeclared absolute entry",
			allowed: []string{"https://partner.example.com/landing"},
			assert:  configErrorNaming("https://partner.example.com/landing"),
		},
		{
			name:    "an entry with userinfo",
			allowed: []string{"https://a@partner.example.com/landing"},
			origins: []string{"https://partner.example.com"},
			assert:  configErrorNaming("https://a@partner.example.com/landing"),
		},
		{
			name:    "a cleartext declared origin",
			origins: []string{"http://partner.example.com"},
			assert:  configErrorNaming("http://partner.example.com"),
		},
		{
			name:    "a declared origin with a path",
			origins: []string{"https://partner.example.com/app"},
			assert:  configErrorNaming("https://partner.example.com/app"),
		},
		{
			// The 2048-byte bound belongs to the federated login's recorded
			// destination, not to every allowlist.
			name:      "an entry over 2048 bytes is not refused",
			allowed:   []string{"/" + strings.Repeat("a", 2048)},
			submitted: "/" + strings.Repeat("a", 2048),
			assert:    resolvesTo("/" + strings.Repeat("a", 2048)),
		},
		{
			name:      "a declared origin makes its entry usable",
			allowed:   []string{"https://partner.example.com/landing"},
			origins:   []string{"https://partner.example.com"},
			submitted: "https://partner.example.com/landing",
			assert:    resolvesTo("https://partner.example.com/landing"),
		},
		{
			name:      "a loopback origin over http is accepted",
			allowed:   []string{"http://localhost:3000/landing"},
			origins:   []string{"http://localhost:3000"},
			submitted: "http://localhost:3000/landing",
			assert:    resolvesTo("http://localhost:3000/landing"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMagicLinkHarness(t)
			h.linkOpts = []httpsec.MagicLinkOption{
				httpsec.WithMagicLinkAllowedRedirects(tc.allowed...),
				httpsec.WithMagicLinkAllowedOrigins(tc.origins...),
			}

			c, err := h.build()
			if err != nil {
				tc.assert(t, "", err)

				return
			}

			out := serve(t, c, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath,
				magicLinkSource, url.Values{"email": {magicLinkKnown}, "next": {tc.submitted}}))
			require.NoError(t, out.err)

			tc.assert(t, h.sender.lastNext(t), nil)
		})
	}
}
