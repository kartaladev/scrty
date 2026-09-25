package httpsec_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/policy"
)

// oidcAnotherSource is a source that has guessed at nothing, which is where a
// case proves a code is still redeemable after its own source was refused.
const oidcAnotherSource = "198.51.100.4"

// switchablePolicy denies every post-authentication evaluation until allow is
// set, standing in for the user who goes and does whatever the policy wanted.
// It denies with no reason, so the engine answers with policy.ErrPolicyDenied.
func switchablePolicy(t *testing.T, allow *atomic.Bool) *policy.Engine {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("oidc_test: switchable").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, *policy.Input) policy.Decision {
			if allow.Load() {
				return policy.Decision{Outcome: policy.Allow}
			}

			return policy.Decision{Outcome: policy.Deny}
		})

	return engineOf(t, p)
}

// forwardingRedeemer is a redeemer that forwards to the harness's handoff
// manager and must be reached exactly times times, which is how a case pins
// that a refused source never gets as far as redeeming.
func forwardingRedeemer(t *testing.T, h *oidcHarness, times int) httpsec.HandoffRedeemer {
	t.Helper()

	r := NewMockHandoffRedeemer(gomock.NewController(t))
	r.EXPECT().Redeem(gomock.Any(), gomock.Any(), gomock.Any()).Times(times).
		DoAndReturn(h.handoffs.Redeem)

	return r
}

// multipartHandoffBody encodes code as a multipart/form-data body carrying the
// handoff field under DefaultOIDCHandoffParam, and returns its content type
// (boundary included) and its bytes. A handoff is read from a form body only,
// and multipart/form-data is a different media type from the URL-encoded form
// readHandoff accepts, so this is the shape a form-only guess would let
// through if the check it stands on were ever dropped.
func multipartHandoffBody(t *testing.T, code string) (string, []byte) {
	t.Helper()

	var buf bytes.Buffer

	w := multipart.NewWriter(&buf)
	require.NoError(t, w.WriteField(httpsec.DefaultOIDCHandoffParam, code))
	require.NoError(t, w.Close())

	return w.FormDataContentType(), buf.Bytes()
}

// requireRedeemable proves code was not spent: a chain with no policy redeems
// it from a source that has been refused nothing.
func requireRedeemable(t *testing.T, h *oidcHarness, code string) {
	t.Helper()

	c, err := httpsec.New(httpsec.EnableOIDCLogin(h.manager, h.handoffs,
		httpsec.WithOIDCTokens(h.tokens), httpsec.WithOIDCSessions(h.sessions)))
	require.NoError(t, err)

	out := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))
	require.NoError(t, out.err, "the code is still redeemable")
}

// requireRefused asserts a refusal with err, mapped to status, that left no
// session and issued no token.
func requireRefused(t *testing.T, h *oidcHarness, out served, err error, status int) {
	t.Helper()

	require.ErrorIs(t, out.err, err)
	assert.Equal(t, status, httpsec.StatusForError(out.err))
	assert.False(t, out.handlerRan, "the application never sees the redemption")
	assert.Zero(t, h.activeSessions(t), "no session is established")
	assert.Zero(t, h.issued.Load(), "and no token is issued")
}

// TestOIDCRedeem pins the handoff redemption endpoint's refusals: where the
// code is read from, what the source guard refuses before anything is
// redeemed, that a policy decision cannot be lost by a replaced redeemer, and
// which failures count against the source.
func TestOIDCRedeem(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// opts configure the chain beside the harness's required wiring.
		opts func(t *testing.T, h *oidcHarness) []httpsec.OIDCOption

		// engine, when set, is the chain's policy engine; allow is the switch
		// a switchable policy reads.
		engine func(t *testing.T, allow *atomic.Bool) *policy.Engine

		// conveyed builds the chain with a CallbackSuccess conveyance, so with
		// redemption off.
		conveyed bool

		// act sends the requests; nil means one redemption of code from
		// oidcTestSource. It returns what the last request produced.
		act func(t *testing.T, c *httpsec.Chain, code string, allow *atomic.Bool) served

		assert func(t *testing.T, h *oidcHarness, code string, out served)
	}

	redeemFrom := func(t *testing.T, c *httpsec.Chain, source, code string) served {
		t.Helper()

		return serve(t, c, handoffRequest(t.Context(), source, code))
	}

	// tenDenialsThenOneMore redeems the code ten times against a denying
	// policy, each refused by the policy, and returns the eleventh.
	tenDenialsThenOneMore := func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
		t.Helper()

		for range 10 {
			require.ErrorIs(t, redeemFrom(t, c, oidcTestSource, code).err, policy.ErrPolicyDenied)
		}

		return redeemFrom(t, c, oidcTestSource, code)
	}

	withRedeemer := func(r func(t *testing.T, h *oidcHarness) httpsec.HandoffRedeemer, more ...httpsec.OIDCOption) func(
		t *testing.T, h *oidcHarness,
	) []httpsec.OIDCOption {
		return func(t *testing.T, h *oidcHarness) []httpsec.OIDCOption {
			return append([]httpsec.OIDCOption{httpsec.WithHandoffRedeemer(r(t, h))}, more...)
		}
	}

	forwarding := func(times int) func(t *testing.T, h *oidcHarness) httpsec.HandoffRedeemer {
		return func(t *testing.T, h *oidcHarness) httpsec.HandoffRedeemer {
			return forwardingRedeemer(t, h, times)
		}
	}

	// reportsSuccess answers for the linked user without looking at the code,
	// after running the checks it is handed when runChecks, ignoring what
	// they said.
	reportsSuccess := func(runChecks bool) func(t *testing.T, h *oidcHarness) httpsec.HandoffRedeemer {
		return func(t *testing.T, h *oidcHarness) httpsec.HandoffRedeemer {
			r := NewMockHandoffRedeemer(gomock.NewController(t))
			r.EXPECT().Redeem(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, _ string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error) {
					p := identity.Principal{ID: oidcTestUserID, Username: "ada@example.com"}

					if runChecks {
						for _, check := range checks {
							_ = check(ctx, p, time.Time{})
						}
					}

					return oidc.HandoffResult{
						Principal: p, Provider: testOIDCProvider, Issuer: h.provider.srv.URL,
					}, nil
				})

			return r
		}
	}

	cases := []testCase{
		{
			name: "a valid code in the form body is redeemed",
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan, "the endpoint is the library's own")
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
		{
			name: "a code in the query string only is refused",
			opts: withRedeemer(forwarding(0)),
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				target := httpsec.DefaultOIDCHandoffPath + "?" +
					url.Values{httpsec.DefaultOIDCHandoffParam: {code}}.Encode()

				return serve(t, c, postValues(t.Context(), target, oidcTestSource, url.Values{}))
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name: "a code in a JSON body is refused",
			opts: withRedeemer(forwarding(0)),
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				req := postBody(t.Context(), httpsec.DefaultOIDCHandoffPath, "application/json",
					strings.NewReader(`{"handoff":"`+code+`"}`))

				return serve(t, c, req)
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name: "a text/plain body naming the field is refused unparsed",
			opts: withRedeemer(forwarding(0)),
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				req := postBody(t.Context(), httpsec.DefaultOIDCHandoffPath, "text/plain",
					strings.NewReader(url.Values{httpsec.DefaultOIDCHandoffParam: {code}}.Encode()))
				req.RemoteAddr = oidcTestSource + ":51000"

				return serve(t, c, req)
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name: "a multipart body carrying the field is refused",
			opts: withRedeemer(forwarding(0)),
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				contentType, body := multipartHandoffBody(t, code)
				req := postBody(t.Context(), httpsec.DefaultOIDCHandoffPath, contentType, bytes.NewReader(body))
				req.RemoteAddr = oidcTestSource + ":51000"

				return serve(t, c, req)
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name: "a form body over the bound is refused even with a valid code",
			opts: withRedeemer(forwarding(0)),
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				values := url.Values{
					httpsec.DefaultOIDCHandoffParam: {code},
					"padding":                       {strings.Repeat("a", int(httpsec.DefaultLoginBodyLimit))},
				}

				return serve(t, c, postValues(t.Context(), httpsec.DefaultOIDCHandoffPath, oidcTestSource, values))
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name: "empty attempts count against the source like any wrong code",
			opts: func(t *testing.T, h *oidcHarness) []httpsec.OIDCOption {
				return []httpsec.OIDCOption{
					httpsec.WithHandoffRedeemer(forwardingRedeemer(t, h, 0)),
					httpsec.WithHandoffRateLimit(3, 5*time.Minute),
				}
			},
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				for range 3 {
					req := postValues(t.Context(), httpsec.DefaultOIDCHandoffPath, oidcTestSource, url.Values{})
					require.ErrorIs(t, serve(t, c, req).err, oidc.ErrInvalidHandoff)
				}

				return redeemFrom(t, c, oidcTestSource, code)
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name: "a throttled source is refused without redeeming",
			opts: func(t *testing.T, h *oidcHarness) []httpsec.OIDCOption {
				return []httpsec.OIDCOption{
					httpsec.WithHandoffRedeemer(forwardingRedeemer(t, h, 1)),
					httpsec.WithHandoffRateLimit(1, 5*time.Minute),
				}
			},
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				require.ErrorIs(t, redeemFrom(t, c, oidcTestSource, "wrong.code").err, oidc.ErrInvalidHandoff)

				return redeemFrom(t, c, oidcTestSource, code)
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name: "an unattributable source is refused without redeeming",
			opts: withRedeemer(forwarding(0)),
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				return redeemFrom(t, c, "", code)
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name:   "deny with no reason is refused with the policy-denied error and keeps the code",
			engine: switchablePolicy,
			act: func(t *testing.T, c *httpsec.Chain, code string, allow *atomic.Bool) served {
				out := redeemFrom(t, c, oidcTestSource, code)

				allow.Store(true)

				return out
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, policy.ErrPolicyDenied, http.StatusForbidden)
				requireRedeemable(t, h, code)
			},
		},
		{
			// No policy at all: the only thing that can refuse this is the
			// guard noticing the policy check never ran.
			name: "an implementation that skips the checks is refused",
			opts: withRedeemer(reportsSuccess(false)),
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				requireRefused(t, h, out, policy.ErrPolicyDenied, http.StatusForbidden)
			},
		},
		{
			// The policy denies the check and allows afterwards, so the only
			// thing that can refuse this is the guard reading what the check
			// decided; a policy that kept denying would be refused by the login
			// tail's own evaluation too.
			name: "an implementation that discards a deny is refused",
			opts: withRedeemer(reportsSuccess(true)),
			engine: func(t *testing.T, allow *atomic.Bool) *policy.Engine {
				t.Helper()

				p := NewMockPolicy(gomock.NewController(t))
				p.EXPECT().Name().Return("oidc_test: denies once").AnyTimes()
				p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
				p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
					DoAndReturn(func(context.Context, *policy.Input) policy.Decision {
						if allow.Swap(true) {
							return policy.Decision{Outcome: policy.Allow}
						}

						return policy.Decision{Outcome: policy.Deny}
					})

				return engineOf(t, p)
			},
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				requireRefused(t, h, out, policy.ErrPolicyDenied, http.StatusForbidden)
			},
		},
		{
			name:   "replaying a denied code is throttled by default",
			opts:   withRedeemer(forwarding(10)),
			engine: switchablePolicy,
			act:    tenDenialsThenOneMore,
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name:   "a consumer opts out of counting refusals",
			opts:   withRedeemer(forwarding(11), httpsec.WithHandoffCountRefusals(false)),
			engine: switchablePolicy,
			act:    tenDenialsThenOneMore,
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				requireRefused(t, h, out, policy.ErrPolicyDenied, http.StatusForbidden)
			},
		},
		{
			name: "guessing still counts with the opt-out",
			opts: withRedeemer(forwarding(10), httpsec.WithHandoffCountRefusals(false)),
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				for range 10 {
					require.ErrorIs(t, redeemFrom(t, c, oidcTestSource, "wrong.code").err, oidc.ErrInvalidHandoff)
				}

				return redeemFrom(t, c, oidcTestSource, code)
			},
			assert: func(t *testing.T, h *oidcHarness, code string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
				requireRedeemable(t, h, code)
			},
		},
		{
			name: "an outage counts against the source with the opt-out",
			opts: func(t *testing.T, _ *oidcHarness) []httpsec.OIDCOption {
				r := NewMockHandoffRedeemer(gomock.NewController(t))
				r.EXPECT().Redeem(gomock.Any(), gomock.Any(), gomock.Any()).Times(10).
					Return(oidc.HandoffResult{}, oidc.ErrInvalidHandoff)

				return []httpsec.OIDCOption{
					httpsec.WithHandoffRedeemer(r), httpsec.WithHandoffCountRefusals(false),
				}
			},
			act: func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
				for range 10 {
					require.ErrorIs(t, redeemFrom(t, c, oidcTestSource, code).err, oidc.ErrInvalidHandoff)
				}

				return redeemFrom(t, c, oidcTestSource, code)
			},
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				requireRefused(t, h, out, oidc.ErrInvalidHandoff, http.StatusUnauthorized)
			},
		},
		{
			name:     "with redemption off the handoff path passes through",
			conveyed: true,
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "the path is the application's once no code is issued")
				assert.Zero(t, h.activeSessions(t))
			},
		},
		{
			name: "a GET on the handoff path passes through",
			opts: withRedeemer(forwarding(0)),
			act: func(t *testing.T, c *httpsec.Chain, _ string, _ *atomic.Bool) served {
				return serve(t, c, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					httpsec.DefaultOIDCHandoffPath, nil))
			},
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Zero(t, h.activeSessions(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()
			code := h.issueHandoff(t, "")

			var allow atomic.Bool
			if tc.engine != nil {
				h.chainOpts = append(h.chainOpts, httpsec.WithPolicyEngine(tc.engine(t, &allow)))
			}

			var opts []httpsec.OIDCOption
			if tc.opts != nil {
				opts = tc.opts(t, h)
			}

			var c *httpsec.Chain
			if tc.conveyed {
				c = h.conveyedChain(t, func(*httpsec.Exchange, oidc.CallbackResult, string) error {
					return nil
				}, opts...)
			} else {
				c = h.chain(t, opts...)
			}

			act := tc.act
			if act == nil {
				act = func(t *testing.T, c *httpsec.Chain, code string, _ *atomic.Bool) served {
					return redeemFrom(t, c, oidcTestSource, code)
				}
			}

			tc.assert(t, h, code, act(t, c, code, &allow))

			assert.NotContains(t, h.logs.String(), code, "no log record carries the code")
			assert.NotContains(t, h.logs.String(), oidcTestIDToken, "no log record carries the ID token")
		})
	}
}

// TestOIDCRedeemRacing pins single use under contention: of eight requests
// redeeming one code at once, exactly one opens a session.
func TestOIDCRedeemRacing(t *testing.T) {
	t.Parallel()

	h := newOIDCHarness(t)
	h.issueTokens()
	code := h.issueHandoff(t, "")
	c := h.chain(t)

	const racers = 8

	var (
		start     sync.WaitGroup
		done      sync.WaitGroup
		succeeded atomic.Int64
		refused   atomic.Int64
	)

	start.Add(1)

	for i := range racers {
		done.Add(1)

		go func() {
			defer done.Done()

			start.Wait()

			// Distinct sources, so no racer is throttled by another's failure.
			source := "203.0.113." + strconv.Itoa(10+i)

			out := serve(t, c, handoffRequest(t.Context(), source, code))
			switch {
			case out.err == nil:
				succeeded.Add(1)
			case assert.ErrorIs(t, out.err, oidc.ErrInvalidHandoff):
				refused.Add(1)
			}
		}()
	}

	start.Done()
	done.Wait()

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one racer redeems")
	assert.Equal(t, int64(racers-1), refused.Load(), "every other one is refused uniformly")
	assert.Equal(t, 1, h.activeSessions(t))
}
