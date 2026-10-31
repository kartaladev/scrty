package httpsec_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// oidcAnotherSource is a source that has guessed at nothing, which is where a
// case proves a code is still redeemable after its own source was refused.
const oidcAnotherSource = "198.51.100.4"

// switchablePolicy denies every post-authentication evaluation until allow is
// set, standing in for the user who goes and does whatever the policy wanted.
// It denies with no reason, so the engine answers with policy.ErrDenied.
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

	c, err := httpsec.New(httpsec.EnableOIDCLogin(httpsec.OIDCDeps{RelyingParty: h.manager, Handoff: h.handoffs},
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
			require.ErrorIs(t, redeemFrom(t, c, oidcTestSource, code).err, policy.ErrDenied)
		}

		return redeemFrom(t, c, oidcTestSource, code)
	}

	withRedeemer := func(r func(t *testing.T, h *oidcHarness) httpsec.HandoffRedeemer, more ...httpsec.OIDCOption) func(
		t *testing.T, h *oidcHarness,
	) []httpsec.OIDCOption {
		return func(t *testing.T, h *oidcHarness) []httpsec.OIDCOption {
			return append([]httpsec.OIDCOption{httpsec.WithOIDCHandoffRedeemer(r(t, h))}, more...)
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
		return func(t *testing.T, _ *oidcHarness) httpsec.HandoffRedeemer {
			r := NewMockHandoffRedeemer(gomock.NewController(t))
			r.EXPECT().Redeem(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, _ string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error) {
					p := identity.Principal{ID: oidcTestUserID, Username: "ada@example.com"}

					if runChecks {
						for _, check := range checks {
							_ = check(ctx, oidc.RedeemCandidate{Principal: p})
						}
					}

					return oidc.HandoffResult{Principal: p}, nil
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
					httpsec.WithOIDCHandoffRedeemer(forwardingRedeemer(t, h, 0)),
					httpsec.WithOIDCHandoffRateLimit(3, 5*time.Minute),
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
					httpsec.WithOIDCHandoffRedeemer(forwardingRedeemer(t, h, 1)),
					httpsec.WithOIDCHandoffRateLimit(1, 5*time.Minute),
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
				requireRefused(t, h, out, policy.ErrDenied, http.StatusForbidden)
				requireRedeemable(t, h, code)
			},
		},
		{
			// No policy at all: the only thing that can refuse this is the
			// guard noticing the policy check never ran.
			name: "an implementation that skips the checks is refused",
			opts: withRedeemer(reportsSuccess(false)),
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				requireRefused(t, h, out, policy.ErrDenied, http.StatusForbidden)
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
				requireRefused(t, h, out, policy.ErrDenied, http.StatusForbidden)
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
			opts:   withRedeemer(forwarding(11), httpsec.WithOIDCHandoffCountRefusals(false)),
			engine: switchablePolicy,
			act:    tenDenialsThenOneMore,
			assert: func(t *testing.T, h *oidcHarness, _ string, out served) {
				requireRefused(t, h, out, policy.ErrDenied, http.StatusForbidden)
			},
		},
		{
			name: "guessing still counts with the opt-out",
			opts: withRedeemer(forwarding(10), httpsec.WithOIDCHandoffCountRefusals(false)),
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
					httpsec.WithOIDCHandoffRedeemer(r), httpsec.WithOIDCHandoffCountRefusals(false),
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
//
// Not a row of TestOIDCRedeem: it sends its eight redemptions concurrently.
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

// The values the assurance cases sign in with.
const (
	assuranceACR      = "urn:corp:loa:2"
	assuranceGoodCode = "246810"
	assuranceUsername = "ada@example.com"
)

var (
	errAssuranceLookupDown    = errors.New("oidc_assurance_test: the enrolment store is down")
	errAssuranceEvaluatorDown = errors.New("oidc_assurance_test: the assurance evaluator is down")
)

// assuranceConfig is how a case wires its assurance deployment beside the
// defaults: the real OIDC manager matching its default configuration, the
// requirement policy in its default mode, and the library's own redeemer.
type assuranceConfig struct {
	// managerOpts configure the OIDC manager; d is the deployment being built,
	// whose switches an option may read.
	managerOpts func(t *testing.T, d *assuranceDeployment) []oidc.Option

	// requirementOpts configure the requirement policy beside the
	// requirement for all and the assurance source.
	requirementOpts []policy.MFARequirementOption

	// oidcOpts configure OIDC login beside the harness's required wiring.
	oidcOpts func(t *testing.T, d *assuranceDeployment) []httpsec.OIDCOption
}

// assuranceDeployment is a federated-login chain wired the way a consumer
// wires provider assurance: the real MFA policies over one second-factor
// method, MFA required for all, the OIDC manager as the assurance source,
// bearer tokens and the verify endpoint, in one chain.
//
// The source is the manager held in current, behind a generated double that
// delegates to it, so a case can tighten the provider's configuration or
// remove the provider while a session is live, as an operator would by
// rebuilding the manager.
type assuranceDeployment struct {
	h       *oidcHarness
	current atomic.Pointer[oidc.RelyingParty]

	// enrolled is whether the user is enrolled on the method, and lookupDown
	// fails the method's enrolment lookup.
	enrolled   atomic.Bool
	lookupDown atomic.Bool

	// evaluatorDown fails the consumer evaluator a case wires.
	evaluatorDown atomic.Bool

	chain *httpsec.Chain
}

func newAssuranceDeployment(t *testing.T, cfg assuranceConfig) *assuranceDeployment {
	t.Helper()

	d := &assuranceDeployment{}

	var managerOpts []oidc.Option
	if cfg.managerOpts != nil {
		managerOpts = cfg.managerOpts(t, d)
	}

	d.h = newOIDCHarness(t, managerOpts...)
	d.current.Store(d.h.manager)

	ctrl := gomock.NewController(t)

	src := NewMockFederatedAssuranceSource(ctrl)
	src.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, user identity.UserID, ev policy.FederatedAssurance) (bool, error) {
			return d.current.Load().MeetsAssurance(ctx, user, ev)
		})

	method := NewMockMethod(ctrl)
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (bool, error) {
			if d.lookupDown.Load() {
				return false, errAssuranceLookupDown
			}

			return d.enrolled.Load(), nil
		})
	method.EXPECT().Verify(gomock.Any(), oidcTestUserID, gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, _ identity.UserID, response []byte) error {
			if string(response) != assuranceGoodCode {
				return errors.New("oidc_assurance_test: wrong code")
			}

			return nil
		})

	lookups, err := mfa.LookupsFor(method)
	require.NoError(t, err)

	challenge, err := policy.NewMFA(lookups)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirement(nil, lookups, append([]policy.MFARequirementOption{
		policy.WithMFARequiredForAll(),
		policy.WithFederatedAssuranceSource(src),
	}, cfg.requirementOpts...)...)
	require.NoError(t, err)

	// Tokens name the session they were issued for, and verify back to it,
	// as a real generator does through the jti.
	d.h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			d.h.issued.Add(1)

			return mfaTokenFor(id), nil
		})
	d.h.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(assuranceUsername, id), nil
		})

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUsername(gomock.Any(), assuranceUsername).AnyTimes().
		Return(&identity.Details{ID: oidcTestUserID, Username: assuranceUsername, Active: true}, nil)

	d.h.chainOpts = []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: d.h.tokens, Sessions: d.h.sessions, Users: users,
		}),
		httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(d.h.tokens)),
	}

	var oidcOpts []httpsec.OIDCOption
	if cfg.oidcOpts != nil {
		oidcOpts = cfg.oidcOpts(t, d)
	}

	d.chain = d.h.chain(t, oidcOpts...)

	return d
}

// issue issues a handoff code for the linked user, as a genuine callback
// whose verified ID token asserted amr and acr would.
func (d *assuranceDeployment) issue(t *testing.T, amr []string, acr string) string {
	t.Helper()

	res := d.h.handoffResult()
	res.AMR, res.ACR = amr, acr

	return d.h.issueHandoffFor(t, res)
}

// redeem posts code to the redemption endpoint from source.
func (d *assuranceDeployment) redeem(t *testing.T, source, code string) served {
	t.Helper()

	return serve(t, d.chain, handoffRequest(t.Context(), source, code))
}

// invoices requests a protected route with credential.
func (d *assuranceDeployment) invoices(t *testing.T, credential string) served {
	t.Helper()

	req := getFrom(t.Context(), "/invoices", oidcTestSource)
	req.Header.Set("Authorization", "Bearer "+credential)

	return serve(t, d.chain, req)
}

// verify answers the MFA challenge of credential's session with the good
// code, and returns the credential the verification rotated to.
func (d *assuranceDeployment) verify(t *testing.T, credential string) string {
	t.Helper()

	req := postValues(t.Context(), testMFAVerifyPath, oidcTestSource, url.Values{"code": {assuranceGoodCode}})
	req.Header.Set("Authorization", "Bearer "+credential)

	out := serve(t, d.chain, req)
	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	rotated := accessTokenFrom(t, out)
	require.NotEqual(t, credential, rotated)

	return rotated
}

// sessionOf loads the session credential was issued for.
func (d *assuranceDeployment) sessionOf(t *testing.T, credential string) *session.Session {
	t.Helper()

	id, ok := strings.CutPrefix(credential, mfaTokenPrefix)
	require.True(t, ok, "a credential this deployment issued")

	s, err := d.h.sessions.Load(t.Context(), id)
	require.NoError(t, err)

	return s
}

// tighten replaces the manager the source matches against with one whose
// provider accepts only amr, as an operator tightening its configuration
// would.
func (d *assuranceDeployment) tighten(t *testing.T, amr ...string) {
	t.Helper()

	d.current.Store(d.h.managerWith(t, NewMockIdentityBroker(gomock.NewController(t)), nil,
		oidc.WithProviderAssurance(testOIDCProvider, oidc.Assurance{AcceptedAMR: amr})))
}

// removeProvider replaces the manager the source matches against with one
// that no longer registers the provider the sessions came from.
func (d *assuranceDeployment) removeProvider(t *testing.T) {
	t.Helper()

	d.current.Store(d.h.managerWith(t, NewMockIdentityBroker(gomock.NewController(t)),
		func(p *oidc.Provider) { p.Name = "elsewhere" }))
}

// loggedIn asserts out is a redemption that completed without a challenge,
// and returns the credential it issued.
func loggedIn(t *testing.T, out served) string {
	t.Helper()

	require.NoError(t, out.err)

	var doc struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken)

	return doc.AccessToken
}

// TestOIDCRedeemAssurance pins what a handoff redemption does with the
// assurance the code's record carries: it reaches the policy as evidence the
// library minted, is recorded on the session without marking the second
// factor, and cannot be widened by the request or by a replaced redeemer.
//
// Its own table: its rows run over an assurance deployment, with the real MFA
// policies and OIDC manager, not over TestOIDCRedeem's harness.
func TestOIDCRedeemAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		cfg  assuranceConfig

		// amr and acr are what the code's record carries.
		amr []string
		acr string

		// enrolled is whether the user is enrolled on the method.
		enrolled bool

		// act redeems the code; nil means one redemption from oidcTestSource.
		act func(t *testing.T, d *assuranceDeployment, code string) served

		assert func(t *testing.T, d *assuranceDeployment, code string, out served)
	}

	// changing is a consumer redeemer that redeems through the library and
	// then changes the result's assurance by edit.
	changing := func(edit func(res *oidc.HandoffResult)) func(t *testing.T, d *assuranceDeployment) []httpsec.OIDCOption {
		return func(t *testing.T, d *assuranceDeployment) []httpsec.OIDCOption {
			r := NewMockHandoffRedeemer(gomock.NewController(t))
			r.EXPECT().Redeem(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(ctx context.Context, code string, checks ...oidc.RedeemCheck) (oidc.HandoffResult, error) {
					res, err := d.h.handoffs.Redeem(ctx, code, checks...)
					if err == nil {
						edit(&res)
					}

					return res, err
				})

			return []httpsec.OIDCOption{httpsec.WithOIDCHandoffRedeemer(r)}
		}
	}

	// refusedByGuard is a redemption the endpoint refused after a redeemer
	// reported success: the policy-denied error, and nothing created.
	refusedByGuard := func(t *testing.T, d *assuranceDeployment, _ string, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, policy.ErrDenied)
		assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.Zero(t, d.h.activeSessions(t), "no session is created")
		assert.Zero(t, d.h.issued.Load(), "and no token is issued")
	}

	cases := []testCase{
		{
			name: "met assurance completes a required, unenrolled user's login without a challenge",
			amr:  []string{"mfa"},
			acr:  assuranceACR,
			assert: func(t *testing.T, d *assuranceDeployment, _ string, out served) {
				credential := loggedIn(t, out)

				s := d.sessionOf(t, credential)
				assert.Equal(t, factor.OIDC, s.FirstFactor)
				assert.Equal(t, []string{"mfa"}, s.FederatedAMR, "the session carries the asserted amr")
				assert.Equal(t, assuranceACR, s.FederatedACR, "and the asserted acr")
				assert.Equal(t, session.MFANone, s.MFA, "provider assurance never marks the second factor")
				assert.False(t, s.MFAAtFirstFactor, "nor the met-at-first-factor marker")
			},
		},
		{
			name:     "unmet assurance for an enrolled user redeems into the MFA challenge",
			enrolled: true,
			assert: func(t *testing.T, d *assuranceDeployment, code string, out served) {
				ch := challengedFor(t, out, policy.ChallengeMFA)
				require.NotEmpty(t, ch)

				s := d.sessionOf(t, ch)
				assert.Equal(t, session.MFAPending, s.MFA)
				assert.Empty(t, s.FederatedAMR)
				assert.Equal(t, 1, d.h.activeSessions(t))

				again := d.redeem(t, oidcAnotherSource, code)
				require.ErrorIs(t, again.err, oidc.ErrInvalidHandoff, "the code was consumed")
			},
		},
		{
			name:     "a policy lookup failure does not spend the code",
			enrolled: true,
			act: func(t *testing.T, d *assuranceDeployment, code string) served {
				d.lookupDown.Store(true)

				first := d.redeem(t, oidcTestSource, code)
				require.ErrorIs(t, first.err, errAssuranceLookupDown)
				require.Zero(t, d.h.activeSessions(t), "the refused redemption creates no session")

				d.lookupDown.Store(false)

				return d.redeem(t, oidcAnotherSource, code)
			},
			assert: func(t *testing.T, d *assuranceDeployment, _ string, out served) {
				challengedFor(t, out, policy.ChallengeMFA)
				assert.Equal(t, 1, d.h.activeSessions(t), "the second redemption completes")
			},
		},
		{
			name: "assurance presented with the redemption is ignored",
			act: func(t *testing.T, d *assuranceDeployment, code string) served {
				target := httpsec.DefaultOIDCHandoffPath + "?" +
					url.Values{"amr": {"mfa"}, "acr": {assuranceACR}}.Encode()

				return serve(t, d.chain, postValues(t.Context(), target, oidcTestSource, url.Values{
					httpsec.DefaultOIDCHandoffParam: {code},
					"amr":                           {"mfa"},
					"acr":                           {assuranceACR},
				}))
			},
			assert: func(t *testing.T, d *assuranceDeployment, code string, out served) {
				require.ErrorIs(t, out.err, policy.ErrMFAEnrolmentRequired,
					"decided as the record's absent assurance")
				assert.Zero(t, d.h.activeSessions(t))
				requireRedeemable(t, d.h, code)
			},
		},
		{
			name: "an evaluator failure denies and does not spend the code",
			cfg: assuranceConfig{
				managerOpts: func(t *testing.T, d *assuranceDeployment) []oidc.Option {
					e := NewMockAssuranceEvaluator(gomock.NewController(t))
					e.EXPECT().MeetsAssurance(gomock.Any(), gomock.Any()).AnyTimes().
						DoAndReturn(func(context.Context, oidc.AssuranceInput) (bool, error) {
							if d.evaluatorDown.Load() {
								return false, errAssuranceEvaluatorDown
							}

							return true, nil
						})

					return []oidc.Option{oidc.WithAssuranceEvaluator(e)}
				},
			},
			amr: []string{"mfa"},
			act: func(t *testing.T, d *assuranceDeployment, code string) served {
				d.evaluatorDown.Store(true)

				first := d.redeem(t, oidcTestSource, code)
				require.ErrorIs(t, first.err, errAssuranceEvaluatorDown, "refused with the evaluator's error")
				require.Zero(t, d.h.activeSessions(t))

				d.evaluatorDown.Store(false)

				return d.redeem(t, oidcAnotherSource, code)
			},
			assert: func(t *testing.T, _ *assuranceDeployment, _ string, out served) {
				loggedIn(t, out)
			},
		},
		{
			name:     "refuse mode keeps the code and counts the refusal against the source",
			cfg:      assuranceConfig{requirementOpts: []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceRefuse)}},
			enrolled: true,
			act: func(t *testing.T, d *assuranceDeployment, code string) served {
				for range 10 {
					out := d.redeem(t, oidcTestSource, code)
					require.ErrorIs(t, out.err, policy.ErrFederatedAssuranceNotMet)
					require.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				}

				return d.redeem(t, oidcTestSource, code)
			},
			assert: func(t *testing.T, d *assuranceDeployment, code string, out served) {
				require.ErrorIs(t, out.err, oidc.ErrInvalidHandoff, "the eleventh is throttled")
				assert.Zero(t, d.h.activeSessions(t))
				requireRedeemable(t, d.h, code)
			},
		},
		{
			name:     "a replaced redeemer naming an amr the check never saw is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.AMR = []string{"mfa"} })},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name:     "a replaced redeemer naming an acr the check never saw is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.ACR = assuranceACR })},
			amr:      []string{"pwd"},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name:     "a replaced redeemer dropping the asserted amr is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.AMR = nil })},
			amr:      []string{"pwd"},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name:     "a replaced redeemer naming a provider the check never saw is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.Provider = "elsewhere" })},
			amr:      []string{"mfa"},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name:     "a replaced redeemer naming an issuer the check never saw is refused",
			cfg:      assuranceConfig{oidcOpts: changing(func(res *oidc.HandoffResult) { res.Issuer = "https://elsewhere.example" })},
			amr:      []string{"mfa"},
			enrolled: true,
			assert:   refusedByGuard,
		},
		{
			name: "a replaced redeemer returning the assurance the check saw completes",
			cfg:  assuranceConfig{oidcOpts: changing(func(*oidc.HandoffResult) {})},
			amr:  []string{"mfa"},
			acr:  assuranceACR,
			assert: func(t *testing.T, d *assuranceDeployment, _ string, out served) {
				s := d.sessionOf(t, loggedIn(t, out))
				assert.Equal(t, []string{"mfa"}, s.FederatedAMR)
				assert.Equal(t, assuranceACR, s.FederatedACR)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newAssuranceDeployment(t, tc.cfg)
			d.enrolled.Store(tc.enrolled)

			code := d.issue(t, tc.amr, tc.acr)

			var out served
			if tc.act != nil {
				out = tc.act(t, d, code)
			} else {
				out = d.redeem(t, oidcTestSource, code)
			}

			tc.assert(t, d, code, out)
		})
	}
}

// TestFederatedRematch pins per-request evaluation of a federated session: the
// session's stored assurance reaches the policies as evidence on every
// request and is matched against the provider's configuration as it is now,
// not as it was at login; a session whose second factor the library verified
// is allowed whatever its stored assurance.
func TestFederatedRematch(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// amr is what the login's record carries, and enrolled whether the
		// user is enrolled on the method.
		amr      []string
		enrolled bool

		// after runs between the login and the request under test, and
		// returns the credential that request presents.
		after func(t *testing.T, d *assuranceDeployment, login served) string

		assert func(t *testing.T, d *assuranceDeployment, credential string, out served)
	}

	// reachedOnce asserts the login's credential reaches the protected route
	// once, before anything changes, and returns it.
	reachedOnce := func(t *testing.T, d *assuranceDeployment, login served) string {
		t.Helper()

		credential := loggedIn(t, login)

		first := d.invoices(t, credential)
		require.NoError(t, first.err)
		require.True(t, first.handlerRan, "the met session reaches the handler")

		return credential
	}

	reached := func(t *testing.T, _ *assuranceDeployment, _ string, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
	}

	challenged := func(t *testing.T, _ *assuranceDeployment, _ string, out served) {
		t.Helper()

		challengedFor(t, out, policy.ChallengeMFA)
	}

	cases := []testCase{
		{
			name:     "a met session reaches the handler while the provider accepts mfa",
			amr:      []string{"mfa"},
			enrolled: true,
			after:    reachedOnce,
			assert:   reached,
		},
		{
			name:  "a met session of a required, unenrolled user reaches the handler",
			amr:   []string{"mfa"},
			after: reachedOnce,
			assert: func(t *testing.T, d *assuranceDeployment, credential string, out served) {
				require.False(t, d.enrolled.Load(), "the user is not enrolled on the method")
				reached(t, d, credential, out)
			},
		},
		{
			name:     "a tightened provider configuration challenges the live session",
			amr:      []string{"mfa"},
			enrolled: true,
			after: func(t *testing.T, d *assuranceDeployment, login served) string {
				credential := reachedOnce(t, d, login)
				d.tighten(t, "hwk")

				return credential
			},
			assert: challenged,
		},
		{
			name:     "a removed provider never matches",
			amr:      []string{"mfa"},
			enrolled: true,
			after: func(t *testing.T, d *assuranceDeployment, login served) string {
				credential := reachedOnce(t, d, login)
				d.removeProvider(t)

				return credential
			},
			assert: challenged,
		},
		{
			name: "a tightened configuration refuses an unenrolled user with enrolment required",
			amr:  []string{"mfa"},
			after: func(t *testing.T, d *assuranceDeployment, login served) string {
				credential := reachedOnce(t, d, login)
				d.tighten(t, "hwk")

				return credential
			},
			assert: func(t *testing.T, _ *assuranceDeployment, _ string, out served) {
				require.ErrorIs(t, out.err, policy.ErrMFAEnrolmentRequired)
				assert.False(t, out.handlerRan, "the stale login is not honoured")
			},
		},
		{
			name:     "a locally satisfied session is allowed whatever its stored assurance",
			amr:      []string{"pwd"},
			enrolled: true,
			after: func(t *testing.T, d *assuranceDeployment, login served) string {
				credential := d.verify(t, challengedFor(t, login, policy.ChallengeMFA))

				s := d.sessionOf(t, credential)
				assert.Equal(t, session.MFASatisfied, s.MFA)
				assert.Equal(t, []string{"pwd"}, s.FederatedAMR, "the rotated session keeps the asserted amr")

				d.removeProvider(t)

				return credential
			},
			assert: reached,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newAssuranceDeployment(t, assuranceConfig{})
			d.enrolled.Store(tc.enrolled)

			login := d.redeem(t, oidcTestSource, d.issue(t, tc.amr, ""))
			credential := tc.after(t, d, login)

			tc.assert(t, d, credential, d.invoices(t, credential))
		})
	}
}

// TestConsumerCreatedSessionAssurance pins the recipe a consumer follows when
// its callback handler creates the session itself: per-request evidence is
// minted only from a session that records the federated first factor, the
// provider and issuer, and the asserted assurance. Any part left out is not a
// partial credit: the session carries no evidence and is treated as though
// the provider had asserted nothing.
func TestConsumerCreatedSessionAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		amr      []string
		enrolled bool
		create   func(d *assuranceDeployment, amr []string) []session.CreateOption
		assert   func(t *testing.T, out served)
	}

	recipe := func(d *assuranceDeployment, amr []string) []session.CreateOption {
		return []session.CreateOption{
			session.WithFirstFactor(factor.OIDC),
			session.WithExternalSession(testOIDCProvider, d.h.provider.srv.URL, oidcTestSessionID, oidcTestIDToken),
			session.WithFederatedAssurance(amr, ""),
		}
	}

	cases := []testCase{
		{
			name:   "first factor, external session and assurance: the evidence is asserted and met",
			amr:    []string{"mfa"},
			create: recipe,
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan, "met evidence completes the request without a challenge")
			},
		},
		{
			name:     "the same recipe with an amr the provider does not accept is challenged",
			amr:      []string{"pwd"},
			enrolled: true,
			create:   recipe,
			assert: func(t *testing.T, out served) {
				challengedFor(t, out, policy.ChallengeMFA)
			},
		},
		{
			name:     "the assurance alone, with no external session, yields no evidence",
			amr:      []string{"mfa"},
			enrolled: true,
			create: func(_ *assuranceDeployment, amr []string) []session.CreateOption {
				return []session.CreateOption{session.WithFederatedAssurance(amr, "")}
			},
			assert: func(t *testing.T, out served) {
				challengedFor(t, out, policy.ChallengeMFA)
			},
		},
		{
			name:     "the first factor and assurance without the external session yield no evidence",
			amr:      []string{"mfa"},
			enrolled: true,
			create: func(_ *assuranceDeployment, amr []string) []session.CreateOption {
				return []session.CreateOption{
					session.WithFirstFactor(factor.OIDC),
					session.WithFederatedAssurance(amr, ""),
				}
			},
			assert: func(t *testing.T, out served) {
				challengedFor(t, out, policy.ChallengeMFA)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newAssuranceDeployment(t, assuranceConfig{})
			d.enrolled.Store(tc.enrolled)

			s, err := d.h.sessions.Create(t.Context(), oidcTestUserID, tc.create(d, tc.amr)...)
			require.NoError(t, err)

			tc.assert(t, d.invoices(t, mfaTokenFor(s.ID)))
		})
	}
}

// TestBearerPerRequestFederatedAssurance pins that the per-request phase is
// handed federated assurance evidence only for a session whose first factor is
// on the federated channel: a session of any other first factor is inert,
// whatever federated fields its record holds.
func TestBearerPerRequestFederatedAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name        string
		firstFactor factor.Kind
		assert      func(t *testing.T, seen *policy.Input)
	}

	cases := []testCase{
		{
			name:        "a password session carrying federated fields is inert",
			firstFactor: factor.Password,
			assert: func(t *testing.T, seen *policy.Input) {
				require.NotNil(t, seen)
				assert.False(t, seen.FederatedAssurance.Asserted(),
					"a session that did not log in through the provider carries no evidence")
			},
		},
		{
			name:        "an oidc session is handed the evidence its record holds",
			firstFactor: factor.OIDC,
			assert: func(t *testing.T, seen *policy.Input) {
				require.NotNil(t, seen)
				ev := seen.FederatedAssurance
				assert.True(t, ev.Asserted())
				assert.Equal(t, "idp", ev.Provider())
				assert.Equal(t, "https://idp.example", ev.Issuer())
				assert.Equal(t, []string{"mfa"}, ev.AMR())
				assert.Equal(t, "x", ev.ACR())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen *policy.Input

			recorder := NewMockPolicy(gomock.NewController(t))
			recorder.EXPECT().Name().Return("test: input recorder").AnyTimes()
			recorder.EXPECT().Phases().Return([]policy.Phase{policy.PerRequest}).AnyTimes()
			recorder.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
					seen = in

					return policy.Decision{Outcome: policy.Allow}
				})

			loaded := liveSession()
			loaded.FirstFactor = tc.firstFactor
			loaded.ExternalProvider = "idp"
			loaded.ExternalIssuer = "https://idp.example"
			loaded.FederatedAMR = []string{"mfa"}
			loaded.FederatedACR = "x"

			h := newAuthHarness(t)
			h.expectVerified()
			h.store.EXPECT().Load(gomock.Any(), testJTI).Return(loaded, nil)
			h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
			h.acceptsActivityWriteBack()

			s := serveBearer(t, h, engineOf(t, recorder), bearerRequest(t.Context(), "Bearer abc.def.ghi"))
			require.NoError(t, s.err)

			tc.assert(t, seen)
		})
	}
}

// TestOIDCRedeemMFADefaultClassification pins the default classification of a
// federated login: OIDC is not exempt by default, so the MFA policies judge it
// like any other login, and the chain insists that the challenge they can now
// raise is enforced.
//
// Its own table: its rows wire the library's MFA policies, and one assembles the
// chain without serving it.
func TestOIDCRedeemMFADefaultClassification(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// withMFA wires EnableMFA beside the policies.
		withMFA bool

		assert func(t *testing.T, h *oidcHarness, enrolled *atomic.Bool)
	}

	cases := []testCase{
		{
			name:    "with EnableMFA wired, a required-but-unenrolled user is refused with enrolment required and keeps the code",
			withMFA: true,
			assert: func(t *testing.T, h *oidcHarness, enrolled *atomic.Bool) {
				c := h.chain(t)
				code := h.issueHandoff(t, "")

				out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))
				require.ErrorIs(t, out.err, policy.ErrMFAEnrolmentRequired)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.Zero(t, h.activeSessions(t), "no session is established")

				// Once the user has enrolled, the same code redeems — into a
				// challenge, since the login is no longer exempt.
				enrolled.Store(true)

				again := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, again.err, &challenge, "the code was kept for a later redemption")
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				assert.Equal(t, []httpsec.MFAMethod{{Name: "totp", Channel: factor.AuthenticatorApp}},
					challenge.Methods, "the handoff's challenge names the method the user can answer it with")
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
		{
			// A handoff that carries no assurance, under the default
			// classification, is refused with enrolment required, keeps the
			// code, and gets no session.
			name:    "required user without assurance is refused",
			withMFA: true,
			assert: func(t *testing.T, h *oidcHarness, _ *atomic.Bool) {
				c := h.chain(t)
				code := h.issueHandoff(t, "")

				out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))

				require.ErrorIs(t, out.err, policy.ErrMFAEnrolmentRequired)
				require.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				require.Zero(t, h.activeSessions(t), "no session may be created")

				again := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))
				require.ErrorIs(t, again.err, policy.ErrMFAEnrolmentRequired, "the code was not consumed")
			},
		},
		{
			name: "without EnableMFA, the classification fails chain assembly",
			assert: func(t *testing.T, h *oidcHarness, _ *atomic.Bool) {
				c, err := h.assemble(h.handoffs,
					httpsec.WithOIDCTokens(h.tokens), httpsec.WithOIDCSessions(h.sessions))
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, strings.ToLower(err.Error()), "enablemfa",
					"the error names what is missing")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			var enrolled atomic.Bool

			h.chainOpts = []httpsec.Option{
				httpsec.WithPolicyEngine(oidcMFAEngine(t, false, enrolled.Load)),
			}
			if tc.withMFA {
				h.chainOpts = append(h.chainOpts, enableMFAFor(t))
			}

			tc.assert(t, h, &enrolled)
		})
	}
}

// sessionWrites records what a session store was asked to write, copied at
// the moment of the write, so a case can tell what a session held when it was
// first stored from what it holds now.
type sessionWrites struct {
	mu      sync.Mutex
	created []session.Session
	saved   []session.Session
}

func (w *sessionWrites) creates() []session.Session {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]session.Session(nil), w.created...)
}

func (w *sessionWrites) saves() []session.Session {
	w.mu.Lock()
	defer w.mu.Unlock()

	return append([]session.Session(nil), w.saved...)
}

// spiedSessions is a session manager over an in-memory store whose writes are
// recorded.
func spiedSessions(t *testing.T) (*session.Sessions, *sessionWrites) {
	t.Helper()

	mem := must.Must(session.NewMemoryStore())
	w := &sessionWrites{}

	store := NewMockStore(gomock.NewController(t))
	store.EXPECT().Create(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, s *session.Session) error {
			w.mu.Lock()
			w.created = append(w.created, *s)
			w.mu.Unlock()

			return mem.Create(ctx, s)
		})
	store.EXPECT().Save(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(ctx context.Context, s *session.Session) error {
			w.mu.Lock()
			w.saved = append(w.saved, *s)
			w.mu.Unlock()

			return mem.Save(ctx, s)
		})
	store.EXPECT().Load(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.Load)
	store.EXPECT().CountActiveByUser(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(mem.CountActiveByUser)

	m, err := session.New(session.WithStore(store))
	require.NoError(t, err)

	return m, w
}

// oidcMFAEngine holds both library MFA policies over a method the linked user
// is enrolled on whenever enrolled reports so, requiring a second factor of
// everyone. With exempt, a consumer exemption rule marks an OIDC login exempt,
// which is a total exemption; without it, the library's default classification
// applies, under which an OIDC login is not exempt.
func oidcMFAEngine(t *testing.T, exempt bool, enrolled func() bool) *policy.Engine {
	t.Helper()

	method := NewMockMFAMethodLookup(gomock.NewController(t))
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (bool, error) { return enrolled(), nil })

	var (
		challengeOpts []policy.MFAOption
		// The source answers the handoffs' unasserted assurance as unmet;
		// OIDC login refuses to assemble a requirement policy without one.
		requirementOpts = []policy.MFARequirementOption{
			policy.WithMFARequiredForAll(),
			policy.WithFederatedAssuranceSource(newTestOIDCManager(t)),
		}
	)

	if exempt {
		classification := policy.WithMFAExemption(func(k factor.Kind) bool {
			return k == factor.OIDC || k.MFAExempt()
		})
		challengeOpts = append(challengeOpts, classification)
		requirementOpts = append(requirementOpts, classification)
	}

	challenge, err := policy.NewMFA([]policy.MFAMethodLookup{method}, challengeOpts...)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirement(nil, []policy.MFAMethodLookup{method}, requirementOpts...)
	require.NoError(t, err)

	return engineOf(t, challenge, requirement)
}

// TestOIDCRedeemSession pins what a successful redemption leaves behind: a
// session carrying the federated login from the write that creates it, the
// login document plus an allowlisted destination, and a challenge when the
// policy raises one.
//
// Its own table: its rows read the session store's writes through a spied
// manager, which TestOIDCRedeem's harness does not wire.
func TestOIDCRedeemSession(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// opts configure the chain beside the harness's required wiring.
		opts []httpsec.OIDCOption

		// chainOpts configure the chain beside EnableOIDCLogin.
		chainOpts func(t *testing.T) []httpsec.Option

		// handoff adjusts the login the redeemed code is issued for.
		handoff func(h *oidcHarness, res *oidc.CallbackResult)

		assert func(t *testing.T, h *oidcHarness, w *sessionWrites, code string, out served)
	}

	mfaWired := func(exempt bool) func(t *testing.T) []httpsec.Option {
		return func(t *testing.T) []httpsec.Option {
			t.Helper()

			return []httpsec.Option{
				httpsec.WithPolicyEngine(oidcMFAEngine(t, exempt, func() bool { return true })),
				enableMFAFor(t),
			}
		}
	}

	decode := func(t *testing.T, out served) map[string]any {
		t.Helper()

		var body map[string]any
		require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))

		return body
	}

	cases := []testCase{
		{
			name: "the session carries the OIDC first factor and the federated fields from its first write",
			handoff: func(_ *oidcHarness, res *oidc.CallbackResult) {
				res.AMR, res.ACR = []string{"pwd", "mfa"}, assuranceACR
			},
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)

				created := w.creates()
				require.Len(t, created, 1)
				assert.Equal(t, factor.OIDC, created[0].FirstFactor)
				assert.Equal(t, testOIDCProvider, created[0].ExternalProvider)
				assert.Equal(t, h.provider.srv.URL, created[0].ExternalIssuer)
				assert.Equal(t, oidcTestSessionID, created[0].ExternalSessionID)
				assert.Equal(t, oidcTestIDToken, created[0].ExternalIDToken)
				assert.Equal(t, oidcTestUserID, created[0].UserID)
				assert.Equal(t, []string{"pwd", "mfa"}, created[0].FederatedAMR, "the asserted amr is in the first write")
				assert.Equal(t, assuranceACR, created[0].FederatedACR, "the asserted acr is in the first write")
				assert.Empty(t, w.saves(), "nothing is added to the session after it was created")
			},
		},
		{
			name: "a provider without session ids records an empty one and the login succeeds",
			handoff: func(_ *oidcHarness, res *oidc.CallbackResult) {
				res.SessionID = ""
			},
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)

				created := w.creates()
				require.Len(t, created, 1)
				assert.Empty(t, created[0].ExternalSessionID)
				assert.Equal(t, h.provider.srv.URL, created[0].ExternalIssuer)
			},
		},
		{
			name: "the response is the login document plus the allowlisted next",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCAllowedRedirects("/welcome")},
			handoff: func(_ *oidcHarness, res *oidc.CallbackResult) {
				res.Next = "/welcome"
			},
			assert: func(t *testing.T, _ *oidcHarness, w *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))
				assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"))

				body := decode(t, out)
				assert.Equal(t, "issued-token", body["access_token"])
				assert.Contains(t, body, "refresh_token", "the same members a form login answers with")
				assert.Equal(t, "/welcome", body["next"])

				created := w.creates()
				require.Len(t, created, 1)
				require.IsType(t, "", body["valid_until"])
				validUntil, err := time.Parse(time.RFC3339Nano, body["valid_until"].(string))
				require.NoError(t, err)
				assert.True(t, created[0].IdleExpiresAt.Equal(validUntil),
					"valid_until is the session's idle expiry")
			},
		},
		{
			name: "a recorded next the allowlist does not hold becomes the root",
			opts: []httpsec.OIDCOption{httpsec.WithOIDCAllowedRedirects("/welcome")},
			handoff: func(_ *oidcHarness, res *oidc.CallbackResult) {
				res.Next = "https://evil.example/welcome"
			},
			assert: func(t *testing.T, _ *oidcHarness, _ *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, "/", decode(t, out)["next"], "the recorded destination is never echoed raw")
			},
		},
		{
			name:      "a challenge consumes the code and returns the challenge",
			chainOpts: mfaWired(false),
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, code string, out served) {
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				require.NotNil(t, challenge.Session)
				assert.Equal(t, session.MFAPending, challenge.Session.MFA, "the session is pending the challenge")
				assert.Equal(t, factor.OIDC, challenge.Session.FirstFactor)
				assert.Equal(t, "no-referrer", out.rec.Header().Get("Referrer-Policy"))
				assert.Equal(t, 1, h.activeSessions(t))
				assert.Len(t, w.creates(), 1)

				again := serve(t, h.chain(t), handoffRequest(t.Context(), oidcAnotherSource, code))
				require.ErrorIs(t, again.err, oidc.ErrInvalidHandoff, "the code was spent")
			},
		},
		{
			name:      "a consumer exemption of oidc creates a session without a challenge",
			chainOpts: mfaWired(true),
			assert: func(t *testing.T, h *oidcHarness, w *sessionWrites, _ string, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)

				created := w.creates()
				require.Len(t, created, 1)
				assert.Equal(t, session.MFANone, created[0].MFA)
				assert.Empty(t, w.saves(), "no challenge was marked")
				assert.Equal(t, 1, h.activeSessions(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			var w *sessionWrites
			h.sessions, w = spiedSessions(t)

			if tc.chainOpts != nil {
				h.chainOpts = tc.chainOpts(t)
			}

			res := h.handoffResult()
			if tc.handoff != nil {
				tc.handoff(h, &res)
			}

			code := h.issueHandoffFor(t, res)

			out := serve(t, h.chain(t, tc.opts...), handoffRequest(t.Context(), oidcTestSource, code))

			tc.assert(t, h, w, code, out)
		})
	}
}
