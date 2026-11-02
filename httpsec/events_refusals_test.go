package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/token/onetime"
)

// faultyChallenges is a passkey challenge store whose lookup and spend run
// hooks a case sets: a hook fails the call by returning an error, or lets it
// through by returning nil.
type faultyChallenges struct {
	onetime.Store

	find    atomic.Pointer[func(ctx context.Context) error]
	consume atomic.Pointer[func(ctx context.Context) error]
}

func (s *faultyChallenges) Consume(ctx context.Context, tid id.ID, at time.Time) error {
	if hook := s.consume.Load(); hook != nil {
		if err := (*hook)(ctx); err != nil {
			return err
		}
	}

	return s.Store.Consume(ctx, tid, at)
}

func (s *faultyChallenges) FindByID(ctx context.Context, tid id.ID) (*onetime.Token, error) {
	if hook := s.find.Load(); hook != nil {
		if err := (*hook)(ctx); err != nil {
			return nil, err
		}
	}

	return s.Store.FindByID(ctx, tid)
}

// scriptedBroker is a consumer identity broker that answers every callback
// with what run returns.
type scriptedBroker struct {
	run func(ctx context.Context) error
}

func (b scriptedBroker) Broker(ctx context.Context, _ oidc.ExternalIdentity) (*identity.Principal, error) {
	return nil, b.run(ctx)
}

// refusalRun is what one row of TestSecurityEvents_Refusals produced: the
// events the chain's sink received, the error the request was answered with,
// and, for a row whose component has a sink of its own, what that sink
// received.
type refusalRun struct {
	events []security.Event
	own    []security.Event
	err    error
}

// reported asserts the run reported name exactly once, with outcome failure,
// from clientIP, carrying kind, and that it reported no other failure.
func reported(name, clientIP string, kind factor.Kind) func(t *testing.T, run refusalRun) {
	return func(t *testing.T, run refusalRun) {
		t.Helper()

		var failures []security.Event
		for _, e := range run.events {
			if e.Outcome == security.OutcomeFailure {
				failures = append(failures, e)
			}
		}

		require.Len(t, failures, 1, "events: %v", namesOf(run.events))
		assert.Equal(t, name, failures[0].Name)
		assert.Equal(t, clientIP, failures[0].ClientIP, "the resolved client address")
		assert.Equal(t, kind, failures[0].Factor)
		assert.False(t, failures[0].At.IsZero())
	}
}

// reportedNothing asserts the run reported no failure at all.
func reportedNothing(t *testing.T, run refusalRun) {
	t.Helper()

	for _, e := range run.events {
		assert.NotEqual(t, security.OutcomeFailure, e.Outcome, "%s reported", e.Name)
	}
}

// TestSecurityEvents_Refusals pins the refusals the chain can tell from an
// outage, each reported once under its documented name, and the outages and
// the refusals answered alike with an outage, which report nothing.
//
// Rows share no setup beyond the recorder: each drives the flow its outcome
// needs through that flow's own harness.
func TestSecurityEvents_Refusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, rec *eventRecorder) refusalRun
		assert func(t *testing.T, run refusalRun)
	}

	// passwordless logs in through a passwordless deployment, after wire.
	passwordless := func(wire func(d *pwlDeployment), credID string) func(*testing.T, *eventRecorder) refusalRun {
		return func(t *testing.T, rec *eventRecorder) refusalRun {
			d := newPwlDeployment(t)
			d.extra = append(d.extra, httpsec.EnableSecurityEvents(rec.sink))
			d.build(t)

			handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
			if wire != nil {
				wire(d)
			}

			out := d.login(t, credID, handle)

			return refusalRun{events: rec.all(), err: out.err}
		}
	}

	// oidcCallback runs one OIDC login whose callback presents code, after
	// wire.
	oidcCallback := func(wire func(h *oidcHarness), code func(l oidcLogin) string) func(*testing.T, *eventRecorder) refusalRun {
		return func(t *testing.T, rec *eventRecorder) refusalRun {
			h := newOIDCHarness(t)
			h.chainOpts = append(h.chainOpts, httpsec.EnableSecurityEvents(rec.sink))
			c := h.chain(t)

			if wire != nil {
				wire(h)
			}

			l := startLogin(t, c, "")
			q := url.Values{"code": {code(l)}, "state": {l.state}}.Encode()
			out := serve(t, c, callbackRequest(t.Context(), q, l.handle))

			return refusalRun{events: rec.all(), err: out.err}
		}
	}

	// recovering builds a recovery deployment reporting to rec.
	recovering := func(t *testing.T, rec *eventRecorder, recOpts ...httpsec.RecoveryOption) *recoveryHarness {
		h := newRecoveryHarness(t)
		h.chainOpts = append(h.chainOpts, httpsec.EnableSecurityEvents(rec.sink))
		h.recOpts = append(h.recOpts, recOpts...)

		return h.build(t)
	}

	// enrolmentBegin posts one enrolment begin through a chain whose begin
	// limiter is l.
	enrolmentBegin := func(l func(t *testing.T) *MockLimiter) func(*testing.T, *eventRecorder) refusalRun {
		return func(t *testing.T, rec *eventRecorder) refusalRun {
			h := newEnrolHarness(t)
			h.extra = append(h.extra, httpsec.EnableSecurityEvents(rec.sink))
			h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithEnrolmentBeginLimiter(l(t))}

			s := h.enrolmentOnly(t, factor.Password)
			out := serve(t, h.chain(t, s), post(t.Context(), enrolBeginPath, ""))

			return refusalRun{events: rec.all(), err: out.err}
		}
	}

	// keyed presents key to an API-key chain reporting to rec, whose manager
	// reports to a sink of its own as well.
	keyed := func(t *testing.T, rec *eventRecorder, present func(valid string) string) refusalRun {
		own := &eventRecorder{}
		keys, err := apikey.New(apikey.WithSecurityEvents(own.sink))
		require.NoError(t, err)

		valid, _, err := keys.Issue(t.Context(), apiKeyPrincipal, "billing", []string{"invoices:read"}, 0)
		require.NoError(t, err)

		h := &apiKeyHarness{keys: keys, valid: valid}
		c, err := httpsec.New(httpsec.EnableAPIKey(keys), httpsec.EnableSecurityEvents(rec.sink))
		require.NoError(t, err)

		out := h.withKey(t, c, apiKeySource, present(valid))

		return refusalRun{events: rec.all(), own: own.all(), err: out.err}
	}

	// passwordlessIn logs in from a credential seeded in state.
	passwordlessIn := func(state passkey.State) func(*testing.T, *eventRecorder) refusalRun {
		return func(t *testing.T, rec *eventRecorder) refusalRun {
			d := newPwlDeployment(t)
			d.extra = append(d.extra, httpsec.EnableSecurityEvents(rec.sink))
			d.build(t)

			out := d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", state))

			return refusalRun{events: rec.all(), err: out.err}
		}
	}

	// passwordlessChallenge logs in after the challenge store's lookup runs
	// hook, given the request's cancel function.
	passwordlessChallenge := func(hook func(cancel context.CancelFunc) func(context.Context) error, spend ...bool) func(*testing.T, *eventRecorder) refusalRun {
		return func(t *testing.T, rec *eventRecorder) refusalRun {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			store := &faultyChallenges{Store: must.Must(onetime.NewMemoryStore())}

			d := newPwlDeployment(t)
			d.challenges = store
			d.extra = append(d.extra, httpsec.EnableSecurityEvents(rec.sink))
			d.build(t)

			handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
			cookie, challenge := d.begun(t)

			h := hook(cancel)
			if len(spend) > 0 && spend[0] {
				store.consume.Store(&h)
			} else {
				store.find.Store(&h)
			}

			req := jsonPost(ctx, passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
			req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie
			out := serveWithContext(ctx, d.chain, req)

			return refusalRun{events: rec.all(), err: out.err}
		}
	}

	// oidcBrokered runs one OIDC callback whose consumer broker answers with
	// run, given the request's cancel function, on a request that carries
	// that cancel.
	oidcBrokered := func(run func(cancel context.CancelFunc) func(context.Context) error) func(*testing.T, *eventRecorder) refusalRun {
		return func(t *testing.T, rec *eventRecorder) refusalRun {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			h := newOIDCHarness(t)
			registry := must.Must(oidc.NewRegistry(h.provider.provider()))
			client := must.Must(outbound.New(outbound.WithHTTPClient(h.provider.srv.Client())))
			h.manager = must.Must(oidc.NewRelyingParty(registry, scriptedBroker{run: run(cancel)},
				oidc.WithOutboundClient(client), oidc.WithFlowStore(h.flows)))
			h.chainOpts = append(h.chainOpts, httpsec.EnableSecurityEvents(rec.sink))
			c := h.chain(t)

			l := startLogin(t, c, "")
			q := url.Values{"code": {l.nonce}, "state": {l.state}}.Encode()
			out := serveWithContext(ctx, c, callbackRequest(ctx, q, l.handle))

			return refusalRun{events: rec.all(), err: out.err}
		}
	}

	failsWith := func(err error) func(context.CancelFunc) func(context.Context) error {
		return func(context.CancelFunc) func(context.Context) error {
			return func(context.Context) error { return err }
		}
	}

	cases := []testCase{
		{
			name: "a passkey assertion for an unknown credential reports authn_login_fail",
			run:  passwordless(nil, "cred-unknown"),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, authenticate.ErrAuthenticationFailed)
				reported(security.AuthnLoginFail, "192.0.2.1", factor.Passkey)(t, run)
			},
		},
		{
			name: "a passkey assertion for a disabled user reports authn_login_fail",
			run:  passwordless(func(d *pwlDeployment) { d.inactive.Store(true) }, "cred-1"),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, authenticate.ErrAuthenticationFailed)
				reported(security.AuthnLoginFail, "192.0.2.1", factor.Passkey)(t, run)
			},
		},
		{
			name: "a passkey assertion whose user could not be loaded reports nothing",
			run:  passwordless(func(d *pwlDeployment) { d.loaderFails.Store(true) }, "cred-1"),
			assert: func(t *testing.T, run refusalRun) {
				require.Error(t, run.err)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(run.err))
				reportedNothing(t, run)
			},
		},
		{
			name: "a passkey login whose client hung up during the consumer's login check reports nothing",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				d := newPwlDeployment(t)
				d.extra = append(d.extra, httpsec.EnableSecurityEvents(rec.sink))
				d.pkOpts = append(d.pkOpts, passkey.WithLoginCheck(func(context.Context, passkey.LoginFacts) error {
					cancel()

					return errors.Join(authenticate.ErrAuthenticationFailed, context.Canceled)
				}))
				d.build(t)

				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, challenge := d.begun(t)

				req := jsonPost(ctx, passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie
				out := serveWithContext(ctx, d.chain, req)

				return refusalRun{events: rec.all(), err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, context.Canceled)
				reportedNothing(t, run)
			},
		},
		{
			name: "a passkey assertion from a pending credential reports authn_login_fail",
			run:  passwordlessIn(passkey.StatePending),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, passkey.ErrPending)
				reported(security.AuthnLoginFail, "192.0.2.1", factor.Passkey)(t, run)
			},
		},
		{
			name: "a passkey assertion from a suspended credential reports authn_login_fail",
			run:  passwordlessIn(passkey.StateSuspended),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, passkey.ErrSuspended)
				reported(security.AuthnLoginFail, "192.0.2.1", factor.Passkey)(t, run)
			},
		},
		{
			name: "a passkey assertion for a challenge the store does not hold reports authn_login_fail",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				d := newPwlDeployment(t)
				d.extra = append(d.extra, httpsec.EnableSecurityEvents(rec.sink))
				d.build(t)

				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, _ := d.begun(t)
				out := d.finish(t, handleAssertionBody("not-the-challenge", "cred-1", handle), cookie)

				return refusalRun{events: rec.all(), err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, authenticate.ErrAuthenticationFailed)
				reported(security.AuthnLoginFail, "192.0.2.1", factor.Passkey)(t, run)
			},
		},
		{
			name: "a passkey login whose challenge store failed reports nothing, and is still answered as a failed assertion",
			run: passwordlessChallenge(func(context.CancelFunc) func(context.Context) error {
				return func(context.Context) error { return errLimiterDown }
			}),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(run.err), "the status is a failed assertion's")
				assert.Equal(t, authenticate.ErrAuthenticationFailed.Error(), run.err.Error(), "the text is the refusal's own")
				reportedNothing(t, run)
			},
		},
		{
			name: "a passkey login whose challenge store failed at the spend reports nothing, and is still answered as a failed assertion",
			run:  passwordlessChallenge(failsWith(errLimiterDown), true),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(run.err))
				reportedNothing(t, run)
			},
		},
		{
			name: "a passkey login whose client hung up during the challenge lookup reports nothing",
			run: passwordlessChallenge(func(cancel context.CancelFunc) func(context.Context) error {
				return func(ctx context.Context) error {
					cancel()

					return ctx.Err()
				}
			}),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, authenticate.ErrAuthenticationFailed)
				reportedNothing(t, run)
			},
		},
		{
			name: "an OIDC callback whose identity is linked to no account reports authn_login_fail",
			run:  oidcBrokered(failsWith(oidc.ErrNoLinkedAccount)),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, oidc.ErrNoLinkedAccount)
				reported(security.AuthnLoginFail, "192.0.2.1", factor.OIDC)(t, run)
			},
		},
		{
			name: "an OIDC callback whose provisioning was refused reports authn_login_fail",
			run:  oidcBrokered(failsWith(oidc.ErrProvisioningRefused)),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, oidc.ErrProvisioningRefused)
				reported(security.AuthnLoginFail, "192.0.2.1", factor.OIDC)(t, run)
			},
		},
		{
			name: "an OIDC callback refused beside an outage reports nothing",
			run:  oidcBrokered(failsWith(errors.Join(oidc.ErrNoLinkedAccount, oidc.ErrExchangeFailed))),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, oidc.ErrExchangeFailed)
				reportedNothing(t, run)
			},
		},
		{
			name: "an OIDC callback refused on a request that ended reports nothing",
			run: oidcBrokered(func(cancel context.CancelFunc) func(context.Context) error {
				return func(context.Context) error {
					cancel()

					return errors.Join(oidc.ErrNoLinkedAccount, context.Canceled)
				}
			}),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, context.Canceled)
				reportedNothing(t, run)
			},
		},
		{
			name: "an OIDC callback whose ID token fails verification reports authn_login_fail",
			run:  oidcCallback(nil, func(oidcLogin) string { return "not-the-nonce" }),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, oidc.ErrInvalidIDToken)
				reported(security.AuthnLoginFail, "192.0.2.1", factor.OIDC)(t, run)
			},
		},
		{
			name: "an OIDC callback whose provider is down reports nothing",
			run: oidcCallback(func(h *oidcHarness) { h.provider.tokenDown.Store(true) },
				func(l oidcLogin) string { return l.nonce }),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, oidc.ErrExchangeFailed)
				reportedNothing(t, run)
			},
		},
		{
			name: "a recovery refused for a wrong saved code reports scrty_recovery_refused",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				h := recovering(t, rec)
				_ = h.saved(t)
				out := h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, "AAAA-BBBB-CCCC", httpsec.RecoveryPasswordParam, e2ePassword))

				return refusalRun{events: rec.all(), err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, recovery.ErrRefused)
				reported(security.RecoveryRefused, e2eSource, "")(t, run)
				assert.Empty(t, run.events[0].User, "a refusal names no user")
			},
		},
		{
			name: "a recovery from a source over its limit reports the limit, not a refused recovery",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				h := recovering(t, rec, httpsec.WithRecoveryLimiter(exceededLimiter(t)))
				saved := h.saved(t)
				out := h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, saved, httpsec.RecoveryPasswordParam, e2ePassword))

				return refusalRun{events: rec.all(), err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, recovery.ErrRefused)
				reported(security.ExcessRateLimitExceeded, e2eSource, "")(t, run)
			},
		},
		{
			name: "a completed recovery is a sign-in, and reports authn_login_success",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				h := recovering(t, rec)
				saved := h.saved(t)
				out := h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, saved, httpsec.RecoveryPasswordParam, e2ePassword))

				return refusalRun{events: rec.all(), err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.NoError(t, run.err)

				var signedIn []security.Event
				for _, e := range run.events {
					if e.Name == security.AuthnLoginSuccess {
						signedIn = append(signedIn, e)
					}
				}

				require.Len(t, signedIn, 1, "events: %v", namesOf(run.events))
				assert.Equal(t, e2eUser, signedIn[0].User)
				assert.Equal(t, factor.Recovery, signedIn[0].Factor)
				assert.Equal(t, e2eSource, signedIn[0].ClientIP)
				assert.NotEmpty(t, signedIn[0].Session)
				reportedNothing(t, run)
			},
		},
		{
			name: "a second-factor challenge over the issue limit reports excess_rate_limit_exceeded",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
				h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(false, nil).AnyTimes()
				h.extra = []mfa.Method{newChallengeStub()}
				h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(1)}
				h.chainOpts = []httpsec.Option{httpsec.EnableSecurityEvents(rec.sink)}

				s := h.pendingSession(t, factor.Password)
				c := h.bearerChain(t)

				require.NoError(t, serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID))).err)
				out := serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID)))

				events := rec.all()
				require.NotEmpty(t, events)
				assert.Equal(t, testMFAUser, events[len(events)-1].User)
				assert.Equal(t, digestOf(s.ID), events[len(events)-1].Session)

				return refusalRun{events: events, err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, mfa.ErrVerifyThrottled)
				reported(security.ExcessRateLimitExceeded, "192.0.2.1", factor.Password)(t, run)
			},
		},
		{
			name: "a second-factor response from a throttled user reports excess_rate_limit_exceeded",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp).throttles().neverVerifies().recordsNoFailure()

				s := h.pendingSession(t, factor.Password)
				out := serve(t, h.chain(t, s, httpsec.EnableSecurityEvents(rec.sink)), postCode(t.Context(), testMFAVerifyPath))

				events := rec.all()
				require.NotEmpty(t, events)
				assert.Equal(t, testMFAUser, events[0].User)

				return refusalRun{events: events, err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, mfa.ErrVerifyThrottled)
				reported(security.ExcessRateLimitExceeded, "192.0.2.1", "")(t, run)
			},
		},
		{
			name: "an enrolment begin over the user's limit reports excess_rate_limit_exceeded",
			run:  enrolmentBegin(exceededLimiter),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, mfa.ErrEnrolmentThrottled)
				reported(security.ExcessRateLimitExceeded, "192.0.2.1", factor.Password)(t, run)
				assert.Equal(t, testMFAUser, run.events[0].User)
			},
		},
		{
			name: "an enrolment begin whose limiter could not answer reports nothing",
			run: enrolmentBegin(func(t *testing.T) *MockLimiter {
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, errLimiterDown)

				return l
			}),
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, mfa.ErrEnrolmentThrottled)
				reportedNothing(t, run)
			},
		},
		{
			name: "a wrong API key reports authn_login_fail once, through the chain and not the manager's own sink",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				return keyed(t, rec, func(string) string { return "sk_0199a0e1-0000-7000-8000-000000000000.Z3Vlc3M" })
			},
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, authenticate.ErrAuthenticationFailed)
				reported(security.AuthnLoginFail, apiKeySource, factor.APIKey)(t, run)
				assert.Empty(t, run.own, "one outcome is reported once")
			},
		},
		{
			name: "a renewal of a family over its limit reports excess_rate_limit_exceeded",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				w := newEventsWorldOf(t, eventsWorldSpec{
					renewalOpts: []httpsec.SessionRenewalOption{httpsec.WithRenewalLimiter(exceededLimiter(t))},
				})
				tok := w.signedIn(t)
				out := w.send(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, tok, nil, nil)

				return refusalRun{events: w.rec.all(), err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.ErrorIs(t, run.err, httpsec.ErrRenewalThrottled)
				reported(security.ExcessRateLimitExceeded, eventsClient, "")(t, run)
			},
		},
		{
			// A refused redemption and an outage are answered with one error
			// by design, so neither is reported.
			name: "a refused magic-link redemption reports nothing",
			run: func(t *testing.T, rec *eventRecorder) refusalRun {
				h := newMagicLinkHarness(t)
				h.chainOpts = append(h.chainOpts, httpsec.EnableSecurityEvents(rec.sink))
				c := h.chain(t)
				tok, _ := h.link(t, c)

				out := h.redeem(t, c, tok, "not-the-binding")

				return refusalRun{events: rec.all(), err: out.err}
			},
			assert: func(t *testing.T, run refusalRun) {
				require.Error(t, run.err)
				reportedNothing(t, run)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t, &eventRecorder{}))
		})
	}
}

// TestSecurityEvents_RecoveryStartHoldsAlike pins that a start for a username
// no account has is held by the sink exactly as one for a known username is:
// the sink is called before the start is answered in both cases, so a sink
// that takes time cannot make the latency tell them apart.
func TestSecurityEvents_RecoveryStartHoldsAlike(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		username string
		assert   func(t *testing.T, e security.Event)
	}

	cases := []testCase{
		{
			name:     "a known username",
			username: e2eAddress,
			assert: func(t *testing.T, e security.Event) {
				assert.Equal(t, e2eUser, e.User)
			},
		},
		{
			name:     "an unknown username",
			username: "nobody@example.com",
			assert: func(t *testing.T, e security.Event) {
				assert.Empty(t, e.User, "no account, no user reference")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			called := make(chan security.Event, 1)
			release := make(chan struct{})

			sink := func(_ context.Context, e security.Event) {
				if e.Name != security.RecoveryStarted {
					return
				}

				called <- e
				<-release
			}

			h := newRecoveryHarness(t)
			h.chainOpts = append(h.chainOpts, httpsec.EnableSecurityEvents(sink))
			h.build(t)

			done := make(chan served, 1)
			go func() {
				done <- serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
					url.Values{httpsec.RecoveryUsernameParam: {tc.username}}))
			}()

			var e security.Event
			select {
			case e = <-called:
			case out := <-done:
				close(release)
				t.Fatalf("the start was answered (%v) without the sink holding it", out.err)
			}

			select {
			case <-done:
				t.Fatal("the start was answered while the sink still held it")
			default:
			}

			close(release)
			out := <-done

			require.NoError(t, out.err)
			assert.Equal(t, http.StatusAccepted, out.rec.Code)
			assert.Equal(t, security.OutcomeSuccess, e.Outcome)
			assert.Equal(t, e2eSource, e.ClientIP)
			tc.assert(t, e)
		})
	}
}

// TestSecurityEvents_ComposedChains pins that a refusal decided by a chain
// whose Assemble runs inside another chain's is reported once, whichever of
// the two report to a sink.
func TestSecurityEvents_ComposedChains(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// outerSink and innerSink say which chains report, each to its own
		// recorder.
		outerSink, innerSink bool

		assert func(t *testing.T, outer, inner *eventRecorder)
	}

	cases := []testCase{
		{
			name:      "the outer chain reports, the inner refuses",
			outerSink: true,
			assert: func(t *testing.T, outer, _ *eventRecorder) {
				assert.Equal(t, []string{security.MaliciousCSRF}, outer.names())
			},
		},
		{
			name:      "both report: the deciding chain's sink, once",
			outerSink: true,
			innerSink: true,
			assert: func(t *testing.T, outer, inner *eventRecorder) {
				assert.Equal(t, []string{security.MaliciousCSRF}, inner.names())
				assert.Empty(t, outer.names(), "one outcome is reported once")
			},
		},
		{
			name:      "only the inner chain reports",
			innerSink: true,
			assert: func(t *testing.T, outer, inner *eventRecorder) {
				assert.Equal(t, []string{security.MaliciousCSRF}, inner.names())
				assert.Empty(t, outer.names())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			outerRec, innerRec := &eventRecorder{}, &eventRecorder{}

			innerOpts := []httpsec.Option{httpsec.WithLogger(discardLogger()), httpsec.EnableCSRFProtection()}
			if tc.innerSink {
				innerOpts = append(innerOpts, httpsec.EnableSecurityEvents(innerRec.sink))
			}

			inner, err := httpsec.New(innerOpts...)
			require.NoError(t, err)

			outerOpts := []httpsec.Option{httpsec.WithLogger(discardLogger())}
			if tc.outerSink {
				outerOpts = append(outerOpts, httpsec.EnableSecurityEvents(outerRec.sink))
			}

			outer, err := httpsec.New(outerOpts...)
			require.NoError(t, err)

			mounted := inner.Assemble(func(*httpsec.Exchange) error { return nil })
			run := outer.Assemble(mounted)

			req := formRequest(t.Context(), "/api/orders", "item=1")
			req.Header.Set("Sec-Fetch-Site", "cross-site")

			rec := httptest.NewRecorder()
			err = run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(rec)))
			require.ErrorIs(t, err, httpsec.ErrCrossSiteRequest)

			tc.assert(t, outerRec, innerRec)
		})
	}
}
