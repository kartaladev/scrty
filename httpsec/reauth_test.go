package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// The re-proof paths under the default prefix.
const (
	reauthMethodsPath  = httpsec.DefaultReauthenticationPrefix + "/methods"
	reauthPasswordPath = httpsec.DefaultReauthenticationPrefix + "/password"
	reauthVerifyTOTP   = httpsec.DefaultReauthenticationPrefix + "/verify/totp"
)

// reauthHarness is a chain with the second factor, form login, logout and
// re-authentication: the MFA harness's method, limiter, tokens and sessions,
// and form login over doubles that no case here reaches, because only its
// presence decides anything at the listing.
type reauthHarness struct {
	*mfaHarness

	authn    *MockAuthenticator
	attempts *MockAttemptStore

	// noMFA and noLogin leave the MFA slot or form login out, and off leaves
	// re-authentication itself out.
	noMFA, noLogin, off bool

	// sessionBearer builds the chain on EnableSessionBearer, which issues the
	// session reference itself, so the second factor and form login are given
	// no token generator.
	sessionBearer bool

	// noReauthTokens leaves WithReauthenticationTokens out.
	noReauthTokens bool

	// reauthOpts are the re-authentication options a case adds after the
	// harness's tokens.
	reauthOpts []httpsec.ReauthenticationOption

	// reauthStore is the re-proof challenge store a case gave the chain, kept
	// so the case can read back what was issued into it.
	reauthStore onetime.Store

	// password, when set, is the authenticator form login judges passwords
	// with in place of authn, and loginOpts are further form login options.
	password  authenticate.Authenticator
	loginOpts []httpsec.LoginOption

	// noCarrier leaves out the carrier that records the resolved session, for
	// a case serving concurrent requests, whose records would race.
	noCarrier bool
}

func newReauthHarness(t *testing.T) *reauthHarness {
	t.Helper()

	ctrl := gomock.NewController(t)

	h := &reauthHarness{
		mfaHarness: newMFAHarness(t),
		authn:      NewMockAuthenticator(ctrl),
		attempts:   NewMockAttemptStore(ctrl),
	}
	h.channel(factor.AuthenticatorApp)

	return h
}

// options is every option the harness's chain is built from, with s carried
// as a first factor would have carried it.
func (h *reauthHarness) options(s *session.Session) []httpsec.Option {
	opts := h.clockOpt()
	if !h.noCarrier {
		opts = append(opts, h.carries(s))
	}

	if !h.noMFA {
		mfaOpts := append([]httpsec.MFAOption{httpsec.WithMFAVerifyLimiter(h.limiter)}, h.mfaOpts...)
		if !h.sessionBearer {
			mfaOpts = append(mfaOpts, httpsec.WithMFATokens(h.tokens))
		}

		opts = append(opts, httpsec.EnableMFA(append([]mfa.Method{h.method}, h.extra...), mfaOpts...))
	}

	if !h.noLogin {
		deps := httpsec.FormLoginDeps{
			Authenticator: h.authn,
			Sessions:      h.sessions,
			Attempts:      h.attempts,
		}
		if h.password != nil {
			deps.Authenticator = h.password
		}
		if !h.sessionBearer {
			deps.Tokens = h.tokens
		}

		opts = append(opts, httpsec.EnableFormLogin(deps, h.loginOpts...))
	}

	opts = append(opts, httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, h.logoutOpts...))

	if !h.off {
		var reauthOpts []httpsec.ReauthenticationOption
		if !h.noReauthTokens {
			reauthOpts = append(reauthOpts, httpsec.WithReauthenticationTokens(h.tokens))
		}

		opts = append(opts, httpsec.EnableReauthentication(append(reauthOpts, h.reauthOpts...)...))
	}

	return append(opts, h.chainOpts...)
}

// build assembles the harness's chain carrying s.
func (h *reauthHarness) build(s *session.Session) (*httpsec.Chain, error) {
	return httpsec.New(h.options(s)...)
}

// fullSession is a live session past its second factor, as a re-proof needs.
func (h *reauthHarness) fullSession(t *testing.T, first factor.Kind) *session.Session {
	t.Helper()

	return h.newSession(t, first, session.MFASatisfied)
}

// get is a GET to target.
func get(r *http.Request, target string) *http.Request {
	return httptest.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
}

// TestEnableReauthentication pins how re-authentication is wired: every
// construction mistake is a configuration error from New naming its cause,
// the endpoints exist only when enabled and only under their prefix, and a
// request the endpoints do not claim passes through untouched.
func TestEnableReauthentication(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// wire configures the harness before the chain is built.
		wire func(h *reauthHarness)

		// request, when set, is served through the built chain, carrying a
		// full session; nil asserts on construction alone.
		request func(r *http.Request) *http.Request

		assert func(t *testing.T, out served, err error)
	}

	// refusedConfig is a construction error naming cause.
	refusedConfig := func(cause string) func(*testing.T, served, error) {
		return func(t *testing.T, _ served, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.ErrorContains(t, err, cause)
		}
	}

	with := func(opts ...httpsec.ReauthenticationOption) func(*reauthHarness) {
		return func(h *reauthHarness) { h.reauthOpts = opts }
	}

	passed := func(t *testing.T, out served, err error) {
		t.Helper()

		require.NoError(t, err)
		require.NoError(t, out.err)
		assert.True(t, out.handlerRan, "the request reached the application")
		assert.Zero(t, out.rec.Body.Len(), "the library wrote nothing")
	}

	// claimed is a re-proof request the endpoints answered, not the
	// application.
	claimed := func(t *testing.T, out served, err error) {
		t.Helper()

		require.NoError(t, err)
		require.Error(t, out.err)
		assert.False(t, out.handlerRan, "the request did not reach the application")
	}

	cases := []testCase{
		{
			name:   "the defaults build",
			wire:   func(*reauthHarness) {},
			assert: func(t *testing.T, _ served, err error) { require.NoError(t, err) },
		},
		{
			// Re-proof endpoints exist only when re-authentication is enabled:
			// "Off by default".
			name: "off by default: a POST to the password path reaches the application",
			wire: func(h *reauthHarness) { h.off = true },
			request: func(r *http.Request) *http.Request {
				return formRequest(r.Context(), reauthPasswordPath, "password=s3cret")
			},
			assert: passed,
		},
		{
			// "Consumer prefix", at the listing; the verify half of the
			// scenario lands with the verify endpoint.
			name: "a consumer prefix moves the endpoints",
			wire: with(httpsec.WithReauthenticationPrefix("/account/confirm/")),
			request: func(r *http.Request) *http.Request {
				return get(r, "/account/confirm/methods")
			},
			assert: func(t *testing.T, out served, err error) {
				t.Helper()

				require.NoError(t, err)
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan, "the listing answered under the consumer's prefix")
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "a consumer prefix frees the default one",
			wire: with(httpsec.WithReauthenticationPrefix("/account/confirm")),
			request: func(r *http.Request) *http.Request {
				return get(r, reauthMethodsPath)
			},
			assert: passed,
		},
		{
			name: "a GET to a verify path passes through",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return get(r, reauthVerifyTOTP)
			},
			assert: passed,
		},
		{
			name: "a POST to the listing path passes through",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return formRequest(r.Context(), reauthMethodsPath, "")
			},
			assert: passed,
		},
		{
			name: "a POST to an unknown path under the prefix passes through",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return formRequest(r.Context(), httpsec.DefaultReauthenticationPrefix+"/other", "")
			},
			assert: passed,
		},
		{
			name: "a GET to the password path passes through",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return get(r, reauthPasswordPath)
			},
			assert: passed,
		},
		{
			name: "a GET to a begin path passes through",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return get(r, httpsec.DefaultReauthenticationPrefix+"/begin/totp")
			},
			assert: passed,
		},
		{
			name: "a POST to a path that only starts like the verify path passes through",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return formRequest(r.Context(), httpsec.DefaultReauthenticationPrefix+"/verifyX", "")
			},
			assert: passed,
		},
		{
			name: "a GET to a path that only starts like the prefix passes through",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return get(r, httpsec.DefaultReauthenticationPrefix+"X/methods")
			},
			assert: passed,
		},
		{
			name: "a POST to a path that only starts like the password path passes through",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return formRequest(r.Context(), reauthPasswordPath+"X", "")
			},
			assert: passed,
		},
		{
			// The re-proofs themselves are not carried out yet; an admitted
			// one is still the endpoint's, never the application's.
			name: "an admitted re-proof never reaches the application",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return formRequest(r.Context(), reauthPasswordPath, "password=s3cret")
			},
			assert: claimed,
		},
		{
			name: "a POST under the begin path is the endpoint's",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return formRequest(r.Context(), httpsec.DefaultReauthenticationPrefix+"/begin/passkey", "")
			},
			assert: claimed,
		},
		{
			// "A method segment is required".
			name: "a POST to the bare verify path is the endpoint's, naming no method",
			wire: func(*reauthHarness) {},
			request: func(r *http.Request) *http.Request {
				return formRequest(r.Context(), httpsec.DefaultReauthenticationPrefix+"/verify/", "")
			},
			assert: func(t *testing.T, out served, err error) {
				t.Helper()

				claimed(t, out, err)
				require.ErrorIs(t, out.err, httpsec.ErrUnknownMFAMethod)
			},
		},
		{
			// "Nothing to re-prove with".
			name:   "neither the MFA slot nor form login",
			wire:   func(h *reauthHarness) { h.noMFA, h.noLogin = true, true },
			assert: refusedConfig("neither EnableMFA nor EnableFormLogin"),
		},
		{
			name: "form login alone builds",
			wire: func(h *reauthHarness) { h.noMFA = true },
			assert: func(t *testing.T, _ served, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "the MFA slot alone builds",
			wire: func(h *reauthHarness) { h.noLogin = true },
			assert: func(t *testing.T, _ served, err error) {
				require.NoError(t, err)
			},
		},
		{
			// "Second factor only without MFA".
			name: "second factor only without the MFA slot",
			wire: func(h *reauthHarness) {
				h.noMFA = true
				h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.RequireSecondFactorForReauthentication()}
			},
			assert: refusedConfig("RequireSecondFactorForReauthentication"),
		},
		{
			// "Empty prefix".
			name:   "an empty prefix",
			wire:   with(httpsec.WithReauthenticationPrefix("")),
			assert: refusedConfig("WithReauthenticationPrefix was given no prefix"),
		},
		{
			name:   "a prefix that matches no request path",
			wire:   with(httpsec.WithReauthenticationPrefix("reauth")),
			assert: refusedConfig(`WithReauthenticationPrefix was given "reauth"`),
		},
		{
			name:   "the root prefix",
			wire:   with(httpsec.WithReauthenticationPrefix("/")),
			assert: refusedConfig("root path"),
		},
		{
			// "Prefix collides with MFA verify".
			name:   "a prefix under the MFA verify prefix",
			wire:   with(httpsec.WithReauthenticationPrefix(httpsec.DefaultMFAVerifyPrefix)),
			assert: refusedConfig(`the MFA verify prefix "/mfa/verify"`),
		},
		{
			name:   "a prefix under the MFA begin prefix",
			wire:   with(httpsec.WithReauthenticationPrefix(httpsec.DefaultMFABeginPrefix + "/again")),
			assert: refusedConfig(`the MFA begin prefix "/mfa/begin"`),
		},
		{
			// The re-proof begin and verify paths of the prefix /mfa are the
			// MFA begin and verify prefixes themselves.
			name: "a re-proof prefix whose paths are the MFA prefixes",
			wire: with(httpsec.WithReauthenticationPrefix("/mfa")),
			assert: refusedConfig(`begin path "/mfa/begin" collides with ` +
				`the MFA begin prefix "/mfa/begin"`),
		},
		{
			name:   "the prefix is the logout path",
			wire:   with(httpsec.WithReauthenticationPrefix(httpsec.DefaultLogoutPath)),
			assert: refusedConfig(`the logout path "` + httpsec.DefaultLogoutPath + `"`),
		},
		{
			// Logout moved under the re-proof verify prefix would be answered
			// as a re-proof, whichever option came first.
			name: "the logout path under the re-proof verify prefix",
			wire: func(h *reauthHarness) {
				h.logoutOpts = []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/reauth/verify/out")}
			},
			assert: refusedConfig(`the logout path "/reauth/verify/out"`),
		},
		{
			name:   "the prefix is the form login path",
			wire:   with(httpsec.WithReauthenticationPrefix(httpsec.DefaultLoginPath)),
			assert: refusedConfig(`the form login path "` + httpsec.DefaultLoginPath + `"`),
		},
		{
			name: "the listing path is the MFA listing path",
			wire: func(h *reauthHarness) {
				h.mfaOpts = []httpsec.MFAOption{
					httpsec.WithMFAVerifyPrefix("/2fa/verify"),
					httpsec.WithMFABeginPrefix("/2fa/begin"),
					httpsec.WithMFAMethodListing(),
				}
				h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.WithReauthenticationPrefix("/mfa")}
			},
			assert: refusedConfig(`the MFA listing path "` + httpsec.DefaultMFAMethodListingPath + `"`),
		},
		{
			// "Enabled twice".
			name: "enabled twice",
			wire: func(h *reauthHarness) {
				h.chainOpts = []httpsec.Option{httpsec.EnableReauthentication(
					httpsec.WithReauthenticationPrefix("/again"),
					httpsec.WithReauthenticationTokens(h.tokens))}
			},
			assert: refusedConfig("EnableReauthentication was given twice"),
		},
		{
			// "No credential to issue".
			name: "a token-bearer chain without a token generator",
			wire: func(h *reauthHarness) {
				h.noReauthTokens = true
				h.chainOpts = []httpsec.Option{httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: h.tokens,
					Sessions: h.sessions,
					Users:    h.users,
				})}
			},
			assert: refusedConfig("WithReauthenticationTokens"),
		},
		{
			// A session-bearer chain issues the session reference itself.
			name: "a session-bearer chain with a token generator",
			wire: func(h *reauthHarness) {
				h.sessionBearer = true
				h.chainOpts = []httpsec.Option{httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
					Sessions: h.sessions,
					Users:    h.users,
				})}
			},
			assert: refusedConfig("WithReauthenticationTokens"),
		},
		{
			name: "a session-bearer chain without a token generator builds",
			wire: func(h *reauthHarness) {
				h.sessionBearer = true
				h.noReauthTokens = true
				h.chainOpts = []httpsec.Option{httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
					Sessions: h.sessions,
					Users:    h.users,
				})}
			},
			assert: func(t *testing.T, _ served, err error) { require.NoError(t, err) },
		},
		{
			name:   "an absent token generator",
			wire:   with(httpsec.WithReauthenticationTokens(nil)),
			assert: refusedConfig("WithReauthenticationTokens needs a token generator"),
		},
		{
			// "Zero lifetime".
			name:   "a zero challenge lifetime",
			wire:   with(httpsec.WithReauthenticationChallengeTTL(0)),
			assert: refusedConfig("WithReauthenticationChallengeTTL was given 0s"),
		},
		{
			name:   "a negative challenge lifetime",
			wire:   with(httpsec.WithReauthenticationChallengeTTL(-time.Minute)),
			assert: refusedConfig("WithReauthenticationChallengeTTL was given -1m0s"),
		},
		{
			name:   "a zero challenge limit",
			wire:   with(httpsec.WithReauthenticationChallengeLimit(0)),
			assert: refusedConfig("WithReauthenticationChallengeLimit was given 0"),
		},
		{
			name:   "a negative challenge limit",
			wire:   with(httpsec.WithReauthenticationChallengeLimit(-1)),
			assert: refusedConfig("WithReauthenticationChallengeLimit was given -1"),
		},
		{
			name:   "an absent challenge store",
			wire:   with(httpsec.WithReauthenticationChallengeStore(nil)),
			assert: refusedConfig("WithReauthenticationChallengeStore needs a one-time store"),
		},
		{
			name:   "an absent responder",
			wire:   with(httpsec.WithReauthenticationResponder(nil)),
			assert: refusedConfig("WithReauthenticationResponder was given no function"),
		},
		{
			name:   "an absent begin responder",
			wire:   with(httpsec.WithReauthenticationBeginResponder(nil)),
			assert: refusedConfig("WithReauthenticationBeginResponder was given no function"),
		},
		{
			name:   "an absent listing responder",
			wire:   with(httpsec.WithReauthenticationMethodsResponder(nil)),
			assert: refusedConfig("WithReauthenticationMethodsResponder was given no function"),
		},
		{
			name: "consumer challenge settings build",
			wire: with(
				httpsec.WithReauthenticationChallengeTTL(2*time.Minute),
				httpsec.WithReauthenticationChallengeLimit(3),
			),
			assert: func(t *testing.T, _ served, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newReauthHarness(t)
			tc.wire(h)

			s := h.fullSession(t, factor.Password)

			c, err := h.build(s)

			var out served
			if tc.request != nil && err == nil {
				base := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
				out = serve(t, c, tc.request(base))
			}

			tc.assert(t, out, err)
		})
	}
}

// pastTheGates publishes s, with its caller unless noCaller, after every gate
// has run: immediately inside the password-change gate. It stands in for a
// consumer who reordered the chain so a session reaches the re-proof endpoints
// without meeting its gate.
func pastTheGates(s *session.Session, noCaller bool) httpsec.Option {
	carrier := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if !noCaller {
			ex.Authentication = &authenticate.Authentication{Principal: testPrincipal(), Time: time.Now()}
			ex.SetContext(httpsec.WithCaller(ex.Context(), ex.Authentication))
		}

		ex.Session = s
		ex.SetContext(httpsec.WithSession(ex.Context(), s))

		return next(ex)
	})

	return httpsec.RegisterInterceptor(carrier, httpsec.After(httpsec.OrderPasswordChange))
}

// TestReauthAdmission pins that only a full session may re-prove: a request
// without a session or a resolved caller is refused as authentication
// required, a session owing a challenge or confined is refused by its own gate
// before the endpoints, and one that reaches them anyway, past a reordered
// chain, is refused by the endpoints as authentication required.
//
// It runs on the enrolment harness, which has every gate the requirement
// names: the recovery, enrolment, second-factor and password-change gates.
func TestReauthAdmission(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// session builds the session the case carries, nil for none.
		session func(t *testing.T, h *enrolHarness) *session.Session

		// reordered carries the session past every gate instead of at the
		// bearer's slot, and noCaller carries it without its caller.
		reordered, noCaller bool

		request func(r *http.Request) *http.Request
		assert  func(t *testing.T, out served)
	}

	full := func(state session.MFAState) func(*testing.T, *enrolHarness) *session.Session {
		return func(t *testing.T, h *enrolHarness) *session.Session {
			return h.sessionIn(t, factor.Password, state)
		}
	}

	owingPasswordChange := func(t *testing.T, h *enrolHarness) *session.Session {
		s := h.sessionIn(t, factor.Password, session.MFASatisfied)
		s.PasswordChangePending = true

		return s
	}

	enrolmentOnly := func(t *testing.T, h *enrolHarness) *session.Session {
		return h.enrolmentOnly(t, factor.Password)
	}

	recoveryPending := func(t *testing.T, h *enrolHarness) *session.Session {
		return h.recoveryPending(t)
	}

	// stillMarked is a session past its second factor that still carries
	// the enrolment confinement marker, which only the upgrade clears.
	stillMarked := func(t *testing.T, h *enrolHarness) *session.Session {
		s := enrolmentOnly(t, h)
		s.MFA = session.MFASatisfied

		return s
	}

	post := func(target string) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request { return formRequest(r.Context(), target, "") }
	}

	listing := func(r *http.Request) *http.Request { return get(r, reauthMethodsPath) }

	refusedAsUnauthenticated := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.False(t, out.handlerRan, "the endpoint refused the request itself")
		assert.Zero(t, out.rec.Body.Len(), "nothing was written")
	}

	challengedWith := func(kind policy.ChallengeKind) func(*testing.T, served) {
		return func(t *testing.T, out served) {
			t.Helper()

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch, "a gate refused the request")
			assert.Equal(t, kind, ch.Kind)
			assert.False(t, out.handlerRan)
			assert.Zero(t, out.rec.Body.Len(), "nothing was written")
		}
	}

	admitted := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.False(t, out.handlerRan, "the listing answered")
		assert.Equal(t, http.StatusOK, out.rec.Code)
		assert.JSONEq(t, `{"methods":[],"password":false}`, out.rec.Body.String())
	}

	cases := []testCase{
		{
			name:    "no session",
			request: post(reauthPasswordPath),
			assert:  refusedAsUnauthenticated,
		},
		{
			name:    "no session at the listing",
			request: listing,
			assert:  refusedAsUnauthenticated,
		},
		{
			name:      "a session without a resolved caller",
			session:   full(session.MFASatisfied),
			reordered: true,
			noCaller:  true,
			request:   listing,
			assert:    refusedAsUnauthenticated,
		},
		{
			name:    "a pending second factor meets the MFA gate",
			session: full(session.MFAPending),
			request: post(reauthVerifyTOTP),
			assert:  challengedWith(policy.ChallengeMFA),
		},
		{
			name:    "a pending password change meets the password-change gate",
			session: owingPasswordChange,
			request: post(reauthPasswordPath),
			assert:  challengedWith(policy.ChallengePasswordChange),
		},
		{
			name:    "an enrolment-only session meets the enrolment gate",
			session: enrolmentOnly,
			request: listing,
			assert:  challengedWith(policy.ChallengeMFAEnrolment),
		},
		{
			name:    "a recovery-pending session meets the recovery gate",
			session: recoveryPending,
			request: post(reauthPasswordPath),
			assert:  challengedWith(policy.ChallengeAccountRecovery),
		},
		{
			name:      "reordered: a pending second factor",
			session:   full(session.MFAPending),
			reordered: true,
			request:   post(reauthVerifyTOTP),
			assert:    refusedAsUnauthenticated,
		},
		{
			name:      "reordered: a pending password change",
			session:   owingPasswordChange,
			reordered: true,
			request:   post(reauthPasswordPath),
			assert:    refusedAsUnauthenticated,
		},
		{
			name:      "reordered: an enrolment-only session",
			session:   enrolmentOnly,
			reordered: true,
			request:   listing,
			assert:    refusedAsUnauthenticated,
		},
		{
			name:      "reordered: a recovery-pending session",
			session:   recoveryPending,
			reordered: true,
			request:   post(reauthPasswordPath),
			assert:    refusedAsUnauthenticated,
		},
		{
			name:      "reordered: a session still carrying the enrolment marker",
			session:   stillMarked,
			reordered: true,
			request:   listing,
			assert:    refusedAsUnauthenticated,
		},
		{
			name:    "a satisfied session is served",
			session: full(session.MFASatisfied),
			request: listing,
			assert:  admitted,
		},
		{
			name:    "a session never asked a second factor is served",
			session: full(session.MFANone),
			request: listing,
			assert:  admitted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)

			var s *session.Session
			if tc.session != nil {
				s = tc.session(t, h)
				h.pinned = s
			}

			carried := s
			if tc.reordered {
				carried = nil
				h.extra = append(h.extra, pastTheGates(s, tc.noCaller))
			}

			h.extra = append(h.extra,
				httpsec.EnablePasswordChangeGate(h.sessions),
				httpsec.EnableRecoveryGateForTest(),
				httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)))

			base := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			tc.assert(t, serve(t, h.chain(t, carried), tc.request(base)))
		})
	}
}

// TestReauthAdmissionRaisedChallenge pins that a request on which the policy
// phase raised a challenge of the consumer's own is not served, though the
// session itself is full: the endpoints refuse it as authentication required,
// and the gate enforcing the challenge stays the consumer's. It runs on a real
// bearer, whose per-request policy phase is what raises the challenge.
func TestReauthAdmissionRaisedChallenge(t *testing.T) {
	t.Parallel()

	const consumerChallenge = policy.ChallengeKind(100)

	type testCase struct {
		name   string
		raises bool
		assert func(t *testing.T, out served)
	}

	cases := []testCase{
		{
			name:   "a full session on a request carrying a consumer's raised challenge is refused",
			raises: true,
			assert: func(t *testing.T, out served) {
				t.Helper()

				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, out.handlerRan)
				assert.Zero(t, out.rec.Body.Len(), "nothing was written")
			},
		},
		{
			name: "the same session with nothing raised is served",
			assert: func(t *testing.T, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.False(t, out.handlerRan, "the listing answered")
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)
			s := h.newSession(t, factor.Password, session.MFASatisfied)

			var policies []policy.Policy
			if tc.raises {
				policies = append(policies, raisingDeclared{kind: consumerChallenge, phase: policy.PerRequest})
			} else {
				policies = append(policies, raisingDeclared{kind: consumerChallenge, phase: policy.PreAuthentication})
			}

			opts := append(h.clockOpt(),
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: h.tokens, Sessions: h.sessions, Users: h.users}),
				httpsec.WithPolicyEngine(engineOf(t, policies...)),
				httpsec.WithChallengeEnforcer(consumerChallenge),
				httpsec.EnableMFA([]mfa.Method{h.method}, httpsec.WithMFAVerifyLimiter(h.limiter), httpsec.WithMFATokens(h.tokens)),
				httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(h.tokens)))

			c, err := httpsec.New(opts...)
			require.NoError(t, err)

			req := get(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), reauthMethodsPath)
			req.Header.Set("Authorization", "Bearer "+mfaTokenFor(s.ID))

			tc.assert(t, serve(t, c, req))
		})
	}
}

// TestReauthMethods pins the method listing: what the session's user may
// re-prove with under the factor policy, as the default JSON document or
// through the consumer's responder, refused rather than shortened when a
// lookup fails.
func TestReauthMethods(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// wire configures the harness; first is the carried session's first
		// factor, a password login unless set.
		wire  func(h *reauthHarness)
		first factor.Kind

		assert func(t *testing.T, out served)
	}

	errLookup := errors.New("reauth_test: enrolment store unavailable for ana@example.com")

	lists := func(want string) func(*testing.T, served) {
		return func(t *testing.T, out served) {
			t.Helper()

			require.NoError(t, out.err)
			assert.False(t, out.handlerRan, "the endpoint answers the request itself")
			assert.Equal(t, http.StatusOK, out.rec.Code)
			assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))
			assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"),
				"the listing describes the user's factors, which no cache may keep")
			assert.JSONEq(t, want, out.rec.Body.String())
		}
	}

	refusedWithLookup := func(t *testing.T, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, errLookup, "the store's failure stays reachable")
		assert.NotContains(t, out.err.Error(), "ana@example.com", "the store's own text stays out")
		assert.False(t, out.handlerRan)
		assert.Zero(t, out.rec.Body.Len(), "no list was written")
	}

	var got []httpsec.ReauthenticationMethods

	cases := []testCase{
		{
			// "A TOTP holder".
			name: "a TOTP holder lists TOTP and not the password",
			wire: func(*reauthHarness) {},
			assert: lists(`{"methods":[{"name":"totp","channel":"authenticator-app","begins":false}],` +
				`"password":false}`),
		},
		{
			// "A user without a second factor".
			name:   "a user without a second factor lists the password",
			wire:   func(h *reauthHarness) { h.totpUnenrolled = true },
			assert: lists(`{"methods":[],"password":true}`),
		},
		{
			name:   "without the MFA slot the password is listed",
			wire:   func(h *reauthHarness) { h.noMFA = true },
			assert: lists(`{"methods":[],"password":true}`),
		},
		{
			name:   "without form login a user without a second factor has nothing",
			wire:   func(h *reauthHarness) { h.noLogin, h.totpUnenrolled = true, true },
			assert: lists(`{"methods":[],"password":false}`),
		},
		{
			// "Nothing to re-prove with", and "Second factor only" at the
			// listing.
			name: "second factor only: a user without a second factor has nothing",
			wire: func(h *reauthHarness) {
				h.totpUnenrolled = true
				h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.RequireSecondFactorForReauthentication()}
			},
			assert: lists(`{"methods":[],"password":false}`),
		},
		{
			name: "second factor only: a TOTP holder lists TOTP",
			wire: func(h *reauthHarness) {
				h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.RequireSecondFactorForReauthentication()}
			},
			assert: lists(`{"methods":[{"name":"totp","channel":"authenticator-app","begins":false}],` +
				`"password":false}`),
		},
		{
			name: "every enrolled method is listed in configuration order",
			wire: func(h *reauthHarness) {
				h.extra = []mfa.Method{&challengeStub{channel: testDeviceChannel, enrolled: true}}
			},
			assert: lists(`{"methods":[` +
				`{"name":"totp","channel":"authenticator-app","begins":false},` +
				`{"name":"passkey","channel":"authenticator-device","begins":true}],"password":false}`),
		},
		{
			// The same-channel rule does not apply to a re-proof: a session
			// that signed in with a passkey re-proves with it.
			name:  "a passkey login lists the passkey it holds",
			first: factor.Passkey,
			wire: func(h *reauthHarness) {
				h.totpUnenrolled = true
				h.extra = []mfa.Method{&challengeStub{channel: factor.Passkey.Channel(), enrolled: true}}
			},
			assert: lists(`{"methods":[{"name":"passkey","channel":"public-key","begins":true}],` +
				`"password":false}`),
		},
		{
			// "Lookup failure".
			name: "a lookup failure refuses",
			wire: func(h *reauthHarness) {
				h.extra = []mfa.Method{&challengeStub{channel: testDeviceChannel, enrolledErr: errLookup}}
			},
			assert: refusedWithLookup,
		},
		{
			// A user with no other second factor whose lookup fails is not
			// offered the password.
			name: "a lookup failure never downgrades to the password",
			wire: func(h *reauthHarness) {
				h.totpUnenrolled = true
				h.extra = []mfa.Method{&challengeStub{channel: testDeviceChannel, enrolledErr: errLookup}}
			},
			assert: refusedWithLookup,
		},
		{
			// "Consumer responder".
			name: "a consumer responder receives the same decision and owns its headers",
			wire: func(h *reauthHarness) {
				h.reauthOpts = []httpsec.ReauthenticationOption{httpsec.WithReauthenticationMethodsResponder(
					func(ex *httpsec.Exchange, m httpsec.ReauthenticationMethods) error {
						got = append(got, m)
						ex.Writer.WriteHeader(http.StatusNoContent)

						return nil
					})}
			},
			assert: func(t *testing.T, out served) {
				t.Helper()

				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Equal(t, http.StatusNoContent, out.rec.Code)
				assert.Empty(t, out.rec.Header().Get("Cache-Control"), "the consumer's responder owns its headers")
				require.Len(t, got, 1)
				assert.Equal(t, httpsec.ReauthenticationMethods{
					Methods: []httpsec.MFAMethod{{Name: "totp", Channel: factor.AuthenticatorApp}},
				}, got[0])
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Not parallel: the consumer-responder row records into got, which
			// the cases share.
			h := newReauthHarness(t)
			tc.wire(h)

			first := tc.first
			if first == "" {
				first = factor.Password
			}

			c, err := h.build(h.fullSession(t, first))
			require.NoError(t, err)

			base := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			tc.assert(t, serve(t, c, get(base, reauthMethodsPath)))
		})
	}
}
