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

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// completionRP is a relying party for testOIDCProvider over idp, whose redirect URL
// is the default callback path on origin: the provider's own origin for a chain that
// completes sign-ins on the server. The provider's subject is linked to
// oidcTestUserID.
func completionRP(t *testing.T, idp *oidcTestProvider, origin string) *oidc.RelyingParty {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id identity.UserID) (*identity.Details, error) {
			if id != oidcTestUserID {
				return nil, identity.ErrUserNotFound
			}

			return &identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil
		})

	links := oidc.NewMemoryLinkStore()
	require.NoError(t, links.Insert(t.Context(), oidc.Link{
		Provider: testOIDCProvider, Issuer: idp.srv.URL, Subject: oidcTestSubject,
		UserID: oidcTestUserID, CreatedAt: time.Now(),
	}))

	broker := must.Must(oidc.NewBroker(links, users))

	reg := idp.provider()
	reg.RedirectURL = origin + httpsec.DefaultOIDCCallbackPath + testOIDCProvider

	client := must.Must(outbound.New(outbound.WithHTTPClient(idp.srv.Client())))

	return must.Must(oidc.NewRelyingParty(must.Must(oidc.NewRegistry(reg)), broker,
		oidc.WithOutboundClient(client), oidc.WithFlowStore(must.Must(oidc.NewMemoryFlowStore()))))
}

// completionProvider is an OpenID Provider on opIssuer whose login page is loginURL.
func completionProvider(t *testing.T, loginURL string) *oidcprovider.Provider {
	t.Helper()

	return must.Must(oidcprovider.New(oidcprovider.Deps{
		Issuer:       opIssuer,
		Clients:      flowClients(),
		Keys:         tokenKeys(),
		Users:        NewMockUserLoader(gomock.NewController(t)),
		LoginURL:     loginURL,
		ConsentURL:   opIssuer + "/consent",
		LogoutURL:    opIssuer + "/logout-page",
		LoggedOutURL: opIssuer + "/bye",
	}))
}

// TestEnableOIDCLogin_ProviderCompletionWiring pins that every wiring under which
// server-side completion could not keep its guarantees fails at construction, naming
// the option, and that the wiring it needs builds (F28).
func TestEnableOIDCLogin_ProviderCompletionWiring(t *testing.T) {
	t.Parallel()

	// wiring is what a row changes of the valid chain.
	type wiring struct {
		noProvider      bool
		callbackSuccess bool
		redeemer        bool
		noHandoff       bool
		noUsers         bool
		foreignSessions bool
		rpOrigin        string
		loginURL        string
	}

	type testCase struct {
		name   string
		wiring wiring
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.ErrorContains(t, err, "WithOIDCProviderCompletion")
	}

	cases := []testCase{
		{
			name:   "the wiring completion needs builds",
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{name: "no OpenID Provider on the chain", wiring: wiring{noProvider: true}, assert: refused},
		{name: "a callback success handler", wiring: wiring{callbackSuccess: true}, assert: refused},
		{name: "a custom handoff redeemer", wiring: wiring{redeemer: true}, assert: refused},
		{name: "no handoff manager", wiring: wiring{noHandoff: true}, assert: refused},
		{name: "no user loader", wiring: wiring{noUsers: true}, assert: refused},
		{name: "a session manager other than the provider's", wiring: wiring{foreignSessions: true}, assert: refused},
		{
			name:   "a provider callback off the issuer's origin",
			wiring: wiring{rpOrigin: "https://other.example"},
			assert: func(t *testing.T, err error) {
				refused(t, err)
				assert.ErrorContains(t, err, `"`+testOIDCProvider+`"`)
			},
		},
		{name: "a login URL with its own query", wiring: wiring{loginURL: opIssuer + "/login?tenant=a"}, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := tc.wiring
			if w.rpOrigin == "" {
				w.rpOrigin = opIssuer
			}
			if w.loginURL == "" {
				w.loginURL = opIssuer + "/login"
			}

			provider := completionProvider(t, w.loginURL)
			sessions := reporting(t, provider)
			deps := httpsec.OIDCDeps{
				RelyingParty: completionRP(t, newOIDCTestProvider(t), w.rpOrigin),
				Handoff:      newTestHandoffManager(t),
				Users:        NewMockUserLoader(gomock.NewController(t)),
			}
			opts := []httpsec.OIDCOption{httpsec.WithOIDCProviderCompletion()}

			if w.noHandoff {
				deps.Handoff = nil
			}
			if w.noUsers {
				deps.Users = nil
			}
			if w.callbackSuccess {
				opts = append(opts, httpsec.WithOIDCCallbackSuccess(
					func(*httpsec.Exchange, oidc.CallbackResult, string) error { return nil }))
			}
			if w.redeemer {
				opts = append(opts, httpsec.WithOIDCHandoffRedeemer(newTestHandoffManager(t)))
			}
			if w.foreignSessions {
				opts = append(opts, httpsec.WithOIDCSessions(reporting(t, provider)))
			}

			chain := []httpsec.Option{
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
					Sessions: sessions, Users: NewMockUserLoader(gomock.NewController(t)),
				}),
				httpsec.EnableJWKSEndpoint(tokenKeys()),
				httpsec.EnableSecurityHeaders(),
				httpsec.EnableCSRFProtection(),
				httpsec.EnableOIDCLogin(deps, opts...),
			}
			if !w.noProvider {
				chain = append(chain, httpsec.EnableOIDCProvider(provider))
			}

			_, err := httpsec.New(chain...)
			tc.assert(t, err)
		})
	}
}

// completionLoginURL is the provider's login page in the completion chains.
const completionLoginURL = opIssuer + "/login"

// completionSetup is what a completion row changes of its chain.
type completionSetup struct {
	// users is OIDCDeps.Users; nil is the provider flow's own loader, which answers
	// every user as active.
	users identity.UserLoader
	// oidc are options beside completion on EnableOIDCLogin, and chain options
	// beside the chain's completion wiring.
	oidc []httpsec.OIDCOption
	// off builds the chain without WithOIDCProviderCompletion, and without a user
	// loader, which only completion takes.
	off bool
	// limiter replaces the resume limiter, which otherwise admits every source and
	// counts the failures recorded against it.
	limiter ratelimit.Limiter
	// pending replaces the provider's pending-request store.
	pending *downablePendingStore
	chain   func(t *testing.T, f *completionFlow) []httpsec.Option
}

// completionFlow is an OpenID Provider chain that also logs users in through an
// upstream provider, with server-side completion on: the fake upstream, and what a
// row reads the outcome through.
type completionFlow struct {
	*opFlow

	// setup is what the flow was built from, so a row reads its doubles back.
	setup completionSetup

	idp      *oidcTestProvider
	rp       *oidc.RelyingParty
	handoffs *oidc.MemoryHandoffStore
	events   *eventRecorder

	// charged counts the resume throttle's recorded failures, and cancelled the
	// held-recovery cancellations a login asked for.
	charged, cancelled atomic.Int64
}

// resumeChargeCounter is a resume limiter that admits every source and counts the
// failures recorded against them in charged.
func resumeChargeCounter(t *testing.T, charged *atomic.Int64) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) error {
			charged.Add(1)

			return nil
		})

	return l
}

func newCompletionFlow(t *testing.T, setup completionSetup) *completionFlow {
	t.Helper()

	f := &completionFlow{
		idp:      newOIDCTestProvider(t),
		handoffs: oidc.NewMemoryHandoffStore(),
		events:   &eventRecorder{},
	}
	f.rp = completionRP(t, f.idp, opIssuer)

	var provider []oidcprovider.Option
	if setup.pending != nil {
		provider = append(provider, oidcprovider.WithPendingRequestStore(setup.pending))
	}

	var limiter ratelimit.Limiter = resumeChargeCounter(t, &f.charged)
	if setup.limiter != nil {
		limiter = setup.limiter
	}

	f.opFlow = newOPFlow(t, flowSetup{
		provider: provider,
		endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCResumeLimiter(limiter)},
		chain: func(t *testing.T, w *opFlow) []httpsec.Option {
			t.Helper()

			users := setup.users
			if users == nil {
				users = w.users
			}

			opts := append([]httpsec.OIDCOption{httpsec.WithOIDCProviderCompletion()}, setup.oidc...)
			if setup.off {
				opts, users = setup.oidc, nil
			}

			// The flow as far as it is built, so a row's options can read its
			// session manager.
			f.opFlow = w

			var extra []httpsec.Option
			if setup.chain != nil {
				extra = setup.chain(t, f)
			}

			return append(append([]httpsec.Option{
				httpsec.EnableSecurityEvents(f.events.sink),
				httpsec.EnableOIDCLogin(httpsec.OIDCDeps{
					RelyingParty: f.rp,
					Handoff:      must.Must(oidc.NewHandoff(f.handoffs, w.users)),
					Users:        users,
				}, opts...),
			}, extra...),
				httpsec.CancelHeldAtLoginForTest(func(context.Context, identity.UserID) error {
					f.cancelled.Add(1)

					return nil
				}))
		},
	})

	return f
}

// signIn runs a federated login with destination next, from its start to the
// upstream's redirect back, which carries change, and returns the callback's answer.
func (f *completionFlow) signIn(t *testing.T, next string, change ...flowChange) flowAnswer {
	t.Helper()

	start := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		opIssuer+httpsec.DefaultOIDCAuthorizePath+testOIDCProvider+"?"+
			url.Values{httpsec.DefaultOIDCNextParam: {next}}.Encode(), nil)

	started := f.serve(t, start, nil)
	require.Equal(t, http.StatusFound, started.status, started.body)

	rpFlow := started.cookie(httpsec.DefaultOIDCFlowCookieName)
	require.NotNil(t, rpFlow, "the login's flow cookie is set")

	upstream := started.location(t).Query()
	callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		opIssuer+httpsec.DefaultOIDCCallbackPath+testOIDCProvider+"?"+
			url.Values{"code": {upstream.Get("nonce")}, "state": {upstream.Get("state")}}.Encode(), nil)

	return f.serve(t, callback, append([]flowChange{
		flowCookieOf(httpsec.DefaultOIDCFlowCookieName, rpFlow.Value),
	}, change...))
}

// parkedAt is the destination of the login page for handle.
func parkedAt(handle string) string {
	return completionLoginURL + "?" + url.Values{oidcprovider.HandleParam: {handle}}.Encode()
}

// sessions counts the linked user's stored sessions.
func (f *completionFlow) storedSessions(t *testing.T) int {
	t.Helper()

	n, err := f.sessions.CountActiveByUser(t.Context(), oidcTestUserID)
	require.NoError(t, err)

	return n
}

// handoffTo reads the destination and handoff code a conveyed login redirects to.
func handoffTo(t *testing.T, a flowAnswer) (*url.URL, string) {
	t.Helper()

	require.NoError(t, a.err)
	require.Equal(t, http.StatusFound, a.status, a.body)

	loc := a.location(t)
	code := loc.Query().Get(httpsec.DefaultOIDCHandoffParam)
	require.NotEmpty(t, code, "the login is conveyed by a handoff code")

	q := loc.Query()
	q.Del(httpsec.DefaultOIDCHandoffParam)
	loc.RawQuery = q.Encode()

	return loc, code
}

// TestOIDCCompletion_Conveyance pins which logins completion leaves to the ordinary
// handoff: a destination that is not the login page carrying one handle alone keeps
// the allowlisted handoff, or "/" (F27), while a qualifying one is completion's and
// is never replaced by "/", even with an empty allowlist.
func TestOIDCCompletion_Conveyance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  completionSetup
		next   func(handle string) string
		assert func(t *testing.T, f *completionFlow, handle string, a flowAnswer)
	}

	conveyedTo := func(want string) func(t *testing.T, f *completionFlow, handle string, a flowAnswer) {
		return func(t *testing.T, f *completionFlow, _ string, a flowAnswer) {
			t.Helper()

			loc, _ := handoffTo(t, a)
			assert.Equal(t, want, loc.String())
			assert.Zero(t, f.storedSessions(t), "the callback creates no session")
			assert.Zero(t, f.charged.Load(), "nothing was charged")
		}
	}

	allowed := completionSetup{oidc: []httpsec.OIDCOption{httpsec.WithOIDCAllowedRedirects("/welcome")}}

	cases := []testCase{
		{
			name:   "an allowlisted destination",
			setup:  allowed,
			next:   func(string) string { return "/welcome" },
			assert: conveyedTo("/welcome"),
		},
		{
			name:   "an extra parameter",
			next:   func(h string) string { return parkedAt(h) + "&x=1" },
			assert: conveyedTo("/"),
		},
		{
			name:   "a trailing slash",
			next:   func(h string) string { return completionLoginURL + "/?req=" + h },
			assert: conveyedTo("/"),
		},
		{
			name:   "a percent-encoded path",
			next:   func(h string) string { return opIssuer + "/%6Cogin?req=" + h },
			assert: conveyedTo("/"),
		},
		{
			name:   "another host",
			next:   func(h string) string { return "https://evil.example/login?req=" + h },
			assert: conveyedTo("/"),
		},
		{
			name:   "a relative destination",
			next:   func(h string) string { return "/login?req=" + h },
			assert: conveyedTo("/"),
		},
		{
			name:   "the login page carrying the handle, with completion off and an empty allowlist",
			setup:  completionSetup{off: true},
			next:   parkedAt,
			assert: conveyedTo("/"),
		},
		{
			name:  "the login page carrying the handle, with an empty allowlist",
			setup: completionSetup{chain: mfaRequired},
			next:  parkedAt,
			assert: func(t *testing.T, f *completionFlow, handle string, a flowAnswer) {
				t.Helper()

				loc, _ := handoffTo(t, a)
				assert.Equal(t, parkedAt(handle), loc.String(), "never replaced by /")
				assert.Zero(t, f.storedSessions(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCompletionFlow(t, tc.setup)
			handle, flow := f.park(t, flowWeb)

			a := f.signIn(t, tc.next(handle), flowCookieOf(flowCookie, flow))
			tc.assert(t, f, handle, a)
		})
	}
}

// mfaRequired is a policy engine requiring a second factor of every user, matching
// a federated login's assurance against f's relying party, and the MFA gate that
// enforces it.
func mfaRequired(t *testing.T, f *completionFlow) []httpsec.Option {
	t.Helper()

	method := totpLike(t)
	lookups := must.Must(mfa.LookupsFor(method))

	challenge := must.Must(policy.NewMFA(lookups))
	requirement := must.Must(policy.NewMFARequirement(nil, lookups,
		policy.WithMFARequiredForAll(), policy.WithFederatedAssuranceSource(f.rp)))

	return []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableMFA([]mfa.Method{method}),
	}
}

// errPendingDown is what a failing pending-request store answers.
var errPendingDown = errors.New("pending-request store down")

// downablePendingStore is a pending-request store whose reads can be made to fail
// once a row has parked its request, and which counts what is written to it.
type downablePendingStore struct {
	oidcprovider.PendingRequestStore

	down    atomic.Bool
	creates atomic.Int64
}

func (s *downablePendingStore) Create(ctx context.Context, r *oidcprovider.PendingRequest) error {
	s.creates.Add(1)

	return s.PendingRequestStore.Create(ctx, r)
}

func (s *downablePendingStore) Load(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
	if s.down.Load() {
		return nil, errPendingDown
	}

	return s.PendingRequestStore.Load(ctx, digest)
}

// TestOIDCCompletion_PreChecksHandle pins that completion checks the parked request
// before anything else happens (D7, step 2; F20, F38): an unknown handle, one expired
// before the callback, and one the browser's flow cookie does not bind are each
// answered with the unknown-handle refusal, charged to the source once; a handle past
// its login stage is refused the same, uncharged; a source over the resume limit is
// throttled before the request is looked up; a failing store is a dependency failure,
// uncharged. None leaves a session, a login event, a handoff or a held recovery
// touched, and the user is never loaded.
func TestOIDCCompletion_PreChecksHandle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// setup is what the row changes of the chain; the user loader and policy
		// are the row's own unless it sets them.
		setup func(t *testing.T) completionSetup
		// parked parks what the row needs, and returns the handle the login
		// starts for and the flow cookie the callback carries.
		parked func(t *testing.T, f *completionFlow) (handle, flow string)
		// assert reads the refusal; the nothing-created checks are common.
		assert func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64)
	}

	unknown := func(charged int64) func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64) {
		return func(t *testing.T, f *completionFlow, a flowAnswer, _ int64) {
			t.Helper()

			require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
			assert.Equal(t, charged, f.charged.Load(), "charged to the source")
		}
	}

	parkedWeb := func(t *testing.T, f *completionFlow) (string, string) {
		t.Helper()

		return f.park(t, flowWeb)
	}

	cases := []testCase{
		{
			name: "an unknown handle",
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				_, flow := f.park(t, flowWeb)

				return "rh.unknown", flow
			},
			assert: unknown(1),
		},
		{
			name: "a handle expired before the callback",
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				handle, flow := f.park(t, flowWeb)
				f.clk.Advance(10*time.Minute + time.Second)

				return handle, flow
			},
			assert: unknown(1),
		},
		{
			name: "a handle the browser's flow cookie does not bind",
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				handle, _ := f.park(t, flowWeb)
				_, other := f.park(t, flowWeb)

				return handle, other
			},
			assert: unknown(1),
		},
		{
			name: "a handle parked at the consent stage",
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				// The provider's own resume moves the request on to consent, since
				// flowWeb needs it.
				handle, flow := f.park(t, flowWeb)
				// Another user's session, so the row's own counts stay the linked user's.
				s, err := f.sessions.Create(t.Context(), "someone-else", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				_, err = f.p.Resume(t.Context(), oidcprovider.ResumeInput{
					Handle:     handle,
					FlowSecret: flow,
					SignIn: &oidcprovider.SignIn{
						User: s.UserID, Family: s.FamilyID,
						AuthenticatedAt: s.AuthenticatedAt, AbsoluteExpiresAt: s.AbsoluteExpiresAt,
					},
					IdleTimeout: f.sessions.IdleTimeout(),
				})
				require.NoError(t, err)
				require.Equal(t, oidcprovider.StageConsent, f.stage(t, handle, flow))

				return handle, flow
			},
			assert: unknown(0),
		},
		{
			name: "a source over the resume limit",
			setup: func(t *testing.T) completionSetup {
				t.Helper()

				// No failure is expected to be recorded: the source is turned away
				// before the request is looked up.
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				return completionSetup{limiter: l}
			},
			parked: parkedWeb,
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, lookups int64) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
				assert.Zero(t, lookups, "the pending request was never looked up")
			},
		},
		{
			name: "a failing pending-request store",
			setup: func(t *testing.T) completionSetup {
				t.Helper()

				store := &downablePendingStore{
					PendingRequestStore: must.Must(oidcprovider.NewMemoryPendingRequestStore()),
				}

				return completionSetup{pending: store}
			},
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				handle, flow := f.park(t, flowWeb)
				f.setup.pending.down.Store(true)

				return handle, flow
			},
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, _ int64) {
				t.Helper()

				require.ErrorIs(t, a.err, errPendingDown)
				assert.NotErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				assert.NotErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
				assert.Zero(t, f.charged.Load(), "a store failure is not the source's")
				assert.Equal(t, int64(1), f.setup.pending.creates.Load(), "nothing written beyond the parked request")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var setup completionSetup
			if tc.setup != nil {
				setup = tc.setup(t)
			}

			// A loader expecting no call: nothing is loaded before the check.
			setup.users = NewMockUserLoader(gomock.NewController(t))
			setup.chain = mfaRequired

			f := newCompletionFlow(t, setup)
			f.setup = setup
			handle, flow := tc.parked(t, f)

			before := f.pending.loads.Load()
			a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))

			tc.assert(t, f, a, f.pending.loads.Load()-before)
			assert.Empty(t, a.header.Get("Location"), "no redirect")
			assert.Zero(t, f.storedSessions(t), "no session")
			assert.Empty(t, f.events.named(event.AuthnLoginSuccess), "no login event")
			assert.Empty(t, f.events.named(event.SessionCreated), "no session event")
			assert.Zero(t, f.cancelled.Load(), "held recoveries untouched")
			assert.Zero(t, f.storedHandoffs(t), "no handoff issued")
		})
	}
}

// storedHandoffs counts the handoff codes the store holds, by purging all of them:
// it is the last thing a row reads from the store.
func (f *completionFlow) storedHandoffs(t *testing.T) int {
	t.Helper()

	n, err := f.handoffs.DeleteExpired(t.Context(), time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	return n
}

var (
	errCompletionDenied     = errors.New("oidc_completion_test: the consumer's policy denies")
	errCompletionLoaderDown = errors.New("oidc_completion_test: the user store is down")
)

// loaderAnswering is OIDCDeps.Users answering every load with details and err.
func loaderAnswering(t *testing.T, details *identity.Details, err error) identity.UserLoader {
	t.Helper()

	l := NewMockUserLoader(gomock.NewController(t))
	l.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(details, err).AnyTimes()

	return l
}

// TestOIDCCompletion_PolicyAndFallback pins D7's steps 3 and 4 and D8: completion
// loads the user and refuses a missing, disabled or mismatched one as a redemption
// does (F21); a policy denial is the policy's reason; a policy that owes a step —
// a second factor the upstream's amr does not meet, a password change the stored
// time requires — falls back to the handoff to the login page carrying the handle
// (F22); and an amr that meets the requirement proceeds. None of them stores a
// session.
func TestOIDCCompletion_PolicyAndFallback(t *testing.T) {
	t.Parallel()

	active := &identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}

	type testCase struct {
		name   string
		setup  completionSetup
		amr    []string
		assert func(t *testing.T, f *completionFlow, handle string, a flowAnswer)
	}

	refusedAs := func(want error) func(t *testing.T, f *completionFlow, _ string, a flowAnswer) {
		return func(t *testing.T, f *completionFlow, _ string, a flowAnswer) {
			t.Helper()

			require.ErrorIs(t, a.err, want)
			assert.Empty(t, a.header.Get("Location"), "no redirect")
			assert.Zero(t, f.storedHandoffs(t), "no handoff issued")
		}
	}

	fallsBack := func(t *testing.T, f *completionFlow, handle string, a flowAnswer) {
		t.Helper()

		loc, _ := handoffTo(t, a)
		assert.Equal(t, parkedAt(handle), loc.String(), "the handoff goes to the login page, handle kept")
		assert.Equal(t, 1, f.storedHandoffs(t))
	}

	cases := []testCase{
		{
			name:   "a user the loader does not know",
			setup:  completionSetup{users: loaderAnswering(t, nil, identity.ErrUserNotFound)},
			assert: refusedAs(oidc.ErrInvalidHandoff),
		},
		{
			name:   "a loader answering no user",
			setup:  completionSetup{users: loaderAnswering(t, nil, nil)},
			assert: refusedAs(oidc.ErrInvalidHandoff),
		},
		{
			name: "a disabled user",
			setup: completionSetup{users: loaderAnswering(t,
				&identity.Details{ID: oidcTestUserID, Username: "ada@example.com"}, nil)},
			assert: refusedAs(oidc.ErrInvalidHandoff),
		},
		{
			name: "a loader answering another user",
			setup: completionSetup{users: loaderAnswering(t,
				&identity.Details{ID: "u-9", Username: "eve@example.com", Active: true}, nil)},
			assert: refusedAs(oidc.ErrInvalidHandoff),
		},
		{
			name:  "a loader that fails",
			setup: completionSetup{users: loaderAnswering(t, nil, errCompletionLoaderDown)},
			assert: func(t *testing.T, f *completionFlow, h string, a flowAnswer) {
				t.Helper()

				refusedAs(errCompletionLoaderDown)(t, f, h, a)
				assert.NotErrorIs(t, a.err, oidc.ErrInvalidHandoff, "an outage, not a refusal")
				assert.NotContains(t, a.err.Error(), errCompletionLoaderDown.Error(), "behind fixed text")
			},
		},
		{
			name: "the policy denies",
			setup: completionSetup{chain: func(t *testing.T, _ *completionFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.WithPolicyEngine(denyingEngine(t, errCompletionDenied))}
			}},
			assert: refusedAs(errCompletionDenied),
		},
		{
			name:   "a second factor the upstream's amr does not meet",
			setup:  completionSetup{chain: mfaRequired},
			amr:    []string{"pwd"},
			assert: fallsBack,
		},
		{
			name: "a password change the stored time requires",
			setup: completionSetup{
				users: loaderAnswering(t, &identity.Details{
					ID: oidcTestUserID, Username: "ada@example.com", Active: true,
					PasswordChangedAt: time.Now().Add(-48 * time.Hour),
				}, nil),
				chain: func(t *testing.T, f *completionFlow) []httpsec.Option {
					t.Helper()

					age := must.Must(policy.NewPasswordAge(policy.WithMaxPasswordAge(24 * time.Hour)))

					return append(passwordChangeOn(t, f.sessions), httpsec.WithPolicyEngine(engineOf(t, age)))
				},
			},
			assert: fallsBack,
		},
		{
			name:  "a second factor the upstream's amr meets",
			setup: completionSetup{users: loaderAnswering(t, active, nil), chain: mfaRequired},
			amr:   []string{"mfa"},
			assert: func(t *testing.T, f *completionFlow, _ string, a flowAnswer) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrProviderSignInUnfinishedForTest, "it proceeds past the policy")
				assert.Zero(t, f.storedHandoffs(t), "no handoff")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCompletionFlow(t, tc.setup)
			if tc.amr != nil {
				f.idp.assert(tc.amr, "")
			}

			handle, flow := f.park(t, flowWeb)

			a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
			tc.assert(t, f, handle, a)

			assert.Zero(t, f.storedSessions(t), "no session")
			assert.Zero(t, f.charged.Load(), "a live handle is charged nothing")
			assert.Zero(t, f.cancelled.Load(), "held recoveries untouched")
		})
	}
}
