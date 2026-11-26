package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// completionRP is a relying party for testOIDCProvider over idp, whose redirect URL
// is the default callback path on origin: the provider's own origin for a chain that
// completes sign-ins on the server. The provider's subject is linked to
// oidcTestUserID, whom the broker's principal names with role admin.
//
// unlinked leaves the subject linked to no one, so the broker answers
// oidc.ErrNoLinkedAccount.
func completionRP(t *testing.T, idp *oidcTestProvider, origin string, unlinked ...bool) *oidc.RelyingParty {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id identity.UserID) (*identity.Details, error) {
			if id != oidcTestUserID {
				return nil, identity.ErrUserNotFound
			}

			// The broker's principal carries a role the user's stored details do
			// not: completion must build the session from the stored ones.
			return &identity.Details{
				ID: oidcTestUserID, Username: "ada@example.com", Active: true,
				Roles: []*identity.AssignedRole{{ID: "r-admin", Name: "admin"}},
			}, nil
		})

	links := oidc.NewMemoryLinkStore()
	if len(unlinked) == 0 || !unlinked[0] {
		require.NoError(t, links.Insert(t.Context(), oidc.Link{
			Provider: testOIDCProvider, Issuer: idp.srv.URL, Subject: oidcTestSubject,
			UserID: oidcTestUserID, CreatedAt: time.Now(),
		}))
	}

	broker := must.Must(oidc.NewBroker(links, users))

	reg := idp.provider()
	reg.RedirectURL = origin + httpsec.DefaultOIDCCallbackPath + testOIDCProvider

	out := []outbound.Option{outbound.WithHTTPClient(idp.srv.Client())}
	if strings.HasPrefix(origin, "http://") {
		// A loopback http issuer's chain is called back over plain http.
		out = append(out, outbound.WithAllowedSchemes("https", "http"))
	}

	client := must.Must(outbound.New(out...))

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
		// usersOnly keeps OIDCDeps.Users and leaves completion off.
		usersOnly bool
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
		{name: "a user loader without completion", wiring: wiring{usersOnly: true}, assert: refused},
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

			if w.usersOnly {
				opts = nil
			}
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
	// issuer is the OpenID Provider's issuer, which the chain also serves the
	// login from; empty is opIssuer.
	issuer string
	// users is OIDCDeps.Users; nil is the provider flow's own loader, which answers
	// every user as active.
	users identity.UserLoader
	// oidc are options beside completion on EnableOIDCLogin, and chain options
	// beside the chain's completion wiring.
	oidc []httpsec.OIDCOption
	// off builds the chain without WithOIDCProviderCompletion, and without a user
	// loader, which only completion takes.
	off bool
	// noHandoff builds OIDC login without a handoff manager, as a cookie chain,
	// which conveys logins in the callback, is built.
	noHandoff bool
	// limiter replaces the resume limiter, which otherwise admits every source and
	// counts the failures recorded against it.
	limiter ratelimit.Limiter
	// pending replaces the provider's pending-request store.
	pending *downablePendingStore
	// codes replaces the provider's code store, so a row can read the codes held.
	codes *oidcprovider.MemoryCodeStore
	// provider are options of the OpenID Provider beside the pending and code stores.
	provider []oidcprovider.Option
	// endpoint are options of the OpenID Provider's endpoints beside the resume
	// limiter.
	endpoint []httpsec.OIDCProviderOption
	// sessions are options of the session manager the chain shares.
	sessions []session.Option
	// bearer replaces the chain's session bearer.
	bearer func(t *testing.T, w *opFlow) httpsec.Option
	// unlinked links the upstream's subject to no one.
	unlinked bool
	// broker replaces the relying party's broker, which otherwise is completionRP's.
	broker func(t *testing.T, idp *oidcTestProvider) oidc.IdentityBroker
	// rp replaces the relying party, whose redirect URL must be on origin.
	rp func(t *testing.T, idp *oidcTestProvider, origin string) *oidc.RelyingParty
	// clients are registered beside the provider flow's own.
	clients []oidcprovider.Client
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
	// cancelFails, when set, is the error the recovery-cancellation seam answers.
	cancelFails atomic.Pointer[error]

	// sessionSeen records whether a consumer interceptor outside OIDC login,
	// registered by observeSession, found a session on the exchange or its
	// context once the callback returned.
	sessionSeen atomic.Bool
}

// observeSession is a consumer interceptor registered outside OIDC login, which
// records in f.sessionSeen whether, once the inner chain has returned, the
// exchange or its context still carries a session: what a consumer's error
// handling sitting there reads through the chain's public accessors.
func observeSession(f *completionFlow) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		err := next(ex)

		_, inContext := httpsec.SessionFromContext(ex.Context())
		if ex.Session != nil || inContext {
			f.sessionSeen.Store(true)
		}

		return err
	}), httpsec.OrderOIDC-1)
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
	origin := setup.issuer
	if origin == "" {
		origin = opIssuer
	}

	f.rp = completionRP(t, f.idp, origin, setup.unlinked)
	if setup.broker != nil {
		f.rp = brokeredRP(t, f.idp, origin, setup.broker(t, f.idp))
	}

	if setup.rp != nil {
		f.rp = setup.rp(t, f.idp, origin)
	}

	provider := append([]oidcprovider.Option(nil), setup.provider...)
	if setup.pending != nil {
		provider = append(provider, oidcprovider.WithPendingRequestStore(setup.pending))
	}

	if setup.codes != nil {
		provider = append(provider, oidcprovider.WithCodeStore(setup.codes))
	}

	var limiter ratelimit.Limiter = resumeChargeCounter(t, &f.charged)
	if setup.limiter != nil {
		limiter = setup.limiter
	}

	f.opFlow = newOPFlow(t, flowSetup{
		issuer:   setup.issuer,
		provider: provider,
		clients:  setup.clients,
		sessions: setup.sessions,
		bearer:   setup.bearer,
		endpoint: append([]httpsec.OIDCProviderOption{httpsec.WithOIDCResumeLimiter(limiter)}, setup.endpoint...),
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

			var handoff *oidc.Handoff
			if !setup.noHandoff {
				handoff = must.Must(oidc.NewHandoff(f.handoffs, w.users))
			}

			return append(append([]httpsec.Option{
				httpsec.EnableSecurityEvents(f.events.sink),
				httpsec.EnableOIDCLogin(httpsec.OIDCDeps{
					RelyingParty: f.rp,
					Handoff:      handoff,
					Users:        users,
				}, opts...),
			}, extra...),
				httpsec.CancelHeldAtLoginForTest(func(context.Context, identity.UserID) error {
					f.cancelled.Add(1)

					if err := f.cancelFails.Load(); err != nil {
						return *err
					}

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

	return f.callBack(t, f.startSSO(t, next), change...)
}

// ssoLogin is a federated login started and not yet called back: the relying
// party's flow cookie it set, and the state and nonce the upstream was sent.
type ssoLogin struct {
	rpFlow, state, nonce string
}

// startSSO starts a federated login with destination next.
func (f *completionFlow) startSSO(t *testing.T, next string) ssoLogin {
	t.Helper()

	start := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		f.issuer+httpsec.DefaultOIDCAuthorizePath+testOIDCProvider+"?"+
			url.Values{httpsec.DefaultOIDCNextParam: {next}}.Encode(), nil)

	started := f.serve(t, start, nil)
	require.Equal(t, http.StatusFound, started.status, started.body)

	rpFlow := started.cookie(httpsec.DefaultOIDCFlowCookieName)
	require.NotNil(t, rpFlow, "the login's flow cookie is set")

	upstream := started.location(t).Query()

	return ssoLogin{rpFlow: rpFlow.Value, state: upstream.Get("state"), nonce: upstream.Get("nonce")}
}

// callBack is the upstream's redirect back for login, carrying the relying party's
// flow cookie login names, and change.
func (f *completionFlow) callBack(t *testing.T, login ssoLogin, change ...flowChange) flowAnswer {
	t.Helper()

	callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		f.issuer+httpsec.DefaultOIDCCallbackPath+testOIDCProvider+"?"+
			url.Values{"code": {login.nonce}, "state": {login.state}}.Encode(), nil)

	return f.serve(t, callback, append([]flowChange{
		flowCookieOf(httpsec.DefaultOIDCFlowCookieName, login.rpFlow),
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

// errRecoveryCancelDown is what a failing recovery-cancellation answers.
var errRecoveryCancelDown = errors.New("recovery cancellation down")

// downablePendingStore is a pending-request store whose reads can be made to fail
// once a row has parked its request, and which counts what is written to it.
type downablePendingStore struct {
	oidcprovider.PendingRequestStore

	down    atomic.Bool
	creates atomic.Int64

	// downAfterNext lets the next read through and fails every read after it: a
	// store that answered the pre-check and fails the resume.
	downAfterNext atomic.Bool

	// onLoad, when a row sets it, runs inside each read before the store answers,
	// and fails the read when it fails: a caller that hangs up mid-read.
	onLoad func(ctx context.Context) error

	// onAdvance, when a row sets it before the request, runs inside each stage
	// spend, before the store writes, and fails the spend when it fails.
	onAdvance func(ctx context.Context, signIn *oidcprovider.SignIn) error
}

func (s *downablePendingStore) Advance(
	ctx context.Context, digest []byte, from, to oidcprovider.Stage, signIn *oidcprovider.SignIn,
) error {
	if s.onAdvance != nil {
		if err := s.onAdvance(ctx, signIn); err != nil {
			return err
		}
	}

	return s.PendingRequestStore.Advance(ctx, digest, from, to, signIn)
}

func (s *downablePendingStore) Create(ctx context.Context, r *oidcprovider.PendingRequest) error {
	s.creates.Add(1)

	return s.PendingRequestStore.Create(ctx, r)
}

func (s *downablePendingStore) Load(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
	if s.onLoad != nil {
		if err := s.onLoad(ctx); err != nil {
			return nil, err
		}
	}

	if s.down.Load() {
		return nil, errPendingDown
	}

	if s.downAfterNext.CompareAndSwap(true, false) {
		s.down.Store(true)
	}

	return s.PendingRequestStore.Load(ctx, digest)
}

// TestOIDCCompletion_PreChecksHandle pins that completion checks the parked request
// before anything else happens (D7, step 2; F20, F38): an unknown handle, one expired
// past its grace window, and one the browser's flow cookie does not bind are each
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
			name: "a handle expired before the callback, past its grace window",
			parked: func(t *testing.T, f *completionFlow) (string, string) {
				t.Helper()

				handle, flow := f.park(t, flowWeb)
				// The default lifetime and grace window, both 10 minutes (D7).
				f.clk.Advance(20*time.Minute + time.Second)

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
			assert: func(t *testing.T, _ *completionFlow, a flowAnswer, lookups int64) {
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

// TestOIDCCompletion_PlainHTTP pins that completion applies the resume endpoint's
// transport guard before anything else (D7, step 2; F57): a qualifying callback not
// made over TLS, while the provider does not allow plain HTTP, is refused as an
// unknown handle with no pending-request lookup, no session, nothing resumed and no
// browser-session cookie; a provider on a loopback http issuer, which allows plain
// HTTP, completes the same callback.
func TestOIDCCompletion_PlainHTTP(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		issuer string // empty is opIssuer, over https
		// flowCookie is the OpenID Provider's flow cookie for the issuer.
		flowCookie string
		assert     func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, lookups int64)
	}

	cases := []testCase{
		{
			name:       "over plain http while the provider insists on TLS: refused before any lookup",
			flowCookie: flowCookie,
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, lookups int64) {
				t.Helper()

				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				assert.Zero(t, lookups, "the pending request was never looked up")
				assert.Zero(t, f.charged.Load(), "not charged: the source was never admitted")
				assert.Empty(t, a.header.Get("Location"), "no redirect")
				assert.Nil(t, a.cookie(flowSession), "no browser-session cookie")
				assert.Nil(t, a.cookie(flowSessionPlain), "no browser-session cookie")
				assert.Zero(t, f.storedSessions(t), "no session")
				assert.Zero(t, f.cancelled.Load(), "held recoveries untouched")
				assert.Zero(t, f.storedHandoffs(t), "no handoff issued")
				assert.Empty(t, f.events.named(event.SessionCreated), "no session event")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "nothing resumed")
			},
		},
		{
			name:       "over plain http on a loopback http issuer, which allows it: completed",
			issuer:     flowLoopback,
			flowCookie: flowCookiePlain,
			assert: func(t *testing.T, f *completionFlow, _, _ string, a flowAnswer, lookups int64) {
				t.Helper()

				require.NoError(t, a.err)
				require.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Positive(t, lookups, "the pending request was looked up")
				loc := a.location(t)
				assert.Equal(t, rpCallback, loc.Scheme+"://"+loc.Host+loc.Path)
				assert.NotEmpty(t, loc.Query().Get("code"), "an authorization code")
				browser := a.cookie(flowSessionPlain)
				require.NotNil(t, browser, "the browser-session cookie is set")
				assert.False(t, browser.Secure)
				assert.Equal(t, 1, f.storedSessions(t))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCompletionFlow(t, completionSetup{issuer: tc.issuer})
			handle, flow := f.parkIn(t, tc.flowCookie, flowFirstParty)

			login := f.startSSO(t, f.issuer+"/login?"+url.Values{oidcprovider.HandleParam: {handle}}.Encode())
			before := f.pending.loads.Load()
			a := f.callBack(t, login, flowCookieOf(tc.flowCookie, flow), flowPlainHTTP)

			tc.assert(t, f, handle, flow, a, f.pending.loads.Load()-before)
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
// does (F21), returning to the login page with access_denied, and a loader failure
// with server_error; a policy denial returns with access_denied; a policy that owes a step —
// a second factor the upstream's amr does not meet, a password change the stored
// time requires — falls back to the handoff to the login page carrying the handle
// (F22), storing no session; and an amr that meets the requirement completes the
// sign-in.
func TestOIDCCompletion_PolicyAndFallback(t *testing.T) {
	t.Parallel()

	active := &identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}

	type testCase struct {
		name   string
		setup  completionSetup
		amr    []string
		assert func(t *testing.T, f *completionFlow, handle string, a flowAnswer)
	}

	// A refusal returns to the login page with its code (D3, D4).
	refusedAs := func(code string) func(t *testing.T, f *completionFlow, handle string, a flowAnswer) {
		return func(t *testing.T, f *completionFlow, handle string, a flowAnswer) {
			t.Helper()

			require.NoError(t, a.err, "nothing reached the error handling")
			require.Equal(t, http.StatusSeeOther, a.status, a.body)
			assert.Equal(t, parkedReturn(handle, httpsec.DefaultOIDCLoginErrorParam, code), a.header.Get("Location"))
			assert.Zero(t, f.storedHandoffs(t), "no handoff issued")
			assert.Zero(t, f.storedSessions(t), "no session")
			assert.Zero(t, f.cancelled.Load(), "held recoveries untouched")
		}
	}

	fallsBack := func(t *testing.T, f *completionFlow, handle string, a flowAnswer) {
		t.Helper()

		loc, _ := handoffTo(t, a)
		assert.Equal(t, parkedAt(handle), loc.String(), "the handoff goes to the login page, handle kept")
		assert.Equal(t, 1, f.storedHandoffs(t))
		assert.Zero(t, f.storedSessions(t), "no session")
		assert.Zero(t, f.cancelled.Load(), "held recoveries untouched")
	}

	cases := []testCase{
		{
			name:   "a user the loader does not know",
			setup:  completionSetup{users: loaderAnswering(t, nil, identity.ErrUserNotFound)},
			assert: refusedAs(oidcprovider.CodeAccessDenied),
		},
		{
			name:   "a loader answering no user",
			setup:  completionSetup{users: loaderAnswering(t, nil, nil)},
			assert: refusedAs(oidcprovider.CodeAccessDenied),
		},
		{
			name: "a disabled user",
			setup: completionSetup{users: loaderAnswering(t,
				&identity.Details{ID: oidcTestUserID, Username: "ada@example.com"}, nil)},
			assert: refusedAs(oidcprovider.CodeAccessDenied),
		},
		{
			name: "a loader answering another user",
			setup: completionSetup{users: loaderAnswering(t,
				&identity.Details{ID: "u-9", Username: "eve@example.com", Active: true}, nil)},
			assert: refusedAs(oidcprovider.CodeAccessDenied),
		},
		{
			name:   "a loader that fails",
			setup:  completionSetup{users: loaderAnswering(t, nil, errCompletionLoaderDown)},
			assert: refusedAs(oidcprovider.CodeServerError),
		},
		{
			name: "the policy denies",
			setup: completionSetup{chain: func(t *testing.T, _ *completionFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.WithPolicyEngine(denyingEngine(t, errCompletionDenied))}
			}},
			assert: refusedAs(oidcprovider.CodeAccessDenied),
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

				require.NoError(t, a.err, "it proceeds past the policy")
				assert.Equal(t, http.StatusSeeOther, a.status, a.body)
				assert.Zero(t, f.storedHandoffs(t), "no handoff")
				assert.Equal(t, 1, f.storedSessions(t), "the sign-in completes on the server")
				assert.Equal(t, int64(1), f.cancelled.Load(), "held recoveries cancelled at the sign-in")
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

			assert.Zero(t, f.charged.Load(), "a live handle is charged nothing")
		})
	}
}

// owingUntilFinished is a post-authentication policy owing a password change while
// owed holds, and allowing once it is cleared: the page finishing the step between
// the callback's fallback and the redemption of its handoff code.
func owingUntilFinished(t *testing.T, owed *atomic.Bool) policy.Policy {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: owed until finished").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, *policy.Input) policy.Decision {
			if owed.Load() {
				return policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengePasswordChange}
			}

			return policy.Decision{Outcome: policy.Allow}
		})

	return p
}

// redeem posts code to the handoff endpoint, as the login page's script does.
func (f *completionFlow) redeem(t *testing.T, code string) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, opIssuer+httpsec.DefaultOIDCHandoffPath,
		strings.NewReader(url.Values{httpsec.DefaultOIDCHandoffParam: {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return f.serve(t, r, nil)
}

// TestOIDCCompletion_FallbackRedemptionKeepsDestination pins the allowlist carve-out
// in the answer to the fallback's redemption (D8, F37): with completion on and an
// empty allowlist, the handoff code an owed step fell back with is redeemed to the
// parked destination, never "/". With completion off, the same recorded destination
// is resolved against the allowlist as before, to "/".
func TestOIDCCompletion_FallbackRedemptionKeepsDestination(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		off    bool
		assert func(t *testing.T, handle string, next string)
	}

	cases := []testCase{
		{
			name: "completion on",
			assert: func(t *testing.T, handle string, next string) {
				t.Helper()

				assert.Equal(t, parkedAt(handle), next, "the parked destination, never /")
			},
		},
		{
			name: "completion off",
			off:  true,
			assert: func(t *testing.T, _ string, next string) {
				t.Helper()

				assert.Equal(t, "/", next, "resolved against the empty allowlist")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var owed atomic.Bool
			owed.Store(true)

			f := newCompletionFlow(t, completionSetup{
				off: tc.off,
				chain: func(t *testing.T, f *completionFlow) []httpsec.Option {
					t.Helper()

					return append(passwordChangeOn(t, f.sessions),
						httpsec.WithPolicyEngine(engineOf(t, owingUntilFinished(t, &owed))))
				},
			})
			handle, flow := f.park(t, flowWeb)

			_, code := handoffTo(t, f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow)))
			require.Zero(t, f.storedSessions(t), "the fallback stores no session")

			owed.Store(false)

			a := f.redeem(t, code)
			require.NoError(t, a.err)
			require.Equal(t, http.StatusOK, a.status, a.body)

			var doc struct {
				Next string `json:"next"`
			}
			require.NoError(t, json.Unmarshal([]byte(a.body), &doc), a.body)

			tc.assert(t, handle, doc.Next)
		})
	}
}

// completionJudged records what the chain's policies were handed for a completed
// sign-in: the roles of the principal each phase judged, and the session the
// per-request phase judged.
type completionJudged struct {
	mu                   sync.Mutex
	postAuth, perRequest [][]string
	perRequestSession    string
	perRequestDecision   policy.Decision
}

func roleNames(p *identity.Principal) []string {
	names := []string{}
	if p == nil {
		return names
	}

	for _, r := range p.Roles {
		names = append(names, r.Name)
	}

	return names
}

// engine is a policy engine recording both phases; the per-request phase answers
// with perRequestDecision, whose zero value is an allow.
func (j *completionJudged) engine(t *testing.T) *policy.Engine {
	t.Helper()

	record := func(phase policy.Phase) policy.Policy {
		p := NewMockPolicy(gomock.NewController(t))
		p.EXPECT().Name().Return("test: records " + phase.String()).AnyTimes()
		p.EXPECT().Phases().Return([]policy.Phase{phase}).AnyTimes()
		p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
			DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
				j.mu.Lock()
				defer j.mu.Unlock()

				if phase == policy.PostAuthentication {
					j.postAuth = append(j.postAuth, roleNames(in.Principal))

					return policy.Decision{Outcome: policy.Allow}
				}

				j.perRequest = append(j.perRequest, roleNames(in.Principal))
				if in.Session != nil {
					j.perRequestSession = in.Session.ID
				}

				return j.perRequestDecision
			})

		return p
	}

	return engineOf(t, record(policy.PostAuthentication), record(policy.PerRequest))
}

// judgedSession is the session the per-request phase judged.
func (j *completionJudged) judgedSession() string {
	j.mu.Lock()
	defer j.mu.Unlock()

	return j.perRequestSession
}

// viewer is the user's stored details, whose only role is viewer.
var viewer = &identity.Details{
	ID: oidcTestUserID, Username: "ada@example.com", Active: true,
	Roles: []*identity.AssignedRole{{ID: "r-viewer", Name: "viewer"}},
}

// fedAssurance is a consumer's sign-in assurance mapping, stating amr fed.
func fedAssurance(*session.Session) ([]string, string) { return []string{"fed"}, "" }

// completionErrorQueryClient is a first-party client whose one registered redirect
// URI, completionErrorQueryURI, carries an error parameter of its own.
const (
	completionErrorQueryClient = "flow-error-query"
	completionErrorQueryURI    = rpCallback + "?error=none"
)

func completionErrorQueryRegistration() oidcprovider.Client {
	return oidcprovider.Client{
		ID: completionErrorQueryClient, Type: oidcprovider.Confidential, Secret: []byte(tokenSecret), FirstParty: true,
		RedirectURIs: []string{completionErrorQueryURI},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:   []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
	}
}

// TestOIDCCompletion_SignsInWithoutScript pins D7's steps 5 to 9: with nothing owed,
// the callback stores the session from the user's stored details (never the
// broker's principal), with the OIDC first factor, the provider session and the
// asserted assurance, after cancelling the held recoveries; judges it under the
// per-request policy; resumes the parked request with the consumer's assurance
// mapping; and answers 303 to where the resume sends the browser, setting the
// browser-session cookie, with no handoff and no credential. The code it carries
// exchanges at the token endpoint. A request that needs consent is sent to the
// consent page instead.
func TestOIDCCompletion_SignsInWithoutScript(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		client string
		// redirectURI, when set, is the redirect URI the request is parked with.
		redirectURI string
		assert      func(t *testing.T, f *completionFlow, handle string, a flowAnswer)
	}

	cases := []testCase{
		{
			// The redirect URI's own error parameter is the client's, not an error
			// response: completion reads what the resume answered, not the query.
			name:        "a client whose registered redirect URI carries its own error parameter, with a code",
			client:      completionErrorQueryClient,
			redirectURI: completionErrorQueryURI,
			assert: func(t *testing.T, f *completionFlow, _ string, a flowAnswer) {
				t.Helper()

				loc := a.location(t)
				q := loc.Query()
				assert.Equal(t, rpCallback, loc.Scheme+"://"+loc.Host+loc.Path)
				assert.Equal(t, "none", q.Get("error"), "the client's own parameter, kept")
				code := q.Get("code")
				require.NotEmpty(t, code, "an authorization code")

				form := exchangeOf(code)
				form.Set("redirect_uri", completionErrorQueryURI)
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, opIssuer+"/oauth2/token",
					strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth(completionErrorQueryClient, tokenSecret)

				x := f.serve(t, r, nil)
				require.Equal(t, http.StatusOK, x.status, x.body)
				assert.Contains(t, x.body, "access_token", "the code exchanges")
			},
		},
		{
			name:   "the client's redirect URI with a code",
			client: flowFirstParty,
			assert: func(t *testing.T, f *completionFlow, _ string, a flowAnswer) {
				t.Helper()

				loc := a.location(t)
				q := loc.Query()
				assert.Equal(t, rpCallback, loc.Scheme+"://"+loc.Host+loc.Path)
				assert.NotEmpty(t, q.Get("code"), "an authorization code")
				assert.Equal(t, "xyz", q.Get("state"))
				assert.Equal(t, opIssuer, q.Get("iss"))

				claims := f.exchange(t, flowFirstParty, q.Get("code"))
				assert.Equal(t, string(oidcTestUserID), claims["sub"])
				assert.Equal(t, []any{"fed"}, claims["amr"], "the consumer's assurance mapping")
			},
		},
		{
			name:   "the consent page, when the request needs consent",
			client: flowWeb,
			assert: func(t *testing.T, _ *completionFlow, handle string, a flowAnswer) {
				t.Helper()

				assert.Equal(t, opIssuer+"/consent?"+url.Values{oidcprovider.HandleParam: {handle}}.Encode(),
					a.header.Get("Location"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var judged completionJudged

			f := newCompletionFlow(t, completionSetup{
				users:    loaderAnswering(t, viewer, nil),
				clients:  []oidcprovider.Client{completionErrorQueryRegistration()},
				endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCSignInAssurance(fedAssurance)},
				chain: func(t *testing.T, _ *completionFlow) []httpsec.Option {
					t.Helper()

					return []httpsec.Option{httpsec.WithPolicyEngine(judged.engine(t))}
				},
			})
			f.idp.assert([]string{"otp"}, "")

			var park []func(url.Values)
			if tc.redirectURI != "" {
				park = append(park, func(v url.Values) { v.Set("redirect_uri", tc.redirectURI) })
			}

			handle, flow := f.park(t, tc.client, park...)

			a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
			require.NoError(t, a.err)
			require.Equal(t, http.StatusSeeOther, a.status, a.body)

			// The answer: no cache, no referrer, no handoff, no credential.
			assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
			assert.Equal(t, "no-referrer", a.header.Get("Referrer-Policy"))
			assert.Empty(t, a.location(t).Query().Get(httpsec.DefaultOIDCHandoffParam), "no handoff")
			assert.NotContains(t, a.body, "access_token", "no credential in the body")
			assert.Empty(t, a.header.Get("Authorization"))
			assert.Zero(t, f.storedHandoffs(t), "no handoff issued")

			browser := a.cookie(flowSession)
			require.NotNil(t, browser, "the browser-session cookie is set")
			assert.NotEmpty(t, browser.Value)
			assert.True(t, browser.HttpOnly)
			assert.True(t, browser.Secure)
			assert.Equal(t, http.SameSiteLaxMode, browser.SameSite)

			rpFlow := a.cookie(httpsec.DefaultOIDCFlowCookieName)
			require.NotNil(t, rpFlow, "the login flow cookie is cleared")
			assert.Negative(t, rpFlow.MaxAge)

			// The session: stored, from the stored details, federated.
			require.Equal(t, 1, f.storedSessions(t))
			assert.Equal(t, 1, int(f.cancelled.Load()), "held recoveries cancelled")

			judged.mu.Lock()
			assert.Equal(t, [][]string{{"viewer"}}, judged.postAuth, "the stored roles, not the broker's")
			assert.Equal(t, [][]string{{"viewer"}}, judged.perRequest, "the stored roles, not the broker's")
			judged.mu.Unlock()

			s, err := f.sessions.Load(t.Context(), judged.judgedSession())
			require.NoError(t, err)
			assert.Equal(t, oidcTestUserID, s.UserID)
			assert.Equal(t, factor.OIDC, s.FirstFactor)
			assert.Equal(t, testOIDCProvider, s.ExternalProvider)
			assert.Equal(t, f.idp.srv.URL, s.ExternalIssuer)
			assert.Equal(t, oidcTestSessionID, s.ExternalSessionID)
			assert.Equal(t, []string{"otp"}, s.FederatedAMR, "the asserted assurance")

			tc.assert(t, f, handle, a)
		})
	}
}

var (
	errSessionStoreDown  = errors.New("oidc_completion_test: the session store is down")
	errCompletionRefused = errors.New("oidc_completion_test: the per-request policy refuses")
)

// completionSessionStore is the chain's session store, which a row can make fail
// a creating write or a family's deletion, or end every session of the user the
// moment the user's sign-ins are listed: a sign-in ending between the resume and
// its confirmation.
type completionSessionStore struct {
	session.Store

	failCreate, failDeleteFamily, failList, endOnList atomic.Bool
}

func newCompletionSessionStore(t *testing.T) *completionSessionStore {
	t.Helper()

	return &completionSessionStore{Store: must.Must(session.NewMemoryStore())}
}

func (s *completionSessionStore) Create(ctx context.Context, sess *session.Session) error {
	if s.failCreate.Load() {
		return errSessionStoreDown
	}

	return s.Store.Create(ctx, sess)
}

// DeleteFamily honours its context, as a store reached over a network does: a
// cancelled one deletes nothing.
func (s *completionSessionStore) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	if s.failDeleteFamily.Load() {
		return 0, errSessionStoreDown
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	return s.Store.DeleteFamily(ctx, family)
}

func (s *completionSessionStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*session.Session, error) {
	if s.failList.Load() {
		return nil, errSessionStoreDown
	}

	if s.endOnList.CompareAndSwap(true, false) {
		if err := s.DeleteByUser(ctx, user); err != nil {
			return nil, err
		}
	}

	return s.Store.ListByUser(ctx, user, now)
}

// hintFor is an ID token of the provider for client naming subject, as a client
// sends it back as id_token_hint.
func hintFor(t *testing.T, f *completionFlow, client, subject string) string {
	t.Helper()

	made, err := token.NewIssuer(tokenKeys(), signingkey.RS256, opIssuer, token.WithClock(f.clk))
	require.NoError(t, err)

	raw, err := made.Issue(t.Context(), token.Issue{
		Type: token.TypeIDToken, Subject: subject, ID: "hint-1",
		Audience: []string{client}, Lifetime: 5 * time.Minute,
	})
	require.NoError(t, err)

	return raw
}

// TestOIDCCompletion_FailurePaths pins what completion does when it cannot finish
// once it has stored the session (D7, steps 5 to 8): a per-request refusal, a resume
// that fails, a resume answering the client's error response, and a sign-in that
// ends before its confirmation each end the session just stored and send no code
// (F23, F24), and a per-request refusal then returns to the login page; a failure
// to end it is logged once at ERROR and answers the refusal unchanged (F25); a
// session store that cannot store it returns to the login page with server_error,
// and the request is never resumed (F26).
func TestOIDCCompletion_FailurePaths(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// refuse makes the per-request policy deny with errCompletionRefused.
		refuse bool
		// challenge makes the per-request policy raise the second-factor
		// challenge, on a chain enforcing it.
		challenge bool
		// arm sets the row's fault, once the request is parked.
		arm func(t *testing.T, f *completionFlow, store *completionSessionStore)
		// hint, when set, is the subject an id_token_hint the request is parked
		// with names.
		hint string
		// cancelInResume cancels the request's context inside the resume's stage
		// spend, which then fails with the context's error.
		cancelInResume bool
		assert         func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, logs []slog.Record)
	}

	// ended is the common outcome of a refusal after the session was stored: it
	// is gone, and no redirect was sent.
	ended := func(want error) func(t *testing.T, f *completionFlow, _, _ string, a flowAnswer, _ []slog.Record) {
		return func(t *testing.T, f *completionFlow, _, _ string, a flowAnswer, _ []slog.Record) {
			t.Helper()

			require.ErrorIs(t, a.err, want)
			assert.Empty(t, a.header.Get("Location"), "no redirect to the client")
			assert.Zero(t, f.storedSessions(t), "the session is ended")
			assert.Equal(t, int64(1), f.cancelled.Load(), "the session was stored first")
			assert.False(t, f.sessionSeen.Load(), "the ended session is gone from the exchange (F46)")
		}
	}

	// signInEnded asserts the provider ended the sign-in the resume was given, so
	// the code it wrote is refused at the exchange: a revocation is recorded for the
	// code's family, caused by the sign-in's end.
	signInEnded := func(t *testing.T, f *completionFlow) {
		t.Helper()

		families, err := f.setup.codes.UnspentByClient(t.Context(), oidcTestUserID, flowFirstParty)
		require.NoError(t, err)
		require.Len(t, families, 1, "the resume wrote one code")

		g, err := f.grants.Load(t.Context(), families[0])
		require.NoError(t, err, "a revocation is recorded for the code's family")
		assert.True(t, g.Revoked)
		assert.Equal(t, oidcprovider.CauseSignInEnded, g.RevokeCause)
	}

	endRecords := func(logs []slog.Record) []slog.Record {
		var out []slog.Record

		for _, r := range logs {
			if v, ok := attrValue(r, "reason"); ok && v.String() == "completion-session-not-ended" {
				out = append(out, r)
			}
		}

		return out
	}

	cases := []testCase{
		{
			name:   "the per-request policy refuses",
			refuse: true,
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, logs []slog.Record) {
				t.Helper()

				// The session is ended, then the login page is told (D3, D4).
				require.NoError(t, a.err)
				assert.Equal(t, parkedReturn(handle, httpsec.DefaultOIDCLoginErrorParam,
					oidcprovider.CodeAccessDenied), a.header.Get("Location"))
				assert.Zero(t, f.storedSessions(t), "the session is ended")
				assert.Equal(t, int64(1), f.cancelled.Load(), "the session was stored first")
				assert.False(t, f.sessionSeen.Load(), "the ended session is gone from the exchange (F46)")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "never resumed, no code")
				assert.Empty(t, endRecords(logs), "the end succeeded")
			},
		},
		{
			name: "cancelling the held recoveries fails before the session is stored",
			arm: func(t *testing.T, f *completionFlow, _ *completionSessionStore) {
				t.Helper()

				f.cancelFails.Store(&errRecoveryCancelDown)
			},
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, _ []slog.Record) {
				t.Helper()

				// A failure storing the session returns to the login page (D4).
				require.NoError(t, a.err)
				assert.Equal(t, parkedReturn(handle, httpsec.DefaultOIDCLoginErrorParam,
					oidcprovider.CodeServerError), a.header.Get("Location"), "not to the client")
				assert.Nil(t, a.cookie(flowSession), "no browser session")
				assert.Zero(t, f.storedSessions(t), "no session is stored")
				assert.False(t, f.sessionSeen.Load(), "no session on the exchange")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "never resumed, no code")
			},
		},
		{
			name: "the resume fails",
			arm: func(t *testing.T, f *completionFlow, _ *completionSessionStore) {
				t.Helper()

				f.setup.pending.downAfterNext.Store(true)
			},
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, logs []slog.Record) {
				t.Helper()

				ended(errPendingDown)(t, f, handle, flow, a, logs)
			},
		},
		{
			name: "the resume answers login_required",
			hint: "u-9",
			assert: func(t *testing.T, f *completionFlow, _, _ string, a flowAnswer, _ []slog.Record) {
				t.Helper()

				require.NoError(t, a.err)
				require.Equal(t, http.StatusSeeOther, a.status, a.body)

				loc := a.location(t)
				assert.Equal(t, rpCallback, loc.Scheme+"://"+loc.Host+loc.Path, "the client's error response")
				assert.Equal(t, "login_required", loc.Query().Get("error"))
				assert.Empty(t, loc.Query().Get("code"), "no code")
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.Equal(t, "no-referrer", a.header.Get("Referrer-Policy"))
				assert.Nil(t, a.cookie(flowSession), "no browser session")
				assert.Zero(t, f.storedSessions(t), "the session is ended")
				assert.False(t, f.sessionSeen.Load(), "the ended session is gone from the exchange (F46)")
			},
		},
		{
			name:      "the per-request policy raises a challenge",
			challenge: true,
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, logs []slog.Record) {
				t.Helper()

				loc, code := handoffTo(t, a)
				assert.Equal(t, parkedAt(handle), loc.String(), "the handoff to the login page (D8)")
				assert.Zero(t, f.storedSessions(t), "the session is ended")
				assert.Equal(t, int64(1), f.cancelled.Load(), "the session was stored first")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "never resumed, no code")
				assert.Nil(t, a.cookie(flowSession), "no browser session")
				assert.False(t, f.sessionSeen.Load(), "the ended session is gone from the exchange (F46)")
				assert.Empty(t, endRecords(logs), "the end succeeded")

				// The page redeems the code it fell back with, to the parked
				// destination, and meets the challenge there.
				r := f.redeem(t, code)
				require.NoError(t, r.err)
				require.Equal(t, http.StatusOK, r.status, r.body)

				var doc struct {
					Next string `json:"next"`
				}
				require.NoError(t, json.Unmarshal([]byte(r.body), &doc), r.body)
				assert.Equal(t, parkedAt(handle), doc.Next, "the parked destination, never /")
			},
		},
		{
			name: "the sign-in ends between the resume and its confirmation",
			arm: func(t *testing.T, _ *completionFlow, store *completionSessionStore) {
				t.Helper()

				store.endOnList.Store(true)
			},
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, logs []slog.Record) {
				t.Helper()

				ended(httpsec.ErrOIDCReauthenticate)(t, f, handle, flow, a, logs)
				assert.Nil(t, a.cookie(flowSession), "no browser session handed out")
			},
		},
		{
			// Confirmation runs after the resume (D7, step 8), so an end that lands
			// inside the resume's own write is caught, and no code reaches the client.
			name: "the sign-in ends inside the resume's own write",
			arm: func(t *testing.T, f *completionFlow, store *completionSessionStore) {
				t.Helper()

				f.setup.pending.onAdvance = func(ctx context.Context, s *oidcprovider.SignIn) error {
					if s == nil {
						return nil
					}

					return store.DeleteByUser(ctx, s.User)
				}
			},
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, logs []slog.Record) {
				t.Helper()

				ended(httpsec.ErrOIDCReauthenticate)(t, f, handle, flow, a, logs)
				assert.Nil(t, a.cookie(flowSession), "no browser session handed out")
				signInEnded(t, f)
			},
		},
		{
			name: "the confirmation fails and so does ending the session",
			arm: func(t *testing.T, f *completionFlow, store *completionSessionStore) {
				t.Helper()

				store.failDeleteFamily.Store(true)
				f.setup.pending.onAdvance = func(context.Context, *oidcprovider.SignIn) error {
					store.failList.Store(true)

					return nil
				}
			},
			assert: func(t *testing.T, f *completionFlow, _, _ string, a flowAnswer, logs []slog.Record) {
				t.Helper()

				require.ErrorIs(t, a.err, errSessionStoreDown, "the confirmation's failure")
				assert.Empty(t, a.header.Get("Location"), "no redirect to the client")
				assert.Nil(t, a.cookie(flowSession), "no browser session handed out")
				assert.False(t, f.sessionSeen.Load(), "the abandoned session is gone from the exchange (F46)")
				signInEnded(t, f)

				records := endRecords(logs)
				require.Len(t, records, 1, "one record of the failed end")
				assert.Equal(t, slog.LevelError, records[0].Level)
			},
		},
		{
			name:           "the request is cancelled during the resume",
			cancelInResume: true,
			assert: func(t *testing.T, f *completionFlow, _, _ string, a flowAnswer, logs []slog.Record) {
				t.Helper()

				require.Error(t, a.err)
				assert.Empty(t, a.header.Get("Location"), "no redirect to the client")
				assert.Nil(t, a.cookie(flowSession), "no browser session handed out")
				assert.Zero(t, f.storedSessions(t), "the session is ended, detached from the request")
				assert.False(t, f.sessionSeen.Load(), "the ended session is gone from the exchange (F46)")
				assert.Empty(t, endRecords(logs), "the end succeeded")
			},
		},
		{
			name:   "ending the session fails",
			refuse: true,
			arm: func(t *testing.T, _ *completionFlow, store *completionSessionStore) {
				t.Helper()

				store.failDeleteFamily.Store(true)
			},
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, logs []slog.Record) {
				t.Helper()

				require.ErrorIs(t, a.err, errCompletionRefused, "the original refusal")
				assert.NotErrorIs(t, a.err, errSessionStoreDown, "unchanged by the failed end")
				assert.False(t, f.sessionSeen.Load(), "the abandoned session is gone from the exchange (F46)")
				assert.Empty(t, a.header.Get("Location"), "no redirect to the client")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "never resumed, no code")

				records := endRecords(logs)
				require.Len(t, records, 1, "one record of the failed end")
				assert.Equal(t, slog.LevelError, records[0].Level)
			},
		},
		{
			name: "the session store fails",
			arm: func(t *testing.T, _ *completionFlow, store *completionSessionStore) {
				t.Helper()

				store.failCreate.Store(true)
			},
			assert: func(t *testing.T, f *completionFlow, handle, flow string, a flowAnswer, _ []slog.Record) {
				t.Helper()

				// A dependency failure returns to the login page (D4).
				require.NoError(t, a.err)
				assert.False(t, f.sessionSeen.Load(), "no session on the exchange")
				assert.Equal(t, parkedReturn(handle, httpsec.DefaultOIDCLoginErrorParam,
					oidcprovider.CodeServerError), a.header.Get("Location"), "not to the client")
				assert.Zero(t, f.storedSessions(t), "no session")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, handle, flow), "never resumed")
				assert.Nil(t, a.cookie(flowSession), "no browser session")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newCompletionSessionStore(t)
			logs := &capturingHandler{}

			judged := completionJudged{}
			if tc.refuse {
				judged.perRequestDecision = policy.Decision{Outcome: policy.Deny, Reason: errCompletionRefused}
			}
			if tc.challenge {
				judged.perRequestDecision = policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengeMFA}
			}

			setup := completionSetup{
				users:    loaderAnswering(t, viewer, nil),
				sessions: []session.Option{session.WithStore(store)},
				pending: &downablePendingStore{
					PendingRequestStore: must.Must(oidcprovider.NewMemoryPendingRequestStore()),
				},
				codes: must.Must(oidcprovider.NewMemoryCodeStore()),
				chain: func(t *testing.T, f *completionFlow) []httpsec.Option {
					t.Helper()

					opts := []httpsec.Option{
						httpsec.WithPolicyEngine(judged.engine(t)),
						httpsec.WithLogger(slog.New(logs)),
						observeSession(f),
					}
					if tc.challenge {
						opts = append(opts, httpsec.EnableMFA([]mfa.Method{totpLike(t)}))
					}

					return opts
				},
			}

			f := newCompletionFlow(t, setup)
			f.setup = setup

			var change []func(url.Values)
			if tc.hint != "" {
				change = append(change, func(v url.Values) { v.Set("id_token_hint", hintFor(t, f, flowFirstParty, tc.hint)) })
			}

			handle, flow := f.park(t, flowFirstParty, change...)
			if tc.arm != nil {
				tc.arm(t, f, store)
			}

			send := []flowChange{flowCookieOf(flowCookie, flow)}
			if tc.cancelInResume {
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)

				send = append(send, func(r *http.Request) { *r = *r.WithContext(ctx) })
				f.setup.pending.onAdvance = func(context.Context, *oidcprovider.SignIn) error {
					cancel()

					return context.Canceled
				}
			}

			a := f.signIn(t, parkedAt(handle), send...)
			f.setup.pending.down.Store(false)

			tc.assert(t, f, handle, flow, a, logs.records())
		})
	}
}

// TestOIDCCompletion_Events pins what completion reports (D10): a completed
// sign-in emits the events a handoff redemption of the same login emits, of the
// same kinds and in the same order, and a broker's refusal at a callback with
// completion on emits the failed login as it does without.
func TestOIDCCompletion_Events(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// run runs the row's login and returns the names of the events its
		// requests emitted from the callback on.
		run    func(t *testing.T) []string
		assert func(t *testing.T, emitted []string)
	}

	// signedIn is the names of the events emitted from the callback on, for a
	// sign-in with nothing owed: completed on the server, or, with completion
	// off, conveyed by a handoff and redeemed.
	signedIn := func(t *testing.T, off bool) []string {
		t.Helper()

		setup := completionSetup{off: off}
		if !off {
			setup.users = loaderAnswering(t, viewer, nil)
		}

		f := newCompletionFlow(t, setup)
		handle, flow := f.park(t, flowFirstParty)
		before := len(f.events.names())

		a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
		if off {
			_, code := handoffTo(t, a)
			redeemed := f.redeem(t, code)
			require.Equal(t, http.StatusOK, redeemed.status, redeemed.body)
		} else {
			require.NoError(t, a.err)
			require.Equal(t, http.StatusSeeOther, a.status, a.body)
		}

		return f.events.names()[before:]
	}

	cases := []testCase{
		{
			name: "a completed sign-in emits what a redemption emits",
			run: func(t *testing.T) []string {
				t.Helper()

				return signedIn(t, false)
			},
			assert: func(t *testing.T, completed []string) {
				t.Helper()

				redeemed := signedIn(t, true)
				require.NotEmpty(t, redeemed)
				assert.Equal(t, redeemed, completed, "the same kinds, in the same order")
				assert.Contains(t, completed, event.AuthnLoginSuccess)
			},
		},
		{
			name: "a broker's refusal emits the failed login",
			run: func(t *testing.T) []string {
				t.Helper()

				f := newCompletionFlow(t, completionSetup{unlinked: true, users: loaderAnswering(t, viewer, nil)})
				handle, flow := f.park(t, flowFirstParty)
				before := len(f.events.names())

				// The refusal returns to the login page (D3), emitting what it did.
				a := f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow))
				require.NoError(t, a.err)
				assert.Equal(t, parkedReturn(handle, httpsec.DefaultOIDCLoginErrorParam,
					oidcprovider.CodeAccessDenied), a.header.Get("Location"))
				assert.Zero(t, f.storedSessions(t))

				return f.events.names()[before:]
			},
			assert: func(t *testing.T, emitted []string) {
				t.Helper()

				assert.Equal(t, []string{event.AuthnLoginFail}, emitted)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.run(t))
		})
	}
}

// parkAlso parks a second request from clientID in the browser whose provider flow
// cookie is flow, as a second tab does, and returns its handle.
func (f *completionFlow) parkAlso(t *testing.T, clientID, flow string) string {
	t.Helper()

	a := f.authorizeGET(t, flowParams(clientID), flowCookieOf(flowCookie, flow))
	require.Equal(t, http.StatusSeeOther, a.status, a.body)

	if set := a.cookie(flowCookie); set != nil {
		require.Equal(t, flow, set.Value, "the browser's flow cookie stands")
	}

	return a.location(t).Query().Get(oidcprovider.HandleParam)
}

// TestOIDCCompletion_TwoTabsSequential pins two parked requests in one browser
// (Review Focus 4, D12): signed in one after the other, each callback resumes its
// own handle and redirects to its own client response, and both codes exchange.
// An SSO login started for the second before the first called back invalidates the
// first: its callback is an invalid state, and creates no session (F29).
func TestOIDCCompletion_TwoTabsSequential(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		run  func(t *testing.T, f *completionFlow, h1, h2, flow string)
	}

	cases := []testCase{
		{
			name: "one after the other",
			run: func(t *testing.T, f *completionFlow, h1, h2, flow string) {
				t.Helper()

				first := f.signIn(t, parkedAt(h1), flowCookieOf(flowCookie, flow))
				require.NoError(t, first.err)
				require.Equal(t, http.StatusSeeOther, first.status, first.body)

				second := f.signIn(t, parkedAt(h2), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, first.sessionSecret(t)))
				require.NoError(t, second.err)
				require.Equal(t, http.StatusSeeOther, second.status, second.body)

				codes := map[string]bool{}

				for _, a := range []flowAnswer{first, second} {
					q := a.location(t).Query()
					require.NotEmpty(t, q.Get("code"), "each callback redirects with its own code")
					assert.Equal(t, "xyz", q.Get("state"))
					codes[q.Get("code")] = true

					claims := f.exchange(t, flowFirstParty, q.Get("code"))
					assert.Equal(t, string(oidcTestUserID), claims["sub"])
				}

				assert.Len(t, codes, 2, "two codes, one per parked request")
				assert.Equal(t, 2, f.storedSessions(t), "one session per completed sign-in")
			},
		},
		{
			name: "the second SSO login started before the first called back",
			run: func(t *testing.T, f *completionFlow, h1, h2, flow string) {
				t.Helper()

				first := f.startSSO(t, parkedAt(h1))
				second := f.startSSO(t, parkedAt(h2))

				// The browser holds one relying-party flow cookie, the second's,
				// when the first's callback arrives.
				stale := first
				stale.rpFlow = second.rpFlow

				a := f.callBack(t, stale, flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, oidc.ErrInvalidState)
				assert.Empty(t, a.header.Get("Location"), "no redirect")
				assert.Zero(t, f.storedSessions(t), "no session")
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, h1, flow), "the first request is untouched")

				// The second goes on as its own.
				b := f.callBack(t, second, flowCookieOf(flowCookie, flow))
				require.NoError(t, b.err)
				require.Equal(t, http.StatusSeeOther, b.status, b.body)
				code := b.location(t).Query().Get("code")
				require.NotEmpty(t, code)
				assert.Equal(t, string(oidcTestUserID), f.exchange(t, flowFirstParty, code)["sub"])
				assert.Equal(t, oidcprovider.StageLogin, f.stage(t, h1, flow), "the first request waits")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newCompletionFlow(t, completionSetup{users: loaderAnswering(t, viewer, nil)})
			h1, flow := f.park(t, flowFirstParty)
			h2 := f.parkAlso(t, flowFirstParty, flow)
			require.NotEqual(t, h1, h2)

			tc.run(t, f, h1, h2, flow)
		})
	}
}
