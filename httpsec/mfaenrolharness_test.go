package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// enrolUsername is the enrolling user's username, which is an address, so the
// default label and contact resolvers read it unchanged.
const enrolUsername = "ana@example.com"

// enrolIssuer is the issuer the TOTP method is built with.
const enrolIssuer = "Example"

// queuedSender is a sender double that declares itself non-blocking, as
// notify.QueuedSender does, so the enrolment path accepts it without the
// synchronous-delivery option. What it is asked to send is the mock's to pin.
type queuedSender struct{ *MockSender }

func (queuedSender) NonBlocking() bool { return true }

var _ notify.NonBlocking = queuedSender{}

// enrolHarness is what an enrolment chain is wired to: a real session manager,
// a real TOTP method over the in-memory store — so a begin really provisions a
// secret and a code computed from it really proves the device — and doubles for
// the user loader and the sender, whose calls are part of what is pinned.
type enrolHarness struct {
	t *testing.T

	sessions *session.Manager
	store    *mfa.MemoryEnrolmentStore
	totp     *mfa.TOTP

	// clock is the TOTP method's clock. Tests move it between requests, never
	// during one.
	clock *clockwork.FakeClock

	users  *MockUserLoader
	sender *MockSender
	tokens *MockGenerator

	// username is what the user loader reports for the enrolling user.
	username string

	// method is what EnableMFA is given, the TOTP method unless a case
	// replaces it.
	method mfa.Method

	enrolOpts  []httpsec.EnrolmentOption
	logoutOpts []httpsec.LogoutOption

	// mfaOpts is further options for EnableMFA, after the harness's tokens.
	mfaOpts []httpsec.MFAOption

	// extra is further chain options, applied after the harness's own.
	extra []httpsec.Option

	// pinned, when set, is carried as it stands in memory on every request
	// instead of being loaded from the store: a test uses it to hand the chain
	// a session the store would no longer load, or to read what a request
	// left on the very object it was given.
	pinned *session.Session

	// withoutGate builds the chain with the enrolment challenge counted as
	// enforced but no enrolment path registered, which is how a test shows a
	// refusal is the gate's and nothing else's.
	withoutGate bool
}

func newEnrolHarness(t *testing.T) *enrolHarness {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.NewManager()
	require.NoError(t, err)

	h := &enrolHarness{
		t:        t,
		sessions: sessions,
		store:    mfa.NewMemoryEnrolmentStore(),
		clock:    clockwork.NewFakeClockAt(time.Now().Truncate(time.Second)),
		users:    NewMockUserLoader(ctrl),
		sender:   NewMockSender(ctrl),
		tokens:   NewMockGenerator(ctrl),
		username: enrolUsername,
	}

	h.totp, err = mfa.NewTOTP(h.store, enrolIssuer, mfa.WithClock(h.clock))
	require.NoError(t, err)

	h.method = h.totp

	h.users.EXPECT().LoadByUserID(gomock.Any(), testMFAUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			return &identity.Details{ID: testMFAUser, Name: "Ana", Username: h.username, Active: true}, nil
		})

	return h
}

// enrolmentEngine is an engine holding the MFA requirement policy with the
// enrolment path on, which is what declares the enrolment challenge the path
// must be paired with.
func enrolmentEngine(t *testing.T) *policy.Engine {
	t.Helper()

	ctrl := gomock.NewController(t)

	lookup := NewMockMFAMethodLookup(ctrl)
	lookup.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	lookup.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()

	p, err := policy.NewMFARequirementPolicy(everyoneRequired{}, lookup, policy.WithMFAEnrolmentPath())
	require.NoError(t, err)

	return engineOf(t, p)
}

// deps is what EnableMFAEnrolment is handed: the user loader and a
// non-blocking sender.
func (h *enrolHarness) deps() httpsec.EnrolmentDeps {
	return httpsec.EnrolmentDeps{Users: h.users, Sender: queuedSender{h.sender}}
}

// options is every option the harness's chain is built from.
func (h *enrolHarness) options(t *testing.T, s *session.Session) []httpsec.Option {
	t.Helper()

	enrolment := httpsec.EnableMFAEnrolment(h.deps(), h.enrolOpts...)
	if h.withoutGate {
		enrolment = httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment)
	}

	return append([]httpsec.Option{
		httpsec.WithPolicyEngine(enrolmentEngine(t)),
		h.carries(s),
		httpsec.EnableMFA(h.method, append([]httpsec.MFAOption{httpsec.WithMFATokens(h.tokens)}, h.mfaOpts...)...),
		enrolment,
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, h.logoutOpts...),
	}, h.extra...)
}

// chain assembles the chain under test, with s carried as a first factor
// would have carried it.
func (h *enrolHarness) chain(t *testing.T, s *session.Session) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(h.options(t, s)...)
	require.NoError(t, err)

	return c
}

// carries stands in for the bearer interceptor: at its slot, it loads s afresh
// from the store on every request, as the bearer loads the session a token
// names, so a request sees what the one before it saved. A session that no
// longer loads is not carried.
func (h *enrolHarness) carries(s *session.Session) httpsec.Option {
	carrier := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if s == nil {
			return next(ex)
		}

		loaded := h.pinned
		if loaded == nil {
			var err error

			loaded, err = h.sessions.Load(ex.Context(), s.ID)
			if err != nil {
				return next(ex)
			}
		}

		ex.Authentication = &authenticate.Authentication{Principal: testPrincipal(), Time: time.Now()}
		ex.Session = loaded
		ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(), ex.Authentication), loaded))

		return next(ex)
	})

	return httpsec.RegisterInterceptor(carrier, httpsec.OrderBearerToken)
}

// enrolmentOnly is a live session for the enrolling user, established by
// first and marked enrolment-only as the login tail would have marked it.
func (h *enrolHarness) enrolmentOnly(t *testing.T, first factor.Kind) *session.Session {
	t.Helper()

	s, err := h.sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(first))
	require.NoError(t, err)

	h.sessions.MarkEnrolmentPending(s, 15*time.Minute)
	require.NoError(t, h.sessions.Save(t.Context(), s))

	return s
}

// sessionIn is a live session for the enrolling user, established by first,
// in state: enrolment-only as the login tail marks it, or any other state as
// set directly.
func (h *enrolHarness) sessionIn(t *testing.T, first factor.Kind, state session.MFAState) *session.Session {
	t.Helper()

	if state == session.MFAEnrolmentPending {
		return h.enrolmentOnly(t, first)
	}

	s, err := h.sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(first))
	require.NoError(t, err)

	s.MFA = state
	require.NoError(t, h.sessions.Save(t.Context(), s))

	return s
}

// stored reloads a session by handle.
func (h *enrolHarness) stored(t *testing.T, handle string) *session.Session {
	t.Helper()

	s, err := h.sessions.Load(t.Context(), handle)
	require.NoError(t, err)

	return s
}

// enrolment reads the enrolling user's enrolment as the store holds it.
func (h *enrolHarness) enrolment(t *testing.T) (mfa.Enrolment, bool) {
	t.Helper()

	e, ok, err := h.store.Get(t.Context(), testMFAUser)
	require.NoError(t, err)

	return e, ok
}

// codeFor is the code an authenticator holding secret shows at the harness's
// clock.
func (h *enrolHarness) codeFor(t *testing.T, secret string) string {
	t.Helper()

	code, err := totp.GenerateCode(secret, h.clock.Now())
	require.NoError(t, err)

	return code
}

// post is a form POST to path, carried under ctx.
func post(ctx context.Context, path, body string) *http.Request {
	return formRequest(ctx, path, body)
}

// serveIn runs req through chain on an exchange seeded from ctx, which a case
// uses to hand the chain a context that is already cancelled.
func serveIn(ctx context.Context, t *testing.T, chain *httpsec.Chain, req *http.Request) served {
	t.Helper()

	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}
