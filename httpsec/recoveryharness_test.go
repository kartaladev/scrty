package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// recoveryCodeSubject is the subject the harness's message builder gives the
// message carrying an issued code, so a test can find it among the notices.
const recoveryCodeSubject = "issued-code"

// recoveryMessages is the harness's message builder: the issued code is the
// whole body, so a test reads it back without parsing prose.
type recoveryMessages struct{}

func (recoveryMessages) IssuedCode(code string, _ time.Time) (string, string) {
	return recoveryCodeSubject, code
}

func (recoveryMessages) Recovered(recovery.Notice) (string, string) { return "recovered", "recovered" }

func (recoveryMessages) Held(_ recovery.Notice, link string, _ time.Time) (string, string) {
	return "held", link
}

func (recoveryMessages) Cancelled(recovery.Notice) (string, string) { return "cancelled", "cancelled" }
func (recoveryMessages) Regenerated(time.Time) (string, string)     { return "regenerated", "regenerated" }

// recoveryHarness is what a recovery chain is wired to: the real recovery core
// over its in-memory stores, a real saved-code manager, a real TOTP method,
// the real password authenticator behind form login and a real session
// manager. Only the user store and the token generator are doubles, since
// scrty ships neither; a case replaces a port with a strict double where it
// must show the port was never reached.
type recoveryHarness struct {
	sessions *session.Manager
	codes    *recovery.Codes
	totp     *mfa.TOTP
	clock    *clockwork.FakeClock
	sender   *capturingSender
	tokens   *MockGenerator
	attempts *policy.MemoryAttemptStore

	// users is what the chain and the core load users through, and
	// authn what form login judges passwords with. Both are real-backed by
	// default; a case may replace either before build.
	users *MockUserLoader
	authn authenticate.Authenticator

	secret string

	// send, when set, replaces sender as the recovery's sender.
	send notify.Sender

	// records, when set, is the recovery's record store in place of the
	// core's in-memory default.
	records recovery.RecordStore

	// proofs are the proof kinds the core enables.
	proofs []recovery.ProofKind

	// coreOpts are further core options, after the harness's own.
	coreOpts []recovery.Option

	// noCoreClock leaves the harness's clock out of the core options, so the
	// core reads whatever time source the chain hands it.
	noCoreClock bool

	// recOpts are further recovery options.
	recOpts []httpsec.RecoveryOption

	// chainOpts are further chain options, applied before recovery.
	chainOpts []httpsec.Option

	// noFormLogin builds the chain without form login, and noBinding without
	// the password-change resolve endpoint, the harness's one binding route.
	noFormLogin bool
	noBinding   bool

	chain *httpsec.Chain

	// allow and coreCheckCalls are state a case's consumer hooks share with
	// its act and assert.
	allow          *atomic.Bool
	coreCheckCalls *atomic.Int32
}

// last is the most recent message the sender was given.
func (s *capturingSender) last(t *testing.T) notify.Message {
	t.Helper()

	s.mu.Lock()
	defer s.mu.Unlock()

	require.NotEmpty(t, s.sent, "nothing was sent")

	return s.sent[len(s.sent)-1]
}

func newRecoveryHarness(t *testing.T) *recoveryHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	clk := clockwork.NewFakeClockAt(time.Now().Truncate(time.Minute))

	// The sessions, the core and TOTP share one fake clock, so a case moves
	// time for all of them at once.
	sessions, err := session.NewManager(session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	codes, err := recovery.NewCodes()
	require.NoError(t, err)

	h := &recoveryHarness{
		sessions: sessions,
		codes:    codes,
		clock:    clk,
		sender:   &capturingSender{},
		tokens:   NewMockGenerator(ctrl),
		attempts: policy.NewMemoryAttemptStore(),
		users:    NewMockUserLoader(ctrl),
		proofs: []recovery.ProofKind{
			recovery.ProofSaved, recovery.ProofIssued, recovery.ProofPassword, recovery.ProofMFA,
		},
	}

	h.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example", mfa.WithClock(clk))
	require.NoError(t, err)

	hash, err := e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func() *identity.Details {
		return &identity.Details{ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress, Password: hash, Active: true}
	}

	h.users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) { return details(), nil })
	h.users.EXPECT().LoadByUserID(gomock.Any(), e2eUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return details(), nil })
	h.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, identity.ErrUserNotFound)

	h.authn, err = authenticate.NewUsernamePasswordAuthenticator(h.users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			return mfaTokenFor(id), nil
		})
	h.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(e2eAddress, id), nil
		})

	return h
}

// options are the chain options the harness builds with.
func (h *recoveryHarness) options(t *testing.T) []httpsec.Option {
	t.Helper()

	kind, err := recovery.MFAEnrolments(h.totp)
	require.NoError(t, err)

	core := []recovery.Option{
		recovery.WithProofs(h.proofs...),
		recovery.WithRepudiationContact("Write to security@example.com if this was not you."),
		recovery.WithAuthenticatorKinds(kind),
		recovery.WithMFAMethods(h.totp),
		recovery.WithMessages(recoveryMessages{}),
	}
	if !h.noCoreClock {
		core = append(core, recovery.WithClock(h.clock))
	}
	core = append(core, h.coreOpts...)

	opts := append([]httpsec.Option(nil), h.chainOpts...)

	if !h.noFormLogin {
		opts = append(opts, httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: h.authn,
			Sessions:      h.sessions,
			Tokens:        h.tokens,
			Attempts:      h.attempts,
		}))
	}

	if !h.noBinding {
		opts = append(opts, httpsec.EnablePasswordChangeGate(h.sessions,
			httpsec.WithChangePasswordEndpoint(passwordResolvePath, func(*httpsec.Exchange) error { return nil })))
	}

	opts = append(opts,
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
		httpsec.EnableAccountRecovery(h.deps(),
			append([]httpsec.RecoveryOption{httpsec.WithRecoveryCore(core...)}, h.recOpts...)...),
	)

	return opts
}

// deps are the recovery's ports.
func (h *recoveryHarness) deps() httpsec.RecoveryDeps {
	var sender notify.Sender = h.sender
	if h.send != nil {
		sender = h.send
	}

	return httpsec.RecoveryDeps{
		Users: h.users, Sessions: h.sessions, Sender: sender, Codes: h.codes, Records: h.records,
	}
}

// build assembles the chain, which must succeed.
func (h *recoveryHarness) build(t *testing.T) *recoveryHarness {
	t.Helper()

	var err error

	h.chain, err = httpsec.New(h.options(t)...)
	require.NoError(t, err)

	return h
}

// saved generates the user's saved set and returns its first code.
func (h *recoveryHarness) saved(t *testing.T) string {
	t.Helper()

	set, err := h.codes.Generate(t.Context(), e2eUser)
	require.NoError(t, err)

	return set[0]
}

// issued starts a recovery through the chain and returns the code it emailed.
func (h *recoveryHarness) issued(t *testing.T) string {
	t.Helper()

	before := h.sender.count()

	out := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryStartPath, e2eSource,
		url.Values{httpsec.RecoveryUsernameParam: {e2eAddress}}))
	require.NoError(t, out.err)
	require.Equal(t, before+1, h.sender.count(), "the start sent no code")

	h.sender.mu.Lock()
	defer h.sender.mu.Unlock()

	last := h.sender.sent[len(h.sender.sent)-1]
	require.Equal(t, recoveryCodeSubject, last.Subject)

	return last.TextBody
}

// enrolTOTP enrols the user on TOTP, so a TOTP code can serve as a proof.
func (h *recoveryHarness) enrolTOTP(t *testing.T) {
	t.Helper()

	prov, err := h.totp.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
	require.NoError(t, err)

	code, err := totp.GenerateCode(prov.Secret, h.clock.Now())
	require.NoError(t, err)
	require.NoError(t, h.totp.ConfirmEnrolment(t.Context(), e2eUser, code))

	h.secret = prov.Secret
}

// totpCode is a code for the next time step, so it is not the step the
// enrolment already spent.
func (h *recoveryHarness) totpCode(t *testing.T) string {
	t.Helper()

	h.clock.Advance(h.totp.Period())

	code, err := totp.GenerateCode(h.secret, h.clock.Now())
	require.NoError(t, err)

	return code
}

// complete posts values to the complete path from the harness's source.
func (h *recoveryHarness) complete(t *testing.T, values url.Values) served {
	t.Helper()

	return serve(t, h.chain, postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource, values))
}

// through runs req through the chain's net/http middleware, which writes the
// status a refusal maps to, so a test compares whole responses.
func (h *recoveryHarness) through(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rec, req)

	return rec
}
