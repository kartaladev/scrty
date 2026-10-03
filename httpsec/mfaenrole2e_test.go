package httpsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The person the end-to-end runs sign in as.
const (
	e2eUser     identity.UserID = "u-1"
	e2eAddress  string          = "grace@example.com"
	e2ePassword string          = "correct horse battery staple"
	e2eSource   string          = "203.0.113.7"
)

// requiredFlag is the requirement lookup: whether the user must use a second
// factor, which an operator may change while a session is live.
type requiredFlag struct{ on atomic.Bool }

func (r *requiredFlag) Required(context.Context, identity.UserID) (bool, error) {
	return r.on.Load(), nil
}

// e2eDeployment is one deployment wired the way a consumer wires the path:
// the real MFA policies over the real TOTP method and its in-memory store, a
// real session manager, form login over the real password authenticator, magic
// link, bearer tokens, the verify endpoint, the enrolment path and logout, all
// in one chain. Only the user store and the token generator are doubles, since
// scrty ships neither.
type e2eDeployment struct {
	sessions *session.Manager
	totp     *mfa.TOTP
	clock    *clockwork.FakeClock
	users    *MockUserLoader
	sender   *capturingSender
	tokens   *MockGenerator
	links    *magiclink.Manager
	required *requiredFlag
	hash     []byte

	// pathOpts configure the policy's enrolment path, and enrolOpts the
	// chain's; both are read when the chain is built.
	pathOpts  []policy.EnrolmentPathOption
	enrolOpts []httpsec.EnrolmentOption

	chain *httpsec.Chain
}

func newE2EDeployment(t *testing.T) *e2eDeployment {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.NewManager()
	require.NoError(t, err)

	d := &e2eDeployment{
		sessions: sessions,
		clock:    clockwork.NewFakeClockAt(time.Now().Truncate(time.Second)),
		users:    NewMockUserLoader(ctrl),
		sender:   &capturingSender{},
		tokens:   NewMockGenerator(ctrl),
		required: &requiredFlag{},
	}
	d.required.on.Store(true)

	d.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll", mfa.WithClock(d.clock))
	require.NoError(t, err)

	onetimes, err := onetime.NewManager("magic-link", onetime.WithTTL(magicLinkTTL))
	require.NoError(t, err)

	d.links, err = magiclink.NewManager(onetimes, d.users, d.sender, "https://app.example.com")
	require.NoError(t, err)

	d.wireUsers(t)
	d.wireTokens()

	return d
}

// e2eEncoder is Argon2id at the cheapest parameters the encoder accepts, so
// a run of logins stays quick.
func e2eEncoder(t *testing.T) password.Encoder {
	t.Helper()

	enc, err := password.NewArgon2idEncoder(password.WithArgon2idMemory(19456),
		password.WithArgon2idIterations(2), password.WithArgon2idThreads(1))
	require.NoError(t, err)

	return enc
}

func (d *e2eDeployment) wireUsers(t *testing.T) {
	t.Helper()

	var err error
	d.hash, err = e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func() *identity.Details {
		return &identity.Details{
			ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress,
			Password: d.hash, Active: true,
		}
	}

	d.users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) { return details(), nil })
	d.users.EXPECT().LoadByUserID(gomock.Any(), e2eUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return details(), nil })
}

// wireTokens issues tokens naming the session they were issued for and
// verifies them back, as a real generator does through the jti.
func (d *e2eDeployment) wireTokens() {
	d.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			return mfaTokenFor(id), nil
		})
	d.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(e2eAddress, id), nil
		})
}

// build assembles the chain from the deployment's current configuration.
func (d *e2eDeployment) build(t *testing.T) *e2eDeployment {
	t.Helper()

	lookups, err := mfa.LookupsFor(d.totp)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookups)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirementPolicy(d.required, lookups,
		policy.WithMFAEnrolmentPath(d.pathOpts...))
	require.NoError(t, err)

	authn, err := authenticate.NewUsernamePasswordAuthenticator(d.users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	d.chain, err = httpsec.New(
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn,
			Sessions:      d.sessions,
			Tokens:        d.tokens,
			Attempts:      policy.NewMemoryAttemptStore(),
		}),
		httpsec.EnableMagicLink(d.links,
			httpsec.WithMagicLinkSessions(d.sessions), httpsec.WithMagicLinkTokens(d.tokens)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: d.tokens, Sessions: d.sessions, Users: d.users,
		}),
		httpsec.EnableMFA([]mfa.Method{d.totp}, httpsec.WithMFATokens(d.tokens)),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: d.users, Sender: d.sender}, d.enrolOpts...),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions}),
	)
	require.NoError(t, err)

	return d
}

// login posts the user's password to the form login endpoint.
func (d *e2eDeployment) login(t *testing.T) served {
	t.Helper()

	return serve(t, d.chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	}))
}

// magicLinkLogin asks for a link, follows it, and returns what following it
// answered.
func (d *e2eDeployment) magicLinkLogin(t *testing.T) served {
	t.Helper()

	asked := serve(t, d.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath, e2eSource,
		url.Values{httpsec.DefaultMagicLinkAddressParam: {e2eAddress}, httpsec.DefaultMagicLinkNextParam: {"/"}}))
	require.NoError(t, asked.err)

	cookie := cookieNamed(asked.rec, httpsec.DefaultBindingCookieName)
	require.NotNil(t, cookie)

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, e2eSource,
		url.Values{httpsec.DefaultMagicLinkTokenParam: {d.sender.lastToken(t)}})
	req.AddCookie(bindingCookie(cookie.Value))

	return serve(t, d.chain, req)
}

// send posts values to path with the credential the caller holds.
func (d *e2eDeployment) send(t *testing.T, path, credential string, values url.Values) served {
	t.Helper()

	req := postValues(t.Context(), path, e2eSource, values)
	req.Header.Set("Authorization", "Bearer "+credential)

	return serve(t, d.chain, req)
}

// invoices requests a protected route with the credential the caller holds.
func (d *e2eDeployment) invoices(t *testing.T, credential string) served {
	t.Helper()

	req := getFrom(t.Context(), "/invoices", e2eSource)
	req.Header.Set("Authorization", "Bearer "+credential)

	return serve(t, d.chain, req)
}

// code is what an authenticator holding secret shows now.
func (d *e2eDeployment) code(t *testing.T, secret string) string {
	t.Helper()

	c, err := totp.GenerateCode(secret, d.clock.Now())
	require.NoError(t, err)

	return c
}

// lastEmailed is the code the latest message the user received carries.
func (d *e2eDeployment) lastEmailed(t *testing.T) string {
	t.Helper()

	d.sender.mu.Lock()
	defer d.sender.mu.Unlock()

	require.NotEmpty(t, d.sender.sent)

	code := sixDigits.FindString(d.sender.sent[len(d.sender.sent)-1].TextBody)
	require.NotEmpty(t, code, "the message carries a code")

	return code
}

// enrolmentChallenged asserts out is the enrolment challenge a login answers
// with, and returns the credential it hands back.
func enrolmentChallenged(t *testing.T, out served) string {
	t.Helper()

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch, "got %v", out.err)
	require.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
	assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
	require.NotNil(t, ch.Session)
	assert.Equal(t, session.MFAEnrolmentPending, ch.Session.MFA, "the session is enrolment-only")
	require.NotEmpty(t, ch.Token, "the credential the enrolment is carried out with")
	assert.False(t, out.handlerRan)

	return ch.Token
}

// challengedFor asserts out is a refusal with a challenge of kind, and returns
// the credential the challenge carries.
func challengedFor(t *testing.T, out served, kind policy.ChallengeKind) string {
	t.Helper()

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch, "got %v", out.err)
	assert.Equal(t, kind, ch.Kind)
	assert.False(t, out.handlerRan)

	return ch.Token
}

// confined asserts an enrolment-only credential reaches nothing but the path.
func (d *e2eDeployment) confined(t *testing.T, credential string) {
	t.Helper()

	challengedFor(t, d.invoices(t, credential), policy.ChallengeMFAEnrolment)
}

// enrolAndVerify carries an enrolment-only credential through the path: begin,
// prove the device, redeem the emailed code when email confirmation is on, and
// verify a fresh code. It returns the credential the verification rotated to.
func (d *e2eDeployment) enrolAndVerify(t *testing.T, credential string, emailed bool) string {
	t.Helper()

	begun := d.send(t, enrolBeginPath, credential, nil)
	require.NoError(t, begun.err)

	var doc beginBody
	require.NoError(t, json.Unmarshal(begun.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.Secret)

	sentBefore := d.sender.count()

	proven := d.send(t, enrolConfirmPath, credential,
		url.Values{"code": {d.code(t, doc.Secret)}})
	require.NoError(t, proven.err)
	assert.Equal(t, http.StatusNoContent, proven.rec.Code)

	if emailed {
		require.Equal(t, sentBefore+1, d.sender.count(), "the emailed code was sent")
		enrolled, err := d.totp.Enrolled(t.Context(), e2eUser)
		require.NoError(t, err)
		require.False(t, enrolled, "a proven device alone does not count")

		redeemed := d.send(t, enrolEmailPath, credential,
			url.Values{"code": {d.lastEmailed(t)}})
		require.NoError(t, redeemed.err)
		assert.Equal(t, http.StatusNoContent, redeemed.rec.Code)
		assert.Equal(t, sentBefore+2, d.sender.count(), "the binding was notified")
	} else {
		assert.Equal(t, sentBefore+1, d.sender.count(), "only the binding was notified")
	}

	enrolled, err := d.totp.Enrolled(t.Context(), e2eUser)
	require.NoError(t, err)
	require.True(t, enrolled)

	// Completing the enrolment is not a second factor.
	challengedFor(t, d.invoices(t, credential), policy.ChallengeMFA)

	// The proof spent this step's code; the verification needs a later one.
	d.clock.Advance(30 * time.Second)

	verified := d.send(t, testMFAVerifyPath, credential, url.Values{"code": {d.code(t, doc.Secret)}})
	require.NoError(t, verified.err)
	require.Equal(t, http.StatusOK, verified.rec.Code)

	rotated := accessTokenFrom(t, verified)
	require.NotEqual(t, credential, rotated)

	return rotated
}

// reached asserts credential now reaches the protected route.
func (d *e2eDeployment) reached(t *testing.T, credential string) {
	t.Helper()

	out := d.invoices(t, credential)
	require.NoError(t, out.err)
	assert.True(t, out.handlerRan, "the protected route is reached")
}

// oidcEnrolmentChain is the OIDC harness's chain under the default
// classification, which does not exempt an OIDC login: the real MFA policies
// over a real, unenrolled TOTP method, with the enrolment path on under
// pathOpts.
func oidcEnrolmentChain(t *testing.T, h *oidcHarness, pathOpts ...policy.EnrolmentPathOption) *httpsec.Chain {
	t.Helper()

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll")
	require.NoError(t, err)

	lookups, err := mfa.LookupsFor(method)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookups)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirementPolicy(nil, lookups,
		policy.WithMFARequiredForAll(), policy.WithMFAEnrolmentPath(pathOpts...),
		policy.WithFederatedAssuranceSource(h.manager))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), oidcTestUserID).AnyTimes().
		Return(&identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil)

	h.chainOpts = []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(h.tokens)),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: users, Sender: &capturingSender{}}),
	}

	return h.chain(t)
}

// TestEnrolmentPathEndToEnd runs the enrolment path through one real chain, as
// a required user with no second factor meets it: from each first factor the
// path admits, through the emailed code or without it, to a protected route
// reached with the credential the verification rotated to; and the logins it
// refuses — a federated login the allowlist leaves out, a login after the path
// closed — refused as they would be with the path off.
func TestEnrolmentPathEndToEnd(t *testing.T) {
	t.Parallel()

	t.Run("a password login enrols through the emailed code and verifies", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t).build(t)

		pending := enrolmentChallenged(t, d.login(t))
		d.confined(t, pending)

		rotated := d.enrolAndVerify(t, pending, true)
		d.reached(t, rotated)

		stale := d.invoices(t, pending)
		require.ErrorIs(t, stale.err, httpsec.ErrAuthenticationRequired, "the enrolment-only handle is gone")
		assert.False(t, stale.handlerRan)
	})

	t.Run("a password login enrols without email confirmation and verifies", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t)
		d.enrolOpts = append(d.enrolOpts, httpsec.WithoutEmailConfirmation())
		d.build(t)

		pending := enrolmentChallenged(t, d.login(t))
		d.confined(t, pending)

		d.reached(t, d.enrolAndVerify(t, pending, false))
	})

	t.Run("a magic-link login is sent to enrol", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t).build(t)

		out := d.magicLinkLogin(t)
		pending := enrolmentChallenged(t, out)

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, factor.MagicLink, ch.Session.FirstFactor)

		d.confined(t, pending)
		d.reached(t, d.enrolAndVerify(t, pending, true))
	})

	t.Run("a federated login with the exemption removed", func(t *testing.T) {
		t.Parallel()

		t.Run("is refused under the default allowlist, and its handoff kept", func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			c := oidcEnrolmentChain(t, h)
			code := h.issueHandoff(t, "")

			out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))
			require.ErrorIs(t, out.err, policy.ErrMFAEnrollmentRequired)
			assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

			var ch *httpsec.ChallengeError
			assert.NotErrorAs(t, out.err, &ch, "no enrolment challenge")
			assert.Zero(t, h.activeSessions(t), "no session is established")

			// Presented again, it is judged again rather than refused as spent.
			again := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))
			require.ErrorIs(t, again.err, policy.ErrMFAEnrollmentRequired, "the handoff was kept")
		})

		t.Run("is sent to enrol when OIDC is on the allowlist", func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			c := oidcEnrolmentChain(t, h,
				policy.WithEnrolmentFirstFactors(factor.Password, factor.MagicLink, factor.OIDC))
			code := h.issueHandoff(t, "")

			out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))
			enrolmentChallenged(t, out)

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch)
			assert.Equal(t, factor.OIDC, ch.Session.FirstFactor)
			assert.Equal(t, 1, h.activeSessions(t))

			again := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))
			require.ErrorIs(t, again.err, oidc.ErrInvalidHandoff, "the handoff was consumed")
		})
	})

	t.Run("a login after the path closed is refused", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t)
		d.pathOpts = append(d.pathOpts, policy.WithEnrolmentPathUntil(time.Now().Add(-time.Minute)))
		d.build(t)

		out := d.login(t)
		require.ErrorIs(t, out.err, policy.ErrMFAEnrollmentRequired)
		assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

		var ch *httpsec.ChallengeError
		assert.NotErrorAs(t, out.err, &ch, "no enrolment challenge")

		count, err := d.sessions.CountActiveByUser(t.Context(), e2eUser)
		require.NoError(t, err)
		assert.Zero(t, count, "no session is established")
	})

	t.Run("an enrolment reset by an operator sends the next login to enrol", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t).build(t)

		// Enrolled out of band, so a login is challenged for the factor.
		provisioning, err := d.totp.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
		require.NoError(t, err)
		require.NoError(t, d.totp.ConfirmEnrolment(t.Context(), e2eUser, d.code(t, provisioning.Secret)))
		d.clock.Advance(30 * time.Second)

		held := challengedFor(t, d.login(t), policy.ChallengeMFA)

		require.NoError(t, mfa.ResetEnrolment(t.Context(), e2eUser, mfa.ResetDeps{
			Enrolments: []mfa.EnrolmentRemover{d.totp}, Sessions: d.sessions, Users: d.users, Sender: d.sender,
		}))

		stale := d.invoices(t, held)
		require.ErrorIs(t, stale.err, httpsec.ErrAuthenticationRequired,
			"the session held before the reset no longer authenticates")
		assert.False(t, stale.handlerRan)

		pending := enrolmentChallenged(t, d.login(t))
		d.confined(t, pending)
		d.reached(t, d.enrolAndVerify(t, pending, true))
	})

	t.Run("a user no longer required stays confined until a fresh login", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t).build(t)

		pending := enrolmentChallenged(t, d.login(t))

		// The operator lifts the requirement while the session is live. The
		// gate reads the session's state, not the policy, so it stays
		// confined.
		d.required.on.Store(false)
		d.confined(t, pending)

		fresh := d.login(t)
		require.NoError(t, fresh.err)
		require.Equal(t, http.StatusOK, fresh.rec.Code)

		var body loginBody
		require.NoError(t, json.Unmarshal(fresh.rec.Body.Bytes(), &body))
		require.NotEmpty(t, body.AccessToken)

		d.reached(t, body.AccessToken)
		d.confined(t, pending)
	})
}
