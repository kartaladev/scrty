package httpsec_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// recoveryStart is when the recovery-pending session in these tests is
// created and marked: 09:00, so a 12-hour absolute timeout ends it at 21:00.
var recoveryStart = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

// recoveryDeployment is the end-to-end deployment with the recovery gate and
// a password-change resolve endpoint, over a session manager and a TOTP method
// that share one fake clock, so a case can say at what time each step runs.
type recoveryDeployment struct {
	*e2eDeployment

	// changed records that the consumer's password-change function ran, and
	// changeErr is what it returns.
	changed    atomic.Bool
	changeErr  error
	owesChange bool
}

// recoverySetup is what a case varies about the deployment.
type recoverySetup struct {
	// required is whether the user must use a second factor.
	required bool

	// pathOpts configure the requirement policy's enrolment path.
	pathOpts []policy.EnrolmentPathOption

	// changeErr is what the consumer's password-change function returns.
	changeErr error

	// owesChange marks the recovery-pending session as also owing a password
	// change, as a recovery whose reset asks for one leaves it.
	owesChange bool

	// enrolmentPathOff builds the requirement policy with no enrolment path at
	// all, rather than one configured by pathOpts.
	enrolmentPathOff bool
}

func newRecoveryDeployment(t *testing.T, setup recoverySetup) *recoveryDeployment {
	t.Helper()

	ctrl := gomock.NewController(t)
	clk := clockwork.NewFakeClockAt(recoveryStart)

	sessions, err := session.NewManager(session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	d := &recoveryDeployment{
		e2eDeployment: &e2eDeployment{
			sessions: sessions,
			clock:    clk,
			users:    NewMockUserLoader(ctrl),
			sender:   &capturingSender{},
			tokens:   NewMockGenerator(ctrl),
			required: &requiredFlag{},
			pathOpts: setup.pathOpts,
		},
		changeErr:  setup.changeErr,
		owesChange: setup.owesChange,
	}
	d.required.on.Store(setup.required)

	d.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll", mfa.WithClock(clk))
	require.NoError(t, err)

	d.wireUsers(t)
	d.wireTokens()

	lookups, err := mfa.LookupsFor(d.totp)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookups)
	require.NoError(t, err)

	var requirementOpts []policy.MFARequirementOption
	if !setup.enrolmentPathOff {
		requirementOpts = append(requirementOpts, policy.WithMFAEnrolmentPath(d.pathOpts...))
	}

	requirement, err := policy.NewMFARequirementPolicy(d.required, lookups, requirementOpts...)
	require.NoError(t, err)

	change := func(*httpsec.Exchange) error {
		d.changed.Store(true)
		return d.changeErr
	}

	chainOpts := []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: d.tokens, Sessions: d.sessions, Users: d.users,
		}),
		httpsec.EnableMFA([]mfa.Method{d.totp}, httpsec.WithMFATokens(d.tokens)),
	}
	// With the enrolment path off, no policy ever raises ChallengeMFAEnrolment,
	// and the enrolment interceptor refuses to be registered over one that
	// cannot.
	if !setup.enrolmentPathOff {
		chainOpts = append(chainOpts,
			httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: d.users, Sender: d.sender}))
	}
	chainOpts = append(chainOpts,
		httpsec.EnablePasswordChangeGate(d.sessions,
			httpsec.WithChangePasswordEndpoint(passwordResolvePath, change)),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions}),
		httpsec.EnableRecoveryGateForTest(),
	)

	d.chain, err = httpsec.New(chainOpts...)
	require.NoError(t, err)

	return d
}

// recovered is a recovery-pending session for the user, created and marked at
// recoveryStart as a completed recovery creates and marks it, and the
// credential that names it.
func (d *recoveryDeployment) recovered(t *testing.T) (*session.Session, string) {
	t.Helper()

	s, err := d.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Recovery))
	require.NoError(t, err)

	d.sessions.MarkRecoveryPending(s, recoveryLifetime, d.clock.Now())
	s.PasswordChangePending = d.owesChange
	require.NoError(t, d.sessions.Save(t.Context(), s))

	return s, mfaTokenFor(s.ID)
}

// enrolled begins a TOTP enrolment, proves the device and redeems the emailed
// code, and returns the secret the authenticator holds.
func (d *recoveryDeployment) enrolled(t *testing.T, credential string) string {
	t.Helper()

	begun := d.send(t, enrolBeginPath, credential, nil)
	require.NoError(t, begun.err)

	var doc beginBody
	require.NoError(t, json.Unmarshal(begun.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.Secret)

	proven := d.send(t, enrolConfirmPath, credential, url.Values{"code": {d.code(t, doc.Secret)}})
	require.NoError(t, proven.err)
	require.Equal(t, http.StatusNoContent, proven.rec.Code)

	redeemed := d.send(t, enrolEmailPath, credential, url.Values{"code": {d.lastEmailed(t)}})
	require.NoError(t, redeemed.err)
	require.Equal(t, http.StatusNoContent, redeemed.rec.Code)

	return doc.Secret
}

// stored reloads a session by handle.
func (d *recoveryDeployment) stored(t *testing.T, handle string) *session.Session {
	t.Helper()

	s, err := d.sessions.Load(t.Context(), handle)
	require.NoError(t, err)

	return s
}

// TestRecoveryBind pins the two ways a recovery-pending session is bound, and
// so leaves the state: an enrolment through the enrolment path followed by a
// verification, and a password change resolved at the consumer's endpoint.
func TestRecoveryBind(t *testing.T) {
	t.Parallel()

	// fullDeadline is the absolute deadline a session created at
	// recoveryStart has under the default 12-hour absolute timeout.
	fullDeadline := recoveryStart.Add(12 * time.Hour)

	type testCase struct {
		name  string
		setup recoverySetup

		// act carries the recovery-pending session s, named by credential,
		// through the steps of the case.
		act    func(t *testing.T, d *recoveryDeployment, s *session.Session, credential string)
		assert func(t *testing.T, d *recoveryDeployment, s *session.Session)
	}

	resolve := func(t *testing.T, d *recoveryDeployment, credential string) served {
		t.Helper()

		return d.send(t, passwordResolvePath, credential, url.Values{"password": {"a new one"}})
	}

	cases := []testCase{
		{
			name:  "an enrolment after recovery ends satisfied, with the deadline and the recovery time",
			setup: recoverySetup{required: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				secret := d.enrolled(t, credential)

				d.clock.Advance(9 * time.Minute)

				verified := d.send(t, testMFAVerifyPath, credential, url.Values{"code": {d.code(t, secret)}})
				require.NoError(t, verified.err)
				require.Equal(t, http.StatusOK, verified.rec.Code)

				rotated := accessTokenFrom(t, verified)
				require.NotEqual(t, credential, rotated, "the verification rotates the session")

				id, ok := strings.CutPrefix(rotated, mfaTokenPrefix)
				require.True(t, ok)

				got := d.stored(t, id)
				assert.Equal(t, session.MFASatisfied, got.MFA)
				assert.True(t, got.AbsoluteExpiresAt.Equal(fullDeadline),
					"the absolute deadline is restored to 21:00, got %s", got.AbsoluteExpiresAt)
				assert.True(t, got.RecoveredAt.Equal(recoveryStart),
					"the recovery time is kept, got %s", got.RecoveredAt)
				assert.True(t, got.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")

				d.reached(t, rotated)
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				_, err := d.sessions.Load(t.Context(), s.ID)
				require.Error(t, err, "the recovery-pending handle no longer loads")
			},
		},
		{
			name:  "a confirmed enrolment alone is not enough",
			setup: recoverySetup{required: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				d.enrolled(t, credential)

				challengedFor(t, d.invoices(t, credential), policy.ChallengeMFA)
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				got := d.stored(t, s.ID)
				assert.Equal(t, session.MFAPending, got.MFA, "the confirmation moves the session to MFA pending")
				assert.True(t, got.EnrolmentOriginDeadline.Equal(fullDeadline), "the confinement marker is kept")
				assert.True(t, got.AbsoluteExpiresAt.Equal(recoveryStart.Add(recoveryLifetime)),
					"the lowered deadline stays until the verification")
				assert.True(t, got.RecoveredAt.Equal(recoveryStart), "the recovery time is kept")
			},
		},
		{
			name:  "the password route restores the deadline, keeps the handle and reaches the handler",
			setup: recoverySetup{owesChange: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				d.clock.Advance(5 * time.Minute)

				out := resolve(t, d, credential)
				require.NoError(t, out.err)
				assert.True(t, d.changed.Load(), "the consumer's function runs")

				d.reached(t, credential)
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				got := d.stored(t, s.ID)
				assert.Equal(t, session.MFANone, got.MFA)
				assert.False(t, got.PasswordChangePending, "the pending password change is cleared")
				assert.True(t, got.AbsoluteExpiresAt.Equal(fullDeadline),
					"the absolute deadline is restored to 21:00, got %s", got.AbsoluteExpiresAt)
				assert.True(t, got.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")
				assert.True(t, got.RecoveredAt.Equal(recoveryStart), "the recovery time is kept")
			},
		},
		{
			name:  "the password route for a required user with the enrolment path on",
			setup: recoverySetup{required: true, owesChange: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				require.NoError(t, resolve(t, d, credential).err)

				challengedFor(t, d.invoices(t, credential), policy.ChallengeMFAEnrolment)
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				assert.Equal(t, session.MFAEnrolmentPending, d.stored(t, s.ID).MFA,
					"the policies decide what the bound session owes")
			},
		},
		{
			name:  "the consumer's function fails",
			setup: recoverySetup{changeErr: errChangeRefused, owesChange: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				out := resolve(t, d, credential)
				require.ErrorIs(t, out.err, errChangeRefused, "the consumer's error is the refusal")
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				got := d.stored(t, s.ID)
				assert.Equal(t, session.MFARecoveryPending, got.MFA, "the session stays recovery-pending")
				assert.True(t, got.PasswordChangePending)
				assert.True(t, got.AbsoluteExpiresAt.Equal(recoveryStart.Add(recoveryLifetime)),
					"the deadline stays lowered")
			},
		},
		{
			// The stated limit (design D8): with the enrolment path off, a
			// required user left with no usable second factor after the reset
			// has no enrolment route at all. Every request is refused as their
			// login would be, before either binding endpoint is reached.
			name:  "a required user with no usable method is refused when the enrolment path is off",
			setup: recoverySetup{required: true, enrolmentPathOff: true},
			act: func(t *testing.T, d *recoveryDeployment, _ *session.Session, credential string) {
				t.Helper()

				out := d.invoices(t, credential)
				require.ErrorIs(t, out.err, policy.ErrMFAEnrollmentRequired)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, out.err, &ch, "no challenge, only a denial")
			},
			assert: func(t *testing.T, d *recoveryDeployment, s *session.Session) {
				t.Helper()

				got := d.stored(t, s.ID)
				assert.Equal(t, session.MFARecoveryPending, got.MFA, "the session stays recovery-pending")
				assert.True(t, got.AbsoluteExpiresAt.Equal(recoveryStart.Add(recoveryLifetime)),
					"the deadline stays lowered")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newRecoveryDeployment(t, tc.setup)
			s, credential := d.recovered(t)

			tc.act(t, d, s, credential)
			tc.assert(t, d, s)
		})
	}
}

// TestRecoveryEnrolmentSaveFails pins that a recovery-pending session whose
// confirmed enrolment cannot be saved is left recovery-pending in memory too,
// not moved to the enrolment-only state it never held. It stands alone
// because it needs a session store that fails on demand and a session carried
// in memory, which no other case here does.
func TestRecoveryEnrolmentSaveFails(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	h.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	h.enrolOpts = []httpsec.EnrolmentOption{httpsec.WithoutEmailConfirmation()}
	h.extra = []httpsec.Option{httpsec.EnableRecoveryGateForTest()}

	var failing atomic.Bool

	var err error
	h.sessions, err = session.NewManager(session.WithStore(
		failingSaves{Store: session.NewMemoryStore(), failing: &failing}))
	require.NoError(t, err)

	s := h.recoveryPending(t)
	h.pinned = s

	c := h.chain(t, s)
	secret := h.beginDoc(t, c).Secret

	failing.Store(true)

	out := serve(t, c, post(t.Context(), enrolConfirmPath, "code="+h.codeFor(t, secret)))

	require.ErrorIs(t, out.err, errStoreLeaky)
	assert.Equal(t, session.MFARecoveryPending, s.MFA, "the session keeps the state it had, in memory too")
	assert.True(t, h.enrolled(t), "the binding stands")
}

// TestRecoveryResolveRefused pins the password-change resolve endpoint's
// refusals on a recovery-pending session, each of which leaves the session in
// memory exactly as it was. A session already past its lowered deadline is not
// revived: the request is answered as for any session that no longer loads,
// and the consumer's function is not run, so no password is changed on a
// request that is then refused. A session that cannot be saved after the
// change keeps its recovery-pending state and its lowered deadlines in memory
// too. It has its own table because each case carries a session in memory
// over a session manager built for it.
func TestRecoveryResolveRefused(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// arrange builds h's session manager and returns what to do once the
		// session exists and before the request is served.
		arrange func(t *testing.T, h *enrolHarness) func()

		assert func(t *testing.T, err error, w *gateWitnesses, before, after session.Session)
	}

	unchanged := func(t *testing.T, before, after session.Session) {
		t.Helper()

		assert.Equal(t, session.MFARecoveryPending, after.MFA, "the session is not moved out of its state")
		assert.True(t, after.AbsoluteExpiresAt.Equal(before.AbsoluteExpiresAt), "nor are its deadlines restored")
		assert.Equal(t, before, after, "the session in memory is as it was")
	}

	cases := []testCase{
		{
			name: "past its lowered deadline",
			arrange: func(t *testing.T, h *enrolHarness) func() {
				t.Helper()

				clk := clockwork.NewFakeClockAt(recoveryStart)

				var err error
				h.sessions, err = session.NewManager(session.WithClock(clk),
					session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
				require.NoError(t, err)

				return func() { clk.Advance(recoveryLifetime + time.Minute) }
			},
			assert: func(t *testing.T, err error, w *gateWitnesses, before, after session.Session) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
				assert.False(t, w.change.Load(), "the consumer's function is not run")
				unchanged(t, before, after)
			},
		},
		{
			name: "the session cannot be saved",
			arrange: func(t *testing.T, h *enrolHarness) func() {
				t.Helper()

				var failing atomic.Bool

				var err error
				h.sessions, err = session.NewManager(session.WithStore(
					failingSaves{Store: session.NewMemoryStore(), failing: &failing}))
				require.NoError(t, err)

				return func() { failing.Store(true) }
			},
			assert: func(t *testing.T, err error, w *gateWitnesses, before, after session.Session) {
				t.Helper()

				require.ErrorIs(t, err, errStoreLeaky)
				assert.True(t, w.change.Load(), "the consumer's function ran")
				unchanged(t, before, after)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newEnrolHarness(t)
			ready := tc.arrange(t, h)

			w := &gateWitnesses{}
			h.extra = append(w.options(h), httpsec.EnableRecoveryGateForTest())

			s := h.recoveryPending(t)
			h.pinned = s
			before := *s

			ready()

			out := serve(t, h.chain(t, s), post(t.Context(), passwordResolvePath, "password=new"))

			tc.assert(t, out.err, w, before, *s)
		})
	}
}
