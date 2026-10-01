package httpsec_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestPasskeyRecoveryRoute runs a recovered session through the passkey
// route over HTTP: created and confined at 09:00 under a 12-hour absolute
// timeout, it registers a passkey, owes a second factor while keeping its
// deadline and recovery time, proves the passkey at the MFA slot at 09:05,
// and ends with a rotated full session whose deadline is 21:00 and whose
// recovery time is 09:00.
func TestPasskeyRecoveryRoute(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	clk := clockwork.NewFakeClockAt(recoveryStart)

	sessions, err := session.NewManager(session.WithClock(clk), session.WithAbsoluteTimeout(12*time.Hour),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	d := &e2eDeployment{
		sessions: sessions,
		clock:    clk,
		users:    NewMockUserLoader(ctrl),
		sender:   &capturingSender{},
		tokens:   NewMockGenerator(ctrl),
		required: &requiredFlag{},
	}
	d.wireUsers(t)
	d.wireTokens()

	d.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll", mfa.WithClock(clk))
	require.NoError(t, err)

	v := newPasskeyVerifierStub(t)

	pm, err := passkey.New(passkey.Deps{Verifier: v.mock, Users: d.users, Sender: d.sender},
		passkey.WithRepudiationContact("help@example.com"))
	require.NoError(t, err)

	method := pm.MFAMethod()

	lookups, err := mfa.LookupsFor(d.totp, method)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookups)
	require.NoError(t, err)

	d.chain, err = httpsec.New(
		httpsec.WithPolicyEngine(engineOf(t, challenge)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: d.tokens, Sessions: d.sessions, Users: d.users}),
		httpsec.EnableMFA([]mfa.Method{d.totp, method}, httpsec.WithMFATokens(d.tokens)),
		httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: pm, Sessions: d.sessions}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions}),
		httpsec.EnableRecoveryGateForTest(),
	)
	require.NoError(t, err)

	s, err := d.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Recovery))
	require.NoError(t, err)

	d.sessions.MarkRecoveryPending(s, recoveryLifetime, clk.Now())
	require.NoError(t, d.sessions.Save(t.Context(), s))

	credential := mfaTokenFor(s.ID)

	bearer := func(req *http.Request) *http.Request {
		req.Header.Set("Authorization", "Bearer "+credential)

		return req
	}

	stored := func(handle string) *session.Session {
		got, err := d.sessions.Load(t.Context(), handle)
		require.NoError(t, err)

		return got
	}

	begun := serve(t, d.chain, bearer(jsonPost(t.Context(), passkeyBeginPath, "")))
	require.NoError(t, begun.err)

	finished := serve(t, d.chain, bearer(jsonPost(t.Context(), passkeyFinishPath,
		registrationBody(v.lastCreation(t), "cred-1"))))
	require.NoError(t, finished.err)
	require.Equal(t, http.StatusOK, finished.rec.Code)

	// The binding moves the session on to its second factor, and keeps its
	// confinement marker, its deadline and its recovery time until the
	// passkey is proven.
	bound := stored(s.ID)
	assert.Equal(t, session.MFAPending, bound.MFA)
	assert.Equal(t, s.EnrolmentOriginDeadline, bound.EnrolmentOriginDeadline)
	assert.Equal(t, s.AbsoluteExpiresAt, bound.AbsoluteExpiresAt)
	assert.True(t, bound.RecoveredAt.Equal(recoveryStart), "the recovery time is kept, got %s", bound.RecoveredAt)

	challengedFor(t, d.invoices(t, credential), policy.ChallengeMFA)

	clk.Advance(5 * time.Minute)

	mfaBegun := serve(t, d.chain, bearer(jsonPost(t.Context(), httpsec.DefaultMFABeginPrefix+"/"+passkey.MethodName, "")))
	require.NoError(t, mfaBegun.err)

	verified := serve(t, d.chain, bearer(jsonPost(t.Context(), httpsec.DefaultMFAVerifyPrefix+"/"+passkey.MethodName,
		assertionBody(v.lastRequest(t), "cred-1"))))
	require.NoError(t, verified.err)
	require.Equal(t, http.StatusOK, verified.rec.Code)

	rotated := accessTokenFrom(t, verified)
	require.NotEqual(t, credential, rotated, "the verification rotates the session")

	id, ok := strings.CutPrefix(rotated, mfaTokenPrefix)
	require.True(t, ok)

	got := stored(id)
	assert.Equal(t, session.MFASatisfied, got.MFA)
	assert.True(t, got.AbsoluteExpiresAt.Equal(recoveryStart.Add(12*time.Hour)),
		"the absolute deadline is restored to 21:00, got %s", got.AbsoluteExpiresAt)
	assert.True(t, got.RecoveredAt.Equal(recoveryStart), "the recovery time is kept, got %s", got.RecoveredAt)
	assert.True(t, got.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")

	_, err = d.sessions.Load(t.Context(), s.ID)
	require.Error(t, err, "the recovery-pending handle no longer loads")

	d.reached(t, rotated)
}
