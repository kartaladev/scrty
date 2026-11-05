package httpsec_test

// A consumer who keeps grants on a recovery, a second-factor reset or a clone suspension keeps the
// grants holding offline_access, and nothing more: a grant without it still ends with the sign-in
// that ended, because the sessions end through a manager that reports to the provider.

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// signInGrants is a sign-in with an online grant and an offline one, both from it.
type signInGrants struct {
	signIn *session.Session
	online id.ID
	// onlineRefresh and refresh are the refresh tokens of the online and the offline grant.
	onlineRefresh, refresh string
}

// grantsFrom signs u-1 in and exchanges two codes from that one sign-in: openid alone, and with
// offline_access.
func (w *grantWorld) grantsFrom(t *testing.T) signInGrants {
	t.Helper()

	s := w.signIn(t)
	issue := func(scope string) map[string]any {
		return assertTokenIssued(t, w.send(t, exchangeOf(w.codeFrom(t, scope, s)), asClient(tokenWeb)), "Bearer")
	}

	online := issue("openid")
	onlineRefresh, ok := online["refresh_token"].(string)
	require.True(t, ok, "a client registered for the refresh grant holds a refresh token also without offline_access")
	offline := issue("openid offline_access")
	refresh, ok := offline["refresh_token"].(string)
	require.True(t, ok)

	return signInGrants{signIn: s, online: gidOf(t, online["access_token"].(string)), onlineRefresh: onlineRefresh, refresh: refresh}
}

// codeFrom is a code for scope, from the sign-in s.
func (w *grantWorld) codeFrom(t *testing.T, scope string, s *session.Session) string {
	t.Helper()

	parked, err := w.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: url.Values{
		"response_type": {"code"}, "client_id": {tokenWeb}, "redirect_uri": {rpCallback}, "scope": {scope},
		"state": {"xyz"}, "code_challenge": {pkceChallengeS256}, "code_challenge_method": {"S256"},
	}})
	require.NoError(t, err)
	require.NotEmpty(t, parked.FlowSecret, parked.Location)
	login, err := url.Parse(parked.Location)
	require.NoError(t, err)
	require.NoError(t, w.consents.Give(t.Context(), s.UserID, tokenWeb, strings.Fields(scope), true, w.clk.Now()))

	res, err := w.p.Resume(t.Context(), oidcprovider.ResumeInput{
		Handle: login.Query().Get("req"), FlowSecret: parked.FlowSecret,
		SignIn: &oidcprovider.SignIn{
			User: s.UserID, Family: s.FamilyID, AuthenticatedAt: w.clk.Now(), AMR: []string{"pwd"},
			AbsoluteExpiresAt: w.clk.Now().Add(8 * time.Hour),
		},
		IdleTimeout: 15 * time.Minute,
	})
	require.NoError(t, err)
	location, err := url.Parse(res.RedirectTo)
	require.NoError(t, err)

	return location.Query().Get("code")
}

// gidOf reads the grant family an access token names, without verifying the token.
func gidOf(t *testing.T, accessToken string) id.ID {
	t.Helper()

	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3, "a JWT access token")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		GID string `json:"gid"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))

	return must.Must(id.Parse(claims.GID))
}

// assertKeptOnlyOffline asserts the offline grant works and the online one ended with its sign-in,
// and that the provider was never asked to revoke by user.
func (w *grantWorld) assertKeptOnlyOffline(t *testing.T, g signInGrants) {
	t.Helper()

	assert.Empty(t, w.grants.causes(), "no revocation by user ran")
	w.assertGrantWorks(t, g.refresh)

	got, err := w.grants.Load(t.Context(), g.online)
	require.NoError(t, err)
	assert.True(t, got.Revoked, "the online grant ended with its sign-in")
	w.assertGrantRevoked(t, g.onlineRefresh)
	assert.Equal(t, oidcprovider.CauseSignInEnded, got.RevokeCause)
}

func TestRecovery_KeepingGrantsEndsOnlineGrantsWithTheirSignIn(t *testing.T) {
	t.Parallel()

	w := newGrantWorld(t)
	g := w.grantsFrom(t)

	h := newRecoveryHarness(t)
	h.proofs = []recovery.ProofKind{recovery.ProofSaved, recovery.ProofIssued}
	h.reference = true
	h.sessions = w.sessions
	h.chainOpts = []httpsec.Option{
		httpsec.EnableJWKSEndpoint(tokenKeys()), httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(), httpsec.EnableOIDCProvider(w.p),
	}
	h.coreOpts = []recovery.Option{recovery.WithoutRecoveryGrantRevocation()}
	h.build(t)

	out := h.complete(t, recoveryForm(
		httpsec.RecoverySavedCodeParam, h.saved(t),
		httpsec.RecoveryIssuedCodeParam, h.issued(t),
	))
	recoveredBySession(t, h, out)

	_, err := w.sessions.Load(t.Context(), g.signIn.ID)
	require.ErrorIs(t, err, session.ErrNotFound, "the earlier sign-in ended")
	w.assertKeptOnlyOffline(t, g)
}

func TestResetEnrolment_KeepingGrantsEndsOnlineGrantsWithTheirSignIn(t *testing.T) {
	t.Parallel()

	w := newGrantWorld(t)
	g := w.grantsFrom(t)
	totp := must.Must(mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example"))

	require.NoError(t, mfa.ResetEnrolment(t.Context(), "u-1", mfa.ResetDeps{
		Enrolments: []mfa.EnrolmentRemover{totp},
		Sessions:   w.sessions,
		Grants:     w.p,
	}, mfa.WithoutResetGrantRevocation(), mfa.WithoutResetNotification()))

	_, err := w.sessions.Load(t.Context(), g.signIn.ID)
	require.ErrorIs(t, err, session.ErrNotFound, "the sessions ended")
	w.assertKeptOnlyOffline(t, g)
}

func TestPasskey_KeepingGrantsOnCloneEndsOnlineGrantsWithTheirSignIn(t *testing.T) {
	t.Parallel()

	w := newGrantWorld(t)
	g := w.grantsFrom(t)
	d := newPwlDeployment(t)

	m, err := passkey.New(passkey.Deps{
		Verifier: d.verifier.mock, Credentials: d.creds, Handles: d.handles,
		Users: d.users, Sender: d.notices, Sessions: w.sessions,
	}, passkey.WithRepudiationContact("help@example.com"), passkey.WithOptionalRecoveryCodes(),
		passkey.WithGrantRevoker(w.p), passkey.WithoutCloneGrantRevocation())
	require.NoError(t, err)
	handle := d.seedCounted(t, e2eUser, "cred-1", passkey.StateActive, 5)

	_, err = m.BeginLogin(t.Context(), "ceremony")
	require.NoError(t, err)
	body := handleAssertionBody(d.verifier.lastRequest(t), "cred-1", handle)
	_, err = m.Authenticate(t.Context(), []byte(body), "ceremony")
	require.ErrorIs(t, err, passkey.ErrCloneSuspected)

	_, err = w.sessions.Load(t.Context(), g.signIn.ID)
	require.ErrorIs(t, err, session.ErrNotFound, "the user's sessions ended")
	w.assertKeptOnlyOffline(t, g)
}
