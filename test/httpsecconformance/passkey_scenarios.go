package httpsecconformance

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/passkey/webauthn"
	"github.com/kartaladev/scrty/passkey/webauthn/webauthntest"
	pgxstore "github.com/kartaladev/scrty/pgx"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// The relying party every passkey scenario's authenticator and verifier agree
// on. An authenticator answers for exactly this ID and origin, so a response
// the chain accepts has been checked against them by the real verifier.
const (
	passkeyRPID            = "example.com"
	passkeyOrigin          = "https://example.com" //nolint:gosec // G101: a fixture string, not a credential
	passkeyRegisterBegin   = httpsec.DefaultPasskeyRegistrationPrefix + "/begin"
	passkeyRegisterFinish  = httpsec.DefaultPasskeyRegistrationPrefix + "/finish"
	passkeyConfirm         = httpsec.DefaultPasskeyRegistrationPrefix + "/confirm"
	passkeyConfirmEmail    = httpsec.DefaultPasskeyRegistrationPrefix + "/confirm-email"
	passkeyList            = httpsec.DefaultPasskeyCredentialsPrefix
	passkeyRemove          = httpsec.DefaultPasskeyCredentialsPrefix + "/remove"
	passwordlessBeginPath  = httpsec.DefaultPasswordlessPrefix + "/begin"
	passwordlessFinishPath = httpsec.DefaultPasswordlessPrefix + "/finish"
	mfaBeginPasskey        = httpsec.DefaultMFABeginPrefix + "/" + passkey.MethodName
	mfaVerifyPasskey       = httpsec.DefaultMFAVerifyPrefix + "/" + passkey.MethodName
	mfaVerifyTOTP          = httpsec.DefaultMFAVerifyPrefix + "/totp"
)

// PasskeyFixture is the passkey wiring of one run, over the durable stores of
// its RecoveryFixture: the passkey credentials and user handles live in the
// same PostgreSQL database as the sessions, the saved codes and the one-time
// challenges, so nothing a ceremony needs is held in a framework's memory.
type PasskeyFixture struct {
	// Base is the durable session, saved-code and one-time wiring the passkey
	// stores sit beside.
	Base *RecoveryFixture

	// Manager runs the ceremonies the chain's endpoints serve.
	Manager *passkey.Manager

	// Credentials is the durable passkey store, read back by a scenario to
	// assert what a ceremony left.
	Credentials passkey.CredentialStore

	// TOTPSecret is the secret of the user's enrolled authenticator app, or
	// empty when the scenario did not enrol one.
	TOTPSecret string
}

// passkeyBuild selects what a passkey scenario's wiring contains beyond the
// part every one shares.
type passkeyBuild struct {
	// savedCodes wires saved recovery codes to registration, so a user with no
	// other way back registers a passkey that waits for them. Without it the
	// optional mode is used and a passkey is active at once.
	savedCodes bool

	// enrolTOTP enrols the user on an authenticator app first.
	enrolTOTP bool
}

// newPasskeyFixture wires the durable stores and the manager.
func newPasskeyFixture(t *testing.T, b passkeyBuild) (*PasskeyFixture, *session.Manager) {
	t.Helper()

	base, sessions := newRecoveryFixture(t)
	ctx := t.Context()

	credentials, err := pgxstore.NewPasskeyCredentialStore(base.Pool, storefix.TestCipher(t))
	require.NoError(t, err)

	handles, err := pgxstore.NewPasskeyHandleStore(base.Pool)
	require.NoError(t, err)

	verifier, err := webauthn.New(passkey.RelyingParty{
		ID: passkeyRPID, Name: "Example", Origins: []string{passkeyOrigin},
	})
	require.NoError(t, err)

	pf := &PasskeyFixture{Base: base, Credentials: credentials}

	deps := passkey.Deps{
		Verifier:    verifier,
		Credentials: credentials,
		Handles:     handles,
		Challenges:  base.OneTime,
		Users:       fixtureUsers{},
		Sender:      base.Outbox,
	}
	opts := []passkey.Option{
		passkey.WithRepudiationContact("security@example.com"),
		passkey.WithClock(base.Clock),
	}

	if b.enrolTOTP {
		lookups, err := mfa.LookupsFor(base.TOTP)
		require.NoError(t, err)

		deps.MFAMethods = lookups

		provisioning, err := base.TOTP.BeginEnrolment(ctx, UserID, Username)
		require.NoError(t, err)

		code, err := totp.GenerateCode(provisioning.Secret, base.Clock.Now())
		require.NoError(t, err)
		require.NoError(t, base.TOTP.ConfirmEnrolment(ctx, UserID, code))

		pf.TOTPSecret = provisioning.Secret
	}

	if b.savedCodes {
		wayBack, err := recovery.NewWayBackCheck(recovery.WayBackDeps{Users: fixtureUsers{}, Codes: base.Codes})
		require.NoError(t, err)

		deps.Recovery = &passkey.RecoveryDeps{Codes: base.Codes, WayBack: wayBack}
	} else {
		opts = append(opts, passkey.WithOptionalRecoveryCodes())
	}

	pf.Manager, err = passkey.New(deps, opts...)
	require.NoError(t, err)

	return pf, sessions
}

// totpCode is the code the enrolled authenticator app shows now, moved on one
// period first so a code the enrolment already spent is never presented again.
func (pf *PasskeyFixture) totpCode(t *testing.T) string {
	t.Helper()

	pf.Base.Clock.Advance(pf.Base.TOTP.Period())

	code, err := totp.GenerateCode(pf.TOTPSecret, pf.Base.Clock.Now())
	require.NoError(t, err)

	return code
}

// methods are the second-factor methods of a chain: the authenticator app
// when the user enrolled one, and always the passkey.
func (pf *PasskeyFixture) methods(withTOTP bool) []mfa.Method {
	if withTOTP {
		return []mfa.Method{pf.Base.TOTP, pf.Manager.MFAMethod()}
	}

	return []mfa.Method{pf.Manager.MFAMethod()}
}

// passkeyOptions is the chain every passkey scenario shares, in the order a
// consumer would wire it: a second-factor challenge policy over the methods,
// form login and bearer authentication, the MFA slot, and the passkey
// endpoints with passwordless login on.
//
// The MFA slot's challenge store is the durable one: a challenge a begin
// request issued has to be there for a verify request served by a chain built
// afterwards, as it is behind two replicas.
func (pf *PasskeyFixture) options(
	t *testing.T, e *Effects, sessions *session.Manager, withTOTP bool,
) []httpsec.Option {
	t.Helper()

	methods := pf.methods(withTOTP)

	lookups, err := mfa.LookupsFor(methods...)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookups)
	require.NoError(t, err)

	engine, err := policy.NewEngine(challenge)
	require.NoError(t, err)

	return append(append(formLoginOptions(e), bearerOptions(e)...),
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableMFA(methods,
			httpsec.WithMFATokens(fixtureTokens{}),
			httpsec.WithMFAChallengeStore(pf.Base.OneTime)),
		httpsec.EnablePasskeys(
			httpsec.PasskeyDeps{Passkeys: pf.Manager, Sessions: sessions, Users: fixtureUsers{}},
			httpsec.WithPasswordlessLogin()),
	)
}

// passkeyRoutes is the application route a scenario ends on: a full session
// reaches it, and anything less is stopped in front of it.
func passkeyRoutes() []Route {
	return []Route{{Method: http.MethodGet, Path: RoutePath, Status: http.StatusOK, Body: RouteBody}}
}

// passkeyEffects is the Effects of a passkey scenario. The session store is the
// durable one, so a scenario reads sessions through Passkey.Base.
func passkeyEffects(pf *PasskeyFixture, sessions *session.Manager) *Effects {
	return &Effects{
		Sessions: sessions,
		Attempts: policy.NewMemoryAttemptStore(),
		Recovery: pf.Base,
		Passkey:  pf,
	}
}

// confirmedSession pre-creates the session a registration is made from: a
// password session whose second factor is satisfied when the user has one.
func (pf *PasskeyFixture) confirmedSession(t *testing.T, sessions *session.Manager, satisfied bool) *session.Session {
	t.Helper()

	s, err := sessions.Create(t.Context(), UserID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	if satisfied {
		s.MFA = session.MFASatisfied
		s.MFASatisfiedAt = pf.Base.Clock.Now()
	}

	require.NoError(t, sessions.Save(t.Context(), s))

	return s
}

// passkeyClient drives a passkey conversation through one adapter, as a
// browser and its authenticator would.
type passkeyClient struct {
	t    *testing.T
	send func(RequestSpec) Result
	auth *webauthntest.Authenticator
	pf   *PasskeyFixture
}

// newPasskeyClient builds the client inside the subtest that uses it, because
// the authenticator reports its failures to the test it was built with.
func newPasskeyClient(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) *passkeyClient {
	t.Helper()

	return &passkeyClient{t: t, send: send, auth: webauthntest.New(t), pf: spec.Effects.Passkey}
}

// bearer is the header of a request made as the session sid.
func bearer(sid string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + issuedTokenFor(Username, sid)}
}

// bearerToken is the header of a request made with the credential token.
func bearerToken(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// withHeader returns h with name set to value.
func withHeader(h map[string]string, name, value string) map[string]string {
	out := map[string]string{name: value}
	for k, v := range h {
		out[k] = v
	}

	return out
}

// post is a POST to path with header and body.
func post(path string, header map[string]string, body string) RequestSpec {
	return RequestSpec{Method: http.MethodPost, Path: path, Header: header, Body: body, ClientAddress: ClientAddress}
}

// get is a GET of path with header.
func get(path string, header map[string]string) RequestSpec {
	return RequestSpec{Method: http.MethodGet, Path: path, Header: header, ClientAddress: ClientAddress}
}

// jsonHeader marks a body as JSON, which the ceremony endpoints read.
var jsonHeader = map[string]string{"Content-Type": "application/json"}

// formHeader marks a body as a URL-encoded form.
var formHeader = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

// ceremonyOptions is what a ceremony begin answered: the challenge the authenticator
// must answer, as the token string the chain issued, and the user handle a
// creation carries.
type ceremonyOptions struct {
	Challenge string
	Handle    []byte
}

// readOptions reads the options out of a begin's answer.
func (c *passkeyClient) readOptions(res Result) ceremonyOptions {
	c.t.Helper()

	require.Equal(c.t, http.StatusOK, res.Status, "begin answered %d: %q", res.Status, res.Body)

	// The registration and passwordless begins wrap the options in a
	// "publicKey" member, as navigator.credentials takes them; the MFA slot's
	// begin answers the options themselves. The two are one shape otherwise.
	type options struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
	}

	var doc struct {
		options
		PublicKey options `json:"publicKey"`
	}

	require.NoError(c.t, json.Unmarshal([]byte(res.Body), &doc), "body: %q", res.Body)

	found := doc.PublicKey
	if found.Challenge == "" {
		found = doc.options
	}

	// The challenge travels base64url-encoded, as clientDataJSON carries it,
	// and the authenticator is handed the string it decodes to.
	token, err := passkey.DecodeChallenge(found.Challenge)
	require.NoError(c.t, err)

	out := ceremonyOptions{Challenge: token}
	if found.User.ID != "" {
		out.Handle, err = base64.RawURLEncoding.DecodeString(found.User.ID)
		require.NoError(c.t, err)
	}

	return out
}

// registerBegin asks to register a passkey as header's session and returns the
// options the authenticator answers.
func (c *passkeyClient) registerBegin(header map[string]string) ceremonyOptions {
	c.t.Helper()

	return c.readOptions(c.send(post(passkeyRegisterBegin, withHeader(header, "Content-Type", "application/json"), "")))
}

// register runs a whole registration as header's session and returns the
// finish's answer.
func (c *passkeyClient) register(header map[string]string) Result {
	c.t.Helper()

	opts := c.registerBegin(header)
	body := c.auth.Create(passkeyRPID, passkeyOrigin, opts.Challenge, opts.Handle, webauthntest.AttestationNone)

	return c.send(post(passkeyRegisterFinish, withHeader(header, "Content-Type", "application/json"), string(body)))
}

// registered is the answer of a successful finish.
type registered struct {
	ID            string   `json:"id"`
	State         string   `json:"state"`
	Pending       []string `json:"pending"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// readRegistered requires res to be a successful finish and reads it.
func (c *passkeyClient) readRegistered(res Result) registered {
	c.t.Helper()

	require.NoError(c.t, res.Refusal)
	require.Equal(c.t, http.StatusOK, res.Status, "finish answered %d: %q", res.Status, res.Body)

	var out registered
	require.NoError(c.t, json.Unmarshal([]byte(res.Body), &out), "body: %q", res.Body)

	return out
}

// ceremonyCookie reads the passwordless ceremony cookie a begin set.
func ceremonyCookie(t *testing.T, res Result) *http.Cookie {
	t.Helper()

	for _, c := range (&http.Response{Header: res.Header}).Cookies() {
		if c.Name == httpsec.DefaultPasswordlessCookieName {
			return c
		}
	}

	require.Fail(t, "no ceremony cookie was set", "Set-Cookie: %v", res.Header.Values("Set-Cookie"))

	return nil
}

// passwordlessLogin begins and finishes a passwordless login, and returns the
// finish's answer. The ceremony cookie travels back the way a browser sends it.
func (c *passkeyClient) passwordlessLogin() Result {
	c.t.Helper()

	begun := c.send(post(passwordlessBeginPath, jsonHeader, ""))
	opts := c.readOptions(begun)
	cookie := ceremonyCookie(c.t, begun)

	body := c.auth.Assert(passkeyRPID, passkeyOrigin, opts.Challenge)

	return c.send(post(passwordlessFinishPath,
		withHeader(jsonHeader, "Cookie", httpsec.DefaultPasswordlessCookieName+"="+cookie.Value), string(body)))
}

// accessTokenOf reads the credential a login or verification answered with.
func accessTokenOf(t *testing.T, res Result) string {
	t.Helper()

	require.NoError(t, res.Refusal)
	require.Equal(t, http.StatusOK, res.Status, "answered %d: %q", res.Status, res.Body)

	var doc struct {
		AccessToken string `json:"access_token"`
	}

	require.NoError(t, json.Unmarshal([]byte(res.Body), &doc), "body: %q", res.Body)
	require.NotEmpty(t, doc.AccessToken)

	return doc.AccessToken
}

// sessionOfToken loads the session a credential issued here names.
func sessionOfToken(t *testing.T, e *Effects, credential string) *session.Session {
	t.Helper()

	claims, err := fixtureTokens{}.Verify(t.Context(), credential)
	require.NoError(t, err)

	return e.Recovery.LoadSession(t, claims.ID())
}

// reachesRoute asserts the credential reaches the application route.
func (c *passkeyClient) reachesRoute(credential string) {
	c.t.Helper()

	res := c.send(get(RoutePath, bearerToken(credential)))

	require.NoError(c.t, res.Refusal)
	assert.Equal(c.t, http.StatusOK, res.Status)
	assert.True(c.t, res.RouteRan, "the credential reaches the route")
}

// passwordLogin posts the fixture user's password, and returns the second-factor
// challenge the chain answered with.
func (c *passkeyClient) passwordLogin() *httpsec.ChallengeError {
	c.t.Helper()

	res := c.send(formBody("username=" + Username + "&password=" + Password))
	assert.Equal(c.t, http.StatusUnauthorized, res.Status)

	var ch *httpsec.ChallengeError
	require.ErrorAs(c.t, res.Refusal, &ch)
	require.Equal(c.t, policy.ChallengeMFA, ch.Kind)
	require.NotEmpty(c.t, ch.Token)

	return ch
}

// proveWithPasskey answers the second-factor challenge token with the passkey.
func (c *passkeyClient) proveWithPasskey(token string) Result {
	c.t.Helper()

	header := bearerToken(token)

	opts := c.readOptions(c.send(post(mfaBeginPasskey, header, "")))
	body := c.auth.Assert(passkeyRPID, passkeyOrigin, opts.Challenge)

	return c.send(post(mfaVerifyPasskey, withHeader(header, "Content-Type", "application/json"), string(body)))
}

// listed is one entry of the listing.
type listed struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// list reads the user's passkeys as header's session.
func (c *passkeyClient) list(header map[string]string) []listed {
	c.t.Helper()

	res := c.send(get(passkeyList, header))
	require.NoError(c.t, res.Refusal)
	require.Equal(c.t, http.StatusOK, res.Status, "listing answered %d: %q", res.Status, res.Body)

	var doc struct {
		Passkeys []listed `json:"passkeys"`
	}

	require.NoError(c.t, json.Unmarshal([]byte(res.Body), &doc), "body: %q", res.Body)

	return doc.Passkeys
}

// passkeyScenarios is every passkey behaviour that must be identical on every
// adapter, run over durable PostgreSQL stores with the real WebAuthn verifier
// and a software authenticator that answers as a browser would.
func passkeyScenarios() []Scenario {
	return []Scenario{
		passkeyRegisterThenPasswordlessLogin(),
		passkeyAsSecondFactorAfterPassword(),
		passkeyCloneIsSuspendedThenRemoved(),
		passkeyFirstPasswordlessPasskeyWaitsForSavedCodes(),
		passkeyRecoveryThenRegistrationReachesFullSession(),
		passkeyEnrolmentOnlyUserRegistersWithEmailedCode(),
	}
}

// passkeyRegisterThenPasswordlessLogin pins spec passkey-login: a registered
// passkey signs its user in with no password, and a user-verified one meets the
// second factor at login, so the session is full from the first request.
func passkeyRegisterThenPasswordlessLogin() Scenario {
	return Scenario{
		Name: "a registered passkey signs in without a password to a full session satisfied at login",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			pf, sessions := newPasskeyFixture(t, passkeyBuild{enrolTOTP: true})
			effects := passkeyEffects(pf, sessions)
			effects.SessionID = pf.confirmedSession(t, sessions, true).ID

			return ChainSpec{Options: pf.options(t, effects, sessions, true), Effects: effects, Routes: passkeyRoutes()}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			c := newPasskeyClient(t, spec, send)

			reg := c.readRegistered(c.register(bearer(spec.Effects.SessionID)))
			assert.Equal(t, "active", reg.State)

			res := c.passwordlessLogin()
			credential := accessTokenOf(t, res)

			cleared := ceremonyCookie(t, res)
			assert.Empty(t, cleared.Value, "the finish clears the ceremony cookie")
			assert.Negative(t, cleared.MaxAge, "the cookie is cleared with Max-Age=0")

			s := sessionOfToken(t, spec.Effects, credential)
			assert.Equal(t, factor.Passkey, s.FirstFactor)
			assert.Equal(t, session.MFASatisfied, s.MFA, "a user-verified passkey met the second factor")
			assert.True(t, s.MFAAtFirstFactor, "the second factor was satisfied at login")

			c.reachesRoute(credential)
		},
	}
}

// passkeyAsSecondFactorAfterPassword pins spec passkey-mfa: after a password
// login the passkey answers the challenge at the MFA slot's begin and verify
// endpoints, and the session that comes back is a rotated, full one.
func passkeyAsSecondFactorAfterPassword() Scenario {
	return Scenario{
		Name: "a password login is challenged and the passkey second factor completes it",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			pf, sessions := newPasskeyFixture(t, passkeyBuild{enrolTOTP: true})
			effects := passkeyEffects(pf, sessions)
			effects.SessionID = pf.confirmedSession(t, sessions, true).ID

			return ChainSpec{Options: pf.options(t, effects, sessions, true), Effects: effects, Routes: passkeyRoutes()}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			c := newPasskeyClient(t, spec, send)

			c.readRegistered(c.register(bearer(spec.Effects.SessionID)))

			ch := c.passwordLogin()

			names := make([]string, 0, len(ch.Methods))
			for _, m := range ch.Methods {
				names = append(names, m.Name)
			}

			assert.ElementsMatch(t, []string{"totp", passkey.MethodName}, names, "both methods are offered")

			pending := spec.Effects.Recovery.LoadSession(t, ch.Session.ID)
			require.Equal(t, session.MFAPending, pending.MFA)

			verified := c.proveWithPasskey(ch.Token)
			credential := accessTokenOf(t, verified)
			assert.NotEqual(t, ch.Token, credential, "the session is rotated")

			s := sessionOfToken(t, spec.Effects, credential)
			assert.Equal(t, session.MFASatisfied, s.MFA)
			assert.False(t, s.MFAAtFirstFactor, "the second factor came after the first")

			c.reachesRoute(credential)
		},
	}
}

// passkeyCloneIsSuspendedThenRemoved pins spec passkey-clone-handling: an
// assertion whose counter went backwards is refused as forbidden, the
// credential is suspended for good, and its user removes it from a fresh
// session that met its authenticator app.
func passkeyCloneIsSuspendedThenRemoved() Scenario {
	return Scenario{
		Name: "a passkey whose counter went backwards is suspended and then removed by its user",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			pf, sessions := newPasskeyFixture(t, passkeyBuild{enrolTOTP: true})
			effects := passkeyEffects(pf, sessions)
			effects.SessionID = pf.confirmedSession(t, sessions, true).ID

			return ChainSpec{Options: pf.options(t, effects, sessions, true), Effects: effects, Routes: passkeyRoutes()}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			c := newPasskeyClient(t, spec, send)

			c.readRegistered(c.register(bearer(spec.Effects.SessionID)))

			// The authenticator reports 5, and the chain stores it.
			c.auth.Counter = 4
			accessTokenOf(t, c.passwordlessLogin())

			// A copy of the key reports 2: not forward of 5.
			c.auth.Counter = 1
			cloned := c.passwordlessLogin()

			assert.Equal(t, http.StatusForbidden, cloned.Status)
			require.ErrorIs(t, cloned.Refusal, passkey.ErrCloneSuspected)
			require.ErrorIs(t, cloned.Refusal, mfa.ErrAuthenticatorRefused)

			// The user comes back with their password and the app.
			ch := c.passwordLogin()
			assert.Equal(t, []string{"totp"}, methodNames(ch), "a suspended passkey is not a second factor")

			verified := c.send(post(mfaVerifyTOTP, withHeader(bearerToken(ch.Token), "Content-Type", formHeader["Content-Type"]),
				url.Values{"code": {spec.Effects.Passkey.totpCode(t)}}.Encode()))
			credential := accessTokenOf(t, verified)

			header := bearerToken(credential)

			held := c.list(header)
			require.Len(t, held, 1)
			assert.Equal(t, "suspended", held[0].State)

			removed := c.send(post(passkeyRemove, withHeader(header, "Content-Type", formHeader["Content-Type"]),
				url.Values{"id": {held[0].ID}}.Encode()))
			require.NoError(t, removed.Refusal)
			assert.Equal(t, http.StatusNoContent, removed.Status)

			assert.Empty(t, c.list(header), "the suspended passkey is gone")
		},
	}
}

// methodNames lists the names of the methods a challenge offers.
func methodNames(ch *httpsec.ChallengeError) []string {
	names := make([]string, 0, len(ch.Methods))
	for _, m := range ch.Methods {
		names = append(names, m.Name)
	}

	return names
}

// passkeyFirstPasswordlessPasskeyWaitsForSavedCodes pins spec passkey-
// registration: a user with no other way back registers a first passkey that
// waits for them to confirm saved recovery codes, is refused as pending until
// they do, and signs in once they have.
func passkeyFirstPasswordlessPasskeyWaitsForSavedCodes() Scenario {
	return Scenario{
		Name: "a first passkey with no other way back waits for a saved code, then signs in",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			pf, sessions := newPasskeyFixture(t, passkeyBuild{savedCodes: true})
			effects := passkeyEffects(pf, sessions)
			effects.SessionID = pf.confirmedSession(t, sessions, false).ID

			return ChainSpec{Options: pf.options(t, effects, sessions, false), Effects: effects, Routes: passkeyRoutes()}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			c := newPasskeyClient(t, spec, send)
			header := bearer(spec.Effects.SessionID)

			reg := c.readRegistered(c.register(header))
			assert.Equal(t, "pending", reg.State)
			assert.Equal(t, []string{"saved_codes"}, reg.Pending)
			require.NotEmpty(t, reg.RecoveryCodes, "the codes are readable once, here")

			// Pending: the key is right and the state is still refused.
			early := c.passwordlessLogin()
			assert.Equal(t, http.StatusForbidden, early.Status)
			require.ErrorIs(t, early.Refusal, passkey.ErrPending)

			confirmed := c.send(post(passkeyConfirm, withHeader(header, "Content-Type", formHeader["Content-Type"]),
				url.Values{"code": {reg.RecoveryCodes[0]}}.Encode()))
			require.NoError(t, confirmed.Refusal)
			assert.Equal(t, http.StatusNoContent, confirmed.Status)

			held := c.list(header)
			require.Len(t, held, 1)
			assert.Equal(t, "active", held[0].State)

			credential := accessTokenOf(t, c.passwordlessLogin())
			c.reachesRoute(credential)
		},
	}
}

// passkeyRecoveryThenRegistrationReachesFullSession pins spec account-recovery
// and passkey-registration together: a recovered session is confined, may
// register a passkey, and reaches a full session only by proving it at the MFA
// slot.
func passkeyRecoveryThenRegistrationReachesFullSession() Scenario {
	return Scenario{
		Name: "a recovered session registers a passkey and proves it to reach a full session",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			pf, sessions := newPasskeyFixture(t, passkeyBuild{})
			ctx := t.Context()

			deps := recovery.Deps{
				Users: fixtureUsers{}, Sessions: sessions, Records: pf.Base.Records, Sender: pf.Base.Outbox,
				Codes: pf.Base.Codes,
			}
			coreOpts := []recovery.Option{
				recovery.WithProofs(recovery.ProofSaved, recovery.ProofIssued),
				recovery.WithRepudiationContact(recoveryRepudiationContact),
				recovery.WithAuthenticatorKinds(pf.Manager.RecoveryKind()),
				recovery.WithMessages(conformanceRecoveryMessages{}),
				recovery.WithClock(pf.Base.Clock),
				recovery.WithIssuedCodeStore(pf.Base.OneTime),
				recovery.WithHoldTokenStore(pf.Base.OneTime),
			}

			standalone, err := recovery.NewRecoverer(deps, coreOpts...)
			require.NoError(t, err)

			saved, err := pf.Base.Codes.Generate(ctx, UserID)
			require.NoError(t, err)

			standalone.Start(ctx, Username)

			effects := passkeyEffects(pf, sessions)
			effects.recoverySavedCode = saved[0]
			effects.recoveryIssuedCode = pf.Base.lastMessage(t)

			return ChainSpec{
				Options: append(pf.options(t, effects, sessions, false),
					httpsec.EnableAccountRecovery(httpsec.RecoveryDeps(deps),
						httpsec.WithRecoveryCore(coreOpts...),
						httpsec.WithRecoveryTokens(fixtureTokens{}))),
				Effects: effects,
				Routes:  passkeyRoutes(),
			}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			c := newPasskeyClient(t, spec, send)

			completed := send(post(httpsec.DefaultRecoveryCompletePath, formHeader, url.Values{
				httpsec.RecoveryUsernameParam:   {Username},
				httpsec.RecoverySavedCodeParam:  {spec.Effects.recoverySavedCode},
				httpsec.RecoveryIssuedCodeParam: {spec.Effects.recoveryIssuedCode},
			}.Encode()))
			recovered := accessTokenOf(t, completed)

			s := sessionOfToken(t, spec.Effects, recovered)
			require.Equal(t, session.MFARecoveryPending, s.MFA)

			// Confined: the application route is refused until a second factor
			// is proven.
			stopped := send(get(RoutePath, bearerToken(recovered)))
			assert.Equal(t, http.StatusForbidden, stopped.Status)
			assert.False(t, stopped.RouteRan)

			header := bearerToken(recovered)

			reg := c.readRegistered(c.register(header))
			assert.Equal(t, "active", reg.State)

			bound := sessionOfToken(t, spec.Effects, recovered)
			assert.Equal(t, session.MFAPending, bound.MFA, "the binding moves the session on to its second factor")
			assert.True(t, bound.RecoveredAt.Equal(s.RecoveredAt), "the recovery time is kept")

			verified := c.proveWithPasskey(recovered)
			credential := accessTokenOf(t, verified)
			assert.NotEqual(t, recovered, credential, "the session is rotated")

			full := sessionOfToken(t, spec.Effects, credential)
			assert.Equal(t, session.MFASatisfied, full.MFA)
			assert.Equal(t, factor.Recovery, full.FirstFactor, "the recovery stays on the record")
			assert.True(t, full.RecoveredAt.Equal(s.RecoveredAt), "the recovery time is kept")

			c.reachesRoute(credential)
		},
	}
}

// passkeyEnrolmentOnlyUserRegistersWithEmailedCode pins spec passkey-
// registration over the enrolment path: an enrolment-only session registers a
// passkey that waits for a code emailed to the user, and proves it at the MFA
// slot once the code is redeemed.
func passkeyEnrolmentOnlyUserRegistersWithEmailedCode() Scenario {
	return Scenario{
		Name: "an enrolment-only user registers a passkey with the emailed code and completes the upgrade",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			pf, sessions := newPasskeyFixture(t, passkeyBuild{})
			effects := passkeyEffects(pf, sessions)

			s, err := sessions.Create(t.Context(), UserID, session.WithFirstFactor(factor.Password))
			require.NoError(t, err)

			sessions.MarkEnrolmentPending(s, 15*time.Minute)
			require.NoError(t, sessions.Save(t.Context(), s))

			effects.SessionID = s.ID

			methods := pf.methods(false)

			lookups, err := mfa.LookupsFor(methods...)
			require.NoError(t, err)

			challenge, err := policy.NewMFAPolicy(lookups)
			require.NoError(t, err)

			requirement, err := policy.NewMFARequirementPolicy(nil, lookups,
				policy.WithMFARequiredForAll(), policy.WithMFAEnrolmentPath())
			require.NoError(t, err)

			engine, err := policy.NewEngine(challenge, requirement)
			require.NoError(t, err)

			return ChainSpec{
				Options: append(bearerOptions(effects),
					httpsec.WithPolicyEngine(engine),
					httpsec.EnableMFA(methods,
						httpsec.WithMFATokens(fixtureTokens{}),
						httpsec.WithMFAChallengeStore(pf.Base.OneTime)),
					httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: fixtureUsers{}, Sender: pf.Base.Outbox}),
					httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: pf.Manager, Sessions: sessions}),
				),
				Effects: effects,
				Routes:  passkeyRoutes(),
			}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			c := newPasskeyClient(t, spec, send)
			header := bearer(spec.Effects.SessionID)

			reg := c.readRegistered(c.register(header))
			assert.Equal(t, "pending", reg.State)
			assert.Equal(t, []string{"email_code"}, reg.Pending)

			// The code is the one message that carries six digits on their own.
			code := emailedCode(t, spec.Effects.Passkey.Base.Outbox)

			wrong := wrongCode(code)

			refused := send(post(passkeyConfirmEmail, withHeader(header, "Content-Type", formHeader["Content-Type"]),
				url.Values{"code": {wrong}}.Encode()))
			require.Error(t, refused.Refusal)
			require.ErrorIs(t, refused.Refusal, mfa.ErrInvalidCode)

			confirmed := send(post(passkeyConfirmEmail, withHeader(header, "Content-Type", formHeader["Content-Type"]),
				url.Values{"code": {code}}.Encode()))
			require.NoError(t, confirmed.Refusal)
			assert.Equal(t, http.StatusNoContent, confirmed.Status)

			bound := spec.Effects.Recovery.LoadSession(t, spec.Effects.SessionID)
			assert.Equal(t, session.MFAPending, bound.MFA, "the confirmed passkey moves the session on to its proof")

			verified := c.proveWithPasskey(issuedTokenFor(Username, spec.Effects.SessionID))
			credential := accessTokenOf(t, verified)

			full := sessionOfToken(t, spec.Effects, credential)
			assert.Equal(t, session.MFASatisfied, full.MFA)
			assert.True(t, full.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")

			c.reachesRoute(credential)
		},
	}
}

// emailedCode finds the six-digit code in the emailed message the user was sent
// for their pending passkey.
func emailedCode(t *testing.T, o *Outbox) string {
	t.Helper()

	for _, m := range o.Messages() {
		if code := sixDigits.FindString(m.TextBody); code != "" {
			return code
		}
	}

	require.Fail(t, "no emailed code was sent", "messages: %d", len(o.Messages()))

	return ""
}

// wrongCode is a six-digit code that is not code.
func wrongCode(code string) string {
	if strings.HasPrefix(code, "0") {
		return "1" + code[1:]
	}

	return "0" + code[1:]
}
