package httpsec_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The passwordless endpoints' paths under the default prefix.
const (
	passwordlessBeginPath  = httpsec.DefaultPasswordlessPrefix + "/begin"
	passwordlessFinishPath = httpsec.DefaultPasswordlessPrefix + "/finish"
)

// pwlLoaderCause is the text of a user loader's outage, which no response
// may carry.
const pwlLoaderCause = "db password=hunter2 unreachable"

// pwlMaxPasswordAge is the password-age policy's limit when a case turns it
// on; the user's password is then twice as old.
const pwlMaxPasswordAge = 24 * time.Hour

// pwlDeployment is a chain wired the way a consumer serving passwordless
// login wires it: the real MFA policies over TOTP and the passkey method, a
// real session manager, form login, bearer tokens, the MFA slot and the
// passkey endpoints over a real passkey.Manager on the in-memory stores and
// the stub verifier. Only the user store and the token generator are
// doubles.
type pwlDeployment struct {
	sessions *session.Manager
	users    *MockUserLoader
	tokens   *MockGenerator
	totp     *mfa.TOTP
	verifier *passkeyVerifierStub
	creds    *passkey.MemoryCredentialStore
	handles  *passkey.MemoryHandleStore
	notices  *capturingSender
	required *requiredFlag

	// inactive makes the user loader report the user disabled, and
	// passwordChangedAt is the password-change time it reports.
	inactive          atomic.Bool
	passwordChangedAt time.Time

	// loaderFails makes LoadByUserID fail with loaderCause, an outage, and
	// loaderOtherUser makes it answer the details of another user.
	loaderFails     atomic.Bool
	loaderOtherUser atomic.Bool

	// hash is the user's password hash, for form login, and totpClock the
	// TOTP method's clock.
	hash      []byte
	totpClock *clockwork.FakeClock

	// pkOpts are further manager options; recovery wires saved codes, and
	// without it the optional mode is chosen.
	pkOpts   []passkey.Option
	recovery *passkey.RecoveryDeps

	// challenges is the passkey manager's challenge store; nil keeps the
	// manager's default.
	challenges onetime.Store

	// passkeyOpts are further EnablePasskeys options, and settings the
	// passwordless settings; withoutPasswordless leaves passwordless login
	// off.
	passkeyOpts         []httpsec.PasskeyOption
	settings            []httpsec.PasswordlessSetting
	withoutPasswordless bool

	// withoutPasskeyMFA leaves the passkey MFA method out of the policies
	// and the MFA slot, as a consumer who only signs in with passkeys does.
	withoutPasskeyMFA bool

	// passwordAge adds the password-age policy and the password-change gate,
	// and mfaLimiter replaces the MFA slot's verification limiter.
	passwordAge bool
	mfaLimiter  ratelimit.Limiter

	// extra are further chain options.
	extra []httpsec.Option

	// responded is what a consumer's responder saw of the exchange when it
	// ran.
	responded struct {
		ran       bool
		auth      *authenticate.Authentication
		inContext bool
	}

	// slots are the slot markers a request passed, in order.
	slots []string

	manager *passkey.Manager
	chain   *httpsec.Chain
}

func newPwlDeployment(t *testing.T) *pwlDeployment {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.NewManager()
	require.NoError(t, err)

	d := &pwlDeployment{
		sessions:          sessions,
		users:             NewMockUserLoader(ctrl),
		tokens:            NewMockGenerator(ctrl),
		verifier:          newPasskeyVerifierStub(t),
		creds:             passkey.NewMemoryCredentialStore(),
		handles:           passkey.NewMemoryHandleStore(),
		notices:           &capturingSender{},
		required:          &requiredFlag{},
		passwordChangedAt: time.Now().Add(-time.Hour),
	}
	d.required.on.Store(true)

	d.totpClock = clockwork.NewFakeClockAt(time.Now().Truncate(time.Second))

	d.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example", mfa.WithClock(d.totpClock))
	require.NoError(t, err)

	d.hash, err = e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func() *identity.Details {
		return &identity.Details{
			ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress, Password: d.hash,
			Active: !d.inactive.Load(), PasswordChangedAt: d.passwordChangedAt,
		}
	}

	d.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, username string) (*identity.Details, error) {
			if username != e2eAddress {
				return nil, identity.ErrUserNotFound
			}

			return details(), nil
		})
	d.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			if d.loaderFails.Load() {
				return nil, errors.New(pwlLoaderCause)
			}

			if user != e2eUser {
				return nil, identity.ErrUserNotFound
			}

			out := details()
			if d.loaderOtherUser.Load() {
				out.ID = "u-someone-else"
			}

			return out, nil
		})

	d.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, sid string, _ *identity.Principal) (string, error) {
			return mfaTokenFor(sid), nil
		})
	d.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			sid, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(e2eAddress, sid), nil
		})

	return d
}

// options are the chain options build assembles, with the manager built.
func (d *pwlDeployment) options(t *testing.T) []httpsec.Option {
	t.Helper()

	pkOpts := []passkey.Option{passkey.WithRepudiationContact("help@example.com")}
	if d.recovery == nil {
		pkOpts = append(pkOpts, passkey.WithOptionalRecoveryCodes())
	}

	m, err := passkey.New(passkey.Deps{
		Verifier:    d.verifier.mock,
		Credentials: d.creds,
		Handles:     d.handles,
		Users:       d.users,
		Sender:      d.notices,
		Sessions:    d.sessions,
		Recovery:    d.recovery,
		Challenges:  d.challenges,
	}, append(pkOpts, d.pkOpts...)...)
	require.NoError(t, err)

	d.manager = m

	methods := []mfa.Method{d.totp, m.MFAMethod()}
	if d.withoutPasskeyMFA {
		methods = methods[:1]
	}

	lookups, err := mfa.LookupsFor(methods...)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookups)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirementPolicy(d.required, lookups)
	require.NoError(t, err)

	policies := []policy.Policy{challenge, requirement}
	if d.passwordAge {
		age, err := policy.NewPasswordAgePolicy(policy.WithMaxPasswordAge(pwlMaxPasswordAge))
		require.NoError(t, err)

		policies = append(policies, age)
	}

	authn, err := authenticate.NewUsernamePasswordAuthenticator(d.users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	mfaOpts := []httpsec.MFAOption{httpsec.WithMFATokens(d.tokens)}
	if d.mfaLimiter != nil {
		mfaOpts = append(mfaOpts, httpsec.WithMFAVerifyLimiter(d.mfaLimiter))
	}

	passkeyOpts := d.passkeyOpts
	if !d.withoutPasswordless {
		passkeyOpts = append([]httpsec.PasskeyOption{httpsec.WithPasswordlessLogin(d.settings...)}, passkeyOpts...)
	}

	opts := []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, policies...)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn, Sessions: d.sessions, Tokens: d.tokens, Attempts: policy.NewMemoryAttemptStore(),
		}),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: d.tokens, Sessions: d.sessions, Users: d.users}),
		httpsec.EnableMFA(methods, mfaOpts...),
		httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: m, Sessions: d.sessions, Users: d.users}, passkeyOpts...),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions}),
	}

	if d.passwordAge {
		d.passwordChangedAt = time.Now().Add(-2 * pwlMaxPasswordAge)
		opts = append(opts, httpsec.EnablePasswordChangeGate(d.sessions))
	}

	return append(opts, d.extra...)
}

// build assembles the chain.
func (d *pwlDeployment) build(t *testing.T) *pwlDeployment {
	t.Helper()

	var err error

	d.chain, err = httpsec.New(d.options(t)...)
	require.NoError(t, err)

	return d
}

// seed stores a passkey with credential ID credID for user, in state, and
// returns the user's handle, assigning one on first use.
func (d *pwlDeployment) seed(t *testing.T, user identity.UserID, credID string, state passkey.State) []byte {
	t.Helper()

	return d.seedCounted(t, user, credID, state, 0)
}

// seedCounted is seed with the stored signature counter signCount.
func (d *pwlDeployment) seedCounted(
	t *testing.T, user identity.UserID, credID string, state passkey.State, signCount uint32,
) []byte {
	t.Helper()

	offered := make([]byte, passkey.HandleSize)
	_, err := rand.Read(offered)
	require.NoError(t, err)

	handle, err := d.handles.Assign(t.Context(), user, offered)
	require.NoError(t, err)

	cid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	require.NoError(t, d.creds.Insert(t.Context(), &passkey.Credential{
		ID:             cid,
		User:           user,
		CredentialID:   []byte(credID),
		PublicKey:      []byte("cose-" + credID),
		BackupEligible: true,
		BackupState:    true,
		SignCount:      signCount,
		Name:           "Phone",
		CreatedAt:      time.Now().Add(-time.Hour),
		State:          state,
	}))

	return handle
}

// begin posts to the passwordless begin path and returns what it answered.
func (d *pwlDeployment) begin(t *testing.T) served {
	t.Helper()

	return serve(t, d.chain, post(t.Context(), passwordlessBeginPath, ""))
}

// begun begins, requires success, and returns the ceremony cookie's value
// and the challenge.
func (d *pwlDeployment) begun(t *testing.T) (cookie, challenge string) {
	t.Helper()

	out := d.begin(t)
	require.NoError(t, out.err)

	c := cookieNamed(out.rec, httpsec.DefaultPasswordlessCookieName)
	require.NotNil(t, c, "the begin sets the ceremony cookie")

	return c.Value, d.verifier.lastRequest(t)
}

// finish posts body to the passwordless finish path carrying cookies, in
// order, as the browser sends them.
func (d *pwlDeployment) finish(t *testing.T, body string, cookies ...string) served {
	t.Helper()

	req := jsonPost(t.Context(), passwordlessFinishPath, body)
	for _, v := range cookies {
		req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: v}) //nolint:gosec // G124: a request cookie
	}

	return serve(t, d.chain, req)
}

// login begins and finishes a passwordless login from credential credID
// presenting handle.
func (d *pwlDeployment) login(t *testing.T, credID string, handle []byte) served {
	t.Helper()

	cookie, challenge := d.begun(t)

	return d.finish(t, handleAssertionBody(challenge, credID, handle), cookie)
}

// sessionCount is the number of sessions the deployment's session store
// holds for the users the tests sign in, however the response looked: a
// session saved before a refusal counts, whatever the body says. out is
// unused and kept so a case reads the same wherever it asserts.
func (d *pwlDeployment) sessionCount(t *testing.T, _ served) int {
	t.Helper()

	total := 0

	for _, user := range []identity.UserID{e2eUser, "u-gone", "u-someone-else"} {
		n, err := d.sessions.CountActiveByUser(t.Context(), user)
		require.NoError(t, err)

		total += n
	}

	return total
}

// finishedSession is the session a successful finish's access token names.
func (d *pwlDeployment) finishedSession(t *testing.T, out served) *session.Session {
	t.Helper()

	require.NoError(t, out.err)

	var doc loginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken)

	return d.sessionOf(t, doc.AccessToken)
}

// clearedCookie asserts the response clears the ceremony cookie named name on
// path.
func clearedCookie(t *testing.T, out served, name, path string) {
	t.Helper()

	c := cookieNamed(out.rec, name)
	require.NotNil(t, c, "the finish response clears the ceremony cookie")
	assert.Empty(t, c.Value)
	assert.Equal(t, path, c.Path)
	assert.Negative(t, c.MaxAge, "Max-Age=0")
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
	assert.Contains(t, out.rec.Header().Get("Set-Cookie"), "Max-Age=0")
}

// sessionOf loads the session the login's access token names.
func (d *pwlDeployment) sessionOf(t *testing.T, accessToken string) *session.Session {
	t.Helper()

	s, err := d.sessions.Load(t.Context(), sessionIDOf(t, accessToken))
	require.NoError(t, err)

	return s
}

// sessionIDOf is the session identifier an access token the deployment's
// generator issued names.
func sessionIDOf(t *testing.T, accessToken string) string {
	t.Helper()

	sid, ok := strings.CutPrefix(accessToken, mfaTokenPrefix)
	require.True(t, ok)

	return sid
}

// otherSession creates a session for the user, as a sign-in on another
// device does, and returns its identifier.
func (d *pwlDeployment) otherSession(t *testing.T) string {
	t.Helper()

	s, err := d.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return s.ID
}

// sessionGone asserts the session with identifier sid no longer loads.
func (d *pwlDeployment) sessionGone(t *testing.T, sid, msg string) {
	t.Helper()

	_, err := d.sessions.Load(t.Context(), sid)
	assert.ErrorIs(t, err, session.ErrSessionNotFound, msg)
}

// TestPasswordless drives passwordless login through a chain.
func TestPasswordless(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, d *pwlDeployment)
		act    func(t *testing.T, d *pwlDeployment) served
		assert func(t *testing.T, d *pwlDeployment, out served)
	}

	refusedAsFailed := func(t *testing.T, d *pwlDeployment, out served) {
		t.Helper()

		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		clearedCookie(t, out, httpsec.DefaultPasswordlessCookieName, passwordlessFinishPath)
		assert.Zero(t, d.sessionCount(t, out), "no session is created")
	}

	cases := []testCase{
		{
			name: "begin answers request options and sets the ceremony cookie",
			act:  func(t *testing.T, d *pwlDeployment) served { return d.begin(t) },
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan, "the endpoint answers the request itself")
				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "no-store", out.rec.Header().Get("Cache-Control"))

				var doc struct {
					PublicKey struct {
						Challenge string `json:"challenge"`
						Allow     int    `json:"allow"`
					} `json:"publicKey"`
				}
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.Equal(t, encodeChallenge(d.verifier.lastRequest(t)), doc.PublicKey.Challenge)
				assert.Zero(t, doc.PublicKey.Allow, "no credentials are allowed by name")

				c := cookieNamed(out.rec, httpsec.DefaultPasswordlessCookieName)
				require.NotNil(t, c)
				assert.True(t, c.HttpOnly)
				assert.True(t, c.Secure)
				assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
				assert.Equal(t, passwordlessFinishPath, c.Path)
				assert.Equal(t, 300, c.MaxAge)

				raw, err := base64.RawURLEncoding.DecodeString(c.Value)
				require.NoError(t, err, "the value is base64url")
				assert.Len(t, raw, 32)

				header := out.rec.Header().Get("Set-Cookie")
				for _, attr := range []string{"HttpOnly", "Secure", "SameSite=Strict", "Path=" + passwordlessFinishPath, "Max-Age=300"} {
					assert.Contains(t, header, attr)
				}
			},
		},
		{
			name: "two begins bind two values",
			act: func(t *testing.T, d *pwlDeployment) served {
				first, _ := d.begun(t)
				out := d.begin(t)
				c := cookieNamed(out.rec, httpsec.DefaultPasswordlessCookieName)
				require.NotNil(t, c)
				assert.NotEqual(t, first, c.Value)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) { require.NoError(t, out.err) },
		},
		{
			name: "the 31st begin from one source is throttled",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.challenges = &countingChallenges{Store: onetime.NewMemoryStore()}
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				for i := range 30 {
					require.NoError(t, d.begin(t).err, "begin %d", i+1)
				}

				return d.begin(t)
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, ratelimit.ErrThrottled)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
				assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultPasswordlessCookieName), "no cookie is set")
				assert.Len(t, d.verifier.requests, 30, "no challenge is issued")
				assert.EqualValues(t, 30, d.challenges.(*countingChallenges).inserts.Load(), "no challenge is stored")
			},
		},
		{
			name: "an unattributable source is refused",
			act: func(t *testing.T, d *pwlDeployment) served {
				req := post(t.Context(), passwordlessBeginPath, "")
				req.RemoteAddr = "0.0.0.0:51000"

				return serve(t, d.chain, req)
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Empty(t, d.verifier.requests, "no challenge is issued")
				assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultPasswordlessCookieName))
			},
		},
		{
			name: "finish logs in, satisfied at the first factor",
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.False(t, out.handlerRan)
				assert.Equal(t, http.StatusOK, out.rec.Code)
				clearedCookie(t, out, httpsec.DefaultPasswordlessCookieName, passwordlessFinishPath)

				var doc loginBody
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				require.NotEmpty(t, doc.AccessToken)

				s := d.sessionOf(t, doc.AccessToken)
				assert.Equal(t, factor.Passkey, s.FirstFactor)
				assert.Equal(t, session.MFASatisfied, s.MFA)
				assert.True(t, s.MFAAtFirstFactor)
				assert.Equal(t, e2eUser, s.UserID)
				assert.True(t, s.IdleExpiresAt.Equal(doc.ValidUntil))
			},
		},
		{
			name: "no ceremony cookie is refused",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				_, challenge := d.begun(t)

				return d.finish(t, handleAssertionBody(challenge, "cred-1", handle))
			},
			assert: refusedAsFailed,
		},
		{
			name: "another browser's cookie is refused",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				other, _ := d.begun(t)
				_, challenge := d.begun(t)

				return d.finish(t, handleAssertionBody(challenge, "cred-1", handle), other)
			},
			assert: refusedAsFailed,
		},
		{
			name: "a bad signature is refused, and the challenge is spent",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, challenge := d.begun(t)
				body := handleAssertionBody(challenge, "cred-1", handle)

				d.verifier.refuseAssertions.Store(true)
				refused := d.finish(t, body, cookie)
				refusedAsFailed(t, d, refused)

				d.verifier.refuseAssertions.Store(false)

				return d.finish(t, body, cookie)
			},
			assert: refusedAsFailed,
		},
		{
			name: "an unknown credential is refused",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)

				return d.login(t, "cred-unknown", handle)
			},
			assert: refusedAsFailed,
		},
		{
			name:  "a disabled user is refused",
			setup: func(_ *testing.T, d *pwlDeployment) { d.inactive.Store(true) },
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: refusedAsFailed,
		},
		{
			name: "an unknown user is refused",
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-gone", d.seed(t, "u-gone", "cred-gone", passkey.StateActive))
			},
			assert: refusedAsFailed,
		},
		{
			name:  "an old password still raises the password-change challenge",
			setup: func(_ *testing.T, d *pwlDeployment) { d.passwordAge = true },
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
				require.NotNil(t, ch.Session)
				assert.NotEmpty(t, ch.Token)
				clearedCookie(t, out, httpsec.DefaultPasswordlessCookieName, passwordlessFinishPath)

				s := d.sessionOf(t, ch.Token)
				assert.True(t, s.PasswordChangePending)
				assert.Equal(t, session.MFASatisfied, s.MFA)
				assert.True(t, s.MFAAtFirstFactor)
			},
		},
		{
			name: "a form body is missing credentials",
			act: func(t *testing.T, d *pwlDeployment) served {
				cookie, _ := d.begun(t)
				req := post(t.Context(), passwordlessFinishPath, "id=cred-1")
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie

				return serve(t, d.chain, req)
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				clearedCookie(t, out, httpsec.DefaultPasswordlessCookieName, passwordlessFinishPath)
			},
		},
		{
			name: "an oversized body is too large",
			act: func(t *testing.T, d *pwlDeployment) served {
				cookie, _ := d.begun(t)

				return d.finish(t, `{"pad":"`+strings.Repeat("a", 17<<10)+`"}`, cookie)
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrRequestTooLarge)
				clearedCookie(t, out, httpsec.DefaultPasswordlessCookieName, passwordlessFinishPath)
			},
		},
		{
			name: "an assertion the verifier cannot read is missing credentials",
			act: func(t *testing.T, d *pwlDeployment) served {
				cookie, _ := d.begun(t)

				return d.finish(t, `{"challenge":"x"}`, cookie)
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				require.ErrorIs(t, out.err, passkey.ErrMalformedResponse)
				clearedCookie(t, out, httpsec.DefaultPasswordlessCookieName, passwordlessFinishPath)
			},
		},
		{
			name: "GET on the finish path passes through and spends nothing",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, challenge := d.begun(t)
				body := handleAssertionBody(challenge, "cred-1", handle)

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, passwordlessFinishPath, strings.NewReader(body))
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie
				got := serve(t, d.chain, req)
				require.NoError(t, got.err)
				require.True(t, got.handlerRan, "a GET passes through")

				return d.finish(t, body, cookie)
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err, "the challenge was not spent by the GET")
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "two ceremony cookies whose first is wrong are refused",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				other, _ := d.begun(t)
				cookie, challenge := d.begun(t)

				return d.finish(t, handleAssertionBody(challenge, "cred-1", handle), other, cookie)
			},
			assert: refusedAsFailed,
		},
		{
			name: "two ceremony cookies whose first binds are accepted",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				other, _ := d.begun(t)
				cookie, challenge := d.begun(t)

				return d.finish(t, handleAssertionBody(challenge, "cred-1", handle), cookie, other)
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name:  "passkeys without passwordless let the begin path through",
			setup: func(_ *testing.T, d *pwlDeployment) { d.withoutPasswordless = true },
			act:   func(t *testing.T, d *pwlDeployment) served { return d.begin(t) },
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.True(t, out.handlerRan)
				assert.Empty(t, d.verifier.requests, "no challenge is issued")
				assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultPasswordlessCookieName))
			},
		},
		{
			name: "runs after the one-time link slot and before Basic",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.extra = append(d.extra,
					httpsec.RegisterInterceptor(d.slotMarker("magic-link"), httpsec.OrderMagicLink),
					httpsec.RegisterInterceptor(d.slotMarker("basic"), httpsec.OrderBasicAuth))
			},
			act: func(t *testing.T, d *pwlDeployment) served { return d.begin(t) },
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, []string{"magic-link"}, d.slots,
					"the one-time link slot ran before, and Basic's never did")
			},
		},
		{
			name: "consumer settings",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasswordlessPrefix("/signin/passkey"))
				d.settings = append(d.settings,
					httpsec.PasswordlessCookieName("pk"),
					httpsec.PasswordlessBeginResponder(func(ex *httpsec.Exchange, options json.RawMessage) error {
						ex.Writer.WriteHeader(http.StatusAccepted)
						_, err := ex.Writer.Write(options)

						return err
					}),
					httpsec.PasswordlessResponder(func(ex *httpsec.Exchange, res httpsec.LoginResult) error {
						ex.Writer.WriteHeader(http.StatusCreated)
						_, err := ex.Writer.Write([]byte(res.Token))

						return err
					}))
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)

				begun := serve(t, d.chain, post(t.Context(), "/signin/passkey/begin", ""))
				require.NoError(t, begun.err)
				assert.Equal(t, http.StatusAccepted, begun.rec.Code)

				c := cookieNamed(begun.rec, "pk")
				require.NotNil(t, c)
				assert.Equal(t, "/signin/passkey/finish", c.Path)

				req := jsonPost(t.Context(), "/signin/passkey/finish",
					handleAssertionBody(d.verifier.lastRequest(t), "cred-1", handle))
				req.AddCookie(&http.Cookie{Name: "pk", Value: c.Value}) //nolint:gosec // G124: a request cookie

				return serve(t, d.chain, req)
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.True(t, strings.HasPrefix(out.rec.Body.String(), mfaTokenPrefix))
				clearedCookie(t, out, "pk", "/signin/passkey/finish")
			},
		},
		{
			name: "a consumer limiter and token generator",
			setup: func(t *testing.T, d *pwlDeployment) {
				ctrl := gomock.NewController(t)

				limiter := NewMockLimiter(ctrl)
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).Times(1)
				limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).Times(1)

				tokens := NewMockGenerator(ctrl)
				tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("consumer-token", nil)

				d.settings = append(d.settings, httpsec.PasswordlessLimiter(limiter), httpsec.PasswordlessTokens(tokens))
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err)

				var doc loginBody
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				assert.Equal(t, "consumer-token", doc.AccessToken)
			},
		},
		{
			name: "a passwordless login publishes no authentication record, as a magic link publishes none",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.settings = append(d.settings, httpsec.PasswordlessResponder(
					func(ex *httpsec.Exchange, _ httpsec.LoginResult) error {
						d.responded.ran = true
						d.responded.auth = ex.Authentication
						_, d.responded.inContext = authenticate.AuthenticationFromContext(ex.Context())

						return nil
					}))
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.NoError(t, out.err)
				require.True(t, d.responded.ran)
				assert.Nil(t, d.responded.auth, "the exchange carries no authentication")
				assert.False(t, d.responded.inContext, "the context carries no authentication")
			},
		},
		{
			name: "a suspended credential's ID with a signature its key did not make is refused as failed",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateSuspended)
				d.verifier.refuseAssertions.Store(true)

				return d.login(t, "cred-1", handle)
			},
			assert: refusedAsFailed,
		},
		{
			name: "a pending credential's ID with a signature its key did not make is refused as failed",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StatePending)
				d.verifier.refuseAssertions.Store(true)

				return d.login(t, "cred-1", handle)
			},
			assert: refusedAsFailed,
		},
		{
			name: "a suspended credential with a valid assertion is refused as suspended",
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateSuspended))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, passkey.ErrSuspended)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.Zero(t, d.sessionCount(t, out))
			},
		},
		{
			name: "a suspected clone at finish is refused as a clone and ends every session of the user",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seedCounted(t, e2eUser, "cred-1", passkey.StateActive, 5)
				first, second := d.otherSession(t), d.otherSession(t)

				out := d.login(t, "cred-1", handle)

				d.sessionGone(t, first, "the user's first session is ended")
				d.sessionGone(t, second, "the user's second session is ended")

				return out
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, passkey.ErrCloneSuspected)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
				assert.Zero(t, d.sessionCount(t, out), "no session is created, and none is left")

				suspended(t, d)
			},
		},
		{
			name: "the handle of another user is refused",
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				other := d.seed(t, "u-2", "cred-2", passkey.StateActive)

				return d.login(t, "cred-1", other)
			},
			assert: refusedAsFailed,
		},
		{
			name: "a challenge the client invented is refused and spends nothing",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, challenge := d.begun(t)

				refusedAsFailed(t, d, d.finish(t, handleAssertionBody("invented-by-the-client", "cred-1", handle), cookie))

				return d.finish(t, handleAssertionBody(challenge, "cred-1", handle), cookie)
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err, "the issued challenge was not spent by the invented one")
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "an assertion in the query string is missing credentials",
			act: func(t *testing.T, d *pwlDeployment) served {
				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				cookie, challenge := d.begun(t)

				query := url.Values{"challenge": {encodeChallenge(challenge)}, "id": {"cred-1"}, "handle": {string(handle)}}
				req := jsonPost(t.Context(), passwordlessFinishPath+"?"+query.Encode(), "")
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: cookie}) //nolint:gosec // G124: a request cookie

				return serve(t, d.chain, req)
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, httpsec.ErrCredentialsMissing)
				assert.Zero(t, d.sessionCount(t, out))
				clearedCookie(t, out, httpsec.DefaultPasswordlessCookieName, passwordlessFinishPath)
			},
		},
		{
			name: "a throttled passwordless source is not throttled on form login or a magic link",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.required.on.Store(false)

				onetimes, err := onetime.NewManager("magic-link", onetime.WithTTL(magicLinkTTL))
				require.NoError(t, err)

				links, err := magiclink.NewManager(onetimes, d.users, d.notices, "https://app.example.com")
				require.NoError(t, err)

				d.extra = append(d.extra, httpsec.EnableMagicLink(links,
					httpsec.WithMagicLinkSessions(d.sessions), httpsec.WithMagicLinkTokens(d.tokens)))
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				for i := range 30 {
					require.NoError(t, d.begin(t).err, "begin %d", i+1)
				}

				require.ErrorIs(t, d.begin(t).err, ratelimit.ErrThrottled)

				// The source the helpers' requests come from by default.
				const source = "192.0.2.1"

				form := serve(t, d.chain, postValues(t.Context(), httpsec.DefaultLoginPath, source, url.Values{
					httpsec.DefaultLoginUsernameParam: {e2eAddress},
					httpsec.DefaultLoginPasswordParam: {e2ePassword},
				}))
				require.NoError(t, form.err, "form login has its own limiter")

				asked := serve(t, d.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath, source,
					url.Values{httpsec.DefaultMagicLinkAddressParam: {e2eAddress}, httpsec.DefaultMagicLinkNextParam: {"/"}}))
				require.NoError(t, asked.err)

				cookie := cookieNamed(asked.rec, httpsec.DefaultBindingCookieName)
				require.NotNil(t, cookie)

				req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, source,
					url.Values{httpsec.DefaultMagicLinkTokenParam: {d.notices.lastToken(t)}})
				req.AddCookie(bindingCookie(cookie.Value))

				return serve(t, d.chain, req)
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err, "a magic link's redemption has its own limiter")
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name:  "a user loader outage is an internal error behind fixed text",
			setup: func(_ *testing.T, d *pwlDeployment) { d.loaderFails.Store(true) },
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.Error(t, out.err)
				assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), pwlLoaderCause)
				assert.NotContains(t, out.rec.Body.String(), pwlLoaderCause)
				assert.Zero(t, d.sessionCount(t, out))
				clearedCookie(t, out, httpsec.DefaultPasswordlessCookieName, passwordlessFinishPath)
			},
		},
		{
			name:  "a user loader answering a different user is refused",
			setup: func(_ *testing.T, d *pwlDeployment) { d.loaderOtherUser.Store(true) },
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: refusedAsFailed,
		},
		{
			name: "a required second factor the passkey cannot give is a challenge listing the other methods",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.pkOpts = append(d.pkOpts, passkey.WithoutSecondFactorAtLogin())
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.enrolTOTP(t)

				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				require.Len(t, ch.Methods, 1)
				assert.Equal(t, "totp", ch.Methods[0].Name)
				require.NotNil(t, ch.Session)
				assert.Equal(t, session.MFAPending, d.sessionOf(t, ch.Token).MFA)
			},
		},
		{
			name: "a required second factor with nothing else enrolled is refused as enrolment required",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.withoutPasskeyMFA = true
				d.pkOpts = append(d.pkOpts, passkey.WithoutSecondFactorAtLogin())
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, policy.ErrMFAEnrollmentRequired)
				assert.Zero(t, d.sessionCount(t, out))
			},
		},
		{
			name: "relaxed user verification logs in on the first factor alone",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.withoutPasskeyMFA = true
				d.required.on.Store(false)
				d.pkOpts = append(d.pkOpts, passkey.WithUserVerification(passkey.UVPreferred))
				d.verifier.notUserVerified.Store(true)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				s := d.finishedSession(t, out)
				assert.Equal(t, factor.Passkey, s.FirstFactor)
				assert.NotEqual(t, session.MFASatisfied, s.MFA, "possession alone satisfies no second factor")
				assert.False(t, s.MFAAtFirstFactor)
			},
		},
		{
			name: "relaxed user verification with the passkey method on the slot is refused as the same channel",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.pkOpts = append(d.pkOpts, passkey.WithUserVerification(passkey.UVPreferred))
				d.verifier.notUserVerified.Store(true)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, policy.ErrSecondFactorSameChannel)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.Zero(t, d.sessionCount(t, out), "no session is created")
			},
		},
		{
			name: "a separate factor with only the passkey method on the slot is refused as the same channel",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.pkOpts = append(d.pkOpts, passkey.WithoutSecondFactorAtLogin())
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, policy.ErrSecondFactorSameChannel)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.Zero(t, d.sessionCount(t, out), "no session is created")
			},
		},
		{
			name: "form login's responder is the default",
			act: func(t *testing.T, d *pwlDeployment) served {
				opts := d.options(t)

				authn, err := authenticate.NewUsernamePasswordAuthenticator(d.users,
					authenticate.WithPasswordEncoder(e2eEncoder(t)))
				require.NoError(t, err)

				// The form login option is the second; replace it with one
				// carrying a consumer responder.
				opts[1] = httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: d.sessions, Tokens: d.tokens, Attempts: policy.NewMemoryAttemptStore(),
				}, httpsec.WithLoginResponder(func(ex *httpsec.Exchange, _ httpsec.LoginResult) error {
					ex.Writer.WriteHeader(http.StatusTeapot)

					return nil
				}))

				d.chain, err = httpsec.New(opts...)
				require.NoError(t, err)

				return d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusTeapot, out.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newPwlDeployment(t)
			if tc.setup != nil {
				tc.setup(t, d)
			}

			d.build(t)

			tc.assert(t, d, tc.act(t, d))
		})
	}
}

// slotMarker is an interceptor that records name in d.slots whenever a
// request passes it. Requests run one at a time in these tests.
func (d *pwlDeployment) slotMarker(name string) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		d.slots = append(d.slots, name)

		return next(ex)
	})
}

// TestPasswordlessConstruction pins the wiring passwordless login refuses.
func TestPasswordlessConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, d *pwlDeployment) []httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
	}
	accepted := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	// withRecovery wires saved codes to the manager.
	withRecovery := func(t *testing.T, d *pwlDeployment) {
		t.Helper()

		codes, err := recovery.NewCodes()
		require.NoError(t, err)

		wayBack, err := recovery.NewWayBackCheck(recovery.WayBackDeps{Users: d.users, Codes: codes})
		require.NoError(t, err)

		d.recovery = &passkey.RecoveryDeps{Codes: codes, WayBack: wayBack}
	}

	cases := []testCase{
		{
			name: "optional mode accepted",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				return d.options(t)
			},
			assert: accepted,
		},
		{
			name: "saved codes wired accepted",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				withRecovery(t, d)

				return d.options(t)
			},
			assert: accepted,
		},
		{
			name: "without saved codes and not optional",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				opts := d.options(t)

				m, err := passkey.New(passkey.Deps{
					Verifier: d.verifier.mock, Users: d.users, Sender: d.notices, Sessions: d.sessions,
				}, passkey.WithRepudiationContact("help@example.com"))
				require.NoError(t, err)

				return append(opts[:4:4], httpsec.EnablePasskeys(
					httpsec.PasskeyDeps{Passkeys: m, Sessions: d.sessions, Users: d.users},
					httpsec.WithPasswordlessLogin()))
			},
			assert: refused,
		},
		{
			name: "without a user loader",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				opts := d.options(t)

				return append(opts[:4:4], httpsec.EnablePasskeys(
					httpsec.PasskeyDeps{Passkeys: d.manager, Sessions: d.sessions},
					httpsec.WithPasswordlessLogin()))
			},
			assert: refused,
		},
		{
			name: "a user loader is not needed without passwordless",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				opts := d.options(t)

				return append(opts[:4:4], httpsec.EnablePasskeys(
					httpsec.PasskeyDeps{Passkeys: d.manager, Sessions: d.sessions}))
			},
			assert: accepted,
		},
		{
			name: "without a token generator",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				opts := d.options(t)

				// No form login to take the generator from.
				return []httpsec.Option{opts[0], opts[2], opts[3], opts[4], opts[5]}
			},
			assert: refused,
		},
		{
			name: "a consumer token generator without form login",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.settings = append(d.settings, httpsec.PasswordlessTokens(d.tokens))
				opts := d.options(t)

				return []httpsec.Option{opts[0], opts[2], opts[3], opts[4], opts[5]}
			},
			assert: accepted,
		},
		{
			name: "passwordless given twice",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasswordlessLogin())

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "a passwordless prefix without passwordless",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.withoutPasswordless = true
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasswordlessPrefix("/signin"))

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "the finish path on the logout path",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				opts := d.options(t)
				opts[5] = httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions},
					httpsec.WithLogoutRequestPath(passwordlessFinishPath))

				return opts
			},
			assert: refused,
		},
		{
			name: "the begin path on the login path",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasswordlessPrefix("/login"))
				opts := d.options(t)

				authn, err := authenticate.NewUsernamePasswordAuthenticator(d.users)
				require.NoError(t, err)

				opts[1] = httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: d.sessions, Tokens: d.tokens, Attempts: policy.NewMemoryAttemptStore(),
				}, httpsec.WithLoginRequestPath("/login/begin"))

				return opts
			},
			assert: refused,
		},
		{
			name: "a passwordless path under the MFA verify prefix",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasswordlessPrefix(httpsec.DefaultMFAVerifyPrefix))

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "an invalid prefix",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.passkeyOpts = append(d.passkeyOpts, httpsec.WithPasswordlessPrefix("signin"))

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "an empty cookie name",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.settings = append(d.settings, httpsec.PasswordlessCookieName(""))

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "a nil limiter",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.settings = append(d.settings, httpsec.PasswordlessLimiter(nil))

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "a nil token generator",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.settings = append(d.settings, httpsec.PasswordlessTokens(nil))

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "a nil responder",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.settings = append(d.settings, httpsec.PasswordlessResponder(nil))

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "a nil begin responder",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.settings = append(d.settings, httpsec.PasswordlessBeginResponder(nil))

				return d.options(t)
			},
			assert: refused,
		},
		{
			name: "a nil setting is skipped",
			setup: func(t *testing.T, d *pwlDeployment) []httpsec.Option {
				d.settings = append(d.settings, nil)

				return d.options(t)
			},
			assert: accepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newPwlDeployment(t)
			_, err := httpsec.New(tc.setup(t, d)...)
			tc.assert(t, err)
		})
	}
}

// TestPasswordless_CancelsHeldRecovery pins that a passwordless login, like
// every first factor that completes a login, cancels the user's held account
// recovery: a user who can sign in has not lost their account.
func TestPasswordless_CancelsHeldRecovery(t *testing.T) {
	t.Parallel()

	h := newRecoveryHarness(t)
	h.withHold()

	verifier := newPasskeyVerifierStub(t)
	creds := passkey.NewMemoryCredentialStore()
	handles := passkey.NewMemoryHandleStore()

	pm, err := passkey.New(passkey.Deps{
		Verifier: verifier.mock, Credentials: creds, Handles: handles, Users: h.users, Sender: h.sender,
		Sessions: h.sessions,
	}, passkey.WithRepudiationContact("help@example.com"), passkey.WithOptionalRecoveryCodes())
	require.NoError(t, err)

	h.chainOpts = append(h.chainOpts, httpsec.EnablePasskeys(
		httpsec.PasskeyDeps{Passkeys: pm, Sessions: h.sessions, Users: h.users},
		httpsec.WithPasswordlessLogin()))
	h.build(t)

	offered := make([]byte, passkey.HandleSize)
	_, err = rand.Read(offered)
	require.NoError(t, err)

	handle, err := handles.Assign(t.Context(), e2eUser, offered)
	require.NoError(t, err)

	cid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	require.NoError(t, creds.Insert(t.Context(), &passkey.Credential{
		ID: cid, User: e2eUser, CredentialID: []byte("cred-1"), PublicKey: []byte("cose-cred-1"),
		BackupEligible: true, Name: "Phone", CreatedAt: time.Now(), State: passkey.StateActive,
	}))

	held := h.hold(t)

	begun := serve(t, h.chain, post(t.Context(), passwordlessBeginPath, ""))
	require.NoError(t, begun.err)

	c := cookieNamed(begun.rec, httpsec.DefaultPasswordlessCookieName)
	require.NotNil(t, c)

	req := jsonPost(t.Context(), passwordlessFinishPath, handleAssertionBody(verifier.lastRequest(t), "cred-1", handle))
	req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // G124: a request cookie

	login := serve(t, h.chain, req)
	require.NoError(t, login.err)
	require.Equal(t, http.StatusOK, login.rec.Code)

	h.clock.Advance(recoveryHoldDelay)

	refusedFinish(t, h.finish(t, held.completion))
}

// countingChallenges counts the challenges inserted into the store it wraps.
type countingChallenges struct {
	onetime.Store

	inserts atomic.Int64
}

func (c *countingChallenges) Insert(ctx context.Context, tok onetime.Token) error {
	c.inserts.Add(1)

	return c.Store.Insert(ctx, tok)
}

func TestPasswordless_SamplesUserRefusals(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, d *pwlDeployment)
		user   identity.UserID
		assert func(t *testing.T, logs string)
	}

	cases := []testCase{
		{
			name: "unknown user",
			user: "u-gone",
			assert: func(t *testing.T, logs string) {
				assert.Equal(t, 1, strings.Count(logs, "a passwordless login's user no longer exists"), "the refusal is logged once")
				assert.Contains(t, logs, "level=DEBUG")
				assert.Contains(t, logs, "flow=passkey-login")
				assert.Contains(t, logs, "reason=user-unknown")
			},
		},
		{
			name:  "inactive user",
			setup: func(_ *testing.T, d *pwlDeployment) { d.inactive.Store(true) },
			user:  e2eUser,
			assert: func(t *testing.T, logs string) {
				assert.Equal(t, 1, strings.Count(logs, "a passwordless login's user is not active"), "the refusal is logged once")
				assert.Contains(t, logs, "level=DEBUG")
				assert.Contains(t, logs, "flow=passkey-login")
				assert.Contains(t, logs, "reason=user-inactive")
			},
		},
		{
			name:  "user mismatch",
			setup: func(_ *testing.T, d *pwlDeployment) { d.loaderOtherUser.Store(true) },
			user:  e2eUser,
			assert: func(t *testing.T, logs string) {
				assert.Equal(t, 1, strings.Count(logs, "the user loader returned a different user"), "the refusal is logged once")
				assert.Contains(t, logs, "level=ERROR")
				assert.Contains(t, logs, "flow=passkey-login")
				assert.Contains(t, logs, "reason=user-mismatch")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer

			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			d := newPwlDeployment(t)
			d.extra = append(d.extra, httpsec.WithLogger(logger))

			if tc.setup != nil {
				tc.setup(t, d)
			}

			d.build(t)

			handle := d.seed(t, tc.user, "cred-1", passkey.StateActive)

			for range 5 {
				out := d.login(t, "cred-1", handle)
				require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
			}

			tc.assert(t, buf.String())
		})
	}
}

// TestPasswordless_RefusalLogsFollowPasskeyInterval pins that the passwordless
// endpoints' refusals are sampled over the passkey manager's window
// (passkey.WithLogInterval), not the chain's (httpsec.WithRefusalLogInterval),
// and that a chain flush reports what they held back.
func TestPasswordless_RefusalLogsFollowPasskeyInterval(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, d *pwlDeployment)
		drive  func(t *testing.T, d *pwlDeployment)
		assert func(t *testing.T, logs string)
	}

	unknownUser := func(t *testing.T, d *pwlDeployment) {
		t.Helper()

		handle := d.seed(t, "u-gone", "cred-1", passkey.StateActive)

		for range 5 {
			out := d.login(t, "cred-1", handle)
			require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		}
	}

	throttled := func(t *testing.T, d *pwlDeployment) {
		t.Helper()

		for range 5 {
			out := serve(t, d.chain, postValues(t.Context(), passwordlessBeginPath, flushSource, url.Values{}))
			require.Error(t, out.err)
		}
	}

	withThrottle := func(t *testing.T, d *pwlDeployment) {
		t.Helper()

		d.settings = append(d.settings, httpsec.PasswordlessLimiter(exceededLimiter(t)))
	}

	const (
		unknownMsg  = "a passwordless login's user no longer exists"
		throttleMsg = "httpsec: source throttled"
	)

	cases := []testCase{
		{
			name: "the passkey interval writing every record governs a user refusal",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.pkOpts = append(d.pkOpts, passkey.WithLogInterval(-1))
			},
			drive: unknownUser,
			assert: func(t *testing.T, logs string) {
				assert.Equal(t, 5, strings.Count(logs, unknownMsg))
			},
		},
		{
			name: "the chain interval does not govern a user refusal",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.extra = append(d.extra, httpsec.WithRefusalLogInterval(-1))
			},
			drive: unknownUser,
			assert: func(t *testing.T, logs string) {
				assert.Equal(t, 1, strings.Count(logs, unknownMsg))
			},
		},
		{
			name: "the passkey interval writing every record governs the begin throttle",
			setup: func(t *testing.T, d *pwlDeployment) {
				withThrottle(t, d)
				d.pkOpts = append(d.pkOpts, passkey.WithLogInterval(-1))
			},
			drive: throttled,
			assert: func(t *testing.T, logs string) {
				assert.Equal(t, 5, strings.Count(logs, throttleMsg))
			},
		},
		{
			name: "the chain interval does not govern the begin throttle",
			setup: func(t *testing.T, d *pwlDeployment) {
				withThrottle(t, d)
				d.extra = append(d.extra, httpsec.WithRefusalLogInterval(-1))
			},
			drive: throttled,
			assert: func(t *testing.T, logs string) {
				assert.Equal(t, 1, strings.Count(logs, throttleMsg))
			},
		},
		{
			name: "a chain flush reports what the passwordless sampler held back",
			drive: func(t *testing.T, d *pwlDeployment) {
				unknownUser(t, d)
				d.chain.FlushRefusalLogs()
			},
			assert: func(t *testing.T, logs string) {
				assert.Equal(t, 1, strings.Count(logs, unknownMsg))
				assert.Contains(t, logs, "refusal logs suppressed")
				assert.Contains(t, logs, "key=passkey-login|user-unknown")
				assert.Contains(t, logs, "suppressed=4")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer

			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			d := newPwlDeployment(t)
			d.extra = append(d.extra, httpsec.WithLogger(logger))

			if tc.setup != nil {
				tc.setup(t, d)
			}

			d.build(t)
			tc.drive(t, d)
			tc.assert(t, buf.String())
		})
	}
}
