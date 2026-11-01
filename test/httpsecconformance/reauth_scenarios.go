package httpsecconformance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/test/httpsecconformance/internal/mocks"
)

// reauthStaleness is how long ago the session of a re-authentication scenario
// authenticated: past the guards' default window of 15 minutes, and inside the
// session's idle timeout, so the session is stale but still alive.
const reauthStaleness = 16 * time.Minute

// reauthScenarios is every re-authentication behaviour that must be identical
// on every adapter: the recency guard's refusal, the re-proofs that lift it,
// and the second-factor endpoint that must not stand in for them.
func reauthScenarios() []Scenario {
	return []Scenario{
		reauthStaleThenTOTP(),
		reauthPasswordWithoutSecondFactor(),
		reauthPasswordRefusedForTOTPHolder(),
		mfaVerifyRefusesFullSession(),
		reauthRefusalCarriesWindow(),
		reauthPrefixUnderFormLogin(),
		renewalLostToReproofIs409(),
		reauthPasswordRefusedByPostAuthenticationDeny(),
	}
}

// staleReadStore is the session store of a scenario that needs a reader to have
// read a session before a rotation wrote, which sequential requests cannot
// arrange once the rotation has landed. Until replayCaptured is called every
// read goes to the store underneath; after it, reads of the captured session
// return it as it was when capture ran, while every write still goes to the
// store underneath, whose conditional write is what decides the race.
//
// Store is the double to hand to the session manager: a generated mock whose
// every method delegates to the store underneath, Load excepted.
type staleReadStore struct {
	// Store is the session store the scenario's manager reads and writes.
	Store *mocks.MockStore

	under session.Store

	mu       sync.Mutex
	id       string
	snapshot *session.Session
	replay   bool
}

// newStaleReadStore is a staleReadStore over under, with its expectations set.
func newStaleReadStore(t *testing.T, under session.Store) *staleReadStore {
	t.Helper()

	s := &staleReadStore{Store: mocks.NewMockStore(gomock.NewController(t)), under: under}

	m := s.Store.EXPECT()
	m.Create(gomock.Any(), gomock.Any()).DoAndReturn(under.Create).AnyTimes()
	m.Save(gomock.Any(), gomock.Any()).DoAndReturn(under.Save).AnyTimes()
	m.Load(gomock.Any(), gomock.Any()).DoAndReturn(s.load).AnyTimes()
	m.Supersede(gomock.Any(), gomock.Any()).DoAndReturn(under.Supersede).AnyTimes()
	m.Delete(gomock.Any(), gomock.Any()).DoAndReturn(under.Delete).AnyTimes()
	m.DeleteFamily(gomock.Any(), gomock.Any()).DoAndReturn(under.DeleteFamily).AnyTimes()
	m.DeleteByUser(gomock.Any(), gomock.Any()).DoAndReturn(under.DeleteByUser).AnyTimes()
	m.DeleteByUserExcept(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(under.DeleteByUserExcept).AnyTimes()
	m.DeleteByUserAndExternalIssuer(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(under.DeleteByUserAndExternalIssuer).AnyTimes()
	m.DeleteByExternalSession(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(under.DeleteByExternalSession).AnyTimes()
	m.DeleteExpired(gomock.Any()).DoAndReturn(under.DeleteExpired).AnyTimes()
	m.CountActiveByUser(gomock.Any(), gomock.Any()).DoAndReturn(under.CountActiveByUser).AnyTimes()
	m.MarkPresented(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(under.MarkPresented).AnyTimes()
	m.RecordActivity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(under.RecordActivity).AnyTimes()
	m.SuccessorPresented(gomock.Any(), gomock.Any()).DoAndReturn(under.SuccessorPresented).AnyTimes()

	return s
}

// capture records the session id as the store now holds it.
func (s *staleReadStore) capture(t *testing.T, id string) {
	t.Helper()

	got, err := s.under.Load(t.Context(), id)
	require.NoError(t, err)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.id, s.snapshot = id, got
}

// replayCaptured makes later reads of the captured session return it as it was.
func (s *staleReadStore) replayCaptured() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.replay = true
}

func (s *staleReadStore) load(ctx context.Context, id string) (*session.Session, error) {
	s.mu.Lock()
	snap := s.snapshot
	replay := s.replay && id == s.id
	s.mu.Unlock()

	if replay {
		out := *snap

		return &out, nil
	}

	return s.under.Load(ctx, id)
}

// reauthWiring is what a re-authentication scenario builds its chain from.
type reauthWiring struct {
	// totp enrols the scenario's user on a TOTP method and mounts the second
	// factor on the chain; login mounts form login.
	totp, login bool

	// fullSession creates the session with its second factor satisfied.
	fullSession bool

	// prefix, when set, is the re-authentication prefix in place of the
	// default.
	prefix string

	// renewal mounts the session renewal endpoint at its default path.
	renewal bool

	// deny mounts a policy engine whose only policy denies after
	// authentication.
	deny bool
}

// newReauthSpec is a chain over one controlled clock, shared by the chain, the
// session manager, the TOTP method and the recency guard, with a session that
// authenticated reauthStaleness ago.
func newReauthSpec(t *testing.T, w reauthWiring) ChainSpec {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())

	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	var stale *staleReadStore

	var sessionStore session.Store = store
	if w.renewal {
		stale = newStaleReadStore(t, store)
		sessionStore = stale.Store
	}

	sessions, err := session.New(session.WithClock(clk), session.WithStore(sessionStore))
	require.NoError(t, err)

	effects := &Effects{
		Sessions:   sessions,
		Store:      store,
		Attempts:   newEffects(t).Attempts,
		totpClock:  clk,
		staleReads: stale,
	}

	opts := append([]httpsec.Option{httpsec.WithClock(clk)}, bearerOptions(effects)...)

	if w.totp {
		method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example", mfa.WithClock(clk))
		require.NoError(t, err)

		provisioning, err := method.BeginEnrolment(t.Context(), UserID, Username)
		require.NoError(t, err)

		code, err := totp.GenerateCode(provisioning.Secret, clk.Now())
		require.NoError(t, err)
		require.NoError(t, method.ConfirmEnrolment(t.Context(), UserID, code))

		effects.totpSecret = provisioning.Secret

		opts = append(opts, httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(fixtureTokens{})))
	}

	if w.login {
		opts = append(opts, formLoginOptions(effects)...)
	}

	var reauthOpts []httpsec.ReauthenticationOption
	if w.prefix != "" {
		reauthOpts = append(reauthOpts, httpsec.WithReauthenticationPrefix(w.prefix))
	}

	opts = append(opts, reauthOptions(reauthOpts...)...)

	if w.renewal {
		opts = append(opts, httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{
			Users:  fixtureUsers{},
			Tokens: fixtureTokens{},
		}))
	}

	if w.deny {
		engine, err := policy.NewEngine(newReauthDenyPolicy(t))
		require.NoError(t, err)

		opts = append(opts, httpsec.WithPolicyEngine(engine))
	}

	create := []session.CreateOption{session.WithFirstFactor(factor.Password)}
	if w.fullSession {
		create = append(create, session.WithSecondFactorAtLogin())
	}

	s, err := sessions.Create(t.Context(), UserID, create...)
	require.NoError(t, err)

	effects.SessionID = s.ID

	// Time passes after the session authenticated, so it is stale when the
	// scenario's first request arrives.
	clk.Advance(reauthStaleness)

	return ChainSpec{
		Options: opts,
		Effects: effects,
		Routes:  []Route{{Method: http.MethodGet, Path: RoutePath, Status: http.StatusOK, Body: RouteBody}},
		Guard:   GuardSpec{Kind: GuardRecent, Path: RoutePath, Clock: clk, Authorizer: fixtureAuthorizer{}},
	}
}

// totpCode is a valid code for the enrolled secret at the run's clock now.
func totpCode(t *testing.T, e *Effects) string {
	t.Helper()

	c, err := totp.GenerateCode(e.totpSecret, e.totpClock.Now())
	require.NoError(t, err)

	return c
}

// reauthOptions mounts re-authentication on the chain.
func reauthOptions(extra ...httpsec.ReauthenticationOption) []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableReauthentication(
			append([]httpsec.ReauthenticationOption{httpsec.WithReauthenticationTokens(fixtureTokens{})}, extra...)...),
	}
}

// guardedGet is a GET of the recency-guarded route with bearer credential tok.
func guardedGet(tok string) RequestSpec {
	return RequestSpec{
		Method:        http.MethodGet,
		Path:          RoutePath,
		Header:        map[string]string{"Authorization": "Bearer " + tok},
		ClientAddress: ClientAddress,
	}
}

// formPost is a form POST to path, carrying bearer credential tok.
func formPost(path, tok string, form url.Values) RequestSpec {
	return RequestSpec{
		Method: http.MethodPost,
		Path:   path,
		Header: map[string]string{
			"Authorization": "Bearer " + tok,
			"Content-Type":  "application/x-www-form-urlencoded",
		},
		Body:          form.Encode(),
		ClientAddress: ClientAddress,
	}
}

// issuedToken reads the credential a successful re-proof answered with.
func issuedToken(t *testing.T, res Result) string {
	t.Helper()

	var doc struct {
		AccessToken string `json:"access_token"`
	}

	require.NoError(t, json.Unmarshal([]byte(res.Body), &doc), "body: %q", res.Body)
	require.NotEmpty(t, doc.AccessToken)

	return doc.AccessToken
}

// requireStaleRefusal pins the recency guard's refusal of a stale session.
func requireStaleRefusal(t *testing.T, res Result) {
	t.Helper()

	assert.Equal(t, http.StatusForbidden, res.Status)
	require.ErrorIs(t, res.Refusal, httpsec.ErrReauthenticationRequired)
	assert.False(t, res.RouteRan, "a stale session does not reach the route")
}

// reauthStaleThenTOTP pins spec reauthentication "Stale session re-proves with
// its second factor": the guard refuses a session older than the window, a
// valid TOTP code at the re-proof endpoint issues a fresh credential, and that
// credential passes the guard.
func reauthStaleThenTOTP() Scenario {
	return Scenario{
		Name: "a stale session re-proves with a TOTP code and passes the recency guard",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newReauthSpec(t, reauthWiring{totp: true})
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			stale := issuedTokenFor(Username, spec.Effects.SessionID)

			requireStaleRefusal(t, send(guardedGet(stale)))

			proved := send(formPost(httpsec.DefaultReauthenticationPrefix+"/verify/totp", stale,
				url.Values{"code": {totpCode(t, spec.Effects)}}))
			require.NoError(t, proved.Refusal)
			require.Equal(t, http.StatusOK, proved.Status, "body: %q", proved.Body)

			admitted := send(guardedGet(issuedToken(t, proved)))
			require.NoError(t, admitted.Refusal)
			assert.Equal(t, http.StatusOK, admitted.Status)
			assert.True(t, admitted.RouteRan, "the re-proved session reaches the route")
		},
	}
}

// reauthPasswordWithoutSecondFactor pins spec reauthentication "Password
// re-proof for a user with no second factor".
func reauthPasswordWithoutSecondFactor() Scenario {
	return Scenario{
		Name: "a stale session of a user with no second factor re-proves with the password",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newReauthSpec(t, reauthWiring{login: true})
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			stale := issuedTokenFor(Username, spec.Effects.SessionID)

			requireStaleRefusal(t, send(guardedGet(stale)))

			proved := send(formPost(httpsec.DefaultReauthenticationPrefix+"/password", stale,
				url.Values{httpsec.DefaultLoginPasswordParam: {Password}}))
			require.NoError(t, proved.Refusal)
			require.Equal(t, http.StatusOK, proved.Status, "body: %q", proved.Body)

			admitted := send(guardedGet(issuedToken(t, proved)))
			require.NoError(t, admitted.Refusal)
			assert.Equal(t, http.StatusOK, admitted.Status)
			assert.True(t, admitted.RouteRan)
		},
	}
}

// reauthPasswordRefusedForTOTPHolder pins spec reauthentication "A password
// does not re-prove a user who holds a second factor".
func reauthPasswordRefusedForTOTPHolder() Scenario {
	return Scenario{
		Name: "a TOTP holder's password is refused as a re-proof",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newReauthSpec(t, reauthWiring{totp: true, login: true})
		},
		Request: func(spec ChainSpec) RequestSpec {
			return formPost(httpsec.DefaultReauthenticationPrefix+"/password",
				issuedTokenFor(Username, spec.Effects.SessionID),
				url.Values{httpsec.DefaultLoginPasswordParam: {Password}})
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			require.ErrorIs(t, res.Refusal, httpsec.ErrReauthenticationMethodNotUsable)
		},
	}
}

// mfaVerifyRefusesFullSession pins spec reauthentication "The second-factor
// endpoint does not re-authenticate": a session that already satisfied its
// second factor is refused there, since proving it afresh is re-authentication's
// business.
func mfaVerifyRefusesFullSession() Scenario {
	return Scenario{
		Name: "the MFA verify endpoint refuses a session whose second factor is satisfied",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newReauthSpec(t, reauthWiring{totp: true, fullSession: true})
		},
		Request: func(spec ChainSpec) RequestSpec {
			// The code is minted here, once the scenario's own Build has
			// enrolled the secret, and is valid when it arrives.
			return formPost(httpsec.DefaultMFAVerifyPrefix+"/totp",
				issuedTokenFor(Username, spec.Effects.SessionID),
				url.Values{"code": {mustTOTPCode(spec.Effects)}})
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)
			require.ErrorIs(t, res.Refusal, httpsec.ErrNoMFAChallengePending)
		},
	}
}

// reauthPrefixUnderFormLogin pins spec reauthentication "A prefix under an
// exact path is accepted": a prefix beneath the login path builds, and each
// endpoint is answered by its own feature.
func reauthPrefixUnderFormLogin() Scenario {
	const prefix = "/login/reauth"

	return Scenario{
		Name: "a re-authentication prefix under the form login path builds and both answer",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newReauthSpec(t, reauthWiring{login: true, prefix: "/login/reauth"})
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			stale := issuedTokenFor(Username, spec.Effects.SessionID)

			methods := send(RequestSpec{
				Method:        http.MethodGet,
				Path:          prefix + "/methods",
				Header:        map[string]string{"Authorization": "Bearer " + stale},
				ClientAddress: ClientAddress,
			})
			require.NoError(t, methods.Refusal)
			assert.Equal(t, http.StatusOK, methods.Status, "body: %q", methods.Body)

			login := send(formPost("/login", stale, url.Values{
				"username": {Username},
				"password": {Password},
			}))
			require.NoError(t, login.Refusal)
			assert.Equal(t, http.StatusOK, login.Status, "body: %q", login.Body)
		},
	}
}

// renewalLostToReproofIs409 pins the sessions requirement "A renewal that lost
// to a strict rotation" as the chain shows it: a re-proof rotates the session
// without grace, so a renewal of the handle it replaced answers 409, and the
// re-proof's credential is the one that authenticates.
func renewalLostToReproofIs409() Scenario {
	return Scenario{
		Name: "a renewal that lost to a re-proof answers 409 and the re-proof's credential works",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newReauthSpec(t, reauthWiring{login: true, renewal: true})
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			old := issuedTokenFor(Username, spec.Effects.SessionID)

			// A request reads the session before the re-proof lands, as the
			// renewal in flight will have; its record is what the renewal
			// goes on to hold after the re-proof has rotated the session.
			requireStaleRefusal(t, send(guardedGet(old)))
			spec.Effects.staleReads.capture(t, spec.Effects.SessionID)

			proved := send(formPost(httpsec.DefaultReauthenticationPrefix+"/password", old,
				url.Values{httpsec.DefaultLoginPasswordParam: {Password}}))
			require.NoError(t, proved.Refusal)
			require.Equal(t, http.StatusOK, proved.Status, "body: %q", proved.Body)

			spec.Effects.staleReads.replayCaptured()

			lost := send(RequestSpec{
				Method:        http.MethodPost,
				Path:          httpsec.DefaultSessionRenewalPath,
				Header:        map[string]string{"Authorization": "Bearer " + old},
				ClientAddress: ClientAddress,
			})
			require.ErrorIs(t, lost.Refusal, httpsec.ErrSessionRenewalConflict)
			assert.Equal(t, http.StatusConflict, lost.Status)

			admitted := send(guardedGet(issuedToken(t, proved)))
			require.NoError(t, admitted.Refusal)
			assert.Equal(t, http.StatusOK, admitted.Status)
			assert.True(t, admitted.RouteRan)
		},
	}
}

// errReauthDenied is the reason reauthDenyPolicy refuses with.
var errReauthDenied = errors.New("httpsecconformance: denied after authentication")

// newReauthDenyPolicy is a policy that denies every user after authentication,
// with errReauthDenied as its reason.
func newReauthDenyPolicy(t *testing.T) *mocks.MockPolicy {
	t.Helper()

	p := mocks.NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("httpsecconformance/reauth-deny").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).
		Return(policy.Decision{Outcome: policy.Deny, Reason: errReauthDenied}).AnyTimes()

	return p
}

// reauthPasswordRefusedByPostAuthenticationDeny pins spec reauthentication
// "Post-authentication deny": the password re-proof is refused with the
// policy's reason and the session is left as it was.
func reauthPasswordRefusedByPostAuthenticationDeny() Scenario {
	return Scenario{
		Name: "a post-authentication deny refuses the password re-proof and leaves the session",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newReauthSpec(t, reauthWiring{login: true, deny: true})
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			stale := issuedTokenFor(Username, spec.Effects.SessionID)

			refused := send(formPost(httpsec.DefaultReauthenticationPrefix+"/password", stale,
				url.Values{httpsec.DefaultLoginPasswordParam: {Password}}))
			require.ErrorIs(t, refused.Refusal, errReauthDenied)
			assert.NotEqual(t, http.StatusOK, refused.Status)

			// The session is as it was: the old handle still loads and is
			// still stale.
			requireStaleRefusal(t, send(guardedGet(stale)))
		},
	}
}

// mustTOTPCode is totpCode for a Request func, which has no *testing.T. The
// enrolled secret is the library's own, so generation cannot fail on it.
func mustTOTPCode(e *Effects) string {
	c, err := totp.GenerateCode(e.totpSecret, e.totpClock.Now())
	if err != nil {
		panic(err)
	}

	return c
}

// reauthRefusalCarriesWindow pins that the recency guard's refusal reaches the
// framework's own error channel carrying the window the route required, so a
// consumer's error handler can tell the caller how recently to re-prove. Fiber
// is the adapter whose error handler this exists for; it runs on every adapter,
// because the three must carry the same window.
func reauthRefusalCarriesWindow() Scenario {
	return Scenario{
		Name: "the recency guard's refusal carries the window",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			return newReauthSpec(t, reauthWiring{login: true})
		},
		Request: func(spec ChainSpec) RequestSpec {
			return guardedGet(issuedTokenFor(Username, spec.Effects.SessionID))
		},
		Assert: func(t *testing.T, res Result) {
			assert.Equal(t, http.StatusForbidden, res.Status)

			var required *httpsec.ReauthenticationRequiredError
			require.True(t, errors.As(res.Refusal, &required), "refusal: %v", res.Refusal)
			assert.Equal(t, 15*time.Minute, required.Window)
		},
	}
}
