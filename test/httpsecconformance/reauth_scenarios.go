package httpsecconformance

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/session"
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
	}
}

// reauthWiring is what a re-authentication scenario builds its chain from.
type reauthWiring struct {
	// totp enrols the scenario's user on a TOTP method and mounts the second
	// factor on the chain; login mounts form login.
	totp, login bool

	// fullSession creates the session with its second factor satisfied.
	fullSession bool
}

// newReauthSpec is a chain over one controlled clock, shared by the chain, the
// session manager, the TOTP method and the recency guard, with a session that
// authenticated reauthStaleness ago.
func newReauthSpec(t *testing.T, w reauthWiring) ChainSpec {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Now())

	store := must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))
	sessions, err := session.New(session.WithClock(clk), session.WithStore(store))
	require.NoError(t, err)

	effects := &Effects{
		Sessions:  sessions,
		Store:     store,
		Attempts:  newEffects(t).Attempts,
		totpClock: clk,
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

	opts = append(opts, reauthOptions()...)

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
func reauthOptions() []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableReauthentication(httpsec.WithReauthenticationTokens(fixtureTokens{})),
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
