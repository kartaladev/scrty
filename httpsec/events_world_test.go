package httpsec_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/session"
)

const (
	// eventsProxy is the trusted proxy every request of the events world
	// arrives through, and eventsClient the client it forwards for.
	eventsProxy  = "10.20.0.2"
	eventsClient = "203.0.113.7"

	// eventsChangePath is the world's password-change endpoint.
	eventsChangePath = "/account/password"

	// eventsRejectedPassword is the new password the world's change function
	// refuses.
	eventsRejectedPassword = "password123"
)

// eventsWorld is one deployment wired the way a consumer wires it, reporting
// to a recorder: session references behind a trusted proxy that may forward
// the host, form login and Basic over the real password authenticator, the
// lockout and idle-timeout policies, logout, renewal, re-authentication,
// session management, a password-change endpoint, CSRF protection and an
// authorization rule closing /admin/ to everyone without the ADMIN role.
type eventsWorld struct {
	clk      *clockwork.FakeClock
	sessions *session.Sessions
	rec      *eventRecorder
	chain    *httpsec.Chain

	// handler, when set, is what the application's handler runs.
	handler func(ex *httpsec.Exchange) error
}

func newEventsWorld(t *testing.T, extra ...httpsec.Option) *eventsWorld {
	t.Helper()

	return newEventsWorldJudgedBy(t, NewMockAuthorizer(gomock.NewController(t)), extra...)
}

// newEventsWorldJudgedBy is newEventsWorld with az as the chain's authorizer.
func newEventsWorldJudgedBy(t *testing.T, az authorize.Authorizer, extra ...httpsec.Option) *eventsWorld {
	t.Helper()

	w := &eventsWorld{
		clk: clockwork.NewFakeClockAt(time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)),
		rec: &eventRecorder{},
	}

	var err error

	w.sessions, err = session.New(session.WithClock(w.clk),
		session.WithStore(must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(w.clk)))),
		session.WithIdleTimeout(7*24*time.Hour),
		session.WithAbsoluteTimeout(30*24*time.Hour))
	require.NoError(t, err)

	hash, err := e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func() *identity.Details {
		return &identity.Details{ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress, Password: hash, Active: true}
	}

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).AnyTimes().
		DoAndReturn(func(any, string) (*identity.Details, error) { return details(), nil })
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().Return(nil, identity.ErrUserNotFound)
	users.EXPECT().LoadByUserID(gomock.Any(), e2eUser).AnyTimes().
		DoAndReturn(func(any, identity.UserID) (*identity.Details, error) { return details(), nil })

	authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	lock, err := lockout.New(lockout.WithClock(w.clk))
	require.NoError(t, err)

	idle, err := policy.NewIdleTimeout(policy.WithIdleTimeout(30 * time.Minute))
	require.NoError(t, err)

	admin := authorize.Rule[httpsec.Request]{
		Match:   func(r httpsec.Request) bool { return strings.HasPrefix(r.Path(), "/admin/") },
		Require: authorize.HasAnyRole("ADMIN"),
	}
	permitAll := authorize.Rule[httpsec.Request]{
		Match:   func(httpsec.Request) bool { return true },
		Require: authorize.PermitAll(),
	}

	change := func(ex *httpsec.Exchange) error {
		if ex.Request.FormValue("new") == eventsRejectedPassword {
			return password.ErrPasswordRejected
		}

		return nil
	}

	w.chain, err = httpsec.New(append([]httpsec.Option{
		httpsec.WithClock(w.clk),
		httpsec.WithLogger(discardLogger()),
		httpsec.WithPolicyEngine(engineOf(t, lock, idle)),
		httpsec.EnableSecurityEvents(w.rec.sink),
		httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
			Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedHost("app.example.com")),
		}),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: users}),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn, Sessions: w.sessions, Attempts: lock.Attempts(),
		}),
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: lock.Attempts()}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: w.sessions}),
		httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: users}),
		httpsec.EnableReauthentication(),
		httpsec.EnableSessionManagement(),
		httpsec.EnablePasswordChangeGate(w.sessions, httpsec.WithPasswordChangeEndpoint(eventsChangePath, change)),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableAuthorization(az, admin, permitAll),
	}, extra...)...)
	require.NoError(t, err)

	return w
}

// send runs one request from the world's client, through its proxy, with
// credential as the session reference when it is not empty, and values as a
// form body when they are not nil.
func (w *eventsWorld) send(t *testing.T, method, path, credential string, values url.Values, headers map[string]string) served {
	t.Helper()

	var req *http.Request
	if values != nil {
		req = httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequestWithContext(t.Context(), method, path, nil)
	}

	req.RemoteAddr = eventsProxy + ":51000"
	req.Header.Set("X-Forwarded-For", eventsClient)

	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}

	for name, value := range headers {
		req.Header.Set(name, value)
	}

	out := served{rec: httptest.NewRecorder()}
	run := w.chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		if w.handler != nil {
			return w.handler(ex)
		}

		return nil
	})

	ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

// login posts the user's identifier and pw to form login.
func (w *eventsWorld) login(t *testing.T, pw string) served {
	t.Helper()

	return w.send(t, http.MethodPost, httpsec.DefaultLoginPath, "", url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {pw},
	}, nil)
}

// signedIn logs the user in and returns the session reference it was handed.
func (w *eventsWorld) signedIn(t *testing.T) string {
	t.Helper()

	out := w.login(t, e2ePassword)
	require.NoError(t, out.err)

	var doc struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.AccessToken)

	return doc.AccessToken
}

// emittedRun is what a row of TestSecurityEvents_Emitted produced, and what
// its event must say.
type emittedRun struct {
	events []security.Event

	clientIP string
	user     identity.UserID
	factor   factor.Kind

	// session is the identifier of the session the event concerns, empty for
	// none; the event must carry its digest.
	session string

	// secrets are every secret the row's requests carried or were handed.
	secrets []string
}

// digestOf is the digest an event names a session by.
func digestOf(id string) string {
	sum := sha256.Sum256([]byte(id))

	return hex.EncodeToString(sum[:])
}

// emitted asserts the run reported name with outcome, carrying what the run
// says it must, and that no event of the run carries any of its secrets.
func emitted(name, outcome string) func(t *testing.T, run emittedRun) {
	return func(t *testing.T, run emittedRun) {
		t.Helper()

		var got []security.Event
		for _, e := range run.events {
			if e.Name == name {
				got = append(got, e)
			}
		}

		require.Len(t, got, 1, "events: %v", namesOf(run.events))

		e := got[0]
		assert.Equal(t, outcome, e.Outcome)
		assert.False(t, e.At.IsZero())
		assert.Equal(t, run.clientIP, e.ClientIP, "the resolved client address")
		assert.Equal(t, run.user, e.User)
		assert.Equal(t, run.factor, e.Factor)

		if run.session == "" {
			assert.Empty(t, e.Session)
		} else {
			assert.Equal(t, digestOf(run.session), e.Session, "the session's digest")
			assert.NotEqual(t, run.session, e.Session, "never the identifier")
		}

		for _, ev := range run.events {
			fields := []string{ev.Name, ev.Outcome, string(ev.User), ev.ClientIP, string(ev.Factor), ev.Session}
			for _, secret := range run.secrets {
				if secret == "" {
					continue
				}

				for _, f := range fields {
					assert.NotContains(t, f, secret, "%s carries a secret", ev.Name)
				}
			}
		}
	}
}

func namesOf(events []security.Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Name)
	}

	return out
}
