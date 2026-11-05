package httpsec_test

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// resume posts body to the resume endpoint, as a page's fetch would.
func (w *opFlow) resume(t *testing.T, body string, change ...flowChange) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		w.issuer+flowResumePath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	return w.serve(t, r, change)
}

// sessionSecret is the browser-session secret the answer set.
func (a flowAnswer) sessionSecret(t *testing.T) string {
	t.Helper()

	c := a.cookie(flowSession)
	require.NotNil(t, c, "the browser-session cookie is set")

	return c.Value
}

// flowLoginBody is the document resuming handle's login stage.
func flowLoginBody(handle string) string {
	return `{"req":` + strconv.Quote(handle) + `}`
}

// flowGrantBody is the document granting scopes at handle's consent stage.
func flowGrantBody(handle string, scopes ...string) string {
	encoded, _ := json.Marshal(map[string]any{"req": handle, "scopes": scopes})

	return string(encoded)
}

// flowDenyBody is the document denying handle's consent stage.
func flowDenyBody(handle string) string {
	return `{"req":` + strconv.Quote(handle) + `,"deny":true}`
}

// atConsent resumes a new request's login stage, by a sign-in of s, through the endpoint.
func (w *opFlow) atConsent(t *testing.T, s *session.Session) (string, string, flowAnswer) {
	t.Helper()

	handle, flow := w.park(t, flowWeb)

	a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
	require.Equal(t, http.StatusOK, a.status, a.body)

	return handle, flow, a
}

// exchange spends code at the token endpoint and returns the ID token's claims.
func (w *opFlow) exchange(t *testing.T, clientID, code string) map[string]any {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+"/oauth2/token",
		strings.NewReader(exchangeOf(code).Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(clientID, tokenSecret)

	a := w.serve(t, r, nil)
	require.Equal(t, http.StatusOK, a.status, a.body)

	var doc struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(a.body), &doc), a.body)

	parts := strings.Split(doc.IDToken, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))

	return claims
}

// flowUnspent is the row's check that a refusal left the login stage answerable.
func flowUnspent(t *testing.T, w *opFlow, handle, flow string) {
	t.Helper()

	assert.Equal(t, oidcprovider.StageLogin, w.stage(t, handle, flow), "the handle can still be resumed")
}

func TestOIDCResume(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup flowSetup
		run   func(t *testing.T, w *opFlow)
	}

	cases := []testCase{
		{
			name: "a login that needs consent answers the consent page, in a document",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, a := w.atConsent(t, w.session(t))

				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.Empty(t, a.header.Get("Location"), "the answer is never a redirect")
				assert.False(t, a.passedOn)

				to := a.redirectTo(t)
				assert.Equal(t, w.issuer+"/consent", to.Scheme+"://"+to.Host+to.Path)
				assert.Equal(t, handle, to.Query().Get(oidcprovider.HandleParam))
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a login that needs no consent answers the client, with a code",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowFirstParty)

				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				to := a.redirectTo(t)
				assert.Equal(t, rpCallback, to.Scheme+"://"+to.Host+to.Path)
				assert.NotEmpty(t, to.Query().Get("code"))
				assert.Equal(t, "xyz", to.Query().Get("state"))
				assert.Equal(t, w.issuer, to.Query().Get("iss"))
			},
		},
		{
			name: "no Authorization header is unauthenticated, with the handle unspent",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a session reference in a cookie is no sign-in",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)
				s := w.session(t)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow),
					flowCookieOf("session", s.ID), flowCookieOf(flowSession, s.ID))
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a session reference in the query is no sign-in",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)
				s := w.session(t)

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					w.issuer+flowResumePath+"?"+url.Values{"access_token": {s.ID}, "session": {s.ID}}.Encode(),
					strings.NewReader(flowLoginBody(handle)))
				r.Header.Set("Content-Type", "application/json")

				a := w.serve(t, r, []flowChange{flowCookieOf(flowCookie, flow)})
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "no flow cookie is an unknown handle",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Empty(t, a.body)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"), "a refusal is not cached either")
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a handle resumed twice is unknown the second time",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow, _ := w.atConsent(t, s)

				a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
			},
		},
		{
			name: "a sign-in too old for max_age must be repeated, with the handle unspent",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				w.clk.Advance(20 * time.Minute)

				handle, flow := w.park(t, flowWeb, func(p url.Values) { p.Set("max_age", "300") })

				a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCReauthenticate)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				flowUnspent(t, w, handle, flow)

				fresh := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, flow))
				assert.Equal(t, http.StatusOK, fresh.status, "a new sign-in resumes the same handle")
			},
		},
		{
			name: "a consent grant binds the code to what was granted",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow, _ := w.atConsent(t, s)

				a := w.resume(t, flowGrantBody(handle, "openid"), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))

				to := a.redirectTo(t)
				assert.NotEmpty(t, to.Query().Get("code"))

				remembered, err := w.consents.Load(t.Context(), s.UserID, flowWeb)
				require.NoError(t, err)
				assert.Equal(t, []string{"openid"}, remembered.Scopes)
			},
		},
		{
			name: "a denial answers access_denied and remembers nothing",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow, _ := w.atConsent(t, s)

				a := w.resume(t, flowDenyBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				to := a.redirectTo(t)
				assert.Equal(t, "access_denied", to.Query().Get("error"))
				assert.Equal(t, "xyz", to.Query().Get("state"))
				assert.Equal(t, w.issuer, to.Query().Get("iss"))

				_, err := w.consents.Load(t.Context(), s.UserID, flowWeb)
				assert.ErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a grant of a scope not asked for is malformed, and the handle stays answerable",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow, _ := w.atConsent(t, s)

				a := w.resume(t, flowGrantBody(handle, "openid", "admin"), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCConsentMalformed)
				assert.Equal(t, http.StatusBadRequest, a.status)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a consent stage answered by another user is an unknown handle",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, _ := w.atConsent(t, w.session(t))

				other, err := w.sessions.Create(t.Context(), "u-2", session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				a := w.resume(t, flowGrantBody(handle, "openid"), flowBearer(other.ID), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a signed-token sign-in resumes too, its session loaded by jti",
			setup: flowSetup{bearer: func(t *testing.T, w *opFlow) httpsec.Option {
				t.Helper()

				return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: flowGenerator(t, w),
					Sessions: w.sessions,
					Users:    w.users,
				})
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)

				tok, err := flowGenerator(t, w).Generate(t.Context(), s.ID, &identity.Principal{ID: s.UserID, Username: string(s.UserID)})
				require.NoError(t, err)

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowBearer(tok), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a federated sign-in's facts come from its session",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t,
					session.WithFirstFactor(factor.OIDC),
					session.WithExternalSession("corp", "https://corp.example.com", "up-1", "raw-id-token"),
					session.WithFederatedAssurance([]string{"pwd", "mfa"}, "urn:example:high"),
				)
				w.clk.Advance(5 * time.Second)

				handle, flow := w.park(t, flowFirstParty)
				a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				claims := w.exchange(t, flowFirstParty, a.redirectTo(t).Query().Get("code"))
				assert.Equal(t, []any{"pwd", "mfa"}, claims["amr"])
				assert.Equal(t, "urn:example:high", claims["acr"])
				assert.Equal(t, "u-1", claims["sub"])
				assert.InDelta(t, float64(s.AuthenticatedAt.Unix()), claims["auth_time"], 0)

				ended, err := w.grants.EndSignIns(t.Context(), oidcprovider.SignInSelector{
					ExternalIssuer: "https://corp.example.com", ExternalSessionID: "up-1",
				}, w.clk.Now())
				require.NoError(t, err)
				require.Len(t, ended, 1, "the grant names the upstream sign-in")
				assert.Equal(t, s.FamilyID, ended[0].SignInFamily)
			},
		},
		{
			name: "a password sign-in asserts pwd",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowFirstParty)
				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				claims := w.exchange(t, flowFirstParty, a.redirectTo(t).Query().Get("code"))
				assert.Equal(t, []any{"pwd"}, claims["amr"])
				assert.NotContains(t, claims, "acr")
			},
		},
		{
			name: "a passkey sign-in asserts no amr",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowFirstParty)
				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t, session.WithFirstFactor(factor.Passkey)).ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				claims := w.exchange(t, flowFirstParty, a.redirectTo(t).Query().Get("code"))
				assert.NotContains(t, claims, "amr")
				assert.NotContains(t, claims, "acr")
			},
		},
		{
			name: "a passkey that met the second factor at login asserts mfa",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowFirstParty)
				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t, session.WithFirstFactor(factor.Passkey), session.WithSecondFactorAtLogin()).ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				claims := w.exchange(t, flowFirstParty, a.redirectTo(t).Query().Get("code"))
				assert.Equal(t, []any{"mfa"}, claims["amr"])
				assert.NotContains(t, claims, "acr")
			},
		},
		{
			name: "a password and a second factor assert pwd and mfa",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowFirstParty)
				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t, session.WithSecondFactorAtLogin()).ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				claims := w.exchange(t, flowFirstParty, a.redirectTo(t).Query().Get("code"))
				assert.Equal(t, []any{"pwd", "mfa"}, claims["amr"])
				assert.NotContains(t, claims, "acr")
			},
		},
		{
			name: "a consumer's assurance replaces the default whole",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCSignInAssurance(func(*session.Session) ([]string, string) {
					return []string{"hwk"}, "urn:example:own"
				}),
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowFirstParty)
				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				claims := w.exchange(t, flowFirstParty, a.redirectTo(t).Query().Get("code"))
				assert.Equal(t, []any{"hwk"}, claims["amr"])
				assert.Equal(t, "urn:example:own", claims["acr"])
			},
		},
		{
			name: "unknown handles past the default limit are refused before any lookup",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				for i := range 30 {
					a := w.resume(t, flowLoginBody("rh.unknown."+strconv.Itoa(i)), flowBearer(s.ID))
					require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle, "attempt %d", i)
				}

				w.pending.loads.Store(0)

				a := w.resume(t, flowLoginBody("rh.unknown.again"), flowBearer(s.ID))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
				assert.Equal(t, http.StatusTooManyRequests, a.status)
				assert.Empty(t, a.header.Get("WWW-Authenticate"), "a page is not told to sign in")
				assert.Empty(t, a.body)
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.Zero(t, w.pending.loads.Load(), "the handle is not looked up")

				other := w.resume(t, flowLoginBody("rh.unknown.other"), flowBearer(s.ID), flowFrom(flowOtherAddr))
				assert.ErrorIs(t, other.err, httpsec.ErrOIDCUnknownHandle, "another source is still heard")
			},
		},
		{
			name: "what the page can cure is not charged to the source",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCResumeLimiter(must1(ratelimit.NewMemoryLimiter(1, time.Minute))),
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				w.clk.Advance(20 * time.Minute)

				handle, flow := w.park(t, flowWeb, func(p url.Values) { p.Set("max_age", "300") })
				for range 3 {
					a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
					require.ErrorIs(t, a.err, httpsec.ErrOIDCReauthenticate)
				}

				fresh := w.session(t)
				a := w.resume(t, flowLoginBody(handle), flowBearer(fresh.ID), flowCookieOf(flowCookie, flow))
				require.Equal(t, http.StatusOK, a.status)

				for range 3 {
					a = w.resume(t, flowGrantBody(handle, "admin"), flowBearer(fresh.ID), flowCookieOf(flowCookie, flow))
					require.ErrorIs(t, a.err, httpsec.ErrOIDCConsentMalformed)
				}
			},
		},
		{
			name: "a consumer's limiter replaces the default",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCResumeLimiter(must1(ratelimit.NewMemoryLimiter(1, time.Minute))),
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)

				a := w.resume(t, flowLoginBody("rh.unknown"), flowBearer(s.ID))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)

				a = w.resume(t, flowLoginBody("rh.unknown"), flowBearer(s.ID))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
			},
		},
		{
			name: "an API key is no sign-in, with the handle unspent",
			setup: flowSetup{chain: func(t *testing.T, w *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.EnableAPIKey(w.apiKeys(t))}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), w.apiKeyHeader())
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "an API key beside a browser session answers no consent",
			setup: flowSetup{chain: func(t *testing.T, w *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.EnableAPIKey(w.apiKeys(t))}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, login := w.atConsent(t, w.session(t))

				a := w.resume(t, flowGrantBody(handle, "openid"), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, login.sessionSecret(t)), w.apiKeyHeader())
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "Basic credentials are no sign-in, with the handle unspent",
			setup: flowSetup{chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				h := newAuthHarness(t)
				h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					Return(&authenticate.Authentication{Principal: &identity.Principal{ID: "u-1"}, Time: time.Now()}, nil).
					AnyTimes()
				h.attempts.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				return []httpsec.Option{httpsec.EnableBasicAuth(h.basicAuthDeps())}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow),
					func(r *http.Request) { r.SetBasicAuth("ada", "s3cret") })
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "an Authorization header nothing on the chain reads answers no consent",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, login := w.atConsent(t, w.session(t))

				a := w.resume(t, flowGrantBody(handle, "openid"), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, login.sessionSecret(t)),
					func(r *http.Request) { r.SetBasicAuth("ada", "s3cret") })
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a session owing a second factor gets the gate's refusal, and resumes afterwards",
			setup: flowSetup{chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{mfaOn(t)}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				s.MFA = session.MFAPending
				require.NoError(t, w.sessions.Save(t.Context(), s))

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))

				elsewhere := w.serve(t,
					httptest.NewRequestWithContext(t.Context(), http.MethodGet, w.issuer+"/api/orders", nil),
					[]flowChange{flowBearer(s.ID)})
				assert.Equal(t, elsewhere.status, a.status, "the refusal the chain gives that state elsewhere")

				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, a.err, &challenge)
				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				flowUnspent(t, w, handle, flow)

				s.MFA = session.MFASatisfied
				require.NoError(t, w.sessions.Save(t.Context(), s))

				after := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				assert.Equal(t, http.StatusOK, after.status, after.body)
			},
		},
		{
			name: "a session owing a second factor is refused on a chain with no gate for it",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				s.MFA = session.MFAPending
				require.NoError(t, w.sessions.Save(t.Context(), s))

				w.refusesOwing(t, s, policy.ChallengeMFA)
			},
		},
		{
			name: "a session owing a password change is refused on a chain with no gate for it",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				s.PasswordChangePending = true
				require.NoError(t, w.sessions.Save(t.Context(), s))

				w.refusesOwing(t, s, policy.ChallengePasswordChange)
			},
		},
		{
			name: "a session limited to enrolment is refused on a chain with no gate for it",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				w.sessions.MarkEnrolmentPending(s, time.Minute)
				require.NoError(t, w.sessions.Save(t.Context(), s))

				w.refusesOwing(t, s, policy.ChallengeMFAEnrolment)
			},
		},
		{
			name: "a session pending recovery is refused on a chain with no gate for it",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				w.sessions.MarkRecoveryPending(s, time.Minute, w.clk.Now())
				require.NoError(t, w.sessions.Save(t.Context(), s))

				w.refusesOwing(t, s, policy.ChallengeAccountRecovery)
			},
		},
		{
			name: "a challenge of the consumer's own raised on the request is refused",
			setup: flowSetup{chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithPolicyEngine(engineOf(t, raisingDeclared{kind: flowConsumerChallenge, phase: policy.PerRequest})),
					httpsec.WithChallengeEnforcer(flowConsumerChallenge),
				}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				w.refusesOwing(t, w.session(t), flowConsumerChallenge)
			},
		},
		{
			name: "a session only a late renewal may recover is refused, with the handle unspent",
			setup: flowSetup{
				sessions: []session.Option{session.WithUnusedSuccessorRecovery()},
				chain: func(t *testing.T, w *opFlow) []httpsec.Option {
					t.Helper()

					return []httpsec.Option{httpsec.EnableSessionRenewal(httpsec.SessionRenewalDeps{Users: w.users})}
				},
			},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				_, _, err := w.sessions.RotateWithGrace(t.Context(), s, 30*time.Second)
				require.NoError(t, err)
				w.clk.Advance(31 * time.Second)

				_, err = w.sessions.Load(t.Context(), s.ID)
				require.ErrorIs(t, err, session.ErrRenewalRequired, "the row's session is the late kind")

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a bound sign-in with no proof gets the chain's refusal, and resumes with one",
			setup: flowSetup{
				provider: []oidcprovider.Option{oidcprovider.WithDPoP()},
				chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
					t.Helper()

					return []httpsec.Option{httpsec.EnableDPoP(*plainDPoP(t))}
				},
			},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				k := newDPoPKey(t, elliptic.P256())
				s := w.session(t, session.WithKeyBinding(session.KeyBinding{JKT: k.jkt}))
				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrInvalidDPoPProof)
				flowUnspent(t, w, handle, flow)

				proof := k.validProof("resume-1").with(map[string]any{
					"htm": http.MethodPost,
					"htu": w.issuer + flowResumePath,
					"iat": w.clk.Now().Unix(),
					"ath": tokenHash(s.ID),
				}).sign(t)

				proved := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), func(r *http.Request) {
					r.Header.Set("Authorization", "DPoP "+s.ID)
					r.Header.Set("DPoP", proof)
				})
				assert.Equal(t, http.StatusOK, proved.status, proved.body)
			},
		},
		{
			name: "a session a consumer's interceptor published from something but a bearer is no sign-in",
			setup: flowSetup{chain: func(t *testing.T, w *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{w.consumerSessions(false)}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), flowConsumerSession(s.ID))
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a consumer's own bearer that records its credential resumes",
			setup: flowSetup{chain: func(t *testing.T, w *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{w.consumerSessions(true)}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), flowConsumerAuthorization(s.ID))
				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a consumer's interceptor reading the query is no sign-in, with the handle unspent",
			setup: flowSetup{chain: func(t *testing.T, w *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						presented := ex.Request.Query("session")
						if presented == "" {
							return next(ex)
						}

						s, err := w.sessions.Load(ex.Context(), presented)
						if err != nil {
							return err
						}

						if err := ex.PublishSession(&authenticate.Authentication{
							Principal: &identity.Principal{ID: s.UserID},
							Time:      w.clk.Now(),
						}, s); err != nil {
							return err
						}

						ex.RecordPresentedToken(presented)

						return next(ex)
					}), httpsec.OrderBearerToken)}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow := w.park(t, flowWeb)

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					w.issuer+flowResumePath+"?session="+s.ID, strings.NewReader(flowLoginBody(handle)))
				r.Header.Set("Content-Type", "application/json")

				a := w.serve(t, r, []flowChange{flowCookieOf(flowCookie, flow)})
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a credential recorded with no session published is no sign-in",
			setup: flowSetup{chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						ex.RecordPresentedToken("recorded")

						return next(ex)
					}), httpsec.OrderBearerToken)}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow),
					func(r *http.Request) { r.Header.Set("Authorization", "Consumer recorded") })
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "two Authorization lines are no sign-in, with the handle unspent",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), flowBearer(s.ID),
					func(r *http.Request) { r.Header.Add("Authorization", "Basic dTpw") })
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusUnauthorized, a.status)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name:  "a credential that is no sign-in is judged before the body is read",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCResumeBodyLimit(8)}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				a := w.resume(t, flowLoginBody("rh.a-handle-past-the-limit"), flowCookieOf(flowCookie, "f"),
					func(r *http.Request) { r.Header.Set("Authorization", "Consumer unread") })
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired, "not ErrRequestTooLarge")
			},
		},
		{
			name: "a throttled source's body is not read",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCResumeLimiter(must1(ratelimit.NewMemoryLimiter(1, time.Minute))),
				httpsec.WithOIDCResumeBodyLimit(32),
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)

				first := w.resume(t, flowLoginBody("rh.unknown"), flowBearer(s.ID))
				require.ErrorIs(t, first.err, httpsec.ErrOIDCUnknownHandle)

				a := w.resume(t, flowLoginBody("rh.a-handle-well-past-the-limit-of-the-body"), flowBearer(s.ID))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled, "not ErrRequestTooLarge")
			},
		},
		{
			name:  "a limiter that cannot answer refuses 429, with the handle unlooked-up",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCResumeLimiter(flowDownLimiter{})}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				a := w.resume(t, flowLoginBody("rh.x.y"), flowBearer(w.session(t).ID))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
				assert.Equal(t, http.StatusTooManyRequests, a.status)
				assert.Empty(t, a.header.Get("WWW-Authenticate"))
				assert.Zero(t, w.pending.loads.Load())
			},
		},
		{
			name: "a source that cannot be attributed is refused 429",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				// With no bearer, so that the bearer's own throttle, which refuses first, is not reached.
				a := w.resume(t, flowLoginBody("rh.x.y"), flowFrom("not-an-address"))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
				assert.Equal(t, http.StatusTooManyRequests, a.status)
				assert.Zero(t, w.pending.loads.Load())
			},
		},
		{
			name: "an empty list of scopes is an answer, and grants nothing",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				handle, flow, _ := w.atConsent(t, s)

				a := w.resume(t, `{"req":`+strconv.Quote(handle)+`,"scopes":[]}`, flowBearer(s.ID),
					flowCookieOf(flowCookie, flow))
				t.Logf("status=%d err=%v body=%s", a.status, a.err, a.body)
				require.ErrorIs(t, a.err, httpsec.ErrOIDCConsentMalformed)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a machine a consumer's interceptor authenticated answers no consent beside a browser session",
			setup: flowSetup{chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error {
						if ex.Request.Header(flowConsumerMachineHeader) != "" {
							if err := ex.PublishSession(&authenticate.Authentication{
								Principal: &identity.Principal{ID: "machine"},
								Time:      time.Now(),
							}, nil); err != nil {
								return err
							}
						}

						return next(ex)
					}), httpsec.OrderBearerToken)}
			}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, login := w.atConsent(t, w.session(t))

				a := w.resume(t, flowGrantBody(handle, "openid"), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, login.sessionSecret(t)),
					func(r *http.Request) { r.Header.Set(flowConsumerMachineHeader, "yes") })
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a browser session ends at its sign-in's absolute deadline",
			setup: flowSetup{
				sessions: []session.Option{
					session.WithIdleTimeout(time.Minute), session.WithAbsoluteTimeout(2 * time.Minute),
				},
			},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				_, _, a := w.atConsent(t, w.session(t))
				secret := a.sessionSecret(t)

				silently := func() flowAnswer {
					return w.authorizeGET(t, flowParams(flowFirstParty, func(p url.Values) { p.Set("prompt", "none") }),
						flowCookieOf(flowSession, secret))
				}

				for range 2 {
					w.clk.Advance(50 * time.Second)
					require.NotEmpty(t, silently().location(t).Query().Get("code"), "use keeps it alive until then")
				}

				w.clk.Advance(25 * time.Second)
				assert.Equal(t, "login_required", silently().location(t).Query().Get("error"))
			},
		},
		{
			name: "a flow cookie from another request's browser is an unknown handle",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)
				_, otherFlow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, otherFlow))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name: "a login sets the browser-session cookie",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				_, _, a := w.atConsent(t, w.session(t))

				c := a.cookie(flowSession)
				require.NotNil(t, c)
				assert.NotEmpty(t, c.Value)
				assert.Equal(t, "/", c.Path)
				assert.True(t, c.Secure)
				assert.True(t, c.HttpOnly)
				assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
				assert.Empty(t, c.Domain)
			},
		},
		{
			name: "a newer login replaces the browser session, and the old secret no longer loads",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				s := w.session(t)
				_, _, first := w.atConsent(t, s)
				old := first.sessionSecret(t)

				handle, flow := w.park(t, flowWeb)
				second := w.resume(t, flowLoginBody(handle), flowBearer(s.ID),
					flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, old))
				require.Equal(t, http.StatusOK, second.status)
				assert.NotEqual(t, old, second.sessionSecret(t))

				silent := w.authorizeGET(t, flowParams(flowFirstParty, func(p url.Values) { p.Set("prompt", "none") }),
					flowCookieOf(flowSession, old))
				assert.Equal(t, "login_required", silent.location(t).Query().Get("error"))
			},
		},
		{
			name: "a browser session lives on the chain's manager's idle timeout",
			setup: flowSetup{
				sessions: []session.Option{session.WithIdleTimeout(time.Minute), session.WithAbsoluteTimeout(time.Hour)},
			},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				_, _, a := w.atConsent(t, w.session(t))
				secret := a.sessionSecret(t)

				w.clk.Advance(61 * time.Second)

				silent := w.authorizeGET(t, flowParams(flowFirstParty, func(p url.Values) { p.Set("prompt", "none") }),
					flowCookieOf(flowSession, secret))
				assert.Equal(t, "login_required", silent.location(t).Query().Get("error"))
			},
		},
		{
			name:  "with browser sessions off a login sets no cookie",
			setup: flowSetup{provider: []oidcprovider.Option{oidcprovider.WithoutBrowserSessions()}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				_, _, a := w.atConsent(t, w.session(t))
				assert.Empty(t, a.cookies)
			},
		},
		{
			name: "a consent answered on the browser session alone is accepted",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, login := w.atConsent(t, w.session(t))

				a := w.resume(t, flowGrantBody(handle, "openid"), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, login.sessionSecret(t)))
				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.NotEmpty(t, a.redirectTo(t).Query().Get("code"))
				assert.Empty(t, a.cookies, "only a login stage sets the cookie")
			},
		},
		{
			name: "a denial on the browser session alone is accepted",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, login := w.atConsent(t, w.session(t))

				a := w.resume(t, flowDenyBody(handle), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, login.sessionSecret(t)))
				require.Equal(t, http.StatusOK, a.status, a.body)
				assert.Equal(t, "access_denied", a.redirectTo(t).Query().Get("error"))
			},
		},
		{
			name: "a cross-site consent on the browser session is refused by CSRF protection",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, login := w.atConsent(t, w.session(t))

				a := w.resume(t, flowGrantBody(handle, "openid"), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, login.sessionSecret(t)),
					func(r *http.Request) {
						r.Header.Set("Sec-Fetch-Site", "cross-site")
						r.Header.Set("Origin", "https://evil.example.com")
					})
				require.ErrorIs(t, a.err, httpsec.ErrCrossSiteRequest)
				assert.Equal(t, http.StatusForbidden, a.status)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a consent with no sign-in and no browser session is unauthenticated",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, _ := w.atConsent(t, w.session(t))

				a := w.resume(t, flowGrantBody(handle, "openid"), flowCookieOf(flowCookie, flow))
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a login stage does not rest on the browser session",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				_, _, login := w.atConsent(t, w.session(t))
				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, login.sessionSecret(t)))
				require.ErrorIs(t, a.err, httpsec.ErrAuthenticationRequired)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name:  "with browser sessions off a consent cookie answers nothing",
			setup: flowSetup{provider: []oidcprovider.Option{oidcprovider.WithoutBrowserSessions()}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, _ := w.atConsent(t, w.session(t))

				a := w.resume(t, flowGrantBody(handle, "openid"), flowCookieOf(flowCookie, flow),
					flowCookieOf(flowSession, strings.Repeat("a", 43)))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCReauthenticate)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a method the endpoint does not serve is answered here, and not passed on",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, w.issuer+flowResumePath, nil)

				a := w.serve(t, r, nil)
				assert.Equal(t, http.StatusMethodNotAllowed, a.status)
				assert.Equal(t, http.MethodPost, a.header.Get("Allow"))
				assert.Equal(t, "no-store", a.header.Get("Cache-Control"))
				assert.False(t, a.passedOn)
			},
		},
		{
			name: "a resume not made over TLS is refused",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID),
					flowCookieOf(flowCookie, flow), flowPlainHTTP)
				require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
				assert.Empty(t, a.cookies)
				flowUnspent(t, w, handle, flow)
			},
		},
		{
			name:  "the loopback issuer resumes over plain http, with its unprefixed cookies",
			setup: flowSetup{issuer: flowLoopback},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow := w.parkIn(t, flowCookiePlain, flowWeb)

				a := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookiePlain, flow))
				require.Equal(t, http.StatusOK, a.status, a.body)

				c := a.cookie(flowSessionPlain)
				require.NotNil(t, c)
				assert.False(t, c.Secure)
				assert.True(t, c.HttpOnly)
				assert.Nil(t, a.cookie(flowSession))

				grant := w.resume(t, flowGrantBody(handle, "openid"),
					flowCookieOf(flowCookiePlain, flow), flowCookieOf(flowSessionPlain, c.Value))
				assert.Equal(t, http.StatusOK, grant.status, grant.body)
			},
		},
		{
			name: "a body that is not JSON is malformed",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				a := w.resume(t, "{", flowBearer(w.session(t).ID))
				require.ErrorIs(t, a.err, httpsec.ErrOIDCConsentMalformed)
				assert.Equal(t, http.StatusBadRequest, a.status)
			},
		},
		{
			name: "a body not declared as JSON is malformed, as a cross-site form could be neither",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				handle, flow, login := w.atConsent(t, w.session(t))

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, w.issuer+flowResumePath,
					strings.NewReader(flowGrantBody(handle, "openid")))
				r.Header.Set("Content-Type", "text/plain")

				a := w.serve(t, r, []flowChange{
					flowCookieOf(flowCookie, flow), flowCookieOf(flowSession, login.sessionSecret(t)),
				})
				require.ErrorIs(t, a.err, httpsec.ErrOIDCConsentMalformed)
				assert.Equal(t, oidcprovider.StageConsent, w.stage(t, handle, flow))
			},
		},
		{
			name: "a body over the default limit is too large",
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				a := w.resume(t, `{"req":"`+strings.Repeat("a", int(httpsec.DefaultLoginBodyLimit))+`"}`,
					flowBearer(w.session(t).ID))
				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
			},
		},
		{
			name:  "a consumer's body limit replaces the default",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCResumeBodyLimit(4)}},
			run: func(t *testing.T, w *opFlow) {
				t.Helper()

				a := w.resume(t, flowLoginBody("rh.x"), flowBearer(w.session(t).ID))
				require.ErrorIs(t, a.err, httpsec.ErrRequestTooLarge)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.run(t, newOPFlow(t, tc.setup))
		})
	}
}

// must1 is a limiter, or the test's end.
func must1(l *ratelimit.MemoryLimiter, err error) ratelimit.Limiter {
	if err != nil {
		panic(errors.Join(errors.New("flow limiter"), err))
	}

	return l
}

// flowGenerator signs what a signed-token bearer verifies, on the chain's clock.
func flowGenerator(t *testing.T, w *opFlow) *token.JWTGenerator {
	t.Helper()

	gen, err := token.NewGenerator(tokenKeys(), token.WithoutIssuer(), token.WithoutAudience(), token.WithClock(w.clk))
	require.NoError(t, err)

	return gen
}

// flowConsumerChallenge is a challenge kind of the consumer's own.
const flowConsumerChallenge policy.ChallengeKind = 100

// apiKeys is a key manager holding one key for the row to present.
func (w *opFlow) apiKeys(t *testing.T) *apikey.Keys {
	t.Helper()

	keys := must.Must(apikey.New(apikey.WithStore(apikey.NewMemoryStore())))

	presented, _, err := keys.Issue(t.Context(), "u-1", "billing", []string{"invoices:read"}, 0)
	require.NoError(t, err)

	w.apiKey = presented

	return keys
}

// apiKeyHeader presents the key apiKeys issued.
func (w *opFlow) apiKeyHeader() flowChange {
	return func(r *http.Request) { r.Header.Set("Authorization", httpsec.DefaultAPIKeyScheme+w.apiKey) }
}

// flowConsumerSessionHeader and flowConsumerMachineHeader are what a consumer's own
// interceptor reads in these rows, in place of the Authorization header.
const (
	flowConsumerSessionHeader = "X-Consumer-Session"
	flowConsumerMachineHeader = "X-Consumer-Machine"
)

// flowConsumerAuthorization presents id to the consumer's interceptor in the Authorization
// header, in a scheme nothing else on the chain reads.
func flowConsumerAuthorization(id string) flowChange {
	return func(r *http.Request) {
		r.Header.Set(flowConsumerSessionHeader, id)
		r.Header.Set("Authorization", "Consumer "+id)
	}
}

func flowConsumerSession(id string) flowChange {
	return func(r *http.Request) { r.Header.Set(flowConsumerSessionHeader, id) }
}

// consumerSessions is a consumer's interceptor publishing the session its header names. It
// states the credential as its own bearer's only when record is set.
func (w *opFlow) consumerSessions(record bool) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		presented := ex.Request.Header(flowConsumerSessionHeader)
		if presented == "" {
			return next(ex)
		}

		s, err := w.sessions.Load(ex.Context(), presented)
		if err != nil {
			return err
		}

		if err := ex.PublishSession(&authenticate.Authentication{
			Principal: &identity.Principal{ID: s.UserID},
			Time:      w.clk.Now(),
		}, s); err != nil {
			return err
		}

		if record {
			ex.RecordPresentedToken(presented)
		}

		return next(ex)
	}), httpsec.OrderBearerToken)
}

// refusesOwing is the row's check that s, which owes kind, cannot resume: it is refused
// with that challenge, and the handle stays unspent.
func (w *opFlow) refusesOwing(t *testing.T, s *session.Session, kind policy.ChallengeKind) {
	t.Helper()

	handle, flow := w.park(t, flowWeb)

	a := w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))

	var challenge *httpsec.ChallengeError
	require.ErrorAs(t, a.err, &challenge)
	assert.Equal(t, kind, challenge.Kind)
	flowUnspent(t, w, handle, flow)
}
