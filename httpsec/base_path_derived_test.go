package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// derivedBase is the base path every chain in this file is built under.
const derivedBase = "/auth"

// Each test here pins one value the chain derives from a built-in endpoint's
// path, under a base path: it must follow the path the endpoint answers at, not
// the path its option declared. A value left on the declared path fails open
// there and closed at the moved path, so every test probes both.

// TestBasePath_PendingSessionsCanSignOut pins that each gate holding a session
// in a pending state exempts logout where logout answers under the base path,
// and gives the path without the base no exemption.
func TestBasePath_PendingSessionsCanSignOut(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// build is the chain carrying a pending session, that session, and the
		// manager it is stored in.
		build func(t *testing.T) (*httpsec.Chain, *session.Session, *session.Sessions)

		path   string
		assert func(t *testing.T, sessions *session.Sessions, s *session.Session, out served)
	}

	enrolChain := func(state func(t *testing.T, h *enrolHarness) *session.Session, extra ...httpsec.Option,
	) func(t *testing.T) (*httpsec.Chain, *session.Session, *session.Sessions) {
		return func(t *testing.T) (*httpsec.Chain, *session.Session, *session.Sessions) {
			h := newEnrolHarness(t)
			h.extra = extra
			s := state(t, h)

			c, err := httpsec.New(append(h.options(t, s), httpsec.WithBasePath(derivedBase))...)
			require.NoError(t, err)

			return c, s, h.sessions
		}
	}

	mfaPending := enrolChain(func(t *testing.T, h *enrolHarness) *session.Session {
		return h.sessionIn(t, factor.Password, session.MFAPending)
	})

	enrolmentOnly := enrolChain(func(t *testing.T, h *enrolHarness) *session.Session {
		return h.enrolmentOnly(t, factor.Password)
	})

	recoveryPending := enrolChain(func(t *testing.T, h *enrolHarness) *session.Session {
		return h.recoveryPending(t)
	}, httpsec.EnableRecoveryGateForTest())

	passwordChangePending := func(t *testing.T) (*httpsec.Chain, *session.Session, *session.Sessions) {
		sessions, err := session.New()
		require.NoError(t, err)

		s, err := sessions.Create(t.Context(), testPrincipal().ID)
		require.NoError(t, err)

		s.PasswordChangePending = true
		require.NoError(t, sessions.Save(t.Context(), s))

		c, err := httpsec.New(
			carryingSession(s),
			httpsec.EnablePasswordChangeGate(sessions,
				httpsec.WithPasswordChangeEndpoint(testChangePasswordPath, func(*httpsec.Exchange) error { return nil })),
			httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}),
			httpsec.WithBasePath(derivedBase),
		)
		require.NoError(t, err)

		return c, s, sessions
	}

	loggedOut := func(t *testing.T, sessions *session.Sessions, s *session.Session, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.NotErrorAs(t, out.err, &ch, "the gate does not refuse the moved logout")
		require.NoError(t, out.err)
		assert.False(t, out.handlerRan, "logout answers the request itself")

		_, err := sessions.Load(t.Context(), s.ID)
		require.Error(t, err, "the session is ended")
	}

	refused := func(t *testing.T, sessions *session.Sessions, s *session.Session, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch, "the path without the base is a route like any other, which the gate refuses")
		assert.False(t, out.handlerRan)

		_, err := sessions.Load(t.Context(), s.ID)
		require.NoError(t, err, "nothing is ended")
	}

	states := []struct {
		name  string
		build func(t *testing.T) (*httpsec.Chain, *session.Session, *session.Sessions)
	}{
		{name: "a session owing a second factor", build: mfaPending},
		{name: "an enrolment-only session", build: enrolmentOnly},
		{name: "a session owing a password change", build: passwordChangePending},
		{name: "a recovery-pending session", build: recoveryPending},
	}

	var cases []testCase

	for _, st := range states {
		cases = append(cases,
			testCase{
				name:   st.name + " can post to the moved logout",
				build:  st.build,
				path:   derivedBase + httpsec.DefaultLogoutPath,
				assert: loggedOut,
			},
			testCase{
				name:   st.name + " gets no exemption at the path without the base",
				build:  st.build,
				path:   httpsec.DefaultLogoutPath,
				assert: refused,
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, s, sessions := tc.build(t)
			tc.assert(t, sessions, s, serve(t, c, formRequest(t.Context(), tc.path, "")))
		})
	}
}

// TestBasePath_GateExemptionsFollow pins that the exemptions the recovery gate
// and the enrolment gate give the enrolment, passkey registration and
// password-change endpoints name the paths those endpoints answer at under the
// base path, and not the paths without it.
func TestBasePath_GateExemptionsFollow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// recovered carries a recovery-pending session; otherwise an
		// enrolment-only one.
		recovered bool

		path   string
		assert func(t *testing.T, out served)
	}

	reached := func(t *testing.T, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.False(t, errors.As(out.err, &ch), "a gate refused the moved endpoint: %v", out.err)
		assert.False(t, out.handlerRan, "the endpoint answers the request itself")
	}

	challenged := func(kind policy.ChallengeKind) func(t *testing.T, out served) {
		return func(t *testing.T, out served) {
			t.Helper()

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch, "got %v", out.err)
			assert.Equal(t, kind, ch.Kind)
			assert.False(t, out.handlerRan)
		}
	}

	moved := func(p string) string { return derivedBase + p }

	cases := []testCase{
		{
			name: "recovery gate: the moved enrolment begin is reachable", recovered: true,
			path: moved(enrolBeginPath), assert: reached,
		},
		{
			name: "recovery gate: the enrolment begin without the base is refused", recovered: true,
			path: enrolBeginPath, assert: challenged(policy.ChallengeAccountRecovery),
		},
		{
			name: "recovery gate: the moved passkey registration begin is reachable", recovered: true,
			path: moved(passkeyBeginPath), assert: reached,
		},
		{
			name: "recovery gate: the passkey registration begin without the base is refused", recovered: true,
			path: passkeyBeginPath, assert: challenged(policy.ChallengeAccountRecovery),
		},
		{
			name: "recovery gate: the moved password-change resolve endpoint is reachable", recovered: true,
			path: moved(passwordResolvePath), assert: reached,
		},
		{
			name: "recovery gate: the password-change resolve endpoint without the base is refused", recovered: true,
			path: passwordResolvePath, assert: challenged(policy.ChallengeAccountRecovery),
		},
		{
			name: "enrolment gate: the moved passkey registration begin is reachable",
			path: moved(passkeyBeginPath), assert: reached,
		},
		{
			name: "enrolment gate: the passkey registration begin without the base is refused",
			path: passkeyBeginPath, assert: challenged(policy.ChallengeMFAEnrolment),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			h.passkeyMethod = true
			h.withRecoveryGate = tc.recovered
			h.extra = append(h.extra, httpsec.EnablePasswordChangeGate(h.sessions,
				httpsec.WithPasswordChangeEndpoint(passwordResolvePath, func(*httpsec.Exchange) error { return nil })))

			var s *session.Session
			if tc.recovered {
				s = h.recoveryPending(t)
			} else {
				s = h.enrolmentOnly(t, factor.Password)
			}

			c, err := httpsec.New(append(h.chainOptions(t, s), httpsec.WithBasePath(derivedBase))...)
			require.NoError(t, err)

			tc.assert(t, serve(t, c, post(t.Context(), tc.path, "")))
		})
	}
}

// derivedProviderChain builds a chain with the provider at issuer under the
// base path, with what the provider needs beside it: a bearer, the key set
// (moved by jwks), security headers and cross-site protection, then extra.
func derivedProviderChain(t *testing.T, issuer string, jwks []httpsec.JWKSOption, popts []oidcprovider.Option,
	extra []httpsec.Option, ep ...httpsec.OIDCProviderOption,
) (*httpsec.Chain, error) {
	t.Helper()

	f := newOPFixture(t)
	p := f.providerOver(t, issuer, f.keys, nil, popts...)

	opts := []httpsec.Option{
		f.bearer(t, reporting(t, p)),
		httpsec.EnableJWKSEndpoint(f.keys, jwks...),
		httpsec.EnableSecurityHeaders(),
		httpsec.EnableCSRFProtection(),
	}
	opts = append(opts, extra...)
	opts = append(opts, httpsec.EnableOIDCProvider(p, ep...), httpsec.WithBasePath(derivedBase))

	return httpsec.New(opts...)
}

// TestBasePath_CrossSiteExemptionsFollow pins that the cross-site layer exempts
// the back-channel logout endpoint and the provider's POST endpoints at the
// paths they answer at under the base path, and judges the paths without it.
func TestBasePath_CrossSiteExemptionsFollow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) *httpsec.Chain
		target string
		assert func(t *testing.T, out served)
	}

	oidcLogin := func(t *testing.T) *httpsec.Chain {
		h := newOIDCHarness(t)
		h.chainOpts = []httpsec.Option{httpsec.EnableCSRFProtection(), httpsec.WithBasePath(derivedBase)}

		return h.chain(t)
	}

	provider := func(t *testing.T) *httpsec.Chain {
		c, err := derivedProviderChain(t, bpIssuer, nil, nil, nil)
		require.NoError(t, err)

		return c
	}

	exempt := func(t *testing.T, out served) {
		t.Helper()

		require.NotErrorIs(t, out.err, httpsec.ErrCrossSiteRequest, "the moved endpoint is exempt")
		assert.False(t, out.handlerRan, "the endpoint answers the request itself")
	}

	judged := func(t *testing.T, out served) {
		t.Helper()

		refusedCrossSite(t, out)
	}

	backchannel := httpsec.DefaultOIDCBackchannelPath + testOIDCProvider

	cases := []testCase{
		{
			name: "back-channel logout at the moved path", build: oidcLogin,
			target: "https://app.example.com" + derivedBase + backchannel, assert: exempt,
		},
		{
			name: "back-channel logout without the base", build: oidcLogin,
			target: "https://app.example.com" + backchannel, assert: judged,
		},
	}

	for _, ep := range []string{"/oauth2/authorize", "/oauth2/token", "/oauth2/revoke", "/oauth2/introspect", "/oauth2/logout"} {
		cases = append(cases,
			testCase{
				name: "provider " + ep + " at the moved path", build: provider,
				target: opIssuer + derivedBase + ep, assert: exempt,
			},
			testCase{
				name: "provider " + ep + " without the base", build: provider,
				target: opIssuer + ep, assert: judged,
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := csrfRequest(t.Context(), http.MethodPost, tc.target, map[string]string{"Sec-Fetch-Site": "cross-site"}, "")
			req.RemoteAddr = tokenAddr

			tc.assert(t, serve(t, tc.build(t), req))
		})
	}
}

// TestBasePath_ProviderCORSScopeFollows pins that the CORS layer treats the
// provider's endpoints by the paths they answer at under the base path: the
// moved client endpoints follow the provider's rules, the moved browser
// endpoints carry no CORS header, and the paths without the base are the
// consumer's own.
func TestBasePath_ProviderCORSScopeFollows(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		assert func(t *testing.T, out served)
	}

	// providerRules is a preflight asking for DPoP allowed: the consumer's
	// policy does not list it, so only the provider's client rules allow it.
	providerRules := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.Equal(t, http.StatusNoContent, out.rec.Code)
		assert.Equal(t, allowedOrigin, out.rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, out.rec.Header().Get("Access-Control-Allow-Headers"), "DPoP")
		assert.Empty(t, out.rec.Header().Get("Access-Control-Allow-Credentials"), "a provider endpoint allows no credentials")
	}

	consumerRules := func(t *testing.T, out served) {
		t.Helper()

		assert.Empty(t, out.rec.Header().Get("Access-Control-Allow-Origin"), "DPoP is not on the consumer's list")
	}

	noAccessControl := func(t *testing.T, out served) {
		t.Helper()

		for name := range out.rec.Header() {
			assert.False(t, strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-"), "%s is set", name)
		}
	}

	cases := []testCase{
		{name: "the moved token endpoint follows the provider's rules", path: derivedBase + "/oauth2/token", assert: providerRules},
		{name: "the token endpoint without the base is the consumer's", path: "/oauth2/token", assert: consumerRules},
		{name: "the moved UserInfo endpoint follows the provider's rules", path: derivedBase + "/oauth2/userinfo", assert: providerRules},
		{
			name: "the discovery document under the base follows the provider's rules",
			path: derivedBase + "/.well-known/openid-configuration", assert: providerRules,
		},
		{name: "the moved authorization endpoint carries no CORS header", path: derivedBase + "/oauth2/authorize", assert: noAccessControl},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := derivedProviderChain(t, bpIssuer, nil, nil, []httpsec.Option{httpsec.EnableCORS(
				httpsec.CORSPolicy{AllowedOrigins: []string{allowedOrigin}, AllowCredentials: true})})
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodOptions, opIssuer+tc.path, nil)
			req.Header.Set("Origin", allowedOrigin)
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
			req.Header.Set("Access-Control-Request-Headers", "DPoP")
			req.RemoteAddr = tokenAddr

			tc.assert(t, serve(t, c, req))
		})
	}
}

// The provider is placed for TestBasePath_ProviderURLsFollow with an issuer
// whose path lies under the base path without being it, so a URL built from
// the declared path rather than the served one names another path: with an
// issuer at the base path, the issuer's path would be put back in front of a
// declared path, and the two would agree by accident.
const (
	derivedOPIssuer = opIssuer + derivedBase + "/op"
	derivedOPPrefix = "/op/oauth2"
)

// TestBasePath_ProviderURLsFollow pins that the URLs the provider redirects to
// and checks against name the paths it answers at under the base path: the
// form POST bounces of the authorization and end-session endpoints, the DPoP
// URL a proof must name, and the token endpoint an assertion must name.
func TestBasePath_ProviderURLsFollow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		issuer string
		jwks   []httpsec.JWKSOption
		popts  []oidcprovider.Option
		extra  []httpsec.Option
		ep     []httpsec.OIDCProviderOption
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	underOP := func(tc testCase) testCase {
		tc.issuer = derivedOPIssuer
		tc.jwks = []httpsec.JWKSOption{httpsec.WithJWKSEndpointPath("/op/jwks.json")}
		tc.ep = []httpsec.OIDCProviderOption{httpsec.WithOIDCProviderPrefix(derivedOPPrefix)}

		return tc
	}

	bounced := func(path, body, location string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, opIssuer+path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = tokenAddr

			out := serve(t, c, req)
			require.NoError(t, out.err)
			require.Equal(t, http.StatusSeeOther, out.rec.Code)
			assert.Equal(t, location, out.rec.Header().Get("Location"), "the bounce names the URL the endpoint answers at")
		}
	}

	dpopProof := func(t *testing.T, c *httpsec.Chain, jti, htu string) string {
		t.Helper()

		k := newDPoPKey(t, elliptic.P256())
		proof := k.validProof(jti).with(map[string]any{
			"htm": http.MethodPost, "htu": htu, "iat": time.Now().Unix(),
		}).sign(t)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, opIssuer+derivedBase+"/oauth2/token",
			strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "client_id": {"billing-web"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", proof)
		req.RemoteAddr = tokenAddr

		rec := httptest.NewRecorder()
		c.Middleware()(http.NotFoundHandler()).ServeHTTP(rec, req)
		require.NotEqual(t, http.StatusNotFound, rec.Code, "the token endpoint answered")

		return rec.Body.String()
	}

	dpop := []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: opIssuer})}

	assertionTo := func(endpoint string) []oidcprovider.Option {
		return []oidcprovider.Option{
			oidcprovider.WithClientAssertionAudience(oidcprovider.AudienceIssuerOrTokenEndpoint),
			oidcprovider.WithAssertionTokenEndpoint(endpoint),
		}
	}

	cases := []testCase{
		underOP(testCase{
			name:   "an authorization POST bounces to the moved endpoint",
			assert: bounced(derivedBase+derivedOPPrefix+"/authorize", "client_id=billing-web", derivedOPIssuer+"/oauth2/authorize?client_id=billing-web"),
		}),
		underOP(testCase{
			name:   "an end-session POST bounces to the moved endpoint",
			assert: bounced(derivedBase+derivedOPPrefix+"/logout", "", derivedOPIssuer+"/oauth2/logout"),
		}),
		{
			name:   "a DPoP proof naming the moved token endpoint is accepted",
			issuer: bpIssuer, popts: []oidcprovider.Option{oidcprovider.WithDPoP()}, extra: dpop,
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "the chain agrees with the URL it publishes")
				assert.NotContains(t, dpopProof(t, c, "moved", opIssuer+derivedBase+"/oauth2/token"), "invalid_dpop_proof")
			},
		},
		{
			name:   "a DPoP proof naming the token endpoint without the base is refused",
			issuer: bpIssuer, popts: []oidcprovider.Option{oidcprovider.WithDPoP()}, extra: dpop,
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.Contains(t, dpopProof(t, c, "unmoved", opIssuer+"/oauth2/token"), "invalid_dpop_proof")
			},
		},
		underOP(testCase{
			name:  "an assertion audience naming the moved token endpoint builds",
			popts: assertionTo(derivedOPIssuer + "/oauth2/token"),
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		}),
		underOP(testCase{
			name:  "an assertion audience naming the token endpoint without the base is refused",
			popts: assertionTo(opIssuer + derivedOPPrefix + "/token"),
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.ErrorContains(t, err, "WithAssertionTokenEndpoint")
			},
		}),
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := derivedProviderChain(t, tc.issuer, tc.jwks, tc.popts, tc.extra, tc.ep...)
			tc.assert(t, c, err)
		})
	}
}

// TestBasePath_CookiesScopedToMovedPaths pins that each cookie an endpoint
// sets for a later request is scoped to the path that later request reaches
// under the base path: a cookie scoped to the path without it would never be
// sent back, and the flow would break.
func TestBasePath_CookiesScopedToMovedPaths(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		cookie string

		// answer runs the request that sets the cookie.
		answer func(t *testing.T) served

		path string
	}

	cases := []testCase{
		{
			name:   "the OIDC flow cookie is scoped to the moved callback",
			cookie: httpsec.DefaultOIDCFlowCookieName,
			answer: func(t *testing.T) served {
				h := newOIDCHarness(t)
				h.chainOpts = []httpsec.Option{httpsec.WithBasePath(derivedBase)}

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					derivedBase+httpsec.DefaultOIDCAuthorizePath+testOIDCProvider, nil)

				return serve(t, h.chain(t), req)
			},
			path: derivedBase + httpsec.DefaultOIDCCallbackPath,
		},
		{
			name:   "the passkey ceremony cookie is scoped to the moved finish",
			cookie: httpsec.DefaultPasswordlessCookieName,
			answer: func(t *testing.T) served {
				h := newPasskeyHarness(t)
				h.withPasswordless()

				c, err := httpsec.New(append(h.chainOptions(t, nil), httpsec.WithBasePath(derivedBase))...)
				require.NoError(t, err)

				return serve(t, c, post(t.Context(), derivedBase+passwordlessBeginPath, ""))
			},
			path: derivedBase + passwordlessFinishPath,
		},
		{
			name:   "the magic-link binding cookie is scoped to the moved redemption",
			cookie: httpsec.DefaultBindingCookieName,
			answer: func(t *testing.T) served {
				h := newMagicLinkHarness(t)
				h.chainOpts = []httpsec.Option{httpsec.WithBasePath(derivedBase)}

				return serve(t, h.chain(t), formRequest(t.Context(), derivedBase+httpsec.DefaultMagicLinkRequestPath,
					url.Values{"email": {magicLinkKnown}}.Encode()))
			},
			path: derivedBase + httpsec.DefaultMagicLinkConsumePath,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := tc.answer(t)
			require.NoError(t, out.err)
			assert.False(t, out.handlerRan, "the endpoint answers the request itself")

			c := cookieNamed(out.rec, tc.cookie)
			require.NotNil(t, c, "the endpoint sets %s", tc.cookie)
			assert.Equal(t, tc.path, c.Path)
		})
	}
}

// TestBasePath_MovedSignalStreamRecordsNoActivity pins that the signal stream
// answered under the base path records no session activity, and that the path
// without the base is an ordinary route that does.
func TestBasePath_MovedSignalStreamRecordsNoActivity(t *testing.T) {
	t.Parallel()

	const touchInterval = time.Minute

	type testCase struct {
		name   string
		assert func(t *testing.T, f *signalsFixture, answer *atomic.Pointer[bool])
	}

	cases := []testCase{
		{
			name: "a GET to the moved stream records no activity",
			assert: func(t *testing.T, f *signalsFixture, answer *atomic.Pointer[bool]) {
				s := f.signIn(t, "u-1")
				before := f.storedSession(t, s.ID)

				f.clk.Advance(2 * touchInterval)

				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)

				resp := f.send(ctx, t, http.MethodGet, derivedBase+httpsec.DefaultSessionSignalsPath, s.ID)
				requireStreamHead(t, resp)

				require.NotNil(t, answer.Load())
				assert.False(t, *answer.Load(), "the moved stream's path records no activity")

				cancel()
				f.waitDone(t)

				after := f.storedSession(t, s.ID)
				assert.True(t, before.LastAccessedAt.Equal(after.LastAccessedAt), "the stream moved the last-activity time")
			},
		},
		{
			name: "a GET to the stream's path without the base records activity",
			assert: func(t *testing.T, f *signalsFixture, answer *atomic.Pointer[bool]) {
				s := f.signIn(t, "u-1")
				before := f.storedSession(t, s.ID)

				f.clk.Advance(2 * touchInterval)

				resp := f.send(t.Context(), t, http.MethodGet, httpsec.DefaultSessionSignalsPath, s.ID)
				require.Equal(t, signalsDownstreamStatus, resp.StatusCode, "the path without the base passes through")
				f.waitDone(t)

				require.NotNil(t, answer.Load())
				assert.True(t, *answer.Load(), "an ordinary route records activity")

				after := f.storedSession(t, s.ID)
				assert.True(t, after.LastAccessedAt.After(before.LastAccessedAt), "the ordinary request recorded activity")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var answer atomic.Pointer[bool]

			f := newSignalsFixture(t, signalsSetup{
				sessionOpts: []session.Option{session.WithTouchInterval(touchInterval)},
				opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{
						httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
							records := httpsec.RecordsSessionActivity(ex)
							answer.Store(&records)

							return next(ex)
						}), httpsec.Before(httpsec.OrderSessionSignals)),
						httpsec.WithBasePath(derivedBase),
					}
				},
			})

			tc.assert(t, f, &answer)
		})
	}
}
