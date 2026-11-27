package httpsec_test

import (
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// certificateFeatures are the options a cookie chain enables certificate
// binding with: a resource server, the feature that verifies bound
// credentials, and the binding itself.
func certificateFeatures() []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(
			&httpsec.StubSource{Name: "provider", Provider: true, Unbound: true})),
		httpsec.EnableCertificateBinding(),
	}
}

// dpopFeatures are the options a cookie chain enables DPoP with, beside a
// resource server, the feature that verifies bound credentials. Where DPoP is
// required the resource server's source takes only bound tokens, as a chain
// with DPoP required must.
func dpopFeatures(require bool) []httpsec.Option {
	return []httpsec.Option{
		httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(
			&httpsec.StubSource{Name: "provider", Provider: true, Unbound: !require})),
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL, Require: require}),
	}
}

// cookieProof is a DPoP proof by k for a POST to path, issued at now and
// carrying jti and no ath, as a proof beside a cookie carries none. broken
// signs it with another key, so its signature does not verify.
func cookieProof(t *testing.T, k dpopKey, path, jti string, now time.Time, broken bool) string {
	t.Helper()

	parts := k.validProof(jti).with(map[string]any{
		"htm": http.MethodPost,
		"htu": dpopPublicURL + path,
		"iat": now.Unix(),
	})
	if broken {
		parts.signKey = newDPoPKey(t, elliptic.P256()).priv
	}

	return parts.sign(t)
}

// visitOn sends a GET for an application page to chain, presenting cookie as
// the session cookie.
func visitOn(t *testing.T, chain *httpsec.Chain, cookie string) served {
	t.Helper()

	req := getFrom(t.Context(), "/orders", e2eSource)
	req.Header.Set("Cookie", named(cookie))

	return serve(t, chain, req)
}

// signInOutcome is what one sign-in or re-proof row produced: its answer, the
// manager its session lives in, the chain it ran on, and the identifier the
// request presented ("" for a fresh sign-in).
type signInOutcome struct {
	out       served
	sessions  *session.Sessions
	chain     *httpsec.Chain
	presented string
}

// TestSessionCookie_SignInNeverBinds pins that a cookie chain that also
// enables certificate binding or DPoP, for its provider or resource server,
// never binds a session to a sender key: a sign-in or re-proof sent over mTLS
// or with a DPoP header (valid, broken, or missing where DPoP is required)
// creates or rotates an unbound session, and its cookie authenticates the
// next request. The request's certificate and proof are not read for the
// session.
func TestSessionCookie_SignInNeverBinds(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(t *testing.T) signInOutcome
		assert func(t *testing.T, o signInOutcome)
	}

	// world builds the browser world with extra chain options.
	world := func(t *testing.T, enrolled bool, extra ...httpsec.Option) *browserWorld {
		t.Helper()

		w := newBrowserWorld(t)
		if enrolled {
			w.enrol(t)
		}

		w.extra = append(w.extra, extra...)

		return w.build(t)
	}

	// login posts the password login, changed by change.
	login := func(t *testing.T, w *browserWorld, change func(*http.Request) *http.Request) signInOutcome {
		t.Helper()

		req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
			httpsec.DefaultLoginUsernameParam: {e2eAddress},
			httpsec.DefaultLoginPasswordParam: {e2ePassword},
		})

		return signInOutcome{out: serve(t, w.chain, change(req)), sessions: w.sessions, chain: w.chain}
	}

	// reauth re-authenticates a fresh sign-in with the password, the request
	// changed by change.
	reauth := func(t *testing.T, w *browserWorld, change func(*http.Request) *http.Request) signInOutcome {
		t.Helper()

		old := w.signedIn(t)
		w.clk.Advance(time.Minute)

		req := postValues(t.Context(), reauthPasswordPath, e2eSource, url.Values{"password": {e2ePassword}})
		req.Header.Set("Cookie", named(old))

		return signInOutcome{out: serve(t, w.chain, change(req)), sessions: w.sessions, chain: w.chain, presented: old}
	}

	overMTLS := func(t *testing.T) func(*http.Request) *http.Request {
		t.Helper()

		cert := newClientCert(t, "browser")

		return func(req *http.Request) *http.Request { return withConnectionCert(req, cert) }
	}

	withDPoP := func(t *testing.T, w *browserWorld, broken bool) func(*http.Request) *http.Request {
		t.Helper()

		k := newDPoPKey(t, elliptic.P256())

		return func(req *http.Request) *http.Request {
			return withProof(req, cookieProof(t, k, req.URL.Path, "jti-"+req.URL.Path, w.clk.Now(), broken))
		}
	}

	unchanged := func(req *http.Request) *http.Request { return req }

	// delivered is the identifier o's answer set the cookie to.
	delivered := func(t *testing.T, o signInOutcome) string {
		t.Helper()

		require.NoError(t, o.out.err, "the sign-in is not refused")

		c := cookieNamed(o.out.rec, httpsec.DefaultSessionCookieName)
		require.NotNil(t, c, "the sign-in set the session cookie")
		require.NotEqual(t, o.presented, c.Value, "the cookie names a new session")

		return c.Value
	}

	// unbound asserts the session the cookie names is stored with no key
	// binding.
	unbound := func(t *testing.T, o signInOutcome, id string) {
		t.Helper()

		s, err := o.sessions.Load(t.Context(), id)
		require.NoError(t, err)
		assert.True(t, s.KeyBinding.IsZero(), "the cookie session is bound to no sender key: %+v", s.KeyBinding)
	}

	// served200 is the default outcome: an unbound session whose cookie
	// authenticates the next request.
	served200 := func(t *testing.T, o signInOutcome) {
		t.Helper()

		id := delivered(t, o)
		unbound(t, o, id)

		next := visitOn(t, o.chain, id)
		require.NoError(t, next.err, "the cookie authenticates the next request")
		assert.True(t, next.handlerRan)
	}

	// loadsConfined is the outcome of a sign-in left confined (a recovery):
	// an unbound session whose cookie is accepted and then challenged, never
	// refused as a credential.
	loadsConfined := func(t *testing.T, o signInOutcome) {
		t.Helper()

		id := delivered(t, o)
		unbound(t, o, id)

		next := visitOn(t, o.chain, id)
		assert.NotErrorIs(t, next.err, httpsec.ErrAuthenticationRequired, "the cookie is not refused")
		keepsCookie(t, next)
	}

	cases := []testCase{
		{
			name: "password login over mTLS on a certificate-binding chain",
			act: func(t *testing.T) signInOutcome {
				return login(t, world(t, false, certificateFeatures()...), overMTLS(t))
			},
			assert: served200,
		},
		{
			name: "password login with a valid DPoP proof",
			act: func(t *testing.T) signInOutcome {
				w := world(t, false, dpopFeatures(false)...)

				return login(t, w, withDPoP(t, w, false))
			},
			assert: served200,
		},
		{
			name: "password login with a DPoP proof that does not verify",
			act: func(t *testing.T) signInOutcome {
				w := world(t, false, dpopFeatures(false)...)

				return login(t, w, withDPoP(t, w, true))
			},
			assert: served200,
		},
		{
			name: "password login without a DPoP proof",
			act: func(t *testing.T) signInOutcome {
				return login(t, world(t, false, dpopFeatures(false)...), unchanged)
			},
			assert: served200,
		},
		{
			name: "password login without a DPoP proof where DPoP is required",
			act: func(t *testing.T) signInOutcome {
				return login(t, world(t, false, dpopFeatures(true)...), unchanged)
			},
			assert: served200,
		},
		{
			name: "re-authentication over mTLS on a certificate-binding chain",
			act: func(t *testing.T) signInOutcome {
				return reauth(t, world(t, false, certificateFeatures()...), overMTLS(t))
			},
			assert: served200,
		},
		{
			name: "re-authentication with a valid DPoP proof",
			act: func(t *testing.T) signInOutcome {
				w := world(t, false, dpopFeatures(false)...)

				return reauth(t, w, withDPoP(t, w, false))
			},
			assert: served200,
		},
		{
			name: "second-factor verification with a DPoP proof that does not verify",
			act: func(t *testing.T) signInOutcome {
				w := world(t, true, dpopFeatures(false)...)

				challenged := w.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending)

				req := postValues(t.Context(), testMFAVerifyPath, e2eSource, url.Values{"code": {w.code(t)}})
				req.Header.Set("Cookie", named(pending.Value))

				return signInOutcome{
					out:      serve(t, w.chain, withDPoP(t, w, true)(req)),
					sessions: w.sessions, chain: w.chain, presented: pending.Value,
				}
			},
			assert: served200,
		},
		{
			name: "magic link redemption over mTLS on a certificate-binding chain",
			act: func(t *testing.T) signInOutcome {
				h := newMagicLinkHarness(t)
				h.tokens = nil
				h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users}))
				h.chainOpts = append(h.chainOpts, certificateFeatures()...)

				chain, err := h.build()
				require.NoError(t, err)

				tok, nonce := h.link(t, chain)

				req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, magicLinkSource,
					url.Values{"token": {tok}})
				if nonce != "" {
					req.AddCookie(bindingCookie(nonce))
				}

				return signInOutcome{
					out: serve(t, chain, overMTLS(t)(req)), sessions: h.sessions, chain: chain,
				}
			},
			assert: served200,
		},
		{
			name: "passwordless passkey login over mTLS on a certificate-binding chain",
			act: func(t *testing.T) signInOutcome {
				d := newPwlDeployment(t)
				_ = d.options(t)

				chain, err := httpsec.New(append([]httpsec.Option{
					httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: d.sessions, Users: d.users}),
					httpsec.EnablePasskeys(
						httpsec.PasskeyDeps{Passkeys: d.manager, Sessions: d.sessions, Users: d.users},
						httpsec.WithPasskeyPasswordlessLogin()),
				}, certificateFeatures()...)...)
				require.NoError(t, err)

				d.chain = chain

				handle := d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				ceremony, challenge := d.begun(t)

				req := jsonPost(t.Context(), passwordlessFinishPath, handleAssertionBody(challenge, "cred-1", handle))
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultPasswordlessCookieName, Value: ceremony}) //nolint:gosec // G124: a request cookie

				return signInOutcome{out: serve(t, chain, overMTLS(t)(req)), sessions: d.sessions, chain: chain}
			},
			assert: served200,
		},
		{
			name: "recovery completion over mTLS on a certificate-binding chain",
			act: func(t *testing.T) signInOutcome {
				h := newRecoveryHarness(t)
				h.cookie = true
				h.chainOpts = append(h.chainOpts, certificateFeatures()...)
				h.build(t)

				req := postValues(t.Context(), httpsec.DefaultRecoveryCompletePath, e2eSource, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword))

				return signInOutcome{out: serve(t, h.chain, overMTLS(t)(req)), sessions: h.sessions, chain: h.chain}
			},
			assert: loadsConfined,
		},
		{
			name: "held recovery finish over mTLS on a certificate-binding chain",
			act: func(t *testing.T) signInOutcome {
				h := newRecoveryHarness(t)
				h.cookie = true
				h.withHold()
				h.chainOpts = append(h.chainOpts, certificateFeatures()...)
				h.build(t)

				held := h.hold(t)
				h.clock.Advance(recoveryHoldDelay + time.Second)

				req := postValues(t.Context(), httpsec.DefaultRecoveryFinishPath, e2eSource,
					url.Values{httpsec.RecoveryCompletionTokenParam: {held.completion}})

				return signInOutcome{out: serve(t, h.chain, overMTLS(t)(req)), sessions: h.sessions, chain: h.chain}
			},
			assert: loadsConfined,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.act(t))
		})
	}
}

// TestSessionBearer_SignInBindsOverMTLS pins that a header-bearer chain still
// binds the session a login over mTLS creates to the client certificate: the
// cookie chain's rule that a session is never bound is its own.
func TestSessionBearer_SignInBindsOverMTLS(t *testing.T) {
	t.Parallel()

	h := newRecoveryHarness(t)
	h.reference = true
	h.chainOpts = append(h.chainOpts, httpsec.EnableCertificateBinding())
	h.build(t)

	req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	})
	out := serve(t, h.chain, withConnectionCert(req, newClientCert(t, "client")))
	require.NoError(t, out.err)

	var doc loginBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))

	s, err := h.sessions.Load(t.Context(), doc.AccessToken)
	require.NoError(t, err, "the access token is the session identifier")
	assert.NotEmpty(t, s.KeyBinding.X5TS256, "the session is bound to the client certificate")
}
