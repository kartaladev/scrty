package httpsec_test

import (
	"crypto/elliptic"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
)

// RFC 9110 section 15.5.2: a server generating a 401 MUST send WWW-Authenticate. Each row answers a
// 401 from an endpoint resting on a sign-in, and states the challenges that answer carries.
func TestOIDCSignInEndpoints_UnauthorizedCarriesAChallenge(t *testing.T) {
	t.Parallel()

	const (
		bearer     = `Bearer realm="oauth2"` //nolint:gosec // G101: a challenge, and no credential
		bareBearer = "Bearer"
		// invalidToken is what RFC 6750 section 3.1 asks of a request that presented a token the chain
		// refused: the code, and nothing about why.
		invalidToken = `Bearer error="invalid_token"` //nolint:gosec // G101: a challenge, and no credential
		unknownToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		// dpopScheme stands for a DPoP challenge, whichever algorithms it names.
		dpopScheme = "DPoP algs="
	)

	withDPoP := func(d func(*testing.T) *httpsec.DPoP) flowSetup {
		return flowSetup{
			provider: []oidcprovider.Option{oidcprovider.WithDPoP()},
			chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.EnableDPoP(*d(t))}
			},
		}
	}

	// staleResume is a resume whose sign-in is too old for the request.
	staleResume := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		s := w.session(t)
		handle, flow := w.park(t, flowWeb, func(v url.Values) { v.Set("max_age", "1") })
		w.clk.Advance(5 * time.Second)

		return w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
	}
	// provedStaleResume is staleResume by a sign-in bound to a key, with its proof, which is all a chain
	// requiring DPoP lets through.
	provedStaleResume := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		k := newDPoPKey(t, elliptic.P256())
		s := w.session(t, session.WithKeyBinding(session.KeyBinding{JKT: k.jkt}))
		handle, flow := w.park(t, flowWeb, func(v url.Values) { v.Set("max_age", "1") })
		w.clk.Advance(5 * time.Second)

		proof := k.validProof("stale-1").with(map[string]any{
			"htm": http.MethodPost, "htu": w.issuer + flowResumePath, "iat": w.clk.Now().Unix(), "ath": tokenHash(s.ID),
		}).sign(t)

		return w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), func(r *http.Request) {
			r.Header.Set("Authorization", "DPoP "+s.ID)
			r.Header.Set("DPoP", proof)
		})
	}
	noCredentialResume := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		handle, flow := w.park(t, flowWeb)

		return w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow))
	}
	owing := func(t *testing.T, w *opFlow) *session.Session {
		t.Helper()

		s := w.session(t)
		s.MFA = session.MFAPending
		require.NoError(t, w.sessions.Save(t.Context(), s))

		return s
	}

	// unknownResume presents a token no sign-in answers to.
	unknownResume := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		handle, flow := w.park(t, flowWeb)

		return w.resume(t, flowLoginBody(handle), flowBearer(unknownToken), flowCookieOf(flowCookie, flow))
	}
	// endedResume presents the token of a sign-in that has ended.
	endedResume := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		s := w.session(t)
		require.NoError(t, w.sessions.Delete(t.Context(), s.ID))
		handle, flow := w.park(t, flowWeb)

		return w.resume(t, flowLoginBody(handle), flowBearer(s.ID), flowCookieOf(flowCookie, flow))
	}
	unknownList := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		return w.consentsGET(t, consentsPath, flowBearer(unknownToken))
	}
	unknownRevoke := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		return w.consentsDELETE(t, consentsPath+"/"+flowWeb, flowBearer(unknownToken))
	}
	owingList := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		return w.consentsGET(t, consentsPath, flowBearer(owing(t, w).ID))
	}
	noCredentialList := func(t *testing.T, w *opFlow) flowAnswer {
		t.Helper()

		return w.consentsGET(t, consentsPath)
	}

	movedConsents := flowSetup{endpoint: []httpsec.OIDCProviderOption{
		httpsec.WithOIDCProviderPath(httpsec.OIDCConsents, movedConsentsPath),
	}}
	movedResume := flowSetup{endpoint: []httpsec.OIDCProviderOption{
		httpsec.WithOIDCProviderPath(httpsec.OIDCResume, movedResumePath),
	}}

	type testCase struct {
		name  string
		setup flowSetup
		send  func(t *testing.T, w *opFlow) flowAnswer
		// want is the challenges, in order.
		want []string
	}

	cases := []testCase{
		{name: "a resume presenting an unknown bearer token", send: unknownResume, want: []string{invalidToken}},
		{
			// RFC 9110 section 11.1: a scheme is compared without regard to case, as the bearer reads it.
			name: "the consents list presenting an unknown token under a lower-case scheme",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath, flowAuthorization("bearer "+unknownToken))
			},
			want: []string{invalidToken},
		},
		{
			name: "the consents list presenting another scheme's credential",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath, flowAuthorization("Basic "+unknownToken))
			},
			want: []string{bearer},
		},
		{
			name: "the consents list at a path of the consumer's", setup: movedConsents,
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsGET(t, movedConsentsPath, flowBearer(unknownToken))
			},
			want: []string{invalidToken},
		},
		{
			name: "a consent's revocation under a path of the consumer's", setup: movedConsents,
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, movedConsentsPath+"/"+flowWeb, flowBearer(unknownToken))
			},
			want: []string{invalidToken},
		},
		{
			name: "a resume at a path of the consumer's", setup: movedResume,
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsDo(t, http.MethodPost, movedResumePath, []flowChange{flowBearer(unknownToken)})
			},
			want: []string{invalidToken},
		},
		{
			// A signed bearer's refusal is no want of a caller, so DPoP's own challenge leaves it here, and
			// with DPoP on the code is not offered: the token could as well be wanted under DPoP.
			name: "with DPoP on, the consents list presenting a token a signed bearer refuses",
			setup: flowSetup{
				provider: withDPoP(plainDPoP).provider,
				chain:    withDPoP(plainDPoP).chain,
				bearer:   flowSignedBearer(),
			},
			send: unknownList,
			want: []string{`DPoP algs="ES256"`, bearer},
		},
		{
			// The token is judged ahead of any proof, so this is no refusal of a proof.
			name: "with DPoP required, a token a signed bearer refuses asks for that scheme alone",
			setup: flowSetup{
				provider: withDPoP(requiredDPoP).provider,
				chain:    withDPoP(requiredDPoP).chain,
				bearer:   flowSignedBearer(),
			},
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath, flowAuthorization("DPoP "+unknownToken), flowHeader("DPoP", "not-a-proof"))
			},
			want: []string{`DPoP algs="ES256"`},
		},
		{
			name: "a signed bearer's refusal of a presented token", setup: flowSetup{bearer: flowSignedBearer()}, send: unknownList,
			want: []string{invalidToken},
		},
		{name: "a resume presenting the token of an ended sign-in", send: endedResume, want: []string{invalidToken}},
		{name: "the consents list presenting an unknown bearer token", send: unknownList, want: []string{invalidToken}},
		{name: "a consent's revocation presenting an unknown bearer token", send: unknownRevoke, want: []string{invalidToken}},
		{
			name: "a resume repeating its Authorization line",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				return w.resume(t, flowLoginBody(handle), flowCookieOf(flowCookie, flow), func(r *http.Request) {
					r.Header.Add("Authorization", "Bearer "+unknownToken)
					r.Header.Add("Authorization", "Bearer "+unknownToken)
				})
			},
			want: []string{bearer},
		},
		{
			name: "with DPoP on, a resume presenting an unknown bearer token", setup: withDPoP(plainDPoP), send: unknownResume,
			want: []string{dpopScheme, bareBearer},
		},
		{
			name: "with DPoP on, the consents list presenting an unknown bearer token", setup: withDPoP(plainDPoP), send: unknownList,
			want: []string{dpopScheme, bareBearer},
		},
		{
			name: "with DPoP on, a consent's revocation presenting an unknown bearer token", setup: withDPoP(plainDPoP), send: unknownRevoke,
			want: []string{dpopScheme, bareBearer},
		},
		{
			name: "with DPoP on, the consents list with no credential", setup: withDPoP(plainDPoP), send: noCredentialList,
			want: []string{dpopScheme, bareBearer},
		},
		{
			name: "with DPoP on, the consents list owing a second factor", setup: withDPoP(plainDPoP), send: owingList,
			want: []string{dpopScheme, bearer},
		},
		{name: "a resume by a stale sign-in", send: staleResume, want: []string{bearer}},
		{name: "a resume with no credential", send: noCredentialResume, want: []string{bearer}},
		{
			name: "a resume owing a second factor",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				return w.resume(t, flowLoginBody(handle), flowBearer(owing(t, w).ID), flowCookieOf(flowCookie, flow))
			},
			want: []string{bearer},
		},
		{
			name: "the consents list with no credential",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath)
			},
			want: []string{bearer},
		},
		{
			name: "the consents list owing a second factor",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsGET(t, consentsPath, flowBearer(owing(t, w).ID))
			},
			want: []string{bearer},
		},
		{
			name: "a consent's revocation with no credential",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/"+flowWeb)
			},
			want: []string{bearer},
		},
		{
			name: "with DPoP on, a stale sign-in is challenged under both schemes", setup: withDPoP(plainDPoP), send: staleResume,
			want: []string{dpopScheme, bearer},
		},
		{
			name: "with DPoP on, a refusal the chain's own challenge answers is challenged once", setup: withDPoP(plainDPoP), send: noCredentialResume,
			want: []string{dpopScheme, bareBearer},
		},
		{
			name: "with DPoP required, only that scheme is asked for", setup: withDPoP(requiredDPoP), send: provedStaleResume,
			want: []string{dpopScheme},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, tc.setup)
			a := tc.send(t, w)

			require.Equal(t, http.StatusUnauthorized, a.status, a.body)

			got := a.header.Values("WWW-Authenticate")
			require.Len(t, got, len(tc.want), "%q", got)
			for i, want := range tc.want {
				if want == dpopScheme {
					assert.True(t, strings.HasPrefix(got[i], dpopScheme), "%q", got)

					continue
				}
				assert.Equal(t, want, got[i])
			}
		})
	}
}

// A refusal that is no 401 is challenged by nothing.
func TestOIDCSignInEndpoints_OtherRefusalsCarryNoChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		send   func(t *testing.T, w *opFlow) flowAnswer
		status int
	}

	cases := []testCase{
		{
			name: "a resume that says nothing the provider could judge",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.resume(t, "not a document", flowBearer(w.session(t).ID))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "a consent the caller never gave",
			send: func(t *testing.T, w *opFlow) flowAnswer {
				t.Helper()

				return w.consentsDELETE(t, consentsPath+"/no-such-client", flowBearer(w.session(t).ID))
			},
			status: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := tc.send(t, newOPFlow(t, flowSetup{}))
			require.Equal(t, tc.status, a.status, a.body)
			assert.Empty(t, a.header.Values("WWW-Authenticate"))
		})
	}
}

// A bad bearer token elsewhere on the chain is refused as it always was: the provider's two sign-in
// endpoints are the only ones it challenges, and this pins that the change did not widen to the rest.
func TestOIDCSignInEndpoints_ChallengeStaysOnItsOwnPaths(t *testing.T) {
	t.Parallel()

	const unknownToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	type testCase struct {
		name   string
		setup  flowSetup
		method string
		path   string
		assert func(t *testing.T, a flowAnswer)
	}

	unchallenged := func(t *testing.T, a flowAnswer) {
		t.Helper()

		require.Equal(t, http.StatusUnauthorized, a.status, a.body)
		assert.Empty(t, a.header.Values("WWW-Authenticate"))
	}

	cases := []testCase{
		{name: "a path outside the provider", method: http.MethodGet, path: "/api/things", assert: unchallenged},
		{name: "a provider path that is not a sign-in endpoint", method: http.MethodGet, path: "/oauth2/other", assert: unchallenged},
		{name: "a path only sharing the consents list's name", method: http.MethodGet, path: consentsPath + "-other", assert: unchallenged},
		{
			// The consents answer the list's path and one segment below it; another endpoint of the
			// chain under that path (a re-authentication prefix at /oauth2/consents/a) is no consent's.
			name:   "a deeper path under the consents list, which another endpoint of the chain may answer",
			method: http.MethodPost, path: consentsPath + "/a/challenge/totp", assert: unchallenged,
		},
		{
			name:   "the consents list's path with a trailing slash",
			method: http.MethodGet, path: consentsPath + "/", assert: unchallenged,
		},
		{
			// No endpoint of the provider's outer slot calls on, and each answers its own refusals. Whatever
			// one returned regardless is left as it came: those endpoints authenticate their own way.
			name: "a 401 an endpoint of the outer slot returned",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithTestOIDCGroup(&httpsec.TestOIDCGroup{Path: "/g", Answer: httpsec.ErrAuthenticationRequired}),
			}},
			method: http.MethodGet, path: "/g", assert: unchallenged,
		},
		{
			name: "the default consents path, once the consumer moved the list",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPath(httpsec.OIDCConsents, movedConsentsPath),
			}},
			method: http.MethodGet, path: consentsPath, assert: unchallenged,
		},
		{
			name: "a path under the default consents path, once the consumer moved the list",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPath(httpsec.OIDCConsents, movedConsentsPath),
			}},
			method: http.MethodDelete, path: consentsPath + "/" + flowWeb, assert: unchallenged,
		},
		{
			name: "the default resume path, once the consumer moved the resume",
			setup: flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCProviderPath(httpsec.OIDCResume, movedResumePath),
			}},
			method: http.MethodPost, path: flowResumePath, assert: unchallenged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, tc.setup)

			tc.assert(t, w.consentsDo(t, tc.method, tc.path, []flowChange{flowBearer(unknownToken)}))
		})
	}
}

// With DPoP on, a refusal DPoP's own challenge answers is challenged by it alone at the resume and the
// consents, exactly as anywhere else on the chain. Nothing is added ahead of it: a client reading the
// first line must see the error it has to act on.
func TestOIDCSignInEndpoints_DPoPAnsweredRefusalIsChallengedOnce(t *testing.T) {
	t.Parallel()

	const (
		invalidProof = `DPoP error="invalid_dpop_proof", algs="ES256"`
		useNonce     = `DPoP error="use_dpop_nonce", algs="ES256"`
		wantsCaller  = `DPoP algs="ES256"`
	)

	onChain := func(d func(*testing.T) *httpsec.DPoP, extra ...httpsec.Option) flowSetup {
		return flowSetup{
			provider: []oidcprovider.Option{oidcprovider.WithDPoP()},
			chain: func(t *testing.T, _ *opFlow) []httpsec.Option {
				t.Helper()

				return append([]httpsec.Option{httpsec.EnableDPoP(*d(t))}, extra...)
			},
		}
	}
	gate := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
		return authorize.ErrAuthenticationRequired
	}), httpsec.OrderMFAChallenge)

	// noProof presents a live sign-in under the DPoP scheme, with no proof beside it.
	noProof := func(t *testing.T, w *opFlow, _, _ string) []flowChange {
		t.Helper()

		return []flowChange{flowAuthorization("DPoP " + w.session(t).ID)}
	}
	// firstStep presents a good proof that carries no nonce, the protocol's first step.
	firstStep := func(t *testing.T, w *opFlow, method, path string) []flowChange {
		t.Helper()

		k := newDPoPKey(t, elliptic.P256())
		tok := w.session(t).ID
		proof := k.validProof("first-step").with(map[string]any{
			"htm": method, "htu": w.issuer + path, "iat": w.clk.Now().Unix(), "ath": tokenHash(tok),
		}).sign(t)

		return []flowChange{flowAuthorization("DPoP " + tok), flowHeader("DPoP", proof)}
	}
	noCredential := func(*testing.T, *opFlow, string, string) []flowChange { return nil }

	exactly := func(want ...string) func(t *testing.T, a flowAnswer) {
		return func(t *testing.T, a flowAnswer) {
			t.Helper()

			require.Equal(t, http.StatusUnauthorized, a.status, a.body)
			assert.Equal(t, want, a.header.Values("WWW-Authenticate"))
		}
	}

	type testCase struct {
		name   string
		setup  flowSetup
		method string
		path   string
		change func(t *testing.T, w *opFlow, method, path string) []flowChange
		assert func(t *testing.T, a flowAnswer)
	}

	endpoints := []struct{ name, method, path string }{
		{"elsewhere on the chain, for comparison", http.MethodGet, "/api/things"},
		{"the consents list", http.MethodGet, consentsPath},
		{"a consent's revocation", http.MethodDelete, consentsPath + "/" + flowWeb},
		{"a resume", http.MethodPost, flowResumePath},
	}
	refusals := []struct {
		name   string
		setup  flowSetup
		change func(t *testing.T, w *opFlow, method, path string) []flowChange
		assert func(t *testing.T, a flowAnswer)
	}{
		{"an invalid proof", onChain(plainDPoP), noProof, exactly(invalidProof)},
		{"an invalid proof with DPoP required", onChain(requiredDPoP), noProof, exactly(invalidProof)},
		{
			"a proof asked for its nonce", onChain(noncedDPoP), firstStep,
			func(t *testing.T, a flowAnswer) {
				t.Helper()

				exactly(useNonce)(t, a)
				assert.NotEmpty(t, a.header.Get("DPoP-Nonce"), "the refusal carries the nonce to retry with")
			},
		},
		{"a consumer's gate refusing with authorize's error", onChain(plainDPoP, gate), noCredential, exactly(wantsCaller, "Bearer")},
		{"a consumer's gate with DPoP required", onChain(requiredDPoP, gate), noCredential, exactly(wantsCaller)},
	}

	var cases []testCase
	for _, r := range refusals {
		for _, e := range endpoints {
			cases = append(cases, testCase{
				name: r.name + ": " + e.name, setup: r.setup, method: e.method, path: e.path, change: r.change, assert: r.assert,
			})
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, tc.setup)

			tc.assert(t, w.consentsDo(t, tc.method, tc.path, tc.change(t, w, tc.method, tc.path)))
		})
	}
}

// RFC 6750 defines invalid_token for the Bearer scheme, so it is answered only to a line under that
// scheme, on a chain whose bearer reads it. A line under a consumer's own scheme is told nothing about
// its token, and neither is a Bearer line that nothing on the chain read.
func TestOIDCSignInEndpoints_InvalidTokenFollowsTheBearerScheme(t *testing.T) {
	t.Parallel()

	const (
		unknownToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		noCode       = `Bearer realm="oauth2"`        //nolint:gosec // G101: a challenge, and no credential
		invalidToken = `Bearer error="invalid_token"` //nolint:gosec // G101: a challenge, and no credential
	)

	sessionBearer := func(opts ...httpsec.SessionBearerOption) func(t *testing.T, w *opFlow) httpsec.Option {
		return func(t *testing.T, w *opFlow) httpsec.Option {
			t.Helper()

			return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users}, opts...)
		}
	}
	// and puts a second bearer on the chain, over the one manager.
	and := func(second func(t *testing.T, w *opFlow) httpsec.Option) func(t *testing.T, w *opFlow) []httpsec.Option {
		return func(t *testing.T, w *opFlow) []httpsec.Option {
			t.Helper()

			return []httpsec.Option{second(t, w)}
		}
	}

	type testCase struct {
		name   string
		setup  flowSetup
		line   string
		assert func(t *testing.T, got []string)
	}

	exactly := func(want ...string) func(t *testing.T, got []string) {
		return func(t *testing.T, got []string) {
			t.Helper()
			assert.Equal(t, want, got)
		}
	}

	token := flowSetup{bearer: sessionBearer(httpsec.WithSessionBearerScheme("Token"))}
	signedToken := flowSetup{bearer: flowSignedBearer(httpsec.WithBearerScheme("Token"))}
	partnerSecond := flowSetup{bearer: flowSignedBearer(), chain: and(flowSignedBearer(httpsec.WithBearerScheme("Partner")))}
	partnerFirst := flowSetup{bearer: flowSignedBearer(httpsec.WithBearerScheme("Partner")), chain: and(flowSignedBearer())}

	cases := []testCase{
		{
			name: "a session bearer under its own scheme, presented that scheme", setup: token,
			line: "Token " + unknownToken, assert: exactly(noCode),
		},
		{
			name: "a session bearer under its own scheme, presented Bearer, which nothing read", setup: token,
			line: "Bearer " + unknownToken, assert: exactly(noCode),
		},
		{
			name: "a signed bearer under its own scheme, presented that scheme", setup: signedToken,
			line: "Token " + unknownToken, assert: exactly(noCode),
		},
		{
			name: "a signed bearer under its own scheme, presented Bearer, which nothing read", setup: signedToken,
			line: "Bearer " + unknownToken, assert: exactly(noCode),
		},
		{
			name:  "a bearer naming the Bearer scheme in another case",
			setup: flowSetup{bearer: sessionBearer(httpsec.WithSessionBearerScheme("BEARER"))},
			line:  "Bearer " + unknownToken, assert: exactly(invalidToken),
		},
		{
			name: "two bearers, the Bearer one enabled first, presented Bearer", setup: partnerSecond,
			line: "Bearer " + unknownToken, assert: exactly(invalidToken),
		},
		{
			name: "two bearers, the Bearer one enabled last, presented Bearer", setup: partnerFirst,
			line: "Bearer " + unknownToken, assert: exactly(invalidToken),
		},
		{
			name: "two bearers, presented the other's scheme", setup: partnerFirst,
			line: "Partner " + unknownToken, assert: exactly(noCode),
		},
		{
			name:  "a bare token a bearer claims, presented no scheme",
			setup: flowSetup{bearer: flowSignedBearer(httpsec.WithBearerAllowEmptyScheme())},
			line:  unknownToken, assert: exactly(noCode),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPFlow(t, tc.setup)
			change := []flowChange{flowAuthorization(tc.line)}

			for _, a := range []flowAnswer{
				w.consentsGET(t, consentsPath, change...),
				w.consentsDELETE(t, consentsPath+"/"+flowWeb, change...),
				w.consentsDo(t, http.MethodPost, flowResumePath, change),
			} {
				require.Equal(t, http.StatusUnauthorized, a.status, a.body)
				tc.assert(t, a.header.Values("WWW-Authenticate"))
			}
		})
	}
}

const (
	movedConsentsPath = "/me/apps"
	movedResumePath   = "/me/resume"
)

// flowAuthorization presents line as the request's Authorization header, as it stands.
func flowAuthorization(line string) flowChange {
	return flowHeader("Authorization", line)
}

// flowHeader sets a request header.
func flowHeader(name, value string) flowChange {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

// flowSignedBearer is a signed-token bearer over the row's own manager.
func flowSignedBearer(opts ...httpsec.BearerTokenOption) func(t *testing.T, w *opFlow) httpsec.Option {
	return func(t *testing.T, w *opFlow) httpsec.Option {
		t.Helper()

		return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: flowGenerator(t, w), Sessions: w.sessions, Users: w.users}, opts...)
	}
}
