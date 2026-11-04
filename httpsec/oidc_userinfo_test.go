package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
)

const (
	userInfoURL = opIssuer + "/oauth2/userinfo"

	challengeNoToken      = `Bearer realm="oauth2"`        //nolint:gosec // G101: a challenge, and no credential
	challengeInvalidToken = `Bearer error="invalid_token"` //nolint:gosec // G101: a challenge, and no credential
	challengeMalformed    = `Bearer error="invalid_request"`
	challengeScope        = `Bearer error="insufficient_scope"`

	challengeDPoP        = `DPoP algs="ES256"`
	challengeDPoPToken   = `DPoP error="invalid_token", algs="ES256"` //nolint:gosec // G101: a challenge, and no credential
	challengeDPoPProof   = `DPoP error="invalid_dpop_proof", algs="ES256"`
	challengeDPoPNonce   = `DPoP error="use_dpop_nonce", algs="ES256"`
	challengeDPoPNoScope = `DPoP error="insufficient_scope", algs="ES256"`
)

// bearerOf presents tok under the Bearer scheme.
func bearerOf(tok string) tokenChange {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

// dpopOf presents tok under the DPoP scheme, beside proof.
func dpopOf(tok, proof string) tokenChange {
	return func(r *http.Request) {
		r.Header.Set("Authorization", "DPoP "+tok)
		r.Header.Add("DPoP", proof)
	}
}

// get calls UserInfo by GET at target.
func (w *opWorld) get(t *testing.T, target string, change ...tokenChange) tokenAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	r.RemoteAddr = tokenAddr
	for _, c := range change {
		c(r)
	}

	return w.serve(t, r)
}

// userInfoProof is a proof from k for method at UserInfo, its ath over tok, with claims set over a
// valid one's.
func (w *opWorld) userInfoProof(t *testing.T, k dpopKey, jti, method, tok string, claims map[string]any) string {
	t.Helper()

	parts := k.validProof(jti).with(map[string]any{
		"htm": method,
		"htu": userInfoURL,
		"iat": w.clk.Now().Unix(),
		"ath": tokenHash(tok),
	})
	if claims != nil {
		parts = parts.with(claims)
	}

	return parts.sign(t)
}

// bound is an access token for tokenWeb bound to k.
func (w *opWorld) bound(t *testing.T, k dpopKey, change func(url.Values)) string {
	t.Helper()

	at, _ := w.issued(t, tokenWeb, change, w.withProof(t, k, "issuing", nil))["access_token"].(string)
	require.NotEmpty(t, at)

	return at
}

// scoped asks for scope alone in an authorization request.
func scoped(scope string) func(url.Values) {
	return func(params url.Values) { params.Set("scope", scope) }
}

// assertChallenged pins a refusal: the status, exactly these challenges, and no body.
func assertChallenged(t *testing.T, a tokenAnswer, status int, challenges ...string) {
	t.Helper()

	assertTokenHeaders(t, a)
	assert.Equal(t, status, a.status)
	assert.Equal(t, challenges, a.header.Values("WWW-Authenticate"))
	assert.Empty(t, a.body)
}

// challengedWith is a row's assert for assertChallenged at 401.
func challengedWith(challenges ...string) func(*testing.T, tokenAnswer) {
	return func(t *testing.T, a tokenAnswer) {
		t.Helper()
		assertChallenged(t, a, http.StatusUnauthorized, challenges...)
	}
}

// claimsAre pins a success holding exactly want.
func claimsAre(want map[string]any) func(*testing.T, tokenAnswer) {
	return func(t *testing.T, a tokenAnswer) {
		t.Helper()

		assertAnswered(t, a)
		assert.Equal(t, "application/json", a.header.Get("Content-Type"))
		assert.Empty(t, a.header.Values("WWW-Authenticate"))
		assert.Equal(t, want, a.document(t))
	}
}

// profileClaims is what the default source releases for the fixture's user under profile.
var profileClaims = map[string]any{
	"sub": "u-1", "name": "Ada Lovelace", "preferred_username": "ada@example.com",
}

func dpopSetup(dpop func(*testing.T) *httpsec.DPoP) opWorldSetup {
	return opWorldSetup{tokenSetup: tokenSetup{dpop: dpop}}
}

// withClaimSource builds a provider reading claims through a mock expect sets up.
func withClaimSource(expect func(m *MockClaimSource)) opWorldSetup {
	return opWorldSetup{provider: func(t *testing.T) []oidcprovider.Option {
		t.Helper()

		source := NewMockClaimSource(gomock.NewController(t))
		if expect != nil {
			expect(source)
		}

		return []oidcprovider.Option{oidcprovider.WithClaimSource(source)}
	}}
}

// TestOIDCUserInfo pins the UserInfo endpoint: where the token is read from, what each scope releases,
// each refusal's challenge, and that nothing it answers can be cached.
func TestOIDCUserInfo(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  opWorldSetup
		send   func(t *testing.T, w *opWorld) tokenAnswer
		assert func(t *testing.T, a tokenAnswer)
	}

	// access is a fresh access token for clientID, with change applied to the authorization request.
	access := func(t *testing.T, w *opWorld, clientID string, change func(url.Values)) string {
		t.Helper()

		at, _ := w.issued(t, clientID, change)["access_token"].(string)
		require.NotEmpty(t, at)

		return at
	}

	cases := []testCase{
		// Where the token is read from.
		{
			name: "GET with the header",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(access(t, w, tokenWeb, nil)))
			},
			assert: claimsAre(profileClaims),
		},
		{
			name: "the scheme's case does not matter",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)

				return w.get(t, userInfoURL, func(r *http.Request) { r.Header.Set("Authorization", "bEaReR "+at) })
			},
			assert: claimsAre(profileClaims),
		},
		{
			name: "POST with the header, and no body to read",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)
				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, userInfoURL, nil)
				r.RemoteAddr = tokenAddr
				bearerOf(at)(r)

				return w.serve(t, r)
			},
			assert: claimsAre(profileClaims),
		},
		{
			name: "POST with the token in a form body",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, userInfoURL, url.Values{"access_token": {access(t, w, tokenWeb, nil)}})
			},
			assert: claimsAre(profileClaims),
		},
		{
			name: "POST with the header beside a form of other parameters",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, userInfoURL, url.Values{"other": {"x"}}, bearerOf(access(t, w, tokenWeb, nil)))
			},
			assert: claimsAre(profileClaims),
		},
		{
			name: "a token in a body that declares no form is no token",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)

				return w.post(t, userInfoURL, url.Values{"access_token": {at}}, func(r *http.Request) {
					r.Header.Set("Content-Type", "text/plain")
				})
			},
			assert: challengedWith(challengeNoToken),
		},
		{
			name: "a token in the query is no token, by GET",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL+"?access_token="+url.QueryEscape(access(t, w, tokenWeb, nil)))
			},
			assert: challengedWith(challengeNoToken),
		},
		{
			name: "a token in the query is no token, by POST",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, userInfoURL+"?access_token="+url.QueryEscape(access(t, w, tokenWeb, nil)), url.Values{})
			},
			assert: challengedWith(challengeNoToken),
		},
		{
			name: "a query beside the header is not read",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL+"?access_token=garbage", bearerOf(access(t, w, tokenWeb, nil)))
			},
			assert: claimsAre(profileClaims),
		},

		// No token, and a malformed request.
		{
			name: "no token has no code",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL)
			},
			assert: challengedWith(challengeNoToken),
		},
		{
			name: "another scheme is no token",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, asClient(tokenWeb))
			},
			assert: challengedWith(challengeNoToken),
		},
		{
			name: "the scheme with nothing after it is no token",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") })
			},
			assert: challengedWith(challengeNoToken),
		},
		{
			name: "an empty form parameter counts as omitted",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, userInfoURL, url.Values{"access_token": {""}})
			},
			assert: challengedWith(challengeNoToken),
		},
		{
			name: "the DPoP scheme is no token while DPoP is off",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, dpopOf(access(t, w, tokenWeb, nil), "proof"))
			},
			assert: challengedWith(challengeNoToken),
		},
		{
			name: "the Authorization header given twice is malformed",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)

				return w.get(t, userInfoURL, bearerOf(at), func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+at) })
			},
			assert: challengedWith(challengeMalformed),
		},
		{
			name: "two ways of sending the token are malformed",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)

				return w.post(t, userInfoURL, url.Values{"access_token": {at}}, bearerOf(at))
			},
			assert: challengedWith(challengeMalformed),
		},
		{
			name: "a form parameter given twice is malformed",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)

				return w.post(t, userInfoURL, url.Values{"access_token": {at, at}})
			},
			assert: challengedWith(challengeMalformed),
		},
		{
			name: "a form that does not parse is malformed",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, userInfoURL, strings.NewReader("access_token=%zz"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.RemoteAddr = tokenAddr

				return w.serve(t, r)
			},
			assert: challengedWith(challengeMalformed),
		},
		{
			name: "a body over the default bound is refused",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, userInfoURL, url.Values{"padding": {strings.Repeat("p", int(httpsec.DefaultLoginBodyLimit))}},
					bearerOf(access(t, w, tokenWeb, nil)))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertTokenHeaders(t, a)
				assert.Equal(t, http.StatusRequestEntityTooLarge, a.status)
			},
		},
		{
			name: "a consumer's bound replaces the default",
			setup: opWorldSetup{tokenSetup: tokenSetup{endpoint: func(*testing.T) []httpsec.OIDCProviderOption {
				return []httpsec.OIDCProviderOption{httpsec.WithOIDCUserInfoBodyLimit(4)}
			}}},
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, userInfoURL, url.Values{"other": {"longer-than-the-bound"}}, bearerOf(access(t, w, tokenWeb, nil)))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertTokenHeaders(t, a)
				assert.Equal(t, http.StatusRequestEntityTooLarge, a.status)
			},
		},

		// Method and transport.
		{
			name: "PUT is answered, not passed on",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.serve(t, httptest.NewRequestWithContext(t.Context(), http.MethodPut, userInfoURL, nil))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				wrongMethod(t, a, "GET, POST")
			},
		},
		{
			name: "a request not made over TLS is refused, its token unread",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(access(t, w, tokenWeb, nil)), overTLSLess)
			},
			assert: challengedWith(challengeMalformed),
		},
		{
			name: "the loopback issuer answers plain http",
			setup: opWorldSetup{
				issuer: "http://127.0.0.1:8080",
				provider: func(*testing.T) []oidcprovider.Option {
					return []oidcprovider.Option{oidcprovider.WithLoopbackHTTPIssuer()}
				},
			},
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(access(t, w, tokenWeb, nil)), overTLSLess)
			},
			assert: claimsAre(profileClaims),
		},

		// What it refuses as a token.
		{
			name: "an expired token",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)
				w.clk.Advance(6 * time.Minute)

				return w.get(t, userInfoURL, bearerOf(at))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "a value that is no token",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf("garbage"))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "an ID token",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(w.issuedToken(t, tokenWeb, "id_token")))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "a refresh token",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(w.issuedToken(t, tokenWeb, "refresh_token")))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "a token for another resource alone",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, func(params url.Values) { params.Set("resource", opAudience) })

				return w.get(t, userInfoURL, bearerOf(at))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "a JWT of a grant since revoked",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				doc := w.issued(t, tokenWeb, nil)
				at, _ := doc["access_token"].(string)
				rt, _ := doc["refresh_token"].(string)
				require.Equal(t, http.StatusOK, w.post(t, revokeURL, tokenForm(rt), asClient(tokenWeb)).status)

				return w.get(t, userInfoURL, bearerOf(at))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "an opaque token is served, until it is revoked",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, opOpaqueClient, nil)
				require.True(t, strings.HasPrefix(at, "at."))
				claimsAre(profileClaims)(t, w.get(t, userInfoURL, bearerOf(at)))
				require.Equal(t, http.StatusOK, w.post(t, revokeURL, tokenForm(at), asClient(opOpaqueClient)).status)

				return w.get(t, userInfoURL, bearerOf(at))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "a disabled user",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)
				w.disabled.Store(true)

				return w.get(t, userInfoURL, bearerOf(at))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "a user who no longer exists",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)
				w.gone.Store(true)

				return w.get(t, userInfoURL, bearerOf(at))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name: "no openid is insufficient_scope, at 403",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(access(t, w, tokenWeb, scoped("profile"))))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertChallenged(t, a, http.StatusForbidden, challengeScope)
			},
		},

		// What it releases.
		{
			name: "the profile scope alone holds back the email",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(access(t, w, tokenWeb, scoped("openid profile"))))
			},
			assert: claimsAre(profileClaims),
		},
		{
			name: "the email scope reads the username, unverified",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(access(t, w, tokenWeb, scoped("openid email"))))
			},
			assert: claimsAre(map[string]any{"sub": "u-1", "email": "ada@example.com", "email_verified": false}),
		},
		{
			name: "a consumer's source is returned unchanged, but for what no one may send",
			setup: withClaimSource(func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), identity.UserID("u-1"), []string{"openid", "org"}).Return(map[string]any{
					"department":     "research",
					"groups":         []string{},
					"email_verified": true,
					"nickname":       "",
					"middle_name":    nil,
					"sub":            "someone else",
				}, nil).Times(1)
			}),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(access(t, w, tokenWeb, scoped("openid org"))))
			},
			assert: claimsAre(map[string]any{
				"sub": "u-1", "department": "research", "groups": []any{}, "email_verified": true,
			}),
		},

		// Failures.
		{
			name: "a claim source that fails is 500 with no text",
			setup: withClaimSource(func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("claims secret text")).Times(1)
			}),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(access(t, w, tokenWeb, nil)))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertTokenFailed(t, a)
				assert.Empty(t, a.body)
				assert.Empty(t, a.header.Values("WWW-Authenticate"))
			},
		},
		{
			name: "a user store that fails is 500 with no text",
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)
				w.outage.Store(true)

				return w.get(t, userInfoURL, bearerOf(at))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertTokenFailed(t, a)
				assert.Empty(t, a.body)
				assert.Empty(t, a.header.Values("WWW-Authenticate"))
			},
		},
		{
			name: "a caller who has left is sent no claims and no challenge",
			setup: withClaimSource(func(m *MockClaimSource) {
				m.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ identity.UserID, _ []string) (map[string]any, error) {
						return nil, ctx.Err()
					},
				).AnyTimes()
			}),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := access(t, w, tokenWeb, nil)

				return w.get(t, userInfoURL, bearerOf(at), func(r *http.Request) {
					ctx, cancel := context.WithCancel(r.Context())
					cancel()
					*r = *r.WithContext(ctx)
				})
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertTokenHeaders(t, a)
				assert.NotEqual(t, http.StatusOK, a.status)
				assert.Empty(t, a.body)
				assert.Empty(t, a.header.Values("WWW-Authenticate"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPWorld(t, tc.setup)
			tc.assert(t, tc.send(t, w))
		})
	}
}

// TestOIDCUserInfo_SenderConstrained pins how UserInfo holds a bound token to its key, and the DPoP
// challenges of RFC 9449 section 7.1.
func TestOIDCUserInfo_SenderConstrained(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  opWorldSetup
		send   func(t *testing.T, w *opWorld) tokenAnswer
		assert func(t *testing.T, a tokenAnswer)
	}

	plain := dpopSetup(plainDPoP)
	k1 := newDPoPKey(t, elliptic.P256())
	k2 := newDPoPKey(t, elliptic.P256())
	cert := newClientCert(t, "client-c")
	other := newClientCert(t, "client-other")

	// presentedWith is a row presenting a token bound to k1 under the DPoP scheme, with the proof
	// signed by k and claims set over a valid one's.
	presentedWith := func(k dpopKey, claims map[string]any) func(*testing.T, *opWorld) tokenAnswer {
		return func(t *testing.T, w *opWorld) tokenAnswer {
			t.Helper()

			at := w.bound(t, k1, nil)

			return w.get(t, userInfoURL, dpopOf(at, w.userInfoProof(t, k, "j2", http.MethodGet, at, claims)))
		}
	}

	certBound := func(t *testing.T, w *opWorld) string {
		t.Helper()

		at, _ := w.issued(t, tokenWeb, nil, withCertificate(cert.cert))["access_token"].(string)
		require.NotEmpty(t, at)

		return at
	}
	certSetup := opWorldSetup{tokenSetup: tokenSetup{cert: true}}

	cases := []testCase{
		{
			name:   "a bound token with a valid proof",
			setup:  plain,
			send:   presentedWith(k1, nil),
			assert: claimsAre(profileClaims),
		},
		{
			name:  "a bound token with a valid proof, by POST",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.bound(t, k1, nil)

				return w.post(t, userInfoURL, url.Values{}, dpopOf(at, w.userInfoProof(t, k1, "j2", http.MethodPost, at, nil)))
			},
			assert: claimsAre(profileClaims),
		},
		{
			name:  "a bound token presented as Bearer",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(w.bound(t, k1, nil)))
			},
			assert: challengedWith(challengeDPoPToken),
		},
		{
			name:  "a bound token presented as Bearer, beside a valid proof",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.bound(t, k1, nil)
				proof := w.userInfoProof(t, k1, "j2", http.MethodGet, at, nil)

				return w.get(t, userInfoURL, bearerOf(at), func(r *http.Request) { r.Header.Set("DPoP", proof) })
			},
			assert: challengedWith(challengeDPoPToken),
		},
		{
			name:  "a bound token in a form body",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.post(t, userInfoURL, url.Values{"access_token": {w.bound(t, k1, nil)}})
			},
			assert: challengedWith(challengeDPoPToken),
		},
		{
			name:   "a proof from another key fails the binding",
			setup:  plain,
			send:   presentedWith(k2, nil),
			assert: challengedWith(challengeDPoPToken),
		},
		{
			name:  "an unbound token under the DPoP scheme fails the binding",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.issuedToken(t, tokenWeb, "access_token")

				return w.get(t, userInfoURL, dpopOf(at, w.userInfoProof(t, k1, "j2", http.MethodGet, at, nil)))
			},
			assert: challengedWith(challengeDPoPToken),
		},
		{
			name:  "an unbound token as Bearer is served while DPoP is not required",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(w.issuedToken(t, tokenWeb, "access_token")))
			},
			assert: claimsAre(profileClaims),
		},
		{
			name:  "a bound token with no proof",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.bound(t, k1, nil)

				return w.get(t, userInfoURL, func(r *http.Request) { r.Header.Set("Authorization", "DPoP "+at) })
			},
			assert: challengedWith(challengeDPoPProof),
		},
		{
			name:   "a proof with no ath",
			setup:  plain,
			send:   presentedWith(k1, map[string]any{"ath": nil}),
			assert: challengedWith(challengeDPoPProof),
		},
		{
			name:   "a proof for another method",
			setup:  plain,
			send:   presentedWith(k1, map[string]any{"htm": http.MethodPost}),
			assert: challengedWith(challengeDPoPProof),
		},
		{
			name:   "a proof for another URL",
			setup:  plain,
			send:   presentedWith(k1, map[string]any{"htu": opIssuer + "/elsewhere"}),
			assert: challengedWith(challengeDPoPProof),
		},
		{
			name:  "a replayed proof reads no claims",
			setup: dpopSetupWithSource(1),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.bound(t, k1, nil)
				proof := w.userInfoProof(t, k1, "j2", http.MethodGet, at, nil)
				assertAnswered(t, w.get(t, userInfoURL, dpopOf(at, proof)))

				return w.get(t, userInfoURL, dpopOf(at, proof))
			},
			assert: challengedWith(challengeDPoPProof),
		},
		{
			name:  "a bad token under the DPoP scheme",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, dpopOf("garbage", w.userInfoProof(t, k1, "j2", http.MethodGet, "garbage", nil)))
			},
			assert: challengedWith(challengeDPoPToken),
		},
		{
			name:  "an expired bound token",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.bound(t, k1, nil)
				w.clk.Advance(6 * time.Minute)

				return w.get(t, userInfoURL, dpopOf(at, w.userInfoProof(t, k1, "j2", http.MethodGet, at, nil)))
			},
			assert: challengedWith(challengeDPoPToken),
		},
		{
			name:  "a bound token without openid",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.bound(t, k1, scoped("profile"))

				return w.get(t, userInfoURL, dpopOf(at, w.userInfoProof(t, k1, "j2", http.MethodGet, at, nil)))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertChallenged(t, a, http.StatusForbidden, challengeDPoPNoScope)
			},
		},
		{
			name:  "no token names both schemes while DPoP is not required",
			setup: plain,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL)
			},
			assert: challengedWith(challengeDPoP, challengeNoToken),
		},
		{
			name:  "no token names DPoP alone once it is required",
			setup: dpopSetup(requiredDPoP),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL)
			},
			assert: challengedWith(challengeDPoP),
		},
		{
			name:  "a bad token as Bearer is answered under DPoP once it is required",
			setup: dpopSetup(requiredDPoP),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf("garbage"))
			},
			assert: challengedWith(challengeDPoPToken),
		},

		// Server nonces.
		{
			name:  "a proof owing a nonce is told so in the resource server's form",
			setup: dpopSetup(noncedDPoP),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				// Bearer needs no nonce to issue, so the token here is unbound and the refusal is the proof's.
				at := w.issuedToken(t, tokenWeb, "access_token")

				return w.get(t, userInfoURL, dpopOf(at, w.userInfoProof(t, k1, "j2", http.MethodGet, at, nil)))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertChallenged(t, a, http.StatusUnauthorized, challengeDPoPNonce)
				assert.NotEmpty(t, a.header.Get("DPoP-Nonce"))
			},
		},
		{
			name:  "the nonce handed out is taken, and a bound token is served",
			setup: dpopSetup(noncedDPoP),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				// The token endpoint hands out the nonce the bound token is issued with.
				code := w.issue(t, tokenWeb, nil)
				first := w.send(t, exchangeOf(code), asClient(tokenWeb), w.withProof(t, k1, "j1", nil))
				require.Equal(t, http.StatusBadRequest, first.status, first.body)
				nonce := first.header.Get("DPoP-Nonce")
				require.NotEmpty(t, nonce)

				a := w.send(t, exchangeOf(code), asClient(tokenWeb), w.withProof(t, k1, "j2", map[string]any{"nonce": nonce}))
				require.Equal(t, http.StatusOK, a.status, a.body)
				at, _ := a.document(t)["access_token"].(string)

				refused := w.get(t, userInfoURL, dpopOf(at, w.userInfoProof(t, k1, "j3", http.MethodGet, at, nil)))
				assertChallenged(t, refused, http.StatusUnauthorized, challengeDPoPNonce)

				return w.get(t, userInfoURL, dpopOf(at, w.userInfoProof(t, k1, "j4", http.MethodGet, at,
					map[string]any{"nonce": refused.header.Get("DPoP-Nonce")})))
			},
			assert: claimsAre(profileClaims),
		},
		{
			name:  "a nonce that cannot be sealed is a failure, with no challenge",
			setup: dpopSetup(sealFailingDPoP),
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := w.issuedToken(t, tokenWeb, "access_token")

				return w.get(t, userInfoURL, dpopOf(at, w.userInfoProof(t, k1, "j2", http.MethodGet, at, nil)))
			},
			assert: func(t *testing.T, a tokenAnswer) {
				t.Helper()
				assertTokenFailed(t, a)
				assert.Empty(t, a.body)
				assert.Empty(t, a.header.Values("WWW-Authenticate"))
			},
		},

		// Certificate binding.
		{
			name:  "a certificate-bound token over its certificate",
			setup: certSetup,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(certBound(t, w)), withCertificate(cert.cert))
			},
			assert: claimsAre(profileClaims),
		},
		{
			name:  "a certificate-bound token over another certificate",
			setup: certSetup,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(certBound(t, w)), withCertificate(other.cert))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name:  "a certificate-bound token over no certificate",
			setup: certSetup,
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				return w.get(t, userInfoURL, bearerOf(certBound(t, w)))
			},
			assert: challengedWith(challengeInvalidToken),
		},
		{
			name:  "a certificate-bound token under the DPoP scheme is refused for that alone",
			setup: opWorldSetup{tokenSetup: tokenSetup{cert: true, dpop: plainDPoP}},
			send: func(t *testing.T, w *opWorld) tokenAnswer {
				t.Helper()

				at := certBound(t, w)

				return w.get(t, userInfoURL, withCertificate(cert.cert),
					dpopOf(at, w.userInfoProof(t, k1, "j2", http.MethodGet, at, nil)))
			},
			assert: challengedWith(challengeDPoPToken),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newOPWorld(t, tc.setup)
			tc.assert(t, tc.send(t, w))
		})
	}
}

// dpopSetupWithSource is plain DPoP over a claim source that may be read at most times.
func dpopSetupWithSource(times int) opWorldSetup {
	setup := withClaimSource(func(m *MockClaimSource) {
		m.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).Return(map[string]any{"name": "Ada"}, nil).Times(times)
	})
	setup.dpop = plainDPoP

	return setup
}

// TestOIDCUserInfo_Options pins what the endpoint's options refuse at construction.
func TestOIDCUserInfo_Options(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		limit  int64
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.ErrorContains(t, err, "WithOIDCUserInfoBodyLimit")
	}

	cases := []testCase{
		{name: "a bound of zero", limit: 0, assert: refused},
		{name: "a negative bound", limit: -1, assert: refused},
		{
			name:  "a positive bound",
			limit: 1,
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}

	f := &opFixture{keys: tokenKeys()}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := f.provider(t)
			_, err := httpsec.New(append(f.wired(t, p), httpsec.EnableOIDCProvider(p, httpsec.WithOIDCUserInfoBodyLimit(tc.limit)))...)
			tc.assert(t, err)
		})
	}
}

// TestOIDCUserInfo_BindingNoLongerVerifiable pins a token bound while its chain could verify the
// binding, presented once it cannot: it is refused, never taken for a plain bearer token. Two
// providers share the grants, as one deployment does across a change of configuration.
func TestOIDCUserInfo_BindingNoLongerVerifiable(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		before tokenSetup
		bind   func(t *testing.T, w *opWorld) tokenChange
		assert func(t *testing.T, a tokenAnswer)
	}

	cert := newClientCert(t, "client-c")

	cases := []testCase{
		{
			name:   "bound to a DPoP key, with DPoP since turned off",
			before: tokenSetup{dpop: plainDPoP},
			bind: func(t *testing.T, w *opWorld) tokenChange {
				t.Helper()

				return w.withProof(t, newDPoPKey(t, elliptic.P256()), "j1", nil)
			},
			assert: challengedWith(`DPoP error="invalid_token"`),
		},
		{
			name:   "bound to a certificate, with certificate binding since turned off",
			before: tokenSetup{cert: true},
			bind: func(*testing.T, *opWorld) tokenChange {
				return withCertificate(cert.cert)
			},
			assert: challengedWith(challengeInvalidToken),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			grants, err := oidcprovider.NewMemoryGrantStore()
			require.NoError(t, err)

			codes, err := oidcprovider.NewMemoryCodeStore()
			require.NoError(t, err)

			shared := func(*testing.T) []oidcprovider.Option {
				return []oidcprovider.Option{oidcprovider.WithGrantStore(grants), oidcprovider.WithCodeStore(codes)}
			}

			before := newOPWorld(t, opWorldSetup{tokenSetup: tc.before, provider: shared})
			after := newOPWorld(t, opWorldSetup{provider: shared})

			at, _ := before.issued(t, tokenWeb, nil, tc.bind(t, before))["access_token"].(string)
			require.NotEmpty(t, at)

			tc.assert(t, after.get(t, userInfoURL, bearerOf(at)))
		})
	}
}
