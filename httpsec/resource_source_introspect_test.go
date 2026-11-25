package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// isEndpoint is a TLS introspection endpoint whose answer a case sets, counting what it receives.
type isEndpoint struct {
	srv *httptest.Server

	mu     sync.Mutex
	answer func(iss string) map[string]any
	status int

	hits     atomic.Int32
	received atomic.Pointer[string]
}

func newISEndpoint(t *testing.T) *isEndpoint {
	t.Helper()

	e := &isEndpoint{status: http.StatusOK}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)

		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		tok := form.Get("token")
		e.received.Store(&tok)

		e.mu.Lock()
		status, answer := e.status, e.answer
		e.mu.Unlock()

		if status != http.StatusOK {
			rw.WriteHeader(status)

			return
		}

		writeJSON(rw, answer(e.srv.URL))
	}))
	t.Cleanup(e.srv.Close)

	return e
}

// set has the endpoint answer change applied to an active access token for the API with subject 42.
func (e *isEndpoint) set(change func(a map[string]any)) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.answer = func(iss string) map[string]any {
		a := map[string]any{
			"active": true, "iss": iss, "sub": "42", "aud": riAPI, "client_id": "web-app",
			"exp": time.Now().Add(time.Hour).Unix(), "token_type": "access_token", "scope": "orders:read",
			"amr": []string{"pwd"},
		}
		if change != nil {
			change(a)
		}

		return a
	}
}

// isWorld is a chain whose resource server trusts one introspection endpoint.
type isWorld struct {
	ep      *isEndpoint
	chain   *httpsec.Chain
	failure atomic.Pointer[error]
	clk     *clockwork.FakeClock
}

// isSetup is what a case asks of its world.
type isSetup struct {
	// opts are the source's options beside its secret and outbound client.
	opts func(w *isWorld) []httpsec.SourceOption

	// rs are further resource-server options; chain further chain options.
	rs    []httpsec.ResourceServerOption
	chain []httpsec.Option

	// bound leaves WithUnboundTokens out.
	bound bool
}

func newISWorld(t *testing.T, setup isSetup) *isWorld {
	t.Helper()

	w := &isWorld{ep: newISEndpoint(t), clk: clockwork.NewFakeClockAt(time.Now())}
	w.ep.set(nil)

	transport, ok := w.ep.srv.Client().Transport.(*http.Transport)
	require.True(t, ok)

	oc, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: transport}))
	require.NoError(t, err)

	opts := []httpsec.SourceOption{httpsec.WithIntrospectionSecret("rs-secret"), httpsec.WithOutboundClient(oc)}
	if !setup.bound {
		opts = append(opts, httpsec.WithUnboundTokens())
	}

	if setup.opts != nil {
		opts = append(opts, setup.opts(w)...)
	}

	rsOpts := append([]httpsec.ResourceServerOption{httpsec.WithPathPrefix("/api/"),
		httpsec.FromIntrospection(w.ep.srv.URL, w.ep.srv.URL+"/introspect", "orders-api", opts...)}, setup.rs...)

	chainOpts := append([]httpsec.Option{
		httpsec.WithClock(w.clk),
		httpsec.WithErrorHandler(func(rw http.ResponseWriter, _ *http.Request, err error) {
			w.failure.Store(&err)
			rw.WriteHeader(httpsec.StatusForError(err))
		}),
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://api.example.com"}),
	}, setup.chain...)
	chainOpts = append(chainOpts, httpsec.EnableResourceServer(riAPI, rsOpts...))

	w.chain, err = httpsec.New(chainOpts...)
	require.NoError(t, err)

	return w
}

// call calls the API with tok under Bearer, or under DPoP with a proof from k when k is not nil.
func (w *isWorld) call(t *testing.T, tok string, k *dpopKey) riCall {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, riAPIURL, nil)

	if k == nil {
		r.Header.Set("Authorization", "Bearer "+tok)
	} else {
		r.Header.Set("Authorization", "DPoP "+tok)
		r.Header.Set("DPoP", k.validProof("p-"+tok).with(map[string]any{
			"htu": riAPIURL, "iat": w.clk.Now().Unix(), "ath": tokenHash(tok),
		}).sign(t))
	}

	var out riCall

	h := w.chain.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		out.ran = true
		out.caller, _ = identity.PrincipalFromContext(r.Context())
		out.token, _ = httpsec.AccessTokenFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	if f := w.failure.Swap(nil); f != nil {
		out.failure = *f
	}

	return out
}

// isUsers is a user store holding active users "42" and "u-7"; one not expected to be asked fails
// the case when it is.
func isUsers(t *testing.T, asked bool) identity.UserLoader {
	t.Helper()

	m := NewMockUserLoader(gomock.NewController(t))
	if asked {
		m.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, id identity.UserID) (*identity.Details, error) {
				return &identity.Details{ID: id, Active: true, Username: string(id) + "@example.com",
					Roles: []*identity.AssignedRole{{ID: "operator", Name: "operator", Primary: true}}}, nil
			}).AnyTimes()
	}

	return m
}

// isLinks is a link store linking subject 42 of issuer iss, under provider "corp", to user u-7 when
// linked.
func isLinks(t *testing.T, iss string, linked bool) oidc.LinkStore {
	t.Helper()

	links := oidc.NewMemoryLinkStore()
	if linked {
		require.NoError(t, links.Insert(t.Context(), oidc.Link{
			ID: must.Must(id.NewV7Generator().NewID()), Provider: "corp", Issuer: iss, Subject: "42", UserID: "u-7",
		}))
	}

	return links
}

// TestResourceServer_FromIntrospection pins the introspection source: acceptance, binding, the
// provider's own and other credentials, caller strategies, and the refusal throttle.
func TestResourceServer_FromIntrospection(t *testing.T) {
	t.Parallel()

	dk := newDPoPKey(t, elliptic.P256())
	other := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name   string
		setup  func(t *testing.T) isSetup
		act    func(t *testing.T, w *isWorld) riCall
		assert func(t *testing.T, w *isWorld, out riCall)
	}

	plain := func(_ *testing.T) isSetup { return isSetup{} }
	send := func(tok string, k *dpopKey) func(t *testing.T, w *isWorld) riCall {
		return func(t *testing.T, w *isWorld) riCall { return w.call(t, tok, k) }
	}
	answering := func(change func(a map[string]any)) func(t *testing.T, w *isWorld) riCall {
		return func(t *testing.T, w *isWorld) riCall {
			w.ep.set(change)

			return w.call(t, "opaque-1", nil)
		}
	}

	accepted := func(t *testing.T, w *isWorld, out riCall) {
		t.Helper()
		require.Equal(t, http.StatusOK, out.status, out.body)
		require.NotNil(t, out.caller)
		assert.Equal(t, identity.UserID(w.ep.srv.URL+"#42"), out.caller.ID)
		assert.Equal(t, []string{"orders:read"}, out.caller.Scopes)
	}
	refused := func(t *testing.T, _ *isWorld, out riCall) {
		t.Helper()
		assert.Equal(t, http.StatusUnauthorized, out.status)
		assert.False(t, out.ran)
		require.Error(t, out.failure)
	}
	invalidToken := func(t *testing.T, w *isWorld, out riCall) {
		t.Helper()
		refused(t, w, out)
		require.ErrorIs(t, out.failure, httpsec.ErrInvalidToken)
	}
	nothingSent := func(t *testing.T, w *isWorld) {
		t.Helper()
		assert.Zero(t, w.ep.hits.Load(), "the token reached the introspection endpoint")
	}
	bound := func(_ *testing.T) isSetup { return isSetup{bound: true} }
	boundTo := func(k dpopKey) func(a map[string]any) {
		return func(a map[string]any) { a["cnf"] = map[string]any{"jkt": k.jkt} }
	}
	limitedTo := func(n int) func(t *testing.T) isSetup {
		return func(_ *testing.T) isSetup {
			return isSetup{rs: []httpsec.ResourceServerOption{
				httpsec.WithRefusalLimiter(must.Must(ratelimit.NewMemoryLimiter(n, time.Hour))),
			}}
		}
	}

	cases := []testCase{
		{name: "an active access token is accepted as a claims-only caller", setup: plain, act: answering(nil), assert: accepted},
		{
			name:  "the token is sent to the endpoint whole",
			setup: plain, act: answering(nil),
			assert: func(t *testing.T, w *isWorld, out riCall) {
				accepted(t, w, out)
				require.NotNil(t, w.ep.received.Load())
				assert.Equal(t, "opaque-1", *w.ep.received.Load())
			},
		},
		{name: "an inactive token is refused", setup: plain, act: answering(func(a map[string]any) { a["active"] = false }), assert: invalidToken},
		{name: "a refresh token reported active is refused", setup: plain, act: answering(func(a map[string]any) { a["token_type"] = "refresh_token" }), assert: invalidToken},
		{name: "an answer naming another issuer is refused", setup: plain, act: answering(func(a map[string]any) { a["iss"] = "https://other.example" }), assert: invalidToken},
		{name: "an answer with no audience is refused", setup: plain, act: answering(func(a map[string]any) { delete(a, "aud") }), assert: invalidToken},
		{name: "an answer with another API's audience is refused", setup: plain, act: answering(func(a map[string]any) { a["aud"] = "urn:other" }), assert: invalidToken},
		{
			name:  "an endpoint answering 503 is a dependency failure, not a refusal",
			setup: plain,
			act: func(t *testing.T, w *isWorld) riCall {
				w.ep.mu.Lock()
				w.ep.status = http.StatusServiceUnavailable
				w.ep.mu.Unlock()

				return w.call(t, "opaque-1", nil)
			},
			assert: func(t *testing.T, _ *isWorld, out riCall) {
				assert.Equal(t, http.StatusInternalServerError, out.status)
				require.Error(t, out.failure)
				assert.NotErrorIs(t, out.failure, httpsec.ErrInvalidToken)
			},
		},
		{
			name:  "the provider's own refresh token is refused and never sent",
			setup: plain, act: send("rt.abc.def", nil),
			assert: func(t *testing.T, w *isWorld, out riCall) { invalidToken(t, w, out); nothingSent(t, w) },
		},
		{
			name:  "the provider's own access token is refused and never sent",
			setup: plain, act: send("at.abc.def", nil),
			assert: func(t *testing.T, w *isWorld, out riCall) { invalidToken(t, w, out); nothingSent(t, w) },
		},
		{
			name:  "an unbound token is refused by default",
			setup: bound, act: answering(nil),
			assert: invalidToken,
		},
		{
			name:  "a bound token with the proof of its key is accepted",
			setup: bound,
			act: func(t *testing.T, w *isWorld) riCall {
				w.ep.set(boundTo(dk))

				return w.call(t, "opaque-1", &dk)
			},
			assert: accepted,
		},
		{
			name:  "a bound token with no proof is refused",
			setup: bound,
			act: func(t *testing.T, w *isWorld) riCall {
				w.ep.set(boundTo(dk))

				return w.call(t, "opaque-1", nil)
			},
			assert: func(t *testing.T, w *isWorld, out riCall) {
				refused(t, w, out)
				require.ErrorIs(t, out.failure, httpsec.ErrInvalidDPoPProof)
			},
		},
		{
			name:  "a bound token with a proof from another key is refused",
			setup: bound,
			act: func(t *testing.T, w *isWorld) riCall {
				w.ep.set(boundTo(dk))

				return w.call(t, "opaque-1", &other)
			},
			assert: func(t *testing.T, w *isWorld, out riCall) {
				refused(t, w, out)
				require.ErrorIs(t, out.failure, httpsec.ErrInvalidDPoPProof)
			},
		},
		{
			name:  "a confirmation naming only a method the chain cannot check is refused",
			setup: plain,
			act: answering(func(a map[string]any) {
				a["cnf"] = map[string]any{"jwk": map[string]any{"kty": "EC"}}
			}),
			assert: invalidToken,
		},
		{
			name: "with a prefix, an unprefixed opaque token is not claimed and nothing is sent",
			setup: func(_ *testing.T) isSetup {
				return isSetup{opts: func(*isWorld) []httpsec.SourceOption {
					return []httpsec.SourceOption{httpsec.WithOpaquePrefix("kc_")}
				}}
			},
			act: send("sess-ref-1", nil),
			assert: func(t *testing.T, w *isWorld, out riCall) {
				assert.True(t, out.ran, "an unclaimed token passes on")
				nothingSent(t, w)
			},
		},
		{
			name: "with a prefix, a session reference goes to the session bearer and nothing is sent",
			setup: func(t *testing.T) isSetup {
				sessions := must.Must(session.New())

				return isSetup{
					opts: func(*isWorld) []httpsec.SourceOption {
						return []httpsec.SourceOption{httpsec.WithOpaquePrefix("kc.")}
					},
					chain: []httpsec.Option{httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{
						Sessions: sessions, Users: isUsers(t, false),
					})},
				}
			},
			act: send("sess-ref-1", nil),
			assert: func(t *testing.T, w *isWorld, out riCall) {
				assert.Equal(t, http.StatusUnauthorized, out.status)
				assert.NotErrorIs(t, out.failure, httpsec.ErrInvalidToken, "judged by the session bearer")
				nothingSent(t, w)
			},
		},
		{
			name: "with a prefix, a prefixed token is introspected",
			setup: func(_ *testing.T) isSetup {
				return isSetup{opts: func(*isWorld) []httpsec.SourceOption {
					return []httpsec.SourceOption{httpsec.WithOpaquePrefix("kc_")}
				}}
			},
			act:    send("kc_token", nil),
			assert: accepted,
		},
		{
			name: "a linked subject is resolved to its linked local user with current roles",
			setup: func(t *testing.T) isSetup {
				return isSetup{opts: func(w *isWorld) []httpsec.SourceOption {
					return []httpsec.SourceOption{httpsec.WithLinkedUsers(isLinks(t, w.ep.srv.URL, true), "corp", isUsers(t, true))}
				}}
			},
			act: answering(nil),
			assert: func(t *testing.T, _ *isWorld, out riCall) {
				require.Equal(t, http.StatusOK, out.status, out.body)
				assert.Equal(t, identity.UserID("u-7"), out.caller.ID)
				assert.True(t, holdsRole(out.caller, "operator"))
				assert.Equal(t, []string{"orders:read"}, out.caller.Scopes)
			},
		},
		{
			// Local user 42 exists in the store; a store asked anything fails the case.
			name: "an unlinked subject equal to a local user is refused, and the local user is never loaded",
			setup: func(t *testing.T) isSetup {
				return isSetup{opts: func(w *isWorld) []httpsec.SourceOption {
					return []httpsec.SourceOption{httpsec.WithLinkedUsers(isLinks(t, w.ep.srv.URL, false), "corp", isUsers(t, false))}
				}}
			},
			act:    answering(nil),
			assert: invalidToken,
		},
		{
			name: "a mapper's principal is the caller, carrying the token's scopes only",
			setup: func(_ *testing.T) isSetup {
				return isSetup{opts: func(*isWorld) []httpsec.SourceOption {
					return []httpsec.SourceOption{httpsec.WithClaimsMapper("corp",
						func(_ context.Context, claims map[string]any) (httpsec.MappedCaller, error) {
							return httpsec.MappedCaller{Principal: &identity.Principal{
								ID: "svc-" + identity.UserID(claims["sub"].(string)), Kind: identity.KindService,
								Scopes: []string{"admin:all"},
							}, External: true}, nil
						})}
				}}
			},
			act: answering(nil),
			assert: func(t *testing.T, _ *isWorld, out riCall) {
				require.Equal(t, http.StatusOK, out.status, out.body)
				assert.Equal(t, identity.UserID("svc-42"), out.caller.ID)
				assert.Equal(t, []string{"orders:read"}, out.caller.Scopes)
			},
		},
		{
			name: "a mapper returning no principal refuses the token",
			setup: func(_ *testing.T) isSetup {
				return isSetup{opts: func(*isWorld) []httpsec.SourceOption {
					return []httpsec.SourceOption{httpsec.WithClaimsMapper("corp",
						func(context.Context, map[string]any) (httpsec.MappedCaller, error) {
							return httpsec.MappedCaller{}, nil
						})}
				}}
			},
			act:    answering(nil),
			assert: invalidToken,
		},
		{
			name: "a mapper that fails is a dependency failure with fixed text",
			setup: func(_ *testing.T) isSetup {
				return isSetup{opts: func(*isWorld) []httpsec.SourceOption {
					return []httpsec.SourceOption{httpsec.WithClaimsMapper("corp",
						func(context.Context, map[string]any) (httpsec.MappedCaller, error) {
							return httpsec.MappedCaller{}, errors.New("mapper secret text")
						})}
				}}
			},
			act: answering(nil),
			assert: func(t *testing.T, _ *isWorld, out riCall) {
				assert.Equal(t, http.StatusInternalServerError, out.status)
				require.Error(t, out.failure)
				assert.NotContains(t, out.failure.Error(), "mapper secret text")
			},
		},
		{
			name:  "past the refusal limit no further introspection call is made",
			setup: limitedTo(2),
			act: func(t *testing.T, w *isWorld) riCall {
				w.ep.set(func(a map[string]any) { a["active"] = false })

				for range 2 {
					require.Equal(t, http.StatusUnauthorized, w.call(t, "bogus", nil).status)
				}

				return w.call(t, "bogus", nil)
			},
			assert: func(t *testing.T, w *isWorld, out riCall) {
				invalidToken(t, w, out)
				assert.Equal(t, int32(2), w.ep.hits.Load(), "the throttled request reached the endpoint")
			},
		},
		{
			name: "binding refusals are not counted",
			setup: func(t *testing.T) isSetup {
				s := limitedTo(1)(t)
				s.bound = true

				return s
			},
			act: func(t *testing.T, w *isWorld) riCall {
				w.ep.set(boundTo(dk))

				for range 3 {
					require.Equal(t, http.StatusUnauthorized, w.call(t, "opaque-1", nil).status)
				}

				return w.call(t, "opaque-1", &dk)
			},
			assert: accepted,
		},
		{
			name: "a failing refusal limiter is a dependency failure and nothing is sent",
			setup: func(_ *testing.T) isSetup {
				return isSetup{rs: []httpsec.ResourceServerOption{httpsec.WithRefusalLimiter(failingLimiter{})}}
			},
			act: answering(nil),
			assert: func(t *testing.T, w *isWorld, out riCall) {
				assert.Equal(t, http.StatusInternalServerError, out.status)
				assert.NotErrorIs(t, out.failure, httpsec.ErrInvalidToken)
				nothingSent(t, w)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newISWorld(t, tc.setup(t))
			tc.assert(t, w, tc.act(t, w))
		})
	}
}

// failingLimiter is a refusal limiter that cannot answer.
type failingLimiter struct{}

func (failingLimiter) Exceeded(context.Context, string) (bool, error) {
	return true, errors.New("limiter store down")
}
func (failingLimiter) RecordFailure(context.Context, string) error {
	return errors.New("limiter store down")
}
func (failingLimiter) Charge(context.Context, string) (ratelimit.Receipt, bool, error) {
	return ratelimit.Receipt{}, true, errors.New("limiter store down")
}
func (failingLimiter) Refund(context.Context, ratelimit.Receipt) error {
	return errors.New("limiter store down")
}

// TestResourceServer_ExternalCallerAssurance pins how an external token's local caller meets the MFA
// requirement, and that a caller naming no local user is not judged.
func TestResourceServer_ExternalCallerAssurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		strategy func(t *testing.T, w *isWorld) httpsec.SourceOption
		mfa      []policy.MFARequirementOption
		amr      []string
		assert   func(t *testing.T, out riCall)
	}

	linked := func(t *testing.T, w *isWorld) httpsec.SourceOption {
		return httpsec.WithLinkedUsers(isLinks(t, w.ep.srv.URL, true), "corp", isUsers(t, true))
	}
	mapperLocal := func(_ *testing.T, _ *isWorld) httpsec.SourceOption {
		return httpsec.WithClaimsMapper("corp", func(context.Context, map[string]any) (httpsec.MappedCaller, error) {
			return httpsec.MappedCaller{Principal: &identity.Principal{ID: "u-7", Kind: identity.KindUser}}, nil
		})
	}

	allowed := func(t *testing.T, out riCall) {
		t.Helper()
		require.Equal(t, http.StatusOK, out.status, out.body)
	}
	insufficient := func(t *testing.T, out riCall) {
		t.Helper()
		assert.Equal(t, http.StatusUnauthorized, out.status)
		assert.Equal(t, []string{`Bearer error="insufficient_user_authentication"`}, out.header.Values("WWW-Authenticate"))
		require.ErrorIs(t, out.failure, httpsec.ErrInsufficientUserAuthentication)
	}
	source := []policy.MFARequirementOption{policy.WithFederatedAssuranceSource(asSource{})}

	cases := []testCase{
		{name: "a claims-only caller is not judged", amr: []string{"pwd"}, assert: allowed},
		{name: "a linked user with a password-only token is refused in challenge mode", strategy: linked, mfa: source, amr: []string{"pwd"}, assert: insufficient},
		{name: "a linked user with a token asserting mfa is allowed", strategy: linked, mfa: source, amr: []string{"mfa"}, assert: allowed},
		{name: "a mapper leaving External unset is judged as a local user", strategy: mapperLocal, mfa: source, amr: []string{"pwd"}, assert: insufficient},
		{
			name: "a linked user is allowed in exempt mode", strategy: linked, amr: []string{"pwd"},
			mfa:    []policy.MFARequirementOption{policy.WithMFARequirementFederatedAssurance(policy.FederatedAssuranceExempt)},
			assert: allowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newISWorld(t, isSetup{
				opts: func(w *isWorld) []httpsec.SourceOption {
					if tc.strategy == nil {
						return nil
					}

					return []httpsec.SourceOption{tc.strategy(t, w)}
				},
				chain: []httpsec.Option{requireMFAForAll(t, tc.mfa...)},
			})
			w.ep.set(func(a map[string]any) { a["amr"] = tc.amr })

			tc.assert(t, w.call(t, "opaque-1", nil))
		})
	}
}

// TestResourceServer_SourceWiring pins the construction errors of the introspection source, the caller
// strategies and the refusal limiter.
func TestResourceServer_SourceWiring(t *testing.T) {
	t.Parallel()

	const iss = "https://sso.example"

	users := func(t *testing.T) identity.UserLoader { return isUsers(t, false) }
	mapper := func(context.Context, map[string]any) (httpsec.MappedCaller, error) {
		return httpsec.MappedCaller{}, nil
	}
	dpop := httpsec.EnableDPoP(httpsec.DPoP{PublicURL: "https://api.example.com"})

	type testCase struct {
		name   string
		build  func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, err error)
	}

	introspection := func(opts ...httpsec.SourceOption) func(t *testing.T) []httpsec.Option {
		return func(_ *testing.T) []httpsec.Option {
			return []httpsec.Option{dpop, httpsec.EnableResourceServer(riAPI, httpsec.FromIntrospection(iss,
				iss+"/introspect", "orders-api", append([]httpsec.SourceOption{httpsec.WithIntrospectionSecret("s")}, opts...)...))}
		}
	}
	built := func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) }
	refused := func(want ...string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)

			for _, w := range want {
				assert.Contains(t, err.Error(), w)
			}
		}
	}
	sessionBearer := func(t *testing.T) httpsec.Option {
		return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: must.Must(session.New()), Users: users(t)})
	}

	cases := []testCase{
		{name: "a valid introspection source", build: introspection(), assert: built},
		{
			name: "a plain-http endpoint",
			build: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{dpop, httpsec.EnableResourceServer(riAPI, httpsec.FromIntrospection(iss,
					"http://idp.example/introspect", "orders-api", httpsec.WithIntrospectionSecret("s")))}
			},
			assert: refused("FromIntrospection"),
		},
		{
			name: "no client authentication",
			build: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{dpop, httpsec.EnableResourceServer(riAPI, httpsec.FromIntrospection(iss,
					iss+"/introspect", "orders-api"))}
			},
			assert: refused("WithIntrospectionSecret", "WithIntrospectionKey"),
		},
		{name: "an issuer with a fragment", build: func(_ *testing.T) []httpsec.Option {
			return []httpsec.Option{dpop, httpsec.EnableResourceServer(riAPI, httpsec.FromIntrospection("https://sso.example#x",
				iss+"/introspect", "orders-api", httpsec.WithIntrospectionSecret("s")))}
		}, assert: refused("https://sso.example#x")},
		{name: "a cache with no entries", build: introspection(httpsec.WithIntrospectionCache(time.Minute, 0)), assert: refused("WithIntrospectionCache")},
		{name: "a cache with no age", build: introspection(httpsec.WithIntrospectionCache(0, 10)), assert: refused("WithIntrospectionCache")},
		{name: "an empty prefix", build: introspection(httpsec.WithOpaquePrefix("")), assert: refused("WithOpaquePrefix")},
		{name: "a key-set option it does not take", build: introspection(httpsec.WithJWKSURL("https://sso.example/keys")), assert: refused("WithJWKSURL")},
		{
			name: "no prefix beside session-reference bearers",
			build: func(t *testing.T) []httpsec.Option {
				return append(introspection()(t), sessionBearer(t))
			},
			assert: refused("WithOpaquePrefix", "EnableSessionBearer"),
		},
		{
			name: "no prefix beside API keys under the Bearer scheme",
			build: func(t *testing.T) []httpsec.Option {
				return append(introspection()(t), httpsec.EnableAPIKey(newAPIKeyHarness(t).keys, httpsec.WithAPIKeyScheme("Bearer ")))
			},
			assert: refused("WithOpaquePrefix", "EnableAPIKey"),
		},
		{
			name: "no prefix beside API keys under a padded, lower-case Bearer scheme",
			build: func(t *testing.T) []httpsec.Option {
				return append(introspection()(t), httpsec.EnableAPIKey(newAPIKeyHarness(t).keys, httpsec.WithAPIKeyScheme(" bearer ")))
			},
			assert: refused("WithOpaquePrefix", "EnableAPIKey"),
		},
		{
			name: "a prefix beside session-reference bearers",
			build: func(t *testing.T) []httpsec.Option {
				return append(introspection(httpsec.WithOpaquePrefix("kc."))(t), sessionBearer(t))
			},
			assert: built,
		},
		{
			name: "a prefix of session-reference characters beside session-reference bearers",
			build: func(t *testing.T) []httpsec.Option {
				return append(introspection(httpsec.WithOpaquePrefix("kc_"))(t), sessionBearer(t))
			},
			assert: refused("WithOpaquePrefix", "EnableSessionBearer", "session"),
		},
		{
			name: "a prefix of session-reference characters beside API keys under the Bearer scheme",
			build: func(t *testing.T) []httpsec.Option {
				return append(introspection(httpsec.WithOpaquePrefix("intro-"))(t),
					httpsec.EnableAPIKey(newAPIKeyHarness(t).keys, httpsec.WithAPIKeyScheme("Bearer")))
			},
			assert: refused("WithOpaquePrefix", "EnableAPIKey", "session"),
		},
		{
			name: "a prefix with a character outside the session-reference alphabet beside API keys",
			build: func(t *testing.T) []httpsec.Option {
				return append(introspection(httpsec.WithOpaquePrefix("intro:"))(t),
					httpsec.EnableAPIKey(newAPIKeyHarness(t).keys, httpsec.WithAPIKeyScheme("Bearer")))
			},
			assert: built,
		},
		{
			name:   "a prefix of session-reference characters on a chain with no other Bearer reader",
			build:  introspection(httpsec.WithOpaquePrefix("kc_")),
			assert: built,
		},
		{name: "two caller strategies", build: introspection(httpsec.WithClaimsOnly(), httpsec.WithClaimsMapper("corp", mapper)), assert: refused("WithClaimsOnly", "WithClaimsMapper")},
		{name: "a nil mapper", build: introspection(httpsec.WithClaimsMapper("corp", nil)), assert: refused("WithClaimsMapper")},
		{name: "a mapper with no provider", build: introspection(httpsec.WithClaimsMapper("", mapper)), assert: refused("WithClaimsMapper")},
		{
			name: "a nil link store",
			build: func(t *testing.T) []httpsec.Option {
				return introspection(httpsec.WithLinkedUsers(nil, "corp", users(t)))(t)
			},
			assert: refused("WithLinkedUsers"),
		},
		{
			name: "a nil linked-user loader",
			build: func(t *testing.T) []httpsec.Option {
				return introspection(httpsec.WithLinkedUsers(oidc.NewMemoryLinkStore(), "corp", nil))(t)
			},
			assert: refused("WithLinkedUsers"),
		},
		{
			name: "local users on an introspection source",
			build: func(t *testing.T) []httpsec.Option {
				return introspection(httpsec.WithLocalUsers(users(t)))(t)
			},
			assert: refused("WithLocalUsers", "WithLinkedUsers"),
		},
		{
			name: "local users on a remote issuer",
			build: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{dpop, httpsec.EnableResourceServer(riAPI, httpsec.FromIssuer(iss, httpsec.WithLocalUsers(users(t))))}
			},
			assert: refused("WithLocalUsers", "WithLinkedUsers"),
		},
		{
			name: "a nil refusal limiter",
			build: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{dpop, httpsec.EnableResourceServer(riAPI, httpsec.WithRefusalLimiter(nil),
					httpsec.FromIntrospection(iss, iss+"/introspect", "orders-api", httpsec.WithIntrospectionSecret("s")))}
			},
			assert: refused("WithRefusalLimiter"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(append([]httpsec.Option{httpsec.WithLogger(slog.New(&capturingHandler{}))}, tc.build(t)...)...)
			tc.assert(t, err)
		})
	}
}

// TestResourceServer_ProviderSourceWiring pins the provider source's caller-strategy construction
// errors.
func TestResourceServer_ProviderSourceWiring(t *testing.T) {
	t.Parallel()

	mapper := func(context.Context, map[string]any) (httpsec.MappedCaller, error) {
		return httpsec.MappedCaller{}, nil
	}

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.SourceOption
		assert func(t *testing.T, err error)
	}

	refused := func(want string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), want)
		}
	}

	cases := []testCase{
		{
			name: "a mapper on the provider source",
			opts: func(*testing.T) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithClaimsMapper("corp", mapper)}
			},
			assert: refused("WithClaimsMapper"),
		},
		{
			name: "linked users on the provider source",
			opts: func(t *testing.T) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithLinkedUsers(oidc.NewMemoryLinkStore(), "corp", isUsers(t, false))}
			},
			assert: refused("WithLinkedUsers"),
		},
		{
			name:   "a nil local-user loader",
			opts:   func(*testing.T) []httpsec.SourceOption { return []httpsec.SourceOption{httpsec.WithLocalUsers(nil)} },
			assert: refused("WithLocalUsers"),
		},
		{
			name: "a consumer's local-user loader",
			opts: func(t *testing.T) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithLocalUsers(isUsers(t, false))}
			},
			assert: func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var err error

			newPSWorld(t, psSetup{buildErr: &err, rs: func(p *oidcprovider.Provider) httpsec.Option {
				return httpsec.EnableResourceServer(psAPI, httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p, tc.opts(t)...))
			}})
			tc.assert(t, err)
		})
	}
}

// TestResourceServer_MapperPrincipalIsCopied pins that the caller published to handlers shares
// nothing with the principal the mapper returned: a mapper that keeps its principal and changes it
// after the request cannot change the caller that request was served as.
func TestResourceServer_MapperPrincipalIsCopied(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		mutate func(kept *identity.Principal)
		assert func(t *testing.T, caller *identity.Principal)
	}

	cases := []testCase{
		{
			name:   "a role's fields",
			mutate: func(kept *identity.Principal) { kept.Roles[0].Name = "changed" },
			assert: func(t *testing.T, caller *identity.Principal) { assert.Equal(t, "reader", caller.Roles[0].Name) },
		},
		{
			name:   "the role list",
			mutate: func(kept *identity.Principal) { kept.Roles[0] = &identity.AssignedRole{Name: "changed"} },
			assert: func(t *testing.T, caller *identity.Principal) { assert.Equal(t, "reader", caller.Roles[0].Name) },
		},
		{
			name:   "the active role",
			mutate: func(kept *identity.Principal) { kept.ActiveRole.Name = "changed" },
			assert: func(t *testing.T, caller *identity.Principal) {
				assert.Equal(t, "reader", caller.ActiveRole.Name)
				assert.Same(t, caller.Roles[0], caller.ActiveRole)
			},
		},
		{
			name: "the organization and its group",
			mutate: func(kept *identity.Principal) {
				kept.Organization.Name = "changed"
				kept.Organization.Group.Name = "changed"
			},
			assert: func(t *testing.T, caller *identity.Principal) {
				assert.Equal(t, "acme", caller.Organization.Name)
				assert.Equal(t, "corp", caller.Organization.Group.Name)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var kept *identity.Principal

			w := newISWorld(t, isSetup{opts: func(_ *isWorld) []httpsec.SourceOption {
				return []httpsec.SourceOption{httpsec.WithClaimsMapper("corp",
					func(context.Context, map[string]any) (httpsec.MappedCaller, error) {
						role := &identity.AssignedRole{ID: "r1", Name: "reader"}
						kept = &identity.Principal{
							ID: "u-7", Kind: identity.KindUser, Roles: []*identity.AssignedRole{role}, ActiveRole: role,
							Organization: &identity.Organization{ID: "o1", Name: "acme", Group: &identity.Group{ID: "g1", Name: "corp"}},
							Scopes:       []string{"orders:read"},
						}

						return httpsec.MappedCaller{Principal: kept, External: true}, nil
					})}
			}})

			out := w.call(t, "opaque-1", nil)
			require.Equal(t, http.StatusOK, out.status, out.body)
			require.NotNil(t, out.caller)
			require.NotNil(t, kept)

			tc.mutate(kept)
			tc.assert(t, out.caller)
		})
	}
}
