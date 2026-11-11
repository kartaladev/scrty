package ginsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/ginsec"
	"github.com/kartaladev/scrty/identity"
)

// countingAttempts counts what Basic authentication records and clears, and
// otherwise answers as an empty store.
type countingAttempts struct{ fails, resets atomic.Int32 }

func (c *countingAttempts) RecordFailure(context.Context, string, time.Time) error {
	c.fails.Add(1)
	return nil
}

func (c *countingAttempts) Reset(context.Context, string) error {
	c.resets.Add(1)
	return nil
}

func (*countingAttempts) FailureCount(context.Context, string, time.Time) (int, error) {
	return 0, nil
}

// countingAuthenticator counts its calls, and answers with err or, when err is
// nil, with one principal.
type countingAuthenticator struct {
	calls atomic.Int32
	err   error
}

func (a *countingAuthenticator) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	a.calls.Add(1)

	if a.err != nil {
		return nil, a.err
	}

	return &authenticate.Authentication{Principal: &identity.Principal{ID: "u-1", Username: "ada"}}, nil
}

// TestRepro_DoubleMount pins that one chain used by a gin engine and by one of
// its route groups runs once on a request to that group: the credentials are
// verified once and the attempt counters are touched once.
func TestRepro_DoubleMount(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		authErr error
		assert  func(t *testing.T, a *countingAuthenticator, at *countingAttempts, rec *httptest.ResponseRecorder)
	}

	cases := []testCase{
		{
			name:    "a refused Basic login is charged once",
			authErr: authenticate.ErrAuthenticationFailed,
			assert: func(t *testing.T, a *countingAuthenticator, at *countingAttempts, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.EqualValues(t, 1, a.calls.Load(), "authenticator calls")
				assert.EqualValues(t, 1, at.fails.Load(), "failures recorded")
			},
		},
		{
			name: "a successful Basic login authenticates once",
			assert: func(t *testing.T, a *countingAuthenticator, at *countingAttempts, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.EqualValues(t, 1, a.calls.Load(), "authenticator calls")
				assert.EqualValues(t, 1, at.resets.Load(), "resets")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := &countingAuthenticator{err: tc.authErr}
			at := &countingAttempts{}
			chain := newChain(t, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: a, Attempts: at}))

			eng := gin.New()
			eng.Use(ginsec.Middleware(chain))
			g := eng.Group("/api")
			g.Use(ginsec.Middleware(chain))
			g.GET("/x", func(gc *gin.Context) { gc.Status(http.StatusOK) })

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/x", nil)
			req.SetBasicAuth("ada", "pw")

			rec := httptest.NewRecorder()
			eng.ServeHTTP(rec, req)

			tc.assert(t, a, at, rec)
		})
	}
}

// passwordAuthenticator maps the Basic password to a principal: "pw-1" is u-1,
// "pw-2" is u-2, anything else is refused.
type passwordAuthenticator struct{ calls atomic.Int32 }

func (a *passwordAuthenticator) Authenticate(_ context.Context, creds identity.Credentials) (*authenticate.Authentication, error) {
	a.calls.Add(1)

	var password string

	switch up := creds.(type) {
	case *identity.UsernamePassword:
		password = string(up.Password)
	}

	switch password {
	case "pw-1":
		return &authenticate.Authentication{Principal: &identity.Principal{ID: "u-1", Username: "ada"}}, nil
	case "pw-2":
		return &authenticate.Authentication{Principal: &identity.Principal{ID: "u-2", Username: "bob"}}, nil
	default:
		return nil, authenticate.ErrAuthenticationFailed
	}
}

// ruleInterceptor is a consumer rule that reads one part of the request and
// refuses when it holds the value the rule forbids.
func ruleInterceptor(read func(r httpsec.Request) string, forbidden string, calls *atomic.Int32) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		calls.Add(1)

		if read(ex.Request) == forbidden {
			return authenticate.ErrAuthenticationFailed
		}

		return next(ex)
	})
}

type doubleOutcome struct {
	rec        *httptest.ResponseRecorder
	handlerRan bool
	// ctxPrincipal is the principal on c.Request.Context() in the handler.
	ctxPrincipal string
	chainCalls   int32
}

// TestGin_DoubleMountPassesRewritesThrough pins the accepted behaviour of a
// consumer middleware that rewrites the request between two mounts of one
// chain: the second mount recognises the request as already judged and passes
// it through, so a rewrite of the credential, Host or query is not re-judged.
// A rewrite of the path is the one that runs the chain again.
func TestGin_DoubleMountPassesRewritesThrough(t *testing.T) {
	t.Parallel()

	basicReq := func(t *testing.T, path, pw string) *http.Request {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		req.SetBasicAuth("ada", pw)

		return req
	}

	type testCase struct {
		name string
		// build returns the chain, the consumer middleware between the mounts,
		// the request, and a counter of how many times the chain's judging
		// code ran.
		build  func(t *testing.T) (*httpsec.Chain, gin.HandlerFunc, *http.Request, *atomic.Int32)
		assert func(t *testing.T, o doubleOutcome)
	}

	cases := []testCase{
		{
			name: "credential swap passes through: the handler sees the first principal, verified once",
			build: func(t *testing.T) (*httpsec.Chain, gin.HandlerFunc, *http.Request, *atomic.Int32) {
				a := &passwordAuthenticator{}
				chain := newChain(t, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: a, Attempts: &countingAttempts{}}))
				swap := func(gc *gin.Context) { gc.Request.SetBasicAuth("ada", "pw-2") }

				return chain, swap, basicReq(t, "/api/x", "pw-1"), &a.calls
			},
			assert: func(t *testing.T, o doubleOutcome) {
				// Accepted: the second mount passes the request through, so the
				// swapped credential is never judged.
				assert.True(t, o.handlerRan)
				assert.Equal(t, "u-1", o.ctxPrincipal, "the principal of the first credential")
				assert.EqualValues(t, 1, o.chainCalls, "authenticator calls")
			},
		},
		{
			name: "invalid credential swap passes through",
			build: func(t *testing.T) (*httpsec.Chain, gin.HandlerFunc, *http.Request, *atomic.Int32) {
				a := &passwordAuthenticator{}
				chain := newChain(t, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: a, Attempts: &countingAttempts{}}))
				swap := func(gc *gin.Context) { gc.Request.SetBasicAuth("ada", "garbage") }

				return chain, swap, basicReq(t, "/api/x", "pw-1"), &a.calls
			},
			assert: func(t *testing.T, o doubleOutcome) {
				assert.Equal(t, http.StatusOK, o.rec.Code)
				assert.True(t, o.handlerRan)
				assert.Equal(t, "u-1", o.ctxPrincipal)
			},
		},
		{
			name: "host swap passes through",
			build: func(t *testing.T) (*httpsec.Chain, gin.HandlerFunc, *http.Request, *atomic.Int32) {
				var calls atomic.Int32
				chain := newChain(t, httpsec.RegisterInterceptor(
					ruleInterceptor(func(r httpsec.Request) string { return r.Host() }, "evil.example", &calls), httpsec.OrderBearerToken))
				swap := func(gc *gin.Context) { gc.Request.Host = "evil.example" }
				req := basicReq(t, "/api/x", "pw-1")
				req.Host = "app.example"

				return chain, swap, req, &calls
			},
			assert: func(t *testing.T, o doubleOutcome) {
				assert.True(t, o.handlerRan, "the second mount passes the rewrite through")
				assert.EqualValues(t, 1, o.chainCalls, "the rule interceptor ran once")
			},
		},
		{
			name: "query swap passes through",
			build: func(t *testing.T) (*httpsec.Chain, gin.HandlerFunc, *http.Request, *atomic.Int32) {
				var calls atomic.Int32
				chain := newChain(t, httpsec.RegisterInterceptor(
					ruleInterceptor(func(r httpsec.Request) string { return r.Query("mode") }, "deny", &calls), httpsec.OrderBearerToken))
				swap := func(gc *gin.Context) { gc.Request.URL.RawQuery = "mode=deny" }

				return chain, swap, basicReq(t, "/api/x?mode=ok", "pw-1"), &calls
			},
			assert: func(t *testing.T, o doubleOutcome) {
				assert.True(t, o.handlerRan, "the second mount passes the rewrite through")
				assert.EqualValues(t, 1, o.chainCalls, "the rule interceptor ran once")
			},
		},
		{
			name: "control: no middleware between the mounts runs the chain once",
			build: func(t *testing.T) (*httpsec.Chain, gin.HandlerFunc, *http.Request, *atomic.Int32) {
				a := &passwordAuthenticator{}
				chain := newChain(t, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: a, Attempts: &countingAttempts{}}))

				return chain, nil, basicReq(t, "/api/x", "pw-1"), &a.calls
			},
			assert: func(t *testing.T, o doubleOutcome) {
				assert.True(t, o.handlerRan)
				assert.Equal(t, "u-1", o.ctxPrincipal)
				assert.EqualValues(t, 1, o.chainCalls)
			},
		},
		{
			name: "control: a path rewrite between the mounts runs the chain in full again",
			build: func(t *testing.T) (*httpsec.Chain, gin.HandlerFunc, *http.Request, *atomic.Int32) {
				a := &passwordAuthenticator{}
				chain := newChain(t, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: a, Attempts: &countingAttempts{}}))
				swap := func(gc *gin.Context) {
					gc.Request.URL.Path = "/api/y"
					gc.Request.URL.RawPath = ""
					gc.Request.SetBasicAuth("ada", "pw-2")
				}

				return chain, swap, basicReq(t, "/api/x", "pw-1"), &a.calls
			},
			assert: func(t *testing.T, o doubleOutcome) {
				assert.EqualValues(t, 2, o.chainCalls, "path is in the key, so the second entry re-runs")
				assert.True(t, o.handlerRan)
				assert.Equal(t, "u-2", o.ctxPrincipal)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, swap, req, calls := tc.build(t)

			var o doubleOutcome

			eng := gin.New()
			eng.Use(ginsec.Middleware(chain))

			g := eng.Group("/api")
			if swap != nil {
				g.Use(swap)
			}

			g.Use(ginsec.Middleware(chain))

			handler := func(gc *gin.Context) {
				o.handlerRan = true

				if p, ok := identity.PrincipalFromContext(gc.Request.Context()); ok {
					o.ctxPrincipal = string(p.ID)
				}

				gc.Status(http.StatusOK)
			}
			g.GET("/x", handler)
			g.GET("/y", handler)

			o.rec = httptest.NewRecorder()
			eng.ServeHTTP(o.rec, req)
			o.chainCalls = calls.Load()

			tc.assert(t, o)
		})
	}
}
