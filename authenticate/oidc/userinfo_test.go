package oidc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/outbound"
)

// userInfoPassword is a body value that must never reach a log or an error.
const userInfoPassword = "enc-secret-pw" //nolint:gosec // G101: a fixture body value, not a credential

func TestUpstream_UserInfo(t *testing.T) {
	t.Parallel()

	const subject = "s-1"
	jsonBody := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}
	}
	status := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"invalid_token","password":"` + userInfoPassword + `"}`))
		}
	}
	// nested returns an answer whose objects nest depth deep, the top-level one
	// counting as the first.
	nested := func(depth int) string {
		return `{"sub":"s-1","a":` + strings.Repeat(`{"a":`, depth-2) + `{}` + strings.Repeat(`}`, depth-2) + `}`
	}
	blockUntilDone := func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

	type env struct {
		requests *atomic.Int64
		auth     *atomic.Value // the Authorization header of the last request
	}
	// endpoint names where the upstream access finds UserInfo, given the
	// test server's URL.
	type testCase struct {
		name     string
		handler  http.HandlerFunc
		token    string
		endpoint func(srvURL string) func(context.Context) (string, error) // nil: the server's /userinfo
		zero     bool                                                      // the zero Upstream
		client   []outbound.Option
		ctx      func(ctx context.Context) context.Context
		assert   func(t *testing.T, e env, got map[string]any, err error)
	}

	refused := func(t *testing.T, _ env, got map[string]any, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrUserInfoFailed)
		assert.Nil(t, got)
	}
	refusedUnsent := func(t *testing.T, e env, got map[string]any, err error) {
		t.Helper()
		refused(t, e, got, err)
		assert.Zero(t, e.requests.Load(), "no request is sent")
	}
	endpointIs := func(raw string, err error) func(string) func(context.Context) (string, error) {
		return func(string) func(context.Context) (string, error) {
			return func(context.Context) (string, error) { return raw, err }
		}
	}

	// other is a second TLS server on another origin, which a redirect from
	// the UserInfo endpoint points at; hits counts what reaches it.
	var otherHits atomic.Int64
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		otherHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"s-1"}`))
	}))
	t.Cleanup(other.Close)

	cases := []testCase{
		{
			name:    "numbers keep their exact text",
			handler: jsonBody(`{"sub":"s-1","emp":12345678901234567890}`),
			assert: func(t *testing.T, _ env, got map[string]any, err error) {
				require.NoError(t, err)
				assert.Equal(t, map[string]any{"sub": "s-1", "emp": json.Number("12345678901234567890")}, got)
			},
		},
		{name: "sub repeated", handler: jsonBody(`{"sub":"s-2","sub":"s-1"}`), assert: refused},
		{name: "member repeated", handler: jsonBody(`{"sub":"s-1","a":1,"a":2}`), assert: refused},
		{name: "member repeated in a nested object", handler: jsonBody(`{"sub":"s-1","a":{"b":1,"b":2}}`), assert: refused},
		{name: "member repeated in an object inside an array", handler: jsonBody(`{"sub":"s-1","a":[{"b":1,"b":2}]}`), assert: refused},
		{name: "member repeated through a JSON escape", handler: jsonBody(`{"sub":"s-1","\u0073ub":"s-1"}`), assert: refused},
		{name: "nesting at the cap", handler: jsonBody(nested(64)), assert: func(t *testing.T, _ env, got map[string]any, err error) {
			require.NoError(t, err)
			assert.Equal(t, "s-1", got["sub"])
		}},
		{name: "nesting beyond the cap", handler: jsonBody(nested(65)), assert: refused},
		{name: "trailing whitespace", handler: jsonBody("{\"sub\":\"s-1\"} \n\t"), assert: func(t *testing.T, _ env, got map[string]any, err error) {
			require.NoError(t, err)
			assert.Equal(t, map[string]any{"sub": "s-1"}, got)
		}},
		{
			name: "redirect to another origin",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, other.URL+"/userinfo", http.StatusFound)
			},
			assert: func(t *testing.T, _ env, got map[string]any, err error) {
				refused(t, env{}, got, err)
				assert.Zero(t, otherHits.Load(), "the redirect target receives no request")
			},
		},
		{
			name:    "ok",
			handler: jsonBody(`{"sub":"s-1","email":"a@corp.example","password":"` + userInfoPassword + `","n":7}`),
			assert: func(t *testing.T, e env, got map[string]any, err error) {
				require.NoError(t, err)
				assert.Equal(t, map[string]any{
					"sub": "s-1", "email": "a@corp.example", "password": userInfoPassword, "n": json.Number("7"),
				}, got)
				assert.Equal(t, "Bearer "+upstreamAccessToken, e.auth.Load())
				assert.Equal(t, int64(1), e.requests.Load())
			},
		},
		{
			name: "ok with a charset parameter",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, _ = w.Write([]byte(`{"sub":"s-1"}`))
			},
			assert: func(t *testing.T, _ env, got map[string]any, err error) {
				require.NoError(t, err)
				assert.Equal(t, map[string]any{"sub": "s-1"}, got)
			},
		},
		{
			name:    "sub mismatch",
			handler: jsonBody(`{"sub":"s-2","password":"` + userInfoPassword + `"}`),
			assert:  refused,
		},
		{
			name:    "same email but another sub",
			handler: jsonBody(`{"sub":"s-2","email":"alice@corp.example","email_verified":true,"password":"` + userInfoPassword + `"}`),
			assert:  refused,
		},
		{
			name:    "sub differs only in letter case",
			handler: jsonBody(`{"sub":"S-1"}`),
			assert:  refused,
		},
		{name: "sub missing", handler: jsonBody(`{"password":"` + userInfoPassword + `"}`), assert: refused},
		{name: "sub not a string", handler: jsonBody(`{"sub":1}`), assert: refused},
		{name: "sub empty", handler: jsonBody(`{"sub":""}`), assert: refused},
		{name: "unauthorized", handler: status(http.StatusUnauthorized), assert: refused},
		{name: "server error", handler: status(http.StatusInternalServerError), assert: refused},
		{
			name: "jwt",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/jwt")
				_, _ = w.Write([]byte(`{"sub":"s-1","password":"` + userInfoPassword + `"}`))
			},
			assert: refused,
		},
		{name: "not an object", handler: jsonBody(`[1]`), assert: refused},
		{name: "null", handler: jsonBody(`null`), assert: refused},
		{name: "not JSON", handler: jsonBody(`password=` + userInfoPassword), assert: refused},
		{name: "trailing data", handler: jsonBody(`{"sub":"s-1"} {"sub":"s-2"}`), assert: refused},
		{
			name:    "oversized",
			handler: jsonBody(`{"sub":"s-1","password":"` + userInfoPassword + `","pad":"` + strings.Repeat("x", 2048) + `"}`),
			client:  []outbound.Option{outbound.WithMaxResponseBytes(1024)},
			assert:  refused,
		},
		{
			name:    "slow",
			handler: blockUntilDone,
			client:  []outbound.Option{outbound.WithTimeout(50 * time.Millisecond)},
			assert: func(t *testing.T, e env, got map[string]any, err error) {
				refused(t, e, got, err)
				assert.NotErrorIs(t, err, context.Canceled, "the client's own bound is the provider failing, not the caller cancelling")
			},
		},
		{name: "no endpoint", endpoint: endpointIs("", nil), assert: refusedUnsent},
		{name: "no endpoint resolver", endpoint: func(string) func(context.Context) (string, error) { return nil }, assert: refusedUnsent},
		{
			name:     "endpoint lookup fails",
			endpoint: endpointIs("", fmt.Errorf("%w: provider %q: discovery: status 503", oidc.ErrDiscoveryFailed, "corp")),
			assert: func(t *testing.T, e env, got map[string]any, err error) {
				refusedUnsent(t, e, got, err)
				assert.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
			},
		},
		{name: "endpoint scheme refused by the client", endpoint: endpointIs("http://corp.example/userinfo", nil), assert: refusedUnsent},
		{name: "no token", token: "-", handler: jsonBody(`{"sub":"s-1"}`), assert: refusedUnsent},
		{name: "zero value", zero: true, assert: refusedUnsent},
		{
			name:    "cancelled",
			handler: jsonBody(`{"sub":"s-1"}`),
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()
				return c
			},
			assert: func(t *testing.T, e env, got map[string]any, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Nil(t, got)
				assert.Zero(t, e.requests.Load())
			},
		},
		{
			name:    "deadline passes mid-request",
			handler: blockUntilDone,
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
				t.Cleanup(cancel)
				return c
			},
			assert: func(t *testing.T, _ env, got map[string]any, err error) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Nil(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := env{requests: &atomic.Int64{}, auth: &atomic.Value{}}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				e.requests.Add(1)
				e.auth.Store(r.Header.Get("Authorization"))
				if tc.handler == nil || r.Method != http.MethodGet || r.URL.Path != "/userinfo" {
					http.NotFound(w, r)
					return
				}
				tc.handler(w, r)
			}))
			t.Cleanup(srv.Close)

			out, err := outbound.New(append([]outbound.Option{outbound.WithHTTPClient(srv.Client())}, tc.client...)...)
			require.NoError(t, err)

			endpoint := func(context.Context) (string, error) { return srv.URL + "/userinfo", nil }
			if tc.endpoint != nil {
				endpoint = tc.endpoint(srv.URL)
			}
			token := upstreamAccessToken
			if tc.token == "-" {
				token = ""
			}
			up := oidc.NewUpstreamForTest(token, subject, endpoint, out)
			if tc.zero {
				up = oidc.Upstream{}
			}

			var logs bytes.Buffer
			ctx := ctxlog.With(t.Context(), testTextLogger(&logs))
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			got, err := up.UserInfo(ctx)
			tc.assert(t, e, got, err)

			// Every row: neither the token nor a body value reaches a log
			// record or the error's text.
			texts := map[string]string{"logs": logs.String()}
			if err != nil {
				texts["error"] = err.Error()
				assert.False(t, errors.Is(err, oidc.ErrUserInfoFailed) && errors.Is(err, context.Canceled),
					"a cancelled caller is not a provider failure")
			}
			for what, text := range texts {
				assert.NotContains(t, text, upstreamAccessToken, "the %s must not hold the access token", what)
				assert.NotContains(t, text, userInfoPassword, "the %s must not hold the response body", what)
			}
		})
	}
}
