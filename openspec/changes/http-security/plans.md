# HTTP Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put scrty's authentication, session, policy and authorization decisions in front of an HTTP handler as one ordered, framework-neutral interceptor chain that fails closed, and confine the HTTP requests scrty itself sends.

**Architecture:** Interceptors read and write only through a small `Request`/`ResponseWriter` abstraction carried on an `Exchange`, so one chain runs unchanged on net/http, gin and fiber. Refusals leave the chain as errors and one public table maps them to a status; rendering belongs to the consumer. Outbound requests go through a separate `outbound` client that checks scheme, origin, redirects, time and size.

**Tech Stack:** Go 1.27, `github.com/lestrrat-go/jwx/v4` (through `token`/`signingkey`), gin v1, fiber v3.5.0, `go.uber.org/mock` (mockgen), `stretchr/testify`, `testing/synctest`.

**Spec:** `openspec/changes/http-security/` — `proposal.md`, `design.md`, `specs/http-security-chain/spec.md`, `specs/http-error-propagation/spec.md`, `specs/framework-adapters/spec.md`, `specs/outbound-http-confinement/spec.md`. Every plan step cites the `tasks.md` number it implements.

---

## Global Constraints

- Module `github.com/kartaladev/scrty`, Go 1.27 minimum. The core module gains **no** third-party dependency from this change; gin and fiber live only in the `ginsec` and `fibersec` nested modules.
- **Test-first, always.** Write the failing test, run it, read the output and confirm it fails for the intended reason. A compile error is **not** a red step — stub the symbol so the test compiles and fails on the assertion. Never mark a step done on a test that has not been seen to fail.
- Table-driven tests follow the project's `table-test` skill: the `assert` closure form (never `want`/`wantErr` fields), a `ctx` modifier where context matters, and `t.Context()` over `context.Background()`.
- Test doubles come from `mockgen` (`use-mockgen` skill): a `//go:generate mockgen -destination=<x>_mock_test.go -package=<pkg>_test -typed <import path> <Interface>` directive beside the consumer, output in `_test.go` files only. Mocks never enter a production build — `TestModuleLayout` enforces it.
- **Library design:** every behaviour has a safe default that needs no configuration, and every default is replaceable without forking. Each option's godoc names the default it replaces; each port's godoc says what the library uses when the consumer supplies none. A contradictory configuration is a `New` error, never a surprise at first use.
- **Legacy reference:** `.claude/.legacy/` is read-only. Never copy its code, tests or comments, and never cite it — not its name, paths or "legacy"/"ported"/"v2" wording. Exclude it from text searches (`rg --glob '!.claude/.legacy'`).
- **No defect claim without a failing test.** Any assertion that existing code is wrong needs a reproducing test, or the label `UNREPRODUCED` with the reason.
- Navigate Go code with `gopls` (references, definitions, implementations), not `grep`. `grep` is for comments, strings and config only.
- Never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`. The tree holds other agents' uncommitted work. Undo by editing the file back.
- Never edit anything under `openspec/`. Report a disagreement between the code and the artifacts; the main session writes them.
- Gate before reporting: `go test -race -count=1 ./...` in the module touched, `go vet ./...`, `gofmt -l .` empty, `golangci-lint run ./...` clean. The full gate is `make check`.

### Names the artifacts get wrong

`design.md`'s Go snippets predate the code. Use these, and do not "fix" the code to match the design:

| design.md writes | the code exports |
|---|---|
| `authn.Authentication`, `authn.ErrAuthenticationFailed` | `authenticate.Authentication`, `authenticate.ErrAuthenticationFailed` |
| `authz.Authorizer`, `authz.Rule` | `authorize.Authorizer`, `authorize.Rule[R any]` (generic) |
| `httpsec.ErrRefusedByPolicy` | not declared — `policy.ErrPolicyDenied` is the sentinel (see below) |
| a hand-rolled reflection nil check | `internal/nilcheck.IsNil(v any) bool` |
| "marshal the jwx set" | `signingkey.KeyManager.JWKS() ([]byte, error)` already returns the bytes |

`session` exports no context helper, so `httpsec` owns the session context key. `authenticate.WithAuthentication` and `authorize.WithAuthorizer` do exist and are used as-is.

**Settled question (Decision 6 is stale):** `policy.Engine.EvaluatePhase` already substitutes `policy.ErrPolicyDenied` for a deny whose reason is nil (`policy/engine.go:128-133`), and the chain always evaluates through an `Engine`. So the nil-reason fallback design Decision 6 describes is unreachable. `StatusForError` maps `policy.ErrPolicyDenied` to 403 and `httpsec` declares no second sentinel for it. `policyDenyReason` is `d.Reason` with no fallback.

**Settled open questions:** `policy.ContextWithPhase`/`PhaseFromContext` are unexported once the chain is shown not to use them (Task 27). `Chain.FlushRefusalLogs` flushes the chain's own sampler only — no shared `RefusalLogFlusher` declaration is introduced here (Task 27).

---

## File Structure

**Core module, new package `httpsec/`** — one responsibility per file, because the package is large and every file is read on its own:

| File | Responsibility |
|---|---|
| `doc.go` | package godoc: the chain, its slots, what fails closed |
| `exchange.go` | `Request`, `ResponseWriter`, `Cookie`, `Exchange`, `Next`, `Interceptor`, `InterceptorFunc` |
| `nethttp.go` | `NewHTTPRequest`, `NewHTTPResponseWriter` — the default adapter, reused by `ginsec` |
| `errors.go` | refusal sentinels, `ChallengeError` |
| `status.go` | `StatusForError` and its ordered table |
| `order.go` | `Order` constants, `Before`, `After` |
| `chain.go` | `Chain`, `New`, `Assemble`, `Middleware`, `FlushRefusalLogs` |
| `options.go` | every `Option`, `Enable*` and `*Deps` struct, plus construction validation |
| `context.go` | the session context key and the publish/read helpers |
| `throttle.go` | `sourceThrottled`, `recordSourceFailure`, the address refusal rules |
| `refusallog.go` | the sampler wiring, keys and the default reporter |
| `login.go` | form login |
| `logincomplete.go` | `postAuthenticationInput`, `completeLogin`, `policyDenyReason` |
| `basic.go` | HTTP Basic authentication |
| `bearer.go` | bearer token authentication |
| `passwordchange.go` | the password-change gate and its resolve endpoint |
| `logout.go` | logout |
| `sessiontouch.go` | session activity write-back |
| `jwks.go` | the key set endpoint |
| `authorization.go` | the authorization stage and the centralized rule set |
| `guards.go` | `Guards` and the per-endpoint guard builders |

**Core module, new package `internal/origin/`:** `same.go` (origin comparison), `allowlist.go` (redirect-target allowlist).

**Core module, new package `outbound/`:** `client.go` (`New`, `Client`, `Get`, `PostForm`, `Response`), `options.go` (the options and their construction checks).

**New nested module `ginsec/`:** `go.mod`, `doc.go`, `middleware.go` (the adapter and refusal handling), `clientip.go` (`WithForwardedClientIP`), `guards.go`.

**New nested module `fibersec/`:** `go.mod`, `doc.go`, `exchange.go` (`Request`/`ResponseWriter` over `fiber.Ctx`), `middleware.go`, `errors.go` (`RefusalError`, `ErrorHandler`, `MapError`), `guards.go`.

**Test module:** `test/httpsecconformance/` — `scenarios.go` (the one exported scenario table), `runner.go` (the harness an adapter suite calls).

**Modified:** `go.work` (add `./ginsec`, `./fibersec`), `policy/policy.go` and `policy/engine.go` (unexport the phase helpers, Task 27).

---

## Task 1: The exchange abstraction

**Implements:** tasks.md 1.1

**Files:**
- Create: `httpsec/exchange.go`, `httpsec/doc.go`
- Test: `httpsec/exchange_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Request`, `ResponseWriter`, `Cookie`, `Exchange`, `NewExchange(ctx context.Context, r Request, w ResponseWriter) *Exchange`, `(*Exchange).Context() context.Context`, `(*Exchange).SetContext(ctx context.Context)`, `Next func(*Exchange) error`, `Interceptor interface{ Intercept(*Exchange, Next) error }`, `InterceptorFunc func(*Exchange, Next) error`. Every later task depends on these names.

- [ ] **Step 1: Write the failing test**

```go
package httpsec_test

import (
	"context"
	"testing"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ctxKey string

func TestExchangeContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		act    func(ex *httpsec.Exchange)
		assert func(t *testing.T, ex *httpsec.Exchange)
	}

	cases := []testCase{
		{
			name: "derives from the seed context",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-1")
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				assert.Equal(t, "r-1", ex.Context().Value(ctxKey("request-id")))
			},
		},
		{
			name: "SetContext is visible to a later reader",
			act: func(ex *httpsec.Exchange) {
				ex.SetContext(context.WithValue(ex.Context(), ctxKey("principal"), "alice"))
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				assert.Equal(t, "alice", ex.Context().Value(ctxKey("principal")))
			},
		},
		{
			name: "cancellation on the seed reaches the exchange",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				require.ErrorIs(t, ex.Context().Err(), context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			ex := httpsec.NewExchange(ctx, stubRequest{}, &stubWriter{})
			require.NotNil(t, ex)
			if tc.act != nil {
				tc.act(ex)
			}
			tc.assert(t, ex)
		})
	}
}
```

Add the stubs in `httpsec/stub_test.go`, because every later test reuses them:

```go
package httpsec_test

import "net/http"

type stubRequest struct {
	method, path string
	headers      map[string]string
	query        map[string]string
	cookies      map[string]string
	form         map[string]string
	body         []byte
	clientIP     string
}

func (r stubRequest) Method() string            { return r.method }
func (r stubRequest) Path() string              { return r.path }
func (r stubRequest) Header(n string) string    { return r.headers[n] }
func (r stubRequest) Query(n string) string     { return r.query[n] }
func (r stubRequest) FormValue(n string) string { return r.form[n] }
func (r stubRequest) ClientIP() string          { return r.clientIP }

func (r stubRequest) Cookie(n string) (string, bool) {
	v, ok := r.cookies[n]
	return v, ok
}

func (r stubRequest) Body(limit int64) ([]byte, error) {
	if int64(len(r.body)) > limit {
		return nil, httpsec.ErrRequestTooLarge
	}
	return r.body, nil
}

type stubWriter struct {
	header http.Header
	status int
	body   []byte
	cookie []*httpsec.Cookie
}

func (w *stubWriter) SetHeader(n, v string) {
	if w.header == nil {
		w.header = http.Header{}
	}
	w.header.Set(n, v)
}
func (w *stubWriter) SetCookie(c *httpsec.Cookie) { w.cookie = append(w.cookie, c) }
func (w *stubWriter) WriteHeader(s int)           { w.status = s }
func (w *stubWriter) Write(b []byte) (int, error) { w.body = append(w.body, b...); return len(b), nil }
```

- [ ] **Step 2: Run the test and confirm it fails for the intended reason**

Run: `go test -run TestExchangeContext -count=1 ./httpsec/`
Expected: the package does not exist yet, so first create `httpsec/exchange.go` holding only the type declarations and a `NewExchange` that returns `nil`. Re-run. Expected: FAIL on `require.NotNil` — **not** a build error. That is the red step.

- [ ] **Step 3: Implement**

```go
// Package httpsec puts scrty's authentication, session, policy and
// authorization decisions in front of an HTTP handler.
package httpsec

import (
	"context"
	"net/http"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/session"
)

// Request is everything an interceptor may read from the request it is
// judging. Each integration implements it over its own framework's request,
// which is what lets one chain run unchanged behind net/http, gin and fiber.
type Request interface {
	Method() string
	Path() string
	Header(name string) string
	Query(name string) string
	Cookie(name string) (value string, ok bool)
	FormValue(name string) string

	// Body returns at most limit bytes of the request body, buffered so a
	// later reader still sees it, and ErrRequestTooLarge when the body is
	// longer. It never returns a body it did not fully read.
	Body(limit int64) ([]byte, error)

	// ClientIP is the address the request is attributed to, or "" when the
	// integration cannot tell. It is never read from a forwarding header
	// unless that integration's own trusted-proxy configuration says so.
	ClientIP() string
}

// Cookie is a cookie an interceptor sets. It mirrors http.Cookie so the
// net/http integration passes it through unchanged.
type Cookie = http.Cookie

// ResponseWriter is everything an interceptor may write.
type ResponseWriter interface {
	SetHeader(name, value string)
	SetCookie(c *Cookie)
	WriteHeader(status int)
	Write(b []byte) (int, error)
}

// Exchange is one request passing through the chain.
//
// The context lives here rather than on the Request because fasthttp's request
// carries no context field. It is seeded from the integration's own incoming
// context, so values and cancellation set before the chain survive, and it is
// written back into the framework's carrier immediately before the handler.
type Exchange struct {
	Request        Request
	Writer         ResponseWriter
	Authentication *authenticate.Authentication
	Session        *session.Session

	ctx context.Context
}

// NewExchange starts an exchange from ctx, which must not be nil.
func NewExchange(ctx context.Context, r Request, w ResponseWriter) *Exchange {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Exchange{Request: r, Writer: w, ctx: ctx}
}

// Context returns the context every call into scrty's cores is made with.
func (e *Exchange) Context() context.Context { return e.ctx }

// SetContext replaces the context. An interceptor that adds security state
// calls it so every later interceptor, and the handler, read that state.
func (e *Exchange) SetContext(ctx context.Context) {
	if ctx != nil {
		e.ctx = ctx
	}
}

// Next runs the rest of the chain, ending in the downstream handler.
type Next func(*Exchange) error

// Interceptor is one stage of the chain. It continues by calling next and
// stops the request by not calling it; anything after next runs once the
// handler and every inner interceptor have returned.
type Interceptor interface {
	Intercept(ex *Exchange, next Next) error
}

// InterceptorFunc adapts a function to Interceptor.
type InterceptorFunc func(ex *Exchange, next Next) error

// Intercept implements Interceptor.
func (f InterceptorFunc) Intercept(ex *Exchange, next Next) error { return f(ex, next) }
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test -run TestExchangeContext -count=1 ./httpsec/` — Expected: PASS.
Then `go vet ./httpsec/` and `gofmt -l httpsec/` (must print nothing).

- [ ] **Step 5: Commit**

```bash
git add httpsec/doc.go httpsec/exchange.go httpsec/exchange_test.go httpsec/stub_test.go
git commit -m "feat(httpsec): the exchange interceptors read and write through

The chain carries its context on the exchange rather than the request, so a
framework whose request has no context field can still be adapted."
```

---

## Task 2: The net/http request implementation

**Implements:** tasks.md 1.2, 1.3, 1.5

**Files:**
- Create: `httpsec/nethttp.go`
- Test: `httpsec/nethttp_test.go`

**Interfaces:**
- Consumes: `Request`, `ErrRequestTooLarge` (Task 4 declares it; declare it in `httpsec/errors.go` here if Task 4 has not landed, and Task 4 keeps the declaration).
- Produces: `NewHTTPRequest(r *http.Request) Request`. `ginsec` reuses it unchanged.

- [ ] **Step 1: Write the failing test for the accessors and the client address**

```go
func TestHTTPRequest(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func() *http.Request
		assert func(t *testing.T, r httpsec.Request)
	}

	cases := []testCase{
		{
			name: "method, path, header and query",
			build: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/login?next=/home", nil)
				req.Header.Set("Authorization", "Bearer abc")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, http.MethodPost, r.Method())
				assert.Equal(t, "/login", r.Path())
				assert.Equal(t, "Bearer abc", r.Header("Authorization"))
				assert.Equal(t, "/home", r.Query("next"))
			},
		},
		{
			name: "absent cookie is reported absent, not empty",
			build: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			assert: func(t *testing.T, r httpsec.Request) {
				v, ok := r.Cookie("sid")
				assert.False(t, ok)
				assert.Empty(t, v)
			},
		},
		{
			name: "form value",
			build: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/login",
					strings.NewReader("username=alice&password=s3cret"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "alice", r.FormValue("username"))
			},
		},
		{
			name: "peer host is the client address and the forwarding header is ignored",
			build: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "198.51.100.7:51234"
				req.Header.Set("X-Forwarded-For", "203.0.113.9")
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "198.51.100.7", r.ClientIP())
			},
		},
		{
			name: "peer without a port yields no client address",
			build: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "@"
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Empty(t, r.ClientIP())
			},
		},
		{
			name: "IPv6 peer keeps its host only",
			build: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "[2001:db8::1]:443"
				return req
			},
			assert: func(t *testing.T, r httpsec.Request) {
				assert.Equal(t, "2001:db8::1", r.ClientIP())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, httpsec.NewHTTPRequest(tc.build()))
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestHTTPRequest -count=1 ./httpsec/`
Declare `func NewHTTPRequest(r *http.Request) Request` returning a struct whose methods all return zero values, so the test compiles. Expected: FAIL on the first assertion of each row, naming the empty value — not a build error.

- [ ] **Step 3: Write the failing body test**

The body is separate because its contract is "buffered once, restored, bounded":

```go
func TestHTTPRequestBody(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		body   string
		limit  int64
		assert func(t *testing.T, req *http.Request, r httpsec.Request)
	}

	cases := []testCase{
		{
			name:  "within the limit and readable twice",
			body:  `{"username":"alice"}`,
			limit: 64 << 10,
			assert: func(t *testing.T, req *http.Request, r httpsec.Request) {
				first, err := r.Body(64 << 10)
				require.NoError(t, err)
				assert.JSONEq(t, `{"username":"alice"}`, string(first))

				// The downstream handler must still see the body.
				rest, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assert.JSONEq(t, `{"username":"alice"}`, string(rest))
			},
		},
		{
			name:  "one byte over the limit is refused unparsed",
			body:  strings.Repeat("a", 65),
			limit: 64,
			assert: func(t *testing.T, _ *http.Request, r httpsec.Request) {
				b, err := r.Body(64)
				require.ErrorIs(t, err, httpsec.ErrRequestTooLarge)
				assert.Empty(t, b)
			},
		},
		{
			name:  "exactly at the limit is accepted",
			body:  strings.Repeat("a", 64),
			limit: 64,
			assert: func(t *testing.T, _ *http.Request, r httpsec.Request) {
				b, err := r.Body(64)
				require.NoError(t, err)
				assert.Len(t, b, 64)
			},
		},
		{
			name:  "buffered once: a second call does not re-read",
			body:  "hello",
			limit: 64,
			assert: func(t *testing.T, _ *http.Request, r httpsec.Request) {
				first, err := r.Body(64)
				require.NoError(t, err)
				second, err := r.Body(64)
				require.NoError(t, err)
				assert.Equal(t, first, second)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tc.body))
			tc.assert(t, req, httpsec.NewHTTPRequest(req))
		})
	}
}
```

- [ ] **Step 4: Run it and confirm the red step**

Run: `go test -run TestHTTPRequestBody -count=1 ./httpsec/`
Expected: FAIL — the stub returns `nil, nil`, so the first row fails on `assert.JSONEq` and the over-limit row fails on `require.ErrorIs`.

- [ ] **Step 5: Implement**

```go
package httpsec

import (
	"bytes"
	"io"
	"net"
	"net/http"
)

// NewHTTPRequest adapts a net/http request. It is the default implementation
// of Request, and ginsec reuses it because gin's context carries both net/http
// types.
func NewHTTPRequest(r *http.Request) Request { return &httpRequest{r: r} }

type httpRequest struct {
	r *http.Request

	body    []byte
	bodyErr error
	read    bool
}

func (h *httpRequest) Method() string         { return h.r.Method }
func (h *httpRequest) Path() string           { return h.r.URL.Path }
func (h *httpRequest) Header(n string) string { return h.r.Header.Get(n) }
func (h *httpRequest) Query(n string) string  { return h.r.URL.Query().Get(n) }

func (h *httpRequest) Cookie(n string) (string, bool) {
	c, err := h.r.Cookie(n)
	if err != nil {
		return "", false
	}
	return c.Value, true
}

// FormValue parses the form under the same bound Body applies, so a form login
// cannot be the one unbounded read on the endpoint.
func (h *httpRequest) FormValue(n string) string { return h.r.FormValue(n) }

// Body reads the body once, bounded by limit, and restores it so the
// downstream handler still reads it in full. A body longer than limit returns
// ErrRequestTooLarge, and nothing is returned to be parsed.
func (h *httpRequest) Body(limit int64) ([]byte, error) {
	if h.read {
		return h.body, h.bodyErr
	}
	h.read = true

	if h.r.Body == nil {
		return nil, nil
	}

	// limit+1 so a body exactly at the limit is accepted and the first byte
	// over it is seen without reading the rest.
	b, err := io.ReadAll(io.LimitReader(h.r.Body, limit+1))
	if err != nil {
		h.bodyErr = err
		return nil, err
	}
	if int64(len(b)) > limit {
		h.bodyErr = ErrRequestTooLarge
		return nil, ErrRequestTooLarge
	}

	h.body = b
	h.r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

// ClientIP is the host part of the transport peer. No forwarding header is
// read: net/http holds no trusted-proxy configuration to decide from, so a
// header here would let a client choose its own rate-limit bucket.
func (h *httpRequest) ClientIP() string {
	host, _, err := net.SplitHostPort(h.r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}
```

- [ ] **Step 6: Run both tests and confirm they pass**

Run: `go test -run 'TestHTTPRequest' -count=1 ./httpsec/` — Expected: PASS (both functions).

- [ ] **Step 7: Commit**

```bash
git add httpsec/nethttp.go httpsec/nethttp_test.go
git commit -m "feat(httpsec): the net/http request, bounded and attributed to its peer

The body is buffered once under a caller's bound and restored for the handler,
and the client address is the transport peer with no forwarding header read."
```

---

## Task 3: The net/http response writer

**Implements:** tasks.md 1.4

**Files:**
- Modify: `httpsec/nethttp.go`
- Test: `httpsec/nethttp_test.go`

**Interfaces:**
- Produces: `NewHTTPResponseWriter(w http.ResponseWriter) ResponseWriter`, and an unexported `committed() bool` on the concrete type that `ginsec` and the default error handler read to decide whether a status may still be set.

- [ ] **Step 1: Write the failing test**

```go
func TestHTTPResponseWriter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		act    func(w httpsec.ResponseWriter)
		assert func(t *testing.T, rec *httptest.ResponseRecorder)
	}

	cases := []testCase{
		{
			name: "header and status",
			act: func(w httpsec.ResponseWriter) {
				w.SetHeader("WWW-Authenticate", `Basic realm="Restricted"`)
				w.WriteHeader(http.StatusUnauthorized)
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Equal(t, `Basic realm="Restricted"`, rec.Header().Get("WWW-Authenticate"))
				assert.Empty(t, rec.Body.String())
			},
		},
		{
			name: "body",
			act: func(w httpsec.ResponseWriter) {
				w.SetHeader("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"access_token":"t"}`))
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
				assert.JSONEq(t, `{"access_token":"t"}`, rec.Body.String())
			},
		},
		{
			name: "cookie",
			act: func(w httpsec.ResponseWriter) {
				w.SetCookie(&httpsec.Cookie{Name: "sid", Value: "abc", HttpOnly: true})
			},
			assert: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Contains(t, rec.Header().Get("Set-Cookie"), "sid=abc")
				assert.Contains(t, rec.Header().Get("Set-Cookie"), "HttpOnly")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			tc.act(httpsec.NewHTTPResponseWriter(rec))
			tc.assert(t, rec)
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestHTTPResponseWriter -count=1 ./httpsec/`
Stub `NewHTTPResponseWriter` to return a writer whose methods do nothing. Expected: FAIL on the status assertion (`200 != 401`), not a build error.

- [ ] **Step 3: Implement**

```go
// NewHTTPResponseWriter adapts a net/http response writer.
func NewHTTPResponseWriter(w http.ResponseWriter) ResponseWriter {
	return &httpResponseWriter{w: w}
}

type httpResponseWriter struct {
	w     http.ResponseWriter
	wrote bool
}

func (h *httpResponseWriter) SetHeader(n, v string) { h.w.Header().Set(n, v) }
func (h *httpResponseWriter) SetCookie(c *Cookie)   { http.SetCookie(h.w, c) }

func (h *httpResponseWriter) WriteHeader(status int) {
	if h.wrote {
		return
	}
	h.wrote = true
	h.w.WriteHeader(status)
}

func (h *httpResponseWriter) Write(b []byte) (int, error) {
	h.wrote = true
	return h.w.Write(b)
}

// committed reports whether a status or body has already gone out, so the
// default error handler does not write a second status over an interceptor's.
func (h *httpResponseWriter) committed() bool { return h.wrote }
```

- [ ] **Step 4: Run it and confirm it passes**

Run: `go test -run TestHTTPResponseWriter -count=1 ./httpsec/` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add httpsec/nethttp.go httpsec/nethttp_test.go
git commit -m "feat(httpsec): the net/http response writer

It records whether the response was committed, so a refusal never writes a
second status over one an interceptor already sent."
```

---

## Task 4: Refusal sentinels and the challenge error

**Implements:** tasks.md 2.1

**Files:**
- Create: `httpsec/errors.go`
- Test: `httpsec/errors_test.go`

**Interfaces:**
- Produces: `ErrAuthenticationRequired`, `ErrCredentialsMissing`, `ErrRequestTooLarge`, `ChallengeError{Kind policy.ChallengeKind; Session *session.Session; Token string}` with `Error() string`. **Do not** declare `ErrRefusedByPolicy` — see Global Constraints.

- [ ] **Step 1: Write the failing test**

The one thing worth pinning is that the error text leaks nothing:

```go
func TestChallengeError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    *httpsec.ChallengeError
		assert func(t *testing.T, text string)
	}

	cases := []testCase{
		{
			name: "names the kind and hides the token and the session handle",
			err: &httpsec.ChallengeError{
				Kind:    policy.ChallengeMFA,
				Session: &session.Session{ID: "sess-handle-0123456789"},
				Token:   "eyJhbGciOiJFUzI1NiJ9.secret.sig",
			},
			assert: func(t *testing.T, text string) {
				assert.Contains(t, text, policy.ChallengeMFA.String())
				assert.NotContains(t, text, "eyJhbGciOiJFUzI1NiJ9.secret.sig")
				assert.NotContains(t, text, "sess-handle-0123456789")
			},
		},
		{
			name: "a gate challenge carries the session and no token",
			err: &httpsec.ChallengeError{
				Kind:    policy.ChallengePasswordChange,
				Session: &session.Session{ID: "sess-handle-0123456789"},
			},
			assert: func(t *testing.T, text string) {
				assert.Contains(t, text, policy.ChallengePasswordChange.String())
				assert.NotContains(t, text, "sess-handle-0123456789")
			},
		},
		{
			name: "a stateless challenge carries neither",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeMFA},
			assert: func(t *testing.T, text string) {
				assert.Contains(t, text, policy.ChallengeMFA.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.err.Error())
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestChallengeError -count=1 ./httpsec/`
Declare `ChallengeError` with `Error()` returning `""`, so the test compiles. Expected: FAIL on `assert.Contains` — the text names no kind.

To be sure the test can catch a leak, temporarily implement `Error()` as `fmt.Sprintf("%s %s %s", e.Kind, e.Token, e.Session.ID)` and re-run: the `NotContains` rows must fail. Restore the stub before implementing.

- [ ] **Step 3: Implement**

```go
package httpsec

import (
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// The refusals this package defines itself. Every other refusal a consumer
// sees comes from the core that decided it — authenticate, authorize, policy
// or session — and this package neither restates nor renames those.
var (
	// ErrAuthenticationRequired refuses a request that presented nothing to
	// authenticate with, or whose session no longer exists, expired, or could
	// not be read. It is deliberately the same refusal in all of those cases:
	// telling them apart would say whether a session ever existed.
	//
	// authorize exports a refusal of the same name for an anonymous request
	// that matched a rule requiring authentication. The authorization stage
	// wraps that one with this, so a consumer matching either identity reaches
	// both and does not have to know which stage refused.
	ErrAuthenticationRequired = errors.New("httpsec: authentication required")

	// ErrCredentialsMissing refuses a login that carried no credentials, or a
	// JSON body that could not be decoded. It is the client's mistake, so it
	// maps to 400, and it says nothing about the account.
	ErrCredentialsMissing = errors.New("httpsec: missing or unreadable login credentials")

	// ErrRequestTooLarge refuses a body over the configured bound before it is
	// parsed.
	ErrRequestTooLarge = errors.New("httpsec: request too large")
)

// ChallengeError refuses a request that must satisfy a challenge before it
// goes further.
//
// It carries what the consumer's error handling needs to prompt for: the kind
// asked for, the pending session when one was established, and the token
// issued alongside it when the challenge was raised at login. Its text names
// only the kind — a challenge is reported to a client, and a token or a
// session handle written into an error string reaches every log that records
// one.
type ChallengeError struct {
	Kind    policy.ChallengeKind
	Session *session.Session // nil for a stateless first factor
	Token   string           // set only when one was issued at login
}

// Error names the challenge kind and nothing else. The session handle and the
// token are fields, not text.
func (e *ChallengeError) Error() string {
	return fmt.Sprintf("httpsec: challenge required: %s", e.Kind)
}
```

- [ ] **Step 4: Run it and confirm it passes**

Run: `go test -run TestChallengeError -count=1 ./httpsec/` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add httpsec/errors.go httpsec/errors_test.go
git commit -m "feat(httpsec): the refusals this package defines and the challenge error

A challenge carries the session and token as fields; its text names only the
kind, so neither reaches a log that records the error."
```

---

## Task 5: The public status table

**Implements:** tasks.md 2.2, 2.3, 2.4

**Files:**
- Create: `httpsec/status.go`, `httpsec/logincomplete.go` (only `policyDenyReason` here)
- Test: `httpsec/status_test.go`

**Interfaces:**
- Produces: `StatusForError(err error) int`, and unexported `policyDenyReason(d policy.Decision) error`. Every default response, every guard and both framework adapters call `StatusForError`.

The table, from `specs/http-error-propagation/spec.md`, with `policy.ErrPolicyDenied` standing in for "refused by policy without a reason":

| Refusal | Status |
|---|---|
| `ErrAuthenticationRequired`, `authorize.ErrAuthenticationRequired`, `authenticate.ErrAuthenticationFailed`, `policy.ErrSessionIdle`, `ratelimit.ErrThrottled` | 401 |
| `*ChallengeError` of kind `policy.ChallengePasswordChange` | 403 |
| `*ChallengeError` of any other kind | 401 |
| `authorize.ErrAccessDenied`, `policy.ErrPolicyDenied`, `policy.ErrMFARequired`, `policy.ErrMFARequirementUnsatisfiable`, `policy.ErrMFAEnrollmentRequired`, `policy.ErrSecondFactorSameChannel` | 403 |
| `ErrCredentialsMissing` | 400 |
| `ErrRequestTooLarge` | 413 |
| `policy.ErrAccountLocked` | 423 |
| `policy.ErrTooManySessions` | 429 |
| anything else | 500 |

Confirm each sentinel's exact name with `go doc ./authorize` and `go doc ./policy` before writing the table; `authorize`'s access-denied sentinel name is elided in the package summary.

- [ ] **Step 1: Write the failing characterization table**

```go
func TestStatusForError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		err  error
		want int
	}

	cases := []testCase{
		{name: "authentication required", err: httpsec.ErrAuthenticationRequired, want: 401},
		{name: "authorize's authentication required", err: authorize.ErrAuthenticationRequired, want: 401},
		{
			name: "the stage's wrap matches both identities",
			err:  fmt.Errorf("%w: %w", httpsec.ErrAuthenticationRequired, authorize.ErrAuthenticationRequired),
			want: 401,
		},
		{name: "authentication failed", err: authenticate.ErrAuthenticationFailed, want: 401},
		{name: "session idle", err: policy.ErrSessionIdle, want: 401},
		{name: "throttled source", err: ratelimit.ErrThrottled, want: 401},
		{name: "access denied", err: authorize.ErrAccessDenied, want: 403},
		{name: "reasonless policy deny", err: policy.ErrPolicyDenied, want: 403},
		{name: "second factor required", err: policy.ErrMFARequired, want: 403},
		{name: "second factor unsatisfiable", err: policy.ErrMFARequirementUnsatisfiable, want: 403},
		{name: "second factor enrolment required", err: policy.ErrMFAEnrollmentRequired, want: 403},
		{name: "second factor on the first factor's channel", err: policy.ErrSecondFactorSameChannel, want: 403},
		{name: "malformed login", err: httpsec.ErrCredentialsMissing, want: 400},
		{name: "request too large", err: httpsec.ErrRequestTooLarge, want: 413},
		{name: "account locked", err: policy.ErrAccountLocked, want: 423},
		{name: "too many sessions", err: policy.ErrTooManySessions, want: 429},

		{
			name: "wrapped sentinel keeps its status",
			err:  fmt.Errorf("evaluating the rule set: %w", authorize.ErrAccessDenied),
			want: 403,
		},
		{
			name: "joined verification failure keeps its status",
			err:  errors.Join(authenticate.ErrAuthenticationFailed, errors.New("token: signature invalid")),
			want: 401,
		},
		{
			name: "second-factor challenge",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengeMFA},
			want: 401,
		},
		{
			name: "password-change challenge",
			err:  &httpsec.ChallengeError{Kind: policy.ChallengePasswordChange},
			want: 403,
		},
		{
			name: "a challenge outranks a sentinel it wraps",
			err: fmt.Errorf("%w: %w",
				&httpsec.ChallengeError{Kind: policy.ChallengeMFA}, authorize.ErrAccessDenied),
			want: 401,
		},
		{
			name: "an unrecognised error is a server fault",
			err:  errors.New("connection refused to db-primary:5432"),
			want: 500,
		},
		{name: "nil is a server fault", err: nil, want: 500},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, httpsec.StatusForError(tc.err))
		})
	}
}
```

This table has no `assert` closure because every row asserts one comparable `int` — the `table-test` skill's closure rule exists for results that are not trivially comparable, and a status code is. Every other table in this plan uses the closure form.

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestStatusForError -count=1 ./httpsec/`
Stub `StatusForError` to `return http.StatusInternalServerError`. Expected: FAIL on every row but the two 500 rows, each naming the status it wanted. Read the output and confirm that is what failed.

- [ ] **Step 3: Implement**

```go
package httpsec

import (
	"errors"
	"net/http"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// statusRow is one refusal and the status it answers with. The table is
// ordered, and the first row whose sentinel the error matches decides, so two
// rows can never disagree about an error that wraps both.
type statusRow struct {
	err    error
	status int
}

var statusTable = []statusRow{
	{ErrAuthenticationRequired, http.StatusUnauthorized},
	{authorize.ErrAuthenticationRequired, http.StatusUnauthorized},
	{authenticate.ErrAuthenticationFailed, http.StatusUnauthorized},
	{policy.ErrSessionIdle, http.StatusUnauthorized},
	{ratelimit.ErrThrottled, http.StatusUnauthorized},

	{ErrCredentialsMissing, http.StatusBadRequest},
	{ErrRequestTooLarge, http.StatusRequestEntityTooLarge},
	{policy.ErrAccountLocked, http.StatusLocked},
	{policy.ErrTooManySessions, http.StatusTooManyRequests},

	{authorize.ErrAccessDenied, http.StatusForbidden},
	{policy.ErrPolicyDenied, http.StatusForbidden},
	{policy.ErrMFARequired, http.StatusForbidden},
	{policy.ErrMFARequirementUnsatisfiable, http.StatusForbidden},
	{policy.ErrMFAEnrollmentRequired, http.StatusForbidden},
	{policy.ErrSecondFactorSameChannel, http.StatusForbidden},
}

// StatusForError maps a refusal to the status it is answered with.
//
// It is the whole mapping contract: every default response this library
// writes, and every helper the integrations offer, goes through it, so a
// consumer's own error handler can fall back to it and agree with the library
// on everything it does not handle itself. It recognises wrapped and joined
// errors, and an error it does not recognise is a server fault, never a
// silent success.
//
// A challenge is checked first, so a challenge that also wraps a refusal
// sentinel is answered as the challenge: the caller can still satisfy it.
func StatusForError(err error) int {
	if err == nil {
		return http.StatusInternalServerError
	}

	var ch *ChallengeError
	if errors.As(err, &ch) {
		if ch.Kind == policy.ChallengePasswordChange {
			return http.StatusForbidden
		}
		return http.StatusUnauthorized
	}

	for _, row := range statusTable {
		if errors.Is(err, row.err) {
			return row.status
		}
	}

	return http.StatusInternalServerError
}
```

And in `httpsec/logincomplete.go`:

```go
// policyDenyReason is the error a deny is refused with.
//
// policy.Engine already guarantees a deny carries a reason, substituting
// policy.ErrPolicyDenied where the policy left it nil, so this is a named
// reader rather than a fallback: every deny site refuses with the reason the
// engine reduced to, and none of them returns nil for a refusal.
func policyDenyReason(d policy.Decision) error { return d.Reason }
```

- [ ] **Step 4: Run it and confirm it passes**

Run: `go test -run TestStatusForError -count=1 ./httpsec/` — Expected: PASS.

- [ ] **Step 5: Write the failing enumeration test**

This is the test that keeps the table honest as other changes add sentinels. It parses the mapped packages' exported `Err*` variables and fails on one the table does not recognise.

```go
// TestStatusForErrorCoversEverySentinel fails when a mapped package exports a
// refusal sentinel StatusForError does not recognise. A new sentinel is then a
// deliberate decision about its status, not an accidental 500.
func TestStatusForErrorCoversEverySentinel(t *testing.T) {
	t.Parallel()

	// Sentinels that are deliberately unmapped, each with the reason. A
	// configuration error is a wiring fault the consumer sees at construction,
	// never a refusal a client is answered with.
	unmapped := map[string]string{
		"authenticate.ErrConfig":                  "a wiring fault, refused at construction",
		"authenticate.ErrNoEligibleAuthenticator": "a wiring fault: nothing was configured to judge the credentials",
		"authenticate.ErrUnsupportedCredentials":  "internal dispatch between providers, never returned to a client",
		"authorize.ErrConfig":                     "a wiring fault, refused at construction",
		"authorize.ErrUnsupportedAttributes":      "a misbuilt guard, deliberately 500 per design Decision 7",
		"authorize.ErrInvalidAttributes":          "a misbuilt guard, deliberately 500 per design Decision 7",
		"session.ErrSessionNotFound":              "converted to ErrAuthenticationRequired before it leaves the chain",
		"session.ErrSessionExpired":               "converted to ErrAuthenticationRequired before it leaves the chain",
		"session.ErrSessionUnreadable":            "converted to ErrAuthenticationRequired before it leaves the chain",
		"ratelimit.ErrSourceUnattributable":       "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"ratelimit.ErrSourceEmpty":                "converted to authenticate.ErrAuthenticationFailed before it leaves the chain",
		"policy.ErrConfig":                        "a wiring fault, refused at construction",
		"policy.ErrReapUnsupported":               "a maintenance-path fault, not a request refusal",
		"policy.ErrRetainSinceRequired":           "a maintenance-path fault, not a request refusal",
		"policy.ErrMFARequirementLookupMissing":   "a wiring fault, refused at construction",
		"ratelimit.ErrConfig":                     "a wiring fault, refused at construction",
		"session.ErrConfig":                       "a wiring fault, refused at construction",
	}

	for _, pkg := range []string{
		"github.com/kartaladev/scrty/authenticate",
		"github.com/kartaladev/scrty/authorize",
		"github.com/kartaladev/scrty/policy",
		"github.com/kartaladev/scrty/ratelimit",
		"github.com/kartaladev/scrty/session",
	} {
		for name, err := range exportedSentinels(t, pkg) {
			if _, ok := unmapped[name]; ok {
				continue
			}
			t.Run(name, func(t *testing.T) {
				assert.NotEqual(t, http.StatusInternalServerError, httpsec.StatusForError(err),
					"%s is exported as a refusal but StatusForError does not recognise it; "+
						"add it to statusTable, or to this test's unmapped map with the reason", name)
			})
		}
	}
}
```

`exportedSentinels` is a helper in the same file. Reflection cannot enumerate package-level variables, so build it as an explicit registry that each package's sentinels are listed in, and pair it with a `go/packages` scan that fails when a package exports an `Err*` the registry does not list — that way adding a sentinel anywhere fails here rather than silently mapping to 500:

```go
// exportedSentinels returns every exported Err* variable of pkg, keyed
// "<pkg>.<Name>". It cross-checks the registry against the package's source,
// so a sentinel added without being registered fails the test rather than
// being skipped.
func exportedSentinels(t *testing.T, pkg string) map[string]error {
	t.Helper()

	registered := sentinelRegistry[pkg]
	require.NotEmpty(t, registered, "no sentinels registered for %s", pkg)

	declared := declaredErrVars(t, pkg) // go/packages: names of exported Err* vars
	for _, name := range declared {
		_, ok := registered[path.Base(pkg)+"."+name]
		assert.True(t, ok, "%s.%s is exported but not registered in sentinelRegistry", pkg, name)
	}

	return registered
}
```

- [ ] **Step 6: Run it and confirm the red step**

Run: `go test -run TestStatusForErrorCoversEverySentinel -count=1 ./httpsec/`
First see it fail on purpose: comment the `{policy.ErrTooManySessions, http.StatusTooManyRequests}` row out of `statusTable` and re-run. Expected: FAIL naming `policy.ErrTooManySessions`. Restore the row and confirm PASS. Then delete one entry from `sentinelRegistry` and confirm the registry cross-check fails too.

- [ ] **Step 7: Run the whole file and commit**

Run: `go test -run 'TestStatusForError|TestPolicyDenyReason' -count=1 ./httpsec/` — Expected: PASS.

```bash
git add httpsec/status.go httpsec/status_test.go httpsec/logincomplete.go
git commit -m "feat(httpsec): one public table maps a refusal to a status

A challenge is read before the sentinels, so a challenge wrapping a refusal is
still answered as the challenge. An enumeration test fails when a mapped
package exports a sentinel the table does not recognise."
```

---

## Task 6: Slots

**Implements:** tasks.md 3.1

**Files:**
- Create: `httpsec/order.go`
- Test: `httpsec/order_test.go`

**Interfaces:**
- Produces: `Order int`, the constants of design Decision 2, `Before(o Order) Order`, `After(o Order) Order`, and `RegisterInterceptor(i Interceptor, at Order) Option` (the `Option` type itself lands in Task 8; declare it here as `type Option func(*config) error` and let Task 8 fill `config`).

- [ ] **Step 1: Write the failing test**

```go
func TestOrder(t *testing.T) {
	t.Parallel()

	t.Run("every named slot leaves its neighbours free", func(t *testing.T) {
		t.Parallel()

		named := map[httpsec.Order]string{
			httpsec.OrderJWKS: "JWKS", httpsec.OrderOIDC: "OIDC",
			httpsec.OrderFormLogin: "FormLogin", httpsec.OrderMagicLink: "MagicLink",
			httpsec.OrderBasicAuth: "BasicAuth", httpsec.OrderAPIKey: "APIKey",
			httpsec.OrderMTLS: "MTLS", httpsec.OrderBearerToken: "BearerToken",
			httpsec.OrderMFAChallenge: "MFAChallenge", httpsec.OrderPasswordChange: "PasswordChange",
			httpsec.OrderLogout: "Logout", httpsec.OrderSessionTouch: "SessionTouch",
			httpsec.OrderAuthorizer: "Authorizer",
		}

		for slot, name := range named {
			_, beforeTaken := named[httpsec.Before(slot)]
			_, afterTaken := named[httpsec.After(slot)]
			assert.False(t, beforeTaken, "the slot before %s is taken by another built-in", name)
			assert.False(t, afterTaken, "the slot after %s is taken by another built-in", name)
		}
	})

	t.Run("Before and After land either side", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, httpsec.Order(499), httpsec.Before(httpsec.OrderBearerToken))
		assert.Equal(t, httpsec.Order(501), httpsec.After(httpsec.OrderBearerToken))
	})

	t.Run("the plugin slots sit where the spec says", func(t *testing.T) {
		t.Parallel()
		// "an interceptor at the one-time link slot runs after form login and
		// before Basic authentication"
		assert.Greater(t, httpsec.OrderMagicLink, httpsec.OrderFormLogin)
		assert.Less(t, httpsec.OrderMagicLink, httpsec.OrderBasicAuth)
	})
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestOrder -count=1 ./httpsec/`
Declare the constants all equal to `0` first. Expected: FAIL on the neighbour check, because every slot collides. That proves the test notices a collision.

- [ ] **Step 3: Implement**

```go
package httpsec

// Order is an interceptor's position in the chain. The lowest order is
// outermost, so an interceptor with a lower order wraps every one above it and
// the downstream handler is innermost.
//
// The named slots are spaced by at least twenty-five, and the slots either side
// of each are left free, so a consumer can register immediately before or
// after any built-in with Before and After without choosing a number that a
// later scrty release might want.
type Order int

const (
	OrderJWKS           Order = 100
	OrderOIDC           Order = 200 // oidc-brokering: authorize, callback, handoff
	OrderFormLogin      Order = 300
	OrderMagicLink      Order = 350 // auth-methods: request and redemption
	OrderBasicAuth      Order = 400
	OrderAPIKey         Order = 450 // auth-methods
	OrderMTLS           Order = 475 // reserved for client certificates
	OrderBearerToken    Order = 500
	OrderMFAChallenge   Order = 600 // auth-methods: verify endpoint and pending gate
	OrderPasswordChange Order = 650
	OrderLogout         Order = 700
	OrderSessionTouch   Order = 800
	OrderAuthorizer     Order = 900
)

// Before is the slot immediately outside o, which runs just before it.
func Before(o Order) Order { return o - 1 }

// After is the slot immediately inside o, which runs just after it and before
// the next named slot.
func After(o Order) Order { return o + 1 }
```

- [ ] **Step 4: Run it and confirm it passes**

Run: `go test -run TestOrder -count=1 ./httpsec/` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add httpsec/order.go httpsec/order_test.go
git commit -m "feat(httpsec): the chain's named slots

The slots either side of each built-in are left free, so a consumer registers
immediately before or after one without picking a number a later release wants."
```

---

## Task 7: Assembly and continuation

**Implements:** tasks.md 3.2, 3.3

**Files:**
- Create: `httpsec/chain.go`
- Test: `httpsec/chain_test.go`

**Interfaces:**
- Consumes: `Order`, `Interceptor`, `Next`, `Exchange`.
- Produces: `Chain` (struct with an unexported ordered `[]registration`), `(*Chain).Assemble(terminal Next) Next`. Every integration calls `Assemble`.

- [ ] **Step 1: Write the failing ordering and continuation table**

```go
func TestChainAssemble(t *testing.T) {
	t.Parallel()

	// recorder appends a name as the interceptor is entered and again, with a
	// "-after" suffix, once everything inside it has returned. The resulting
	// slice shows both the order and the nesting.
	type testCase struct {
		name     string
		register func(c *chainBuilder)
		assert   func(t *testing.T, trace []string, err error)
	}

	cases := []testCase{
		{
			name: "ascending slot order, lowest outermost",
			register: func(c *chainBuilder) {
				c.at(500, "five")
				c.at(100, "one")
				c.at(300, "three")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"one", "three", "five", "handler",
					"five-after", "three-after", "one-after",
				}, trace)
			},
		},
		{
			name: "equal slots keep registration order",
			register: func(c *chainBuilder) {
				c.at(400, "first")
				c.at(400, "second")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"first", "second", "handler", "second-after", "first-after"}, trace)
			},
		},
		{
			name: "Before and After bracket a named slot",
			register: func(c *chainBuilder) {
				c.at(int(httpsec.OrderBearerToken), "bearer")
				c.at(int(httpsec.After(httpsec.OrderBearerToken)), "audit")
				c.at(int(httpsec.Before(httpsec.OrderBearerToken)), "pre")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"pre", "bearer", "audit", "handler",
					"audit-after", "bearer-after", "pre-after",
				}, trace)
			},
		},
		{
			name: "an interceptor that does not continue stops the request",
			register: func(c *chainBuilder) {
				c.at(100, "outer")
				c.stopAt(300, "gate")
				c.at(500, "inner")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"outer", "gate", "outer-after"}, trace)
				assert.NotContains(t, trace, "inner")
				assert.NotContains(t, trace, "handler")
			},
		},
		{
			name: "an error propagates outward unchanged",
			register: func(c *chainBuilder) {
				c.at(100, "outer")
				c.failAt(900, "deep", errSentinel)
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.ErrorIs(t, err, errSentinel)
				assert.Equal(t, []string{"outer", "deep", "outer-after"}, trace)
			},
		},
		{
			name: "the post-handler step runs after the handler wrote",
			register: func(c *chainBuilder) {
				c.at(800, "touch")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"touch", "handler", "touch-after"}, trace)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newChainBuilder()
			tc.register(b)

			run := b.chain().Assemble(func(ex *httpsec.Exchange) error {
				b.record("handler")
				return nil
			})
			err := run(httpsec.NewExchange(t.Context(), stubRequest{}, &stubWriter{}))
			tc.assert(t, b.trace(), err)
		})
	}
}
```

`chainBuilder` is a test helper in the same file holding a mutex-guarded `[]string` and the registrations; `at` registers a recording interceptor that calls `next`, `stopAt` one that returns `nil` without calling it, and `failAt` one that returns the given error without calling it.

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestChainAssemble -count=1 ./httpsec/`
Stub `Assemble` to return the terminal unchanged. Expected: FAIL on the first row — the trace is `["handler"]`, so no interceptor ran. Read the diff and confirm that is the failure.

- [ ] **Step 3: Implement**

```go
package httpsec

import "slices"

// registration is one interceptor and the slot it was registered at, with the
// sequence it was registered in so a stable sort keeps equal slots in order.
type registration struct {
	interceptor Interceptor
	order       Order
	seq         int
}

// Chain is the assembled security chain. It is built once by New and is safe
// for concurrent use: assembly reads the registrations and never writes them.
type Chain struct {
	registrations []registration
	// the rest is filled in by Task 8
}

// Assemble folds the chain around terminal and returns the outermost step.
//
// Interceptors run in ascending slot order with the lowest outermost, so the
// fold runs backwards: the last interceptor wraps the terminal and each
// earlier one wraps what has been built so far.
func (c *Chain) Assemble(terminal Next) Next {
	regs := slices.Clone(c.registrations)
	slices.SortStableFunc(regs, func(a, b registration) int {
		if a.order != b.order {
			return int(a.order - b.order)
		}
		return a.seq - b.seq
	})

	next := terminal
	for i := len(regs) - 1; i >= 0; i-- {
		inner := next
		interceptor := regs[i].interceptor
		next = func(ex *Exchange) error { return interceptor.Intercept(ex, inner) }
	}
	return next
}
```

Continuation needs no code of its own: an interceptor stops by not calling `next`, and an error returns through every enclosing frame unchanged because no frame in `Assemble` inspects it.

- [ ] **Step 4: Run it and confirm it passes**

Run: `go test -race -run TestChainAssemble -count=1 ./httpsec/` — Expected: PASS. Run under `-race` because the trace slice is shared across the fold.

- [ ] **Step 5: Commit**

```bash
git add httpsec/chain.go httpsec/chain_test.go
git commit -m "feat(httpsec): assemble the chain around the handler

A stable sort by slot then registration order, folded backwards, so the lowest
slot is outermost and an error returns through every frame unchanged."
```

---

## Task 8: Construction, validation and context derivation

**Implements:** tasks.md 3.4, 3.5, 3.6

**Files:**
- Create: `httpsec/options.go`, `httpsec/context.go`
- Modify: `httpsec/chain.go`
- Test: `httpsec/options_test.go`, `httpsec/context_test.go`

**Interfaces:**
- Consumes: `internal/nilcheck.IsNil`, `Order`, `Interceptor`.
- Produces: `Option func(*config) error`, `New(opts ...Option) (*Chain, error)`, `RegisterInterceptor(i Interceptor, at Order) Option`, `WithPolicyEngine(*policy.Engine) Option`, `WithLogger(*slog.Logger) Option`, `WithRateLimiter(ratelimit.Limiter) Option`, `WithIPv6SourcePrefix(int) Option`, and the context helpers `withSession(ctx, *session.Session) context.Context` / `SessionFromContext(ctx) (*session.Session, bool)`. Later tasks add their own `Enable*` options to `config`.

- [ ] **Step 1: Write the failing construction-refusal table**

One row per refusal in design Decision 4. Every row asserts the error names the option **and** the dependency, because "construction failed" without a name sends the consumer reading library source.

```go
func TestNewRefusesWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "form login without a session manager",
			opts: []httpsec.Option{
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authentication: &authenticate.Manager{},
					Tokens:         stubGenerator{},
					Attempts:       policy.NewMemoryAttemptStore(),
					// Sessions deliberately absent.
				}),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.Error(t, err)
				assert.Nil(t, c, "no usable chain may be returned alongside a configuration error")
				assert.Contains(t, err.Error(), "EnableFormLogin")
				assert.Contains(t, err.Error(), "session manager")
			},
		},
		{
			name: "a dependency present but holding a typed nil",
			opts: []httpsec.Option{
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Users:    (*stubUserLoader)(nil), // non-nil interface, nil pointer
					Sessions: &session.Manager{},
					Verifier: stubVerifier{},
				}),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.Error(t, err)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "EnableBearerToken")
				assert.Contains(t, err.Error(), "user loader")
			},
		},
		{
			name: "a nil interceptor",
			opts: []httpsec.Option{httpsec.RegisterInterceptor(nil, httpsec.OrderBearerToken)},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
			},
		},
		{
			name: "a nil rate limiter",
			opts: []httpsec.Option{httpsec.WithRateLimiter(nil)},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "WithRateLimiter")
			},
		},
		{
			name: "a nil refusal log reporter",
			opts: []httpsec.Option{httpsec.WithRefusalLogReporter(nil)},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "WithRefusalLogReporter")
			},
		},
		{
			name: "a login body limit of zero",
			opts: []httpsec.Option{
				httpsec.EnableFormLogin(validFormLoginDeps(t), httpsec.WithLoginBodyLimit(0)),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "WithLoginBodyLimit")
			},
		},
		{
			name: "an IPv6 source prefix outside 1..128",
			opts: []httpsec.Option{httpsec.WithIPv6SourcePrefix(129)},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "WithIPv6SourcePrefix")
			},
		},
		{
			name: "the minimum wiring succeeds",
			opts: []httpsec.Option{},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "a consumer who wires nothing must still get a usable chain")
				assert.NotNil(t, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts...)
			tc.assert(t, c, err)
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step, row by row**

Run: `go test -run TestNewRefusesWiring -count=1 ./httpsec/`
Stub `New` to `return &Chain{}, nil`. Expected: every refusal row FAILs on `require.Error`, and the last row passes. **Each row must be seen failing**; do not implement the checks in one pass and run once. Implement one check, re-run, watch that row go green and the rest stay red.

The typed-nil row deserves its own confirmation that it tests what it claims: with `nilcheck.IsNil` replaced by a plain `== nil`, that row must fail. Try it, see it fail, restore.

- [ ] **Step 3: Implement**

```go
package httpsec

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
)

// ErrConfig is the wiring fault every option refuses with. It never reaches a
// client: a chain that does not build serves no traffic.
var ErrConfig = errors.New("httpsec: invalid configuration")

// config accumulates what the options set. New validates it and only then
// builds a Chain, so a chain that exists is one whose every option took effect.
type config struct {
	registrations []registration
	seq           int

	engine  *policy.Engine
	logger  *slog.Logger
	limiter ratelimit.Limiter

	ipv6Prefix    int
	ipv6PrefixSet bool

	refusalInterval time.Duration
	refusalReporter func(key string, suppressed int)
	reporterSet     bool

	formLogin *formLoginConfig // nil when not enabled; likewise for each built-in
	// ... one field per Enable* option, added by the task that adds the option
}

// Option configures the chain. Every option either takes effect or is refused
// by New: none is documented away, and none is silently ignored.
type Option func(*config) error

// RegisterInterceptor runs i at slot at.
//
// A consumer registers at any slot, including Before or After a named one. To
// replace a built-in, leave it disabled and register your own at its slot.
//
// A nil interceptor is refused: without the check it panics on every request,
// and on fiber an unrecovered handler panic ends the process.
func RegisterInterceptor(i Interceptor, at Order) Option {
	return func(c *config) error {
		if nilcheck.IsNil(i) {
			return fmt.Errorf("%w: RegisterInterceptor was given no interceptor for slot %d", ErrConfig, at)
		}
		c.seq++
		c.registrations = append(c.registrations, registration{interceptor: i, order: at, seq: c.seq})
		return nil
	}
}

// New builds the chain. It applies every option, then validates what they set,
// and returns no chain at all when anything cannot take effect.
func New(opts ...Option) (*Chain, error) {
	c := &config{
		logger:          slog.Default(),
		refusalInterval: time.Minute,
		ipv6Prefix:      64,
	}

	for _, opt := range opts {
		if opt == nil {
			continue // a consumer building the slice conditionally need not filter it
		}
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if err := c.validate(); err != nil {
		return nil, err
	}

	return c.build()
}

// validate reports the first wiring fault, naming the option and the
// dependency at fault so the consumer fixes it without reading library source.
func (c *config) validate() error {
	if c.ipv6PrefixSet && (c.ipv6Prefix < 1 || c.ipv6Prefix > 128) {
		return fmt.Errorf("%w: WithIPv6SourcePrefix takes a prefix length in 1..128, got %d",
			ErrConfig, c.ipv6Prefix)
	}
	if c.reporterSet && c.refusalReporter == nil {
		return fmt.Errorf("%w: WithRefusalLogReporter was given no reporter; "+
			"omit it to keep the default summary reporter", ErrConfig)
	}
	// One block per enabled built-in, added by the task that adds it. Each
	// reports through requireDep so every message reads the same way.
	if c.formLogin != nil {
		if err := c.formLogin.validate(); err != nil {
			return err
		}
	}
	return nil
}

// requireDep refuses a dependency that is absent, or present but holding a
// typed nil. (*T)(nil) inside an interface is not nil to ==, and would panic on
// the first request instead of failing here.
func requireDep(option, dependency string, v any) error {
	if nilcheck.IsNil(v) {
		return fmt.Errorf("%w: %s needs a %s", ErrConfig, option, dependency)
	}
	return nil
}
```

And `httpsec/context.go`:

```go
package httpsec

import (
	"context"

	"github.com/kartaladev/scrty/session"
)

// sessionKey is this package's own context key. session exports no context
// helper of its own, and an unexported key type means no other package can
// collide with it or overwrite what the chain published.
type sessionKey struct{}

// withSession publishes s so every later interceptor and the handler read it.
func withSession(ctx context.Context, s *session.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// SessionFromContext returns the session the chain resolved for this request.
// It reports an absent session as absent rather than as an empty one, so a
// caller that ignores ok is not handed something it could mistake for a live
// session.
func SessionFromContext(ctx context.Context) (*session.Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*session.Session)
	return s, ok && s != nil
}
```

- [ ] **Step 4: Run it and confirm it passes**

Run: `go test -run TestNewRefusesWiring -count=1 ./httpsec/` — Expected: PASS.

- [ ] **Step 5: Write the failing context-derivation test**

```go
func TestChainContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, seen context.Context, err error)
	}

	cases := []testCase{
		{
			name: "an upstream value survives the chain",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-7")
			},
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)
				assert.Equal(t, "r-7", seen.Value(ctxKey("request-id")))
			},
		},
		{
			name: "state an interceptor adds reaches the handler",
			assert: func(t *testing.T, seen context.Context, err error) {
				require.NoError(t, err)
				s, ok := httpsec.SessionFromContext(seen)
				require.True(t, ok)
				assert.Equal(t, "sess-1", s.ID)
			},
		},
		{
			name: "cancellation reaches an in-flight lookup",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, seen context.Context, err error) {
				require.ErrorIs(t, seen.Err(), context.Canceled)
			},
		},
	}
	// Each case assembles a chain with one interceptor that publishes a
	// session and calls next, and a terminal that captures ex.Context().
}
```

- [ ] **Step 6: Run it, confirm the red step, and implement**

Run: `go test -run TestChainContext -count=1 ./httpsec/` — Expected: FAIL on the session row, because nothing publishes it yet. The publishing interceptor is the test's own, so the production change is only that `Assemble` never replaces `ex.ctx` itself.

- [ ] **Step 7: Gate and commit**

Run: `go test -race -count=1 ./httpsec/`, `go vet ./httpsec/`, `gofmt -l httpsec/`, `golangci-lint run ./httpsec/...`.

```bash
git add httpsec/options.go httpsec/context.go httpsec/chain.go httpsec/options_test.go httpsec/context_test.go
git commit -m "feat(httpsec): a chain that does not build serves no traffic

Every option either takes effect or is refused by New, naming the option and
the dependency at fault; a dependency holding a typed nil is refused too."
```

---

## Task 9: Client address refusal

**Implements:** tasks.md 4.1

**Files:**
- Create: `httpsec/throttle.go`
- Test: `httpsec/throttle_test.go`

**Interfaces:**
- Produces: unexported `classifyAddress(addr string) (reason string, ok bool)` returning the sampler key suffix for a refusal (`"no-client-address"`, `"not-single-ip"`, `"unspecified-address"`) and `ok` when the address may be keyed on.

- [ ] **Step 1: Write the failing table**

```go
func TestClassifyAddress(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		addr   string
		assert func(t *testing.T, reason string, ok bool)
	}

	accepted := func(t *testing.T, reason string, ok bool) {
		t.Helper()
		assert.True(t, ok)
		assert.Empty(t, reason)
	}
	refused := func(want string) func(t *testing.T, reason string, ok bool) {
		return func(t *testing.T, reason string, ok bool) {
			t.Helper()
			assert.False(t, ok)
			assert.Equal(t, want, reason)
		}
	}

	cases := []testCase{
		{name: "an ordinary IPv4 peer", addr: "198.51.100.7", assert: accepted},
		{name: "an ordinary IPv6 peer", addr: "2001:db8::1", assert: accepted},
		{name: "empty", addr: "", assert: refused("no-client-address")},
		{name: "a list, as a forwarding header yields", addr: "203.0.113.9, 198.51.100.7",
			assert: refused("not-single-ip")},
		{name: "a hostname", addr: "proxy.internal", assert: refused("not-single-ip")},
		{name: "host and port", addr: "198.51.100.7:51234", assert: refused("not-single-ip")},
		{name: "IPv4 unspecified", addr: "0.0.0.0", assert: refused("unspecified-address")},
		{name: "IPv6 unspecified", addr: "::", assert: refused("unspecified-address")},
		{name: "IPv4-mapped unspecified", addr: "::ffff:0.0.0.0", assert: refused("unspecified-address")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reason, ok := httpsec.ClassifyAddressForTest(tc.addr)
			tc.assert(t, reason, ok)
		})
	}
}
```

`classifyAddress` is unexported, so expose it to the external test package through an `export_test.go` in package `httpsec`: `var ClassifyAddressForTest = classifyAddress`. That file is a test file, so nothing exported by it reaches a consumer.

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestClassifyAddress -count=1 ./httpsec/`
Stub it to `return "", true`. Expected: every refusal row FAILs on `assert.False(t, ok)`; the two accepted rows pass.

- [ ] **Step 3: Implement**

```go
// classifyAddress decides whether addr may key a rate-limit bucket.
//
// fasthttp reports 0.0.0.0 for every non-TCP peer, so keying on an unspecified
// address pools unrelated clients into one bucket and lets any of them exhaust
// it for all the others. An address that is not exactly one IP has the same
// problem, and an empty one names nobody at all. Each is refused rather than
// pooled, and the reason becomes the sampler key so an operator sees which of
// the three is happening.
func classifyAddress(addr string) (reason string, ok bool) {
	if addr == "" {
		return "no-client-address", false
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "not-single-ip", false
	}
	if ip.Unmap().IsUnspecified() {
		return "unspecified-address", false
	}
	return "", true
}
```

`Unmap` is what makes `::ffff:0.0.0.0` refuse: `IsUnspecified` alone is false for the mapped form.

- [ ] **Step 4: Run it, confirm PASS, and commit**

Run: `go test -run TestClassifyAddress -count=1 ./httpsec/`

```bash
git add httpsec/throttle.go httpsec/throttle_test.go httpsec/export_test.go
git commit -m "feat(httpsec): an unattributable client address is refused, never pooled

An empty, non-single-IP or unspecified address would key one bucket for
unrelated clients, so it refuses instead, naming which of the three it was."
```

---

## Task 10: The source throttle seam

**Implements:** tasks.md 4.2

**Files:**
- Modify: `httpsec/throttle.go`
- Test: `httpsec/throttle_test.go`

**Interfaces:**
- Consumes: `ratelimit.SourceGuard`, `ratelimit.Limiter`, `classifyAddress`.
- Produces: `sourceThrottled(ctx, g *ratelimit.SourceGuard, clientIP, flow string, ...) (ratelimit.Source, error)` and `recordSourceFailure(ctx, g *ratelimit.SourceGuard, s ratelimit.Source, flow string)`. `auth-methods` and `oidc-brokering` build their redemption interceptors on these.

- [ ] **Step 1: Generate the limiter mock**

Add to `httpsec/throttle.go`:

```go
//go:generate mockgen -destination=limiter_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/ratelimit Limiter
```

Run `go generate ./httpsec/`. Confirm `limiter_mock_test.go` is a `_test.go` file in package `httpsec_test`, so `TestModuleLayout` stays green.

- [ ] **Step 2: Write the failing table**

```go
func TestSourceThrottle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		clientIP string
		limiter  func(t *testing.T, ctrl *gomock.Controller) *MockLimiter
		ctx      func(ctx context.Context) context.Context
		assert   func(t *testing.T, src ratelimit.Source, err error)
	}

	cases := []testCase{
		{
			name:     "an allowed source passes and carries its key",
			clientIP: "198.51.100.7",
			limiter:  limiterAllowing,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, src.Key())
			},
		},
		{
			name:     "a throttled source is refused",
			clientIP: "198.51.100.7",
			limiter:  limiterThrottling,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, ratelimit.ErrThrottled)
			},
		},
		{
			name:     "a limiter failure refuses too",
			clientIP: "198.51.100.7",
			limiter:  limiterFailing,
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed,
					"a limiter outage must read to the client as an ordinary failed attempt")
			},
		},
		{
			name:     "an unspecified address is refused before the limiter is asked",
			clientIP: "0.0.0.0",
			limiter: func(t *testing.T, ctrl *gomock.Controller) *MockLimiter {
				m := NewMockLimiter(ctrl)
				// No EXPECT: the limiter must not be consulted at all.
				return m
			},
			assert: func(t *testing.T, src ratelimit.Source, err error) {
				require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
				assert.Empty(t, src.Key(), "no bucket may be keyed on an unattributable address")
			},
		},
	}
	// Each case builds a SourceGuard over the mock and calls sourceThrottled.
}
```

- [ ] **Step 3: Run it and confirm the red step**

Run: `go test -run TestSourceThrottle -count=1 ./httpsec/` — Expected: FAIL. The unattributable row is the one to read carefully: gomock must report no unexpected call, and the assertion must fail on the error, not on the mock.

- [ ] **Step 4: Implement**

```go
// sourceThrottled checks the request's source before the guarded work runs.
//
// It refuses with authenticate.ErrAuthenticationFailed for an unattributable
// address and for a limiter outage alike, so a client cannot tell a refused
// source from a wrong credential — and so a source the chain cannot attribute
// never reaches the limiter to be pooled with others.
func sourceThrottled(
	ctx context.Context,
	g *ratelimit.SourceGuard,
	clientIP, flow string,
	s *logsample.Sampler,
	log *slog.Logger,
	now time.Time,
) (ratelimit.Source, error) {
	if reason, ok := classifyAddress(clientIP); !ok {
		logSampled(ctx, s, log, slog.LevelError, now, flow+"|"+reason,
			"httpsec: refusing a request whose client address cannot be attributed",
			slog.String("flow", flow), slog.String("reason", reason))
		return ratelimit.Source{}, authenticate.ErrAuthenticationFailed
	}

	src, err := g.Check(ctx, clientIP)
	switch {
	case errors.Is(err, ratelimit.ErrThrottled):
		logSampled(ctx, s, log, slog.LevelWarn, now, flow+"|"+src.Key(),
			"httpsec: source throttled",
			slog.String("flow", flow), slog.String("source", src.Key()))
		return src, err
	case err != nil:
		// A limiter that cannot answer has not said the source is within its
		// limit, so the request is refused rather than admitted unchecked.
		logSampled(ctx, s, log, slog.LevelError, now, flow,
			"httpsec: the rate limiter could not answer",
			slog.String("flow", flow), slog.Any("error", err))
		return ratelimit.Source{}, authenticate.ErrAuthenticationFailed
	}

	return src, nil
}

// recordSourceFailure counts a failure against the source that made it.
//
// It runs on a context the request's cancellation does not reach: a client
// that submits a wrong credential and disconnects before the response has
// still made the attempt, and a cancelled recording would let a guesser evade
// the limit by hanging up.
func recordSourceFailure(ctx context.Context, g *ratelimit.SourceGuard, s ratelimit.Source, flow string) {
	g.RecordFailure(context.WithoutCancel(ctx), s)
}
```

- [ ] **Step 5: Write the failing disconnect test**

The spec scenario "Client disconnects after guessing" is the one behaviour `WithoutCancel` exists for, so it gets its own case:

```go
func TestRecordSourceFailureSurvivesDisconnect(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Record(gomock.Any(), gomock.Any()).Times(1).
		DoAndReturn(func(ctx context.Context, _ ratelimit.Source) error {
			assert.NoError(t, ctx.Err(), "the recording must not see the client's cancellation")
			return nil
		})

	ctx, cancel := context.WithCancel(t.Context())
	guard := newGuard(t, limiter)
	src, err := httpsec.SourceThrottledForTest(ctx, guard, "198.51.100.7", "login", nil, slog.Default(), time.Now())
	require.NoError(t, err)

	cancel() // the client hangs up before the response
	httpsec.RecordSourceFailureForTest(ctx, guard, src, "login")
}
```

Confirm the mock's `Record` name and signature against `go doc ./ratelimit Limiter` before writing this; use whatever the interface actually declares.

- [ ] **Step 6: Run it, confirm the red step, implement, confirm PASS**

Red step: with plain `ctx` instead of `context.WithoutCancel(ctx)`, the `assert.NoError(t, ctx.Err())` inside the mock fails. See that, then switch to `WithoutCancel` and see it pass.

- [ ] **Step 7: Commit**

```bash
git add httpsec/throttle.go httpsec/throttle_test.go httpsec/limiter_mock_test.go httpsec/export_test.go
git commit -m "feat(httpsec): the source throttle seam redemption flows share

A failure is recorded on a context the client's disconnect does not cancel, so
hanging up after a wrong guess does not evade the limit."
```

---

## Task 11: Sampled refusal logs

**Implements:** tasks.md 4.3, 4.4, 4.5

**Files:**
- Create: `httpsec/refusallog.go`
- Modify: `httpsec/options.go`, `httpsec/chain.go`
- Test: `httpsec/refusallog_test.go`

**Interfaces:**
- Consumes: `logsample.New(window, opts...)`, `(*logsample.Sampler).Allow(key, now)`, `(*logsample.Sampler).Flush()`.
- Produces: `WithRefusalLogInterval(d time.Duration) Option`, `WithRefusalLogReporter(fn func(key string, suppressed int)) Option`, `(*Chain).FlushRefusalLogs()`, and unexported `logSampled(...)`.

- [ ] **Step 1: Write the failing windowing test**

Time-dependent, so it runs under `testing/synctest` with a captured `slog` handler:

```go
func TestRefusalLogSampling(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		interval time.Duration
		act      func(t *testing.T, s *logsample.Sampler, log *slog.Logger)
		assert   func(t *testing.T, records []slog.Record)
	}

	cases := []testCase{
		{
			name:     "a flood from one source writes one warning in the window",
			interval: time.Minute,
			act: func(t *testing.T, s *logsample.Sampler, log *slog.Logger) {
				for range 50 {
					httpsec.LogSampledForTest(s, log, slog.LevelWarn, time.Now(), "login|198.51.100.7", "throttled")
				}
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 1)
			},
		},
		{
			name:     "two sources do not suppress each other",
			interval: time.Minute,
			act: func(t *testing.T, s *logsample.Sampler, log *slog.Logger) {
				httpsec.LogSampledForTest(s, log, slog.LevelWarn, time.Now(), "login|198.51.100.7", "throttled")
				httpsec.LogSampledForTest(s, log, slog.LevelWarn, time.Now(), "login|203.0.113.9", "throttled")
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 2)
			},
		},
		{
			name:     "a flood against one flow does not suppress another flow",
			interval: time.Minute,
			act: func(t *testing.T, s *logsample.Sampler, log *slog.Logger) {
				for range 10 {
					httpsec.LogSampledForTest(s, log, slog.LevelWarn, time.Now(), "login|198.51.100.7", "throttled")
				}
				httpsec.LogSampledForTest(s, log, slog.LevelWarn, time.Now(), "magiclink|198.51.100.7", "throttled")
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 2, "every key starts with the flow, so flows never share a window")
			},
		},
		{
			name:     "an interval of zero disables sampling",
			interval: 0,
			act: func(t *testing.T, s *logsample.Sampler, log *slog.Logger) {
				for range 5 {
					httpsec.LogSampledForTest(s, log, slog.LevelWarn, time.Now(), "login|198.51.100.7", "throttled")
				}
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 5)
			},
		},
		{
			name:     "a written record carries the count suppressed before it",
			interval: time.Minute,
			act: func(t *testing.T, s *logsample.Sampler, log *slog.Logger) {
				for range 4 {
					httpsec.LogSampledForTest(s, log, slog.LevelWarn, time.Now(), "login|198.51.100.7", "throttled")
				}
				synctest.Wait()
				time.Sleep(time.Minute + time.Second) // the window rolls
				httpsec.LogSampledForTest(s, log, slog.LevelWarn, time.Now(), "login|198.51.100.7", "throttled")
			},
			assert: func(t *testing.T, records []slog.Record) {
				require.Len(t, records, 2)
				assert.Equal(t, int64(3), attr(records[1], "suppressed"),
					"the second record reports the three it stood in for")
				assert.False(t, hasAttr(records[0], "suppressed"),
					"the first suppressed nothing, so it carries no count")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var h capturingHandler
				log := slog.New(&h)
				s := logsample.New(tc.interval)
				tc.act(t, s, log)
				synctest.Wait()
				tc.assert(t, h.records())
			})
		})
	}
}
```

These cases do not call `t.Parallel()` inside the subtest: `synctest.Test` owns the bubble's goroutines.

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestRefusalLogSampling -count=1 ./httpsec/`
Stub `logSampled` to write every record unconditionally. Expected: FAIL on the flood row with 50 records instead of 1, and on the suppressed-count row. The disabled-interval row passes even stubbed — that is fine, it guards the opposite direction.

- [ ] **Step 3: Implement**

```go
// logSampled writes at most one record per key per window, attaching the count
// it stood in for.
//
// A nil sampler writes every record, which is what an interval of zero or less
// configures: sampling is a defence against a flood filling a disk, and a
// consumer who would rather have every line says so.
func logSampled(
	ctx context.Context,
	s *logsample.Sampler,
	log *slog.Logger,
	level slog.Level,
	now time.Time,
	key, msg string,
	attrs ...slog.Attr,
) {
	write, suppressed := s.Allow(key, now)
	if !write {
		return
	}
	if suppressed > 0 {
		// Attached only when non-zero, so an ordinary record is not padded
		// with "suppressed=0" on every line.
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}
	log.LogAttrs(ctx, level, msg, attrs...)
}
```

- [ ] **Step 4: Write the failing reporter and flush test**

```go
func TestRefusalLogReporter(t *testing.T) {
	// Rows:
	//  - "the default reporter summarises a key that goes quiet": 5 events in one
	//    window, the window rolls, and a WARN record names the key with
	//    suppressed=4.
	//  - "a consumer reporter replaces it": 3 suppressed, FlushRefusalLogs, and
	//    the consumer's function receives ("login|198.51.100.7", 3).
	//  - "a nil reporter is refused at construction": covered by Task 8's table;
	//    assert here only that the default is installed when none is given.
}
```

- [ ] **Step 5: Run it, confirm the red step, and implement**

```go
// WithRefusalLogInterval sets the window the chain's own refusal records are
// sampled over.
//
// The default is one minute. Zero or less disables sampling, so every record is
// written. It governs only the chain's own records — the throttled-source
// warning, the limiter failure and the unattributable-address errors. It does
// not change which requests are refused, and it does not set any other
// component's window: authenticate and policy each sample under their own
// option, because one option must never govern two subsystems.
func WithRefusalLogInterval(d time.Duration) Option { /* ... */ }

// WithRefusalLogReporter replaces what happens to the counts a sampled key
// suppressed once that key goes quiet.
//
// The default writes one WARN record, "httpsec: refusal logs suppressed",
// carrying the key and the suppressed count. There is always a reporter:
// without one the counts for a key that stops recurring are simply dropped, and
// an operator reading the sampled records would under-count the flood. A nil
// reporter is refused at construction rather than silently restoring the
// default, because a consumer supplying one means their metrics depend on it.
func WithRefusalLogReporter(fn func(key string, suppressed int)) Option { /* ... */ }

// FlushRefusalLogs reports every pending suppressed count now, for example
// from a shutdown hook, so counts held for a window that will never close are
// not lost.
//
// It flushes the chain's own sampler only. The authenticate and policy
// components each sample under their own options and expose their own flush;
// this chain does not reach into them, so a consumer who wants exact counts
// everywhere flushes each.
func (c *Chain) FlushRefusalLogs() { c.sampler.Flush() }
```

- [ ] **Step 6: Write the unsampled DEBUG case**

```go
// A request whose context ended before the limiter answered is the client's
// own doing, not a refusal worth a sampled warning, so it is DEBUG and skips
// the sampler entirely.
func TestRefusalLogUnsampledDebug(t *testing.T) { /* 5 cancelled requests -> 5 DEBUG records */ }
```

Red step: route it through `logSampled` first and watch the count come back 1 instead of 5.

- [ ] **Step 7: Gate and commit**

Run: `go test -race -run 'TestRefusalLog' -count=1 ./httpsec/`

```bash
git add httpsec/refusallog.go httpsec/refusallog_test.go httpsec/options.go httpsec/chain.go
git commit -m "feat(httpsec): the chain's refusal logs are sampled and always summarised

Every key starts with its flow, so a burst against one flow never suppresses
another's record, and a key that goes quiet still reports what it suppressed."
```

---

## Task 12: The login completion seam

**Implements:** tasks.md 5.1, 5.2, 5.3

**Files:**
- Modify: `httpsec/logincomplete.go`
- Test: `httpsec/logincomplete_test.go`

**Interfaces:**
- Consumes: `policy.Engine`, `policy.Input`, `session.Manager`, `token.Generator`, `policyDenyReason`, `withSession`.
- Produces: unexported `postAuthenticationInput(p *identity.Principal, first factor.Kind, username string, passwordChangedAt, now time.Time) *policy.Input` and `completeLogin(ex *Exchange, deps loginTailDeps, in *policy.Input) (token string, err error)`. `auth-methods` and `oidc-brokering` build every other first factor on `completeLogin`.

- [ ] **Step 1: Write the failing order test**

The order is the whole point of the seam, so the test pins it rather than the outcome alone:

```go
func TestCompleteLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine *policy.Engine
		sessions sessionSpy // records Create/Save/Delete in order
		tokens   tokenSpy   // records Generate
		assert func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string)
	}

	cases := []testCase{
		{
			name:   "an allowed login creates the session, then issues the token",
			engine: allowingEngine(t),
			assert: func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string) {
				require.NoError(t, err)
				assert.NotEmpty(t, tok)
				assert.Equal(t, []string{"Create", "Generate"}, calls)
				assert.NotNil(t, ex.Session, "the authentication is published for a consumer handler")
			},
		},
		{
			name:   "a deny refuses with the policy's reason and creates nothing",
			engine: denyingEngine(t, policy.ErrAccountLocked),
			assert: func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string) {
				require.ErrorIs(t, err, policy.ErrAccountLocked)
				assert.Empty(t, tok)
				assert.Empty(t, calls, "no session is created for a login policy refused")
			},
		},
		{
			name:   "a reasonless deny still refuses, and never reads as success",
			engine: denyingEngine(t, nil), // the engine substitutes ErrPolicyDenied
			assert: func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string) {
				require.Error(t, err, "a reasonless deny must never return nil")
				require.ErrorIs(t, err, policy.ErrPolicyDenied)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(err))
				assert.Empty(t, calls)
			},
		},
		{
			name:   "a challenge is marked and saved before the token is issued",
			engine: challengingEngine(t, policy.ChallengeMFA),
			assert: func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				require.NotNil(t, ch.Session)
				assert.NotEmpty(t, ch.Token)
				assert.Equal(t, []string{"Create", "Save", "Generate"}, calls,
					"the pending marker must be durable before a token for it exists")
			},
		},
		{
			name:     "a failed save leaves no token issued",
			engine:   challengingEngine(t, policy.ChallengeMFA),
			sessions: sessionSpy{saveErr: errors.New("store unavailable")},
			assert: func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string) {
				require.Error(t, err)
				assert.Empty(t, tok)
				assert.NotContains(t, calls, "Generate",
					"a token must never exist for a session whose pending flag failed to persist")
			},
		},
	}
	// Each case calls completeLogin with postAuthenticationInput(...) and the spies.
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestCompleteLogin -count=1 ./httpsec/`
Stub `completeLogin` to `return "", nil`. Expected: FAIL on the first row's `assert.NotEmpty(t, tok)`, and on each refusal row's `require.Error`. Confirm the reasonless-deny row fails on `require.Error` — that row is the one guarding against a refusal being served as a 200.

- [ ] **Step 3: Implement**

```go
// postAuthenticationInput builds the policy input for a login that has just
// succeeded.
//
// Every field is a parameter rather than a struct literal the caller fills in,
// so an interceptor cannot quietly omit one: a missing passwordChangedAt
// disables a password-age gate on that interceptor's path alone, which is
// exactly the kind of hole that is never noticed. first is factor.Kind rather
// than a string so it cannot be transposed with username, and the two times
// are adjacent so every call site's argument order is pinned by a test that
// fires the challenge.
func postAuthenticationInput(
	p *identity.Principal,
	first factor.Kind,
	username string,
	passwordChangedAt, now time.Time,
) *policy.Input {
	return &policy.Input{
		User:              p.ID,
		Username:          username,
		Principal:         p,
		FirstFactor:       first,
		PasswordChangedAt: passwordChangedAt,
		Now:               now,
	}
}

// completeLogin is the tail every first factor shares: policy, session, token.
//
// It exists so a redemption flow added by another capability cannot end a login
// differently from form login — the same phase, the same challenge handling and
// the same ordering guarantee, written once.
func completeLogin(ex *Exchange, deps loginTailDeps, in *policy.Input) (string, error) {
	ctx := ex.Context()

	d := deps.engine.EvaluatePhase(ctx, policy.PostAuthentication, in)
	if d.Outcome == policy.Deny {
		return "", policyDenyReason(d)
	}

	s, err := deps.sessions.Create(ctx, in.Principal.ID, session.WithFirstFactor(in.FirstFactor))
	if err != nil {
		return "", err
	}

	if d.Outcome == policy.Challenge {
		// Marked and saved before the token exists. A token issued first would
		// be a credential for a session whose pending flag never persisted —
		// that is, one that answers requests as if the challenge were met.
		markChallengePending(s, d.Challenge)
		if err := deps.sessions.Save(ctx, s); err != nil {
			return "", err
		}
	}

	tok, err := deps.tokens.Generate(ctx, s.ID, in.Principal)
	if err != nil {
		return "", err
	}

	// Published even on the challenge path, so a consumer rendering the prompt
	// still reads who is being challenged.
	ex.Session = s
	ex.SetContext(withSession(authenticate.WithAuthentication(ctx, ex.Authentication), s))

	if d.Outcome == policy.Challenge {
		return tok, &ChallengeError{Kind: d.Challenge, Session: s, Token: tok}
	}
	return tok, nil
}
```

Check `session.WithFirstFactor`'s real name against `go doc ./session CreateOption` before writing this; use whatever `CreateOption` the package exports.

- [ ] **Step 4: Run it and confirm it passes**

Run: `go test -run TestCompleteLogin -count=1 ./httpsec/` — Expected: PASS.

- [ ] **Step 5: Write the failing "another first factor" test**

The seam's whole claim is that a non-form first factor ends identically:

```go
// TestCompleteLoginOtherFirstFactor proves the seam is the reason another
// capability's redemption interceptor cannot end a login differently.
func TestCompleteLoginOtherFirstFactor(t *testing.T) {
	t.Parallel()

	engine := challengingEngine(t, policy.ChallengePasswordChange)
	ex := newExchange(t)

	// A stand-in for the magic-link interceptor auth-methods will add: it
	// resolves a principal by its own means, then hands it to the seam.
	in := httpsec.PostAuthenticationInputForTest(
		&identity.Principal{ID: "u-1", Username: "alice"},
		factor.Kind("magic-link"), "alice", time.Time{}, time.Now())

	_, err := httpsec.CompleteLoginForTest(ex, depsFor(t, engine), in)

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, err, &ch)
	assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
	require.NotNil(t, ch.Session, "exactly as form login would refuse it")
}
```

- [ ] **Step 6: Run it, confirm PASS, and commit**

```bash
git add httpsec/logincomplete.go httpsec/logincomplete_test.go httpsec/export_test.go
git commit -m "feat(httpsec): one login tail every first factor shares

The pending challenge is saved before a token for it is issued, so no token
exists for a session whose pending flag failed to persist."
```

---

## Task 13: Form login

**Implements:** tasks.md 6.1, 6.2, 6.3, 6.4

**Files:**
- Create: `httpsec/login.go`
- Modify: `httpsec/options.go`
- Test: `httpsec/login_test.go`

**Interfaces:**
- Consumes: `completeLogin`, `postAuthenticationInput`, `policyDenyReason`, `sourceThrottled`, `Request.Body`.
- Produces: `EnableFormLogin(d FormLoginDeps, opts ...LoginOption) Option`, `FormLoginDeps{Authentication, Sessions, Tokens, Attempts}`, `WithLoginRequestPath`, `WithLoginParams`, `WithLoginBodyLimit`, `WithLoginResponder`, `LoginResult{Token string; Session *session.Session}`.

- [ ] **Step 1: Write the failing matching and binding table**

Rows, each a spec scenario: successful login; `GET /login` passes through; a request to another path passes through; consumer field names `email`/`secret`; a JSON body when the form yields neither; a JSON body without a JSON content type is **not** read as one.

```go
func TestFormLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.LoginOption
		request func() *http.Request
		assert  func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool, err error)
	}

	cases := []testCase{
		{
			name:    "a correct login answers with the token and never calls the handler",
			request: formLogin("/login", "username=alice&password=s3cret"),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool, err error) {
				require.NoError(t, err)
				assert.False(t, handlerRan)
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

				var body struct {
					AccessToken  string    `json:"access_token"`
					RefreshToken string    `json:"refresh_token"`
					ValidUntil   time.Time `json:"valid_until"`
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
				assert.NotEmpty(t, body.AccessToken)
				assert.Empty(t, body.RefreshToken)
				assert.False(t, body.ValidUntil.IsZero())
			},
		},
		{
			name:    "a GET on the login path is not a login",
			request: get("/login"),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool, err error) {
				require.NoError(t, err)
				assert.True(t, handlerRan, "the request continues to the handler untouched")
			},
		},
		{
			name:    "consumer field names",
			opts:    []httpsec.LoginOption{httpsec.WithLoginParams("email", "secret")},
			request: formLogin("/login", "email=alice&secret=s3cret"),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool, err error) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name:    "a JSON body when the form yields neither field",
			request: jsonLogin("/login", `{"username":"alice","password":"s3cret"}`),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool, err error) {
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, rec.Code)
			},
		},
		{
			name:    "a consumer responder replaces the body",
			opts:    []httpsec.LoginOption{httpsec.WithLoginResponder(writePlainToken)},
			request: formLogin("/login", "username=alice&password=s3cret"),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool, err error) {
				require.NoError(t, err)
				assert.Equal(t, "text/plain", rec.Header().Get("Content-Type"))
				assert.NotEmpty(t, rec.Body.String())
			},
		},
		{
			name:    "a consumer login path leaves the default passing through",
			opts:    []httpsec.LoginOption{httpsec.WithLoginRequestPath("/session")},
			request: formLogin("/login", "username=alice&password=s3cret"),
			assert: func(t *testing.T, rec *httptest.ResponseRecorder, handlerRan bool, err error) {
				require.NoError(t, err)
				assert.True(t, handlerRan)
			},
		},
	}
	// Each case builds a chain with EnableFormLogin over in-memory collaborators
	// and serves the request through Chain.Middleware.
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestFormLogin -count=1 ./httpsec/` — Expected: FAIL on the success row (no response written), with the pass-through rows already green because a stub that handles nothing does continue.

- [ ] **Step 3: Write the failing sequence table**

The order of the steps is what the spec pins, so assert on the collaborators, not only the status:

```go
func TestFormLoginSequence(t *testing.T) {
	// Rows:
	//  - "a locked account is never probed": the pre-authentication phase denies
	//    with policy.ErrAccountLocked; assert the refusal is that error, that the
	//    authenticator's Authenticate was never called, and that the response
	//    maps to 423.
	//  - "a wrong password records one failed attempt": assert the refusal is
	//    authenticate.ErrAuthenticationFailed and the attempt store holds exactly
	//    one more attempt for that username.
	//  - "a correct password clears the attempts": assert the store's count for
	//    that username is zero afterwards.
	//  - "an attempt-store failure does not change the outcome": the store errors
	//    on record; assert the refusal is still ErrAuthenticationFailed, and that
	//    an ERROR record was written naming the bookkeeping failure.
	//  - "a post-authentication deny refuses without creating a session".
}
```

- [ ] **Step 4: Run it, confirm the red step, and implement matching, binding and the sequence**

```go
// Intercept answers a login on the configured path and passes everything else
// through untouched.
func (l *formLogin) Intercept(ex *Exchange, next Next) error {
	if ex.Request.Method() != http.MethodPost || ex.Request.Path() != l.path {
		return next(ex)
	}

	username, password, err := l.bind(ex.Request)
	if err != nil {
		return err // ErrRequestTooLarge or ErrCredentialsMissing
	}

	ctx := ex.Context()
	now := l.clock.Now()

	// Before the credential is checked, so a locked account is refused without
	// its password ever being tested — the refusal must not double as an
	// oracle for whether the password was right.
	pre := l.engine.EvaluatePhase(ctx, policy.PreAuthentication, &policy.Input{
		Username: username, Now: now,
	})
	if pre.Outcome == policy.Deny {
		return policyDenyReason(pre)
	}

	auth, err := l.authn.Authenticate(ctx, identity.NewUsernamePassword(username, password))
	if err != nil {
		// Bookkeeping, not the decision: a store that cannot record the attempt
		// must not turn a wrong password into a 500, and must not turn it into
		// a success either.
		if recErr := l.attempts.Record(ctx, username, now); recErr != nil {
			l.log.ErrorContext(ctx, "httpsec: recording a failed login attempt",
				slog.String("error", recErr.Error()))
		}
		return err
	}
	if clrErr := l.attempts.Clear(ctx, username); clrErr != nil {
		l.log.ErrorContext(ctx, "httpsec: clearing failed login attempts",
			slog.String("error", clrErr.Error()))
	}

	ex.Authentication = auth

	tok, err := completeLogin(ex, l.tail, postAuthenticationInput(
		auth.Principal, factor.KindPassword, username, auth.PasswordChangedAt, now))
	if err != nil {
		return err
	}

	// A login is answered here, not by the application's handler: the handler
	// behind the chain serves the application, and there is no application
	// route for the library's own endpoint.
	return l.respond(ex, LoginResult{Token: tok, Session: ex.Session})
}
```

Confirm `identity.NewUsernamePassword`, `policy.AttemptStore`'s method names and `factor.KindPassword` against `go doc` before writing; use the real names.

- [ ] **Step 5: Write the failing body-bound table, run it red, implement**

```go
func TestFormLoginBody(t *testing.T) {
	// Rows:
	//  - "a 1 MiB JSON body under the default limit is refused unparsed":
	//    require.ErrorIs ErrRequestTooLarge, StatusForError 413, and the
	//    authenticator was never called.
	//  - "a raised limit parses a 100 KiB body": WithLoginBodyLimit(256<<10) and a
	//    100 KiB body logs in normally.
	//  - "no credentials at all": ErrCredentialsMissing, StatusForError 400, and
	//    no authentication attempted.
	//  - "an undecodable JSON body": ErrCredentialsMissing, 400.
	//  - "a limit of zero is refused at construction": already a row in Task 8's
	//    table; assert here only that the default is 64 KiB by showing a 65 KiB
	//    body refused and a 63 KiB one accepted.
}
```

The bound matters because this is an unauthenticated endpoint: an unbounded read here is a memory-exhaustion path that needs no credentials at all.

- [ ] **Step 6: Gate and commit**

Run: `go test -race -run TestFormLogin -count=1 ./httpsec/`

```bash
git add httpsec/login.go httpsec/login_test.go httpsec/options.go
git commit -m "feat(httpsec): form login

The pre-authentication phase runs before the password is checked, so a locked
account is refused without its credential being tested, and the body is bounded
because the endpoint is unauthenticated."
```

---

## Task 13b: Form login binds from the body only

**Implements:** tasks.md 6.9

**Files:**
- Modify: `httpsec/login.go`
- Test: `httpsec/login_test.go`

**Why:** `Request.FormValue` carries net/http's semantics, which read the URL query as well as the
parsed body. Reproduced against the delivered code:

```
--- FAIL: TestZZQueryCredentials
    DEFECT: credentials read from the URL query: username="ada" password="s3cret"
```

`POST /login?username=ada&password=s3cret` therefore authenticates, and the password reaches access
logs, proxy logs, browser history and any `Referer` a later page sends. The spec's "read the
username and password from form fields" is body-only; a URL is not a form field.

Only form login's binding narrows. `Request.FormValue` keeps its net/http semantics, because a
consumer interceptor reading an ordinary query parameter is legitimate and the adapter contract is
public.

- [ ] **Step 1: Write the failing test**

```go
func TestFormLoginIgnoresQueryCredentials(t *testing.T) {
	// Rows:
	//  - "credentials in the query alone do not authenticate": POST
	//    /login?username=ada&password=s3cret with an EMPTY body is refused with
	//    ErrCredentialsMissing, and the authenticator is NEVER called (mock built
	//    with no EXPECT()).
	//  - "credentials in the body still authenticate": the same pair posted as a
	//    form body succeeds.
	//  - "a query pair cannot complete a half-filled body": body carries only
	//    username, query carries password; refused with ErrCredentialsMissing.
	//  - "an unrelated query parameter is harmless": POST /login?next=/home with a
	//    valid body still succeeds.
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestFormLoginIgnoresQueryCredentials -count=1 ./httpsec/`
Expected: the first and third rows FAIL — the request authenticates, and gomock reports an
unexpected `Authenticate` call. That failure is the defect.

- [ ] **Step 3: Implement**

Parse the body form yourself rather than calling `FormValue`, so the query is never consulted:

```go
// bindForm reads the credential from the parsed POST body only.
//
// Request.FormValue carries net/http's semantics, which merge the URL query
// into the form. A credential accepted from a query string is a credential
// written into every access log, proxy log and browser history that sees the
// URL, and into the Referer of the next page the browser loads. A login is a
// body, so the query is not consulted here at all.
func (l *formLogin) bindForm(raw []byte) (username, password string, ok bool) {
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return "", "", false
	}
	return values.Get(l.usernameField), values.Get(l.passwordField), true
}
```

Apply it only when the content type is `application/x-www-form-urlencoded`; the JSON path is
unaffected because a JSON body was never merged with the query.

- [ ] **Step 4: Run it and confirm it passes, then check the adapters agree**

Run: `go test -race -run TestFormLogin -count=1 ./httpsec/`. The gin and fiber conformance runs
(Task 27) must carry a query-credential scenario, so an adapter cannot reintroduce the merge.

- [ ] **Step 5: Commit**

```bash
git add httpsec/login.go httpsec/login_test.go
git commit -m "fix(httpsec): a credential in the URL query never authenticates

net/http merges the query into the form, so a password in a URL logged in
every proxy would have logged a user in too. Form login reads the body alone."
```

---

## Task 14: HTTP Basic authentication

**Implements:** tasks.md 6.5

**Files:**
- Create: `httpsec/basic.go`
- Test: `httpsec/basic_test.go`

**Interfaces:**
- Produces: `EnableBasicAuth(d BasicAuthDeps, opts ...BasicAuthOption) Option`, `WithBasicAuthRealm(realm string) BasicAuthOption` (default `Restricted`).

- [ ] **Step 1: Write the failing table**

```go
func TestBasicAuth(t *testing.T) {
	// Rows, each a spec scenario:
	//  - "correct credentials reach the handler with no session": assert the
	//    principal is in the context, ex.Session is nil, and the session store
	//    minted nothing.
	//  - "a request with no Basic header passes through untouched".
	//  - "a header that is not valid base64": ErrAuthenticationFailed, 401.
	//  - "a decoded header with no colon separator": ErrAuthenticationFailed.
	//  - "an incorrect password": ErrAuthenticationFailed, one failed attempt
	//    recorded, and the response carries WWW-Authenticate: Basic
	//    realm="Restricted".
	//  - "a consumer realm": WithBasicAuthRealm("internal-api") puts that name in
	//    the header.
	//  - "the pre-authentication phase denies": refused with the policy's reason,
	//    and the credential was never checked.
	//  - "the stateless phase requires a second factor": refused with that
	//    phase's reason, or a *ChallengeError carrying a nil Session and an
	//    empty Token — assert both are absent, because there is nothing for a
	//    stateless caller to come back to.
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestBasicAuth -count=1 ./httpsec/` — Expected: FAIL on the first row; the pass-through row is green from the start.

- [ ] **Step 3: Implement**

```go
// Intercept authenticates a Basic credential and establishes no session.
//
// The scheme is matched exactly, as "Basic " with its trailing space: a
// case-insensitive match here would also claim headers meant for another
// scheme registered at a nearby slot.
func (b *basicAuth) Intercept(ex *Exchange, next Next) error {
	header := ex.Request.Header("Authorization")
	if !strings.HasPrefix(header, basicPrefix) {
		return next(ex)
	}

	username, password, ok := decodeBasic(strings.TrimPrefix(header, basicPrefix))
	if !ok {
		// A malformed header is reported as a failed authentication, not as a
		// malformed request: telling the two apart tells a prober which of its
		// guesses was even parsed.
		b.challenge(ex)
		return authenticate.ErrAuthenticationFailed
	}

	ctx := ex.Context()
	now := b.clock.Now()

	pre := b.engine.EvaluatePhase(ctx, policy.PreAuthentication, &policy.Input{Username: username, Now: now})
	if pre.Outcome == policy.Deny {
		return policyDenyReason(pre)
	}

	auth, err := b.authn.Authenticate(ctx, identity.NewUsernamePassword(username, password))
	if err != nil {
		if recErr := b.attempts.Record(ctx, username, now); recErr != nil {
			b.log.ErrorContext(ctx, "httpsec: recording a failed basic attempt",
				slog.String("error", recErr.Error()))
		}
		b.challenge(ex)
		return authenticate.ErrAuthenticationFailed
	}

	// Stateless: there is no later phase in which this caller could answer a
	// challenge, so a challenge here decides outright and carries nothing to
	// come back to.
	d := b.engine.EvaluatePhase(ctx, policy.StatelessAuthentication, postAuthenticationInput(
		auth.Principal, factor.KindPassword, username, auth.PasswordChangedAt, now))
	switch d.Outcome {
	case policy.Deny:
		return policyDenyReason(d)
	case policy.Challenge:
		return &ChallengeError{Kind: d.Challenge}
	}

	ex.Authentication = auth
	ex.SetContext(authenticate.WithAuthentication(ctx, auth))
	return next(ex)
}

// challenge sets the header that tells a client which realm to answer for. It
// is set before the refusal returns, so the default error handler — which
// writes a status and no body — still sends it.
func (b *basicAuth) challenge(ex *Exchange) {
	ex.Writer.SetHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", b.realm))
}
```

- [ ] **Step 4: Run it, confirm PASS, and commit**

```bash
git add httpsec/basic.go httpsec/basic_test.go httpsec/options.go
git commit -m "feat(httpsec): HTTP Basic authentication, stateless

A challenge in the stateless phase decides outright and carries no session and
no token: there is no later request for this caller to answer on."
```

---

## Task 15: Bearer token authentication

**Implements:** tasks.md 6.6, 6.7, 6.8

**Files:**
- Create: `httpsec/bearer.go`
- Test: `httpsec/bearer_test.go`

**Interfaces:**
- Consumes: `token.Verifier`, `session.Manager`, `identity.UserLoader`, `policy.Engine`, `withSession`.
- Produces: `EnableBearerToken(d BearerTokenDeps, opts ...BearerTokenOption) Option`, `BearerTokenDeps{Verifier, Sessions, Users}`, `WithBearerScheme(string) BearerTokenOption` (default `Bearer`), `WithBearerAllowEmptyScheme() BearerTokenOption`.

The token's `jti` is the session identifier: `completeLogin` issues with `Generate(ctx, s.ID, principal)`, so `Claims.ID()` names the session and `Claims.Subject()` names the user.

- [ ] **Step 1: Write the failing scheme and verification table**

```go
func TestBearerToken(t *testing.T) {
	// Rows:
	//  - "a valid token reaches the handler with principal and session in context".
	//  - "the scheme matches without regard to case": "bearer <t>" and "BEARER <t>".
	//  - "a request with another scheme passes through untouched".
	//  - "a bare token is ignored by default, and accepted with
	//     WithBearerAllowEmptyScheme".
	//  - "a consumer scheme": WithBearerScheme("Token") accepts "token <t>".
	//  - "a tampered token": errors.Is authenticate.ErrAuthenticationFailed, and
	//    a DEBUG record carries the verifier's cause while the refusal does not.
}
```

- [ ] **Step 2: Run it, confirm the red step, and implement the header handling**

```go
// Intercept authenticates a bearer token against a live session and a live
// user.
func (b *bearer) Intercept(ex *Exchange, next Next) error {
	tok, ok := b.presented(ex.Request.Header("Authorization"))
	if !ok {
		return next(ex)
	}

	ctx := ex.Context()

	claims, err := b.verifier.Verify(ctx, tok)
	if err != nil {
		// Joined, not wrapped: an operator's log records which check the token
		// failed, while a caller still matches the one uniform failure. The
		// cause is logged at DEBUG and never returned to the client.
		b.log.DebugContext(ctx, "httpsec: bearer token rejected", slog.String("error", err.Error()))
		return errors.Join(authenticate.ErrAuthenticationFailed, err)
	}
	// ... session and user resolution, Step 4
}
```

- [ ] **Step 3: Write the failing session and user resolution table**

```go
func TestBearerSessionResolution(t *testing.T) {
	// Rows, all refusing with httpsec.ErrAuthenticationRequired so a client
	// cannot tell them apart:
	//  - "the session is gone" (session.ErrSessionNotFound).
	//  - "the session expired" (session.ErrSessionExpired).
	//  - "the session cannot be decrypted" (session.ErrSessionUnreadable): assert
	//    additionally that an ERROR record was written — a retired sealing key
	//    must be visible to an operator, while the caller is simply asked to log
	//    in again rather than served a 500 storm.
	//  - "the user no longer exists": the loader reports absent.
	//  - "the user is reloaded, so roles are current": the loader returns a
	//    principal whose roles differ from the token's subject claim, and the
	//    handler reads the loader's roles, not the token's.
}
```

The last row is the one that matters most: it is why the user is reloaded at all.

- [ ] **Step 4: Run it, confirm the red step, and implement**

```go
	s, err := b.sessions.Load(ctx, claims.ID())
	switch {
	case errors.Is(err, session.ErrSessionUnreadable):
		// Visible to an operator because it means a sealing key was retired
		// while sessions sealed under it were still live; answered to the
		// caller as "log in again", because that is the remedy and a 500 is not.
		b.log.ErrorContext(ctx, "httpsec: a session could not be decrypted",
			slog.String("error", err.Error()))
		return ErrAuthenticationRequired
	case err != nil:
		// Missing and expired are the same answer as unreadable: distinguishing
		// them would report whether a session ever existed.
		return ErrAuthenticationRequired
	}

	// Reloaded rather than taken from the token, so a role revoked a minute ago
	// is not honoured for the rest of the token's life.
	p, err := b.users.Load(ctx, claims.Subject())
	if err != nil {
		return ErrAuthenticationRequired
	}

	ex.Authentication = &authenticate.Authentication{Principal: p, Time: b.clock.Now()}
	ex.Session = s
	ctx = withSession(authenticate.WithAuthentication(ctx, ex.Authentication), s)
	ex.SetContext(ctx)
```

Confirm `identity.UserLoader`'s method name and return shape with `go doc ./identity UserLoader`; adapt the two lines above to it.

- [ ] **Step 5: Write the failing per-request phase table**

```go
func TestBearerPerRequestPhase(t *testing.T) {
	// Rows:
	//  - "a deny refuses": the request is refused with the policy's reason and
	//    the handler does not run.
	//  - "a reasonless deny is 403, never 200": assert StatusForError is 403 and
	//    the handler did not run. This is the row that catches a refusal served
	//    as a success.
	//  - "a password-change challenge marks the session and continues": assert
	//    the session now carries the pending marker, the handler DID run (the
	//    gate at OrderPasswordChange enforces it, and its resolve endpoint must
	//    stay reachable), and no error was returned.
	//  - "an MFA challenge likewise marks and continues".
}
```

- [ ] **Step 6: Run it, confirm the red step, implement, and commit**

```go
	d := b.engine.EvaluatePhase(ctx, policy.PerRequest, &policy.Input{
		User: p.ID, Principal: p, Session: s,
		FirstFactor: s.FirstFactor, Now: b.clock.Now(),
	})
	switch d.Outcome {
	case policy.Deny:
		return policyDenyReason(d)
	case policy.Challenge:
		// Marked and continued, not refused here: the gate for this challenge
		// enforces it, and refusing at this slot would also block the very
		// endpoint the caller must reach to resolve it.
		markChallengePending(s, d.Challenge)
	}

	return next(ex)
```

```bash
git add httpsec/bearer.go httpsec/bearer_test.go httpsec/options.go
git commit -m "feat(httpsec): bearer tokens authenticate against a live session and user

The user is reloaded so a revoked role is not honoured for the token's life,
and a mid-session challenge is marked and continued so its gate enforces it."
```

---

## Task 16: The password-change gate, logout, session touch and the key set

**Implements:** tasks.md 7.1, 7.2, 7.3, 7.4, 7.5

**Files:**
- Create: `httpsec/passwordchange.go`, `httpsec/logout.go`, `httpsec/sessiontouch.go`, `httpsec/jwks.go`
- Test: one `_test.go` beside each
- Modify: `httpsec/options.go`

**Interfaces:**
- Produces: `EnablePasswordChangeGate(sessions *session.Manager, opts ...PasswordChangeOption) Option`, `WithChangePasswordEndpoint(path string, fn ChangePasswordFunc) PasswordChangeOption`, `ChangePasswordFunc func(ex *Exchange) error`, `EnableLogout(d LogoutDeps, opts ...LogoutOption) Option`, `WithLogoutRequestPath(string) LogoutOption`, `EnableJWKSEndpoint(keys KeySetProvider, opts ...JWKSOption) Option`, `KeySetProvider interface{ JWKS() ([]byte, error) }`, `WithJWKSEndpointPath(string) JWKSOption`.

`signingkey.KeyManager` already satisfies `KeySetProvider` — it exports `JWKS() ([]byte, error)`. Do not re-marshal a jwx set.

- [ ] **Step 1: The password-change gate — write the failing table, run it red, implement**

```go
func TestPasswordChangeGate(t *testing.T) {
	// Rows:
	//  - "a session with the pending marker is refused": errors.As a
	//    *ChallengeError of kind ChallengePasswordChange carrying the session and
	//    an empty Token; the handler did not run; StatusForError is 403.
	//  - "a session without the marker passes".
	//  - "a request with no session passes" — the gate guards sessions, and an
	//    anonymous request is the authentication interceptors' business.
}

func TestChangePasswordEndpoint(t *testing.T) {
	// Rows:
	//  - "POST to the resolve path passes the gate and runs the consumer's
	//    function, which owns the response": assert the consumer's body and that
	//    the marker is now cleared and saved.
	//  - "the next request on that session passes the gate".
	//  - "an unauthenticated POST to the resolve path": ErrAuthenticationRequired,
	//    and the consumer's function did NOT run.
	//  - "the consumer's function fails": its error is the refusal, unchanged,
	//    and the marker is still set.
	//  - "GET on the resolve path is still gated": only POST is let through.
}
```

```go
// Intercept refuses any session that owes a password change, and lets the
// consumer's resolve endpoint through so the debt can be paid.
func (g *passwordChangeGate) Intercept(ex *Exchange, next Next) error {
	if g.isResolveRequest(ex.Request) {
		return g.resolve(ex)
	}
	if ex.Session != nil && ex.Session.PasswordChangePending {
		return &ChallengeError{Kind: policy.ChallengePasswordChange, Session: ex.Session}
	}
	return next(ex)
}

func (g *passwordChangeGate) resolve(ex *Exchange) error {
	// The endpoint changes this caller's own password, so there must be a
	// caller: without a session it would be an unauthenticated password change.
	if ex.Session == nil {
		return ErrAuthenticationRequired
	}
	if err := g.change(ex); err != nil {
		return err // the consumer's error is the refusal, unchanged
	}

	ex.Session.PasswordChangePending = false
	return g.sessions.Save(ex.Context(), ex.Session)
}
```

- [ ] **Step 2: Logout — write the failing table, run it red, implement**

```go
func TestLogout(t *testing.T) {
	// Rows:
	//  - "an authenticated POST deletes the session and answers 200 empty": and a
	//    later request with the same token is refused.
	//  - "a second logout for an already-deleted session is also 200": a race
	//    between two logouts is normal, not an error.
	//  - "an anonymous POST": ErrAuthenticationRequired.
	//  - "a stateless authenticated request is answered without deleting
	//     anything": assert the session store was never asked to delete.
	//  - "the handler is never called".
	//  - "a consumer path answers there and leaves /logout passing through".
}
```

```go
	if err := l.sessions.Delete(ctx, ex.Session.ID); err != nil && !errors.Is(err, session.ErrSessionNotFound) {
		return err
	}
	// Already gone is the outcome logout wanted. Two clients ending one session
	// is ordinary, and reporting the loser an error would have it retry.
	ex.Writer.WriteHeader(http.StatusOK)
	return nil
```

- [ ] **Step 3: Session touch — write the failing table, run it red, implement**

```go
func TestSessionTouch(t *testing.T) {
	// Rows:
	//  - "a completed request advances the idle deadline".
	//  - "a request refused by a guard still advances it": activity is activity,
	//    and a caller whose request was refused was still there.
	//  - "a touch failure after a 200 changes neither the response nor the
	//     error": assert the recorder still reads 200 and the chain returned nil.
	//  - "a request with no session touches nothing".
}
```

```go
// Intercept records activity after everything inside it has returned.
func (s *sessionTouch) Intercept(ex *Exchange, next Next) error {
	err := next(ex)

	if ex.Session != nil {
		// Deliberately ignored. This is bookkeeping: a store that cannot record
		// activity must not mask the handler's result or turn a served request
		// into an error, and a concurrent logout makes "not found" normal here.
		// The absolute deadline still bounds the session.
		if tErr := s.sessions.Touch(context.WithoutCancel(ex.Context()), ex.Session); tErr != nil {
			s.log.DebugContext(ex.Context(), "httpsec: recording session activity",
				slog.String("error", tErr.Error()))
		}
	}

	return err
}
```

- [ ] **Step 4: The key set endpoint — write the failing table, run it red, implement**

```go
func TestJWKSEndpoint(t *testing.T) {
	// Rows:
	//  - "GET the default path answers 200 with a JSON content type and a key
	//     set": parse the body and assert every key has a "kid" and none has a
	//     private member ("d", "p", "q", "dp", "dq", "qi", "k").
	//  - "the handler is never called".
	//  - "a POST on the path passes through".
	//  - "a consumer path serves there and the default passes through".
	//  - "a provider failure propagates as an error": StatusForError is 500 and
	//    no body was written.
}
```

The private-member assertion is the one worth writing carefully: it is the difference between serving a key set and serving the signing keys.

- [ ] **Step 5: Gate and commit**

Run: `go test -race -run 'TestPasswordChange|TestChangePassword|TestLogout|TestSessionTouch|TestJWKS' -count=1 ./httpsec/`

```bash
git add httpsec/passwordchange.go httpsec/logout.go httpsec/sessiontouch.go httpsec/jwks.go httpsec/options.go httpsec/*_test.go
git commit -m "feat(httpsec): the gate, logout, session touch and the key set

Touch runs after everything inside it and ignores its own failure, so
bookkeeping never masks the handler's result."
```

---

## Task 17: The authorization stage and the centralized rule set

**Implements:** tasks.md 8.1, 8.2

**Files:**
- Create: `httpsec/authorization.go`
- Test: `httpsec/authorization_test.go`

**Interfaces:**
- Consumes: `authorize.Authorizer`, `authorize.Rule[R any]`, `authorize.NewRules[R any]`, `authorize.WithAuthorizer`.
- Produces: `EnableAuthorization(az authorize.Authorizer, rules ...authorize.Rule[Request]) Option`, appending across calls.

`authorize.Rules` is generic and unconstrained on purpose, so the chain instantiates it over its own `Request`: `authorize.NewRules[Request](rules...)`. A consumer's `Match` then sees the whole request — path, method, headers — through the same abstraction every interceptor reads.

- [ ] **Step 1: Write the failing table**

```go
func TestAuthorizationRules(t *testing.T) {
	t.Parallel()

	adminRule := authorize.Rule[httpsec.Request]{
		Match:   func(r httpsec.Request) bool { return strings.HasPrefix(r.Path(), "/admin/") },
		Require: requireRole("ADMIN"),
	}
	permitAll := authorize.Rule[httpsec.Request]{
		Match:   func(httpsec.Request) bool { return true },
		Require: authorize.PermitAll,
	}

	type testCase struct {
		name   string
		rules  []authorize.Rule[httpsec.Request]
		path   string
		as     *identity.Principal // nil means anonymous
		assert func(t *testing.T, handlerRan bool, err error)
	}

	cases := []testCase{
		{
			name:  "the first matching rule decides",
			rules: []authorize.Rule[httpsec.Request]{adminRule, permitAll},
			path:  "/admin/users",
			as:    &identity.Principal{ID: "u-1"}, // no ADMIN
			assert: func(t *testing.T, handlerRan bool, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied,
					"a later permit-all must not rescue what an earlier rule refused")
				assert.False(t, handlerRan)
			},
		},
		{
			name:  "a request no rule matches is denied",
			rules: []authorize.Rule[httpsec.Request]{{
				Match:   func(r httpsec.Request) bool { return strings.HasPrefix(r.Path(), "/api/") },
				Require: authorize.PermitAll,
			}},
			path: "/other",
			as:   &identity.Principal{ID: "u-1"},
			assert: func(t *testing.T, handlerRan bool, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied,
					"an endpoint added without a rule is closed, not open")
				assert.False(t, handlerRan)
			},
		},
		{
			name:  "an anonymous request to a protected rule",
			rules: []authorize.Rule[httpsec.Request]{adminRule, permitAll},
			path:  "/admin/users",
			as:    nil,
			assert: func(t *testing.T, handlerRan bool, err error) {
				require.ErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, err, authorize.ErrAuthenticationRequired,
					"the stage wraps the core's sentinel, so either identity matches")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(err))
			},
		},
		{
			name:  "with no rules nothing is enforced centrally",
			rules: nil,
			path:  "/anything",
			as:    nil,
			assert: func(t *testing.T, handlerRan bool, err error) {
				require.NoError(t, err)
				assert.True(t, handlerRan, "authorization is then the guards' business")
			},
		},
	}
	// Each case also asserts the authorizer is readable from the handler's
	// context, because the stage always runs.
}
```

Confirm `authorize.PermitAll`'s real name with `go doc ./authorize Requirement` before writing; substitute whatever the package exports for an always-permit requirement.

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestAuthorizationRules -count=1 ./httpsec/`
Stub the stage to call `next` unconditionally. Expected: the three enforcing rows FAIL on `require.ErrorIs`, and the guards-only row passes.

- [ ] **Step 3: Implement**

```go
// Intercept publishes the authorizer and applies the centralized rules.
//
// The stage always runs, even with no rules: a per-endpoint guard reads the
// authorizer from the request context, and a guard that cannot find one fails
// closed. Publishing it here means a consumer wires the authorizer once.
func (a *authorization) Intercept(ex *Exchange, next Next) error {
	ctx := authorize.WithAuthorizer(ex.Context(), a.authorizer)
	ex.SetContext(ctx)

	if a.rules == nil {
		// An empty rule set is a configuration, not an omission: the consumer
		// has said authorization belongs at the operations. It is not the same
		// as permitting, and the guards there still decide.
		return next(ex)
	}

	if err := a.rules.Evaluate(ctx, ex.Request); err != nil {
		if errors.Is(err, authorize.ErrAuthenticationRequired) {
			// Wrapped so a consumer matching this package's sentinel reaches it
			// too, without having to know which stage refused.
			return fmt.Errorf("%w: %w", ErrAuthenticationRequired, err)
		}
		return err
	}

	return next(ex)
}
```

- [ ] **Step 4: Run it, confirm PASS, and commit**

```bash
git add httpsec/authorization.go httpsec/authorization_test.go httpsec/options.go
git commit -m "feat(httpsec): the authorization stage and the centralized rule set

The stage always runs so a guard downstream reads one authorizer; a non-empty
rule set denies what no rule matched, so a route added without one is closed."
```

---

## Task 18: Per-endpoint guards

**Implements:** tasks.md 8.3, 8.4

**Files:**
- Create: `httpsec/guards.go`
- Test: `httpsec/guards_test.go`

**Interfaces:**
- Produces: `NewGuards(az authorize.Authorizer, opts ...GuardOption) *Guards`, `(*Guards).RequireAuthenticated()`, `(*Guards).ResourcePrivileges(group, resource string)` with `RequireOne/RequireAll/RequireAny(...)`, `ResourceOwnerships[ID any](g *Guards, group, resource string, checker OwnershipChecker[ID])` with `.ForResource(extract func(Request) (ID, error))`, and `WithGuardErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) GuardOption`.

- [ ] **Step 1: Write the failing fail-closed table**

```go
func TestGuardsFailClosed(t *testing.T) {
	// Rows, each asserting the route did NOT run:
	//  - "no principal": ErrAuthenticationRequired.
	//  - "no authorizer in the context and none at construction":
	//    authorize.ErrAccessDenied — a guard that cannot find a judge refuses.
	//  - "the identifier extractor fails": the extractor's own error is the
	//    refusal, unchanged, so the consumer sees why.
	//  - "the authorizer refuses": the authorizer's error is the refusal.
	//  - "a guard refuses on top of a permissive centralized rule": the rule
	//    permits, the guard refuses, the route does not run.
	//  - "the happy path runs the route".
}

func TestGuardsAuthorizerSource(t *testing.T) {
	// Rows:
	//  - "the context's authorizer is preferred over the construction one": the
	//    chain published a permitting authorizer and the guard was built with a
	//    refusing one; the route runs.
	//  - "the construction authorizer is the fallback when the chain published
	//     none": the guard was built with a permitting one; the route runs.
}
```

The preference matters: one chain publishes one authorizer, and a guard built earlier must not keep judging by a stale one.

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestGuards -count=1 ./httpsec/`
Stub every guard to call the route. Expected: every fail-closed row FAILs on "the route ran".

- [ ] **Step 3: Implement**

```go
// authorizerFor is where every guard finds its judge.
//
// The chain's authorizer wins, so one wiring decides for every guard behind it,
// and the one the guard was built with is the fallback for a guard used outside
// a chain. When there is neither, the guard refuses: a guard that cannot find
// an authorizer has not been told the request is allowed.
func (g *Guards) authorizerFor(ctx context.Context) (authorize.Authorizer, bool) {
	if az, ok := authorize.AuthorizerFromContext(ctx); ok && !nilcheck.IsNil(az) {
		return az, true
	}
	if !nilcheck.IsNil(g.authorizer) {
		return g.authorizer, true
	}
	return nil, false
}
```

Confirm `authorize.AuthorizerFromContext`'s real name with `go doc ./authorize`; `WithAuthorizer` exists, so its reader does too.

- [ ] **Step 4: Run it, confirm PASS, and commit**

```bash
git add httpsec/guards.go httpsec/guards_test.go
git commit -m "feat(httpsec): per-endpoint guards that fail closed

A guard reads the chain's authorizer and falls back to its own; with neither it
refuses, because a guard that found no judge has not been told to allow."
```

---

## Task 19: The net/http entrypoint and default error handling

**Implements:** tasks.md 9.1, 9.2, 9.3, 9.4

**Files:**
- Modify: `httpsec/chain.go`, `httpsec/options.go`
- Test: `httpsec/middleware_test.go`

**Interfaces:**
- Produces: `(*Chain).Middleware() func(http.Handler) http.Handler`, `WithErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) Option`.

- [ ] **Step 1: Write the failing middleware test**

```go
func TestMiddleware(t *testing.T) {
	// Rows:
	//  - "the principal and session reach the handler".
	//  - "an upstream request identifier survives the chain".
	//  - "the handler's own context cancellation still works".
}
```

- [ ] **Step 2: Run it, confirm the red step, and implement**

```go
// Middleware runs the chain in front of an ordinary net/http handler.
func (c *Chain) Middleware() func(http.Handler) http.Handler {
	return func(downstream http.Handler) http.Handler {
		run := c.Assemble(func(ex *Exchange) error {
			// The chain's accumulated context is written back onto the request
			// here, at the innermost point, so everything it resolved is
			// readable by the handler through r.Context() as usual.
			downstream.ServeHTTP(ex.nativeWriter(), ex.nativeRequest().WithContext(ex.Context()))
			return nil
		})

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Seeded from the incoming context, never replaced, so values and
			// cancellation set by middleware before the chain survive it.
			ex := NewExchange(r.Context(), NewHTTPRequest(r), NewHTTPResponseWriter(w))
			if err := run(ex); err != nil {
				c.handleError(w, r, err)
			}
		})
	}
}
```

- [ ] **Step 3: Write the failing default-response table**

This is the fail-closed contract, so every row is a spec scenario:

```go
func TestDefaultErrorResponse(t *testing.T) {
	// Rows, all with no error handler configured:
	//  - "an unauthenticated request": 401 with an EMPTY body, and the handler
	//    did not run.
	//  - "internal error text is withheld": a lookup fails with "connection
	//    refused to db-primary:5432"; assert 500 and that the body contains
	//    neither "connection refused" nor "db-primary".
	//  - "a challenge header set before refusing is kept": Basic fails; assert
	//    401, a WWW-Authenticate header, and an empty body.
	//  - "an interceptor that already wrote is not overwritten": assert the
	//    status it wrote survives.
}
```

The second row is the one that earns the design: the default must not be "write err.Error()".

- [ ] **Step 4: Run it, confirm the red step, and implement**

```go
// handleError answers a refusal.
//
// The default is the mapped status and nothing else: a body would either leak
// what the refusal knew — a driver's error text, whether an account exists — or
// invent a format the consumer must then work around. Rendering is the
// consumer's, through WithErrorHandler; the library's job is to fail closed.
func (c *Chain) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if c.errorHandler != nil {
		c.errorHandler(w, r, err)
		return
	}
	w.WriteHeader(StatusForError(err))
}
```

```go
// WithErrorHandler replaces what a refusal answers with.
//
// The default writes the status StatusForError gives and no body, so nothing
// the library knows reaches a client that the consumer did not choose to send.
// A handler set here receives the response writer, the request and the
// propagated error for every refusal, and the default response is not written.
// Pass the same function to WithGuardErrorHandler to answer guard refusals
// identically.
func WithErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) Option { /* ... */ }
```

- [ ] **Step 5: Write the failing consumer-handler table, run it red, implement**

```go
func TestConsumerErrorHandler(t *testing.T) {
	// Rows:
	//  - "a consumer renders a JSON body": the handler writes
	//    {"error":"forbidden"} with StatusForError's 403; assert both.
	//  - "the default is not also written": assert exactly one status and the
	//    consumer's body alone.
	//  - "a guard uses WithGuardErrorHandler": the guard's refusal reaches it.
	//  - "a guard with no handler agrees with the table": a guard refusing with
	//    authorize.ErrInvalidAttributes answers 500, the status the table gives,
	//    NOT 400 — invalid attributes come from a misbuilt guard, not a client.
}
```

The last row is a deliberate departure recorded in design Decision 7; assert the table's answer so a future switch cannot quietly disagree with it.

- [ ] **Step 6: Run the whole package under race and the gates**

Run:
```sh
go test -race -count=1 ./httpsec/
go vet ./...
gofmt -l . | tee /dev/stderr | wc -l   # must be 0
golangci-lint run ./httpsec/...
```

- [ ] **Step 7: Commit**

```bash
git add httpsec/chain.go httpsec/options.go httpsec/middleware_test.go
git commit -m "feat(httpsec): the net/http entrypoint and a fail-closed default

With no error handler a refusal is the mapped status and an empty body, so no
internal text reaches a client the consumer did not choose to send it to."
```

---

## Task 19b: The principal reaches the request context

**Implements:** tasks.md 9.5

**Files:**
- Modify: `httpsec/basic.go`, `httpsec/bearer.go`, `httpsec/logincomplete.go`
- Test: `httpsec/guards_test.go`, `httpsec/middleware_test.go`

**Why (REPRODUCED):** the chain publishes `authenticate.WithAuthentication` at all three sites but
never `identity.WithPrincipal`, while `guards.go:123` reads `identity.PrincipalFromContext`. So a
caller the chain has just authenticated is refused by its own guard:

```
--- FAIL: TestZZGuardBehindAuthentication
    DEFECT: the caller was authenticated, yet the guard refused: status=401
```

Fix the publish sites, not the read. The spec requires the principal itself to reach the handler's
context ("Principal reaches the handler"; "gin handler reads the principal"), so a guard reading
`authenticate.AuthenticationFromContext` instead would satisfy the guard and still leave the
handler unable to read a principal.

- [ ] **Step 1: Write the failing tests**

```go
// A guard behind a chain that HAS authenticated the caller must let them through.
// Without this, RequireAuthenticated refuses every caller on every first factor,
// and the failure looks exactly like a missing credential.
func TestGuardBehindAuthentication(t *testing.T) {
	// Rows, one per first factor that publishes an authentication:
	//  - form login, basic, bearer: a guarded route behind the chain RUNS.
	//  - an unauthenticated request to the same guarded route is still refused
	//    with ErrAuthenticationRequired, so the fix does not open the guard.
}
```

and, in `middleware_test.go`, extend the context row: the handler reads the principal through
`identity.PrincipalFromContext(r.Context())`, not only the authentication result.

- [ ] **Step 2: Run them and confirm the red step**

Run: `go test -run 'TestGuardBehindAuthentication|TestMiddleware' -count=1 ./httpsec/`
Expected: the guarded rows FAIL with a 401 and the route not run; the unauthenticated row already
passes, which is what shows the fix must not simply drop the check.

- [ ] **Step 3: Implement**

At each of the three sites, publish both, so one call site cannot drift from the other:

```go
// publishCaller puts the authentication result and the principal on ctx.
//
// Both are published because they answer different questions: an interceptor
// asks what authenticated this request, and a guard or a consumer's handler
// asks who the caller is. Publishing only the first left every guard reading
// identity.PrincipalFromContext refusing a caller the chain had just
// authenticated.
func publishCaller(ctx context.Context, a *authenticate.Authentication) context.Context {
	ctx = authenticate.WithAuthentication(ctx, a)
	if a != nil && a.Principal != nil {
		ctx = identity.WithPrincipal(ctx, a.Principal)
	}
	return ctx
}
```

Confirm `identity.WithPrincipal`'s real name with `go doc ./identity` first.

- [ ] **Step 4: Confirm it passes, and that the guard still fails closed**

Run: `go test -race -count=1 ./httpsec/`. The unauthenticated row must still refuse.

- [ ] **Step 5: Commit**

```bash
git add httpsec/basic.go httpsec/bearer.go httpsec/logincomplete.go httpsec/guards_test.go httpsec/middleware_test.go
git commit -m "fix(httpsec): the principal reaches the request context

A guard reads identity.PrincipalFromContext, which nothing published, so a
caller the chain had just authenticated was refused by its own guard."
```

---

## Task 19c: A consumer's own first factor can publish its caller

**Implements:** tasks.md 9.6

**Files:**
- Modify: `httpsec/logincomplete.go` (export the helper), `httpsec/order.go` (godoc on `RegisterInterceptor`)
- Test: `httpsec/guards_test.go`

**Why (REPRODUCED):** Task 19b fixed the three built-in publish sites, but `publishCaller` stayed
unexported. A consumer writing their own first factor reaches for `authenticate.WithAuthentication`,
which is exported and obvious, and their guards then refuse every caller:

```
STILL BROKEN: authenticated caller refused by its own guard: status=401
STILL BROKEN: handler cannot read the principal
```

The spec says a consumer interceptor "SHALL be able to do everything a built-in one can". Publishing
a caller that guards and handlers can see is now something only a built-in can do, so the helper
must be reachable. Exporting one helper is better than documenting two calls, for the same reason
19b gave: two call sites drift, one cannot.

- [ ] **Step 1: Write the failing test**

```go
// A consumer's own first factor must be able to publish its caller the way a
// built-in does. Without an exported helper the consumer reaches for
// authenticate.WithAuthentication alone, and every guard behind them refuses.
func TestConsumerFirstFactorPublishesCaller(t *testing.T) {
	// Rows:
	//  - "a consumer interceptor using the exported helper": a guarded route
	//    behind it RUNS, and the handler reads identity.PrincipalFromContext.
	//  - "the same guard still refuses a caller nothing authenticated": 401,
	//    route not run — the helper must not open the guard.
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestConsumerFirstFactorPublishesCaller -count=1 ./httpsec/`
Expected: the first row FAILS — the helper does not exist, so stub it as a function returning `ctx`
unchanged and watch the row fail on the guard's 401, not on a build error.

- [ ] **Step 3: Implement**

Export the existing helper and keep the built-ins on it:

```go
// WithCaller publishes an authentication result and the caller it resolved.
//
// A consumer writing their own first factor calls this rather than
// authenticate.WithAuthentication, which publishes only the event: a guard and
// a consumer's handler ask who the caller is, and read the principal. The two
// are published together here so no call site can publish one without the
// other.
func WithCaller(ctx context.Context, a *authenticate.Authentication) context.Context
```

Name it in `RegisterInterceptor`'s godoc, so a consumer registering a first factor is told where to
look.

- [ ] **Step 4: Confirm it passes and nothing regressed**

Run: `go test -race -count=1 ./httpsec/`, then `go test -race -count=1 ./...` in `ginsec` and
`fibersec`.

- [ ] **Step 5: Commit**

```bash
git add httpsec/logincomplete.go httpsec/order.go httpsec/guards_test.go
git commit -m "feat(httpsec): a consumer's own first factor can publish its caller

Publishing the event without the principal left every guard refusing, and the
helper that got it right was unexported."
```

---

## Task 20: Origin comparison

**Implements:** tasks.md 10.1

**Files:**
- Create: `internal/origin/same.go`, `internal/origin/doc.go`
- Test: `internal/origin/same_test.go`

**Interfaces:**
- Produces: `origin.Same(a, b string) bool`, `origin.Normalize(raw string) (scheme, host, port string, ok bool)`.

- [ ] **Step 1: Write the failing table**

Every relaxation of this comparison makes more strings equal, which helps a discovery check and weakens a redirect allowlist. The table is therefore as much about what must **not** match as what must:

```go
func TestOriginSame(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		a, b string
		want bool
	}

	cases := []testCase{
		{name: "identical", a: "https://idp.example.com/a", b: "https://idp.example.com/b", want: true},
		{name: "ASCII case folding of scheme and host",
			a: "HTTPS://IdP.Example.com/a", b: "https://idp.example.com/b", want: true},
		{name: "a default port is removed",
			a: "https://idp.example.com:443/a", b: "https://idp.example.com/b", want: true},
		{name: "http's default port is removed too",
			a: "http://idp.example.com:80/a", b: "http://idp.example.com/b", want: true},
		{name: "userinfo is ignored",
			a: "https://user:pw@idp.example.com/a", b: "https://idp.example.com/b", want: true},

		{name: "different hosts", a: "https://idp.example.com", b: "https://cdn.example.net", want: false},
		{name: "a scheme downgrade", a: "https://idp.example.com", b: "http://idp.example.com", want: false},
		{name: "a non-default port", a: "https://idp.example.com:8443", b: "https://idp.example.com", want: false},
		{name: "ports are compared as written, not numerically",
			a: "https://idp.example.com:0443", b: "https://idp.example.com:443", want: false},
		{name: "a trailing root label is significant",
			a: "https://idp.example.com./a", b: "https://idp.example.com/a", want: false},

		// The look-alikes. Unicode case mapping folds U+0130 to "i" and U+212A
		// to "k"; applying it here would make an attacker's host equal to the
		// one an allowlist declared.
		{name: "U+0130 is not ASCII i", a: "https://İdp.example.com", b: "https://idp.example.com", want: false},
		{name: "U+212A is not ASCII k", a: "https://Keys.example.com", b: "https://keys.example.com", want: false},
		{name: "IDNA is not applied",
			a: "https://xn--idp-9na.example.com", b: "https://ïdp.example.com", want: false},

		{name: "another scheme matches nothing", a: "mailto:a@b", b: "mailto:a@b", want: false},
		{name: "two unparsable values match nothing", a: "mailto:a@b", b: "mailto:c@d", want: false},
		{name: "no host matches nothing", a: "https:///path", b: "https:///path", want: false},
		{name: "empty matches nothing", a: "", b: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, origin.Same(tc.a, tc.b))
			assert.Equal(t, tc.want, origin.Same(tc.b, tc.a), "the comparison must be symmetric")
		})
	}
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestOriginSame -count=1 ./internal/origin/`
Stub `Same` to `return a == b`. Expected: the case-folding, default-port and userinfo rows FAIL, and — importantly — the `mailto:` and empty rows fail too, because `a == b` is true for them. That confirms the "matches nothing" rows are load-bearing.

- [ ] **Step 3: Implement**

```go
// Package origin compares URL origins and validates redirect targets.
//
// The comparison is deliberately narrow. Every normalisation step makes more
// strings equal, and the two callers pull in opposite directions: a discovery
// check wants a lenient comparison so a provider's own variants match, and a
// redirect allowlist wants a strict one so an attacker's host does not. Strict
// is the safe direction, so only ASCII case folding and default-port removal
// are applied. Adding a step is a decision to be argued for each caller
// separately, not a tidy-up.
package origin

// Same reports whether a and b have the same origin.
//
// Both must use http or https and have a host. Scheme and host are compared
// after ASCII case folding, a port equal to the scheme's default is removed,
// and userinfo is ignored. Nothing else is normalised: no Unicode case mapping
// and no IDNA, because both fold distinct hosts together; ports are compared as
// written, so "0443" is not "443"; and a trailing root label is significant,
// because "example.com." and "example.com" are different names to resolvers
// that are given them literally.
//
// A value that cannot be parsed, uses another scheme or has no host matches
// nothing at all — including another such value. Two unusable strings are not
// evidence of a common origin.
func Same(a, b string) bool {
	as, ah, ap, ok := Normalize(a)
	if !ok {
		return false
	}
	bs, bh, bp, ok := Normalize(b)
	if !ok {
		return false
	}
	return as == bs && ah == bh && ap == bp
}

// Normalize splits raw into its origin parts, or reports that it has none.
func Normalize(raw string) (scheme, host, port string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", false
	}

	// ToLower, not strings.ToLower on arbitrary Unicode: ASCII only, so U+0130
	// stays U+0130 rather than folding onto "i".
	scheme = asciiLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", "", false
	}

	host = asciiLower(u.Hostname())
	if host == "" {
		return "", "", "", false
	}

	port = u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}

	return scheme, host, port, true
}

// asciiLower folds only A-Z. strings.ToLower applies Unicode case mapping,
// which maps U+0130 to "i" and U+212A to "k", making an attacker's host equal
// to one an allowlist declared.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
```

`asciiLower` operating on bytes is safe here because it only touches bytes in the ASCII range, which never appear inside a multi-byte UTF-8 sequence.

- [ ] **Step 4: Run it, confirm PASS, and commit**

Run: `go test -run TestOriginSame -count=1 ./internal/origin/`

```bash
git add internal/origin/same.go internal/origin/doc.go internal/origin/same_test.go
git commit -m "feat(origin): a deliberately narrow origin comparison

Only ASCII case folding and default-port removal. Unicode folding would make
U+0130 equal to i, and an attacker's host equal to a declared one."
```

---

## Task 21: The redirect-target allowlist

**Implements:** tasks.md 10.2, 10.3

**Files:**
- Create: `internal/origin/allowlist.go`
- Test: `internal/origin/allowlist_test.go`

**Interfaces:**
- Produces: `origin.NewAllowlist(entries []string, declaredOrigins []string, entryOption, originOption string) (*Allowlist, error)` and `(*Allowlist).Resolve(requested string) string`. `auth-methods` and `oidc-brokering` expose it through their own options, passing their own option names so the error message names the option the consumer actually set.

- [ ] **Step 1: Write the failing construction table**

Each row asserts the message names the offending entry **and** the option, because the consumer has to find which of their configured values is at fault:

```go
func TestAllowlistConstruction(t *testing.T) {
	// Rows that must FAIL construction:
	//  - "//partner.example.com/landing" (protocol-relative): names the entry.
	//  - "/\\evil.example.net" (a backslash after the leading slash).
	//  - "//evil" and "/ /x" (whitespace), "/a\tb" (a control character).
	//  - "https://partner.example.com/landing" with no declared origins: names
	//    the entry AND the origin-declaration option it needs.
	//  - "https://user:pw@partner.example.com/x" (userinfo in an entry).
	//  - a declared origin "http://partner.example.com": cleartext off loopback.
	//  - a declared origin "https://partner.example.com/path" (a path).
	//  - a declared origin "https://partner.example.com?q=1" (a query).
	//  - a declared origin "https://partner.example.com#f" (a fragment).
	//  - a declared origin "https://user:pw@partner.example.com" (userinfo).
	//
	// Rows that must SUCCEED:
	//  - "/landing" and "/a/b?c=d" (host-relative).
	//  - "https://partner.example.com/landing" WITH that origin declared.
	//  - a declared origin "http://localhost:3000" (cleartext on loopback).
	//  - a declared origin "https://partner.example.com/" (a lone trailing slash).
	//  - no entries and no origins at all: the default, which accepts only
	//    host-relative targets.
}
```

- [ ] **Step 2: Run it and confirm the red step**

Run: `go test -run TestAllowlistConstruction -count=1 ./internal/origin/`
Stub `NewAllowlist` to accept everything. Expected: every refusal row FAILs on `require.Error`. Implement one validation rule at a time and watch its row go green.

- [ ] **Step 3: Implement**

```go
// validateEntry accepts a host-relative path, or an absolute URL on a declared
// origin.
//
// The two forms are the only ones that cannot be made to point somewhere the
// consumer never declared. "//host/path" is refused although it starts with a
// slash: a browser reads it as protocol-relative and goes to host. "/\host" is
// refused for the same reason — several browsers normalise the backslash to a
// slash and follow it off-site.
func validateEntry(entry string, declared []string, entryOption, originOption string) error {
	if entry == "" {
		return fmt.Errorf("%w: %s was given an empty redirect target", ErrConfig, entryOption)
	}

	if strings.HasPrefix(entry, "/") {
		if len(entry) > 1 && (entry[1] == '/' || entry[1] == '\\') {
			return fmt.Errorf(
				"%w: %s entry %q is not host-relative: a browser reads a second slash or a "+
					"backslash here as the start of a host", ErrConfig, entryOption, entry)
		}
		if strings.ContainsFunc(entry, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) {
			return fmt.Errorf("%w: %s entry %q contains whitespace or a control character",
				ErrConfig, entryOption, entry)
		}
		return nil
	}

	// Absolute: it must be on an origin the consumer declared, so a target can
	// never leave for a host they never named.
	u, err := url.Parse(entry)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: %s entry %q is neither a host-relative path nor an absolute URL",
			ErrConfig, entryOption, entry)
	}
	if u.User != nil {
		return fmt.Errorf("%w: %s entry %q carries userinfo", ErrConfig, entryOption, entry)
	}
	if !slices.ContainsFunc(declared, func(d string) bool { return Same(d, entry) }) {
		return fmt.Errorf(
			"%w: %s entry %q is on an origin that was not declared; declare it with %s",
			ErrConfig, entryOption, entry, originOption)
	}
	return nil
}
```

```go
// Resolve returns the target to redirect to.
//
// A requested target is used only when it exactly equals a configured entry
// that is still acceptable under the construction rules, which is why the entry
// is re-checked rather than trusted because it was validated once. Anything
// else — an unlisted value, a near miss, an empty request — becomes "/".
// Falling back rather than refusing keeps a flow that has already succeeded
// from ending in an error page over where to land afterwards.
func (a *Allowlist) Resolve(requested string) string {
	for _, entry := range a.entries {
		if requested == entry && validateEntry(entry, a.declared, a.entryOption, a.originOption) == nil {
			return entry
		}
	}
	return "/"
}
```

- [ ] **Step 4: Write the failing resolve table, run it red, confirm PASS**

```go
func TestAllowlistResolve(t *testing.T) {
	// Rows:
	//  - "a declared partner URL resolves to itself".
	//  - "a host-relative entry resolves to itself".
	//  - "/\\evil.example.net, which is not an entry, falls back to /".
	//  - "an entry's prefix is not a match": "/land" against the entry
	//    "/landing" falls back, because matching is exact.
	//  - "an empty request falls back to /".
	//  - "a case variant of an entry falls back": paths are case-sensitive.
}
```

- [ ] **Step 5: Commit**

```bash
git add internal/origin/allowlist.go internal/origin/allowlist_test.go
git commit -m "feat(origin): redirect targets are host-relative or on a declared origin

A protocol-relative entry and a backslash after the leading slash are refused
at construction: browsers read both as the start of a host."
```

---

## Task 22: The confined outbound client

**Implements:** tasks.md 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7

**Files:**
- Create: `outbound/client.go`, `outbound/options.go`, `outbound/doc.go`
- Test: `outbound/client_test.go`, `outbound/options_test.go`

**Interfaces:**
- Consumes: `internal/origin.Same`.
- Produces: `outbound.New(opts ...Option) (*Client, error)`, `(*Client).Get(ctx, url string, h http.Header) (*Response, error)`, `(*Client).PostForm(ctx, url string, form url.Values) (*Response, error)`, `Response{Status int; Header http.Header; Body []byte}`, and `WithHTTPClient`, `WithAllowedSchemes`, `WithAllowedOrigins`, `WithMaxRedirects`, `WithTimeout`, `WithMaxResponseBytes`.

- [ ] **Step 1: Write the failing construction table, run it red, implement**

```go
func TestOutboundConstruction(t *testing.T) {
	// Rows that must FAIL, each naming its option:
	//  - WithAllowedSchemes("ftp"): only http may be added to https.
	//  - WithAllowedSchemes("file"), WithAllowedSchemes(""): likewise.
	//  - WithMaxRedirects(-1).
	//  - WithTimeout(0) and WithTimeout(-time.Second).
	//  - WithMaxResponseBytes(0) and WithMaxResponseBytes(-1).
	//  - WithHTTPClient(nil).
	//  - WithAllowedOrigins("https://idp.example.com/path"): an origin with a path.
	//
	// Rows that must SUCCEED:
	//  - no options at all: https only, 10 hops, 10s, 1 MiB.
	//  - WithAllowedSchemes("http") added to the default.
	//  - WithMaxRedirects(0): redirects are never followed, which is a
	//    configuration, not a mistake.
}
```

- [ ] **Step 2: Write the failing target-check table, run it red, implement**

```go
func TestOutboundTargets(t *testing.T) {
	// Rows. The servers count connections, so "failed before anything was sent"
	// is asserted, not assumed:
	//  - "plain http is refused by default": target http://<server>; assert the
	//    error AND that the server's connection counter is zero.
	//  - "the consumer allows http": WithAllowedSchemes("http"); the request is
	//    sent and the counter is one.
	//  - "an origin not on the allowlist": WithAllowedOrigins("https://idp...")
	//    and a target on evil.example.net; counter zero.
	//  - "default port equivalence": declared "https://idp.example.com:443",
	//    target "https://IDP.example.com/token"; allowed.
	//  - "an empty URL", "an unparsable URL", "a URL with no host": each fails
	//    before anything is sent.
}
```

```go
// checkTarget refuses a URL before a connection is opened.
//
// Everything here is checked before the request is sent, not after: a token
// request carries a client secret, and a check that runs on the response has
// already let it leave.
func (c *Client) checkTarget(raw string) error {
	scheme, _, _, ok := origin.Normalize(raw)
	if !ok {
		return fmt.Errorf("%w: %q is not an absolute http or https URL with a host", ErrRefused, raw)
	}
	if !slices.Contains(c.schemes, scheme) {
		return fmt.Errorf("%w: scheme %q is not allowed", ErrRefused, scheme)
	}
	if len(c.origins) > 0 && !slices.ContainsFunc(c.origins, func(o string) bool { return origin.Same(o, raw) }) {
		return fmt.Errorf("%w: %q is not on an allowed origin", ErrRefused, raw)
	}
	return nil
}
```

- [ ] **Step 3: Write the failing redirect table**

```go
func TestOutboundRedirects(t *testing.T) {
	// Rows, each with a counting server so "no request was sent" is asserted:
	//  - "off-origin": idp redirects to cdn.example.net; the fetch fails and
	//    cdn's counter is zero.
	//  - "a downgrade": https redirects to http on the same host; fails.
	//  - "same-origin": /jwks -> /keys is followed and returns the body.
	//  - "a loop stops at the cap": a server that always redirects to another
	//    path on its own origin, with a counter; assert the request fails and the
	//    counter is 11 (the original plus ten hops), NOT 51. Build the server to
	//    stop after 50 so a missing cap fails the test instead of hanging it.
	//  - "the cap is configurable": WithMaxRedirects(2) stops at 2.
	//  - "zero disables redirects": the first redirect fails, counter is 1.
	//  - "the consumer's own CheckRedirect still runs": a client whose
	//    CheckRedirect refuses everything; a same-origin redirect fails.
	//  - "the library's check runs BEFORE the consumer's": a consumer
	//    CheckRedirect that records it was called; on an off-origin redirect it
	//    must NOT have been called, because the library refused first.
}
```

- [ ] **Step 4: Run it, confirm the red step, and implement**

```go
// install puts the library's redirect policy on a copy of the consumer's
// client. The consumer's client is never mutated: it may be shared.
func (c *Client) install(hc *http.Client) *http.Client {
	copied := *hc
	consumer := hc.CheckRedirect

	copied.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// The hop cap first, because installing any CheckRedirect discards
		// net/http's own limit of 10. Without this a same-origin loop would run
		// until the timeout, turning a misconfigured provider into a stall.
		if len(via) > c.maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrRefused, c.maxRedirects)
		}
		// Against via[0], the URL the request started with — not the previous
		// hop. Comparing hop to hop would let a chain walk to any origin one
		// step at a time.
		if err := c.checkRedirect(req.URL.String(), via[0].URL.String()); err != nil {
			return err
		}
		if consumer != nil {
			return consumer(req, via)
		}
		return nil
	}
	return &copied
}
```

- [ ] **Step 5: Write the failing body-replay test**

This is the reason `WithHTTPClient` takes `*http.Client` and not an opaque `Do`:

```go
// TestOutboundNoBodyReplay proves a 307 cannot resend a client secret to
// another origin. The check runs before the redirected request is sent, so the
// final-URL check is not what protects this: by then it would be unsendable.
func TestOutboundNoBodyReplay(t *testing.T) {
	t.Parallel()

	var secretsReceived atomic.Int64
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "client_secret") {
			secretsReceived.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(evil.Close)

	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/token", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(idp.Close)

	c, err := outbound.New(outbound.WithHTTPClient(clientTrusting(t, idp, evil)))
	require.NoError(t, err)

	_, err = c.PostForm(t.Context(), idp.URL+"/token", url.Values{
		"client_secret": {"the-secret"},
		"code":          {"the-code"},
	})

	require.Error(t, err)
	assert.Zero(t, secretsReceived.Load(), "no client secret may reach another origin")
}
```

- [ ] **Step 6: Run it and confirm the red step**

Run: `go test -run TestOutboundNoBodyReplay -count=1 ./outbound/`
Before the redirect policy is installed, net/http follows the 307 itself and resends the body. Expected: FAIL with `secretsReceived == 1`. **That failure is the defect the check exists for — record its output.** Then install the policy and see it pass with zero.

- [ ] **Step 7: Write the failing final-URL, timeout and body-limit tables, run them red, implement**

```go
func TestOutboundFinalURL(t *testing.T) {
	// "a consumer Transport that follows a redirect itself": the response comes
	// from evil.example.net; assert the response is rejected and Body is empty.
	// This is the backstop for the documented limit that a consumer transport
	// bypasses the pre-send check.
}

func TestOutboundTimeout(t *testing.T) {
	// Rows, each against a server that accepts and never answers:
	//  - "the default bound": fails within ~10s. Use synctest so the test does
	//    not actually wait ten seconds.
	//  - "a consumer client with no timeout still fails within the bound".
	//  - "a consumer bound of 3s fails within 3s".
	//  - "an earlier caller deadline wins": a 1s context beats a 10s bound.
}

func TestOutboundBodyLimit(t *testing.T) {
	// Rows:
	//  - "a 5 MiB key set under the 1 MiB default": the fetch fails, and assert
	//    len(Body) <= 1 MiB so nothing beyond the bound was read into memory.
	//  - "a raised 4 MiB limit reads a 2 MiB document in full".
	//  - "a body exactly at the limit is accepted".
}
```

```go
	// Re-checked because a consumer's Transport may have followed a redirect
	// without CheckRedirect ever being consulted. This cannot unsend a request,
	// which is why the pre-send checks exist — but it does stop the content of
	// an unexpected origin being returned as if the provider had answered.
	if res.Request != nil {
		if err := c.checkTarget(res.Request.URL.String()); err != nil {
			return nil, fmt.Errorf("the response came from an unexpected URL: %w", err)
		}
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, c.maxBytes))
```

- [ ] **Step 8: Write the package godoc with the stated limits**

The two limits the design requires stating, on `WithHTTPClient`:
- a consumer `Transport` that follows redirects itself bypasses the pre-send check, leaving only the final-URL re-check;
- the client is copied, never mutated, so the consumer's own client keeps its behaviour elsewhere.

And on the package: outbound confinement does **not** filter targets by resolved IP. A consumer who needs that supplies a `Transport` whose dialer enforces it.

- [ ] **Step 9: Gate and commit**

Run: `go test -race -count=1 ./outbound/ ./internal/origin/`, `golangci-lint run ./outbound/... ./internal/origin/...`

```bash
git add outbound/ internal/origin/
git commit -m "feat(outbound): confine the requests scrty itself sends

The redirect policy is installed on a copy of the consumer's client, so a 307
cannot replay a token request's client secret to another origin."
```

---

## Task 23: The ginsec module

**Implements:** tasks.md 12.1, 12.2, 12.3, 12.6

**Files:**
- Create: `ginsec/go.mod`, `ginsec/doc.go`, `ginsec/middleware.go`, `ginsec/clientip.go`
- Modify: `go.work`
- Test: `ginsec/middleware_test.go`

**Interfaces:**
- Consumes: `httpsec.Chain.Assemble`, `httpsec.NewHTTPRequest`, `httpsec.NewHTTPResponseWriter`, `httpsec.StatusForError`.
- Produces: `ginsec.Middleware(c *httpsec.Chain, opts ...Option) gin.HandlerFunc`, `ginsec.WithForwardedClientIP() Option`.

- [ ] **Step 1: Create the module and prove the core stays clean**

```bash
mkdir -p ginsec
cd ginsec
cat > go.mod <<'EOF'
module github.com/kartaladev/scrty/ginsec

go 1.27

require (
	github.com/gin-gonic/gin v1.11.0
	github.com/kartaladev/scrty v0.0.0
	github.com/stretchr/testify v1.12.1
)

// The core module is not tagged yet, so there is no version to require. It is
// swapped for a real version at the first release.
replace github.com/kartaladev/scrty => ../
EOF
cd .. && go work use ./ginsec
```

Pin the latest gin v1 at implementation time (`go get github.com/gin-gonic/gin@latest` inside `ginsec`) and record the resolved version in the commit message — design.md's Open Questions leaves the exact minor to the implementer, and it changes no spec or task.

- [ ] **Step 2: Run the layout guard and confirm it stays green**

Run: `go test -run TestModuleLayout -count=1 .` from the repository root.
Expected: PASS, "real tree has no violations". If it fails, the core `go.mod` has picked up gin — that is the violation the guard exists for, and it must be fixed rather than excluded.

Confirm the guard actually notices: temporarily add `require github.com/gin-gonic/gin v1.11.0` to the **core** `go.mod`, re-run, see the violation reported, then remove it.

- [ ] **Step 3: Write the failing context and refusal tests**

```go
func TestGinContext(t *testing.T) {
	// Rows:
	//  - "a route handler reads the principal from c.Request.Context()".
	//  - "a route handler reads the session".
	//  - "gin middleware before the chain stored a trace id, and the route still
	//     reads it".
}

func TestGinRefusal(t *testing.T) {
	// Rows:
	//  - "no error middleware": an access-denied refusal answers 403 with an
	//    EMPTY body and the route did not run.
	//  - "the error is on gin's channel": assert c.Errors carries it and that
	//    errors.Is reaches the original refusal.
	//  - "consumer error middleware renders": middleware registered BEFORE the
	//    chain reads c.Errors after c.Next() and writes its own JSON body,
	//    Content-Type and status; assert all three survive, which proves the
	//    adapter did not commit the header block.
	//  - "a response already written is not overwritten": an interceptor wrote
	//    201 before refusing; assert 201 stands.
}
```

The consumer-middleware row is the one that pins `c.Status` + `c.Abort` over `AbortWithStatus`: with `AbortWithStatus` the header block is committed and the consumer's `Content-Type` never appears.

- [ ] **Step 4: Run them, confirm the red step, and implement**

```go
// Middleware runs the chain in front of the gin handlers registered after it.
//
// gin's context carries both net/http types, so the chain's default net/http
// request and response implementations are reused rather than reimplemented.
func Middleware(c *httpsec.Chain, opts ...Option) gin.HandlerFunc {
	cfg := newConfig(opts...)

	return func(gc *gin.Context) {
		req := httpsec.NewHTTPRequest(gc.Request)
		if cfg.forwardedClientIP {
			req = clientIPOverride{Request: req, ip: gc.ClientIP()}
		}

		run := c.Assemble(func(ex *httpsec.Exchange) error {
			// Written back before the route runs, so a handler reads everything
			// the chain resolved through the request context as usual.
			gc.Request = gc.Request.WithContext(ex.Context())
			gc.Next()
			return nil
		})

		if err := run(httpsec.NewExchange(gc.Request.Context(), req, httpsec.NewHTTPResponseWriter(gc.Writer))); err != nil {
			// The error goes on gin's own channel, so a consumer's error
			// middleware handles it the way it handles every other.
			_ = gc.Error(err)

			// c.Status, not AbortWithStatus: Status is lazy and Abort does not
			// commit it, so error middleware further out can still set its own
			// headers and body. AbortWithStatus writes the header block and
			// would leave a consumer unable to render anything at all.
			if !gc.Writer.Written() {
				gc.Status(httpsec.StatusForError(err))
			}
			gc.Abort()
			return
		}

		// A request the chain answered itself: abort without a status of its
		// own, so a matched route or a NoRoute handler cannot overwrite what
		// the chain wrote.
		if !gc.IsAborted() && chainAnswered(gc) {
			gc.Abort()
		}
	}
}
```

- [ ] **Step 5: Write the failing client-address test, run it red, implement**

```go
func TestGinClientIP(t *testing.T) {
	// Rows:
	//  - "the default ignores a forwarding header": a peer at 198.51.100.7 sends
	//    X-Forwarded-For: 203.0.113.9; the throttled flow is keyed on
	//    198.51.100.7.
	//  - "the opt-in uses gin's client address": engine.SetTrustedProxies
	//    (["10.0.0.2"]) plus WithForwardedClientIP, a proxy at 10.0.0.2
	//    forwarding 198.51.100.7; keyed on 198.51.100.7.
	//  - "the opt-in still refuses an unattributable address": gin reports "";
	//    the request is refused, not pooled.
}
```

- [ ] **Step 6: Write the godoc the spec requires**

On `WithForwardedClientIP`:

```go
// WithForwardedClientIP attributes a request to gin's own client address
// instead of the transport peer.
//
// The default is the peer, because it cannot be chosen by the client.
//
// gin trusts every proxy until the consumer calls engine.SetTrustedProxies:
// until then c.ClientIP() returns whatever a client put in the forwarding
// header, so this option lets a client choose its own rate-limit bucket. Set
// the trusted proxy list first, and only then enable this.
//
// It lives here rather than on the chain because net/http and fiber hold no
// gin proxy configuration: a core option would silently do nothing on them,
// and an option that does not take effect is exactly what this library refuses.
```

On the package: gin middleware registered **after** the chain does not run for refused or self-answered requests, so register logging and metrics before it.

- [ ] **Step 7: Gate and commit**

Run, from `ginsec`: `go test -race -count=1 ./...`, `go vet ./...`, `golangci-lint run ./...`. From the root: `go test -run TestModuleLayout -count=1 .`

```bash
git add ginsec/ go.work go.work.sum
git commit -m "feat(ginsec): run the chain on gin

A refusal goes on gin's error channel with a lazily-set status, so a consumer's
error middleware can still render while a request is never answered 200."
```

---

## Task 24: gin self-answered requests and guards

**Implements:** tasks.md 12.4, 12.5

**Files:**
- Modify: `ginsec/middleware.go`
- Create: `ginsec/guards.go`
- Test: `ginsec/guards_test.go`

**Interfaces:**
- Produces: `ginsec.NewGuards(az authorize.Authorizer, opts ...GuardOption) *Guards`, mirroring `httpsec.Guards`.

- [ ] **Step 1: Write the failing self-answered test**

```go
func TestGinSelfAnswered(t *testing.T) {
	// Rows:
	//  - "a route on the logout path does not run": register the chain and a
	//    POST /logout route that writes 201; log out and assert the response is
	//    200, the body is empty, and the route's counter is zero.
	//  - "a NoRoute handler does not append to the key set": register a NoRoute
	//    that writes "not found"; request the key set path and assert the body
	//    is EXACTLY the key set, with no trailing text.
	//  - "the login response survives": a route on /login that would write 418
	//    does not run.
}
```

The NoRoute row is the sharp one: without the abort, gin runs `NoRoute` after the chain wrote, appending to a body that already parsed as JSON.

- [ ] **Step 2: Run it, confirm the red step, and implement**

Expected red: the logout row reports 201, or the key set row reports a body with `not found` appended. Read which, then implement the bare abort.

- [ ] **Step 3: Write the failing guard test, run it red, implement**

```go
func TestGinGuards(t *testing.T) {
	// Rows:
	//  - "a guard refuses with no error middleware": 403, empty body, the route
	//    did not run. Register-and-abort alone would answer 200 here, which is
	//    exactly what this row forbids.
	//  - "the guard's error is on gin's channel".
	//  - "consumer error middleware renders the guard's refusal".
	//  - "a guard reads the authorizer the chain published".
}
```

```go
// refuse answers a guard's refusal the way the chain's own refusals are
// answered: the error on gin's channel, a lazily-set status so middleware can
// still render, and the route skipped.
//
// The status is set here, not only the error registered: with no error
// middleware, registering and aborting answers 200 with an empty body, which is
// a refusal served as a success.
func refuse(gc *gin.Context, err error) {
	_ = gc.Error(err)
	if !gc.Writer.Written() {
		gc.Status(httpsec.StatusForError(err))
	}
	gc.Abort()
}
```

- [ ] **Step 4: Gate and commit**

```bash
git add ginsec/
git commit -m "feat(ginsec): guards and requests the chain answered itself

A bare abort stops a matched route or a NoRoute handler from appending to what
the chain wrote; a guard sets the mapped status so it never answers 200."
```

---

## Task 25: The fibersec module

**Implements:** tasks.md 13.1, 13.2, 13.3, 13.7, 13.8

**Files:**
- Create: `fibersec/go.mod`, `fibersec/doc.go`, `fibersec/exchange.go`, `fibersec/middleware.go`
- Modify: `go.work`
- Test: `fibersec/exchange_test.go`, `fibersec/middleware_test.go`

**Interfaces:**
- Produces: `fibersec.Middleware(c *httpsec.Chain) fiber.Handler`, and unexported `request`/`responseWriter` implementing `httpsec.Request`/`httpsec.ResponseWriter` over `fiber.Ctx`.

- [ ] **Step 1: Create the module and re-check the accessor names**

```bash
mkdir -p fibersec && cd fibersec
cat > go.mod <<'EOF'
module github.com/kartaladev/scrty/fibersec

go 1.27

require (
	github.com/gofiber/fiber/v3 v3.5.0
	github.com/kartaladev/scrty v0.0.0
	github.com/stretchr/testify v1.12.1
)

replace github.com/kartaladev/scrty => ../
EOF
cd .. && go work use ./fibersec
```

Then, before writing the adapter, confirm each accessor against the pinned tag — v3 renamed several from v2:

```sh
cd fibersec && go doc github.com/gofiber/fiber/v3.Ctx | grep -E 'Method|Path|Get|Query|Cookies|FormValue|Body|IP|Set|Cookie|Status|Write|Context|SetContext|Next'
```

Use what that prints. Do not transcribe the names from `design.md` without checking them.

Run `go test -run TestModuleLayout -count=1 .` from the root and confirm the core module still has no fiber dependency.

- [ ] **Step 2: Write the failing exchange test**

```go
func TestFiberExchange(t *testing.T) {
	// Rows:
	//  - "method, path, header, query, cookie and form value" read through the
	//    abstraction match what was sent.
	//  - "an oversized body is refused": a body over the limit returns
	//    httpsec.ErrRequestTooLarge. fiber has already buffered the body, so
	//    this is a length check, not a bounded read.
	//  - "a body at the limit is accepted".
	//  - "no net/http request is constructed": assert through a fiber app whose
	//    handler records that c.Request() is fasthttp's, and that the adapter
	//    exposes no *http.Request. Keep this row simple and direct: its purpose
	//    is to fail if someone later adds an adaptor.ConvertRequest call.
}
```

- [ ] **Step 3: Run it, confirm the red step, and implement**

```go
// request implements httpsec.Request directly over fiber's context.
//
// Nothing here builds a net/http request. Converting would allocate and copy
// every header and the whole body on every secured request, which is the cost
// fiber exists to avoid.
type request struct{ c fiber.Ctx }

func (r request) Method() string            { return r.c.Method() }
func (r request) Path() string              { return r.c.Path() }
func (r request) Header(n string) string    { return r.c.Get(n) }
func (r request) Query(n string) string     { return fiber.Query[string](r.c, n) }
func (r request) FormValue(n string) string { return r.c.FormValue(n) }
func (r request) ClientIP() string          { return r.c.IP() }

// Cookie cannot tell an empty cookie from an absent one: fiber returns "" for
// both. This is stated on the package, and no interceptor keys a decision on
// the difference.
func (r request) Cookie(n string) (string, bool) {
	v := r.c.Cookies(n)
	return v, v != ""
}

// Body checks the length of the body fiber has already buffered, rather than
// reading under a bound: there is nothing left to bound by the time a handler
// runs.
func (r request) Body(limit int64) ([]byte, error) {
	b := r.c.Body()
	if int64(len(b)) > limit {
		return nil, httpsec.ErrRequestTooLarge
	}
	// Copied because fiber's accessors are zero-copy into the request buffer,
	// which is reused once the request ends.
	return bytes.Clone(b), nil
}
```

- [ ] **Step 4: Write the failing context test, run it red, implement**

```go
func TestFiberContext(t *testing.T) {
	// Rows:
	//  - "a route handler reads the principal from the handler context's request
	//     context".
	//  - "fiber middleware before the chain stored a trace id, and the route
	//     still reads it".
}
```

- [ ] **Step 5: Write the failing client-address test, run it red**

```go
func TestFiberClientIP(t *testing.T) {
	// Rows:
	//  - "app.Test with no proxy trust is refused as unspecified": fiber's
	//    in-memory transport reports 0.0.0.0, so a throttled flow refuses rather
	//    than pooling every test request into one bucket.
	//  - "with TrustProxy, an explicit Proxies list and EnableIPValidation, a
	//     forwarded 198.51.100.7 is used".
}
```

The first row is why the conformance suite configures `TrustProxy` with `Proxies: {"0.0.0.0"}` for the scenarios that need an address.

- [ ] **Step 6: Write the package godoc the spec requires**

State, on the package:
- the safe proxy configuration in full: `TrustProxy`, an explicit `TrustProxyConfig.Proxies` list, `UnixSocket` when the proxy uses one and `"0.0.0.0"` in the list for a socket-only proxy, `ProxyHeader`, and `EnableIPValidation`;
- the pitfalls: `UnixSocket` alone selects the leftmost, client-written address, and `Loopback`, `Private` and `LinkLocal` skip real clients;
- that fiber's string and body accessors are zero-copy and valid only for the request, so an interceptor keeping a value beyond it copies first;
- that fiber cannot tell an empty cookie from an absent one;
- that fiber's built-in error handler writes the status text as the body, and `fibersec.ErrorHandler` gives the bare status instead.

- [ ] **Step 7: Gate and commit**

```bash
git add fibersec/ go.work go.work.sum
git commit -m "feat(fibersec): run the chain on fiber without a net/http request

The request and response abstractions are implemented over fiber.Ctx directly,
so a secured request never pays for a conversion."
```

---

## Task 26: fiber refusals and guards

**Implements:** tasks.md 13.4, 13.5, 13.6

**Files:**
- Create: `fibersec/errors.go`, `fibersec/guards.go`
- Test: `fibersec/errors_test.go`, `fibersec/guards_test.go`

**Interfaces:**
- Produces: `fibersec.RefusalError` with `Unwrap() []error`, `fibersec.ErrorHandler(c fiber.Ctx, err error) error`, `fibersec.MapError(err error) (int, any)`, `fibersec.NewGuards(...)`.

- [ ] **Step 1: Write the failing refusal-error test**

```go
func TestFiberRefusalError(t *testing.T) {
	// Rows:
	//  - "errors.Is reaches the original refusal": a wrapped access-denied.
	//  - "errors.As reaches *httpsec.ChallengeError, with its kind, session and
	//     token intact": this is what lets a consumer render a prompt.
	//  - "errors.As reaches *fiber.Error carrying the mapped status".
	//  - "Error() is only the status text": for a refusal whose cause reads
	//    "connection refused to db-primary:5432", assert the text is exactly
	//    "Forbidden"/"Internal Server Error" and contains neither "connection
	//    refused" nor "db-primary".
	//  - "fiber's built-in handler cannot leak the cause": run a fiber app with
	//    no ErrorHandler configured, refuse with that cause, and assert the body
	//    is at most "Internal Server Error".
}
```

The last row is the departure's whole justification: fiber's `DefaultErrorHandler` writes `err.Error()` into the body, so returning the raw error would publish driver text to a consumer who configured nothing.

- [ ] **Step 2: Run it, confirm the red step, and implement**

```go
// RefusalError is what the chain returns to fiber.
//
// It wraps two things through Unwrap() []error: the refusal itself, so
// errors.Is and errors.As still reach it and a *httpsec.ChallengeError is still
// readable, and a *fiber.Error carrying the mapped status, so fiber's own error
// handling reads the status the way it expects.
//
// Its own text is only the standard status text. fiber's built-in
// DefaultErrorHandler writes err.Error() straight into the response body, so a
// raw refusal would put internal detail — a driver's message, a provider's
// hostname — in front of any consumer who never configured a handler. The
// status text says what happened without saying anything a client should not
// learn.
type RefusalError struct {
	refusal error
	status  *fiber.Error
}

func (e *RefusalError) Error() string   { return http.StatusText(e.status.Code) }
func (e *RefusalError) Unwrap() []error { return []error{e.refusal, e.status} }
```

- [ ] **Step 3: Write the failing handler and helper test, run it red, implement**

```go
func TestFiberErrorHandler(t *testing.T) {
	// Rows:
	//  - "ErrorHandler answers the bare status with an empty body": an
	//    unauthenticated refusal is 401 with len(body) == 0.
	//  - "MapError returns the status and a minimal body": an access-denied
	//    refusal gives (403, fiber.Map{"error": "Forbidden"}).
	//  - "a consumer handler extracts the challenge and renders its own prompt":
	//    errors.As reaches the ChallengeError, its kind and token are available,
	//    and the consumer's body is the response.
}
```

```go
// ErrorHandler answers a refusal with the mapped status and an empty body.
//
// Set it as fiber.Config.ErrorHandler to get the same fail-closed default the
// net/http chain has. Without it, fiber's built-in handler writes the status
// text as the body — harmless, but not empty, because fiber owns that handler
// and the library cannot make it write nothing.
func ErrorHandler(c fiber.Ctx, err error) error {
	return c.SendStatus(httpsec.StatusForError(err))
}

// MapError returns the status and a minimal body for a consumer's own handler
// to send after it has logged or enriched the error.
//
// The body holds only the standard status text, never the error's own, for the
// same reason the default response has no body at all.
func MapError(err error) (int, any) {
	status := httpsec.StatusForError(err)
	return status, fiber.Map{"error": http.StatusText(status)}
}
```

- [ ] **Step 4: Write the failing guard test, run it red, implement, and commit**

```go
func TestFiberGuards(t *testing.T) {
	// Rows:
	//  - "a guard returns its refusal the same way": the route did not run, and
	//    the returned error is identifiable as the original refusal.
	//  - "with fibersec.ErrorHandler it answers 403 with an empty body".
}
```

```bash
git add fibersec/
git commit -m "feat(fibersec): refusals fiber's error handling can read safely

RefusalError keeps the original refusal matchable while its own text is only
the status text, so fiber's built-in handler cannot put a cause in a body."
```

---

## Task 27: The adapter conformance suite

**Implements:** tasks.md 14.1, 14.2, 14.3, 14.4, 14.5, 14.6

**Files:**
- Create: `test/httpsecconformance/scenarios.go`, `test/httpsecconformance/runner.go`
- Test: `test/httpsec_nethttp_test.go`, `test/httpsec_gin_test.go`, `test/httpsec_fiber_test.go`, `httpsec/adapter_test.go`
- Modify: `test/go.mod` (add `ginsec` and `fibersec`, each with a `replace`)

**Interfaces:**
- Produces: `httpsecconformance.Scenarios() []Scenario`, `Scenario{Name string; Build func(*testing.T) ChainSpec; Request RequestSpec; Assert func(*testing.T, Result)}`, `httpsecconformance.Run(t *testing.T, adapter Adapter)`, and `Adapter interface{ Serve(t *testing.T, spec ChainSpec, req RequestSpec) Result }`.

**The direction of the dependency is the whole point, and an earlier draft of this plan had it backwards.** The `test` module is imported by **no** scrty module — not even from a `_test.go` file, because a test-only import still puts the helpers' dependencies in a consumer's module graph. So `ginsec` and `fibersec` must NOT require `github.com/kartaladev/scrty/test`.

The `test` module imports THEM instead: `test/go.mod` gains `ginsec` and `fibersec` (each with a `replace` onto its directory, since nothing is tagged), and all three adapter runs live in `test`. That also matches the project context, which places "conformance suites and the tests that use them" in the `test` module.

`TestModuleLayout` will not catch a mistake here: `layout_guard_test.go:141` skips any directory holding a `go.mod`, so the root guard never scans `ginsec` or `fibersec`. The rule is binding regardless of the guard. If you believe the direction must be reversed, STOP and report rather than adding the requirement to an integration module.

- [ ] **Step 1: Write the scenario table**

One table, exported, covering exactly the scenarios the spec lists:

```go
// Scenarios is every behaviour that must be identical on every adapter.
//
// It is data, not tests: each adapter's own suite runs it through its
// framework, so a change to an interceptor is checked on all three at once
// rather than on whichever one its author had in mind.
func Scenarios() []Scenario {
	return []Scenario{
		{Name: "login succeeds"},                  // 200, a token, one session created
		{Name: "login fails on a wrong password"}, // 401, no error text, one failed attempt
		{Name: "a locked account is refused"},     // 423, the password never checked
		{Name: "a valid bearer token is accepted"},
		{Name: "a tampered bearer token is refused"}, // 401
		{Name: "a centralized rule allows"},
		{Name: "a centralized rule denies"}, // 403, the route did not run
		{Name: "a guard allows"},
		{Name: "a guard denies"}, // 403, the route did not run
		{Name: "a login challenge"},
		{Name: "an endpoint answered by the chain"},   // logout: 200, empty, route skipped
		{Name: "the key set endpoint"},                // exact body, nothing appended
		{Name: "context propagation to the handler"},  // principal, session, upstream value
		{Name: "an unattributable client address"},    // refused, never pooled
	}
}
```

Each scenario's `Assert` checks the status, the library-set headers, the refusal error's identity and the session and attempt side effects — the four things the spec says must agree.

- [ ] **Step 2: Write the failing net/http run**

```go
func TestConformanceNetHTTP(t *testing.T) {
	t.Parallel()
	httpsecconformance.Run(t, nethttpAdapter{}) // httptest.NewServer
}
```

- [ ] **Step 3: Run it and confirm the red step**

Run: `go test -run TestConformanceNetHTTP -count=1 ./...` in `test`.
Expected: FAIL on every scenario until the adapter is written — and this is the run that proves the table is wired to something. Once net/http is green, it is the reference the other two are compared against.

- [ ] **Step 4: Write the gin and fiber runs, and watch each fail first**

```go
// test/httpsec_gin_test.go
func TestConformanceGin(t *testing.T) { httpsecconformance.Run(t, ginAdapter{}) }

// test/httpsec_fiber_test.go — TrustProxy with Proxies {"0.0.0.0"} and a
// forwarded header, because fiber's in-memory test transport reports an
// unspecified peer that a throttled flow would otherwise refuse.
func TestConformanceFiber(t *testing.T) { httpsecconformance.Run(t, fiberAdapter{}) }
```

Run each and read the failures. A scenario that fails on gin or fiber but passes on net/http is an adapter defect, and it is the suite's whole purpose to surface it there rather than in a consumer's application.

- [ ] **Step 5: Write the failing construction-parity test**

```go
// The same wiring mistake must fail the same way whichever framework is in
// front, because the chain is built before any of them is involved.
func TestConformanceConstruction(t *testing.T) {
	_, err := httpsec.New(httpsec.EnableFormLogin(httpsec.FormLoginDeps{ /* no Sessions */ }))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EnableFormLogin")
	assert.Contains(t, err.Error(), "session manager")
}
```

Run it in all three modules, asserting the identical message.

- [ ] **Step 6: Write the failing consumer-adapter test**

```go
// TestConsumerAdapter proves the abstraction really is the public adapter
// contract: a consumer supports another framework by implementing Request and
// ResponseWriter, with no change to any interceptor.
func TestConsumerAdapter(t *testing.T) {
	// A minimal "framework" of the test's own: a struct with a method map and a
	// byte buffer. Run form login and bearer authentication through
	// Chain.Assemble over it and assert the same outcomes as net/http.
}
```

- [ ] **Step 7: Gate and commit**

Run: `go test -race -count=1 ./...` in each of `.`, `test`, `ginsec`, `fibersec`. Then confirm the direction of the dependency holds: `grep -r "scrty/test" ginsec/ fibersec/` must print nothing, and neither module's `go.mod` may name it.

```bash
git add test/httpsecconformance/ test/httpsec_nethttp_test.go test/httpsec_gin_test.go test/httpsec_fiber_test.go test/go.mod httpsec/adapter_test.go
git commit -m "test: one conformance table every adapter runs

A change to an interceptor is checked on net/http, gin and fiber at once,
rather than on whichever one its author had in mind."
```

---

## Task 28: Settle the open questions and reconcile the artifacts

**Implements:** tasks.md 15.1, 15.2, 15.3, 15.4, 15.5

**Files:**
- Modify: `policy/policy.go`, `policy/engine.go`, `httpsec/doc.go`, `outbound/doc.go`
- Report (do **not** edit): `openspec/changes/http-security/design.md`, `openspec/changes/http-security/specs/http-error-propagation/spec.md`

- [ ] **Step 1: Confirm the phase helpers are unused, then unexport them**

```sh
gopls references ./policy/policy.go:<line of ContextWithPhase>
gopls references ./policy/policy.go:<line of PhaseFromContext>
```

Expected: the only references are inside `policy` itself (`Engine.EvaluatePhase` calls `ContextWithPhase`) and its tests. If any `httpsec` call site appears, **stop**: the question is answered the other way and the helpers stay exported. Report that rather than unexporting them.

With no external references, rename both to `contextWithPhase` and `phaseFromContext` (use `gopls rename`, not a text substitution), and update the `EvaluatePhase` godoc that currently points a consumer at `ContextWithPhase`.

- [ ] **Step 2: Verify nothing broke**

Run: `go build ./...` in every workspace module, then `go test -race -count=1 ./policy/`.
Then check the archived spec: `grep -n "ContextWithPhase\|PhaseFromContext" openspec/specs/security-policy/spec.md`. If it pins either as public, **report it and stop** — an archived spec is a settled decision, and changing it is the main session's call, not this task's.

- [ ] **Step 3: Write the failing flush-scope test**

```go
// TestFlushRefusalLogsScope pins that the chain flushes its own sampler and
// nothing else. authenticate and policy each sample under their own option and
// expose their own flush; reaching into them from here would make one call
// govern three subsystems.
func TestFlushRefusalLogsScope(t *testing.T) {
	// Assert: the chain's pending counts are reported after FlushRefusalLogs,
	// and a policy engine wired into the same chain, holding its own pending
	// counts, has NOT been flushed.
}
```

- [ ] **Step 4: Write the package godoc**

For `httpsec` and `outbound`, every exported option names the default it replaces, and every port says what the library uses when the consumer supplies none. Check with:

```sh
go doc -all ./httpsec | grep -c "The default"
go doc ./httpsec
go doc ./outbound
```

Read the output and confirm no exported `With*` or `Enable*` is missing its default, and no port is missing its "with none supplied" sentence.

- [ ] **Step 5: Run the full gate**

```sh
make check
```

Expected: green across `fmt-check`, `vet`, `lint`, `test`, `vuln` and `generate-check` in every workspace module. `generate-check` failing means `mockgen` output is stale — regenerate and commit it.

- [ ] **Step 6: Report the artifact reconciliation to the main session**

Do **not** edit anything under `openspec/`. Report, as a list the main session can act on:

1. `design.md` Decision 6 is stale — `policy.Engine` already substitutes `ErrPolicyDenied`, so departure (b) is retired and `policy.ErrPolicyDenied` is the mapped sentinel; `httpsec` declares none of its own.
2. `design.md` snippets name `authn`/`authz`; the packages are `authenticate`/`authorize`.
3. `EnableAuthorization` takes `...authorize.Rule[Request]`, because `authorize.Rule` is generic.
4. `httpsec` owns the session context key; `session` exports no helper.
5. `internal/nilcheck.IsNil` is reused for the typed-nil check; `signingkey.KeyManager.JWKS()` already returns the marshalled set.
6. The authorization stage wraps `authorize.ErrAuthenticationRequired` with `httpsec.ErrAuthenticationRequired` so either identity matches.
7. The `http-error-propagation` spec's refusal-contract requirement and status table should name `policy.ErrPolicyDenied` for the reasonless-deny row.
8. Both open questions are settled: the phase helpers are unexported, and the chain flushes only its own sampler.
9. The gin version `ginsec` pinned.

- [ ] **Step 7: Commit**

```bash
git add policy/ httpsec/doc.go outbound/doc.go httpsec/refusallog_test.go
git commit -m "refactor(policy): unexport the phase helpers

The chain always evaluates through an Engine, which sets the phase itself, so
no caller outside policy needs them. Settled before the first tag, while it is
still free."
```

---

## Self-Review

**Spec coverage.** Every requirement in the four delta specs maps to a task: the chain's ordering, continuation, registration, construction and context requirements to Tasks 1, 7, 8; form login, Basic and bearer to 13, 14, 15; the gate, logout, touch and key set to 16; both authorization models to 17, 18; the client-address and sampled-log requirements to 9, 10, 11; the seams to 12; every `http-error-propagation` requirement to 4, 5, 19; every `framework-adapters` requirement to 23, 24, 25, 26, 27; every `outbound-http-confinement` requirement to 20, 21, 22.

**Known gap, deliberate.** `specs/http-security-chain` names slots for federated login, API keys, client certificates and second-factor challenges. Task 6 reserves the constants; the interceptors themselves belong to `auth-methods` and `oidc-brokering`, as `design.md`'s Non-Goals state. Task 12's "another first factor" test is what holds the seam to its promise in the meantime.

**Type consistency.** `Next`, `Interceptor`, `Exchange`, `Order`, `Option`, `StatusForError`, `ChallengeError`, `completeLogin`, `sourceThrottled`, `Guards`, `RefusalError` are spelled identically everywhere they appear. `Request`/`ResponseWriter` are the same two interfaces in Tasks 1, 2, 3, 23, 25 and 27.

**Ordering.** Tasks 20–22 (`internal/origin`, `outbound`) touch no file Tasks 1–19 touch and can run alongside them. Tasks 23–26 need `httpsec` complete through Task 19. Task 27 needs all three adapters. Task 28 is last, because Step 1 can only be decided once every `httpsec` call site exists.
