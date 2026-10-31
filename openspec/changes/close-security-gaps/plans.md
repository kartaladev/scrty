# close-security-gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **DRAFT.** Written against the `reauthentication` and `key-port-context` work in progress on `feat/reauthentication`. Task group 1 re-reads what those changes landed and corrects this plan before any other task starts. Nothing below is to be executed before that.

**Goal:** Close the thirteen security gaps in `proposal.md` before `v0.1.0`.

**Architecture:** Every browser-facing layer is a chain interceptor in a new outer slot (headers 25, CORS 50, CSRF 75), written once against `httpsec.Request` and `ResponseWriter`, so net/http, gin and fiber share it. Trusted-proxy resolution wraps the adapter's `Request` once when the chain starts, and every interceptor and the handler read its answer. Sender-constrained tokens, sign-in listing and the password policy extend the existing `session`, `token` and `authenticate/password` cores.

**Tech Stack:** Go 1.27, `net/http`, gin, fiber v3, `github.com/lestrrat-go/jwx/v4` (JOSE), testify, `go.uber.org/mock`, testcontainers-go (PostgreSQL 15 and 18).

**Spec:** `openspec/changes/close-security-gaps/` — `proposal.md`, `design.md` (decisions D1–D18), `specs/**/spec.md`, `tasks.md`.

## Global Constraints

- Go 1.27 floor; every module declares `go 1.27`.
- The core module adds no dependency; the breach check uses the existing confined outbound client; JOSE work uses jwx v4 only.
- Nothing in `github.com/kartaladev/scrty/test` is imported by another scrty module, including from `_test.go` files.
- Test-first for every task (`golang-tdd.md`): run the new test and see it fail for the intended reason before writing code; a compile error is not a red step.
- Table tests follow the `table-test` skill (`assert` closures, `ctx` modifier, `t.Context()`); mocks come from `use-mockgen`; PostgreSQL comes from `use-testcontainers` helpers already in `test/`.
- Every option's godoc names the default it replaces; every port says what the library uses when none is supplied (`library-design.md`).
- Wiring mistakes fail at construction with an error wrapping `httpsec.ErrConfig` (or the package's own `ErrConfig`) that names the option.
- No error text, log record or event carries a password, token, proof, certificate, CSRF token, session identifier or stored hash.
- A defect found along the way is claimed only with a failing test (`defect-claims.md`).
- The predecessor is never cited in code, docs or commits (`legacy-reference.md`).
- Slot values: `OrderSecurityHeaders = 25`, `OrderCORS = 50`, `OrderCSRF = 75`.
- Defaults pinned by the specs: HSTS `max-age=31536000; includeSubDomains`; CORS max age 10 minutes; DPoP proof lifetime 60 seconds; DPoP algorithms `ES256`; trusted-proxy `MaxHops` 1; password minimum 15 (floor 8), maximum accepted at least 64, common list at least 3,000 entries; unseen-device window 90 days.

## Review Focus

- An IPv4-mapped IPv6 peer (`::ffff:10.20.0.2`) must match a trusted IPv4 prefix (`10.20.0.0/16`), and vice versa nothing else must. Test added to 2.5.
- Forwarded entries with ports, brackets, `unknown` or RFC 7239 obfuscated identifiers (`203.0.113.7:4711`, `[2001:db8::1]:443`, `for=_hidden`): ports stripped, non-IP identifiers ending the walk as an unattributable client. Test added to 2.5.
- A host compared with the allowlist case-insensitively and without its port (`App.Example.com:443` matches `app.example.com`). Test added to 2.6.
- DPoP `htu` normalisation: scheme and host lower-cased, default port dropped, path compared as sent (`https://APP.example.com:443/api/orders` equals `https://app.example.com/api/orders`). Test added to 8.6.
- `Origin: null` from a sandboxed iframe or a `file:` page, with no `Sec-Fetch-Site`, is refused on an unsafe method. Test added to 5.1.

---

## Delegation lanes

Each lane owns its files; a file not listed is held by the main session for review only. Lanes inside one phase run in parallel, each in its own worktree where noted, and merge in the order given. A lane longer than six tasks runs as sequential dispatches; after each dispatch the main session runs the verification commands and a fresh reviewer checks the diff.

| Phase | Lane | Tasks | Owns | Model (reason) |
|---|---|---|---|---|
| 0 | main session | 1.1–1.3 | OpenSpec artifacts only | — |
| A | R: request and proxies | 2.1–2.5, then 2.6–2.10 | `httpsec/nethttp.go`, `httpsec/client.go` (new), `httpsec/proxies.go` (new), `httpsec/chain.go`, `httpsec/throttle.go`, `httpsec/options.go`, `httpsec/errors.go`, `httpsec/ginsec/*`, `httpsec/fibersec/*`, `test/httpsecconformance/proxy_scenarios.go` (new) | Opus (an interface every other lane compiles against; security-critical refusal logic) |
| B (worktrees) | H: headers, CORS, CSRF | 3.1–3.5; 3.6–3.10; 4.1–4.5; 5.1–5.4; 5.5–5.7 | `httpsec/order_outer.go`, `headers.go`, `cors.go`, `csrf.go` (all new), `httpsec/logout.go`, conformance `headers_scenarios.go`, `cors_scenarios.go`, `csrf_scenarios.go` | Sonnet for 3.x (known pattern); Opus for 4.x and 5.x (refusal logic written for the first time) |
| B (worktrees) | S: sessions | 6.1–6.6; 7.1–7.5 | `session/*`, `store/sqlstore/session.go`, `store/pgxstore/session.go`, `store/gormstore/session.go`, `store/migrate/securitystate/` (new file), `test/storetest/session*.go`, `httpsec/session_management.go` (new), `authenticate/passkey` removal path, `notify` templates | Opus (store contract other modules implement; owner checks) |
| B (worktrees) | P: passwords | 10.1–10.5; 10.6–10.8 | `authenticate/password/*`, `httpsec/login.go`, `httpsec/basic.go`, `test/identity` history conformance | Opus for 10.1–10.5 (behaviour-preserving move of the reuse guard); Sonnet for 10.6–10.8 |
| B | T: supply chain | 13.1–13.4 | `.github/`, `tools/`, `Makefile` | Sonnet |
| C | D: sender-constrained tokens | 8.1–8.5; 8.6–8.9; 9.1–9.4 | `token/*`, `httpsec/dpop.go`, `httpsec/certbinding.go` (new), `httpsec/bearer.go`, `session_bearer.go`, `session_renewal.go`, `complete.go`, `mfa_verify.go`, `passkey_login.go`, `magiclink.go`, `oidc_redeem.go`, `recovery.go`, `reauth*.go`, conformance `dpop_scenarios.go` | Opus (security-critical verification; touches several packages) |
| C, after D | C: automation challenge | 12.1–12.3 | `httpsec/challenge.go` (new) and the call sites in `login.go`, `basic.go`, `magiclink.go`, `passkey_login.go`, `recovery.go` | Opus (refusal ordering before account lookup) |
| D | E: security events | 11.1–11.4 | a new `security` package, and every emitting call site | Opus (touches every package) |
| D, last | main session + reviewer | 14.1–14.3 | none | Opus reviewer |

`httpsec/errors.go` is owned by lane R in phase A; in phase B and later, each lane adds its own sentinel in its own file and appends its rows to the status table in `errors.go` within its worktree; the main session resolves the table merge (a few lines, stated when it happens).

---

## Task group 1: draft review (main session)

### Task 1.1: Reconcile with `reauthentication`

- [ ] Read the landed `reauthentication` specs (`openspec/specs/reauthentication`, the modified `http-error-propagation`, `sessions`, `multi-factor-auth`, `passkey-authentication`, `framework-adapters`) and `httpsec/reauth*.go`.
- [ ] Update this change's deltas where the landed text differs: the error table (fold the ADDED requirement into the modified contract if preferred), `Session.AuthenticatedWithin`, re-proof rotation (D8 binding), guard construction.
- [ ] Run `openspec validate close-security-gaps --strict`. Expected: no errors.
- [ ] Record the changes in `design.md` D1.

### Task 1.2: Reconcile with `key-port-context`

- [ ] Read the landed bearer requirement and `token-issuance` delta, and the new key-port signatures in `token/`.
- [ ] Update the `token-issuance` delta and D8 to the landed signatures; validate as in 1.1.

### Task 1.3: Settle the blocking open questions

- [ ] CSRF token style (synchronizer token on the session, or HMAC-signed double-submit cookie): decide, record in D6 with sources.
- [ ] Forwarded client-certificate header and encoding for nginx (`$ssl_client_escaped_cert`), Traefik and the team's gateway, from each proxy's documentation: record in D9 with sources.
- [ ] Run `openspec validate close-security-gaps --strict`; regenerate this plan's affected tasks (5.3, 9.2) through `/superpowers:writing-plans` if their shape changed.

---

## Task group 2: request host and scheme, trusted proxies (lane R)

**Interfaces produced (every later lane consumes these):**
- `type Request interface { ...existing...; Host() string; Secure() bool }` in `httpsec/exchange.go`'s interface block.
- `func WithHTTPSDeployment() Option`
- `type TrustedProxies struct { Prefixes []netip.Prefix; Headers HeaderFamily; MaxHops int }`
- `func XForwarded(fields ...ForwardedField) HeaderFamily`, `func Forwarded(fields ...ForwardedField) HeaderFamily`
- `const ForwardedFor, ForwardedProto, ForwardedHost ForwardedField`
- `func WithTrustedProxies(tp TrustedProxies, opts ...ProxyOption) Option`, `func TrustAllProxies() ProxyOption`, `func KeepForwardedHeaders() ProxyOption`
- `func WithAllowedHosts(hosts ...string) Option`
- `type Client struct { IP string; Secure bool; Host string; ViaProxy bool }`, `func ClientFromContext(ctx context.Context) (Client, bool)`
- `var ErrHostNotAllowed = errors.New("httpsec: host not allowed")`

### Task 2.1: `Host()` and `Secure()` on the net/http request
**Files:** Modify `httpsec/exchange.go` (interface), `httpsec/nethttp.go`; Test `httpsec/nethttp_test.go`
- [ ] Red: `TestHTTPRequest_HostAndSecure`, table over `httptest.NewRequest` with `r.Host = "app.example.com"` and `r.TLS` set / nil; assert `Host()` and `Secure()`.
- [ ] Run `go test -run TestHTTPRequest_HostAndSecure -count=1 ./httpsec/` — expect FAIL: `Host` undefined is a compile error, so first add the methods returning zero values, re-run, expect FAIL on the assertions.
- [ ] Green: `func (h *httpRequest) Host() string` returns `h.r.Host`; `Secure()` returns `h.r.TLS != nil`.
- [ ] Run again — PASS. Commit `feat(httpsec): requests expose host and transport security`.

### Task 2.2: Adapters implement them
**Files:** Modify `httpsec/fibersec/exchange.go`; gin reuses `NewHTTPRequest`; Test `httpsec/fibersec/exchange_test.go`, `httpsec/ginsec/middleware_test.go`
- [ ] Red: `TestRequest_HostAndSecure` in each adapter module, a fiber app served over `httptest` TLS and plain; assert host `app.example.com` and secure flag.
- [ ] Run `go test -run TestRequest_HostAndSecure ./...` in each module — expect FAIL.
- [ ] Green: fiber reads the request's `Host` header and the connection's TLS state, never `c.Hostname()`, `c.Secure()` or `c.Scheme()` (they honour fiber's proxy trust).
- [ ] PASS; commit.

### Task 2.3: `WithHTTPSDeployment`
**Files:** Create `httpsec/client.go`; Modify `httpsec/options.go`; Test `httpsec/client_test.go`
- [ ] Red: `TestHTTPSDeployment` — a plain request through a chain with the option sees `Secure() == true`; a chain with both this option and `WithTrustedProxies` fails `New` with `ErrConfig` naming `WithHTTPSDeployment`.
- [ ] Run; expect FAIL. Green: a resolved-request wrapper in `client.go` overriding `Secure()`; the conflict check in `New`. PASS; commit.

### Task 2.4: Trusted-proxy construction rules
**Files:** Create `httpsec/proxies.go`; Test `httpsec/proxies_test.go`
- [ ] Red: `TestTrustedProxies_Construction`, one table: empty prefixes; `0.0.0.0/0`; `::/0`; no family; family with no fields; `ForwardedHost` without `WithAllowedHosts`; `MaxHops: 0`; `TrustAllProxies()` with `0.0.0.0/0` succeeds. Each assert names the option in the error.
- [ ] Run; expect FAIL. Green: validation in `WithTrustedProxies` and `New`. `MaxHops` zero value means "unset" and defaults to 1; an explicit negative is refused. PASS; commit.

### Task 2.5: Right-to-left resolution
**Files:** Modify `httpsec/proxies.go`, `httpsec/client.go`, `httpsec/chain.go` (wrap the adapter request before the first interceptor); Test `httpsec/proxies_test.go`
- [ ] Red: `TestTrustedProxies_Resolve`, a table built from the `trusted-proxies` scenarios: forged left-most entry (`1.2.3.4, 203.0.113.7` → `203.0.113.7`); bypassed proxy; two hops with `MaxHops: 2`; repeated `X-Forwarded-For` headers joined; other family ignored; unnamed field ignored; unparsable header ignored. Review Focus rows: `::ffff:10.20.0.2` matching `10.20.0.0/16`; entries with ports and brackets; `unknown` and `for=_hidden` ending the walk as an unattributable client.
- [ ] Run; expect FAIL. Green: parse with `netip.ParseAddr` after stripping port and brackets, `Unmap()` before prefix checks; scheme and host taken from the client's hop (`X-Forwarded-Proto`/`-Host` read as single values set by the nearest trusted proxy; RFC 7239 `proto=`/`host=` from the client's element). PASS; commit.

### Task 2.6: Host allowlist
**Files:** Modify `httpsec/proxies.go`, `httpsec/errors.go`; Test `httpsec/proxies_test.go`, `httpsec/errors_test.go`
- [ ] Red: `TestTrustedProxies_HostNotAllowed` (`evil.example` refused before the handler runs; Review Focus row: `App.Example.com:443` accepted for `app.example.com`), and a `TestStatusForError` row `ErrHostNotAllowed → 400`.
- [ ] Run; expect FAIL. Green: compare lower-cased host without port; register the sentinel and row. PASS; commit.

### Task 2.7: Header removal on every adapter
**Files:** Modify `httpsec/proxies.go`, `httpsec/fibersec/exchange.go`, `httpsec/ginsec/middleware.go`; Test the three modules
- [ ] Red: `TestTrustedProxies_RemovesHeaders` in core, gin and fiber: a handler after the chain sees no `X-Forwarded-*` and no `Forwarded`; with `KeepForwardedHeaders()` it sees them unchanged.
- [ ] Run; expect FAIL. Green: an optional `headerRemover` interface the adapters' requests implement (`DelHeader(name string)`), called after resolution. PASS; commit.

### Task 2.8: `ClientFromContext` and the source guards
**Files:** Modify `httpsec/client.go`, `httpsec/throttle.go`; Test `httpsec/client_test.go`, `httpsec/throttle_test.go`
- [ ] Red: `TestClientFromContext` (IP, Secure, Host, ViaProxy for a proxied request) and `TestSourceGuard_UsesResolvedClient` (the limiter key is the forwarded client, not the proxy).
- [ ] Run; expect FAIL. Green: store `Client` in the request context at resolution; source guards read `Request.ClientIP()` of the resolved request. PASS; commit.

### Task 2.9: Adapters stop deferring to their frameworks (BREAKING)
**Files:** Modify `httpsec/ginsec/middleware.go`, `httpsec/fibersec/middleware.go`; Create `test/httpsecconformance/proxy_scenarios.go`; Modify `test/httpsecconformance/runner.go`
- [ ] Red: conformance scenarios "gin's own trusted proxies do not change the chain", "Same answer on every adapter", "Opting into gin's client address", "fiber with a trusted proxy".
- [ ] Run `go test -run 'TestConformance' ./...` in `test`; expect FAIL on gin.
- [ ] Green: remove `ginsec.WithForwardedClientIP`; both adapters hand the raw peer to the chain. PASS; commit `feat(httpsec)!: adapters resolve clients through the chain's trusted proxies`.

### Task 2.10: Documentation
**Files:** godoc in `httpsec/proxies.go`, `client.go`; `README.md`
- [ ] Godoc each option with its default; README section with the nginx and Traefik configurations from the gap review (Case 3). Verify `go doc ./httpsec WithTrustedProxies` and `go vet ./...` clean. Commit.

---

## Task group 3: outer slots and security headers (lane H, dispatches H1: 3.1–3.5, H2: 3.6–3.10)

**Interfaces produced:**
- `const OrderSecurityHeaders Order = 25; OrderCORS Order = 50; OrderCSRF Order = 75` in `httpsec/order_outer.go`
- `func EnableSecurityHeaders(opts ...HeaderOption) Option`
- `func WithHSTS(maxAge time.Duration, opts ...HSTSOption) HeaderOption`, `func HSTSIncludeSubdomains() HSTSOption`, `func HSTSPreload() HSTSOption`
- `type CSPPolicy`, `func StrictCSP(directives ...CSPDirectiveValue) CSPPolicy`, `func HashCSP(sha256Hashes ...string) CSPPolicy`, `func CSPDirective(name string, sources ...string) CSPDirectiveValue`, `func WithCSP(p CSPPolicy) HeaderOption`
- `func WithCSPReportOnly() HeaderOption`, `func WithReportingEndpoint(name, url string) HeaderOption`
- `type HeaderProfile`, `func APIHeaders() HeaderProfile`, `func WithHeaderProfile(p HeaderProfile, m RouteMatcher) HeaderOption`, `type RouteMatcher func(Request) bool`, `func PathPrefix(prefix string) RouteMatcher`
- `func WithHeader(name, value string) HeaderOption`, `func WithoutHeader(name string) HeaderOption`
- `func CSPNonce(ctx context.Context) (string, bool)`
- `func WithLogoutClearSiteData(directives ...string) LogoutOption`

### Task 3.1: Outer slots
- [ ] Red `TestOrder_OuterSlots`: `OrderSecurityHeaders < OrderCORS < OrderCSRF < OrderJWKS`, each 25 apart. Fail, add constants, pass, commit.

### Task 3.2: Default document headers
**Files:** Create `httpsec/headers.go`; Test `httpsec/headers_test.go`
- [ ] Red `TestSecurityHeaders_Defaults`: the four headers with the exact spec values; none of `X-XSS-Protection`, `X-Frame-Options`, `Cross-Origin-Embedder-Policy`, `Origin-Agent-Cluster`; a 401 from a bearer refusal carries the same headers; a chain without the layer sets none.
- [ ] Fail; Green: interceptor at `OrderSecurityHeaders` that calls `SetHeader` before `next`. Pass; commit.

### Task 3.3: Nonce
- [ ] Red `TestSecurityHeaders_Nonce`: `CSPNonce` equals the header's nonce; two responses differ; decoded length ≥ 16 bytes; a failing randomness source (test seam `export_test.go`) yields 500 and no CSP header.
- [ ] Fail; Green: 16 bytes from `crypto/rand`, base64 std encoding, context value. Pass; commit.

### Task 3.4: Profiles
- [ ] Red `TestSecurityHeaders_Profiles`: `/api/orders` under `PathPrefix("/api/")` gets the API profile and no nonce; `/` gets the document set; the first matching profile wins.
- [ ] Fail; Green; pass; commit.

### Task 3.5: HSTS
- [ ] Red `TestSecurityHeaders_HSTS`: secure request gets the header; insecure does not; behind a trusted proxy forwarding `https` it does; `HSTSPreload()` with `maxAge < 365*24h` or without subdomains fails `New` naming `WithHSTS`.
- [ ] Fail; Green (reads `Request.Secure()` from group 2); pass; commit.

### Task 3.6: Handler wins, streaming intact
- [ ] Red `TestSecurityHeaders_HandlerWins` (handler's `Referrer-Policy: no-referrer` is sent) and `TestSecurityHeaders_Streaming` (`http.NewResponseController(w).Flush()` and `Hijack()` succeed behind the layer).
- [ ] Fail if wrapping was introduced, else these pass at once: invert temporarily (wrap the writer in a test build) to see them fail, then restore. Commit.

### Task 3.7: Report-only and hash preset
- [ ] Red `TestSecurityHeaders_ReportOnly` (`Content-Security-Policy-Report-Only` present, enforced header absent, `Reporting-Endpoints: csp="https://reports.example.com/csp"`, policy carries `report-to csp` and `report-uri https://reports.example.com/csp`) and `TestSecurityHeaders_HashPreset` (`script-src 'sha256-…'`, no nonce generated).
- [ ] Fail; Green; pass; commit.

### Task 3.8: Clear-Site-Data on logout
**Files:** Modify `httpsec/logout.go`; Test `httpsec/logout_test.go`
- [ ] Red `TestLogout_ClearSiteData`: opted in with `"cache"`, `"storage"` over HTTPS → `Clear-Site-Data: "cache", "storage"`; over HTTP → absent; not opted in → absent; an unknown directive fails construction.
- [ ] Fail; Green; pass; commit.

### Task 3.9: Conformance on three adapters
- [ ] Create `test/httpsecconformance/headers_scenarios.go` with the spec scenarios; register in `runner.go`; run `go test -run TestConformance ./...` in `test` (fail before registration of the interceptor in the adapters' builds is impossible, so invert one expected value to see a failure, then restore). Commit.

### Task 3.10: Docs
- [ ] Godoc each option with its default; README section with the Vite (`html.cspNonce: '__CSP_NONCE__'`), Next.js and `html/template` examples. `go doc ./httpsec EnableSecurityHeaders`. Commit.

---

## Task group 4: CORS (lane H, dispatch H3)

**Interfaces produced:**
- `type CORSPolicy struct { AllowedOrigins, AllowedMethods, AllowedHeaders, ExposedHeaders []string; AllowCredentials bool; MaxAge time.Duration }`
- `func EnableCORS(p CORSPolicy, opts ...CORSOption) Option`, `func WithOriginPattern(pattern string) CORSOption`, `func WithoutAutomaticCORSHeaders() CORSOption`
- Unexported hooks read from the chain config: `config.dpopEnabled bool`, `config.csrfTokenHeader string` (set by groups 5 and 8).

### Task 4.1: Construction refusals
- [ ] Red `TestCORS_Construction` table: no origins; `null`; origin with path, query, fragment, userinfo; `*` with credentials; `https://*.example.com` without `WithOriginPattern`. Each names the field. Fail; Green in `httpsec/cors.go`; pass; commit.

### Task 4.2: Matching and actual responses
- [ ] Red `TestCORS_Origins`: exact match (scheme and host case-insensitive) gets `Access-Control-Allow-Origin` and `Vary: Origin`; `https://app.example.com.evil.example` gets nothing; credentials never with `*`; disallowed origin request still reaches the handler. Fail; Green; pass; commit.

### Task 4.3: Preflight
- [ ] Red `TestCORS_Preflight`: allowed preflight → 204, allow headers, `Access-Control-Max-Age: 600`, no authentication interceptor called (a recording interceptor at `OrderBearerToken`); `MaxAge: time.Hour` → `3600`; disallowed origin or method → 204 without CORS headers. Fail; Green; pass; commit.

### Task 4.4: Follows the chain
- [ ] Red `TestCORS_FollowsChain`: with `config.dpopEnabled` set through `export_test.go`, `DPoP` is allowed and `DPoP-Nonce`, `WWW-Authenticate` exposed; with `config.csrfTokenHeader = "X-CSRF-Token"` it is allowed; `WithoutAutomaticCORSHeaders()` adds nothing. Fail; Green; pass; commit.

### Task 4.5: Conformance and docs
- [ ] `test/httpsecconformance/cors_scenarios.go`; run in `test`; godoc with defaults. Commit.

---

## Task group 5: CSRF protection (lane H, dispatches H4: 5.1–5.4, H5: 5.5–5.7)

**Interfaces produced:**
- `func EnableCSRFProtection(opts ...CSRFOption) Option`, `func WithCSRFTrustedOrigins(origins ...string) CSRFOption`, `func WithoutCORSOriginsTrustedForCSRF() CSRFOption`, `func WithCSRFTokenNames(header, field string) CSRFOption`, `func WithCSRFExemption(method, pattern string) CSRFOption`, `func WithoutCSRFProtection() Option`
- `func CSRFToken(ctx context.Context) (string, bool)`
- `var ErrCrossSiteRequest = errors.New("httpsec: cross-site request refused")`
- Interceptors that authenticate by cookie declare it through an unexported `cookieAuthenticator` marker the construction check reads.

### Task 5.1: Fetch Metadata and Origin
- [ ] Red `TestCSRF_FetchMetadata`: a table over method × `Sec-Fetch-Site` × `Origin`, each row also run through `net/http.CrossOriginProtection` as the oracle for rows where both should agree (same-site rows differ only when the origin is trusted); Review Focus row: `Origin: null`, no `Sec-Fetch-Site`, `POST` → refused.
- [ ] Fail; Green in `httpsec/csrf.go` at `OrderCSRF`, comparing against `Request.Secure()`/`Host()`; pass; commit.

### Task 5.2: Trusted origins
- [ ] Red `TestCSRF_TrustedOrigins`: CORS-allowed sibling passes on `same-site`; with `WithoutCORSOriginsTrustedForCSRF()` it is refused; `WithCSRFTrustedOrigins` adds one. Fail; Green; pass; commit.

### Task 5.3: Token layer (style from task 1.3)
- [ ] Red `TestCSRF_Token`: cookie-authenticated `POST` with no token, a malformed token, another session's token → refused; correct token → passes; bearer-only `POST` with no token → passes; `CSRFToken(ctx)` returns the token for the session.
- [ ] Fail; Green; pass; commit.

### Task 5.4: Mandatory with cookie authentication
- [ ] Red `TestCSRF_RequiredWithCookies`: a test interceptor carrying the cookie marker without `EnableCSRFProtection` fails `New` naming CSRF protection; with `WithoutCSRFProtection()` it builds. Fail; Green; pass; commit.

### Task 5.5: Exemptions
- [ ] Red `TestCSRF_Exemptions`: `WithCSRFExemption("POST", "/webhooks/payments")` passes cross-site; back-channel logout path passes by default; no option exempts everything (the API has none — assert via a compile-time absent symbol check is not possible, so assert that an empty pattern fails construction). Fail; Green; pass; commit.

### Task 5.6: Status and conformance
- [ ] Red `TestStatusForError` row `ErrCrossSiteRequest → 403`; conformance `csrf_scenarios.go`, including a cross-site post to the password re-proof endpoint. Fail; Green; pass; commit.

### Task 5.7: Docs
- [ ] Godoc with defaults; README on the token accessor and exemptions. Commit.

---

## Task group 6: sessions — listing, metadata, binding (lane S, dispatch S1)

**Interfaces produced:**
- `session.Store`: `ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*Session, error)` (live, non-superseded members; the manager groups by family).
- `type SignIn struct { Handle id.ID; CreatedAt, LastUsedAt time.Time; FirstFactor identity.FirstFactor; ClientIP, UserAgent string; Current bool }`
- `func (m *Sessions) ListSignIns(ctx context.Context, user identity.UserID, current string) ([]SignIn, error)`
- `func (m *Sessions) EndSignIn(ctx context.Context, user identity.UserID, handle id.ID) error` (returns `ErrNotFound` for another user's family), `func (m *Sessions) EndOtherSignIns(ctx context.Context, user identity.UserID, keep string) (int, error)`
- `func WithSessionMetadata() Option`; `CreateOption`s `WithClientMetadata(ip, userAgent string)` and `WithKeyBinding(b KeyBinding)`
- `type KeyBinding struct { JKT string; X5TS256 string }` (at most one set); `Session.KeyBinding` field, written by `Create` only.

### Task 6.1: `ListByUser` in memory
- [ ] Red `TestMemoryStore_ListByUser` and `TestSessions_ListSignIns`: two families, one renewed twice → two sign-ins; expired-only family absent; superseded members absent; another user's absent. Fail; Green in `session/store_memory.go`, `session/sessions.go`; pass; commit.

### Task 6.2: Metadata
- [ ] Red `TestSessions_Metadata`: off by default (empty fields); with `WithSessionMetadata()` the chain-resolved IP and a user agent truncated to 256 bytes are kept across renewal. Fail; Green; pass; commit.

### Task 6.3: Key binding
- [ ] Red `TestSessions_KeyBinding`: successor of rotation, renewal and re-authentication rotation keeps the binding; `Save` of a copy with the binding cleared leaves it stored. Fail; Green (successor construction in `sessions.go`; `Save` preserves the field like `MFAAtFirstFactor`); pass; commit.

### Task 6.4: End by handle
- [ ] Red `TestSessions_EndSignIn`: own handle revokes the family; another user's handle → `ErrNotFound`, nothing revoked; `EndOtherSignIns` keeps the current family. Fail; Green over `RevokeFamily`; pass; commit.

### Task 6.5: Migration
**Files:** Create `store/migrate/securitystate/20261101000000_session_signins.sql` (date set at implementation); Test `test/migrate_securitystate_test.go`
- [ ] Red: populated-database test (sessions created under the previous migration still load, unbound, without metadata) and rollback test, on PostgreSQL 15 and 18.
- [ ] Fail; Green: nullable `client_ip text`, `user_agent text`, `binding_jkt text`, `binding_x5t text`, index on `(user_ref, absolute_expires_at)` (column names reconciled with the existing table at implementation). Pass; commit.

### Task 6.6: Durable stores
- [ ] Red: new cases in `test/storetest` session suite (listing, metadata, binding round trip, binding untouched by save, another user's sessions never listed). Run `go test ./...` in `test`; expect FAIL for every durable store.
- [ ] Green in `store/sqlstore/session.go`, `store/pgxstore/session.go`, `store/gormstore/session.go`, and the sealing decorator in `session/store_encrypted.go`. Pass; commit.

---

## Task group 7: session management endpoints and notices (lane S, dispatch S2)

**Interfaces produced:**
- `func EnableSessionManagement(m *session.Sessions, opts ...SessionManagementOption) Option`, `func WithSessionManagementPrefix(p string) SessionManagementOption` (default `/sessions`)
- `var ErrSignInNotFound` mapped to 404
- `func WithoutPasskeyRemovalNotification() PasskeyOption`
- `func WithSignInNotice(sender notify.Sender, opts ...SignInNoticeOption) Option`, `func SignInNoticeWindow(d time.Duration) SignInNoticeOption` (default 90 days)

### Task 7.1: Endpoints
- [ ] Red `TestSessionManagement`: list marks the current sign-in and carries no session identifier; "Sign out other devices" with a 2-minute-old authentication; "Stale session" with a 2-hour-old one refused with the reauthentication-required error; "Another user's handle" → 404. Fail; Green in `httpsec/session_management.go`, using `Session.AuthenticatedWithin` from `reauthentication`; pass; commit.

### Task 7.2: Status
- [ ] Red `TestStatusForError` row `ErrSignInNotFound → 404`; fail; register; pass; commit.

### Task 7.3: Passkey removal notice
- [ ] Red `TestPasskey_RemovalNotice` (label and time in the message, no credential ID or user handle; opt-out sends nothing; send failure keeps the removal). Fail; Green in the passkey manage path and `notify`; pass; commit.

### Task 7.4: Unseen-device sign-in notice
- [ ] Red `TestSignInNotice`: new metadata → notice; matching metadata within 90 days → none; enabled without `WithSessionMetadata` or without a sender → `New` fails naming the notice. Fail; Green after login completion, through the sender (queued senders return at once); pass; commit.

### Task 7.5: Conformance and docs
- [ ] Conformance scenarios on three adapters; godoc and README with defaults. Commit.

---

## Task group 8: confirmation claim and DPoP (lane D, dispatches D1: 8.1–8.5, D2: 8.6–8.9)

**Interfaces produced:**
- `token`: an issuing option `WithConfirmation(c Confirmation)`; `type Confirmation struct { JKT, X5TS256 string }`; the verifier's result exposes `Confirmation`.
- `httpsec`: `type DPoP struct { Require bool; ProofMaxAge time.Duration; Replay ReplayStore; Algorithms []jwa.SignatureAlgorithm }`, `func WithDPoP(d DPoP) BearerTokenOption` (and the session-bearer equivalent), `func WithoutDPoP() BearerTokenOption`, `func WithDPoPNonce() Option`, `func WithPublicURL(base string) Option`
- `type ReplayStore interface { Seen(ctx context.Context, jtiDigest string, until time.Time) (bool, error) }` with an in-memory default
- `var ErrInvalidDPoPProof`, `var ErrDPoPNonceRequired` (both 401)

### Task 8.1: `cnf` claim
- [ ] Red `TestGenerator_Confirmation` (`jkt`, `x5t#S256`, none) and `TestVerifier_Confirmation` (returned; malformed `cnf` refused); both set is a configuration error. Fail; Green in `token/claims.go`, `generator.go`, `verifier.go`; pass; commit.

### Task 8.2: Proof verification
**Files:** Create `httpsec/dpop.go`; Test `httpsec/dpop_test.go`
- [ ] Red `TestDPoP_Proof`: a table of proofs signed with jwx v4 — valid; wrong `typ`; `alg: none`; HS256; private key in `jwk`; bad signature; wrong `htm`; wrong `htu`; `iat` 61 s old; `iat` 61 s ahead; missing `jti`; wrong `ath`; two `DPoP` headers. Every failure is `ErrInvalidDPoPProof`.
- [ ] Fail; Green: parse with `jws.Parse`, verify with the embedded `jwk`, thumbprint per RFC 7638 (`jwk.Key.Thumbprint(crypto.SHA256)`); pass; commit.

### Task 8.3: Replay store
- [ ] Red `TestDPoP_Replay` (a `jti` seen within 60 s refused; after 60 s accepted again; store error refuses and maps to 500), run with `-race` and two concurrent identical proofs → exactly one accepted. Fail; Green: in-memory store keyed by the `jti` digest with expiry sweep; pass; commit.

### Task 8.4: Bearer interceptors
- [ ] Red `TestDPoP_Bearer`: `Authorization: DPoP` accepted with a proof; unbound `Bearer` still accepted; bound token as `Bearer` refused; bound token with another key's proof refused; `Require: true` refuses an unbound token; `WithoutDPoP()` refuses the `DPoP` scheme. Fail; Green in `bearer.go` and `session_bearer.go`; pass; commit.

### Task 8.5: Binding at every issuing endpoint
- [ ] Red `TestDPoP_Binding`: one row per endpoint (login, MFA verify, passkey login, magic link, OIDC handoff, recovery completion, re-authentication, renewal) — a proof without `ath` yields a token with `cnf.jkt` and a bound session; renewal of a bound session without the bound key refused. Fail; Green through one helper the issuing paths call (`complete.go` and the endpoints that mint on their own); pass; commit.

### Task 8.6: Public URL
- [ ] Red `TestDPoP_PublicURL`: trusted proxy forwards `https` and `app.example.com`, app sees `http://10.20.1.5:8080/api/orders`, proof `htu` `https://app.example.com/api/orders` passes; `WithPublicURL` overrides; Review Focus row: `https://APP.example.com:443/api/orders` equals `https://app.example.com/api/orders`. Fail; Green; pass; commit.

### Task 8.7: Nonces and challenges
- [ ] Red `TestDPoP_Nonce` (opt-in; missing nonce → 401 `WWW-Authenticate: DPoP error="use_dpop_nonce"` plus `DPoP-Nonce`), `TestDPoP_Challenge` (invalid signature → `DPoP error="invalid_dpop_proof", algs="ES256"`), and `TestStatusForError` rows → 401. Fail; Green; pass; commit.

### Task 8.8: End to end
- [ ] Conformance `dpop_scenarios.go` on three adapters; a recorded proof vector produced by the gap review's `dpop.ts` in a headless browser (fixture in `test/testdata/dpop/`) verifies against a test server. Commit.

### Task 8.9: Docs
- [ ] Godoc `WithDPoP` with its defaults; README with the React, Next.js and htmx samples. Commit.

---

## Task group 9: mTLS-bound tokens (lane D, dispatch D3)

**Interfaces produced:** `func WithCertificateBinding() BearerTokenOption`; `TrustedProxies.ClientCertHeader string` (from task 1.3); `var ErrCertificateBinding` (401); the check runs at `OrderMTLS`.

### Task 9.1: Direct TLS
- [ ] Red `TestCertificateBinding_Direct` over `httptest.NewUnstartedServer` with `tls.RequireAnyClientCert`: signing in with certificate C binds `x5t#S256`; later request with C passes. Fail; Green in `httpsec/certbinding.go`; pass; commit.

### Task 9.2: Forwarded certificate
- [ ] Red `TestCertificateBinding_Forwarded`: header from a trusted peer parsed (encoding from 1.3); same header from an untrusted peer ignored. Fail; Green; pass; commit.

### Task 9.3: Refusal and conformance
- [ ] Red: bound token without its certificate → `ErrCertificateBinding` → 401; conformance on three adapters. Fail; Green; pass; commit.

### Task 9.4: Docs
- [ ] Godoc and README with the proxy configuration. Commit.

---

## Task group 10: password policy and rehash (lane P, dispatches P1: 10.1–10.5, P2: 10.6–10.8)

**Interfaces produced:**
- `func NewPolicy(opts ...PolicyOption) (*Policy, error)`; `func (p *Policy) Check(ctx context.Context, user *identity.Details, candidate string) error`; `func (p *Policy) Change(ctx context.Context, user *identity.Details, candidate string, write WriteFunc) error`
- Options: `MinLength(n int)`, `MaxLength(n int)`, `WithoutCommonPasswords()`, `CommonPasswords(list []string)`, `ContextWords(fn func(*identity.Details) []string)`, `Breached(src BreachSource, onFailure LookupFailure)`, `PwnedPasswords(c *outbound.Client) BreachSource`, `const Refuse, Accept LookupFailure`, `NoReuse(h History, depth int, opts ...ReuseOption)`, `WithEncoder(e Encoder)`, `WithClock(c clock.Clock)`
- `var ErrPasswordRejected`; `type RejectedError struct { Rule Rule }`; `ErrPasswordReused` also matches `ErrPasswordRejected`
- `type Upgrader interface { NeedsUpgrade(encoded []byte) bool }`
- `httpsec`: `func WithLoginRehash(fn func(ctx context.Context, user *identity.Details, hash []byte) error) LoginOption` (and the Basic equivalent)

### Task 10.1: Defaults and option semantics
- [ ] Red `TestPolicy_Defaults` and `TestPolicy_Options` with the `password-policy` scenarios (a 16-character list entry; `short`; `MinLength(8)` keeps the list; `WithoutCommonPasswords()` removes it). Fail; Green in `authenticate/password/policy.go`; embed the list as `authenticate/password/common.txt` via `embed`; pass; commit.

### Task 10.2: Length and context words
- [ ] Red `TestPolicy_Length` (15 three-byte characters pass; 64 accepted; `MinLength(6)` refused at construction) and `TestPolicy_ContextWords`. Fail; Green with `utf8.RuneCountInString`; pass; commit.

### Task 10.3: Breach check
- [ ] Red `TestPolicy_Breached` against an `httptest` range server: request path is the first 5 SHA-1 hex characters only, carries `Add-Padding: true`; hit refused; padded zero-count rows ignored; timeout with `Refuse` → policy-unavailable error; with `Accept` → accepted; no failure mode → construction error. Fail; Green; pass; commit.

### Task 10.4: Move the reuse guard into `NoReuse` (BREAKING)
- [ ] Red: port every test in `authenticate/password/reuse_test.go` and the history conformance in `test/identity` to `NewPolicy(NoReuse(...))`; they fail to compile only on the removed name, then — after a stub `NoReuse` returning a rule that accepts everything — fail on behaviour.
- [ ] Green: move the guard's logic behind `NoReuse`; delete `NewReuseGuard`; sign-up rule (no stored hash, no history → accept). Pass; commit `feat(password)!: one password policy, reuse included`.

### Task 10.5: Status
- [ ] Red `TestStatusForError` rows: each rule's refusal → 422; `ErrPasswordReused` → 422 and `errors.Is(err, ErrPasswordRejected)`. Fail; Green; pass; commit.

### Task 10.6: Upgrader
- [ ] Red `TestEncoder_NeedsUpgrade`: Argon2id 128 MiB asked about 64 MiB → true; own hash → false; bcrypt cost raised → true; scrypt N raised → true. Fail; Green; pass; commit.

### Task 10.7: Login rehash
- [ ] Red `TestLogin_Rehash`: outdated hash with a write → write gets a 128 MiB hash; no write → nothing; write error → login still succeeds and the log record carries no password or hash. Fail; Green in `login.go`, `basic.go`; pass; commit.

### Task 10.8: Docs
- [ ] Godoc each option with its default; README password section, including the breach check's failure-mode choice. Commit.

---

## Task group 11: security events (lane E)

**Interfaces produced:** package `github.com/kartaladev/scrty/security`: `type Event struct { Name string; At time.Time; Outcome string; User identity.UserID; ClientIP string; Factor identity.FirstFactor; Session string }`, `type Sink func(ctx context.Context, e Event)`, name constants (`LoginSuccess = "authn_login_success"`, ...); `httpsec.WithSecurityEvents(s security.Sink) Option`.

### Task 11.1: Package and sink
- [ ] Red `TestSecurityEvents_Sink` (no sink → nothing; failed login → one `authn_login_fail`). Fail; Green; pass; commit.

### Task 11.2: Emission everywhere
- [ ] Red `TestSecurityEvents_Emitted`: one table row per event name in the spec list and per `scrty_` name; each asserts no secret in any field. Fail; Green at each call site; pass; commit.

### Task 11.3: Observers as events
- [ ] Red `TestSecurityEvents_Observers`: lockout report → `authn_login_lock`; reuse → `authn_token_reuse`; configured observers still called. Fail; Green; pass; commit.

### Task 11.4: Docs
- [ ] Godoc lists every name. Commit.

---

## Task group 12: automation challenge (lane C)

**Interfaces produced:** `type ChallengeVerifier interface { Verify(ctx context.Context, r Request, s ChallengeSignals) (ChallengeDecision, error) }`, `type ChallengeSignals struct { SourceFailures, IdentifierFailures int }`, `const ChallengePass, ChallengeRefuse, ChallengeNotNeeded`, `func WithChallengeVerifier(v ChallengeVerifier, opts ...ChallengeOption) Option`, `func WithChallengeFlows(flows ...ChallengeFlow) ChallengeOption`, `func WithoutChallengeRefusalCounting() ChallengeOption`, `var ErrChallengeRequired` (403).

### Task 12.1: Flows
- [ ] Red `TestChallenge_Flows` with a mockgen `ChallengeVerifier`: refusal before account lookup and without a lockout failure, for each of the five flows; unselected flow not called; no verifier → no calls. Fail; Green; pass; commit.

### Task 12.2: Signals, counting, status
- [ ] Red `TestChallenge_Signals`, `TestChallenge_CountsAgainstSource`, `TestStatusForError` row → 403. Fail; Green; pass; commit.

### Task 12.3: Conformance and docs
- [ ] Three adapters; godoc and README. Commit.

---

## Task group 13: supply chain (lane T)

### Task 13.1: SHA pins and the check
- [ ] Red: a check script `tools/cmd/pincheck` (or a vetted `tool` directive) run in CI on a scratch branch referencing `actions/checkout@v5` → fails naming the workflow and action.
- [ ] Green: pin every action in `.github/workflows/ci.yml` to its commit SHA with `# vX.Y.Z`; the check passes on `main`. Commit.

### Task 13.2: Dependabot
- [ ] Add `.github/dependabot.yml` with a `gomod` entry per published module directory and one `github-actions` entry, weekly. Verify GitHub's configuration check accepts it. Commit.

### Task 13.3: SBOM
- [ ] Add the generator as a `tool` directive in `tools/go.mod`; a `sbom` target in `Makefile` producing one file per published module; the release gate fails when generation fails (prove with a broken module path first). Commit.

### Task 13.4: Vulnerabilities block the release
- [ ] On a disposable branch, pin a module to a known-vulnerable version and see the gate fail; make `vuln` part of the release gate; the gate passes on `main`. Commit.

---

## Task group 14: integration (main session and a fresh reviewer)

### Task 14.1
- [ ] `make check` in the root and `go test -race ./...` in every module, including the full conformance suite. Expected: all pass.

### Task 14.2
- [ ] `govulncheck ./...`, `gofmt -l .`, `go vet ./...` in every module. Expected: clean.

### Task 14.3
- [ ] An Opus reviewer that wrote none of the code checks the whole branch against every requirement in `specs/`, listing each as met or filing a finding (with a failing test or `UNREPRODUCED`).

---

## Self-review notes

- Spec coverage: every requirement in the nine new and ten modified capability deltas maps to a task above; `supply-chain` maps to group 13; `http-error-propagation` rows are spread across 2.6, 5.6, 7.2, 8.7, 9.3, 10.5 and 12.2.
- Interfaces: names introduced in a group's Interfaces block are the ones later groups use (`Request.Host/Secure`, `ClientFromContext`, `config.dpopEnabled`, `session.KeyBinding`, `token.Confirmation`).
- Draft caveat: every signature touching `reauthentication` (`Session.AuthenticatedWithin`, the re-proof rotation) or `key-port-context` (token issuance options) is re-checked in task group 1.
