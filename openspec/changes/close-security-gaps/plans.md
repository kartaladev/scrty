# close-security-gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> Reconciled on 2026-11-02 with `reauthentication` (archived) and `key-port-context` (merged as `9248c66`; task 1.1 found no difference). Task 1.2 settled the CSRF token style: a token stored on the sign-in by default, behind a replaceable port (D6).

**Goal:** Close the thirteen security gaps in `proposal.md` before `v0.1.0`, with every edge case the specs pin.

**Architecture:** Every browser-facing layer is a chain interceptor in a new outer slot (headers 25, CORS 50, CSRF 75), written once against `httpsec.Request` and `ResponseWriter`, so net/http, gin and fiber share it. Trusted-proxy resolution wraps the adapter's `Request` once when the chain starts, and every interceptor and the handler read its answer. DPoP is one chain-wide feature (`EnableDPoP`) that both bearer modes and every issuing endpoint read; proofs are checked in each endpoint's side-effect-free checks, before `key-port-context`'s issue-then-spend step. Sign-in listing, the key binding and the password policy extend the existing `session`, `token` and `authenticate/password` cores.

**Tech Stack:** Go 1.27, `net/http`, gin, fiber v3, `github.com/lestrrat-go/jwx/v4` (JOSE), testify, `go.uber.org/mock`, testcontainers-go (PostgreSQL 15 and 18).

**Spec:** `openspec/changes/close-security-gaps/` — `proposal.md`, `design.md` (decisions D1–D19), `specs/**/spec.md`, `tasks.md`.

## Global Constraints

- Go 1.27 floor; every module declares `go 1.27`.
- The core module adds no dependency; the breach check uses the existing confined outbound client; JOSE work uses jwx v4 only.
- Nothing in `github.com/kartaladev/scrty/test` is imported by another scrty module, including from `_test.go` files.
- Test-first for every task (`golang-tdd.md`): run the new test and see it fail for the intended reason before writing code; a compile error is not a red step.
- Table tests follow the `table-test` skill (`assert` closures, `ctx` modifier, `t.Context()`); mocks come from `use-mockgen`; PostgreSQL comes from the `use-testcontainers` helpers already in `test/`.
- Every option's godoc names the default it replaces; every port says what the library uses when none is supplied (`library-design.md`).
- Wiring mistakes fail at construction with an error wrapping `httpsec.ErrConfig` (or the package's own `ErrConfig`) that names the option. Every `EnableX` given twice is a configuration error.
- No error text, log record or event carries a password, token, proof, certificate, CSRF token, session identifier, stored hash, context word or forwarded host.
- Outages and hang-ups follow `key-port-context`: a failing dependency (replay store, breach lookup with failures refusing, challenge verifier, session listing) fails with fixed library text, maps to 500 and is charged to no throttle; a request whose own context ended fails matching the context's error (`internal/hangup.ByCaller`) and logs nothing at ERROR.
- Issue before spend (`key-port-context` D7): nothing an issuing endpoint adds may spend or store before the credential is issued; DPoP proofs are verified in the checks.
- A defect found along the way is claimed only with a failing test (`defect-claims.md`). The predecessor is never cited (`legacy-reference.md`).
- Slot values: `OrderSecurityHeaders = 25`, `OrderCORS = 50`, `OrderCSRF = 75`.
- Naming (D19): top-level features are `EnableX`; declarations are `WithX` (`WithHTTPSDeployment`); options inside a feature are `WithX`/`WithoutX`.
- Defaults pinned by the specs: HSTS `max-age=31536000; includeSubDomains`; CORS max age 10 minutes, methods `GET, HEAD, POST`; DPoP proof lifetime 60 s, algorithms `ES256`, proof size 8 KiB, `jti` at most 256 bytes; trusted-proxy `MaxHops` 1; password minimum 15 (floor 8), maximum 128 (floor 64), common list at least 3,000 entries, context-word containment from 4 characters; user agent 512 bytes; CSRF names `X-CSRF-Token` / `csrf_token`.

## Review Focus

- A request whose `Origin` and `Host` are equal but differ only by a default port (`https://app.example.com:443` against host `app.example.com`): CSRF's Origin comparison must normalise the default port as CORS does, or a same-origin request from a browser behind a proxy that keeps the port is refused. Test added to 5.1.
- A DPoP proof presented on a `HEAD` request or with a percent-encoded path (`/api/ord%65rs`): `htm` compares the method exactly, and `htu` compares the path as the client sent it, not decoded. Test added to 8.3.
- A sign-in listing for a user with many renewed families (100 families, each renewed 10 times): one entry per family and one store query, not a query per family. Test added to 6.2.
- A password candidate holding a NUL byte: the policy refuses nothing new, but a change must surface the encoder's `ErrContainsNUL` unchanged, not panic or truncate. Test added to 10.2.
- A forwarded header line of 64 KiB from a trusted peer: resolution walks from the right and stops at the client, so it must not split and parse every entry. Test added to 2.5 (a benchmark-free assertion: the parser is handed only the tail it reaches).
- A trusted proxy that folds a client-sent forwarded-certificate line into its own (`escaped(D), escaped(C)`), or a value with text before the PEM block: the decoder must find no certificate, not bind the first block. Test added to 9.2.
- An attacker probing recovery start for usernames whose owner signed in since a failed login: the verifier must receive identical signals for a known and an unknown username. Test added to 12.3.

---

## Delegation lanes

Each lane owns its files; a file not listed is held by the main session for review only. Lanes inside one phase run in parallel, each in its own worktree where noted. A lane longer than six tasks runs as sequential dispatches; after each dispatch the main session runs the verification commands and a fresh reviewer checks the diff.

| Phase | Lane | Tasks (dispatches) | Owns | Model (reason) |
|---|---|---|---|---|
| 0 | main session | 1.1–1.2 | OpenSpec artifacts only | — |
| A | R: request and proxies | 2.1–2.6; 2.7–2.11 | `httpsec/nethttp.go`, `client.go` (new), `proxies.go` (new), `chain.go`, `throttle.go`, `options.go`, `errors.go`, `httpsec/ginsec/*`, `httpsec/fibersec/*`, `test/httpsecconformance/proxy_scenarios.go` (new) | Opus (an interface every lane compiles against; refusal logic) |
| B (worktrees) | H: headers, CORS, CSRF | 3.1–3.6; 3.7–3.11; 4.1–4.6; 5.1–5.4; 5.5–5.7 | `httpsec/order_outer.go`, `headers.go`, `cors.go`, `csrf.go` (all new), `httpsec/logout.go`, conformance `headers_scenarios.go`, `cors_scenarios.go`, `csrf_scenarios.go` | Sonnet for 3.x (known pattern); Opus for 4.x and 5.x (refusal logic written for the first time) |
| B (worktrees) | S: sessions | 6.1–6.4 (S1, before H4); 6.5–6.7; 7.1–7.5 | `session/*`, `store/sqlstore/session.go`, `store/pgxstore/session.go`, `store/gormstore/session.go`, `store/migrate/securitystate/` (new file), `test/storetest/session*.go`, `httpsec/session_management.go` (new), `httpsec/signin_notice.go` (new), the passkey removal path, `notify` templates | Opus (store contract other modules implement; owner checks; `Commit` rules) |
| B (worktrees) | P: passwords | 10.1–10.6; 10.7–10.10; 10.11 | `authenticate/password/*`, `httpsec/login.go`, `httpsec/basic.go`, the password re-proof path, `test/identity` history conformance | Opus for 10.1–10.6 (behaviour-preserving move of the reuse guard); Sonnet for 10.7–10.10 |
| B | T: supply chain | 13.1–13.4 | `.github/`, `tools/`, `Makefile` | Sonnet |
| C | D: sender-constrained tokens | 8.1–8.5; 8.6–8.9; 8.10–8.12; 9.1–9.4 | `token/*`, `httpsec/dpop.go`, `dpop_replay.go`, `dpop_nonce.go`, `certbinding.go` (new), `bearer.go`, `session_bearer.go`, `session_renewal.go`, `complete.go`, `mfa_verify.go`, `passkey_login.go`, `magiclink.go`, `oidc_redeem.go`, `redemption.go`, `recovery.go`, `reauth*.go`, conformance `dpop_scenarios.go` | Opus (security-critical verification; issue-before-spend ordering; several packages) |
| C, after D | C: automation challenge | 12.1–12.4 | `httpsec/challenge.go` (new) and its call sites in `login.go`, `basic.go`, `magiclink.go`, `passkey_login.go`, `recovery.go` | Opus (refusal ordering before account lookup; outage split) |
| D | E: security events | 11.1–11.5 | a new `security` package, and every emitting call site | Opus (touches every package; "only what happened" ordering) |
| D, last | main session + reviewer | 14.1–14.3 | none | Opus reviewer |

`httpsec/errors.go` is owned by lane R in phase A; afterwards each lane adds its sentinel in its own file and appends its rows to the status table in its worktree; the main session resolves the table merge (a few lines, stated when it happens).

---

## Task group 1: baseline check (main session)

### Task 1.1: Recheck `key-port-context` as merged
- [x] Read the merged `key-port-context` specs and `httpsec/bearer.go`, `session/prepared.go`, `session/reuse.go`, `internal/hangup/hangup.go`, and `StatusForError`'s issuing mark.
- [x] Where the merged text differs from D1, update `design.md` D1 and the affected deltas; run `openspec validate close-security-gaps`. Expected: no errors (the 500-character warnings are known).
- [x] If a signature in this plan changed, regenerate the affected tasks through `/superpowers:writing-plans`.

### Task 1.2: Settle the CSRF token style
- [x] Decide synchronizer token on the sign-in, or HMAC-signed double-submit cookie keyed by the family; both must survive renewal and not a new sign-in. Record in D6 with sources; empty the Open Questions; regenerate task 5.3 if its shape changed. Settled: stored on the sign-in, replaceable (D6); tasks 5.3, 6.4, 6.6 and 6.7 regenerated.

---

## Task group 2: request host and scheme, trusted proxies (lane R)

**Interfaces produced (every later lane consumes these):**
- `type Request interface { ...existing...; Host() string; Secure() bool; HeaderValues(name string) []string }` (`HeaderValues` required, D2)
- `func WithHTTPSDeployment() Option`
- `type TrustedProxies struct { Prefixes []netip.Prefix; Headers HeaderFamily; MaxHops int }`
- `func XForwarded(fields ...ForwardedField) HeaderFamily`, `func Forwarded(fields ...ForwardedField) HeaderFamily`
- `const ForwardedFor, ForwardedProto ForwardedField`; `func ForwardedHost(allowed ...string) ForwardedField`
- `func EnableTrustedProxies(tp TrustedProxies, opts ...ProxyOption) Option`, `func TrustAllProxies() ProxyOption`, `func KeepForwardedHeaders() ProxyOption`, `func WithClientCertificateHeader(name string, decode func(string) (*x509.Certificate, error)) ProxyOption` (decoder nil = URL-encoded PEM; consumed by group 9)
- `type Client struct { IP string; Secure bool; Host string; ViaProxy bool }`, `func ClientFromContext(ctx context.Context) (Client, bool)`
- `var ErrHostNotAllowed = errors.New("httpsec: host not allowed")`

### Task 2.1: `Host()` and `Secure()` on the net/http request
**Files:** Modify `httpsec/exchange.go` (interface), `httpsec/nethttp.go`; Test `httpsec/nethttp_test.go`
- [ ] Red `TestHTTPRequest_HostAndSecure`: table over `httptest.NewRequest` with `r.Host = "app.example.com"` and `r.TLS` set / nil. Add the methods returning zero values first, so the red step fails on the assertions.
- [ ] Run `go test -run TestHTTPRequest_HostAndSecure -count=1 ./httpsec/`: FAIL on values. Green: `Host()` returns `r.Host`, `Secure()` returns `r.TLS != nil`. PASS; commit.

### Task 2.2: Adapters implement them
**Files:** Modify `httpsec/fibersec/exchange.go`; gin reuses `NewHTTPRequest`; Test the adapter modules
- [ ] Red `TestRequest_HostAndSecure` in each adapter: over TLS and plain for `app.example.com`; gin with `SetTrustedProxies(nil)`-free engine trusting everything and `X-Forwarded-Proto: https` → insecure; fiber with `ProxyHeader: "X-Forwarded-Host"` and that header set → host stays `app.example.com`.
- [ ] FAIL; Green: fiber reads the `Host` header and the connection's TLS state, never `c.Hostname()`, `c.Secure()` or `c.Scheme()`. PASS; commit.

### Task 2.3: `WithHTTPSDeployment`
**Files:** Create `httpsec/client.go`; Modify `options.go`; Test `client_test.go`
- [ ] Red `TestHTTPSDeployment`: plain request judged secure, host from `Host`, client from the peer; with `EnableTrustedProxies` too, `New` fails naming both options. FAIL; Green: a resolved-request wrapper overriding `Secure()`; the conflict check in `New`. PASS; commit.

### Task 2.4: Trusted-proxy construction rules
**Files:** Create `httpsec/proxies.go`; Test `proxies_test.go`
- [ ] Red `TestTrustedProxies_Construction`, one table: empty prefixes; invalid prefix; `0.0.0.0/0`; `::/0`; no family; no field; `ForwardedHost()` with no host; `ForwardedHost("https://app.example.com")`, `""`, `"a/b"`, `"u@h"`; `MaxHops: -1`; enabled twice; `TrustAllProxies()` with `0.0.0.0/0` builds. Each names the option.
- [ ] FAIL; Green. `MaxHops` zero means unset and defaults to 1. PASS; commit.

### Task 2.5: Right-to-left resolution of the client address
**Files:** Modify `proxies.go`, `client.go`, `chain.go` (wrap before the first interceptor); Test `proxies_test.go`
- [ ] Red `TestTrustedProxies_Resolve`, rows from the `trusted-proxies` scenarios: forged left-most (`1.2.3.4, 203.0.113.7` → `203.0.113.7`); bypassed proxy; two hops with `MaxHops: 2`; hop limit reached (`→ 10.20.5.5`); every entry trusted (`→ 10.20.9.9`); two header lines joined; peer `::ffff:10.20.0.2`; `Forwarded: for="[2001:db8::7]:4711"`; `for=unknown` and `for=_hidden` → `ClientIP() == ""`; `not-an-ip, 203.0.113.7` → `203.0.113.7`; `203.0.113.7, not-an-ip` → `""` (not `10.20.0.2`); trusted peer, no header → peer. Review Focus row: a 64 KiB header whose last entry is the client resolves without splitting the whole value (assert through an `export_test.go` counter of entries parsed, expecting 1).
- [ ] FAIL; Green: walk entries from the right with `strings.LastIndexByte`, strip port and brackets, `netip.ParseAddr`, `Unmap()` and drop the zone before prefix checks. PASS; commit.

### Task 2.6: Scheme and host from the client's hop
- [ ] Red `TestTrustedProxies_SchemeHost`: `Forwarded` element's `proto`/`host`; single-valued `X-Forwarded-Proto`; aligned lists read at the client's index; `https, http` against three addresses → transport; `wss` → transport; `X-Forwarded-Port: 8443` ignored.
- [ ] FAIL; Green; PASS; commit.

### Task 2.7: Host allowlist
**Files:** Modify `proxies.go`, `errors.go`; Test `proxies_test.go`, `errors_test.go`
- [ ] Red `TestTrustedProxies_HostNotAllowed`: `evil.example` refused before any interceptor (a recording interceptor at `Before(OrderSecurityHeaders)` is not called) and its text does not contain `evil.example`; `App.Example.COM:8443` allowed with resolved host `app.example.com:8443`; `app.example.com.evil.example` refused; the same header from an untrusted peer ignored, not refused; `TestStatusForError` row → 400.
- [ ] FAIL; Green: compare lower-cased host name without port and trailing dot. PASS; commit.

### Task 2.8: Header removal on every adapter
**Files:** Modify `proxies.go`, `fibersec/exchange.go`, `ginsec/middleware.go`; Test the three modules
- [ ] Red `TestTrustedProxies_RemovesHeaders` in core, gin and fiber: after the chain no `Forwarded`, no `X-Forwarded-*` (including `-Port`, `-Prefix`), no named certificate header, from trusted and untrusted peers; with `KeepForwardedHeaders()` unchanged; without the feature, untouched.
- [ ] FAIL; Green: an optional `headerRemover` interface (`DelHeader(name string)`) the adapters' requests implement, called after resolution. PASS; commit.

### Task 2.9: `ClientFromContext` and the source guards
**Files:** Modify `client.go`, `throttle.go`; Test `client_test.go`, `throttle_test.go`
- [ ] Red `TestClientFromContext` (proxied request; no trusted proxies → peer, `ViaProxy == false`) and `TestSourceGuard_UsesResolvedClient` (two forwarded clients keyed apart).
- [ ] FAIL; Green: store `Client` in the context at resolution; `ClientIP()`, `Host()`, `Secure()` of the wrapper return it. PASS; commit.

### Task 2.10: Adapters stop deferring to their frameworks (BREAKING)
**Files:** Modify `ginsec/middleware.go`, `fibersec/middleware.go`; Create `test/httpsecconformance/proxy_scenarios.go`; Modify `runner.go`
- [ ] Red: conformance "gin's own trusted proxies do not change the chain", "Same answer on every adapter", "Opting into gin's client address", "fiber with a trusted proxy", "gin handler after the chain", "fiber handler after the chain". FAIL on gin.
- [ ] Green: remove `ginsec.WithForwardedClientIP`; both adapters hand the raw peer to the chain. PASS; commit `feat(httpsec)!: adapters resolve clients through the chain's trusted proxies`.

### Task 2.11: Documentation
- [ ] Godoc each option with its default; README section with nginx and Traefik configurations, advising a test before trusting Traefik's host field. Verify `go doc ./httpsec EnableTrustedProxies`, `go vet ./...`. Commit.

---

## Task group 3: outer slots and security headers (lane H, dispatches H1: 3.1–3.6, H2: 3.7–3.11)

**Interfaces produced:**
- `const OrderSecurityHeaders Order = 25; OrderCORS Order = 50; OrderCSRF Order = 75` in `httpsec/order_outer.go`
- `func EnableSecurityHeaders(opts ...HeaderOption) Option`
- `func WithHSTS(maxAge time.Duration, opts ...HSTSOption) HeaderOption`, `func HSTSIncludeSubdomains() HSTSOption`, `func WithoutHSTSSubdomains() HSTSOption`, `func HSTSPreload() HSTSOption`
- `type CSPPolicy`, `func StrictCSP(directives ...CSPDirectiveValue) CSPPolicy`, `func HashCSP(hashes ...string) CSPPolicy`, `func CSPDirective(name string, sources ...string) CSPDirectiveValue`, `func WithCSP(p CSPPolicy) HeaderOption`
- `func WithCSPReportOnly() HeaderOption`, `func WithCSPReportOnlyPolicy(p CSPPolicy) HeaderOption` (beside the enforced one), `func WithReportingEndpoint(name, url string) HeaderOption`
- `type HeaderProfile`, `func APIHeaders() HeaderProfile`, `func WithHeaderProfile(p HeaderProfile, m RouteMatcher) HeaderOption`, `type RouteMatcher func(Request) bool`, `func PathPrefix(prefix string) RouteMatcher`
- `func WithHeader(name, value string) HeaderOption`, `func WithoutHeader(name string) HeaderOption`
- `func CSPNonce(ctx context.Context) (string, bool)`
- `func WithLogoutClearSiteData(directives ...string) LogoutOption`

### Task 3.1: Outer slots
- [ ] Red `TestOrder_OuterSlots`: 25 < 50 < 75 < `OrderJWKS`, 25 apart. FAIL; add constants; PASS; commit.

### Task 3.2: Default document headers
**Files:** Create `httpsec/headers.go`; Test `headers_test.go`
- [ ] Red `TestSecurityHeaders_Defaults`: the four headers with the exact spec values; none of the four not sent; a 401 bearer refusal carries the same headers; a host-not-allowed 400 carries them (the layer exposes an unexported `applyHeaders(w, req)` the chain calls on a resolution refusal; no interceptor runs); without the layer none; enabled twice fails `New`.
- [ ] FAIL; Green: interceptor at `OrderSecurityHeaders` setting headers before `next`. PASS; commit.

### Task 3.3: Directive editing
- [ ] Red `TestSecurityHeaders_Directives`: `img-src 'self' data:` added; `frame-ancestors 'self'` replaces `'none'` once; `WithoutHeader("Cross-Origin-Opener-Policy")` removes it; a source with `;`, `,` or `\n` fails `New` naming the policy. FAIL; Green; PASS; commit.

### Task 3.4: Nonce
- [ ] Red `TestSecurityHeaders_Nonce`: `CSPNonce` equals the header's nonce; two responses differ; decoded length ≥ 16 bytes; a failing randomness seam (`export_test.go`) yields 500 and the handler is not called; an API-profile route finds no nonce. FAIL; Green: 16 bytes from `crypto/rand`, base64 std encoding. PASS; commit.

### Task 3.5: Profiles
- [ ] Red `TestSecurityHeaders_Profiles`: `/api/orders` under `PathPrefix("/api/")` gets the API profile; `/apix` does not; `/api/admin/` profile registered first wins for `/api/admin/users`; unmatched gets the document set. FAIL; Green; PASS; commit.

### Task 3.6: HSTS
- [ ] Red `TestSecurityHeaders_HSTS`: secure → header; insecure → none; trusted proxy forwarding `https` → header; untrusted peer's `X-Forwarded-Proto: https` → none; `WithHSTS(0)` → `max-age=0; includeSubDomains`; negative age, and `HSTSPreload()` below a year or with `WithoutHSTSSubdomains()`, fail `New` naming `WithHSTS`. FAIL; Green; PASS; commit.

### Task 3.7: Handler wins, streaming intact
- [ ] Red `TestSecurityHeaders_HandlerWins` and `TestSecurityHeaders_Streaming` (`http.NewResponseController(w).Flush()` and `Hijack()`). These pass at once without a wrapper: invert temporarily (wrap the writer in the test) to see them fail, then restore. Commit.

### Task 3.8: Report-only and hash preset
- [ ] Red `TestSecurityHeaders_ReportOnly` (report-only alone; enforced plus a report-only candidate sharing one nonce; `Reporting-Endpoints: csp="https://reports.example.com/csp"` with `report-to csp` and `report-uri`; `http://` endpoint fails `New`) and `TestSecurityHeaders_HashPreset` (`script-src 'sha256-…'`, no nonce; `sha256-not-base64!` and no hash fail `New`). FAIL; Green; PASS; commit.

### Task 3.9: Clear-Site-Data on logout
**Files:** Modify `httpsec/logout.go`; Test `logout_test.go`
- [ ] Red `TestLogout_ClearSiteData`: `"cache"`, `"storage"` over HTTPS → `Clear-Site-Data: "cache", "storage"`; over HTTP → none; refused logout → none; not opted in → none; no directive or `"executionContexts"` fails construction. FAIL; Green; PASS; commit.

### Task 3.10: Conformance on three adapters
- [ ] `test/httpsecconformance/headers_scenarios.go` with the spec scenarios, including a refusal through each adapter's default error handling; invert one expected value to see it fail, restore. Commit.

### Task 3.11: Docs
- [ ] Godoc each option with its default; README with the Vite, Next.js and `html/template` nonce examples. `go doc ./httpsec EnableSecurityHeaders`. Commit.

---

## Task group 4: CORS (lane H, dispatch H3)

**Interfaces produced:**
- `type CORSPolicy struct { AllowedOrigins, AllowedMethods, AllowedHeaders, ExposedHeaders []string; AllowCredentials bool; MaxAge time.Duration }` (methods default `GET, HEAD, POST`; max age 10 min)
- `func EnableCORS(p CORSPolicy, opts ...CORSOption) Option`, `func WithOriginPattern(pattern string) CORSOption`, `func WithoutAutomaticCORSHeaders() CORSOption`
- Unexported: `config.corsOrigins() (exact []string, patterns []originPattern)` read by group 5; `config.dpopEnabled bool`, `config.csrfTokenHeader string` set by groups 8 and 5.

### Task 4.1: Construction
- [ ] Red `TestCORS_Construction`: `HTTPS://App.Example.com:443` normalised; refused: none, `null`, `ftp://…`, path, query, fragment, userinfo, `*` with credentials, `*` beside another origin, `https://*.example.com` without `WithOriginPattern`, `https://a*.example.com` as a pattern, enabled twice. FAIL; Green in `httpsec/cors.go`; PASS; commit.

### Task 4.2: Matching and actual responses
- [ ] Red `TestCORS_Origins`: exact match gets `Access-Control-Allow-Origin` and `Vary: Origin`; look-alike, `http://` and `:8443` get none; pattern matches `a.example.com` only; no `Origin` still gets `Vary: Origin`; `*` without credentials → `*`; credentials → `Access-Control-Allow-Credentials: true` and the echoed origin; exposed headers on actual responses. FAIL; Green; PASS; commit.

### Task 4.3: A refusal is readable
- [ ] Red `TestCORS_RefusalReadable`: a bearer 401 for an allowed origin carries the allow-origin and `Access-Control-Expose-Headers: WWW-Authenticate`. FAIL; Green (set before `next`); PASS; commit.

### Task 4.4: Preflight
- [ ] Red `TestCORS_Preflight`: allowed → 204, allow headers, `Access-Control-Max-Age: 600`, `Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers`, no interceptor at `OrderBearerToken` called; `MaxAge: time.Hour` → `3600`; `DELETE` with default methods → bare 204; `x-debug` → bare 204; `content-type` plus a second line `AUTHORIZATION` → allowed; `OPTIONS` without `Access-Control-Request-Method` reaches the bearer. FAIL; Green; PASS; commit.

### Task 4.5: Follows the chain
- [ ] Red `TestCORS_FollowsChain`: `config.dpopEnabled` → `DPoP` allowed, `DPoP-Nonce` and `WWW-Authenticate` exposed; `config.csrfTokenHeader` → allowed; `WithoutAutomaticCORSHeaders()` → a `dpop` preflight gets a bare 204. FAIL; Green; PASS; commit.

### Task 4.6: Conformance and docs
- [ ] `cors_scenarios.go` on three adapters; godoc with defaults (`go doc ./httpsec EnableCORS`). Commit.

---

## Task group 5: CSRF protection (lane H, dispatches H4: 5.1–5.4, H5: 5.5–5.7)

**Interfaces produced:**
- `func EnableCSRFProtection(opts ...CSRFOption) Option`, `func WithCSRFTrustedOrigins(origins ...string) CSRFOption`, `func WithoutCORSOriginsTrustedForCSRF() CSRFOption`, `func WithCSRFTokenNames(header, field string) CSRFOption`, `func WithCSRFExemption(method, pattern string) CSRFOption`, `func WithoutBackchannelLogoutExemption() CSRFOption`, `func WithoutCSRFProtection() Option`
- `func CSRFToken(ctx context.Context) (string, bool)` (reads through the configured `CSRFTokens`)
- `type CSRFTokens interface { Token(ctx context.Context, s *session.Session) (string, error); Verify(ctx context.Context, s *session.Session, presented string) error }` — `Verify` returns `ErrCrossSiteRequest` for a missing, malformed or foreign token; the default reads `Session.CSRFToken` and compares with `subtle.ConstantTimeCompare`, and a session holding no token fails `Verify`
- `func WithCSRFTokens(t CSRFTokens) CSRFOption` (default: the session-stored source; nil fails `New`)
- The chain passes `session.WithCSRFToken()` to `Prepare`/`Create` at every sign-in when CSRF protection and a cookie authenticator are both on
- `var ErrCrossSiteRequest = errors.New("httpsec: cross-site request refused")`
- Interceptors that authenticate by cookie carry an unexported `cookieAuthenticator` marker the construction check reads.

### Task 5.1: Fetch Metadata and Origin
- [ ] Red `TestCSRF_FetchMetadata`: method × `Sec-Fetch-Site` × `Origin`, each row also run through `net/http.CrossOriginProtection` as the oracle where both should agree; login CSRF (`POST /login`, no credential checked, no session); `Origin: null`; `:8443`; `get` and `PROPFIND` unsafe; behind a trusted proxy passes; safe `GET` passes. Review Focus row: `Origin: https://app.example.com:443` against host `app.example.com` passes.
- [ ] FAIL; Green in `httpsec/csrf.go` at `OrderCSRF`, comparing a normalised `Origin` with `Secure()`/`Host()`. PASS; commit.

### Task 5.2: Trusted origins
- [ ] Red `TestCSRF_TrustedOrigins`: CORS sibling passes on `same-site`; opt-out refuses it; `WithCSRFTrustedOrigins` adds one (normalised; `null` fails `New`); CORS `*` trusts nothing; unlisted `blog.example.com` refused. FAIL; Green; PASS; commit.

### Task 5.3: Token layer (D6: stored on the sign-in, replaceable)
**Consumes:** `session.Session.CSRFToken`, `session.WithCSRFToken()` (task 6.4, lane S). Dispatch H4 starts only after S1 has landed; until then it stops at 5.2.
- [ ] Red `TestCSRF_Token`: missing, malformed, another sign-in's → refused; correct → passes; token read before a renewal passes after it; token read before logout refused after a new login; a session with no token (built without `WithCSRFToken`) → refused; bearer-only `POST` passes; `CSRFToken(ctx)` returns the sign-in's token; comparison through `subtle.ConstantTimeCompare`; `WithCSRFTokens(hmacSource)` (a test source deriving `HMAC(k, family)`) → its token passes, the stored token is refused, `CSRFToken(ctx)` returns the HMAC token; `WithCSRFTokens(nil)` fails `New`.
- [ ] FAIL; Green; PASS; commit.

### Task 5.4: Mandatory with cookie authentication
- [ ] Red `TestCSRF_RequiredWithCookies`: a test interceptor carrying the marker without protection fails `New` naming CSRF protection; with `WithoutCSRFProtection()` builds. FAIL; Green; PASS; commit.

### Task 5.5: Exemptions
- [ ] Red `TestCSRF_Exemptions`: `POST /webhooks/payments` exempt; `/webhooks/payments/`, `/Webhooks/payments`, `/webhooks/payments/../../settings` and `DELETE /webhooks/payments` judged; `/webhooks/*/events` matches one segment only; back-channel logout exempt by default and judged after `WithoutBackchannelLogoutExemption()`; empty method or path `/` fails `New`. FAIL; Green: match the chain's routed path exactly (the CVE-2025-47910 lesson). PASS; commit.

### Task 5.6: Status and conformance
- [ ] Red `TestStatusForError` row `ErrCrossSiteRequest → 403`; conformance `csrf_scenarios.go` including the password re-proof and `DELETE /sessions`. FAIL; Green; PASS; commit.

### Task 5.7: Docs
- [ ] Godoc with defaults; README on the token accessor and exemption rules. `go doc ./httpsec EnableCSRFProtection`. Commit.

---

## Task group 6: sessions — listing, metadata, binding (lane S, dispatches S1: 6.1–6.4, S2: 6.5–6.7)

**Interfaces produced:**
- `session.Store`: `ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*Session, error)` — live, non-superseded members, exact user match.
- `type SignIn struct { Handle id.ID; CreatedAt, LastUsedAt time.Time; FirstFactor identity.FirstFactor; Pending policy.ChallengeKind; ClientIP, UserAgent string; Current bool }`
- `func (m *Sessions) ListSignIns(ctx context.Context, user identity.UserID, current *Session) ([]SignIn, error)`
- `func (m *Sessions) EndSignIn(ctx context.Context, user identity.UserID, handle string) error` (`ErrNotFound` for malformed, unknown or foreign), `func (m *Sessions) EndOtherSignIns(ctx context.Context, user identity.UserID, current *Session) (int, error)` over `DeleteByUserExcept`
- `func WithSessionMetadata() Option`; `CreateOption`s `WithClientMetadata(ip, userAgent string)`, `WithKeyBinding(b KeyBinding)` and `WithCSRFToken()` (32 bytes from `crypto/rand`, base64url without padding); `RotateOption` `WithReauthenticationBinding(b KeyBinding)`
- `type KeyBinding struct { JKT, X5TS256 string }` (at most one); `Session.KeyBinding`, `Session.ClientIP`, `Session.UserAgent`, `Session.CSRFToken` written by `Create` and `Supersede` only.
- `var ErrListUnavailable` (fixed text, wraps the store error).

### Task 6.1: `ListByUser` in memory
- [ ] Red `TestMemoryStore_ListByUser`: live heads only, judged by `now`; `Alice` and `alice` apart; another user's absent. FAIL; Green in `session/store_memory.go`; PASS; commit.

### Task 6.2: The manager's listing
- [ ] Red `TestSessions_List`: two devices, one renewed twice → two; expired-only family absent; within grace → one entry with the successor's last use; pending second factor → `Pending` set; no identifier or digest in any field; store error → `ErrListUnavailable`; cancelled context → matches `context.Canceled`. Review Focus row: 100 families × 10 renewals → 100 entries and exactly one `ListByUser` call (a counting store). FAIL; Green; PASS; commit.

### Task 6.3: Metadata
- [ ] Red `TestSessions_Metadata`: off → empty; on → `203.0.113.7` and `Firefox/140` kept across renewal; a 2,000-byte agent with a multi-byte character at byte 512 → ≤ 512 bytes and `utf8.ValidString`; `""` client IP kept absent. FAIL; Green; PASS; commit.

### Task 6.4: Key binding
- [ ] Red `TestSessions_KeyBinding`: rotation, renewal and re-authentication successors keep `K`; the successor handed to `RotateIssuing`'s and `RotateWithGraceIssuing`'s step already carries `K`; `Save` of a cleared copy leaves it; `Prepare` with `K`, set `K2`, `Commit` → `ErrConfig`, nothing stored; `WithReauthenticationBinding(K2)` on a session bound to `K` → `ErrConfig`; on an unbound one → bound to `K2`; both members set → `ErrConfig`. FAIL; Green (successor construction; `Commit`'s built-field check; `Save` preserves like `MFAAtFirstFactor`). PASS; commit.
- [ ] Red `TestSessions_CSRFToken`: no `WithCSRFToken` → `""`; with it → decodes to 32 bytes; rotation, renewal (within and outside grace) and re-authentication successors carry the same token, already set on the successor handed to the issuing step; `Save` of a cleared copy keeps it; `Prepare` with `T`, change to `T2`, `Commit` → `ErrConfig`, nothing stored; two sign-ins of one user → different tokens. FAIL; Green beside the binding. PASS; commit.

### Task 6.5: End by handle
- [ ] Red `TestSessions_EndSignIn`: own handle revokes the family; current handle revokes the current session; `not-a-family`, unknown and `u-2`'s handle → `ErrNotFound`, nothing revoked; `EndOtherSignIns` racing a renewal keeps the successor (barrier test). FAIL; Green; PASS; commit.

### Task 6.6: Migration
**Files:** Create `store/migrate/securitystate/20261102000000_session_signins.sql`; Test `test/migrate_securitystate_test.go`
- [ ] Red: populated-database and rollback tests on PostgreSQL 15 and 18. FAIL; Green: nullable `client_ip text`, `user_agent text`, `binding_kind text`, `binding_thumbprint text`, `csrf_token text` (sealed); no index (listing uses `sessions_user`). The populated-database test asserts existing rows load with no token. PASS; commit.

### Task 6.7: Durable stores
- [ ] Red: new cases in the `test/storetest` session suite (listing, exact match, metadata, binding and CSRF token round trip, save keeps all three, supersession inserts all three, a store whose listing returns another user's session fails naming the listing check). FAIL for every durable store.
- [ ] Red: sealing tests beside the existing ID-token ones: the stored `csrf_token` neither equals nor contains the token; a successor's copy is sealed for the successor's identifier and opens; a token copied into another session's row → unreadable-session error, token not returned. FAIL.
- [ ] Green in `store/sqlstore`, `store/pgxstore`, `store/gormstore` session files and the sealing decorator. PASS; commit.

---

## Task group 7: session management endpoints and notices (lane S, dispatch S3)

**Interfaces produced:**
- `func EnableSessionManagement(opts ...SessionManagementOption) Option` (uses the chain's `WithSessions` manager; none → `ErrConfig`), `func WithSessionManagementPrefix(p string) SessionManagementOption` (default `/sessions`)
- `var ErrSessionHandleNotFound` (404)
- `func WithoutPasskeyRemovalNotification() PasskeyOption`
- `func EnableSignInNotice(sender notify.Sender, opts ...SignInNoticeOption) Option`, `func WithSignInMatcher(fn func(new, known SignIn) bool) SignInNoticeOption` (default: equal user agent), `func WithSeenDevices(p SeenDevices) SignInNoticeOption`, `type SeenDevices interface { Seen(ctx context.Context, user identity.UserID, userAgent string) (bool, error) }`

### Task 7.1: Endpoints
- [ ] Red `TestSessionManagement`: list marks current, carries no identifier, needs no recency; "Sign out other devices"; "Only the current sign-in" → success, nothing revoked; "Stale session" → reauthentication-required, nothing revoked; foreign handle → `ErrSessionHandleNotFound`; own current handle → session gone; "Current during the grace window"; recovery-pending and MFA-pending sessions refused as elsewhere; every response `Cache-Control: no-store`; construction without a manager fails. FAIL; Green in `httpsec/session_management.go` with `reauthentication`'s recency guard. PASS; commit.

### Task 7.2: Status and outage
- [ ] Red `TestStatusForError` row → 404, and `TestSessionManagement_Outage` (listing store error → 500, fixed text). FAIL; Green; PASS; commit.

### Task 7.3: Passkey removal notice
- [ ] Red `TestPasskey_RemovalNotice`: label and time, no credential ID or user handle; opt-out sends nothing; send failure keeps the removal; refused removal (outside freshness) sends nothing. FAIL; Green; PASS; commit.

### Task 7.4: Unseen-device sign-in notice
- [ ] Red `TestSignInNotice`: `Safari/19` beside a live `Firefox/140` → notice; same agent → none; first sign-in → none; seen-devices port answering true → none; a sign-in whose `Commit` fails → none; send failure → sign-in unaffected, logged; notice text has no handle, token or full address; without metadata or sender → `New` fails naming the notice. FAIL; Green after the session is stored. PASS; commit.

### Task 7.5: Conformance and docs
- [ ] Conformance on three adapters; godoc and README with defaults. Commit.

---

## Task group 8: confirmation claim and DPoP (lane D, dispatches D1: 8.1–8.5, D2: 8.6–8.9, D3: 8.10–8.12)

**Interfaces produced:**
- `token`: issuing option `WithConfirmation(c Confirmation)` through the optional `ConfirmingGenerator` (`GenerateWith(ctx, id, p, opts ...IssueOption)`), refused at construction by `EnableDPoP`/`EnableCertificateBinding` when the chain's generator lacks it; `type Confirmation struct { JKT, X5TS256 string; Other []string }`; the verifier's result exposes `Confirmation`.
- `httpsec.Request` gains `EscapedPath() string` (required; every adapter and test double implements it), task 8.6's dispatch.
- `httpsec`: `type DPoP struct { Require bool; ProofMaxAge time.Duration; Replay ReplayStore; Algorithms []jwa.SignatureAlgorithm; Nonce bool; PublicURL string; MaxProofSize int }`, `func EnableDPoP(d DPoP) Option`
- `type ReplayStore interface { Record(ctx context.Context, key string, until time.Time) (fresh bool, err error) }` (atomic insert-if-absent; key = digest of `jti` and thumbprint), in-memory default
- `var ErrInvalidDPoPProof`, `var ErrDPoPNonceRequired` (matches `ErrInvalidDPoPProof`; both 401)
- `type TokenType string; const TokenTypeBearer, TokenTypeDPoP TokenType`, carried on the issued result every responder receives.

### Task 8.1: `cnf` claim
- [ ] Red `TestGenerator_Confirmation` (`jkt`, `x5t#S256`, none; both → `ErrConfig`; a 10-character thumbprint → `ErrConfig`) and `TestVerifier_Confirmation` (returned; `{"jkt": 7}`, `{}`, a string `cnf` refused). FAIL; Green in `token/`; PASS; commit.

### Task 8.2: `EnableDPoP`
**Files:** Modify `httpsec/options.go` (`New` validates the options), `httpsec/bearer.go`, `httpsec/session_bearer.go`; Test `httpsec/dpop_test.go`
**Interfaces produced:** an unexported field on the chain's configuration, `bindingVerifiers []string`, holding the names of enabled features that verify bound credentials. `EnableBearerToken` appends `"EnableBearerToken"` and `EnableSessionBearer` appends `"EnableSessionBearer"`. Construction reads it after every option has applied. `oidc-provider` later appends its provider here. Nothing exported (D8, amended 2026-11-02).
- [ ] Red `TestDPoP_Construction`, a table:
  - no bearer mode, so `bindingVerifiers` is empty → `errors.Is(err, ErrConfig)`, and the message names `EnableDPoP`;
  - only `EnableSessionBearer` → built;
  - only `EnableBearerToken` → built;
  - `EnableDPoP` given twice → `ErrConfig`;
  - the order of options does not matter: `EnableDPoP` before the bearer option → built;
  - defaults filled: `ProofMaxAge` 60 s, `ES256`, 8 KiB, in-memory replay store;
  - not enabled → `Authorization: DPoP` passes through, and a protected route refuses it.
- [ ] FAIL on the assertions, not on compiling: add `EnableDPoP` as a stub first. Green; PASS; commit.

### Task 8.3: Proof verification
**Files:** Create `httpsec/dpop.go`; Test `dpop_test.go`
- [ ] Red `TestDPoP_Proof`, proofs signed with jwx v4: valid; 9 KiB header (no signature verified: a counting key seam); two headers; `DPoP` scheme without a header; wrong `typ`; `none`; `HS256`; `jwk` with `d`; P-384 key under `ES256`; bad signature; wrong `htm`; `htu` for `/api/payments`; `https://APP.example.com:443/api/orders` against `…/api/orders?page=2` passes; `iat` 61 s old and 5 min ahead; `ath` for another token; `ath` on an issuing request. Review Focus rows: `HEAD` proof on `GET` refused; `htu` `/api/orders` against request path `/api/ord%65rs` refused.
- [ ] FAIL; Green in the D8 order; thumbprint via `jwk.Key.Thumbprint(crypto.SHA256)`. PASS; commit.

### Task 8.4: Replay store
**Files:** Create `httpsec/dpop_replay.go`
- [ ] Red `TestDPoP_Replay` with `-race`: replay within 60 s refused, accepted after; a proof refused for `htm` leaves its `jti` unrecorded; two identical concurrent proofs → one accepted; 300-byte `jti` refused; store error → fixed text, 500, not charged; cancelled context → matches `context.Canceled`, nothing at ERROR. FAIL; Green; PASS; commit.

### Task 8.5: Bearer interceptors
- [ ] Red `TestDPoP_Bearer`: `DPoP` accepted in signed-bearer and session-reference modes (`ath` over the reference); unbound `Bearer` accepted; bound as `Bearer` refused; another key's proof refused; `Require` refuses an old unbound token; `cnf` `{"jwk":…}` refused, not accepted as bearer. FAIL; Green in `bearer.go`, `session_bearer.go`; PASS; commit.

### Task 8.6: Proof before spend, binding at issue
- [ ] Red `TestDPoP_Binding` and `TestDPoP_ProofBeforeSpend`, one row per endpoint (login, MFA verify, passkey, magic link, OIDC handoff, recovery, re-authentication, renewal): valid proof → `cnf.jkt` and a bound stored session; no proof → unbound; bad proof → `ErrInvalidDPoPProof` with the link, handoff code, challenge attempts or recovery proofs unspent and no session stored; bad proof at `/login` → no lockout failure; `Require` without a proof → refused before any account lookup (a mock `UserLoader` with no expected calls).
- [ ] FAIL; Green: verify in each endpoint's checks; pass `WithKeyBinding` to `Prepare` and `WithConfirmation` to the issuer. PASS; commit.

### Task 8.7: Binding through rotation
- [ ] Red `TestDPoP_Rotation`: renewal with a proof leaves an unbound session unbound; re-authentication binds an unbound one and keeps a bound one; renewal and re-authentication with another key refused, nothing rotated; an ended family with the bound key → expired, nothing stored. FAIL; Green; PASS; commit.

### Task 8.8: Token type
- [ ] Red `TestDPoP_TokenType`: every issuing endpoint's responder receives `TokenTypeDPoP` with a proof and `TokenTypeBearer` without. FAIL; Green; PASS; commit.

### Task 8.9: Public URL
- [ ] Red `TestDPoP_PublicURL`: behind a trusted proxy `https://app.example.com/api/orders` passes for `http://10.20.1.5:8080/api/orders`; `PublicURL` overrides. FAIL; Green; PASS; commit.

### Task 8.10: Nonces and challenges
**Files:** Create `httpsec/dpop_nonce.go`
- [ ] Red `TestDPoP_Nonce` (missing and expired nonce → 401, `error="use_dpop_nonce"`, fresh `DPoP-Nonce`; a nonce from a second chain with the same key material accepted), `TestDPoP_Challenge` (`DPoP error="invalid_dpop_proof", algs="ES256"`; missing token with DPoP optional → both `DPoP` and `Bearer` challenges) and `TestStatusForError` rows → 401. FAIL; Green: nonces sealed with the chain's key material; PASS; commit.

### Task 8.11: End to end
- [ ] Conformance `dpop_scenarios.go` on three adapters; a recorded proof vector from the doc's `dpop.ts` (fixture in `test/testdata/dpop/`) verifies against a test server. Commit.

### Task 8.12: Docs
- [ ] Godoc `EnableDPoP` with defaults; README with React, Next.js and htmx samples. `go doc ./httpsec EnableDPoP`. Commit.

---

## Task group 9: mTLS-bound tokens (lane D, dispatch D4; review fixes D5)

**Interfaces produced:** `func EnableCertificateBinding(opts ...CertificateBindingOption) Option`; `Request.ClientCertificate() *x509.Certificate` (required, D9); the forwarded header and decoder come from `WithClientCertificateHeader` (group 2); `var ErrCertificateBinding` (401); `OrderMTLS` fixes the request's thumbprint on the exchange and the bearer modes (slot 500) compare it with `cnf.x5t#S256` in constant time (D9).

### Task 9.1: Direct TLS
- [ ] Red `TestCertificateBinding_Direct` over `httptest.NewUnstartedServer` with `tls.RequestClientCert`: certificate C binds `x5t#S256`; C passes; none and D refused. FAIL; Green in `httpsec/certbinding.go`; PASS; commit.
- [ ] Red, one table row per issuing endpoint (form login, passkey login, magic link, OIDC redemption, recovery complete and finish, re-authentication of an unbound sign-in), mirroring `dpop_endpoints_test.go`: each binds C's thumbprint on the token and the session. Show each row fails with that endpoint's binding argument replaced by nil. Commit.

### Task 9.2: Forwarded certificate
- [ ] Resolution keeps the trusted peer's raw certificate header on the internal resolution (never on `Client`) before removing it; red first that the value reaches `OrderMTLS` after removal.
- [ ] Red `TestCertificateBinding_Forwarded`: URL-encoded PEM from a trusted peer binds C; a consumer decoder is used when given; untrusted peer ignored; undecodable value → no certificate, bound token refused; the header on two lines → no certificate. FAIL; Green; PASS; commit.
- [ ] Review Focus row: red `TestCertificateBinding_Forwarded` rows `escaped(D) + ", " + escaped(C)` in one line → no certificate, and `"junk%0A" + escaped(C)` → no certificate. Green: the default decoder accepts exactly one CERTIFICATE block, with only whitespace before and after it. Commit.

### Task 9.3: Both offered, switched off, conformance
- [ ] Red: proof and certificate → `cnf.jkt` only; `x5t#S256` token after the feature is off → `ErrCertificateBinding` in both bearer modes and under both the `Bearer` and `DPoP` schemes; the session-versus-token check (a `Verifier` dropping `cnf` from a certificate-bound sign-in is refused) with a row that fails when the check is removed; `EnableCertificateBinding` with `EnableDPoP(DPoP{Require: true})` → `ErrConfig` naming both; `TestStatusForError` row → 401; conformance on three adapters. FAIL; Green; PASS; commit.

### Task 9.4: Docs
- [ ] Godoc and README: default off, the decoder (one PEM block, nothing else), validity left to TLS or the proxy, that `Request.ClientCertificate` answers the forwarded certificate to every interceptor once a header is named, that every proxy must overwrite or strip the header on every request, and proxy examples checked against each proxy's documentation. Commit.

---

## Task group 10: password policy and rehash (lane P, dispatches P1: 10.1–10.6, P2: 10.7–10.10)

**Interfaces produced:**
- `func NewPolicy(opts ...PolicyOption) (*Policy, error)`; `func (p *Policy) Check(ctx context.Context, user *identity.Details, candidate string) error`; `func (p *Policy) Change(ctx context.Context, user *identity.Details, candidate string, write WriteFunc) error`
- Options: `MinLength(n int)`, `MaxLength(n int)`, `WithoutCommonPasswords()`, `CommonPasswords(list []string)`, `ContextWords(fn func(context.Context, *identity.Details) ([]string, error))`, `Breached(src BreachSource, onFailure LookupFailure)`, `PwnedPasswords(c *outbound.Client) BreachSource`, `const Refuse, Accept LookupFailure`, `NoReuse(h History, depth int, opts ...ReuseOption)`, `WithEncoder(e Encoder)`, `WithClock(c clock.Clock)`
- `var ErrPasswordRejected`; `type RejectedError struct { Rule Rule }`; `const RuleTooShort, RuleTooLong, RuleCommon, RuleContextWord, RuleBreached, RuleReused Rule`; `ErrReused` also matches `ErrPasswordRejected`; `var ErrLookupUnavailable` (500)
- `type Upgrader interface { NeedsUpgrade(encoded []byte) bool }`
- `httpsec`: `type RehashFunc func(ctx context.Context, user *identity.Details, replaced, upgraded []byte) error`; `func WithLoginRehash(fn RehashFunc) LoginOption` and the Basic and re-proof equivalents; `password.ConditionalProvisionerRehash(p identity.Provisioner) RehashFunc`

### Task 10.1: Defaults and ordering
- [ ] Red `TestPolicy_Defaults` and `TestPolicy_Options`: the `password-policy` scenarios; a too-short candidate makes no breach lookup (a mock source with no expected calls). FAIL; Green in `authenticate/password/policy.go`, the list embedded as `common.txt`; PASS; commit.

### Task 10.2: Length
- [ ] Red `TestPolicy_Length`: 15 three-byte characters pass; spaces kept; `""` too short; 129 too long; bcrypt with 30 three-byte characters too long at `Check`. Review Focus row: a change with `"pass\x00word…"` returns `ErrContainsNUL` unchanged. FAIL; Green with `utf8.RuneCountInString`; PASS; commit.

### Task 10.3: Context words
- [ ] Red `TestPolicy_ContextWords`: `Alice.Smith2026`; `my-alice.smith2026-pass`; `abc` only on equality; a failing word function returns its error, not a rejection. FAIL; Green; PASS; commit.

### Task 10.4: Breach check
- [ ] Red `TestPolicy_Breached` against an `httptest` range server asserting the path is the 5-character prefix and `Add-Padding: true`: count 3 refused; count 0 ignored; timeout, 429 and a malformed body → `ErrLookupUnavailable` with `Refuse`, accepted with `Accept`; cancelled context → `context.Canceled` under both; no failure mode → construction error. FAIL; Green; PASS; commit.

### Task 10.5: Move the reuse guard into `NoReuse` (BREAKING)
- [ ] Red: port every test in `reuse_test.go` and the history conformance in `test/identity` to `NewPolicy(NoReuse(...))`; they fail to compile only on the removed name, then, after a stub rule that accepts everything, fail on behaviour.
- [ ] Green: move the logic behind `NoReuse`; delete `NewReuseGuard`; no stored hash and no history → accept. PASS; commit `feat(password)!: one password policy, reuse included`.

### Task 10.6: Construction and no secrets
- [ ] Red `TestPolicy_Construction` (max 32, max below min, empty replacement list, plus the moved reuse cases) and `TestPolicy_NoSecrets` (refusal texts and a captured log carry no candidate, hash or context word). FAIL; Green; PASS; commit.

### Task 10.7: Status
- [ ] Red `TestStatusForError` rows: each rule → 422; `ErrReused` → 422 and `errors.Is(err, ErrPasswordRejected)`; `ErrLookupUnavailable` → 500. FAIL; Green; PASS; commit.

### Task 10.8: Upgrader
- [ ] Red `TestEncoder_NeedsUpgrade`: Argon2id 128 MiB about 64 MiB → true; own → false; 128 MiB hash under a 64 MiB encoder → false; bcrypt hash under Argon2id → true; garbage → false; bcrypt and scrypt raised costs → true. FAIL; Green; PASS; commit.

### Task 10.9: Login rehash
- [ ] Red `TestLogin_Rehash` for form login, Basic and the password re-proof: write receives the 64 MiB hash replaced and a 128 MiB hash; no write → no encode; wrong password → no call; write error → success, log without hashes; MFA challenge → write called; `ConditionalProvisionerRehash` after a concurrent password change leaves the new hash. FAIL; Green; PASS; commit.

### Task 10.11: Atomic conditional password update (D11)
**Files:** `identity/ports.go` (option), the identity stores in `identity/` (in-memory, if any), `store/sqlstore/identity.go`, `store/pgxstore/identity.go`, `store/gormstore/identity.go`, the identity conformance suite in `test/identity`, `authenticate/password/rehash.go`.
**Interfaces:** `func WithUserPasswordIf(expected []byte) UserOption`; `var ErrNotUpdated` (identity; not a storage failure); `ConditionalProvisionerRehash` maps `ErrNotUpdated` to success-without-write.
- [ ] Red: conformance cases — `H1` → `H2` when unchanged; stays `H3` after a change meanwhile, `errors.Is(err, identity.ErrNotUpdated)`; two concurrent conditional updates on `H1` → exactly one wins (barrier); a broken consumer store that ignores the condition fails the suite naming the conditional-update check. `TestConditionalProvisionerRehash`: no reload call; `ErrNotUpdated` → nil, nothing written.
- [ ] FAIL on every store; Green: `UPDATE … SET password_hash = $new WHERE id = $id AND password_hash = $expected`, zero rows → `ErrNotUpdated` (re-check existence only to tell not-found apart); `PasswordChangedAt` unchanged unless named. PASS; commit.

### Task 10.10: Docs
- [ ] Godoc each option with its default; README password section with the failure-mode choice and the conditional rehash write. `go doc ./authenticate/password NewPolicy`. Commit.

---

## Task group 11: security events (lane E, dispatches E1: 11.1–11.3, E2: 11.4–11.5)

**Interfaces produced:** package `github.com/kartaladev/scrty/security`: `type Event struct { Name string; At time.Time; Outcome string; User identity.UserID; ClientIP string; Factor identity.FirstFactor; Session string }`, `type Sink func(ctx context.Context, e Event)`, name constants; `httpsec.EnableSecurityEvents(s security.Sink) Option`.

### Task 11.1: Package and sink
- [ ] Red `TestSecurityEvents_Sink`: no sink → nothing; failed login → one `authn_login_fail`; a panicking sink → login succeeds, panic logged; a cancelled request context → the sink's context not done. FAIL; Green; PASS; commit.

### Task 11.2: Emission everywhere
- [ ] Red `TestSecurityEvents_Emitted`: one row per name in the spec list and per `scrty_` name, each asserting the resolved client address and no secret in any field. FAIL; Green at each call site; PASS; commit.

### Task 11.3: Only what happened
- [ ] Red `TestSecurityEvents_OnlyWhatHappened`: lost magic-link race → one `authn_token_created`; failed `Commit` → no creation event; session store outage at the bearer → no `authn_login_fail`, no `authz_fail`; hang-up → no failure event. FAIL; Green: emit after `Commit` and hand-out. PASS; commit.

### Task 11.4: Observers as events
- [ ] Red `TestSecurityEvents_Observers`: lockout → `authn_login_lock`; reuse → `authn_token_reuse`; configured observers still called. FAIL; Green; PASS; commit.

### Task 11.5: Docs
- [ ] Godoc lists every name and the sink's contract, including a blocking sink. Commit.

---

## Task group 12: automation challenge (lane C; review fixes C2; durable limiters C3)

**Interfaces produced:** `type ChallengeVerifier interface { Verify(ctx context.Context, r Request, s ChallengeSignals) (ChallengeDecision, error) }`, `type ChallengeSignals struct { SourceHasFailures, IdentifierHasFailures bool }`, `const ChallengePass, ChallengeRefuse, ChallengeNotNeeded ChallengeDecision`, `func EnableAutomationChallenge(v ChallengeVerifier, opts ...ChallengeOption) Option`, `func WithChallengeFlows(flows ...ChallengeFlow) ChallengeOption`, `func WithoutChallengeRefusalCounting() ChallengeOption`, `var ErrChallengeRequired` (403), `var ErrChallengeUnavailable` (500); `ratelimit.RecentFailureReporter { HasRecentFailures(ctx context.Context, key string) (bool, error) }` (optional, found by type assertion); `func (g *SourceGuard) HasRecentFailures(ctx context.Context, clientAddr string) bool`.

### Task 12.1: Flows and construction
- [ ] Red `TestChallenge_Flows` and `TestChallenge_Construction` with a mockgen verifier: refusal before account lookup and without a lockout failure, for each of the five flows; unselected flow not called; no verifier → no calls; nil verifier and no flows fail `New`; `WithChallengeFlows(ChallengeFlowPasswordlessBegin)` on a chain without passkey login → `ErrConfig` naming the flow; the default selection on a chain enabling none of the five → `ErrConfig`. FAIL; Green (after the source limit); PASS; commit.
- [ ] Red: Basic's verifier runs before its pre-authentication phase (a locked account refused by the verifier spends no decoy verification). FAIL by moving the call; Green; commit.

### Task 12.2: Outage and hang-up
- [ ] Red `TestChallenge_Outage`: verifier error → `ErrChallengeUnavailable`, 500, no lookup, nothing charged; cancelled context → `context.Canceled`, nothing at ERROR; an attempt-store error while reading the identifier signal → reported as failures and logged as other attempt-store failures are. FAIL; Green; PASS; commit.

### Task 12.3: Signals, counting, status
- [ ] Red `TestChallenge_Signals` and `TestChallenge_SignalsPerFlow` (clean source; suspicious identifier at login and Basic; recovery start, magic-link request and passwordless begin report `IdentifierHasFailures=false` for a username with failures; the window is the lockout's `FailureWindow()`, shown with `lockout.WithFailureWindow(time.Hour)` and a failure 2 h old → false; failing limiter reported as failures; recovery start's source signal read from its completion guard), `TestChallenge_CountsAgainstSource` (a row per flow with a source limit — form login, Basic, passwordless begin, recovery start: limit exhausted → refused before the verifier; not charged to lockout; opt-out keeps reaching the verifier), `TestStatusForError` row → 403. Review Focus row: `TestChallenge_NoEnumeration` — after one failed login each for a known and an unknown username and the owner's successful sign-in, recovery start gives the verifier identical signals for both. FAIL; Green; PASS; commit.

### Task 12.4: Conformance and docs
- [ ] Three adapters, each scenario run once (`go test -run 'TestChallenge' ./...` in `test`); godoc (`ChallengeSignals.IdentifierHasFailures` states the login/Basic residual) and README (the sample verifier does not challenge on the identifier signal alone; magic-link refusals are uncounted). Commit.

### Task 12.5: Durable limiters report recent failures
**Files:** `internal/pglimiter/runner.go` (backend query), `internal/unavailable/wrap.go` (forwarding), `store/sqlstore/limiter.go`, `store/pgxstore/limiter.go`, `ratelimit/redisstore/limiter.go`, their tests; PostgreSQL and Redis from the existing `test` helpers.
- [ ] Red `TestLimiter_HasRecentFailures` per backend (Redis, sqlstore, pgxstore), table rows: a clean key → false; one failure → true; failures older than the window → false; store unreachable → true with an error. FAIL (the limiter lacks the method, so the type assertion reports true for the clean key); Green: a read-only count within the window, recording nothing. PASS; commit.
- [ ] Red `TestWrap_HasRecentFailures` in `internal/unavailable`: forwards the backend's answer; a backend without the interface, a backend error, and the wrapper in its unavailable mode → true. FAIL; Green; PASS; commit.
- [ ] Red conformance in `test`: a chain whose source limit is kept by the Redis and the SQL limiter tells the verifier a clean source is clean. FAIL; Green; PASS. Update the README's limit note. Commit.

---

## Task group 13: supply chain (lane T)

### Task 13.1: SHA pins and the check
- [ ] Red: a check (`tools/cmd/pincheck`) run on a scratch branch with `actions/checkout@v5` and with a 7-character SHA → fails naming the workflow and action; `./.github/actions/setup` passes.
- [ ] Green: pin every action and reusable workflow to a 40-character SHA with `# vX.Y.Z`, container actions by digest; the check passes on `main`. Commit.

### Task 13.2: Dependabot
- [ ] `.github/dependabot.yml`: a `gomod` entry for every directory with a published `go.mod` (nested included), one `github-actions` entry, weekly. Verify GitHub's check accepts it. Commit.

### Task 13.3: SBOM
- [ ] Generator as a `tool` directive in `tools/go.mod`; a `sbom` target producing one file per published module; the gate fails when generation fails (prove with a broken module path first). Commit.

### Task 13.4: Vulnerabilities block the release
- [ ] On a disposable branch, pin a module to a known-vulnerable version and see the gate fail; make `vuln` part of the gate; it passes on `main`. Commit.

---

## Task group 14: integration (main session and a fresh reviewer)

### Task 14.1
- [ ] `make check` and `go test -race ./...` in every module, with the full conformance suite. Expected: all pass.

### Task 14.2
- [ ] `govulncheck ./...`, `gofmt -l .`, `go vet ./...` in every module. Expected: clean.

### Task 14.3
- [ ] An Opus reviewer that wrote none of the code checks the branch against every requirement in `specs/`, listing each as met or filing a finding (with a failing test or `UNREPRODUCED`).

---

## Self-review notes

- Spec coverage: every requirement in the nine new and ten modified capability deltas maps to a task; `http-error-propagation`'s MODIFIED contract and table rows are spread across 2.7, 5.6, 7.2, 8.10, 9.3, 10.7 and 12.3; `supply-chain` is group 13.
- Interfaces: names in a group's Interfaces block are the ones later groups use (`Request.Host/Secure`, `ClientFromContext`, `WithClientCertificateHeader`, `config.dpopEnabled`, `session.KeyBinding`, `token.Confirmation`, `TokenType`, `RehashFunc`).
- Task numbers match `tasks.md` one to one; no step adds scope beyond it.
