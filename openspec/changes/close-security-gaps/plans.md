# close-security-gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> Extended on 2026-11-03 with task group 15, the PR #45 review follow-up: every finding was reproduced by a failing test on `b441110` before it was planned, and each fix is dated 2026-11-03 in D4, D8, D10, D11, D13 or D15.

> Reconciled on 2026-11-02 with `reauthentication` (archived) and `key-port-context` (merged as `9248c66`; task 1.1 found no difference). Task 1.2 settled the CSRF token style: a token stored on the sign-in by default, behind a replaceable port (D6).

**Goal:** Close the thirteen security gaps in `proposal.md` before `v0.1.0`, with every edge case the specs pin.

**Architecture:** Every browser-facing layer is a chain interceptor in a new outer slot (headers 25, CORS 50, CSRF 75), written once against `httpsec.Request` and `ResponseWriter`, so net/http, gin and fiber share it. Trusted-proxy resolution wraps the adapter's `Request` once when the chain starts, and every interceptor and the handler read its answer. DPoP is one chain-wide feature (`EnableDPoP`) that both bearer modes and every issuing endpoint read; proofs are checked in each endpoint's side-effect-free checks, before `key-port-context`'s issue-then-spend step. Sign-in listing, the key binding and the password policy extend the existing `session`, `token` and `authenticate/password` cores.

**Tech Stack:** Go 1.27, `net/http`, gin, fiber v3, `github.com/lestrrat-go/jwx/v4` (JOSE), testify, `go.uber.org/mock`, testcontainers-go (PostgreSQL 15 and 18).

**Spec:** `openspec/changes/close-security-gaps/` — `proposal.md`, `design.md` (decisions D1–D19, with the 2026-11-03 amendments), `specs/**/spec.md` (including the `security-policy` delta), `tasks.md`.

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
- A consumer that builds a CSP from a config file and ends with `CSPPolicy{}.With(dirs...)` where `dirs` is empty: it must be refused at construction, not sent as `""`. Test added to 15.1 (the `.With()` case).
- A chain behind a trusted proxy with DPoP but no `ForwardedHost` allowlist: the host is still the transport's `Host`, so construction must refuse it, not treat "has proxies" as "host declared". Test added to 15.7.
- A login that verifies, is refused afterwards, and is retried with the right password and allowed: the second request must encode exactly once and write once, with no hash left over from the first request's handle. Test added to 15.4.
- An IPv4-mapped IPv6 client (`::ffff:203.0.113.7`) behind a guard with an IPv6 aggregate: the aggregate signal must be false, as for IPv4, not computed over the mapped prefix. Test added to 15.6.
- A client that presents its token as `Authorization: DPoP <token>` on an unbound session at renewal (the DPoP scheme with no binding): it must stay refused by `admitBinding` as today, not be let through because a proof with `ath` now verifies. Test added to 16.1.
- A request with two `Authorization` headers, or a `Bearer` header with an empty token, beside a proof carrying `ath` at re-authentication: the presented token is whatever the bearer accepted, and a proof hashing anything else is refused. Test added to 16.1.
- A sign-in notice dropped because the bound is full: the dropped sign-in's response is identical to a notified one's (status, headers, timing within the test's tolerance), so a client cannot tell. Test added to 16.3.

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
| F (parallel) | F1: CSP | 15.1 | `httpsec/headers.go`, `httpsec/headers_report.go`, their tests | Sonnet (a construction check of a known pattern) |
| F (parallel) | F2: lockout | 15.2 | `policy/lockout/lockout_observer.go`, its tests | Sonnet (one normalisation, the fix the repro already proved) |
| F (parallel) | F3: breach | 15.3 | `authenticate/password/breach.go`, `policy.go`, their tests | Sonnet (option plumbing and a log line) |
| F (parallel) | F4: rehash | 15.4 | `authenticate/password_upgrade.go`, `authenticate/password.go`, `httpsec/rehash.go`, their tests | Opus (behaviour-preserving refactor that holds a plaintext password) |
| F (worktree) | F5: challenge | 15.5 (F5a); 15.6 (F5b) | `httpsec/challenge.go`, `ratelimit/guard.go`, their tests, the README's challenge section | Sonnet for 15.5 (a default set); Opus for 15.6 (a public signal across two packages) |
| F (worktree) | F6: DPoP host | 15.7 | `httpsec/dpop.go`, every test and conformance scenario that enables DPoP, the README's DPoP section | Sonnet (a stated construction rule, applied across tests) |
| F, last | main session + reviewer | 15.8–15.9 | none | Opus reviewer (covers refusal and refactor work) |
| G (worktree) | G1: DPoP proof | 16.1 (G1a); 16.2 (G1b) | `httpsec/mfa_verify.go` (`continuingProof`), `httpsec/dpop.go` (`issuingBinding`, `verify`), `httpsec/dpop_replay.go` (`record` only), `httpsec/dpop_nonce.go`, their tests | Opus for 16.1 (security-critical verification); Sonnet for 16.2 (an ordering the finding states) |
| G (worktree) | G2: notice bound | 16.3 | `httpsec/signin_notice.go`, its tests, the README's notice paragraph | Opus (concurrency: a non-blocking bound and its release) |
| G (worktree) | G3: replay shards | 16.4 | `httpsec/dpop_replay.go` (`memoryReplayStore` only), its tests | Opus (concurrency: per-shard locks and sweeps). Shares `dpop_replay.go` with G1: G3 owns the store type, G1 the verifier's `record`; the main session merges |
| G, last | main session + reviewer | 16.5–16.6 | none | Opus reviewer |

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

**Interfaces produced:** package `github.com/kartaladev/scrty/security`: `type Event struct { Name string; At time.Time; Outcome string; User identity.UserID; ClientIP string; Factor factor.Kind; Session string }`, `type Sink func(ctx context.Context, e Event)`, name constants; `httpsec.EnableSecurityEvents(s security.Sink) Option`.

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

## Task group 15: PR #45 review follow-up (lanes F1–F6, then the main session)

Every task's red step starts from a reproduction test already seen failing on `b441110`. Copies are in `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/13a45b79-fab6-4a2f-a1ae-e86c7bad55b5/scratchpad/repro/<lane>/`, and the originals are in the agent worktrees under `.claude/worktrees/`. If neither survives, rebuild the test from the scenario the task names; the assertions below are the contract. Rename `*_repro_test.go` into the package's own test file for the behaviour, and drop anything only the repro needed. F5 and F6 both touch the README, in different sections, so each runs in its own worktree and the main session merges them.

### Task 15.1: An empty CSP policy is refused (D4)

**Files:** Modify `httpsec/headers.go` (`WithCSP`), `httpsec/headers_report.go` (`WithCSPReportOnlyPolicy`); test `httpsec/headers_edit_test.go`.

**Interfaces:** Produces nothing new. Both options return `newConfigError(...)` (wraps `ErrConfig`) when `len(p.directives) == 0`, checked after `p.err`.

- [ ] **Step 1: Failing test.** Move `TestWithCSP_RefusesPolicyWithNoDirectives` and `TestWithCSP_NeverSendsAnEmptyPolicy` from repro `csp/` into `headers_edit_test.go`. Cases: `WithCSP(CSPPolicy{})`, `WithCSP(CSPPolicy{}.With())`, `WithHeaderProfile(APIHeaders(WithCSP(CSPPolicy{})), PathPrefix("/api/"))`, the same through `NewHeaderProfile`, and `WithCSPReportOnlyPolicy(CSPPolicy{})`. Each asserts `require.ErrorIs(err, httpsec.ErrConfig)` with the message containing `WithCSP` (or `WithCSPReportOnlyPolicy`). Controls: `WithCSP(StrictCSP())` builds; `APIHeaders(WithoutHeader("Content-Security-Policy"))` builds and sends no CSP.
- [ ] **Step 2: Run** `go test -run 'TestWithCSP_' -count=1 ./httpsec/`. Expected: FAIL, "Expected error with \"httpsec: invalid configuration\" in chain but got nil", for the five empty cases only.
- [ ] **Step 3: Implement** the length check in both options, with messages `"WithCSP was given a policy with no directive; remove the header with WithoutHeader to send none"` and the same naming `WithCSPReportOnlyPolicy`. Update both godocs.
- [ ] **Step 4: Run** `go test -run 'TestWithCSP_|TestHeaders' -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 4a (amended after the group review): Failing test** `TestWithHeader_RefusesAnEmptyContentSecurityPolicy`, with `""` and `"  "` for both CSP headers, each expecting `ErrConfig` naming `WithoutHeader`, and a non-empty value as the control. Run it and expect FAIL (`got nil`). Then refuse those values in `WithHeader` and re-run Step 4.
- [ ] **Step 5: Commit** `fix(httpsec): a CSP policy with no directive fails construction`.

### Task 15.2: A zero-time failure is recorded at the policy's clock (D13, `security-policy`)

**Files:** Modify `policy/lockout/lockout_observer.go` (`observedAttempts.RecordFailure`, the `p.streaks != nil && at.IsZero()` guard, and its godoc); test `policy/lockout/lockout_events_test.go` and `lockout_observer_test.go`.

- [ ] **Step 1: Failing tests.** Move `TestAttempts_CountsZeroInstantFailuresAtThePolicyClock` and `TestAttempts_ReportsLockOnceOnTheZeroInstantFailureThatLocks` from repro `lockout/`. Use `WithSliding(3, 15*time.Minute)`, the package's fake clock, and a `MemoryAttemptStore` with 48h retention.
  - First test: three `Attempts().RecordFailure(ctx, "ada", time.Time{})` calls, without a streak store and with a sink and an observer, then `Evaluate` returns `policy.Deny`. Add a streak-store case (green today, the contrast).
  - Second test: three failures seeded two hours ago, then three zero-time failures. The sink sees exactly `authn_login_fail_max` and `authn_login_lock` once, on the third, with `At == clock.Now()`.
  - Add a kept-time case: `RecordFailure` at `now-10m` is counted at `now-10m`, which `FailureCount(since=now-5m)` does not include.
- [ ] **Step 2: Run** `go test -run 'TestAttempts_' -count=1 ./policy/lockout/`. Expected: FAIL, `expected: 1 actual: 0` (Allow) and `expected: [authn_login_fail_max authn_login_lock] actual: []`.
- [ ] **Step 3: Implement.** Normalise `at` to `p.clock.Now()` whenever `at.IsZero()`, before the lock is taken, and drop the streak condition. Godoc: "A zero instant is recorded at the policy's clock."
- [ ] **Step 4: Run** `go test -run 'TestAttempts_|TestLockout' -count=1 ./policy/lockout/`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(lockout): a failure recorded without a time counts at the policy's clock`.

### Task 15.3: A breach lookup the policy accepts leaves an ERROR record (D10)

**Files:** Modify `authenticate/password/breach.go` (`breachRule.check`, `BreachSource` godoc), `authenticate/password/policy.go` (`policyConfig.logger`, the new option, validation); test `authenticate/password/breach_test.go`, `policy_construction_test.go`.

**Interfaces:** Produces `func WithPolicyLogger(l *slog.Logger) PolicyOption`. Default `slog.Default()`; nil (typed nil included) fails `NewPolicy` with `ErrConfig` naming `WithPolicyLogger`. `breachRule` gains `logger *slog.Logger`, set from the config after the options run.

- [ ] **Step 1: Failing test.** `TestPolicy_BreachedLeavesATraceWhenTheLookupFailsAndAccepts`, reshaped from repro `breach/`. A capturing `slog.Handler` is passed through `WithPolicyLogger`, with `Breached(src, Accept)` and `MockBreachSource.Range` returning `errors.New("dial tcp: refused")`.
  - Assert exactly one record at `slog.LevelError`, with message `"password: breach lookup failed; the candidate was accepted unchecked"`.
  - Assert its attributes carry the failure's Go type and do not contain the candidate, its SHA-1 hex, its 5-character prefix, its 35-character suffix, or the text `dial tcp`.
  - Cases: a hang-up (`ctx` cancelled, source returns `ctx.Err()`) gives no ERROR record and `errors.Is(err, context.Canceled)`; `Refuse` returns `ErrLookupUnavailable` and writes no record.
  - Construction: `WithPolicyLogger(nil)` gives `ErrConfig`.
  - Keep `TestPolicy_BreachedMatchesASourceKeyInAnyCase` (lower-case keys refused as breached). Invert it once to see it is sensitive.
- [ ] **Step 2: Run** `go test -run 'TestPolicy_Breached|TestNewPolicy' -count=1 ./authenticate/password/`. Expected: FAIL, `"[]" should have 1 item(s), but has 0`, and the nil-logger case builds.
- [ ] **Step 3: Implement** the option, the nil check, and the log call in the `Accept` branch: `r.logger.LogAttrs(ctx, slog.LevelError, msgBreachLookupAccepted, diag.Failure("breach-lookup", err)...)`. Add a sentence to `BreachSource`'s godoc that suffixes are matched without regard to case. Delete the repro benchmark.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `fix(password): a breach lookup accepted on failure is logged`.

### Task 15.4: The upgraded hash is encoded only once the outcome is decided (D11)

**Files:** Modify `authenticate/password_upgrade.go` (`PasswordUpgrade`, `prepareUpgrade`, `Result`), `authenticate/password.go` (the `prepareUpgrade` call at line ~409), `httpsec/rehash.go` (the caller of `Result`, line ~54); test `authenticate/password_upgrade_test.go`, `httpsec/login_rehash_test.go`.

**Interfaces:**
- `PasswordUpgrade` keeps `RequestPasswordUpgrade(ctx) (context.Context, *PasswordUpgrade)` and `Result() (user *identity.Details, replaced, upgraded []byte, ok bool)`.
- `prepareUpgrade` no longer encodes. It stores `enc password.Encoder`, `logger`, `user`, `replaced` and `presented string`, and marks the handle pending.
- `Result()` encodes on its first call while pending, under the handle's mutex, then sets `presented = ""` and caches the answer. Later calls return the cached answer and never encode.
- An Encode error is logged as today and answers `ok == false`.
- The httpsec login layer calls `Result()` only on the path that runs the write, after the outcome is decided. That is already the case: it must not be called earlier.

- [ ] **Step 1: Failing tests.**
  - `TestLogin_RehashEncodesOnlyForALoginThatIsNotRefused` (repro `rehash-htu/`). A post-authentication `denyingIn` policy refuses, and the test expects 0 encodes and 0 writes. The allowed case expects 1 encode and 1 write.
  - The same refused case for Basic (`WithBasicAuthRehash`) and for the password re-proof (`WithReauthenticationRehash`).
  - `TestPasswordUpgrade_ResultEncodesOnce`: two `Result()` calls give the same `upgraded` bytes and one Encode.
  - Review Focus: a refused login, then an allowed retry, encodes once and writes once.
- [ ] **Step 2: Run** `go test -run 'Rehash|PasswordUpgrade' -count=1 ./httpsec/ ./authenticate/`. Expected: FAIL. The refused cases fail with `expected: 0 actual: 1` on "Encode calls the login cost".
- [ ] **Step 3: Implement** the lazy encode as in Interfaces. The godoc of `RequestPasswordUpgrade` says the extra derivation is spent only for a login whose outcome asks for it, and that the presented password is held in the handle until then, for the request's lifetime.
- [ ] **Step 4: Run** the same command, then `go test -race ./authenticate/ ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(authenticate): rehash encodes only for a login that is not refused`.

### Task 15.5: Basic is challenged only when named (D15), dispatch F5a

**Files:** Modify `httpsec/challenge.go` (`challengeFlowsAll` stays the set of valid names; add `challengeFlowsDefault` without `ChallengeFlowBasicAuth`; `EnableAutomationChallenge` starts from it; the "covers no enabled flow" error names `WithChallengeFlows`), `README.md` (challenge section); test `httpsec/challenge_test.go`.

- [ ] **Step 1: Failing tests.**
  - `TestEnableAutomationChallenge_BasicRequestFromCleanSourceConsultsNothing` (repro `challenge/`): 5 successful Basic requests under the default selection, with 0 verifier calls, 0 `FailureCount` and 0 `HasRecentFailures`.
  - A case with `WithChallengeFlows(ChallengeFlowBasicAuth)`: the verifier is called once per request, before `Authenticate`.
  - Construction: a chain with only Basic and the default selection fails with `ErrConfig` containing `WithChallengeFlows`.
- [ ] **Step 2: Run** `go test -run 'TestEnableAutomationChallenge|TestChallenge' -count=1 ./httpsec/`. Expected: FAIL, `Should be zero, but was 5` (×3), and the Basic-only chain builds.
- [ ] **Step 3: Implement** the default set and the error text. Update the godoc of `EnableAutomationChallenge` and `WithChallengeFlows` (the default names four flows; Basic is opt-in, and why). In the README, the sample verifier's flow list says the same.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): the automation challenge selects Basic only when named`.

### Task 15.6: The IPv6 aggregate is reported apart from the source (D15), dispatch F5b, after F5a

**Files:** Modify `ratelimit/guard.go` (new method), `httpsec/challenge.go` (`ChallengeSignals`, `recentFailureReader`, `signals`); test `ratelimit/guard_test.go`, `httpsec/challenge_test.go`.

**Interfaces:**
- `func (g *SourceGuard) HasRecentAggregateFailures(ctx context.Context, clientAddr string) bool`:
  - Returns false when no aggregate is configured, or when the address is IPv4 or IPv4-mapped.
  - Returns true when the aggregate limiter does not implement `RecentFailureReporter`, when it errors (logged as `reportUnreported` does), or when the address cannot be attributed.
  - Otherwise returns the limiter's answer for `flow + ":" + <aggregate prefix>`.
- `HasRecentFailures` is unchanged.
- `ChallengeSignals.SourceAggregateHasFailures bool`, documented as above.
- The chain reads it through an optional `recentAggregateFailureReader` interface on the source. A source without that interface reports `false`, because only the library's guard keeps an aggregate.

- [ ] **Step 1: Failing tests.**
  - `TestSourceGuard_HasRecentAggregateFailures`, reshaped from repro `TestSourceGuard_HasRecentFailures_SeesAggregateFailures`. It uses a /56 aggregate, with 3 failures from three /64s of `2001:db8:1::/56`. Cases:
    - fresh `2001:db8:1:ff::1` → true;
    - `2001:db8:2:ff::1` → false;
    - IPv4 `203.0.113.7` → false;
    - `::ffff:203.0.113.7` → false;
    - no aggregate configured → false;
    - an aggregate limiter that errors → true.
  - `HasRecentFailures("2001:db8:1:ff::1")` stays false.
  - Chain test: the verifier sees `SourceHasFailures == false` and `SourceAggregateHasFailures == true` for the fresh /64.
- [ ] **Step 2: Run** `go test -run 'RecentAggregateFailures|TestChallenge_Signals' -count=1 ./ratelimit/ ./httpsec/`. Expected: FAIL to compile first, which is not the red step. Add the method as `return false` and the field, then re-run. Expected: FAIL, `Should be true` on the fresh-/64 case.
- [ ] **Step 3: Implement** the method with `g.keyer.keys(clientAddr, g.aggregateBits)`, which yields the aggregate key the check and record paths use. Then fill the field in `signals`.
- [ ] **Step 4: Run** the same command, then `go test -race ./ratelimit/ ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): the challenge verifier is told about the source's IPv6 aggregate`.

### Task 15.7: DPoP needs a declared host (D8)

**Files:** Modify `httpsec/dpop.go` (the chain-level check beside the "no feature that verifies bound credentials" rule; `PublicURL` godoc; `EnableDPoP` godoc), `README.md` (DPoP section); tests: `httpsec/dpop_test.go` and every `httpsec` and `test/` file whose chain enables DPoP; `test/httpsecconformance/dpop_scenarios.go`.

**Interfaces:**
- The check passes when `d.publicURL != nil`, or when `c.proxies != nil && len(c.proxies.allowed) > 0`.
- Otherwise it fails with `newConfigError("EnableDPoP needs the host its proofs are judged against: set DPoP.PublicURL, or name the allowed hosts with EnableTrustedProxies(..., ForwardedHost(...))")`.

- [ ] **Step 1: Failing tests** in `dpop_test.go`'s construction table:
  - no `PublicURL` and no proxies → `ErrConfig` containing `PublicURL` and `ForwardedHost`;
  - trusted proxies without `ForwardedHost` → the same error (Review Focus);
  - `PublicURL: "https://app.example.com"` → builds;
  - proxies with `ForwardedHost("app.example.com")` → builds.
  - Reshape `TestDPoP_HTURefusesHostTheDeploymentDidNotDeclare` (repro `rehash-htu/`) to `PublicURL: "https://app.example.com"`: a proof for `https://evil.example/api/orders` with `Host: evil.example` gives `ErrInvalidDPoPProof`.
- [ ] **Step 2: Run** `go test -run 'TestDPoP|TestEnableDPoP' -count=1 ./httpsec/`. Expected: FAIL, the first two construction cases build with no error.
- [ ] **Step 3: Implement** the check. Then give every DPoP chain in tests, conformance and README samples `PublicURL` (or a `ForwardedHost` allowlist where the scenario is behind a proxy, as the trusted-proxy `htu` scenario now states).
- [ ] **Step 4: Run** `go test -count=1 ./httpsec/...` and, in the `test` module, `go test -run 'DPoP' ./...`. Expected: PASS.
- [ ] **Step 4a (amended after review): Failing test** `TestDPoP_HTURefusesHostOffTheForwardedHostAllowlist`. The chain has trusted proxies with `ForwardedHost("app.example.com")` and no `PublicURL`. A proof for `http://evil.example/api/orders` is sent with `Host: evil.example`, in two cases: from an untrusted peer, and from a trusted peer that forwards no host. Expect `ErrInvalidDPoPProof` and that the handler does not run. Add a control: a forwarded `app.example.com` passes. Run it and expect FAIL (`got nil`). Then implement: in the proof check, when `PublicURL` is nil, refuse a resolved host that is not in `c.proxies.allowed`, compared as the proxy check compares hosts. Re-run Step 4.
- [ ] **Step 5: Commit** `fix(httpsec)!: DPoP refuses a chain whose host is not declared`.

### Task 15.8: Adapters and gate (main session)
- [ ] Merge the F5 and F6 worktrees, then run the challenge, header and DPoP conformance scenarios on net/http, gin and fiber, and `make check`. Expected: all pass, with `gofmt -l`, `go vet` and `govulncheck` clean.

### Task 15.9: Review (fresh reviewer)
- [ ] An Opus reviewer that wrote none of group 15 checks the diff against every requirement and scenario changed on 2026-11-03: `security-headers`, `security-policy`, `password-policy`, `http-security-chain` (rehash), `automation-challenge` and `sender-constrained-tokens`. It lists each as met, or files a finding with a failing test or `UNREPRODUCED`.


## Task group 16: PR #45 second review (lanes G1–G3, then the main session)

Each red step starts from a reproduction seen failing on `7ce3d4a`, in `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/13a45b79-fab6-4a2f-a1ae-e86c7bad55b5/scratchpad/repro-g16/<a|b|c>/` and in the worktrees `.claude/worktrees/repro-g16-<a|b|c>`. Move each `*_repro_test.go` into the package's own test file for the behaviour. G1, G2 and G3 run in their own worktrees in parallel; G1's two dispatches run in order.

### Task 16.1: A proof beside a presented token carries its `ath` (D8)

**Files:** Modify `httpsec/mfa_verify.go` (`continuingProof`), `httpsec/dpop.go` (`issuingBinding`, a new helper); test `httpsec/dpop_issuing_test.go` (or a new `dpop_continuing_test.go`).

**Interfaces (revised during 16.1):** the signed-bearer and session-reference interceptors record the credential they authenticated on the `Exchange` through `func (e *Exchange) RecordPresentedToken(tok string)`, set only on success; a consumer's own bearer calls the same method after verifying its credential. `continuingProof` and `issuingBinding` pass it to `v.verify(ctx, r, tok)` in place of `""`; it is `""` where no bearer authenticated the request (login, a cookie session). No second parse of the `Authorization` header.

- [ ] **Step 1: Failing tests.** Move `TestContinuingProof_RequiresAthBesideAccessToken` (12 cases: renewal, MFA verify, re-authentication × unbound, certificate-bound × with, without `ath`). With `ath` over the presented token: accepted. Without: `ErrInvalidDPoPProof`, nothing rotated. Add the Review Focus cases: two `Authorization` headers with a proof hashing either → refused; an unbound session under the `DPoP` scheme at renewal → still refused as today. Keep a cookie-session row: a proof without `ath` is accepted, one with `ath` refused.
- [ ] **Step 2: Run** `go test -run 'TestContinuingProof_' -count=1 ./httpsec/`. Expected: FAIL, `Received unexpected error: httpsec: invalid DPoP proof` on the six with-`ath` rows, and the without-`ath` rows accepted.
- [ ] **Step 3: Implement** the recorded credential (`Exchange.bearerCredential`, set by both bearers on success) and a `tok string` parameter on `issuingBinding`, passed at every caller. Update `continuingProof`'s and `reauthBinding`'s comments.
- [ ] **Step 4: Run** `go test -run 'TestContinuingProof_|TestDPoP|Renew|Reauth|MFAVerify' -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): a proof beside a presented access token is checked against its ath`.

### Task 16.2: A nonce is refreshed only for an accepted proof (D8), after 16.1

**Files:** Modify `httpsec/dpop.go` (`verify`, the `refreshNonce` call at line ~566), `httpsec/dpop_replay.go` (`dpopVerifier.record`); test `httpsec/dpop_nonce_test.go`.

**Interfaces:** `dpopProof` gains `staleNonce bool`, set by `verify` where it now calls `refreshNonce`. `record` calls `v.refreshNonce(ctx)` after a fresh insert succeeds and only when `p.staleNonce`. Every path that verifies a proof already calls `record` after `verify`; confirm with gopls references that none skips it.

- [ ] **Step 1: Failing test.** Move `TestDPoP_ReplayedProofGetsNoNonceRefreshAndSealsNothing`: two replicas with counting ciphers, one key, one replay store; the replay to either has no `DPoP-Nonce` and B seals 0. Keep the existing "Expired nonce" and "One nonce per replica" scenarios green.
- [ ] **Step 2: Run** `go test -run 'TestDPoP_ReplayedProof' -count=1 ./httpsec/`. Expected: FAIL, `Should be empty, but was <nonce>` and `expected: 0 actual: 1`.
- [ ] **Step 3: Implement** the flag and the moved call.
- [ ] **Step 4: Run** `go test -run 'TestDPoP' -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): a refused DPoP proof is given no new nonce`.

### Task 16.3: The sign-in notice is bounded (D14)

**Files:** Modify `httpsec/signin_notice.go` (`signInNotice`, `start`, options), `README.md` (notice paragraph); test `httpsec/signin_notice_test.go`.

**Interfaces:** Produces `const DefaultSignInNoticeConcurrency = 32` and `func WithSignInNoticeConcurrency(n int) SignInNoticeOption`; `n < 1` fails construction with `ErrConfig` naming the option. `signInNotice` holds `slots chan struct{}` of that capacity. `start` acquires with a non-blocking send; when full it drops the notice and logs `msgSignInNoticeDropped` at WARN through the package's sampled logger, with no user attribute; the goroutine releases its slot in its deferred function, after the recovered panic.

- [ ] **Step 1: Failing tests.** Move `TestSignInNotice_BoundsConcurrentNoticeWork` (200 concurrent logins, a store that blocks, peak ≤ 32). Add: `WithSignInNoticeConcurrency(4)` → peak ≤ 4; `WithSignInNoticeConcurrency(0)` → `ErrConfig`; a dropped notice leaves one WARN record without the user ID; Review Focus: a dropped sign-in's response has the same status and headers as a notified one's. After the gate opens, every slot is free again (a further login is notified).
- [ ] **Step 2: Run** `go test -race -run 'SignInNotice' -count=1 ./httpsec/`. Expected: FAIL, `"200" is not less than or equal to "32"`, and the construction case builds.
- [ ] **Step 3: Implement** the bound, the option, the constant, the log line. Update the godoc of `EnableSignInNotice` and the README.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `fix(httpsec): the sign-in notice runs at most 32 at once`.

### Task 16.4: The default replay store is sharded (D8)

**Files:** Modify `httpsec/dpop_replay.go` (`memoryReplayStore`, `newMemoryReplayStore`, `Record`); test `httpsec/dpop_replay_test.go`.

**Interfaces:** `memoryReplayStore` holds `[64]replayShard`; `replayShard` has its own `sync.Mutex`, `map[string]time.Time` and `nextSweep`. The shard is chosen from the key, which is already a digest (FNV-1a over the key's bytes, modulo 64). `Record`'s signature and its insert-if-absent and `until` rules are unchanged.

- [ ] **Step 1: Failing test** `TestMemoryReplayStore_SweepsOnlyItsShard`: fill the store with expired keys across shards, advance the clock past the sweep interval, call `Record` once, and assert that only the shard that call landed on was emptied (an unexported count per shard, read in the internal test). Keep the existing replay tests unchanged. Move `BenchmarkReplayRecordSweep` and `BenchmarkReplayRecordNormal` beside it.
- [ ] **Step 2: Run** `go test -run 'TestMemoryReplayStore_' -count=1 ./httpsec/`. Expected: FAIL, the whole store emptied by one sweep (add the shard accessor as a stub first, so the red is an assertion).
- [ ] **Step 3: Implement** the shards.
- [ ] **Step 4: Run** `go test -race -run 'Replay' -count=1 ./httpsec/`, then `go test -run '^$' -bench 'ReplayRecord' -benchmem ./httpsec/`. Expected: PASS, and the 600,000-entry sweep about a sixty-fourth of the 4.6 ms and 71 ms measured before; report both.
- [ ] **Step 5: Commit** `perf(httpsec): the default DPoP replay store is sharded`.

### Task 16.5: Gate (main session)
- [ ] Merge G1, G2, G3 (G1 and G3 both touch `dpop_replay.go`, different declarations), then `make check`. Expected: exit 0.

### Task 16.6: Review (fresh reviewer)
- [ ] An Opus reviewer that wrote none of group 16 checks the diff against the requirements and scenarios changed in the second review: `sender-constrained-tokens` (the issuing-endpoint wording, "Proof beside a presented token at a continuing endpoint", "Proof without ath beside a presented token", the nonce sentence, "Refused replay gets no new nonce") and `http-security-chain` (the notice bound, "Burst of sign-ins", "Consumer's bound"), and D8 and D14. Each met, or a finding with a failing test or `UNREPRODUCED`.

## Task group 17: Package naming (lane H, one dispatch, then the main session)

A mechanical rename with no behaviour change, so the existing suites are its test (`golang-tdd.md`: "mechanical renames already covered by existing tests"); there is no red step. One lane, because every importer of the renamed packages changes with them: the call graph does not split. Haiku, in its own worktree from the branch head, using gopls.

### Task 17.1: `security` becomes `event`, `internal/secevent` becomes `internal/eventsink` (D13)

**Files:** Move `security/` to `event/` (`doc.go`, `event.go`, `doc_test.go`, `event_test.go`) and `internal/secevent/` to `internal/eventsink/`; modify every importer across the `go.work` modules (core, `httpsec/fibersec`, `httpsec/ginsec`, `test`), and `README.md`'s security-events section.

**Interfaces produced:** `github.com/kartaladev/scrty/event` with the same identifiers as before (`Event`, `Sink`, the name and outcome constants, `Names`); `internal/eventsink` with the same identifiers as `secevent` (`Emitter`, `Own`, `With`, `Send`, `Deliver`, `Enabled`, `WithFactor`, `FactorOf`, `GuardRefused`, `SessionDigest`, `MsgSinkPanicked`). Option names unchanged: `httpsec.EnableSecurityEvents`, `*.WithSecurityEvents`, `mfa.WithThrottleSecurityEvents`, `mfa.WithResetSecurityEvents`.

- [ ] **Step 1: Baseline.** `go build ./... && go test -count=1 ./...` in the core module passes before any edit; record it.
- [ ] **Step 2: Rename** with `gopls rename` on each package clause (it moves the directory and rewrites import paths), or `git mv` plus a gopls-checked import rewrite where gopls refuses. External test packages become `event_test` and `eventsink_test`. No import alias anywhere; a local identifier that would shadow `event` is renamed instead.
- [ ] **Step 3: Godoc and README.** The package comment starts `// Package event`; every `security.X` in comments and the README becomes `event.X`; `go doc github.com/kartaladev/scrty/event` in the README.
- [ ] **Step 4: Verify.** `go build ./... && go vet ./...` in each module of `go.work`; `go test -count=1 ./...` in the core module, `httpsec/fibersec`, `httpsec/ginsec`; `gofmt -l .` empty; the stale-name search in task 17.1 of `tasks.md` finds nothing outside `openspec/`.
- [ ] **Step 5: Report** files moved, importer count per module, the suite results; the main session commits `refactor: name the security-event package event`.

### Task 17.2: Gate (main session)
- [ ] Merge lane H, then `make check`. Expected: exit 0.

### Task 17.3: Review (fresh reviewer)
- [ ] A Sonnet reviewer that did not write the rename checks the diff: no stale `security` package reference or `secevent` in code, godoc or README; no alias added; option names unchanged; only package clauses, import paths, qualifiers and comments changed (no logic line). Each met, or a finding.

## Task group 18: Verification follow-up (lanes I1–I3 in parallel, then the main session)

From the `/opsx:verify` report of 2026-11-03. Each lane runs in its own worktree from the branch head; no file is shared. The new tests pin behaviour the code already has, so each red step breaks that behaviour temporarily, shows the test failing for that reason, and edits it back (`golang-tdd.md`). The two framework-adapters scenarios the report listed are already covered by the conformance rows `trustedProxyNamesTheClientOnEveryAdapter` and `unattributableClientAddress`, which run on net/http, gin and fiber; they get no task. The Basic rehash scenario (D11) is already pinned by `login_rehash_test.go` ("challenged after the password verified").

### Task 18.1: The policy's godoc states its one log record (lane I1, Haiku: exact text)

**Files:** Modify `authenticate/password/policy.go:84-85` (the `Policy` type comment).

- [ ] **Step 1:** Replace "The policy writes no log record, and does not keep the candidate after a call returns." with: "The policy never logs a candidate, a hash or a context word, and does not keep the candidate after a call returns. Its one log record is a breach-lookup failure accepted under Accept, written at ERROR with fixed text to the logger WithPolicyLogger sets (default slog.Default())."
- [ ] **Step 2:** `gofmt -l authenticate/password` empty; `go vet ./authenticate/password/`; `go doc ./authenticate/password Policy` shows the text.

### Task 18.2: Depth 3 and listing across replicas (lane I2, Sonnet)

**Files:** Test `authenticate/password/reuse_test.go` (new row or test `TestPolicy_ReuseDepthThreeSequence`); `test/storetest/session_signins_suite.go` (new case "listing across replicas").

- [ ] **Step 1: Depth 3.** A policy with the reuse rule at depth 3 over an in-memory history; provision `p1`; change to `p2`, `p3`, `p4` through the policy, each succeeding. Then: changing to `p4`, `p3`, `p2` each fails with `errors.Is(err, password.ErrReused)`; changing to `p1` succeeds. Red step: set the depth to 2 temporarily and see the `p2` row fail ("expected ErrReused"), then restore.
- [ ] **Step 2: Replicas.** In the sign-in suite, a case that creates a sign-in for user U through the harness store and another through `h.NewReplica(t)`, then lists U on each: both listings return both families (compare with `assertListed`). Red step: list on the replica with a different user temporarily and see it return one, then restore. Skip the case where the harness has no replica, as the ambient suite does.
- [ ] **Step 3: Verify.** `go test -count=1 -run 'Reuse' ./authenticate/password/`; `cd test && go test -count=1 -run 'Session' ./sqlstore/ ./pgxstore/ ./gormstore/` (Docker).

### Task 18.3: Repository check for Dependabot coverage and no auto-merge (lane I3, Sonnet)

**Files:** Create `tools/repocheck/repocheck.go` (package `repocheck`, doc comment stating both rules) and `tools/repocheck/repocheck_test.go`; `tools/go.mod` (promote `golang.org/x/mod` to a direct requirement for `modfile.ParseWork`).

**Interfaces produced:**
- `func MissingUpdateEntries(dependabot []byte, modules []string) ([]string, error)` returns each directory in `modules` (go.work `use` paths, plus `tools`) with no `package-ecosystem: gomod` entry whose `schedule.interval` is `daily` or `weekly`, and `"github-actions"` when that ecosystem has no such entry.
- `func AutoMergeSteps(workflows map[string][]byte) []string` returns `file: reason` for every workflow that approves or merges a pull request: a `run` containing `gh pr merge` or `gh pr review` with `--approve`; a `uses` of `peter-evans/enable-pull-request-automerge`, `pascalgn/automerge-action`, `hmarr/auto-approve-action` or `ahmadnassri/action-dependabot-auto-merge`; or any text containing `enablePullRequestAutoMerge`, `mergePullRequest` or `addPullRequestReview`.

- [ ] **Step 1: Failing tests.** `TestMissingUpdateEntries` (table: every module covered → none; `httpsec/ginsec` missing → `["httpsec/ginsec"]`; monthly schedule → listed; no github-actions → `["github-actions"]`). `TestAutoMergeSteps` (table: plain CI → none; `gh pr merge --auto --squash` → named; `hmarr/auto-approve-action@<sha>` → named; `gh pr review --approve` → named). `TestRepository_DependabotAndWorkflows` reads `../../go.work`, `../../.github/dependabot.yml` and `../../.github/workflows/*.y*ml` and asserts both functions return nothing.
- [ ] **Step 2: Run** `cd tools && GOWORK=off go test -count=1 ./repocheck/`. Expected: FAIL, undefined functions are a compile error and not the red step, so first add the two functions returning nil, then see the fixture rows fail on their assertions.
- [ ] **Step 3: Implement** with `gopkg.in/yaml.v3` (already required) and `modfile.ParseWork`. Paths are compared cleaned and without a leading `./` or `/`.
- [ ] **Step 4: Verify** `cd tools && GOWORK=off go vet ./... && GOWORK=off go test -race -count=1 ./...`; `make tools-check`.

### Task 18.4: Gate (main session)
- [ ] Merge I1–I3, then `make check`. Expected: exit 0.

### Task 18.5: Review (fresh reviewer)
- [ ] A Sonnet reviewer that wrote none of group 18 checks the diff against the changed scenarios: `password-policy` "Depth 3", `security-state-stores` "Listing across replicas", `supply-chain` "Every module covered", "Never merged automatically" and "Auto-merge workflow refused", and the policy godoc against D10. Each met, or a finding.

---

## Self-review notes

- Spec coverage: every requirement in the nine new and ten modified capability deltas maps to a task; `http-error-propagation`'s MODIFIED contract and table rows are spread across 2.7, 5.6, 7.2, 8.10, 9.3, 10.7 and 12.3; `supply-chain` is group 13.
- Interfaces: names in a group's Interfaces block are the ones later groups use (`Request.Host/Secure`, `ClientFromContext`, `WithClientCertificateHeader`, `config.dpopEnabled`, `session.KeyBinding`, `token.Confirmation`, `TokenType`, `RehashFunc`).
- Task numbers match `tasks.md` one to one; no step adds scope beyond it.
- Group 15 (2026-11-03): each of the six changed capabilities maps to one task (`security-headers` 15.1, `security-policy` 15.2, `password-policy` 15.3, `http-security-chain` 15.4, `automation-challenge` 15.5–15.6, `sender-constrained-tokens` 15.7). New names used across tasks: `WithPolicyLogger`, `SourceGuard.HasRecentAggregateFailures`, `ChallengeSignals.SourceAggregateHasFailures`, `challengeFlowsDefault`. The breach-loop optimisation was declined in D10 and has no task beyond its pinning test.
- Group 16 (2026-11-03, second review): `sender-constrained-tokens` maps to 16.1 and 16.2, the notice bound in `http-security-chain` to 16.3, the replay sharding (D8, no spec change) to 16.4. New names: `Exchange.bearerCredential`, `issuingBinding`'s `tok` parameter, `dpopProof.staleNonce`, `DefaultSignInNoticeConcurrency`, `WithSignInNoticeConcurrency`, `replayShard`. The three cleanups and the unreproduced list-sort claim have no task; they are recorded under design.md's Open Questions.
- Group 17 (2026-11-03, naming): D13's package-name amendment maps to 17.1; no spec changes, since specs name no package. No new identifiers: the two packages keep every exported name.

- Group 18 (2026-11-03, verification follow-up): the reworded `supply-chain` requirements map to 18.3 (the SBOM requirement needs no new code: `make sbom` already fails when one cannot be made); the Basic rehash clarification and the two framework-adapters scenarios are covered by existing tests, named in the group's preamble. New names: `repocheck.MissingUpdateEntries`, `repocheck.AutoMergeSteps`.
