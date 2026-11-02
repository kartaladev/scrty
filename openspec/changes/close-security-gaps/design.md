# Design

> Reconciled on 2026-11-02 with `reauthentication` (archived on `main`) and `key-port-context` (merged as `9248c66`, archived). D1 records what that changed.

## Context

See `proposal.md` for the gaps and why they close together before `v0.1.0`. The constraints that shape the approach:

- `httpsec` is one ordered interceptor chain that runs unchanged behind net/http, gin and fiber, through its own `Request` and `ResponseWriter` interfaces. Anything a browser-hardening layer needs must be expressible through those interfaces, because fiber is not net/http.
- `httpsec.Request` has no host and no notion of transport security today. HSTS, the CSRF Origin check and the DPoP `htu` check all need both.
- Attribution reads the TCP peer and never a forwarding header (`http-security-chain`). gin and fiber defer to their frameworks' own proxy settings (`framework-adapters`). Behind a reverse proxy, every per-source limit therefore keys on the proxy.
- `reauthentication` (archived) gave the chain:
  - a recency guard (`Session.AuthenticatedWithin`, `WithRecentAuthenticationWindow`);
  - re-proof endpoints (`EnableReauthentication`) that rotate through `RotateIssuing`;
  - 403 and 409 rows in the status table.
- `key-port-context` (PR #39) gives every key port a per-call context, and three rules this change must keep:
  - an outage is not a refusal: it fails the request with fixed library text and is answered 500;
  - a request whose own context ended is not refused (`internal/hangup.ByCaller`);
  - a credential is issued before anything is stored or spent (`Prepare`/`Commit`, `RotateWithGraceIssuing`).
- Nothing is tagged, so the breaking items here are decisions, not migrations for consumers.

## Goals / Non-Goals

**Goals:**
- One implementation per concern, shared by net/http, gin and fiber, verified by the conformance suite on all three.
- Safe defaults with an override for every default (`library-design.md`). Every layer that can change a working deployment's behaviour is opt-in, and strict once enabled.
- Settle every public API that would be breaking after the tag: `Request`, `session.Store`, the password policy and the slot numbers.

**Non-Goals:**
- A cookie-borne browser session. That stays in `bff-resource-server`; this change only makes CSRF protection ready for it and mandatory with it.
- Rewriting the request for downstream code (D7).
- Bundling any third-party CAPTCHA, breach-check or SBOM vendor client beyond what each decision names.
- An OAuth authorization server, so no token revocation or introspection endpoints (RFC 7009, RFC 7662).

## Decisions

### D1. Reconciled with `reauthentication` and `key-port-context` (2026-11-02)

The draft was written before either change landed. The reconciliation changed these points:

- **The error contract and table are MODIFIED, not extended beside.** No other open change modifies those two `http-error-propagation` requirements. The table's 422 row named the `password-encoding` reuse error, which D10 moves to `password-policy`, so it had to change anyway. The separate ADDED requirement is gone.
- **The reuse error is `password.ErrReused`,** not `ErrPasswordReused`.
- **No listing index.** `sessions_user ON sessions (user_id)` already exists, so the migration adds columns only (D12).
- **DPoP is a top-level `EnableDPoP`** (D8). Session-reference authentication is its own interceptor (`EnableSessionBearer`), and the issuing endpoints belong to neither bearer.
- **Issue before spend (`key-port-context` D7).** The DPoP proof is checked in an issuing endpoint's side-effect-free checks, before any link, code or attempt is spent. The binding is set when the session is built, and `Prepared.Commit`'s "stored as built" rule covers it.
- **Outage and hang-up (`key-port-context` D3, D8).** The DPoP replay store, the breach lookup, the challenge verifier and the session listing each fail as a dependency failure (500, fixed text, not charged), or with the context's error when the caller left. This reverses the draft's "a verifier error refuses with challenge-required" (D15).
- **Rotation refuses an ended family** (`key-port-context`, `86e7d4c`). A binding is never carried into a family that has ended.
- **Recency for ending sessions** uses `reauthentication`'s guard and its default window, unchanged (D12).

**Rechecked against the merged text (task 1.1, 2026-11-02).** `key-port-context` merged as `9248c66` (PR #39), whose tree is identical to the reviewed head `86e7d4c`, and was archived in `e8762b6`. `Sessions.Prepare`/`Prepared.Commit`, `Sessions.RotateIssuing` and `RotateWithGraceIssuing`, `internal/hangup.ByCaller`, and the issuing mark `StatusForError` checks before anything else are as this decision describes them. Nothing above changed. One rule the bullets do not restate: a user store that cannot answer a login, Basic, recovery or API key owner check (`authenticate.ErrUnavailable`) stays 401, not 500. No dependency this change adds is a user store, so D18's 500 rows are unaffected.

### D2. `Request` gains `Host()` and `Secure()` (BREAKING, pre-tag)

```go
type Request interface {
    // ... existing methods ...
    Host() string // resolved host: Host header, or a trusted proxy's forwarded host (D7)
    Secure() bool // resolved transport security: TLS, the HTTPS-deployment declaration, or a trusted proxy (D7)
    HeaderValues(name string) []string // every line of a repeated header, in order (added 2026-11-02)
}
```

- **`HeaderValues` (added 2026-11-02, during task 2.5).** `Header` returns the first line only, and a forwarded chain must be read right to left across every line, or a line the client sent could be read in place of the proxy's. The first implementation made `HeaderValues` optional, falling back to `Header` for a custom adapter that lacks it. That fallback is a silent weakening (`library-design.md` rule 4), so it is a required method, breaking before the tag for the same reason as `Host`/`Secure`.

- **Default:** net/http and gin read `r.Host` and `r.TLS != nil`; fiber reads its host and TLS state from the connection, never from its proxy-aware helpers. The chain wraps the adapter's request with the resolved values (D7), so every interceptor reads one answer.
- **Override:** `WithHTTPSDeployment()` declares every request secure, for TLS that ends upstream without forwarded headers. It conflicts with `EnableTrustedProxies`, which is a configuration error.
- **Why now:** adding a method to an interface consumers implement is breaking after the tag. The CSRF layer needs `Host()` anyway, and doing it later would break custom adapters twice.
- **Alternatives rejected:**
  - *A single `URL()` accessor.* It is broader than needed, and invites rebuilding the URL inconsistently.
  - *Leaving HSTS unconditional.* RFC 6797 §7.2 forbids sending it over plaintext.

### D3. Three outermost slots, in this order

```go
const (
    OrderSecurityHeaders Order = 25
    OrderCORS            Order = 50
    OrderCSRF            Order = 75
    // OrderJWKS = 100, unchanged
)
```

- **Security headers are outermost**, so a CORS preflight answer and a CSRF refusal carry `nosniff` and the rest too.
  - The exploration's chain diagram drew CORS before headers. That order was revised here, and the gap-review document should follow.
- **CORS sits before CSRF**, so a preflight (`OPTIONS`, a safe method) is answered before the CSRF check could matter.
- **Client resolution happens before the first interceptor.** It is not an interceptor: it wraps the adapter's `Request` once, when the chain starts.
- **A host refusal still carries the security headers (settled 2026-11-02, task 2.7 review).** Resolution refuses an unknown forwarded host before any interceptor runs, so nothing a consumer registers sees the forged host. The security-headers layer exposes its header-setting step to the chain, and the chain applies it to that one response before writing the refusal. That is the only response written outside the slot.
- **The spacing follows the existing rule:** slots 25 apart, with the neighbours free for `Before`/`After`.

```
 adapter request (net/http | gin | fiber)
        |
        v
 +-------------------------------------------+
 | client resolution (D7), not a slot        |  TCP peer, TLS, Host
 |  - trusted proxies? -> forwarded values   |  or forwarded For/Proto/Host
 |  - wraps Request: ClientIP/Secure/Host    |  ClientFromContext(ctx)
 +-------------------------------------------+
        |
 25  [ security headers ]  set headers, then next()  -> every response below carries them
        |
 50  [ CORS ]              preflight OPTIONS? ----> 204 + allow headers (stop)
        |
 75  [ CSRF ]              unsafe + cross-site? --> 403 ErrCrossSiteRequest (stop)
        |
 100 [ JWKS ] 200 [ OIDC ] 300 [ form login ] ... 475 [ mTLS binding (D9) ]
 500 [ bearer: Bearer | DPoP (D8) ] ... 655 [ reauth ] ... 900 [ authorizer ]
        |
        v
 handler  -- reads CSPNonce(ctx), ClientFromContext(ctx)
```
- **Override:** consumers register around any of them with `Before`/`After`. The slot values are API once tagged.

### D4. Security headers: opt-in, strict once enabled, chosen by route

```go
httpsec.EnableSecurityHeaders(
    httpsec.WithHSTS(365*24*time.Hour, httpsec.HSTSIncludeSubdomains()), // preload: HSTSPreload(), opt-in
    httpsec.WithCSP(httpsec.StrictCSP(httpsec.CSPDirective("img-src", "'self'", "data:"))),
    httpsec.WithHeaderProfile(httpsec.APIHeaders(), httpsec.PathPrefix("/api/")),
    httpsec.WithCSPReportOnly(), httpsec.WithReportingEndpoint("csp", "https://reports.example.com/csp"),
)
func CSPNonce(ctx context.Context) (string, bool)
```

- **Defaults once enabled:**
  - **Document profile.** A nonce CSP with `'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`, plus `nosniff`, `Referrer-Policy: strict-origin-when-cross-origin` and `Cross-Origin-Opener-Policy: same-origin-allow-popups`.
  - **API profile.** `default-src 'none'; frame-ancestors 'none'`, `nosniff` and `Referrer-Policy: no-referrer`.
  - **HSTS** is one year with `includeSubDomains`, sent only when `Secure()`.
  - **Not sent:** `X-XSS-Protection`, `X-Frame-Options`, COEP and Origin-Agent-Cluster.
- **Override:** every header's value can be set, removed or extended. Profiles are chosen by matcher, and the first match wins. `HashCSP(hashes...)` replaces the nonce for a static SPA shell.
- **Responses written outside the slot (recorded 2026-11-02, task 3.2).** A host refusal, and a 500 when the random source fails, carry the headers with a CSP rendered without its nonce source, which admits no script. On a host refusal, HSTS follows the transport's `Secure()`, since the forwarded values were refused.
- **Every profile is editable (task 3.5 review).** `WithHeader`, `WithoutHeader` and `WithCSP` edit the document profile. The API profile and any consumer profile are built with the same editors (`APIHeaders(opts...)`), so no profile is fixed (`library-design.md` rule 2). `Strict-Transport-Security` is set only through `WithHSTS`, which takes whole seconds. `PathPrefix` reads a prefix without a leading `/` as rooted, and `/api/` also matches `/api`.
- **Profile building and report-only scope (recorded 2026-11-02, tasks 3.8 and the profile follow-up).** `NewHeaderProfile(opts...)` builds a consumer profile from nothing, and `CSPPolicy.With(directives...)` edits a policy, `HashCSP`'s included. Layer-wide options (`WithHSTS`, the report-only and reporting options, a nested profile) are refused inside a profile. `WithCSPReportOnly` switches the document profile only, and a route profile keeps its enforced policy. A second reporting endpoint, or one with no policy to report from, is a configuration error. `HashCSP` sends the hashes with `object-src`, `base-uri` and `frame-ancestors 'none'`, and no `'strict-dynamic'`.
- **No writer wrapping.** Headers are set on the response before `next`, so a handler's own `Header().Set` wins and `Flush`/`Hijack` are untouched. Choosing a profile from the response's `Content-Type` would need a wrapper, which loses `http.Flusher` and `http.Hijacker`.
- **Nonce:** 16 bytes from `crypto/rand`, base64, stored in the request context. Handing it to templates follows OWASP's advice against injecting nonces into every script tag.
- **Why these values:**
  - *COOP.* `same-origin-allow-popups`, not `same-origin`, so popup-based OIDC login keeps working.
  - *X-XSS-Protection.* MDN warns it can create XSS holes in otherwise safe sites.
  - *preload.* Not a default: hstspreload.org asks tooling not to enable it by default, and removal takes months.
```
 request ---> profile matchers, first match wins
               |
               +-- PathPrefix("/api/") ---> API profile
               |                            CSP: default-src 'none'; frame-ancestors 'none'
               |                            nosniff, Referrer-Policy: no-referrer, no nonce
               |
               +-- (no match) ------------> document profile
                                            nonce = 16 random bytes -> CSPNonce(ctx)
                                            CSP: script-src 'nonce-..' 'strict-dynamic'; ...
                                            nosniff, strict-origin-when-cross-origin, COOP

 both profiles: Secure()? --yes--> Strict-Transport-Security: max-age=31536000; includeSubDomains
                          --no---> no HSTS (RFC 6797 7.2)
```

- **Matcher:** this change ships a path-prefix matcher and a function matcher. Whether to also accept `authorize.Rule` is an open question.
- **Alternatives rejected:**
  - *On by default.* A strict CSP breaks every inline script of an existing app on upgrade.
  - *Helmet's default CSP* (`'self'` with `'unsafe-inline'` styles). It is weaker than a nonce policy, and ASVS L3 asks for nonces or hashes.

### D5. CORS: scrty's own, exact, refusing unsafe configurations

```go
httpsec.EnableCORS(httpsec.CORSPolicy{
    AllowedOrigins: []string{"https://app.example.com"},
    AllowedHeaders: []string{"Authorization", "Content-Type"},
    ExposedHeaders: []string{"WWW-Authenticate"},
    AllowCredentials: false,
    MaxAge: 10 * time.Minute,
})
```

- **Default:** off. Once enabled:
  - origins must match exactly, and `Vary: Origin` is always sent;
  - preflights get 204 in `OrderCORS`;
  - `MaxAge` is 10 minutes;
  - a disallowed origin gets no headers, and the request is otherwise unaffected.
- **Refused at construction:**
  - no origins;
  - the `null` origin;
  - an origin with a path or userinfo;
  - `*` with credentials;
  - a pattern without `WithOriginPattern`.
```
 browser on https://app.example.com              scrty at api.example.com
 ----------------------------------              ------------------------
 OPTIONS /api/orders                     -->     slot 50 (CORS)
   Origin: https://app.example.com               origin exactly on the list?
   Access-Control-Request-Headers:                 no  --> 204, no CORS headers
     authorization, dpop                           yes --> 204
                                         <--         Access-Control-Allow-Origin: https://app.example.com
                                                     Access-Control-Allow-Headers: Authorization, Content-Type, DPoP
                                                     Access-Control-Max-Age: 600
                                                     Vary: Origin
                                                   (no authentication interceptor runs)
 GET /api/orders + Authorization + DPoP  -->     slots 75 .. 900 as usual
```

- **Settled during tasks 4.1–4.6 (2026-11-02).**
  - **Also refused at construction:** an empty or non-token method or header name, `*` in a method or header list, a negative `MaxAge`, an origin with no host or a malformed port, a trailing `/` (a path), and a pattern without a wildcard. A pattern alone counts as an allowed origin.
  - **Pattern breadth.** A pattern needs at least two labels after its wildcard, so `https://*.com` is refused. Without a public-suffix list, `https://*.co.uk` cannot be told apart from `https://*.example.com`, and the godoc says so.
  - **Preflight caching.** `MaxAge` zero means the 10-minute default. `WithoutPreflightCaching()` sends `Access-Control-Max-Age: 0`, so the default is replaceable in both directions. Giving a `MaxAge` as well is a configuration error.
  - **`*` allows `null` too.** With `*` and no credentials, every origin gets `*`, including `null`, as the spec says. Nothing is reflected, and no credential is sent.
  - **`Vary` is added to, never replaced (task 4.2 review).** `ResponseWriter` gains a required `AddHeader(name, value string)`, before the tag, so CORS adds `Origin` to a `Vary` an outer layer or an earlier interceptor set. Replacing it would let a cache serve one variant to a client that cannot read it.
  - **`MaxAge` below one second** (other than zero) is a configuration error, since it would truncate to `0` and silently turn caching off. Turning it off is `WithoutPreflightCaching()`.
  - **Allowed headers in a preflight answer.** The answer lists the headers the preflight asked for, spelt as the policy spells them, not the whole policy list. That is the spec's wording, and the diagram above shows the request's two headers for the same reason.
- **Follows the chain:** with DPoP on, `DPoP` is allowed and `DPoP-Nonce`/`WWW-Authenticate` are exposed. With a CSRF token header, its name is allowed. `WithoutAutomaticCORSHeaders()` turns this off.
- **Departure from the established design.** It relied on a gin-only CORS middleware. scrty serves three adapters and must behave the same on all of them, and a preflight that reaches the fail-closed authorizer is refused. So CORS lives in the chain.
- **Alternatives rejected:** *rs/cors or go-chi/cors.*
  - They are net/http only.
  - Both allow every origin by default.
  - Neither refuses `*` with credentials.

### D6. CSRF: Fetch Metadata and Origin, plus a session-bound token, moved from `bff-resource-server`

- **The check:**
  - It applies to unsafe methods.
  - `Sec-Fetch-Site` of `same-origin` or `none` passes.
  - `same-site` or `cross-site` is refused unless the origin is trusted.
  - Without Fetch Metadata, an `Origin` is compared with the resolved scheme and host (D2, D7).
  - A request with neither header passes this check.
  - This mirrors Go's `net/http.CrossOriginProtection`, which tests use as an oracle. It cannot be used directly, because fiber is not net/http.
```
 method GET/HEAD/OPTIONS? --yes--> pass
        | no
        v
 Sec-Fetch-Site present?
   |yes                                   |no
   v                                      v
 same-origin | none --> pass           Origin present?
 same-site | cross-site                  |no  --> pass (non-browser client)
   |                                     |yes
   v                                     v
 Origin trusted? --yes--> pass         Origin == resolved scheme://host? --yes--> pass
   |no                                   |no
   v                                     v
 403 ErrCrossSiteRequest               Origin trusted? --yes--> pass, --no--> 403
        |
 (passed) authenticated by cookie? --no--> done
        | yes
        v
 CSRF token present and issued for this session? --yes--> pass, --no--> 403
```

- **Trusted origins:** every CORS-allowed origin by default, so a frontend on a sibling subdomain works. Same-site is refused otherwise, as Go's implementation does. **Override:** `WithCSRFTrustedOrigins`, `WithoutCORSOriginsTrustedForCSRF`.
- **Token layer:** cookie-authenticated unsafe requests need a token bound to the sign-in, in a header (`X-CSRF-Token`) or a form field (`csrf_token`), both replaceable. Bearer-only requests need none.
- **Token style (settled 2026-11-02, task 1.2): a synchronizer token stored on the sign-in, behind a replaceable port.**
  - **Default:** 32 bytes from `crypto/rand`, made when a cookie-authenticated sign-in's session is built (`Prepare`/`Create`, through a create option the chain passes only when CSRF protection is on). Every successor carries it, the way it carries the key binding (D12), so it survives renewal and rotation. A new sign-in is a new family and gets a new token. It is compared in constant time.
  - **At rest:** sealed by the sealing decorator and bound to its session identifier, as the retained ID token is. A successor's copy is sealed again for the successor's identifier. The page needs to read it again, so a one-way digest cannot serve.
  - **A sign-in without a token** (made before the migration, or before CSRF protection was enabled) is refused on unsafe cookie requests until the user signs in again. The README says so.
  - **Override:** `WithCSRFTokens(t CSRFTokens)` replaces the source, for example with an HMAC over the family handle under the consumer's own key. The port takes the request's session and answers its token, and verifies a presented one. `CSRFToken(ctx)` reads through it, whichever source is in use.
  - **Why stored by default:** OWASP recommends the synchronizer pattern for stateful applications, and Spring's default and Django's session mode keep the token server-side. A signed token needs a server key, and the chain has none, so it could not be a default that works with no configuration (`library-design.md`). Its key rotation, which needs several keys verified side by side, and its lack of revocation on its own are the consumer's to take on.
  - **Alternatives rejected:**
    - *Signed double-submit as the default:* a mandatory key.
    - *Rotating the token with the session identifier:* the bff draft did this, but the spec requires the token to survive renewals, so a page would race every renewal.
    - *Per-request tokens:* OWASP notes they break the Back button.
- **Mandatory with cookie authentication.** A chain enabling any cookie-authenticating interceptor fails construction without CSRF protection, unless `WithoutCSRFProtection()` is given. Today no built-in cookie authenticator exists. The rule binds the cookie session `bff-resource-server` will add.
- **Settled during tasks 5.1–5.4 (2026-11-02).**
  - **Departures from Go's `CrossOriginProtection`, all stricter or normalising.** A default port is normalised (`:443` matches `https` with no port). An `http` Origin is refused on an `https` request, because Go compares the host only. The scheme and host compared are the resolved ones, so a request behind a trusted proxy is judged by the origin the browser saw.
  - **Declaring a cookie authenticator.** The construction rule binds any interceptor that authenticates by cookie, a consumer's own included. So the marker is an exported interface a consumer's interceptor implements, not an unexported one only built-ins can carry.
  - **Stored tokens follow the default source.** A sign-in is created with a stored token only when CSRF protection is on, a cookie authenticator is registered, and the default token source is in use. A consumer's own source keeps no sealed value it never reads.
  - **Where the token is read.** The header first, then a URL-encoded form field of at most 1 MiB, never the query. A multipart form sends the token in the header. An empty token is refused without asking the source, and a source's own failure is returned as it is, not as a refusal.
- **Settled during tasks 5.5–5.7 (2026-11-02).**
  - **A consumer's cookie authenticator.** It implements the exported `CookieAuthenticator` marker and calls the exported `CheckCSRFToken(ex, s)` before it publishes its session. `CheckCSRFToken` also puts the checked sign-in's token where `CSRFToken(ctx)` reads it, so the accessor works for a consumer's authenticator as for a built-in one.
  - **Exemptions match the path as sent.** An exemption is compared with the escaped path (`Request.EscapedPath`, D8), so `/webhooks%2Fpayments` is not the exempt `/webhooks/payments`, whatever a framework's router does with it. Construction also refuses an exemption of a safe method, a relative path, dot or empty segments, a partial `*`, or a pattern of wildcards alone.
  - **The back-channel exemption** is `POST` on the back-channel logout path and follows `WithOIDCBackchannelLogoutPath`. It applies only when OIDC login is enabled. The path is matched as a literal, never as an exemption pattern, so a `*` in it widens nothing.
    - A provider segment holding `%`, `.` or `..` does not match.
    - With CSRF protection on, a back-channel path that cannot be exempted as written (a percent-encoding, or an empty or dot segment) is an error from `New`, naming `WithOIDCBackchannelLogoutPath` and `WithoutBackchannelLogoutExemption`. With CSRF protection off, the path is accepted as before.
    - An exemption that cannot be built is an error from `New`, never dropped.
  - **A `*` segment is judged after decoding (task 5.5 review).** The fixed segments of an exemption compare with the escaped path. A segment matched by `*` is decoded first, and refused if it holds an encoded `/` or is a dot segment, so a wildcard cannot be widened through an encoding either.
  - **A cookie authenticator must run after the CSRF layer (task 5.5 review).** A review reproduced that a `CookieAuthenticator` registered at or before `OrderCSRF` ran before the layer judged the request, and `CheckCSRFToken` then passed without checking a token. Two guards close it:
    - **at construction:** `New` refuses a `CookieAuthenticator` registered at or before `OrderCSRF` (`library-design` rule 6);
    - **at the call:** `CheckCSRFToken` fails closed when the CSRF layer has not judged the exchange, for example when a consumer calls it outside the chain. The error wraps `ErrConfig`, answered 500, and is not a 403, because the fault is the wiring, not the request. The one exception is a chain built with `WithoutCSRFProtection()`, where the consumer opted out and the call passes. A chain with no CSRF layer and no opt-out also fails closed: for example, an authenticator that calls the check but does not carry the marker that makes `New` require protection.
    - On an exempt route, and on `GET`, `HEAD` and `OPTIONS`, the layer has judged the request, so the check reads no token and passes.
  - **Override:** none for the ordering. A cookie authenticator that ran before the check would make the token optional, which is the guarantee the option exists to give.
  - **Whether a sign-in gets a token is decided when the chain is built**, on the login dependencies, not read from the request context, so a redeemer that returns a context not derived from the request still issues it.
- **Exemptions** are by method and path only. Back-channel logout is exempt by default.
- **Default:** off, until cookie authentication is enabled (then required).
- **Alternatives rejected:** *token only.* OWASP and web.dev present Fetch Metadata as the first layer, and it needs no state.

### D7. Trusted proxies: opt-in, explicit, read right to left, never rewriting the request

```go
httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
    Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
    Headers:  httpsec.XForwarded(
        httpsec.ForwardedFor,
        httpsec.ForwardedProto,
        httpsec.ForwardedHost("app.example.com"), // the allowlist is the field's argument
    ),
    MaxHops: 1,
})
func ClientFromContext(ctx context.Context) (Client, bool) // IP, Secure, Host, ViaProxy; false outside the chain
```

- **Default:** off; the TCP peer, transport TLS and `Host`. Once enabled, every control is on:
  - **Required:** the prefixes, exactly one header family, the named fields, and an allowlist when the host is trusted.
  - **Reading:**
    - repeated headers are joined;
    - entries are read right to left, skipping trusted hops up to `MaxHops` (1);
    - the scheme and host come from the client's hop.
  - **An unknown forwarded host is refused** with `ErrHostNotAllowed` (400), as Django does.
  - **Both header families are removed** after resolution.
```
 browser 203.0.113.7 --> nginx 10.20.0.2 --> app 10.20.1.5
   sends forged                appends client
   X-Forwarded-For: 1.2.3.4

 app receives from peer 10.20.0.2:
   X-Forwarded-For: 1.2.3.4, 203.0.113.7
   X-Forwarded-Proto: https

 peer 10.20.0.2 in a trusted prefix?  no --> ignore all forwarded headers, client = peer
        | yes
        v
 read X-Forwarded-For right to left, MaxHops = 1:
   [ 1.2.3.4 ,  203.0.113.7 ]
                     ^ first entry not added by a trusted proxy --> client = 203.0.113.7
        ^ never reached: a forged entry cannot become the client

 resolved: Client{IP: 203.0.113.7, Secure: true, Host: app.example.com, ViaProxy: true}
 then: host on ForwardedHost's allowlist? (if named) --no--> 400 ErrHostNotAllowed
 then: delete Forwarded and X-Forwarded-* from the request (default)
```

- **Overrides:**
  - `MaxHops(n)`;
  - `KeepForwardedHeaders()`;
  - `TrustAllProxies()`, explicit, for tests;
  - `Forwarded(...)` for RFC 7239.
- **Departure from the closest precedent:** ASP.NET Core allows every host when `AllowedHosts` is empty. scrty requires the list, because the host feeds the CSRF check, the DPoP `htu` and links.
- **No request rewriting.**
  - ASP.NET Core and Spring rewrite the request, but they own their request types.
  - In Go, "secure" lives in `r.TLS`, which cannot be faked honestly. Fiber's request cannot be rewritten the same way.
  - Express, gin, fiber and chi's replacement for `RealIP` expose accessors.
  - Removing the consumed headers is the part of the rewrite model that ports to all three adapters.
- **Adapters ignore their frameworks' proxy settings.**
  - **BREAKING:** `ginsec.WithForwardedClientIP` is removed.
  - gin trusts every proxy until configured. One resolver gives one answer everywhere.
- **Stated limit: proxies on a Unix socket (recorded 2026-11-02, group 2 review).** A peer that is not TCP has no address, so no prefix can trust it, and its forwarded headers are never read. There is no override in this change. A consumer behind a socket-connected proxy keeps the transport answer, and can declare HTTPS with `WithHTTPSDeployment`. A socket-peer option is additive later if asked for.
- **Seams later groups use.** A host refusal returns from the resolver inside the chain's assembly, before any interceptor, and group 3 applies the security headers there, on the exchange's writer, before a consumer's error handler sees it. The resolved-request wrapper forwards only `Request`'s methods, so any optional interface group 9 reads, such as the connection's peer certificate, must be forwarded through it.
- **No named presets** (loopback or private ranges) in this change. They are additive later if asked for.
- **Absorbs `trusted-proxy-client-ip`.** One trust setting answers the client, scheme and host questions. That change's proposal is marked superseded.
- **Alternatives rejected:**
  - *Reading both header families.* A client can inject the family the proxy does not overwrite.
  - *Trusting all fields once the proxy is trusted.* nginx passes client headers through unless each one is overwritten.

### D8. DPoP: one chain-wide feature, accepted once enabled, required by option, bound at every issuing endpoint

```go
httpsec.EnableDPoP(httpsec.DPoP{
    Require:     false,             // default
    ProofMaxAge: 60 * time.Second,  // default
    Replay:      replayStore,       // default: in-memory, per process
    Algorithms:  []jwa.SignatureAlgorithm{jwa.ES256()}, // default
    Nonce:       false,             // default; true turns on server nonces
    NonceCipher: nil,               // required when Nonce is true; e.g. seal.SessionCipher
    NonceLifetime: 5 * time.Minute, // default
    PublicURL:   "",                // default: built from the resolved scheme and host (D2, D7)
    MaxProofSize: 8 << 10,          // default 8 KiB
})
```

- **Why top-level (changed 2026-11-02).** The draft put DPoP on `EnableBearerToken`. But session-reference mode is its own interceptor, and the issuing endpoints (login, magic link, OIDC handoff, passkey, MFA, recovery, re-authentication, renewal) belong to neither bearer. A feature that spans issuance and verification is `EnableX` by D19, as `EnableCertificateBinding` already is. Enabling it with nothing on the chain that verifies a bound credential is a configuration error (amended 2026-11-02, below).
- **What counts as a verifier (amended 2026-11-02, for `oidc-provider`).**
  - **The original rule:** the draft refused DPoP on a chain with neither bearer mode.
  - **What the rule is for:** a chain that binds tokens but never checks a binding would issue `cnf.jkt` for nothing, and suggest a protection it does not give.
  - **Why it was amended:** an OpenID Provider (`oidc-provider` P6) checks bindings itself, at its token endpoint (refresh tokens bound to a DPoP key) and at UserInfo, and may run on a chain with no first-party bearer. The old rule would refuse that chain although it verifies every binding it issues.
  - **The amended rule:** the chain refuses DPoP unless at least one enabled feature verifies bound credentials.
  - **Who counts in this change:** the signed-bearer and session-reference modes, and no other feature. `oidc-provider` adds its provider to that set.
  - **No new API.** The set is internal to `httpsec`, because every feature that can be in it is a built-in `Enable…` option of the same package. A consumer's own handler that checks DPoP proofs does not count, and the godoc says so.
  - **Default and override:** unchanged. The rule has no override, because a chain that binds without verifying is the meaningless configuration `library-design` rule 6 refuses at construction.
  - **Rejected:**
    - *Dropping the rule.* A chain with no verifier would accept the option silently.
    - *An exported "DPoP consumer" registration for consumer code.* No consumer feature needs it yet, and it would add a public contract before the tag for a single built-in user.
- **Verification, in this order:**
  1. size within the bound, exactly one `DPoP` header, then `typ`, an asymmetric `alg` from the set (never `none` or a MAC), and a public `jwk` whose key type fits `alg`;
  2. the signature;
  3. `htm`, and `htu` against the resolved public URL, both normalised (scheme and host case, default port) and without query or fragment (RFC 9449 §4.3);
  4. `iat` within the lifetime either side, by the chain's clock;
  5. `ath` when a token is presented, and absent when none is;
  6. `nonce` when enabled;
  7. `jti` unseen, then recorded. It is recorded last, so a proof refused for any other reason consumes nothing, and nobody can fill the store with proofs that never verified.
  - JWS parsing and the RFC 7638 thumbprint use jwx v4, the project's single JOSE stack.
```
 client (key pair, private key non-exportable)          scrty
 -------------------------------------------            -----
 POST /login                                  -->  verify proof (no ath)
   DPoP: proof{htm:POST, htu:/login}               issue token, cnf.jkt = thumbprint(pub)
                                              <--  session.KeyBinding = jkt

 GET /api/orders                              -->  slot 500, bearer interceptor:
   Authorization: DPoP <token>                       1 typ, alg in set, jwk public only
   DPoP: proof{htm:GET, htu:/api/orders,             2 signature
               ath:hash(token), jti, iat}            3 htm, htu vs resolved public URL (D7)
                                                     4 iat within 60 s, jti unseen (replay store)
                                                     5 ath == hash(token)
                                                     6 thumbprint(jwk) == token cnf.jkt
                                                   all pass --> authenticated

 thief with copied token:
   Authorization: Bearer <token>              -->  token has cnf --> 401 (RFC 9449 7.1)
   Authorization: DPoP <token> + own proof    -->  thumbprint != cnf.jkt --> 401

 renewal / re-proof rotation                  -->  successor keeps the same KeyBinding
```

- **Binding:** an issuing endpoint whose request carries a valid proof without `ath` binds the token (`cnf.jkt`) and the session. The issuing endpoints are login completion, MFA verify, passkey login, magic link, OIDC handoff, recovery completion, re-authentication and renewal. Successors inherit the binding (`sessions`).
  - In session-reference mode the binding lives on the session alone, since the bearer value is opaque.
  - **Proof before spend.** The proof is verified in the endpoint's checks, before `key-port-context` D7's issue-then-spend step. A bad proof leaves a magic link, a handoff code, a challenge's attempts and recovery proofs unspent. It is charged as a malformed request, never as a failed credential, so it cannot lock an account.
  - **The binding is fixed at sign-in.** It is set on the built session (`Prepare`), so the issuing step's token carries it, and `Commit` refuses a binding changed in between. Renewal never adds, changes or removes one. Otherwise a thief holding an unbound session could renew it under their own key and lock out its owner. Re-authentication may bind an unbound session, because it is a fresh proof of the user's factor, and keeps a bound one bound.
  - **Token type.** The issued result tells the responder `DPoP` or `Bearer`, so its token response can say which (RFC 9449 §5).
- **Refusals:**
  - a bound token as `Bearer`, as RFC 9449 §7.1 requires;
  - a proof from another key;
  - renewal or re-authentication without the bound key;
  - a token whose `cnf` the chain cannot honour: an unknown member, both members, or a binding whose feature is off. Such a token is never accepted as a plain bearer token.
  - All answer 401 with `WWW-Authenticate: DPoP error=...`. A missing token with DPoP optional gets both the `DPoP` and the `Bearer` challenge.
- **Settled during tasks 8.1–8.5 (2026-11-02).**
  - **Issuing a bound token.** `token.Generator` keeps its signature. A generator that can bind implements the optional `token.ConfirmingGenerator` (`GenerateWith(ctx, id, p, opts ...IssueOption)`), as the built-in JWT generator does. `EnableDPoP` and `EnableCertificateBinding` refuse, at construction, a chain whose token generator does not implement it, so a token is never issued unbound when binding was asked for. Changing the interface would have broken every consumer generator, DPoP or not.
  - **The path as sent.** `Request` gains `EscapedPath()` (required, before the tag, as `HeaderValues` did), so `htu` compares the path the client sent on every adapter. An optional interface with a fallback to the decoded path would let `/api/ord%65rs` match `/api/orders` on an adapter that lacks it. The comparison does not decode, so `%65` and `e` differ (stricter than RFC 9449's SHOULD on RFC 3986 §6.2.2 normalisation, which only ever refuses a valid proof), but the hex digits of a percent-encoding compare without case, so `%2f` matches `%2F`.
  - **Session-reference binding is checked before anything is published.** Resolution gains an admission step after the session loads, so a session bound to another key is refused before the caller is published or a policy runs.
  - **What the chain refuses.** An unbound credential presented under the `DPoP` scheme is refused. In signed mode the stored session's binding must equal the token's `cnf`. A `cnf` with an unknown member, or both members, is refused as unauthenticated (401), never read as unbound. `x5t#S256` belongs to D9. While tasks 8.1–8.9 were in progress, `Nonce: true` was a configuration error, so it never read as enforced when it was not. Task 8.10 lifts that (below).
- **Settled during tasks 8.6–8.9 (2026-11-02).**
  - **Proof before spend, per endpoint.** Login checks the proof before the password, and a bad proof never counts as a failed password. Magic link and the OIDC handoff check it before redeeming, and a bad proof is charged to the source as a request without a usable link or code already is. Passkey login and recovery check it before the assertion or the recovery proofs and charge nothing, as for a malformed request. A valid proof is recorded at once, so a replay is refused before anything is spent too.
  - **Who binds.** The session is bound when it is built at first factor. MFA verify and renewal inherit the binding the bearer already checked, and never add one. Re-authentication binds an unbound session from a proof without `ath`, as an issuing endpoint does, and keeps a bound one bound. Recovery binds the session its core builds (`recovery.WithFinishKeyBinding`).
  - **A late renewal is admitted too.** A renewal presented after the grace window reaches the renewal endpoint without the bearer's admission step, so the endpoint runs the same binding check, and records the proof, once it loads the session.
  - **Token type in every document.** Each issuing result carries `TokenType`, and the default documents include `token_type` (RFC 9449 §5), because the OIDC handoff has no responder of its own to say it.
- **Replay record outlives the proof (task 8.4 review).** A proof's record is kept until `iat + 2 × ProofMaxAge`, not `iat + ProofMaxAge`. The `iat` check and the store's expiry read the clock at different moments, and a proof accepted just before its lifetime ended would otherwise find its own record already expired on replay. The margin covers any delay between the two reads up to a whole lifetime.
- **Proof refusals at the interceptor are not charged to the source.** An invalid proof at the bearer interceptors is answered 401 without a throttle charge. It costs one signature check after the cheap structural checks, and requests reach it only through the throttles that run first. At the issuing endpoints a bad proof is charged as a malformed request (above). A session-reference credential that loads but is refused for its binding (presented as `Bearer`, or with another key's proof) is different: it is a valid credential used by the wrong sender, so it is charged to the source as any refused reference is (the project rule for refused valid credentials), and its error also matches `ErrAuthenticationRequired`, so code cannot tell it apart from a missing session (what the wire shows is settled below).
- **Replay store:** a port with one atomic insert-if-absent, keyed by a digest of the `jti` and the key thumbprint. It shares the multi-replica caveat of the rate limiter and accepts a shared store. A store failure is a dependency failure: 500, fixed text, not charged. A request whose context ended fails with the context's error (`key-port-context` D8).
- **Nonces:** off by default. They cost a round trip, and the 60-second lifetime with `jti` already bounds replay. When on, they are stateless and sealed, so every replica that shares the key can verify them without a shared store.
- **Nonce key (settled 2026-11-02, task 8.10, user's choice).**
  - **The decision:** the chain holds no key of its own, so the consumer supplies one as `DPoP.NonceCipher` (`httpsec.NonceCipher`: `Seal` and `Open` with additional data, the same methods as `session.Cipher`, so `seal.SessionCipher` plugs in).
  - **Separation:** nonces are sealed with their own additional data (`scrty/httpsec:dpop-nonce:v1`), so a nonce opens as nothing else sealed under the same keys, and nothing else opens as a nonce.
  - **Construction rules:** `Nonce: true` without a cipher is a configuration error from `New`. So are a cipher or a lifetime set while `Nonce` is false, and a negative lifetime.
  - **Lifetime:** `NonceLifetime` defaults to 5 minutes, and anything below 10 seconds is a configuration error. Nonces are issued to the second, so a lifetime under 2 seconds would seal on every request, which breaks the one-seal-per-half-lifetime bound. Below about 10 seconds, a nonce can expire during a slow client's round trip. A fresh nonce is sent in `DPoP-Nonce` once half the lifetime has passed. RFC 9449 §8.2 leaves the timing to the server.
  - **Override:** the cipher is a port, so key storage and rotation are the consumer's. The lifetime is a field.
  - **Rejected:**
    - *A random key per process when none is given.* On more than one replica, or after a restart, nonces would be refused with no warning, which is the silent degradation `library-design` rule 4 forbids.
    - *A stateful nonce store.* It needs shared storage and a write per nonce, with no gain over sealed nonces.
- **One nonce per replica, not per request (task 8.10 review, 2026-11-02).**
  - **The problem:** the proof is checked before any credential, so a client with a key it made itself and no credential would get a freshly sealed nonce on every request. Sealing costs CPU, and an AEAD key has a bounded number of safe seals (about 2^32 for AES-GCM with random nonces). If the consumer reuses its session keyring, unauthenticated traffic spends the session keys' budget.
  - **The rule:** each replica seals one current nonce and hands the same value to every client until half `NonceLifetime` has passed, then seals the next one. So there is at most one seal per half-lifetime per replica, whatever the traffic.
  - **Why it is still sound:** RFC 9449 §8.2 leaves to the server when a new nonce is supplied. The nonce stays unpredictable because it is sealed. Freshness comes from its lifetime, and replay protection still comes from `jti` and the replay store, not from the nonce being unique to a client.
  - **The godoc and README also advise** a keyring kept for nonces alone.
  - **No override is needed:** the sealing rate is an implementation bound, not a policy.
  - **Nobody waits on a seal they do not need (task 8.10 re-review).** The current nonce is read without a lock, and no lock is held across `Seal`.
    - A request presenting a still-valid nonce is never held up by a refresh, and its response carries the next nonce only once one exists.
    - A request that is refused to be handed a nonce waits for the one seal in flight, so every client gets the same nonce. It waits only until its own context ends.
    - When the sealing request hangs up, a waiter seals in its place. A cipher failure reaches the waiters as a dependency failure and is not cached.
- **The nonce round trip is not charged (task 8.10 review).** At magic link and the OIDC handoff, only `ErrInvalidDPoPProof` that is not `ErrDPoPNonceRequired` is charged to the source. A refusal that asks for a nonce is the protocol's normal first step. A failure of the replay store or the nonce cipher is a dependency failure, a 500 that is not charged. Login, passkey, recovery, re-authentication and MFA verify charge no proof failure at all.
- **Guards carry the challenge (task 8.10 review).** A per-route guard's refusal carries the same `WWW-Authenticate` challenge as the chain's. On net/http and gin, the guard writes it before a consumer's `WithGuardErrorHandler` runs, so the handler sees it as the chain's own error handler does and can remove it. On fiber, the guard's error already returns through the chain's challenge interceptor. The challenge reaches the guards through an internal package (`internal/guardauth`), so no new API is exported.
- **What the wire shows for a binding-refused reference (wording settled in the task 8.10 review).** "Cannot be told apart from a missing session" holds in code: the error matches `ErrAuthenticationRequired`, and the status is 401 for both. On the wire, the challenge carries `error="invalid_dpop_proof"`, which a missing reference's challenge does not. The requirement "DPoP is accepted beside Bearer" and its challenge scenario oblige that. A holder of a stolen reference can therefore learn that it is live and bound. It cannot use it, and the refusal is charged to its source.
- **Default:** accepted, not required, so existing bearer clients keep working while browser clients opt in by sending proofs.
- **Alternatives rejected:**
  - *Required by default.* That would break every non-DPoP client on upgrade.
  - *Binding only at login.* Renewal and re-proof would then issue unbound successors.

### D9. mTLS-bound tokens (RFC 8705)

- **Default:** off. **Override:** `EnableCertificateBinding(...)`, a top-level option, because the binding spans token issuance and its own slot (D19).
- **Behaviour:** an issuing request with a client certificate binds `cnf.x5t#S256`. A bound token is accepted only with the same certificate, checked in the existing `OrderMTLS` slot.
- **Behind a TLS-terminating proxy:** the certificate comes from a header the consumer names in the trusted-proxy configuration. It is read only from a trusted peer, removed with the other forwarded headers, and decoded as URL-encoded PEM by default, or by a decoder the consumer supplies.
- **Proxy formats (changed 2026-11-02).** The draft left the header and encoding of each proxy open. A replaceable decoder settles the spec without that survey. The README gives examples for proxies whose format has been verified against their documentation (task 9.4), and a value that does not decode means no certificate.
- **The forwarded value is captured before removal (settled 2026-11-02, task 2.8 review).** Resolution removes every forwarded header, the named certificate header included, so the binding at `OrderMTLS` could never read it. Resolution therefore keeps the raw header value from a trusted peer on the resolved client, unexported, before removing the header. Group 9 decodes it, and an untrusted peer's value is never kept.
- **`Request` gains `ClientCertificate() *x509.Certificate` (BREAKING, pre-tag; settled 2026-11-02, group 9).** `Request` had no way to reach the connection's peer certificate, and gin and fiber hide it behind their own types. An optional method found by type assertion was rejected for the reason D2 rejected the optional `HeaderValues`: an adapter without it would issue unbound tokens with no error, a silent weakening (`library-design.md` rule 4). net/http and gin answer the leaf of `r.TLS.PeerCertificates`; fiber reads the connection's TLS state; each answers nil when there is none. The chain's resolved request (D7) answers with the certificate binding uses, so every interceptor reads one answer: from a peer that is not a trusted proxy, the connection's certificate; from a trusted proxy, the named header's value decoded once, or nil when no header is named or the value does not decode. A trusted proxy's own connection certificate is never taken for the client's.
- **Where the comparison runs (recorded 2026-11-02, group 9 review).** The `OrderMTLS` slot fixes the request's certificate thumbprint on the exchange; the comparison with the token's `cnf.x5t#S256` runs in the bearer modes (slot 500), the first place the token is known, in constant time. Issuing endpoints ahead of slot 475 read `Request.ClientCertificate` directly. The raw forwarded value is kept on the chain's internal resolution and its resolved request, never on the exported `Client`.
- **Refusals around DPoP (settled 2026-11-02).** A certificate-bound token presented while certificate binding is off is refused with `ErrCertificateBinding` in both bearer modes, whatever scheme carried it. `EnableCertificateBinding` together with a required DPoP is a configuration error: every issuing request would then carry a proof and bind it, so no certificate binding could ever be made.
- **The forwarded value is one certificate and nothing else (settled 2026-11-02).** The named header sent more than once is ignored, and the default decoder accepts exactly one PEM certificate block with nothing but whitespace around it. A review test showed that taking the first of several blocks, or skipping text before it, lets a proxy that folds a client-sent header line into its own bind the client's choice of certificate.
- **The certificate is everyone's to read.** With a certificate header named, `Request.ClientCertificate` answers the forwarded certificate to every interceptor, whether or not certificate binding is enabled. Every proxy must overwrite or strip the named header on every request, a request without a certificate included, and the README says so for each proxy example.
- **Validity is not checked here.** The library compares thumbprints only (RFC 8705 §3). The TLS server or the proxy validates the chain and dates, and the godoc says so.
- **Both offered:** a request with a valid DPoP proof and a client certificate binds DPoP only. A token carries one confirmation, and DPoP survives proxies that do not forward certificates.
```
 direct TLS:      client cert C --TLS--> app          cert = connection's peer certificate
 behind a proxy:  client cert C --TLS--> proxy --HTTP + cert header--> app
                                                      cert = named header, only from a trusted peer (D7)

 issue: cnf.x5t#S256 = base64url(SHA-256(DER(C)))
 use:   request cert hash == cnf.x5t#S256 ? accept : 401 ErrCertificateBinding   (slot 475)
```

- **Why build it now:** decided 2026-11-01. Service-to-service callers need sender-constraint without a browser key.

### D10. One password policy absorbing the reuse guard (BREAKING, pre-tag)

```go
policy, err := password.NewPolicy(
    password.MinLength(15),                        // default 15; below 8 is a configuration error
    password.ContextWords(func(ctx context.Context, u *identity.Details) ([]string, error) { ... }),
    password.Breached(password.PwnedPasswords(outbound), password.Refuse), // failure mode required
    password.NoReuse(history, 5),
    password.WithEncoder(enc),                     // default: Argon2id at its defaults; nil refused
)
err = policy.Check(ctx, user, candidate)
err = policy.Change(ctx, user, candidate, write)
```

```
 policy.Change(ctx, user, candidate, write)
   |
   |  rules, cheapest first; first refusal stops (ErrPasswordRejected{Rule})
   +--> length            15..max, counted in code points       (default)
   +--> common list       >= 3,000 entries, case-insensitive    (default)
   +--> context words     consumer's words for this user        (opt-in)
   +--> breach check      HIBP range API, 5 hex chars of SHA-1  (opt-in, failure mode required)
   +--> NoReuse           current hash + N-1 retired hashes     (opt-in, history + depth required)
   |
   v
 retire current hash into history (only with NoReuse)
   v
 encode candidate (policy's encoder)
   v
 write(ctx, user, newHash, now)   <- consumer's function, or the ready-made provisioner write
```

- **Defaults:**
  - minimum length 15 (NIST SP 800-63B-4, single-factor);
  - maximum 128 code points by default, replaceable but never below 64, never truncated, trimmed or normalised;
  - with a bcrypt encoder, the check also refuses more than 72 bytes, so a check and a change agree;
  - a bundled common-password list of at least 3,000 entries (ASVS 6.2.4);
  - no composition rules (NIST: SHALL NOT);
  - rules run cheapest first.
- **Context words (changed 2026-11-02).** A candidate is refused when it equals a context word, or contains one of 4 or more characters, case-insensitively. Equality alone lets `alice.smith2026!` through. Words shorter than 4 characters are refused only on equality, so a short service name does not refuse ordinary passphrases.
- **Encoder (changed 2026-11-02, task 10.1 review).** With none named, the policy encodes with Argon2id at the built-in defaults, so `NewPolicy()` works with no configuration. A nil encoder is a configuration error. The reuse guard required one only because it had no default.
- **The common list at the default minimum (observed 2026-11-02).** The bundled list (SecLists' xato top 10,000, MIT, notice shipped beside it) has 9,917 distinct entries, which meets ASVS's 3,000, but only 2 are 15 characters or longer. At the default minimum, the length rule does most of the work and the list mainly protects consumers who lower the minimum towards 8. Kept as is (decided 2026-11-02): the list is replaceable through `CommonPasswords`, so a consumer who wants long passphrases covered supplies their own.
- **Options replace only the rule they name.** `WithoutCommonPasswords()` removes that default explicitly, so setting one rule never silently drops a safe default.
- **Breach check:** opt-in. It uses the HIBP range API through the confined outbound client, with `Add-Padding: true`, and the lookup source is replaceable for an offline corpus.
  - `OnLookupFailure` is required: Spring's checker fails open, and the safe and convenient answers differ, so the consumer chooses. A timeout, a non-success status (429 included) and an unparseable body are all lookup failures. A hang-up fails with the context's error, whichever mode was chosen.
  - Padded entries (count 0) are discarded, as HIBP documents.
- **Reuse** is the `NoReuse` rule, with every guarantee the reuse guard had.
  - `NewReuseGuard` is removed, which is BREAKING before the tag.
  - The `password-encoding` reuse requirements are REMOVED there and ADDED here.
  - **Sign-up:** `Check` treats a user with no stored hash as having nothing to reuse.
- **Where it runs.** scrty never holds a new plaintext password outside this policy: the change endpoint calls the consumer's `ChangePasswordFunc`, and the default identity store stores hashes. The consumer calls `policy.Change` from that function.
- **Alternatives rejected:** *keeping `ReuseGuard` beside a new policy.* That leaves two objects to configure, with reuse separate from every other rule.

### D11. Rehash on login

- **Encoder side:** an optional `password.Upgrader` interface (`NeedsUpgrade(encoded) bool`), type-asserted as `Recognizer` is. The built-ins implement it; a consumer encoder without it never upgrades.
- **Login side:** `httpsec.WithLoginRehash(func(ctx, user, oldHash, newHash) error)` (and its Basic and re-proof equivalents) runs after a password verified and the request was not refused afterwards: form login, Basic authentication and password re-proof, including a login challenged for a second factor. It costs one extra key derivation on that request. Its error is logged and never changes the outcome.
- **The write receives the hash it replaces (changed 2026-11-02).** A login that verified the old password can finish after a concurrent password change stored a new hash. An unconditional write would then put the old password back. Handing the write the replaced hash lets the consumer update only while it is still the stored one (compare-and-swap).
- **The ready-made write is atomic (decided 2026-11-02).** `identity.UserProvisioner.Update` gains an option naming the expected hash (`WithUserPasswordIf`), and every shipped identity store decides it in the `UPDATE`'s own `WHERE`, reporting not-updated as a distinct result, not a storage error (`default-identity-store`). `password.ConditionalProvisionerRehash` uses it. The first implementation reloaded and then updated, which left a window between the two calls. A consumer store that does not honour the option fails the conformance suite.
- **How the login reaches the hashes.** The password provider wipes the submitted password and `Authentication` never carries a hash, so the login layer asks for an upgrade through the request context (`authenticate.RequestPasswordUpgrade`). The provider re-encodes with its own encoder only when asked, after the password verified and the current encoder's `NeedsUpgrade` said so, and leaves the result in that handle.
- **Upgrade judged by the current encoder.** `NeedsUpgrade` is asked of the current encoder, and a value it cannot parse never upgrades. A hash of another algorithm reports that it needs upgrading, but the login only reaches the upgrade once the password verified, and a built-in encoder does not verify another algorithm's hash (`authentication`: an unrecognised hash is refused). Moving users from bcrypt to Argon2id at login therefore needs a consumer encoder that verifies both. Shipping one is not part of this change (narrowed 2026-11-02, task 10.9 review).
- **Mixed parameters.** A hash with any parameter below the encoder's (memory, iterations, parallelism, salt or key length; bcrypt or scrypt cost) needs upgrading, even if another parameter is above. The re-encoded hash then has exactly the encoder's parameters, so a hash never oscillates.
- **One option per entry point.** `WithLoginRehash` (form login), `WithBasicAuthRehash` and `WithReauthenticationRehash` (password re-proof), each inside its feature (D19). A write given to one does not cover another.
- **Default:** no rehash without a write.
- **Alternatives rejected:** *rehashing in the background.* It would need a goroutine that outlives the request, holding the plaintext.

### D12. User-facing session management (BREAKING for custom stores, pre-tag)

- **The unit is a sign-in (a family).** Renewals do not show as extra devices. The handle is the family identifier, which is not a secret, and revoking by handle uses the existing family revocation.
```
 user u-1
  |
  +-- family F1 (laptop)   s1 --renew--> s2 --renew--> s3 (live)   => one sign-in, handle F1
  |
  +-- family F2 (phone)    s4 (live, current request)                => one sign-in, handle F2, Current
  |
  +-- family F3 (old)      s5 (expired)                              => not listed

 GET    /sessions          -> [F1, F2]          (no session identifiers, ever)
 DELETE /sessions/F1       -> RevokeFamily(F1)  (needs a recent authentication)
 DELETE /sessions          -> revoke every family except the current one
 DELETE /sessions/Fx (u-2) -> 404, nothing revoked
```

- **`session.Store` gains `ListByUser`.** A listing opens no sealed field: the retained ID token and the CSRF token come back empty from it, and a row whose listed fields cannot be read fails the whole call.
- **Ending sign-ins (task 6.5).** `EndSignIn` confirms ownership through one listing, then revokes the family, so a family with no live member is not found. `EndOtherSignIns` refuses a nil current session, or one of another user, rather than ending every sign-in.
- **The listing is `ListByUser`.** Every store implements it from the existing `sessions_user` index, judging liveness by the time the caller passes, as `CountActiveByUser` does. The security-state migration adds the metadata and binding columns, and no index (`schema-migrations`).
- **Sign-in metadata** (client address, user agent) is off by default, because both are personal data. `WithSessionMetadata()` turns it on. The user agent is truncated to 512 bytes at a UTF-8 boundary.
- **Endpoints:** `httpsec.EnableSessionManagement` registers `GET /sessions`, `DELETE /sessions/{handle}` and `DELETE /sessions`, all under a replaceable prefix and off by default.
  - Ending sessions requires a recent authentication, using `reauthentication`'s recency guard and window (ASVS 7.5.2). Listing does not.
  - "End others" uses the existing `DeleteByUserExcept`, which already keeps a successor that a racing renewal inserts.
  - Ending the current sign-in by its own handle acts as a logout. Refusing it would only send the client to another endpoint.
  - A sign-in still owing a second factor or a recovery step is listed and marked, because an unknown pending sign-in is exactly what the user needs to see.
  - A malformed, unknown or foreign handle is 404 and revokes nothing. Every response is `no-store`.
  - **Settled during task 7.1 (2026-11-02).** The slot is `OrderSessionManagement` (674), after re-authentication. Only a full session reaches it. The recency window is `reauthentication`'s 15-minute default, replaceable with `WithSessionManagementRecency`. Ending the current sign-in revokes its family. It does not run the logout endpoint's other steps (Clear-Site-Data, the OIDC end-session redirect), which stay with that endpoint. The default listing shows the recorded client address, as the `sessions` spec says, because metadata is opt-in.
  - **`no-store` reaches every response under the prefix (task 7.1 review).** The feature also sets `Cache-Control: no-store` at an outer position, right after the security headers, for every request under its prefix. A refusal from an earlier interceptor, such as a revoked session reference, therefore carries it too.
  - **Where metadata comes from.** The chain records the resolved client address and the request's user agent at login completion, for every first factor. The user agent is put on the context when the chain resolves the client, not by individual flows.

### D13. Security events

```go
type Event struct {
    Name     string // OWASP Logging Vocabulary, or scrty_*
    At       time.Time
    Outcome  string
    User     identity.UserID
    ClientIP string
    Factor   factor.Kind
    Session  string // digest, never the identifier
}
httpsec.EnableSecurityEvents(func(ctx context.Context, e security.Event))
```

- **Default:** no sink, no events.
- **Names (corrected 2026-11-02, group 11).** The vocabulary names rate-limit refusals (`excess_rate_limit_exceeded`) and CSRF refusals (`malicious_csrf`), so those use its names; the draft listed both under `scrty_`, against its own rule that a vocabulary name is used where one applies. Host refusal, second factors, passkeys, recovery, re-authentication, session management, DPoP, certificate binding, the automation challenge and key rotation have no vocabulary name and keep `scrty_` names.
- **Delivery:** synchronous, on a context without cancellation. The sink's errors are ignored, and it cannot change outcomes: a panic is recovered and logged without the event's contents (changed 2026-11-02, because an unrecovered panic would turn a decided outcome into a 500).
- **Only what happened.** A creation event is emitted after the session is stored and its credential handed out. A credential that `key-port-context` D7 issues and then discards (a lost race, a failed commit, a step that outlived its window) emits nothing. A hang-up or a dependency failure emits no refusal event.
- **Observers:** the lockout and reuse observers keep working and are also delivered as events.
- **Alternatives rejected:**
  - *An asynchronous queue in the library.* It would bound memory and lose events, which is the consumer's trade-off to make.
  - *Logs only.* That is what A09 flags.

### D14. Security notices

- **Passkey removal** notifies by default, with `WithoutPasskeyRemovalNotification()` to turn it off. NIST 800-63B-4 §4.5 SHOULD.
- **MFA:** there is no user-facing MFA removal endpoint today, and operator resets already notify.
- **An unseen-device sign-in notice** is opt-in. It requires session metadata and a sender.
  - **Matching against live sign-ins (changed 2026-11-02).** The draft matched the user's sessions of the last 90 days. Expired sessions are swept, so that history does not exist. The notice therefore matches the user's other live sign-ins, by user agent by default, through a replaceable matcher. A consumer who keeps device history supplies a seen-devices port, which is consulted beside them.
  - A user's first sign-in, with nothing to compare, is not notified. A sign-in whose session was never stored is not notified.
  - **Settled during task 7.4 (2026-11-02).** The seen-devices port can only suppress a notice, and with no other live sign-in nothing is sent whatever the port says. A failing port, listing or recipient lookup sends nothing and is logged without its text. A sign-in still owing a second factor is notified, because an unfamiliar pending sign-in is what the user needs to see. 
  - **Off the request path (task 7.4 review).** All of the notice's work (the listing, the seen-devices port, the recipient lookup and the send) runs after the sign-in, on a context the request's cancellation does not end, with a timeout (`WithSignInNoticeTimeout`, default 30 seconds) and a recovered panic. It never delays the response, as the spec requires. Sign-ins are throttled, so one short-lived goroutine per notice stays bounded.
  - **Coarse device text.** The notice names the device by browser and platform family ("Firefox on Linux"), by the browser alone when the platform is not recognised, or "an unrecognised device", and never copies any part of the user agent. The message builder stays replaceable.
  - **Names (task 7.4 follow-up).** `WithSignInNoticeTimeout` (default `DefaultSignInNoticeTimeout`, 30 seconds; zero or negative is a configuration error). The background work ends at the timeout only if the consumer's ports honour their context, and the godoc says so. `OrderSessionManagementNoStore` (`OrderSecurityHeaders + 2`) leaves `After(OrderSecurityHeaders)` free for consumers. `passkey.WithoutRemovalNotice()` is a per-removal option, and `httpsec.WithoutPasskeyRemovalNotification()` passes it on every removal through the endpoint.
  - **What the background work receives.** Only the values it needs: the user's ID, the sign-in's family and time, and a fresh principal holding ID, name, username and kind. Roles, organisation and scopes are left out rather than shared with the request. A recipient function that needs more looks it up by the user's ID.
  - **No synchronous-sender rule.** Once the notice runs off the request path, a sender that waits for delivery holds only the background work, up to its timeout, never the response. The refusal of such a sender and `WithSynchronousSignInNotice` are therefore dropped.

### D15. Automation challenge

- **The port:** `ChallengeVerifier.Verify(ctx, req, signals) (Decision, error)`, where `signals` reports recent limiter failures for the source and identifier.
- **Flows:** with a verifier given, it runs before login, Basic, magic-link request, passwordless begin and recovery start, all selected by default. `WithChallengeFlows` narrows them.
- **Order:** the source limit first, then the verifier, then the flow's work. A request the source limit refuses never reaches the verifier.
- **Refusals** count against the source limit by default, never against the identifier's lockout.
- **A verifier error is a dependency failure (changed 2026-11-02).** The draft refused it with challenge-required. `key-port-context` D3 makes an outage a 500 with fixed text, charged to nobody, and this follows it. A hang-up fails with the context's error.
- **No vendor is bundled.**
- **The identifier signal only at form login and Basic (settled 2026-11-02, group 12 review).** A sign-in by an account's owner resets its failures, and only a real account has an owner. A review test showed the identifier signal then differs between a known and an unknown username, so at recovery start, which answers alike for both, a verifier that challenges on it would answer whether an account exists. Recovery start, magic-link requests and passwordless begin therefore report no identifier failures. Login and Basic keep the signal: the same reset already lifts a known account's lockout and not an unknown one's, so the signal discloses nothing those flows do not. The godoc of `ChallengeSignals` states this residual, and the README's sample verifier does not challenge on the identifier signal alone.
- **The identifier window is the lockout's (settled 2026-11-02).** **Default:** the failure window of the lockout policy the flow uses (`lockout.Policy.FailureWindow`). **Override:** `lockout.WithFailureWindow`, so the challenge and the lockout never disagree about what "recent" means; the challenge has no window of its own. The chain reaches it through `policy.Engine.FailureWindows()`, which asks each registered policy for an optional `FailureWindow()`; with several, the widest is used, which can only make the verifier ask more, and with none, the lockout's default of 24 hours.
- **Selections that guard nothing fail construction (settled 2026-11-02).** `WithChallengeFlows` naming a flow the chain does not enable is a configuration error, and so is a verifier whose selection, the default included, covers no enabled flow (`library-design.md` rule 6): either would read as protection the chain does not have.
- **Magic-link requests have no source limit, so a refusal there is counted nowhere (recorded 2026-11-02).** Adding a limit to that endpoint is outside this change.
- **Recent failures are an optional limiter answer (settled 2026-11-02).** `ratelimit.RecentFailureReporter` is found by type assertion, like `PolicyReporter`, so a consumer's limiter keeps compiling; one without it is reported as having failures, which can only make the verifier ask more. Every limiter the library ships answers it, the Redis, SQL and pgx limiters included, and the outage wrapper around them reports failures while its backend is unavailable (task 12.5, the user's choice). Making it a required `Limiter` method was rejected: the fallback errs towards asking, so it is not a silent weakening. One case reads clean on purpose: in the wrapper's fall-back mode, a failure dropped because the local count was full is not reported once the backend is back, mirroring how `Exceeded` treats it there.

### D16. Supply chain

- SHA-pinned actions and reusable workflows (full 40-character SHA) with the tag in a comment, container actions pinned by digest, and local actions exempt. A CI check enforces it.
- Dependabot for `gomod`, in every published module including the nested ones, and for `github-actions`.
- An SBOM per published module, produced in the release gate. The generator is a `tool` directive in the `tools` module, chosen in the tasks.
- `govulncheck` blocks a release.
- **Coordinates with `release-readiness`**, which owns the release gate and `SECURITY.md`.
  - This change ships `make release-gate` (`vuln`, then `sbom`) as a stand-in until `release-readiness` adds `make release-check` and its module list. That change then calls both targets from its own.
  - **Attaching the SBOMs to a release is `release-readiness`'s release workflow (its task 3.3).** This change only produces them, one per published module, and fails the gate when one cannot be made. The `supply-chain` scenario "attached to the release" is met when that workflow lands, and the review of this change records it as owned there.
  - The published set includes `test`, as `release-readiness` counts it. `tools` gets Dependabot updates, because it pins the gate's own tools, but no SBOM.

### D17. Clear-Site-Data on logout

- **Default:** not sent.
- **Override:** `WithLogoutClearSiteData(directives...)`, sent only when `Secure()`.
- **Why not by default:** `"cookies"` clears the whole registrable domain, sibling subdomains included. The W3C document is a 2017 Working Draft with uneven support.

### D18. Refusals and statuses

| Refusal | Status |
|---|---|
| `ErrCrossSiteRequest` | 403 |
| `ErrHostNotAllowed` | 400 |
| `ErrInvalidDPoPProof` (and `ErrDPoPNonceRequired`, which also matches it), `ErrCertificateBinding` | 401 |
| `ErrChallengeRequired` | 403 |
| `password.ErrPasswordRejected` | 422; `password.ErrReused` stays 422 and is also `ErrPasswordRejected` |
| `ErrSessionHandleNotFound` | 404 |
| replay-store, history, breach-lookup (failures refusing), challenge-verifier and session-listing failures | 500 (dependency failures, fixed text, not charged) |

These rows MODIFY the `http-error-propagation` contract and table (D1). A request whose own context ended in any of those dependencies fails with the context's error, as `key-port-context` D8 does at verification.

### D19. Top-level options that switch on a security feature are named `Enable…`

```
 httpsec.New(
     EnableX(...)       <- switches on a feature that is off until called; checked at build time
     WithX(...)         <- a setting or declaration that switches on no feature (WithClock, WithLogger,
                           WithHTTPSDeployment)
 )
 EnableX(deps, WithY(...), WithoutZ())   <- options inside a feature tune it: With / Without
```

- **Rule:** every top-level `httpsec.New` option that switches on a security feature is `EnableX`, registered through the existing `config.enable` seam so its dependencies are checked when the chain is built. A top-level option that only sets something or declares a fact is `WithX`. Options inside a feature are `WithX` of that feature's option type, and turning off an on-by-default behaviour is `WithoutX`. This states the convention the existing API already follows (`EnableFormLogin` beside `WithClock` and `WithLoginLimiter`).
- **This change's top-level options:** `EnableSecurityHeaders`, `EnableCORS`, `EnableCSRFProtection`, `EnableTrustedProxies`, `EnableDPoP`, `EnableCertificateBinding`, `EnableSessionManagement`, `EnableAutomationChallenge`, `EnableSignInNotice`, `EnableSecurityEvents`. Each may be given once; a second call is a configuration error. `WithHTTPSDeployment` stays `With`, because it declares a fact about the deployment and switches nothing on.
- **Inside features:** DPoP's nonce, public URL and replay store are fields of its config, not top-level options. The forwarded-host allowlist is the argument of `ForwardedHost(...)`, so a trusted host can never be configured without one.
- **Alternatives rejected:** *`Enable` everywhere, including inside features.* It contradicts the sub-option style of the whole existing API, and `Enable` nested in `Enable` reads as two features.

## Risks / Trade-offs

- [This is the largest change so far: thirteen gaps across `httpsec`, `password`, `session`, `token`, the stores and CI] → The tasks split into lanes by file ownership. The breaking APIs (D2, D10, D12) come first, so later lanes build on settled interfaces.
- [A strict CSP breaks inline scripts the moment a consumer enables it] → Report-only mode and the hash preset. The README walks through a report-only rollout.
- [A misconfigured proxy list makes rate limits key on the proxy again, or trusts too much] → Construction refuses an empty list and catch-all prefixes. The README has nginx and Traefik examples. Traefik's handling of client-supplied `X-Forwarded-Proto`/`-Host` is unverified, so the docs advise testing before trusting the host field.
- [The DPoP replay store is per process by default, so across replicas a proof could be replayed within its 60 seconds] → The same documented limit as the in-memory rate limiter, with the same remedy: a shared store.
- [Building DPoP and mTLS doubles the bearer interceptor's paths] → Both share one binding abstraction on the session and token, and conformance runs each on all three adapters.
- [The bundled common-password list adds size to the core module] → A few tens of kilobytes, compressed in the binary. The list is replaceable.
- [`key-port-context` lands differently from PR #39's head] → Retired: it merged with the reviewed head's tree unchanged, and task 1.1 found no difference (D1).
- [Thirty-four requirements exceed OpenSpec's 500-character advisory] → `openspec validate --strict` reports them as warnings, as it does for `key-port-context`. No CI step runs it. Splitting them is left to archive time, when the main specs are rewritten anyway.

## Migration Plan

- **Implement after** `key-port-context` merges. `reauthentication` already has. Branch from `main`.
- **Breaking before the tag:**
  - `Request.Host()`/`Secure()` (D2);
  - `ginsec.WithForwardedClientIP` removed, and with it `ginsec.Option`, so `ginsec.Middleware(chain)` takes no options (D7);
  - `Request.HeaderValues` and `Request.EscapedPath` required (D2, D8), and `ResponseWriter.AddHeader` required (D5);
  - `identity.UserProvisioner.Update` honours `WithUserPasswordIf` in every store (D11);
  - `recovery.Finish` takes variadic options (`WithFinishKeyBinding`); existing calls compile, but a method expression or a consumer interface with the old signature does not (D8);
  - `NewReuseGuard` removed (D10);
  - `session.Store.ListByUser` (D12).
- **Schema:** one new security-state migration (D12), columns only. They are nullable, so it applies to populated databases and rolls back fully.
- **Other changes:**
  - `trusted-proxy-client-ip` is marked superseded;
  - `bff-resource-server` drops `csrf-protection` from its capabilities;
  - `release-readiness` lists this change as landing before it, and folds it into the first changelog entry.
- **Rollback:** a revert, plus rolling back the one migration.

## Open Questions

None.

Settled on 2026-11-02: the CSRF token style (a synchronizer token stored on the sign-in, behind a replaceable port, D6); the forwarded-certificate format (a replaceable decoder, D9); header profiles take a path prefix or a function, and an `authorize.Rule` adapter is additive later (D4); DPoP server nonces stay off by default (D8).

## References

### Researched (accessed 2026-10-31 unless noted)

**Scope: OWASP and ASVS mapping**
- [OWASP Top 10:2025](https://top10.owasp.org/2025/) and its [introduction source](https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/0x00_2025-Introduction.md): current categories, SSRF in A01, new A03 and A10. Treated as final because the live site carries no release-candidate banner.
- [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10): still the latest edition.
- [ASVS 5.0.0 V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md): requirements 3.4.1–3.4.8, 3.5.x, 3.7.4.

**D4: security headers**
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) and the [Secure Headers list](https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_add.json) (updated 2026-10-18): recommended values.
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html): hand the nonce to templates, never inject it.
- [web.dev: Strict CSP](https://web.dev/articles/strict-csp): nonce with `'strict-dynamic'`; hashes for static pages.
- [hstspreload.org](https://hstspreload.org/): preload requirements, and the advice against enabling it by default.
- MDN [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security), [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection), [COOP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy), [COEP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy): values and breakage.
- [Helmet](https://github.com/helmetjs/helmet), [fiber helmet](https://github.com/gofiber/fiber/blob/main/docs/middleware/helmet.md), [Spring Security headers](https://docs.spring.io/spring-security/reference/features/exploits/headers.html), [unrolled/secure](https://github.com/unrolled/secure), [gin-contrib/secure](https://github.com/gin-contrib/secure): prior defaults. Of these, only unrolled/secure generates nonces, and gin-contrib/secure still emits `X-XSS-Protection`. Live figures drift.
- [Vite CSP](https://vite.dev/guide/features#content-security-policy-csp) and [Next.js CSP guide](https://nextjs.org/docs/app/guides/content-security-policy) (accessed 2026-11-01): how the two frontends consume a nonce.

**D5: CORS**
- [MDN CORS guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS) and [Access-Control-Max-Age](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Max-Age): `Vary: Origin`, no `*` with credentials, preflight caps.
- [PortSwigger: CORS](https://portswigger.net/web-security/cors): reflected origins, `null`, matching mistakes.
- rs/cors, go-chi/cors and gorilla/handlers source: permissive defaults, and no refusal of `*` with credentials.

**D6: CSRF**
- [web.dev: Fetch Metadata](https://web.dev/articles/fetch-metadata) and the [Go 1.25 release notes](https://go.dev/doc/go1.25): `net/http.CrossOriginProtection`, read in go1.27.3's `net/http/csrf.go`.

**D6: CSRF token style** (accessed 2026-11-02)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html): the synchronizer token is the recommended pattern for stateful software; a signed double-submit token must be bound to the session; per-request tokens can break the Back button; a new session gets a new token.
- [Spring Security 7.1.2 CSRF](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html) and [`CsrfAuthenticationStrategy`](https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/csrf/CsrfAuthenticationStrategy.java) (main branch): server-side token by default, replaced at authentication.
- [Django CSRF](https://docs.djangoproject.com/en/stable/ref/csrf/) and [`django.contrib.auth.login`](https://github.com/django/django/blob/main/django/contrib/auth/__init__.py) (main branch): the token rotates at login; `CSRF_USE_SESSIONS` keeps it in the session.
- [ASP.NET Core antiforgery](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery): tokens tied to the user's identity and refreshed after authentication.
- [Go `net/http.CrossOriginProtection`](https://pkg.go.dev/net/http#CrossOriginProtection) (go1.25.0 source): header checks only, no token; why the token layer is scrty's own.
- Unverified, not relied on: how gorilla/csrf v1.7.3 treats a login, and the key-rotation cost of a signed token, which is reasoned and not sourced.

**D7: trusted proxies**
- [ASP.NET Core: proxy servers and load balancers](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer): `ForwardedHeaders.None`, loopback `KnownProxies`, `ForwardLimit` 1, `AllowedHosts`, `X-Original-*`.
- [Spring Framework: Forwarded Headers](https://docs.spring.io/spring-framework/reference/web/webmvc/filters.html): wrapping, header removal, `removeOnly`, the edge resetting both families.
- [Express: behind proxies](https://expressjs.com/en/guide/behind-proxies.html), [Django settings](https://docs.djangoproject.com/en/stable/ref/settings/), [MDN X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For): accessors, per-field opt-in, right-to-left selection, `ALLOWED_HOSTS`.
- [nginx proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [Traefik entrypoints](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/), [Fiber v3 config](https://docs.gofiber.io/api/fiber): what each sends and trusts.
- [gorilla ProxyHeaders](https://pkg.go.dev/github.com/gorilla/handlers#ProxyHeaders) and [chi RealIP](https://pkg.go.dev/github.com/go-chi/chi/v5/middleware#RealIP): rewriting without trust checks; chi deprecated `RealIP`.

**D8, D9: sender-constrained tokens** (accessed 2026-11-01)
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html): proof fields and checks, `cnf.jkt`, refusing bound tokens as bearer, `DPoP-Nonce`, CORS exposure. Re-read 2026-11-02 for the nonce key: §8 says nonces are opaque and unpredictable and leaves how they are generated to the server; §8.2 lets the server send a new nonce whenever it chooses; §9 covers resource-server nonces with `use_dpop_nonce`.
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.txt) (accessed 2026-10-31): sender-constraining SHOULD; refresh rotation as the alternative.
- [htmx events](https://htmx.org/events/): `htmx:confirm` with `issueRequest`, for the browser sample.

**D10, D11: passwords**
- [NIST SP 800-63B-4: authenticators](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/): 15/8 minimums, 64 maximum, blocklist SHALL, no composition rules.
- [ASVS 5.0 V6](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x15-V6-Authentication.md): 6.2.1, 6.2.4, 6.2.12.
- [HIBP API v3](https://haveibeenpwned.com/API/v3): the k-anonymity range lookup and padding.
- [Spring HaveIBeenPwnedRestApiPasswordChecker](https://github.com/spring-projects/spring-security/blob/main/web/src/main/java/org/springframework/security/web/authentication/password/HaveIBeenPwnedRestApiPasswordChecker.java): fails open.
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and [ASP.NET PasswordVerificationResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.passwordverificationresult): rehash at login.

**D12, D13, D14: sessions, events, notices**
- [ASVS 5.0 V7](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x16-V7-Session-Management.md): 7.5.2, view and terminate sessions after re-authentication.
- [OWASP Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html): event names; re-read 2026-11-02 for `excess_rate_limit_exceeded` and `malicious_csrf`, and to confirm it names no MFA or host-refusal event.
- [NIST SP 800-63B-4: events](https://pages.nist.gov/800-63-4/sp800-63b/events/): §4.1.2.1 and §4.5 notifications.
- [Ory Kratos API](https://github.com/ory/kratos/blob/master/spec/api.json): session listing and revocation endpoints.

**D1, D6, D10, D11, D14: reconciliation and edge cases** (accessed 2026-11-02)
- [OSV GO-2025-3955 / CVE-2025-47910](https://osv.dev/vulnerability/GO-2025-3955): `net/http.CrossOriginProtection` bypass patterns matched more than intended. Why CSRF exemptions match the exact routed path only (D6).
- [HIBP API v3, padding](https://haveibeenpwned.com/API/v3): "padded entries always have a password count of 0 and can be discarded". Why the breach check ignores count-zero entries (D10).
- [RFC 9449 §4.3, §5, §7.1](https://www.rfc-editor.org/rfc/rfc9449.html): `htu` normalisation, one `DPoP` header, `token_type`, refusing bound tokens as bearer (D8).
- [RFC 8705 §3](https://www.rfc-editor.org/rfc/rfc8705#section-3): the resource server compares the certificate thumbprint (D9).
- Reasoned from scrty's own settled specs and the `key-port-context` design: issue before spend, outage versus refusal, hang-up (D1, D11, D13, D14, D15).

**D15: automation challenge**
- [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): challenge only suspicious traffic.

**D1, D2, D3, D16, D17, D18, D19**
- Reasoned from scrty's own settled specs (`http-security-chain`, `framework-adapters`, `http-error-propagation`, `sessions`), the in-progress `reauthentication`, `key-port-context` and `release-readiness` designs, and the established design.

### Primary documentation

- [RFC 6797 (HSTS)](https://www.rfc-editor.org/rfc/rfc6797), [W3C CSP Level 3](https://www.w3.org/TR/CSP3/), [W3C Clear Site Data](https://www.w3.org/TR/clear-site-data/), [WHATWG Fetch](https://fetch.spec.whatwg.org/), [RFC 7239 (Forwarded)](https://www.rfc-editor.org/rfc/rfc7239.html), [RFC 8705 (OAuth mTLS)](https://www.rfc-editor.org/rfc/rfc8705), [RFC 7638 (JWK thumbprint)](https://www.rfc-editor.org/rfc/rfc7638).
