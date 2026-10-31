# Design

> **Draft.** Written against the specs as `reauthentication` and `key-port-context` will leave them. Every decision below that touches guards, the error table, session rotation, the bearer interceptor or token issuance must be rechecked against what those changes land, before implementation starts.

## Context

See `proposal.md` for the gaps and why they close together before `v0.1.0`. The constraints that shape the approach:

- `httpsec` is one ordered interceptor chain that runs unchanged behind net/http, gin and fiber, through its own `Request` and `ResponseWriter` interfaces. Anything a browser-hardening layer needs must be expressible through those interfaces, because fiber is not net/http.
- `httpsec.Request` has no host and no notion of transport security today. HSTS, the CSRF Origin check and the DPoP `htu` check all need both.
- Attribution reads the TCP peer and never a forwarding header (`http-security-chain`). gin and fiber defer to their frameworks' own proxy settings (`framework-adapters`). Behind a reverse proxy, every per-source limit therefore keys on the proxy.
- After `reauthentication`, the chain also has:
  - a recency check on the session (`Session.AuthenticatedWithin`);
  - re-proof endpoints that rotate the session;
  - a status table carrying 409 and 403 rows for its refusals.

  After `key-port-context`, the bearer requirement and token issuance take a context-aware key port. This change builds on both.
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

### D1. Draft baseline: the in-progress changes, not the archived specs

- Spec deltas add requirements beside those `reauthentication` and `key-port-context` modify, and do not re-modify them. The new refusals are one ADDED requirement in `http-error-propagation`, not an edit of the contract and table requirements that `reauthentication` modifies. This keeps the three changes mergeable in any archive order.
- When `reauthentication` merges, the review pass:
  - re-reads its landed specs;
  - folds this change's refusals into the contract and table requirements if the project prefers one list;
  - rechecks D8's binding on re-proof rotation and D12's use of the recency check.

### D2. `Request` gains `Host()` and `Secure()` (BREAKING, pre-tag)

```go
type Request interface {
    // ... existing methods ...
    Host() string // resolved host: Host header, or a trusted proxy's forwarded host (D7)
    Secure() bool // resolved transport security: TLS, the HTTPS-deployment declaration, or a trusted proxy (D7)
}
```

- **Default:** net/http and gin read `r.Host` and `r.TLS != nil`; fiber reads its host and TLS state from the connection, never from its proxy-aware helpers. The chain wraps the adapter's request with the resolved values (D7), so every interceptor reads one answer.
- **Override:** `WithHTTPSDeployment()` declares every request secure, for TLS that ends upstream without forwarded headers. It conflicts with `WithTrustedProxies`, which is a configuration error.
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
- **Token layer:** cookie-authenticated unsafe requests need a token bound to the session, in a header (`X-CSRF-Token`) or a form field (`csrf_token`), both replaceable. Bearer-only requests need none.
- **Mandatory with cookie authentication.** A chain enabling any cookie-authenticating interceptor fails construction without CSRF protection, unless `WithoutCSRFProtection()` is given. Today no built-in cookie authenticator exists. The rule binds the cookie session `bff-resource-server` will add.
- **Exemptions** are by method and path only. Back-channel logout is exempt by default.
- **Default:** off, until cookie authentication is enabled (then required).
- **Alternatives rejected:** *token only.* OWASP and web.dev present Fetch Metadata as the first layer, and it needs no state.

### D7. Trusted proxies: opt-in, explicit, read right to left, never rewriting the request

```go
httpsec.WithTrustedProxies(httpsec.TrustedProxies{
    Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
    Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto, httpsec.ForwardedHost),
    MaxHops:  1,
})
httpsec.WithAllowedHosts("app.example.com")
func ClientFromContext(ctx context.Context) Client // IP, Secure, Host, ViaProxy
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
 then: host on allowlist? (if ForwardedHost named) --no--> 400 ErrHostNotAllowed
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
- **No named presets** (loopback or private ranges) in this change. They are additive later if asked for.
- **Absorbs `trusted-proxy-client-ip`.** One trust setting answers the client, scheme and host questions. That change's proposal is marked superseded.
- **Alternatives rejected:**
  - *Reading both header families.* A client can inject the family the proxy does not overwrite.
  - *Trusting all fields once the proxy is trusted.* nginx passes client headers through unless each one is overwritten.

### D8. DPoP: accepted by default, required by option, bound at every issuing endpoint

```go
httpsec.EnableBearerToken(deps, httpsec.WithDPoP(httpsec.DPoP{
    Require:     false,             // default
    ProofMaxAge: 60 * time.Second,  // default
    Replay:      replayStore,       // default: in-memory, per process
    Algorithms:  []jwa.SignatureAlgorithm{jwa.ES256()}, // default
}))
httpsec.WithDPoPNonce()         // opt-in server nonces
httpsec.WithPublicURL("https://app.example.com") // optional; default from D2/D7
```

- **Verification:**
  - `typ`, an asymmetric `alg` from the set, and a public `jwk`;
  - the signature;
  - `htm`, and `htu` against the resolved public URL;
  - `iat` within the lifetime either side;
  - `jti` unseen;
  - `ath` when a token is presented;
  - `nonce` when enabled.
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
- **Refusals:**
  - a bound token as `Bearer`, as RFC 9449 §7.1 requires;
  - a proof from another key;
  - renewal without the bound key.
  - All answer 401 with `WWW-Authenticate: DPoP error=...`.
- **Replay store:** a `onetime.Store`-shaped port keyed by the `jti` digest. It shares the multi-replica caveat of the rate limiter and accepts a shared store. A store failure refuses (500).
- **Nonces:** off by default (open question). They cost a round trip, and the 60-second lifetime with `jti` already bounds replay.
- **Default:** accepted, not required, so existing bearer clients keep working while browser clients opt in by sending proofs.
- **Alternatives rejected:**
  - *Required by default.* That would break every non-DPoP client on upgrade.
  - *Binding only at login.* Renewal and re-proof would then issue unbound successors.

### D9. mTLS-bound tokens (RFC 8705)

- **Default:** off. **Override:** `WithCertificateBinding()` on bearer authentication.
- **Behaviour:** an issuing request with a client certificate binds `cnf.x5t#S256`. A bound token is accepted only with the same certificate, checked in the existing `OrderMTLS` slot.
- **Behind a TLS-terminating proxy:** the certificate comes from a header the consumer names in the trusted-proxy configuration. It is read only from a trusted peer, and parsed as URL-encoded PEM.
- **Open:** which header and encoding each common proxy uses must be verified before the spec for that part is final (open question).
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
    password.ContextWords(func(u *identity.Details) []string { ... }),
    password.Breached(password.PwnedPasswords(outbound), password.OnLookupFailure(password.Refuse)),
    password.NoReuse(history, 5),
    password.WithEncoder(enc),
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
  - maximum at least 64, never truncated;
  - a bundled common-password list of at least 3,000 entries (ASVS 6.2.4);
  - no composition rules (NIST: SHALL NOT);
  - rules run cheapest first.
- **Options replace only the rule they name.** `WithoutCommonPasswords()` removes that default explicitly, so setting one rule never silently drops a safe default.
- **Breach check:** opt-in. It uses the HIBP range API through the confined outbound client, with `Add-Padding: true`, and the lookup source is replaceable for an offline corpus.
  - `OnLookupFailure` is required: Spring's checker fails open, and the safe and convenient answers differ, so the consumer chooses.
- **Reuse** is the `NoReuse` rule, with every guarantee the reuse guard had.
  - `NewReuseGuard` is removed, which is BREAKING before the tag.
  - The `password-encoding` reuse requirements are REMOVED there and ADDED here.
  - **Sign-up:** `Check` treats a user with no stored hash as having nothing to reuse.
- **Where it runs.** scrty never holds a new plaintext password outside this policy: the change endpoint calls the consumer's `ChangePasswordFunc`, and the default identity store stores hashes. The consumer calls `policy.Change` from that function.
- **Alternatives rejected:** *keeping `ReuseGuard` beside a new policy.* That leaves two objects to configure, with reuse separate from every other rule.

### D11. Rehash on login

- **Encoder side:** an optional `password.Upgrader` interface (`NeedsUpgrade(encoded) bool`), type-asserted as `Recognizer` is. The built-ins implement it; a consumer encoder without it never upgrades.
- **Login side:** `httpsec.WithLoginRehash(func(ctx, user, newHash) error)` runs after a successful password login. It costs one extra key derivation on that request. Its error is logged and never fails the login.
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

- **`session.Store` gains `ListByUser`.** Every store implements it, and the security-state migration adds the listing index (`schema-migrations`).
- **Sign-in metadata** (client address, user agent) is off by default, because both are personal data. `WithSessionMetadata()` turns it on.
- **Endpoints:** `httpsec.EnableSessionManagement` registers `GET /sessions`, `DELETE /sessions/{handle}` and `DELETE /sessions`, all under a replaceable prefix and off by default.
  - Ending sessions requires a recent authentication, using `reauthentication`'s recency check (ASVS 7.5.2).

### D13. Security events

```go
type Event struct {
    Name     string // OWASP Logging Vocabulary, or scrty_*
    At       time.Time
    Outcome  string
    User     identity.UserID
    ClientIP string
    Factor   identity.FirstFactor
    Session  string // digest, never the identifier
}
httpsec.WithSecurityEvents(func(ctx context.Context, e security.Event))
```

- **Default:** no sink, no events.
- **Delivery:** synchronous, on a context without cancellation. The sink's errors are ignored, and it cannot change outcomes.
- **Observers:** the lockout and reuse observers keep working and are also delivered as events.
- **Alternatives rejected:**
  - *An asynchronous queue in the library.* It would bound memory and lose events, which is the consumer's trade-off to make.
  - *Logs only.* That is what A09 flags.

### D14. Security notices

- **Passkey removal** notifies by default, with `WithoutPasskeyRemovalNotification()` to turn it off. NIST 800-63B-4 §4.5 SHOULD.
- **MFA:** there is no user-facing MFA removal endpoint today, and operator resets already notify.
- **An unseen-device sign-in notice** is opt-in. It requires session metadata and a sender, and matches against the user's sessions of the last 90 days.

### D15. Automation challenge

- **The port:** `ChallengeVerifier.Verify(ctx, req, signals) (Decision, error)`, where `signals` reports recent limiter failures for the source and identifier.
- **Flows:** with a verifier given, it runs before login, Basic, magic-link request, passwordless begin and recovery start, all selected by default. `WithChallengeFlows` narrows them.
- **Refusals** count against the source limit by default.
- **No vendor is bundled.**

### D16. Supply chain

- SHA-pinned actions with the tag in a comment, enforced by a CI check.
- Dependabot for `gomod`, in every published module, and for `github-actions`.
- An SBOM per published module, produced in the release gate. The generator is a `tool` directive in the `tools` module, chosen in the tasks.
- `govulncheck` blocks a release.
- **Coordinates with `release-readiness`**, which owns the release gate and `SECURITY.md`.

### D17. Clear-Site-Data on logout

- **Default:** not sent.
- **Override:** `WithLogoutClearSiteData(directives...)`, sent only when `Secure()`.
- **Why not by default:** `"cookies"` clears the whole registrable domain, sibling subdomains included. The W3C document is a 2017 Working Draft with uneven support.

### D18. Refusals and statuses

| Refusal | Status |
|---|---|
| `ErrCrossSiteRequest` | 403 |
| `ErrHostNotAllowed` | 400 |
| `ErrInvalidDPoPProof` (and the nonce variant), `ErrCertificateBinding` | 401 |
| `ErrChallengeRequired` | 403 |
| `password.ErrPasswordRejected` | 422; `ErrPasswordReused` stays 422 and is also `ErrPasswordRejected` |
| a session handle not found | 404 |
| replay-store, history and breach-lookup failures | 500 (dependency failures) |

## Risks / Trade-offs

- [This is the largest change so far: thirteen gaps across `httpsec`, `password`, `session`, `token`, the stores and CI] → The tasks split into lanes by file ownership. The breaking APIs (D2, D10, D12) come first, so later lanes build on settled interfaces.
- [A strict CSP breaks inline scripts the moment a consumer enables it] → Report-only mode and the hash preset. The README walks through a report-only rollout.
- [A misconfigured proxy list makes rate limits key on the proxy again, or trusts too much] → Construction refuses an empty list and catch-all prefixes. The README has nginx and Traefik examples. Traefik's handling of client-supplied `X-Forwarded-Proto`/`-Host` is unverified, so the docs advise testing before trusting the host field.
- [The DPoP replay store is per process by default, so across replicas a proof could be replayed within its 60 seconds] → The same documented limit as the in-memory rate limiter, with the same remedy: a shared store.
- [Building DPoP and mTLS doubles the bearer interceptor's paths] → Both share one binding abstraction on the session and token, and conformance runs each on all three adapters.
- [The bundled common-password list adds size to the core module] → A few tens of kilobytes, compressed in the binary. The list is replaceable.
- [Draft drift: `reauthentication` may land differently] → D1's review pass before implementation.

## Migration Plan

- **Implement only after** `reauthentication` (and `key-port-context`) merge and this draft is reviewed (D1). Branch from `main`.
- **Breaking before the tag:**
  - `Request.Host()`/`Secure()` (D2);
  - `ginsec.WithForwardedClientIP` removed (D7);
  - `NewReuseGuard` removed (D10);
  - `session.Store.ListByUser` (D12).
- **Schema:** one new security-state migration (D12). It is nullable, so it applies to populated databases and rolls back fully.
- **Other changes:**
  - `trusted-proxy-client-ip` is marked superseded;
  - `bff-resource-server` drops `csrf-protection` from its capabilities;
  - `release-readiness` lists this change as landing before it, and folds it into the first changelog entry.
- **Rollback:** a revert, plus rolling back the one migration.

## Open Questions

- The CSRF token style: a synchronizer token stored on the session, or a double-submit cookie signed with a server key. Either satisfies the spec; it matters once cookie sessions exist.
- The forwarded client-certificate header and encoding per proxy (nginx `$ssl_client_escaped_cert`, Traefik's TLS client-certificate middleware, API gateways). Verify against each proxy's documentation before finalising D9.
- Whether header profiles also accept `authorize.Rule` matchers (D4).
- Whether DPoP server nonces stay off by default (D8).

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

**D7: trusted proxies**
- [ASP.NET Core: proxy servers and load balancers](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer): `ForwardedHeaders.None`, loopback `KnownProxies`, `ForwardLimit` 1, `AllowedHosts`, `X-Original-*`.
- [Spring Framework: Forwarded Headers](https://docs.spring.io/spring-framework/reference/web/webmvc/filters.html): wrapping, header removal, `removeOnly`, the edge resetting both families.
- [Express: behind proxies](https://expressjs.com/en/guide/behind-proxies.html), [Django settings](https://docs.djangoproject.com/en/stable/ref/settings/), [MDN X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For): accessors, per-field opt-in, right-to-left selection, `ALLOWED_HOSTS`.
- [nginx proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html), [Traefik entrypoints](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/), [Fiber v3 config](https://docs.gofiber.io/api/fiber): what each sends and trusts.
- [gorilla ProxyHeaders](https://pkg.go.dev/github.com/gorilla/handlers#ProxyHeaders) and [chi RealIP](https://pkg.go.dev/github.com/go-chi/chi/v5/middleware#RealIP): rewriting without trust checks; chi deprecated `RealIP`.

**D8, D9: sender-constrained tokens** (accessed 2026-11-01)
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html): proof fields and checks, `cnf.jkt`, refusing bound tokens as bearer, `DPoP-Nonce`, CORS exposure.
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
- [OWASP Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html): event names.
- [NIST SP 800-63B-4: events](https://pages.nist.gov/800-63-4/sp800-63b/events/): §4.1.2.1 and §4.5 notifications.
- [Ory Kratos API](https://github.com/ory/kratos/blob/master/spec/api.json): session listing and revocation endpoints.

**D15: automation challenge**
- [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): challenge only suspicious traffic.

**D1, D2, D3, D16, D17, D18**
- Reasoned from scrty's own settled specs (`http-security-chain`, `framework-adapters`, `http-error-propagation`, `sessions`), the in-progress `reauthentication`, `key-port-context` and `release-readiness` designs, and the established design.

### Primary documentation

- [RFC 6797 (HSTS)](https://www.rfc-editor.org/rfc/rfc6797), [W3C CSP Level 3](https://www.w3.org/TR/CSP3/), [W3C Clear Site Data](https://www.w3.org/TR/clear-site-data/), [WHATWG Fetch](https://fetch.spec.whatwg.org/), [RFC 7239 (Forwarded)](https://www.rfc-editor.org/rfc/rfc7239.html), [RFC 8705 (OAuth mTLS)](https://www.rfc-editor.org/rfc/rfc8705), [RFC 7638 (JWK thumbprint)](https://www.rfc-editor.org/rfc/rfc7638).
