## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** When this change is applied, the core module already holds:
  - `pkg/id` and `pkg/logsample` (project-foundation);
  - `identity`, `password`, `token` and `signingkey` (identity-and-tokens);
  - `authn`, `authz`, `session`, `policy`, `factor`, `ratelimit` and `onetime` (authn-authz-core);
  - the durable stores and the `test` module (durable-persistence).

  There is no HTTP code, and no consumers or tags.
- **Product decisions already made:**
  - `httpsec` is a framework-agnostic core built as an around-interceptor chain with ordered slots;
  - errors propagate, rendering belongs to the consumer, and the sentinels, the challenge error type and a status-only mapping are public;
  - refusal logs are sampled with `pkg/logsample`, and scrty's own callers always configure a reporter;
  - options are named after what they govern;
  - gin and fiber integrations are nested modules;
  - constructors with functional options are the primary API, and DI wiring is optional;
  - `github.com/lestrrat-go/jwx/v4` is the only JOSE stack.
- **Capabilities this change uses, without restating them:**
  - `authentication` decides credentials and bounds its own refusal logs;
  - `authorization` owns the rule set, matchers, requirements and the no-match deny;
  - `sessions` owns handles, expiry, the first factor and challenge attributes;
  - `security-policy` owns phases, decisions, built-in policies and its own log sampling;
  - `rate-limiting` owns the limiter, canonical source keys (including IPv6 prefix grouping) and the source guard;
  - `token-issuance` verifies bearer tokens;
  - `signing-keys` produces the public key set, as a jwx v4 set;
  - `log-sampling` owns the sampler;
  - `module-layout` owns the nested-module and test-module rules.
- **Project rules:** library-design, golang-tdd, table-test, use-mockgen and use-testcontainers.
- **Framework versions:** gin v1 (latest at implementation) and fiber v3.5.0. The fiber accessor names below are re-checked against the pinned tag before the adapter is written.

## Goals / Non-Goals

**Goals:**
- One chain, written once, whose outcome does not depend on the framework in front of it.
- A consumer who wires nothing beyond their authentication method gets fail-closed behaviour: bare statuses, no leaked text, no client address taken from an untrusted header.
- Every option either takes effect or is refused before traffic.
- Seams stable enough that auth-methods and oidc-brokering add their interceptors without changing the core.

**Non-Goals:**
- **Redemption interceptors.** Magic-link request and redemption, API-key verification, the second-factor challenge interceptor (its verify endpoint and its pending gate), client certificates and the OIDC authorize, callback, handoff and federated-logout pieces belong to `auth-methods` and `oidc-brokering`. This change defines their slots and seams only.
- **Rendering.** No problem-details or other body renderer.
- **Other protections.** CSRF protection, CORS, security headers and backend-for-frontend cookies.
- **Other frameworks.** Adapters beyond net/http, gin and fiber. chi and other stdlib routers use the net/http adapter.
- **SSRF address filtering.** Filtering outbound targets by resolved IP. See Risks.

## Decisions

### 1. The core runs on a framework-neutral exchange

Interceptors never see a framework type. They read and write through a small request/response abstraction, and each adapter implements it natively:
- **net/http:** the default adapter, over `*http.Request` and `http.ResponseWriter`. chi and other stdlib routers use it.
- **gin:** reuses the net/http implementation, because gin's context carries both types.
- **fiber:** implements the abstraction directly over `fiber.Ctx`, so no net/http request is ever built on a secured fiber request.

```go
type Request interface {
    Method() string
    Path() string
    Header(name string) string
    Query(name string) string
    Cookie(name string) (value string, ok bool)
    FormValue(name string) string
    Body(limit int64) ([]byte, error) // buffered once; over limit returns ErrRequestTooLarge
    ClientIP() string                 // "" when the adapter cannot tell
}
type ResponseWriter interface {
    SetHeader(name, value string)
    SetCookie(c *Cookie)
    WriteHeader(status int)
    Write(b []byte) (int, error)
}
type Exchange struct {
    Request        Request
    Writer         ResponseWriter
    Authentication *authn.Authentication
    Session        *session.Session
    // unexported: accumulated context
}
func NewExchange(ctx context.Context, r Request, w ResponseWriter) *Exchange
func (e *Exchange) Context() context.Context
func (e *Exchange) SetContext(ctx context.Context)

type Next func(*Exchange) error
type Interceptor interface{ Intercept(ex *Exchange, next Next) error }
type InterceptorFunc func(ex *Exchange, next Next) error
func NewHTTPRequest(r *http.Request) Request            // net/http implementation, reused by ginsec
func NewHTTPResponseWriter(w http.ResponseWriter) ResponseWriter
```

- **Continuation:** an interceptor continues by calling `next` and stops by not calling it. The innermost `next` runs the downstream handler, so post-handler logic is plain code after `next` returns.
- **Context:** carried on the `Exchange`, because fasthttp's request has no context field. It is seeded from the adapter's incoming native context, and synced back into the native carrier immediately before the handler.
- **Default:** the three shipped adapters.
- **Override:** the abstraction is a public adapter contract. A consumer supports another framework by implementing `Request`/`ResponseWriter` and running `Chain.Assemble`, without changing the core or any interceptor.
- **Body buffering:** the net/http `Body` buffers the body once, then restores it so the downstream handler can still read it.
- **Stated fiber limits:**
  - fiber's string and body accessors are zero-copy and valid only for the request, so an interceptor must copy anything it keeps beyond it;
  - fiber cannot tell an empty cookie from an absent one.

### 2. Slots and registration

```go
type Order int
const (
    OrderJWKS           Order = 100
    OrderOIDC           Order = 200 // oidc-brokering: authorize, callback, handoff
    OrderFormLogin      Order = 300
    OrderMagicLink      Order = 350 // auth-methods: request and redemption
    OrderBasicAuth      Order = 400
    OrderAPIKey         Order = 450 // auth-methods
    OrderMTLS           Order = 475 // reserved
    OrderBearerToken    Order = 500
    OrderMFAChallenge   Order = 600 // auth-methods: verify endpoint and pending gate
    OrderPasswordChange Order = 650
    OrderLogout         Order = 700
    OrderSessionTouch   Order = 800
    OrderAuthorizer     Order = 900
)
func Before(o Order) Order // o - 1
func After(o Order) Order  // o + 1

func RegisterInterceptor(i Interceptor, at Order) Option
```

- **Assembly:** a stable sort by order, then a fold around the terminal. It is built once at construction.
- **Default:** built-ins at their named slots; session touch and the authorizer are always registered.
- **Override:** `RegisterInterceptor` at any slot. To replace a built-in, do not enable it and register your own at its slot.

### 3. Constructors with explicit dependencies

```go
func New(opts ...Option) (*Chain, error)
func (c *Chain) Middleware() func(http.Handler) http.Handler
func (c *Chain) Assemble(terminal Next) Next // used by adapters
func (c *Chain) FlushRefusalLogs()

func EnableFormLogin(d FormLoginDeps, opts ...LoginOption) Option
func EnableBasicAuth(d BasicAuthDeps, opts ...BasicAuthOption) Option
func EnableBearerToken(d BearerTokenDeps, opts ...BearerTokenOption) Option
func EnableLogout(d LogoutDeps, opts ...LogoutOption) Option
func EnableJWKSEndpoint(keys KeySetProvider, opts ...JWKSOption) Option
func EnablePasswordChangeGate(sessions *session.Manager, opts ...PasswordChangeOption) Option
func EnableAuthorization(az authz.Authorizer, rules ...authz.Rule) Option
func WithPolicyEngine(e *policy.Engine) Option // default: none, so every phase allows
func WithLogger(l *slog.Logger) Option        // default: slog.Default()
```

- **`*Deps` structs:** each holds the collaborators its interceptor needs. For form login these are the authentication manager, session manager, token issuer and attempt store.
- **The `do` module:** only calls these constructors.
- **Departure (a):** collaborators are passed to constructors, not resolved from a DI container at chain assembly. The settled decisions say constructors first and no DI dependency in the core. The diagnostics stay precise:
  - "not provided" and "provided but nil" are reported separately;
  - each error names the `Enable*` option and the dependency.

### 4. Construction refuses what cannot take effect

`New` applies every option, then validates. Refused:
- a missing dependency for an enabled interceptor, or one holding a typed nil (checked by reflection, so `(*T)(nil)` inside an interface is not taken as present);
- a nil limiter;
- an IPv6 source prefix outside 1..128 (`WithIPv6SourcePrefix`, default 64, passed through to `rate-limiting`'s key function);
- a nil refusal log reporter;
- a login body limit of zero or less;
- a nil interceptor;
- the allowlist and origin errors of Decision 15, raised by the options of other changes that use it.

The principle, adopted as scrty's own: **a public option either takes effect or is refused at construction**, never documented or logged away.

- **Departure (b), nil interceptor:** `RegisterInterceptor(nil, …)` is refused. Without the check, a nil interceptor panics on every request. On fiber an unrecovered handler panic takes the process down, a failure mode the typed-nil dependency checks already exist to prevent.

### 5. Errors propagate, and one table maps them

```go
var (
    ErrAuthenticationRequired = errors.New("httpsec: authentication required")
    ErrCredentialsMissing     = errors.New("httpsec: missing or unreadable login credentials")
    ErrRequestTooLarge        = errors.New("httpsec: request too large")
)
type ChallengeError struct {
    Kind    policy.ChallengeKind
    Session *session.Session // nil for a stateless first factor
    Token   string           // set when issued at login
}
func (e *ChallengeError) Error() string // names Kind only
func StatusForError(err error) int
```

- **How the table works:** `StatusForError` checks `*ChallengeError` first, with `errors.As`. It then walks one ordered table of sentinel rows with `errors.Is`. The statuses are those in the `http-error-propagation` spec. The table includes the `authn`, `authz`, `policy` and second-factor sentinels.
- **Default:** every library default response and helper uses the table.
- **Override:** the consumer's error handler (net/http), their gin error middleware, or their fiber error handler, each calling `StatusForError` for what they do not handle themselves.
- **Departure (a):** no problem-details mappers ship. The status-only function is the whole mapping contract, by settled decision.
- **No `ErrRefusedByPolicy`.** A reasonless deny arrives as `policy.ErrPolicyDenied`, which the engine substitutes, and the table maps that. See Decision 6.
- **Departure (b):** `ErrCredentialsMissing` maps to 400. Unmapped, a login with no credentials or an undecodable JSON body answered 500, reporting a client mistake as a server fault. It still reveals nothing about the account.

### 6. A policy deny without a reason is always a refusal

`policy.Engine.EvaluatePhase` already guarantees it: a `Deny` whose `Reason` is nil has
`policy.ErrPolicyDenied` substituted before the decision is returned (`policy/engine.go:128-133`),
and an outcome the engine cannot interpret denies with the same error. The chain always evaluates
through an `Engine` (Decision 3), so a reasonless deny cannot reach a deny site.

`policyDenyReason(d)` is therefore `d.Reason` — a named reader, not a fallback — and every deny
site uses it: pre- and post-authentication in form login, the stateless phase in Basic
authentication, the per-request phase in bearer authentication, and the login completion seam.

- **Mapping:** `StatusForError` maps `policy.ErrPolicyDenied` to 403.
- **Departure retired.** An earlier draft of this design added an `httpsec.ErrRefusedByPolicy`
  sentinel and a nil-reason fallback, on the grounds that a reasonless deny returned nil and so
  served a refusal as a 200 with an empty body. `policy` has since closed that at the engine, so the
  fallback is unreachable and the second sentinel would be a name nothing produces. One refusal has
  one identity: a consumer matching `policy.ErrPolicyDenied` reaches every reasonless deny, and
  there is no second name for them to miss.
- **Where two names already exist**, the chain wraps rather than picks. `authorize` exports its own
  `ErrAuthenticationRequired` for an anonymous request that matched a protected rule; the
  authorization stage wraps it with `httpsec.ErrAuthenticationRequired`, so `errors.Is` reaches
  either and a consumer need not know which stage refused.
- **Override:** a consumer policy that wants a specific status sets a reason.

### 7. The net/http default response is a bare status

```go
func WithErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) Option // default: bare status
func NewGuards(az authz.Authorizer, opts ...GuardOption) *Guards
func WithGuardErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) GuardOption
```

- **Default:** `w.WriteHeader(StatusForError(err))`, with no body.
- **Override:** `WithErrorHandler`, and `WithGuardErrorHandler` for guards. A consumer passes the same function to both.
- **Departure (b):** the net/http guards' default handler now derives its status from `StatusForError`, instead of its own switch. A separate switch disagrees with the table on invalid authorization attributes (400 against 500), contradicting the rule that every default status comes from the one mapping. The table's 500 stands: invalid attributes come from a misbuilt guard, not the client.

### 8. Form login, Basic and bearer authentication

- **Form login:**
  - **Match:** `POST /login`; override with `WithLoginRequestPath`. Fields `username` and `password`; override with `WithLoginParams`.
  - **Binding:** form fields first, then a JSON object when both are empty and `Content-Type` declares JSON.
  - **Sequence:** pre-authentication phase, authenticate (recording or resetting attempts, with store failures logged, not returned), post-authentication phase, then the login completion (Decision 11).
  - **Success body:** `{"access_token", "refresh_token": "", "valid_until": <session idle expiry>}`, with `Content-Type: application/json`.
  - **Override:** `WithLoginResponder(func(ex *Exchange, res LoginResult) error)` replaces the body writer.
    - **Departure (a):** the success body is replaceable rather than fixed, because every default must be replaceable.
- **Login body limit:**
  - **Default:** `WithLoginBodyLimit` 64 KiB, passed to `Request.Body(limit)` and applied by each adapter before the form or JSON is parsed (`http.MaxBytesReader` on net/http, a length check on fiber's already-buffered body). Over the limit returns `ErrRequestTooLarge`.
  - **Departure (b):** the JSON body was read without bound on an unauthenticated endpoint, the same memory-exhaustion pitfall that is explicitly bounded for provider responses.
- **Basic authentication:**
  - the `Basic ` prefix is matched exactly;
  - the realm defaults to `Restricted`; override with `WithBasicAuthRealm`;
  - the `StatelessAuthentication` phase runs after success, and there is never a session.
- **Bearer tokens:**
  - **Scheme:** default `Bearer`, case-insensitive; override with `WithBearerScheme`. `WithBearerAllowEmptyScheme` also accepts a bare token.
  - **Verification:** through `token-issuance`'s verifier (jwx v4). A failure returns `errors.Join(authn.ErrAuthenticationFailed, cause)` and logs the cause at DEBUG.
  - **Session and user:**
    - a missing or expired session returns `ErrAuthenticationRequired`;
    - an undecryptable session returns `ErrAuthenticationRequired` and is logged at ERROR, so a retired sealing key forces re-login instead of a 500 storm;
    - the user is reloaded by subject, so roles are live.
  - **Per-request phase:** a deny refuses (Decision 6). A challenge marks the challenge pending on the session and continues, so a mid-session challenge is enforced by its gate while that gate's resolve endpoint stays reachable.
  - **No `WWW-Authenticate` header**, because response headers for bearer APIs belong to the consumer's error handler.

### 9. Password-change gate, logout, session touch, key set

- **Password-change gate** (`OrderPasswordChange`):
  - **Refusal:** blocks a session carrying the pending password-change marker with `*ChallengeError{Kind: ChallengePasswordChange, Session}`.
  - **Override:** `WithChangePasswordEndpoint(path string, fn ChangePasswordFunc)` lets `POST path` through. It requires a session, runs the consumer's function, then clears and saves the marker, and the function owns the response.
  - **Default:** a pure gate, which only a new login clears.
  - **Second factor:** the pending gate lives in `auth-methods`' challenge interceptor at `OrderMFAChallenge`.
- **Logout:**
  - **Match:** `POST /logout`; override with `WithLogoutRequestPath`.
  - **Behaviour:** requires an authentication result, deletes the session when there is one (an already-gone session is not an error), answers 200 with an empty body, and never calls the handler.
  - **Federated logout:** `oidc-logout` extends this interceptor with an end-session step after the local delete, through an optional end-session builder dependency on `LogoutDeps`.
- **Session touch:**
  - runs `next` first, then calls `Touch` for any session on the exchange, including when `next` returned an error;
  - its own error is ignored, and the handler's result is returned unchanged.
- **Key set:**
  - **Match:** `GET /.well-known/jwks.json`; override with `WithJWKSEndpointPath`.
  - **Behaviour:** `KeySetProvider` returns `signing-keys`' public jwx v4 set, marshalled as JSON with `Content-Type: application/json`, status 200.
  - **Errors:** propagate.

### 10. Authorization: rules in the chain, guards per endpoint

- **Always:** the authorizer stage at `OrderAuthorizer` adds the authorizer to the context.
- **With rules** (`EnableAuthorization(az, rules...)`, which appends across calls): first match wins, and a request with no match is denied, per `authorization`.
- **With no rules:** nothing is enforced centrally, and guards decide.
- **Guards:**
  - `httpsec.NewGuards`, `ginsec.NewGuards` and `fibersec.NewGuards` share one fluent shape: `RequireAuthenticated()`, `ResourcePrivileges(group, resource).RequireOne/RequireAll/RequireAny(...)`, and `ResourceOwnerships[ID](guards, group, resource, checker).ForResource(extract)`.
  - They read the authorizer from the context and fall back to the one given at construction.
  - Every failure skips the route.
- **Default:** both models are available, and guards add to rules.
- **Override:** the rule set, custom `authz` requirements and matchers, and the guard error handling of Decisions 7 and 13.

### 11. Seams for redemption flows

The seams are package-level helpers inside `httpsec`. The redemption interceptors that `auth-methods` and `oidc-brokering` add are written in `httpsec` too, next to form login, and enabled by their own `Enable*` options.

```go
// unexported, inside httpsec
func postAuthenticationInput(p *identity.Principal, first factor.Kind, username string, passwordChangedAt, now time.Time) *policy.Input
func completeLogin(ex *Exchange, deps loginTailDeps, in *policy.Input) (token string, err error)
func sourceThrottled(ctx context.Context, l ratelimit.Limiter, clientIP string, flow string, s *logsample.Sampler, now time.Time) (key string, throttled bool)
func recordSourceFailure(ctx context.Context, l ratelimit.Limiter, key, flow string)
```

- **Login input:** its fields are parameters, so an interceptor cannot silently omit the password change time and disable a password-age gate on its path only. `first` is a distinct type, so it cannot be transposed with `username`. The two `time.Time` parameters are adjacent, so each call site is tested for a firing challenge, which pins argument order.
- **`completeLogin` order:**
  1. post-authentication phase, with deny through `policyDenyReason`;
  2. create the session with its first factor;
  3. if challenged, mark and save before issuing the token, so no token exists for a session whose pending flag failed to persist;
  4. issue the token;
  5. publish the authentication onto the exchange and context, so a consumer handling the challenge still sees the principal;
  6. return `*ChallengeError{Kind, Session, Token}` when challenged.
- **Source throttle:** `sourceThrottled` and `recordSourceFailure` wrap `rate-limiting`'s source guard with the request's client address, the chain's sampler and its logger. `recordSourceFailure` runs on `context.WithoutCancel`.
- **Check-then-consume:** redemption interceptors check the source before lookups, and consume their credential only after their own refusal checks. The ordering and the refused-redemption counting belong to `auth-methods` and `oidc-brokering`.
- **Override:** none. These are internal composition points; a consumer's own first factor is a registered interceptor (Decision 2).

### 12. Client address and throttle refusals

- **net/http:** `r.RemoteAddr`'s host, or no address when it is not `host:port`.
  - **Override:** none, because net/http has no trusted proxy configuration to take a forwarded address from. A consumer behind a proxy that needs one uses gin or fiber trust, or their own middleware that rewrites `RemoteAddr` from a header their proxy overwrites.
- **gin:**
  - **Default:** the peer.
  - **Override:** `ginsec.WithForwardedClientIP()` uses `c.ClientIP()`. Its godoc states it is safe only after `engine.SetTrustedProxies`.
  - **Departure (b):** the opt-in lives in `ginsec`, not the core. As a core option it would silently do nothing on net/http and fiber, which violates the principle in Decision 4.
- **fiber:** `c.IP()`, which is the peer unless the consumer enables `TrustProxy`. The godoc gives the safe configuration:
  - `TrustProxy`;
  - an explicit `TrustProxyConfig.Proxies` list, with `UnixSocket` when the proxy uses one, and `"0.0.0.0"` in the list for a socket-only proxy;
  - `ProxyHeader`;
  - `EnableIPValidation`.

  It also records the pitfalls:
  - `UnixSocket` alone selects the leftmost, client-written address;
  - `Loopback`, `Private` and `LinkLocal` skip real clients.
- **Refusals** (the `Check` step): an empty, non-single-IP or unspecified address, or a limiter error, refuses with `authn.ErrAuthenticationFailed`.
  - **Why an unspecified address is refused:** fasthttp reports `0.0.0.0` for every non-TCP peer, so keying on it pools those clients into one bucket.
  - **Logging:** ERROR, sampled (Decision 14). A request whose context ended before the limiter answered is logged at DEBUG and not sampled.

### 13. Framework adapters

| | Context seed | Before the handler | Refusal | Answered by the chain |
|---|---|---|---|---|
| net/http | `r.Context()` | `next.ServeHTTP(w, r.WithContext(ex.Context()))` | error handler (Decision 7) | handler never called |
| gin | `c.Request.Context()` | `c.Request = c.Request.WithContext(...)`, then `c.Next()` | `c.Error(err)`; `c.Status(StatusForError(err))` if not written; `c.Abort()` | bare `c.Abort()` |
| fiber | `c.Context()` | `c.SetContext(...)`, then `c.Next()` | return a `*fibersec.RefusalError` | handler never called |

- **gin chain refusals:** `c.Status` is lazy and `c.Abort` does not commit it, so a consumer's error middleware can still set its headers and body. `AbortWithStatus` would commit the header block and is never used.
- **gin self-answered requests:** the bare abort stops gin's handler loop from running a matched route or a consumer `NoRoute` that would overwrite a lazily-set status. Documented: middleware registered after the chain does not run for refused or self-answered requests, so register logging and metrics before it.
- **gin guards:** `c.Error(err)`, then `c.Status(StatusForError(err))` if not written, then `c.Abort()`.
  - **Departure (a)+(b):** guards also set the status, instead of only registering the error and aborting. With no error middleware, register-and-abort answers 200 with an empty body. The settled decision requires a fail-closed status on gin's channel.
- **fiber refusals:** `RefusalError` wraps the original refusal and a `*fiber.Error{Code: status}` through `Unwrap() []error`, and its `Error()` returns `http.StatusText(status)`.
  - **`fibersec.MapError(err) (int, any)`:** returns the status and `fiber.Map{"error": http.StatusText(status)}`.
  - **`fibersec.ErrorHandler`:** answers the bare status with an empty body.
  - **Default:** whatever `fiber.Config.ErrorHandler` the consumer set, which sees the `RefusalError`. `errors.As` still reaches `*httpsec.ChallengeError`.
  - **Departure (b)+(a):** the chain wraps the error rather than returning it raw. fiber's built-in `DefaultErrorHandler` writes `err.Error()` into the body, so a raw error leaks internal detail such as driver error text to a consumer who never set a handler, even though the mapping helper withholds it.
  - **Stated limit:** with fiber's built-in handler the body is the status text, not empty, because fiber owns that handler. `fibersec.ErrorHandler` gives the bare default in one line.
- **fiber façade:** `fibersec` implements `Request` and `ResponseWriter` directly over `fiber.Ctx` (`Method`, `Path`, `Get`, `Query`, `Cookies`, `FormValue`, `Body`, `IP`; `Set`, `Cookie`, `Status`, `Write`), with no conversion to net/http types.
- **Conformance:** `test/httpsecconformance` holds one scenario table. The net/http (`httptest`), gin (test engine) and fiber (`app.Test`) suites each run it from their own `_test.go` files. fiber runs set `TrustProxy` with `Proxies: {"0.0.0.0"}` and a forwarded header where a throttled flow needs an address.

### 14. Refusal logs: sampled, always reported, named for what they govern

```go
func WithRefusalLogInterval(d time.Duration) Option // default time.Minute; <= 0 disables sampling
func WithRefusalLogReporter(fn func(key string, suppressed int)) Option // default: summary WARN; nil refused
func (c *Chain) FlushRefusalLogs()
```

- **Sampler:** one per chain, shared by every flow using the throttle seam. Every key starts with the flow's name, so a burst against one flow never suppresses another's record.
- **Keys:**
  - `flow|source` for the throttled WARN;
  - `flow` for the limiter-failure ERROR;
  - `flow|no-client-address`, `flow|not-single-ip` and `flow|unspecified-address` for the unattributable ERRORs.
- **Suppressed count:** attached only when non-zero.
- **Default reporter:** writes `httpsec: refusal logs suppressed` at WARN with `key` and `suppressed`.
- **Override:** interval, reporter and `FlushRefusalLogs` (for example from a shutdown hook), which together give exact counts.
- **Departure (a), always a reporter:** the sampler always has a reporter. Without one, counts for keys that go quiet are dropped. The settled decision requires a reporter that emits a summary.
- **Departure (a), split interval:** `WithRefusalLogInterval` governs only the chain's own records, and does not also set the MFA-requirement policy's log interval. The chain now takes the consumer's `policy.Engine` as given, and the policy's interval is configured on the policy (`security-policy`). One option governing two subsystems violates the settled naming rule.

### 15. Outbound confinement

```go
package outbound
func New(opts ...Option) (*Client, error)
func (c *Client) Get(ctx context.Context, url string, h http.Header) (*Response, error)
func (c *Client) PostForm(ctx context.Context, url string, form url.Values) (*Response, error)
type Response struct{ Status int; Header http.Header; Body []byte } // Body read to the limit

func WithHTTPClient(hc *http.Client) Option  // default: a dedicated client, never http.DefaultClient; copied, not mutated
func WithAllowedSchemes(s ...string) Option  // default "https"; only "http" may be added
func WithAllowedOrigins(o ...string) Option  // default: none, the caller's configured target
func WithMaxRedirects(n int) Option          // default 10; 0 = none; < 0 refused
func WithTimeout(d time.Duration) Option     // default 10s; <= 0 refused
func WithMaxResponseBytes(n int64) Option    // default 1 MiB; <= 0 refused
```

- **Redirect handling:** the client installs `CheckRedirect` on its copy of the consumer's client.
  1. It enforces the hop cap first, because installing any `CheckRedirect` discards net/http's own cap, and a same-origin loop would otherwise run until timeout.
  2. It checks the scheme and same origin against `via[0]`.
  3. It then calls the consumer's own `CheckRedirect`.
- **Final URL:** `res.Request.URL` is re-checked before the body is read.
- **Body:** read through `io.LimitReader`.
- **Deadline:** `WithTimeout` sets a context deadline around the whole call, whatever timeout the supplied client has. An earlier caller deadline wins.
- **Departure (a):** configurable schemes, allowed origins, cap, timeout and size. They are configurable rather than fixed constants, because the settled decision lists them as confinement controls and every default must be replaceable. The defaults keep the fixed values: https only, 10 hops, 10 s, 1 MiB.
- **Departure (b):** only `*http.Client` is accepted, not any `Do` implementation. With an opaque `Do`, a `307` or `308` from a token endpoint replays the body, with the client secret, code and verifier, to the redirect target before any check can run. The final-URL check cannot unsend it. Accepting any `Do` and relying on that check is a pitfall admitted in the very documentation that accepts it. A `*http.Client` still gives full control of `Transport`: tracing, proxies, mTLS and test roots.
  - **Stated limit:** a consumer `Transport` that follows redirects itself bypasses the pre-send check.
- **Origin comparison** (`internal/origin.Same`):
  - ASCII case folding and default-port removal only;
  - no IDNA and no Unicode folding;
  - ports compared as written;
  - a trailing dot is significant;
  - userinfo is ignored;
  - anything unparsable matches nothing.

  Every relaxation makes more strings equal, which helps a discovery check and weakens a redirect allowlist, so a relaxation must be argued for each caller separately. The godoc carries that warning.
- **Redirect-target allowlist** (`internal/origin.Allowlist`):
  - validates entries and declared origins at construction with messages naming the entry and option;
  - an entry is host-relative, or absolute with a declared origin and no userinfo;
  - a declared origin is `https`, or `http` on loopback, with no path, query, fragment or userinfo;
  - `Resolve` does exact matching, re-checks the matched entry, and falls back to `/`.

  `auth-methods` and `oidc-brokering` expose it through their own options.
- **Placement:** `outbound` is public because consumers configure it. The origin helpers are internal because consumers only supply strings.
- **Recommended move:** the only callers are provider discovery, key set fetch and the token exchange, all in `oidc-brokering`.

### 16. Test-first throughout

- **Chain:**
  - ordering and short-circuit tables;
  - one row per construction refusal, each seen failing first;
  - a context-propagation case with cancellation;
  - a reasonless-deny row per deny site, asserting 403, not 200.
- **Error mapping:**
  - a characterization table over every sentinel, wrapped and joined forms, and challenge precedence;
  - a test that enumerates the exported refusal sentinels of the mapped packages and fails on an unmapped one.
- **Adapters:**
  - the conformance table on all three frameworks;
  - gin: lazy status survives a later route and a `NoRoute`, the guard answers 403 without error middleware, and consumer middleware headers survive;
  - fiber: the built-in handler withholds error text, `RefusalError` keeps identity, and an unspecified `app.Test` peer is refused.
- **Throttle and logs:**
  - peer, forwarded (gin, fiber) and every unattributable form;
  - `testing/synctest` windows with a captured `slog` handler;
  - the default summary record, a consumer reporter plus flush, and interval zero.
- **Outbound** (`httptest.NewTLSServer`):
  - off-origin, downgrade and same-origin redirects;
  - a loop server that stops after 50 hops, so a missing cap fails rather than hangs;
  - a 307 token redirect whose evil server counts received secrets (must be zero);
  - oversized, slow and hanging servers, and a consumer client with no timeout.
- **Origin comparison:** an accept and reject table with the U+0130 and U+212A look-alikes. Allowlist rows for each refusal message.
- **Mocks:** `mockgen` for the limiter and stores where no in-memory default serves.

## Decisions taken during implementation

Recorded here because each changes what a consumer sees, and none was in the design as first
written. The names in the Go snippets above predate the code: read `authn` as `authenticate` and
`authz` as `authorize` throughout.

### 17. Corrections to the API this design sketched

- `authorize.Rule`/`Rules` are generic, so `EnableAuthorization(az authorize.Authorizer, rules ...authorize.Rule[Request])` instantiates the rule set over the chain's own `Request`. Rules append across calls; the **authorizer is last-call-wins**, because a chain judges by one authorizer.
- `session` exports no context helper, so `httpsec` owns the session context key.
- `internal/nilcheck.IsNil` is reused for every typed-nil check rather than a second reflection helper, and `signingkey.KeyManager.JWKS()` already returns marshalled bytes, so `KeySetProvider` is `interface{ JWKS() ([]byte, error) }` and nothing re-marshals a jwx set.
- `WithErrorHandler` governs the **net/http chain only**. gin refusals go to gin's error channel and fiber's to fiber's error handler, each by design. Documented on the option and on both adapters.

### 18. The caller is published, not only the authentication event

The chain publishes the authentication result **and** the principal, through one exported helper,
`httpsec.WithCaller`.

- **Why.** Publishing only `authenticate.WithAuthentication` left `identity.PrincipalFromContext`
  empty, and the guards read it — so a caller the chain had just authenticated was refused 401 by
  its own guard, on every first factor. The failure was indistinguishable from a missing credential,
  which is why it survived until an adapter test looked for the principal specifically.
- **Why exported.** A consumer's own first factor is a registered interceptor (Decision 2), and the
  spec requires such an interceptor to do everything a built-in can. With the helper unexported, a
  consumer reaching for `authenticate.WithAuthentication` — the obvious exported API — hit the same
  trap. One call publishes both, so no call site can publish one without the other.
- **Override:** none. A consumer who wants only the event calls `authenticate.WithAuthentication`
  directly and accepts that guards will not see their caller.

### 19. Form login binds from the POST body only

- **Default:** the credential is read from the parsed body, and only when it declares
  `application/x-www-form-urlencoded`. The URL query is never consulted.
- **Why.** `Request.FormValue` carries net/http's semantics, which merge the query into the form, so
  `POST /login?username=ada&password=s3cret` authenticated — putting the password into every access
  log, proxy log, browser history and `Referer` that saw the URL. "Form fields" in the requirement
  means a body; a URL is not one.
- **Scope.** Only form login's binding narrows. `Request.FormValue` keeps net/http semantics, because
  a consumer interceptor reading an ordinary query parameter is legitimate and the abstraction is a
  public adapter contract.
- **Stated limits:** a `multipart/form-data` login is refused with `ErrCredentialsMissing`, and a
  urlencoded body that does not parse yields no credential rather than the pairs that did. Both are
  fail-closed and both are documented.

### 20. Defaults and required dependencies settled at construction

- **Rate limiter:** defaults to an in-memory limiter (5 failures per 15 minutes, matching `policy`'s
  lockout defaults), built at construction so the documented default is real. `WithRateLimiter(nil)`,
  and a typed nil, are refused.
- **Refused as nil**, beyond the list in Decision 4: `WithPolicyEngine`, `WithLogger` and
  `WithErrorHandler`. A nil engine would read as "no policies" while the consumer believed theirs
  were running, and a nil error handler would answer a refused request with 200.
- **Required, not defaulted:** the attempt store on form login and Basic, because a library-supplied
  store is one the consumer's lockout policy never reads — a lockout that silently never fires. The
  godoc says to pass the same store `policy` was given. `LogoutDeps.Sessions` is likewise required.
- **Session-store outage answers 401, not 500.** Every `Load` failure is `ErrAuthenticationRequired`,
  so a client cannot learn whether a session existed. The cost is that an outage looks like a
  logged-out user; the uniform refusal is the requirement.
- **The per-request challenge marker is per-request.** `completeLogin` saves the marker set at login
  before any token exists, which is the case that must survive. On the per-request path the policy
  re-evaluates on every request, so persisting the marker would freeze a decision the policy owns.
  With the gate enabled the marker is never reached by session touch anyway, because the gate at
  `OrderPasswordChange` refuses without calling `next`.

### 21. Adapter and outbound details the pinned versions forced

- **fiber v3.5.0:** `fiber.Ctx` is an interface; `c.Cookie` takes fiber's own cookie type;
  `c.SendStatus` writes the status text as the body, so `fibersec.ErrorHandler` uses `c.Status` to
  keep the bare-status contract; and `c.IP()` reads the proxy header only when `Config.ProxyHeader`
  is set, so that field is **mandatory** in the safe proxy configuration, not optional.
  `fibersec.NewGuards` takes no options: the only thing its peers let a consumer replace is how a
  refusal is answered, and on fiber that is `fiber.Config.ErrorHandler`.
- **`outbound`:** the body is read to `maxBytes+1` so "fits exactly" is distinguishable from
  "truncated"; the final-URL check applies the scheme/allowlist rules **and** same-origin-with-start,
  because the allowlist is empty by default and would otherwise permit any HTTPS host; and
  `WithAllowedSchemes` adds to `https`, which is always allowed, since removing it could not make
  anything safer.
- **`internal/origin.NewAllowlist` copies its input slices**, so a caller mutating its slice after
  construction cannot change a list that was already validated.

### 22. What this change deliberately leaves unwired

The source throttle seam (`sourceThrottled`, `recordSourceFailure`) has no built-in caller. Form
login's per-account lockout is the policy engine reading the attempt store; per-source throttling
belongs to the redemption flows `auth-methods` adds. The seam, the client-address rules and the
sampled refusal logs are complete and tested; the first interceptor to throttle a flow supplies its
own `ratelimit.SourceGuard` built over `Chain`'s limiter and IPv6 prefix.

### 23. The conformance suite's module direction

`test` requires `ginsec` and `fibersec`, and all three adapter runs live in `test`. The reverse —
an adapter requiring `github.com/kartaladev/scrty/test` — is forbidden even from a `_test.go` file,
because a test-only import puts the helpers' dependencies in a consumer's module graph.
`TestModuleLayout` cannot catch a mistake here: it skips any directory holding a `go.mod`, so it
never scans the integration modules. The check is a documented manual one.

## Risks / Trade-offs

- **[The request/response abstraction is a public contract that every adapter depends on]** → Its shape is settled before the first tag. The conformance suite runs every change to an interceptor through all three adapters.
- **[Values read from fiber's zero-copy accessors alias the request buffer]** → Documented on `fibersec`. An interceptor that keeps a value beyond the request, for example for asynchronous logging, copies it.
- **[With fiber's built-in error handler the body is the status text, not empty]** → Documented limit. `fibersec.ErrorHandler` gives the bare default, and the text never carries error detail.
- **[A misconfigured gin or fiber trusted proxy setup lets clients choose their rate-limit key]** → Both opt-ins are off by default and documented with the exact safe settings and the bypass.
- **[gin middleware registered after the chain does not run for refused or self-answered requests]** → Documented on `ginsec`.
- **[No central rules configured means only guards protect routes]** → Documented on `EnableAuthorization`. The conformance suite includes a guards-only app.
- **[A session carrying a pending second factor is enforced only if `auth-methods`' challenge interceptor is enabled]** → `auth-methods` must refuse, at construction, a policy that can challenge for a second factor without that interceptor. Flagged as a dependency.
- **[Sampling hides exact refusal volume]** → The default reporter writes a summary. A consumer reporter plus `FlushRefusalLogs` gives exact counts.
- **[Session touch ignores its own failures silently]** → Kept deliberately: a bookkeeping failure must not mask the handler's result, and a concurrent logout makes not-found normal. Idle expiry still bounds the session.
- **[Outbound confinement does not filter internal IP ranges]** → Targets are consumer-configured or come from a consumer-configured provider. A consumer who needs IP filtering supplies a `Transport` whose dialer enforces it.
- **[`StatusForError` knows sentinels from several packages]** → The enumeration test fails when a change adds an unmapped refusal sentinel.

## Migration Plan

Not applicable: a new library with no consumers and no tags.

## Open Questions

All three are settled. They are kept here with their answers, because each was recorded as open and
a reader of this design will otherwise wonder how it was closed.

- **gin pin — settled.** `ginsec` pins `github.com/gin-gonic/gin v1.12.0`, the latest v1 at
  implementation. It changed no spec, approach or task.
- **Does anything evaluate a policy without an engine? — settled: no.** `gopls references` found no
  caller of `policy.ContextWithPhase` or `PhaseFromContext` outside `policy` itself, in any module.
  `Engine.EvaluatePhase` sets the phase itself, and the chain always goes through an engine. Both
  helpers are unexported. Nothing is tagged, so this cost nothing; after the first tag it would have
  been a breaking change. The override a phase-sensitive policy still has is
  `policy.WithMFARequirementPhaseSource`, which is what the godoc now points a consumer at, so the
  archived `security-policy` requirement — "a consumer SHALL be able to replace how such a policy
  learns the phase" — is still met without either helper being public. The package's own tests reach
  the unexported publisher through `policy/export_test.go`, the same idiom `factor` and `httpsec`
  use.
- **One `RefusalLogFlusher`, or one per capability? — settled: one per capability, for now**, pinned
  by `TestFlushRefusalLogsScope`, which wires a real policy engine into the chain and asserts the
  chain reports its own suppressed counts while the policy's stay held.**
  `Chain.FlushRefusalLogs` flushes the chain's own sampler only, and its godoc says consumers flush
  `authenticate` and `policy` themselves. No shared declaration is introduced by this change. Go
  satisfies interfaces structurally, so a consumer asserting against any of the identical
  `FlushRefusalLogs() error` declarations already reaches every component; the duplication costs
  documentation, not interoperability. A shared declaration remains free until the first tag.
