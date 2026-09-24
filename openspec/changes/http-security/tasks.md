# Tasks

Every task follows the project's test-first rule: write the failing test, run it, confirm it
fails for the intended reason (a compile error is not a red step), then implement. "Verify" in a
task names the focused run that must first fail and then pass.

Package names in `design.md`'s Go snippets predate the code that now exists. Throughout, read
`authn` as `authenticate`, `authz` as `authorize`. `authorize.Rule`/`Rules` are generic, so the
centralized rule set is instantiated over the chain's own request type, and `session` exports no
context helper, so `httpsec` owns the session context key. Task 15.3 records these in `design.md`.

## 1. Exchange abstraction and the net/http implementation

- [x] 1.1 Define `Request`, `ResponseWriter`, `Cookie` and `Exchange` in `httpsec` with
  `NewExchange`, `Context` and `SetContext` (design Decision 1). Verify with a table test over a
  stub `Request`/`ResponseWriter` asserting the exchange derives from the context it was seeded
  with and that `SetContext` is visible to a later reader: `go test -run TestExchange -count=1
  ./httpsec/`.
- [x] 1.2 Implement `NewHTTPRequest` over `*http.Request` covering `Method`, `Path`, `Header`,
  `Query`, `Cookie` and `FormValue`. Verify with a table test built from `httptest.NewRequest`
  rows: `go test -run TestHTTPRequest -count=1 ./httpsec/`.
- [x] 1.3 Implement `Request.Body(limit)` on the net/http request so the body is buffered once,
  restored for the downstream handler, and a body over the limit returns `ErrRequestTooLarge`
  without being parsed (spec: "Login request bodies are bounded"). Verify a case reading the body
  twice and a case at limit+1 byte: `go test -run TestHTTPRequestBody -count=1 ./httpsec/`.
- [x] 1.4 Implement `NewHTTPResponseWriter` covering `SetHeader`, `SetCookie`, `WriteHeader` and
  `Write`, recording whether the response was committed. Verify against `httptest.ResponseRecorder`:
  `go test -run TestHTTPResponseWriter -count=1 ./httpsec/`.
- [x] 1.5 Implement `ClientIP` on the net/http request as the host part of `RemoteAddr`, returning
  `""` when it is not `host:port`, reading no forwarding header (spec: "The net/http chain
  attributes requests to the transport peer"). Verify with rows for a spoofed `X-Forwarded-For`, a
  peer with no port and an IPv6 peer: `go test -run TestHTTPRequestClientIP -count=1 ./httpsec/`.

## 2. Refusal errors and the public status table

- [x] 2.1 Declare `ErrAuthenticationRequired`, `ErrCredentialsMissing` and `ErrRequestTooLarge` in
  `httpsec`, and `ChallengeError` with `Kind`, `Session` and `Token`. Declare no
  `ErrRefusedByPolicy`: `policy.Engine` already substitutes `policy.ErrPolicyDenied` for a
  reasonless deny (`policy/engine.go:128-133`), so that sentinel is the one the chain sees.
  Verify `ChallengeError.Error()` names the kind only and contains neither token nor session handle
  (spec: "Challenge text carries no secret"): `go test -run TestChallengeError -count=1
  ./httpsec/`.
- [x] 2.2 Implement `StatusForError` as the one public mapping: `*ChallengeError` first through
  `errors.As`, then an ordered sentinel table through `errors.Is`, covering every row of the
  `http-error-propagation` table across `authenticate`, `authorize`, `policy` and `session`.
  Verify with a characterization table including wrapped, joined and challenge-wrapping-sentinel
  rows and an unrecognised error mapping to 500: `go test -run TestStatusForError -count=1
  ./httpsec/`.
- [x] 2.3 Add the enumeration test that walks the exported refusal sentinels of the mapped packages
  and fails on one `StatusForError` does not recognise (design Decision 16). Verify it fails when a
  sentinel is temporarily removed from the table, then passes: `go test -run
  TestStatusForErrorCoversEverySentinel -count=1 ./httpsec/`.
- [x] 2.4 Map `policy.ErrPolicyDenied` to 403 in `StatusForError`, satisfying the spec's
  "refused by policy without a reason" row, and implement `policyDenyReason(d policy.Decision) error`
  as `d.Reason` with no nil fallback. Verify a reasonless consumer deny reduced by
  `policy.Engine.EvaluatePhase` arrives carrying `policy.ErrPolicyDenied` and maps to 403, never to
  200 and never to an authentication failure: `go test -run TestPolicyDenyReason -count=1
  ./httpsec/`.

## 3. Slots, registration, assembly and construction validation

- [x] 3.1 Declare the `Order` constants of design Decision 2 with `Before` and `After`, and
  `RegisterInterceptor`. Verify the named slots leave the adjacent slots free and that
  `Before`/`After` land between neighbours: `go test -run TestOrder -count=1 ./httpsec/`.
- [x] 3.2 Implement `Chain.Assemble(terminal Next)` as a stable sort by order folded around the
  terminal. Verify with the spec's ordering table — ascending slot order, equal slots in
  registration order, adjacent slots around the bearer slot: `go test -run TestChainAssemble
  -count=1 ./httpsec/`.
- [x] 3.3 Implement continuation semantics: an interceptor that does not call `next` stops the
  request, one that calls it can act afterwards, and an error propagates outward unchanged.
  Verify with the three scenarios of "An interceptor continues, stops or acts after the handler":
  `go test -run TestChainContinuation -count=1 ./httpsec/`.
- [x] 3.4 Implement `New(opts ...Option) (*Chain, error)` applying options then validating, with the
  reflection-based typed-nil check so `(*T)(nil)` inside an interface is not taken as present
  (design Decision 4). Verify a dependency holding a typed nil fails construction rather than
  panicking on the first request: `go test -run TestNewRejectsTypedNil -count=1 ./httpsec/`.
- [x] 3.5 Add one construction-refusal row per case in design Decision 4 — absent dependency for an
  enabled interceptor, nil limiter, nil refusal log reporter, login body limit <= 0, nil
  interceptor, IPv6 source prefix outside 1..128 — each error naming the `Enable*`/`With*` option
  and the dependency at fault. Verify every row is seen failing before the check exists:
  `go test -run TestNewRefusesWiring -count=1 ./httpsec/`.
- [x] 3.6 Implement context derivation: the exchange starts from the incoming request's context so
  upstream values and cancellation survive, and interceptor calls into the cores receive it (spec:
  "The request context is derived, never replaced"). Verify an upstream value reaches the handler
  and a cancelled client request is observed by an in-flight lookup: `go test -run
  TestChainContext -count=1 ./httpsec/`.

## 4. Client address refusal, the throttle seam and sampled refusal logs

- [x] 4.1 Implement the unattributable-address refusal: empty, not a single IP, or unspecified
  (`0.0.0.0`, `::`, `::ffff:0.0.0.0`) refuses with `authenticate.ErrAuthenticationFailed` before the
  guarded work and is never pooled into a bucket. Verify with a table over every form plus the
  list-valued address `203.0.113.9, 198.51.100.7`: `go test -run TestSourceAddressRefusal -count=1
  ./httpsec/`.
- [x] 4.2 Implement `sourceThrottled` and `recordSourceFailure` over `ratelimit.SourceGuard`, with
  `recordSourceFailure` running on `context.WithoutCancel` so a client that disconnects after
  guessing is still counted (spec: "Client disconnects after guessing"). Verify with a mockgen
  `ratelimit.Limiter`, including a limiter error refusing the request: `go test -run
  TestSourceThrottle -count=1 ./httpsec/`.
- [x] 4.3 Wire the chain's `logsample.Sampler` with the keys of design Decision 14 —
  `flow|source`, `flow` for a limiter failure, and `flow|<reason>` for each unattributable form —
  so a burst against one flow never suppresses another's record. Verify with `testing/synctest`
  windows and a captured `slog` handler covering the flood, two-sources and disabled-interval
  scenarios: `go test -run TestRefusalLogSampling -count=1 ./httpsec/`.
- [x] 4.4 Implement `WithRefusalLogInterval`, `WithRefusalLogReporter` and
  `Chain.FlushRefusalLogs`, with the default summary WARN reporter and a nil reporter refused at
  construction. Verify the default summary names the key and suppressed count, a consumer reporter
  receives the pending count on flush, and the suppressed count is attached only when non-zero:
  `go test -run TestRefusalLogReporter -count=1 ./httpsec/`.
- [x] 4.5 Log a request whose context ended before the limiter answered at DEBUG, unsampled (spec:
  "A request that ended before the rate-limit check"). Verify the record is DEBUG and bypasses the
  sampler: `go test -run TestRefusalLogUnsampledDebug -count=1 ./httpsec/`.

## 5. The login completion seam

- [x] 5.1 Implement `postAuthenticationInput` with the principal, first factor, submitted username
  and password change time as separate parameters, `first` a distinct type (design Decision 11).
  Verify a row per call site shows a firing password-age challenge, pinning argument order:
  `go test -run TestPostAuthenticationInput -count=1 ./httpsec/`.
- [x] 5.2 Implement `completeLogin` in the order of design Decision 11: post-authentication phase
  with `policyDenyReason`, create the session with its first factor, mark and save a pending
  challenge before the token is issued, issue the token, publish onto the exchange and context,
  then return `*ChallengeError`. Verify a save failure leaves no token issued and that a challenged
  login returns the kind, pending session and token: `go test -run TestCompleteLogin -count=1
  ./httpsec/`.
- [x] 5.3 Verify the seam behaves identically for a first factor that is not form login (spec:
  "Another first factor reuses login completion"): a stub redemption interceptor handing a principal
  to `completeLogin` under a password-change policy is refused with a password-change challenge
  carrying a pending session. `go test -run TestCompleteLoginOtherFirstFactor -count=1 ./httpsec/`.

## 6. Form login, Basic and bearer authentication

- [x] 6.1 Implement form login matching `POST /login` with `WithLoginRequestPath`, `WithLoginParams`
  and form-then-JSON binding, passing every other request through. Verify the happy path, a GET
  passing through, and consumer field names `email`/`secret`: `go test -run TestFormLogin -count=1
  ./httpsec/`.
- [x] 6.2 Implement the form login sequence: pre-authentication phase before credentials are
  checked, authenticate, record or clear attempts with store failures logged and not returned, then
  `completeLogin`. Verify a locked account is refused with the lockout reason and the password is
  never checked, and that a wrong password records one failed attempt: `go test -run
  TestFormLoginSequence -count=1 ./httpsec/`.
- [x] 6.3 Implement `WithLoginBodyLimit` (64 KiB default) applied through `Request.Body` before
  parsing, and refuse a credential-less or undecodable JSON login with `ErrCredentialsMissing`.
  Verify a 1 MiB body is refused with `ErrRequestTooLarge` with no authentication attempted, a
  raised limit parses a 100 KiB body, and a missing-credentials login maps to 400: `go test -run
  TestFormLoginBody -count=1 ./httpsec/`.
- [x] 6.4 Implement the default JSON success body (`access_token`, empty `refresh_token`,
  `valid_until`) and `WithLoginResponder` replacing it, with the handler never called on success.
  Verify the default document's fields and a consumer responder writing its own body: `go test -run
  TestFormLoginResponse -count=1 ./httpsec/`.
- [x] 6.5 Implement Basic authentication: exact `Basic ` prefix, base64 and separator validation,
  pre-authentication phase, `WWW-Authenticate` on failure with `WithBasicAuthRealm` (default
  `Restricted`), the stateless-authentication phase on success, and never a session or token.
  Verify valid credentials reach the handler with no session, invalid ones carry the realm header,
  and a stateless challenge carries no session and no token: `go test -run TestBasicAuth -count=1
  ./httpsec/`.
- [x] 6.6 Implement bearer authentication: case-insensitive scheme with `WithBearerScheme` and
  `WithBearerAllowEmptyScheme`, verification returning `errors.Join(ErrAuthenticationFailed, cause)`
  with the cause logged at DEBUG, and the principal, authentication result and session published to
  the context. Verify a valid token, a tampered token and the consumer scheme `Token`: `go test -run
  TestBearerToken -count=1 ./httpsec/`.
- [x] 6.7 Implement bearer session and user resolution: a missing or expired session and a vanished
  user return `ErrAuthenticationRequired`; an undecryptable session returns it and is logged at
  ERROR. Verify each case and assert the ERROR record for the undecryptable session: `go test -run
  TestBearerSessionResolution -count=1 ./httpsec/`.
- [x] 6.8 Implement the bearer per-request policy phase: a deny refuses through `policyDenyReason`,
  a challenge marks the challenge pending on the session and continues so its gate enforces it.
  Verify a reasonless deny is 403 not 200, and that a mid-session password-change challenge marks
  the session and continues: `go test -run TestBearerPerRequestPhase -count=1 ./httpsec/`.

- [x] 6.9 Bind the login credential from the parsed POST body only, ignoring the URL query, so a
  credential in a URL never authenticates. `Request.FormValue` keeps net/http semantics for consumer
  interceptors; only form login's own binding narrows. Verify test-first: `POST
  /login?username=ada&password=s3cret` with an empty body is refused with `ErrCredentialsMissing`
  and attempts no authentication, while the same credentials in the body still succeed — and the
  same holds on gin and fiber: `go test -run TestFormLoginIgnoresQueryCredentials -count=1
  ./httpsec/`.

## 7. Password-change gate, logout, session touch and the key set endpoint

- [x] 7.1 Implement the password-change gate refusing any session carrying the pending marker with
  `*ChallengeError{Kind: ChallengePasswordChange, Session}` and never calling the handler. Verify
  the refusal carries the session and no token: `go test -run TestPasswordChangeGate -count=1
  ./httpsec/`.
- [x] 7.2 Implement `WithChangePasswordEndpoint(path, fn)`: `POST path` passes the gate, a request
  with no session is refused with `ErrAuthenticationRequired` without running the consumer's
  function, the consumer's error is the refusal, and on success the marker is cleared, the session
  saved and the response owned by the consumer. Verify all three rules: `go test -run
  TestChangePasswordEndpoint -count=1 ./httpsec/`.
- [x] 7.3 Implement logout on `POST /logout` with `WithLogoutRequestPath`: no authentication result
  refuses with `ErrAuthenticationRequired`, a session is deleted, an already-gone session is not an
  error, a stateless request deletes nothing, and the answer is 200 with an empty body and no
  handler call. Verify each, including a consumer path leaving `/logout` passing through: `go test
  -run TestLogout -count=1 ./httpsec/`.
- [x] 7.4 Implement session touch at `OrderSessionTouch`: run `next` first, then advance the idle
  deadline for any session on the exchange, including when `next` returned an error, ignoring its
  own failure. Verify a refused request still advances the deadline and that a touch failure after a
  200 changes neither the response nor the returned error: `go test -run TestSessionTouch -count=1
  ./httpsec/`.
- [x] 7.5 Implement the key set endpoint on `GET /.well-known/jwks.json` with
  `WithJWKSEndpointPath`, answering 200 with the JSON Web Key Set and a JSON content type, never
  calling the handler, and propagating a provider failure as an error. Verify the response carries
  no private members and that a consumer path is served while the default passes through: `go test
  -run TestJWKSEndpoint -count=1 ./httpsec/`.

## 8. Authorization: the chain stage and per-endpoint guards

- [x] 8.1 Implement the authorization stage at `OrderAuthorizer`, always registered, publishing the
  authorizer through `authorize.WithAuthorizer`. Verify that with no rules configured every request
  reaches its route and a guard on that route reads the authorizer: `go test -run
  TestAuthorizationStage -count=1 ./httpsec/`.
- [x] 8.2 Implement `EnableAuthorization(az authorize.Authorizer, rules ...authorize.Rule[Request])`
  appending across calls and instantiating `authorize.Rules` over the chain's request type. Verify
  first-match-wins, an unmatched request refused with access denied, and an anonymous request to a
  rule requiring authentication refused with `ErrAuthenticationRequired`: `go test -run
  TestAuthorizationRules -count=1 ./httpsec/`.
- [x] 8.3 Implement `NewGuards` with `RequireAuthenticated`, `ResourcePrivileges(...).RequireOne/
  RequireAll/RequireAny` and `ResourceOwnerships[ID](...).ForResource(extract)`, reading the
  authorizer from the context and falling back to the one given at construction. Verify the
  fallback and the context preference: `go test -run TestGuardsAuthorizerSource -count=1
  ./httpsec/`.
- [x] 8.4 Implement the four guard fail-closed refusals — no principal, no authorizer, extractor
  error, authorizer refusal — each skipping the route. Verify with a table, including a guard
  refusing on top of a permissive centralized rule: `go test -run TestGuardsFailClosed -count=1
  ./httpsec/`.

## 9. The net/http entrypoint and default error handling

- [x] 9.1 Implement `Chain.Middleware() func(http.Handler) http.Handler`, seeding from
  `r.Context()` and calling the handler with `r.WithContext(ex.Context())`. Verify the principal and
  session reach the handler and an upstream request identifier survives: `go test -run
  TestMiddleware -count=1 ./httpsec/`.
- [x] 9.2 Implement the default refusal response: the mapped status with an empty body, no error
  text, the handler not reached, and headers an interceptor set before refusing kept. Verify 401
  with an empty body, a 500 withholding `connection refused to db-primary:5432`, and a kept
  `WWW-Authenticate`: `go test -run TestDefaultErrorResponse -count=1 ./httpsec/`.
- [x] 9.3 Implement `WithErrorHandler` and `WithGuardErrorHandler`, the consumer's handler replacing
  the default entirely, and the guard default deriving its status from `StatusForError` rather than
  its own switch (design Decision 7). Verify a consumer JSON body at 403, the guard handler
  receiving the guard's refusal, and a guard refusing on invalid authorization attributes answering
  the status the table gives: `go test -run TestConsumerErrorHandler -count=1 ./httpsec/`.
- [x] 9.4 Run the whole `httpsec` package green under race and the workspace gates:
  `go test -race -count=1 ./httpsec/`, `go vet ./...`, `gofmt -l .` empty and
  `golangci-lint run ./httpsec/...` clean.

- [x] 9.5 Publish the principal under `identity`'s own context key wherever the chain publishes an
  authentication result, so a guard and a consumer handler can read it. REPRODUCED: nothing calls
  `identity.WithPrincipal`, while `guards.go:123` reads `identity.PrincipalFromContext`, so a caller
  the chain authenticated is refused 401 by `RequireAuthenticated()` — per-endpoint guards are
  broken behind every authentication method. Fix at the three publish sites (`basic.go`,
  `bearer.go`, `logincomplete.go`), not by changing what guards read, because the spec requires the
  principal itself to reach the handler's context. Verify test-first: a guarded route behind an
  authenticating chain runs, and the handler reads the principal through
  `identity.PrincipalFromContext`: `go test -run 'TestGuardBehindAuthentication|TestMiddleware'
  -count=1 ./httpsec/`.

- [x] 9.6 Export the caller-publishing helper so a consumer's own first factor can do what a
  built-in does. REPRODUCED: an interceptor registered by a consumer that publishes with
  `authenticate.WithAuthentication` alone — the obvious exported API — leaves every guard refusing
  its callers 401, because `publishCaller` is unexported and guards read
  `identity.PrincipalFromContext`. The spec requires a consumer interceptor to be able to do
  everything a built-in can, so publish-the-caller must be reachable. Export it (one call, so two
  call sites cannot drift) and name it in the `RegisterInterceptor` godoc. Verify test-first: a
  guarded route behind a CONSUMER-registered first factor runs, and an unauthenticated request to
  the same route is still refused: `go test -run TestConsumerFirstFactorPublishesCaller -count=1
  ./httpsec/`.

## 10. Origin comparison and the redirect-target allowlist

- [x] 10.1 Implement `internal/origin.Same`: ASCII case folding and default-port removal only, no
  IDNA or Unicode folding, ports compared as written, a trailing dot significant, userinfo ignored,
  and anything unparsable matching nothing including another such value. Verify with an accept and
  reject table including the U+0130 and U+212A look-alikes and two `mailto:` values: `go test -run
  TestOriginSame -count=1 ./internal/origin/`.
- [x] 10.2 Implement `internal/origin.Allowlist` entry and declared-origin validation at
  construction, each error naming the entry and the option at fault: host-relative entries starting
  with `/` and not followed by `/` or `\`, absolute entries needing a declared origin and no
  userinfo, and declared origins `https` or `http` on loopback with no path, query, fragment or
  userinfo. Verify one row per refusal message, including `//partner.example.com/landing`, an
  undeclared absolute entry and `http://partner.example.com`: `go test -run TestAllowlistConstruction
  -count=1 ./internal/origin/`.
- [x] 10.3 Implement `Allowlist.Resolve` as exact matching with a re-check of the matched entry and
  a fallback to `/`. Verify a declared partner URL resolves and `/\evil.example.net` falls back:
  `go test -run TestAllowlistResolve -count=1 ./internal/origin/`.

## 11. The confined outbound client

- [x] 11.1 Create the `outbound` package with `New`, `Client`, `Response` and the options of design
  Decision 15, refusing at construction a scheme other than `http`/`https`, a negative redirect cap,
  a timeout <= 0 and a response limit <= 0. Verify one row per refusal: `go test -run
  TestOutboundConstruction -count=1 ./outbound/`.
- [x] 11.2 Implement scheme and allowed-origin checks before anything is sent, with `https` the only
  default scheme and default-port equivalence on origins. Verify `http://idp.example.com/jwks`
  fails before a connection is opened, an allowed `http` localhost fetch is sent, and
  `https://IDP.example.com/token` matches the declared `https://idp.example.com:443`: `go test -run
  TestOutboundTargets -count=1 ./outbound/`.
- [x] 11.3 Install `CheckRedirect` on a copy of the consumer's `*http.Client`, enforcing the hop cap
  first, then scheme and same-origin against `via[0]`, then the consumer's own `CheckRedirect`.
  Verify off-origin, downgrade and same-origin redirects, a consumer check that refuses every
  redirect, a loop server that would run 50 hops failing at 10, and a cap of zero never following:
  `go test -run TestOutboundRedirects -count=1 ./outbound/`.
- [x] 11.4 Verify no credential-bearing body is replayed to another origin: a `307` from a token
  endpoint to an evil server that counts received secrets must leave that count at zero.
  `go test -run TestOutboundNoBodyReplay -count=1 ./outbound/`.
- [x] 11.5 Implement the final-URL re-check before the body is read, rejecting a response whose
  `res.Request.URL` fails the scheme, allowed-origin or same-origin rules and returning no content.
  Verify with a consumer transport that follows a redirect itself to `https://evil.example.net`:
  `go test -run TestOutboundFinalURL -count=1 ./outbound/`.
- [x] 11.6 Implement the time bound (10s default) as a context deadline around the whole call,
  whatever timeout the supplied client has, with an earlier caller deadline winning. Verify with a
  hanging server, a consumer client with no timeout, and a 3s consumer bound: `go test -run
  TestOutboundTimeout -count=1 ./outbound/`.
- [x] 11.7 Implement the response body bound (1 MiB default) through `io.LimitReader`, so an
  oversized document fails to parse and is not used. Verify a 5 MiB key set fails with at most
  1 MiB read and a raised 4 MiB limit reads a 2 MiB document in full: `go test -run
  TestOutboundBodyLimit -count=1 ./outbound/`.

## 12. The ginsec integration module

- [x] 12.1 Create the `ginsec` nested module requiring gin with a replace onto the core, add it to
  `go.work`, and confirm the core module gains no gin dependency. Verify `TestModuleLayout`'s "real
  tree has no violations" row still passes: `go test -run TestModuleLayout -count=1 .`.
- [x] 12.2 Implement the gin adapter reusing the net/http `Request`/`ResponseWriter`, seeding from
  `c.Request.Context()`, setting `c.Request = c.Request.WithContext(...)` before `c.Next()`. Verify
  a gin route handler reads the principal from the request context and an upstream value survives:
  `go test -run TestGinContext -count=1 ./...` in `ginsec`.
- [x] 12.3 Implement gin refusal handling: `c.Error(err)`, `c.Status(StatusForError(err))` when
  nothing has written yet, then `c.Abort()`, never `AbortWithStatus`. Verify 403 with an empty body
  and no route call when no error middleware is registered, and that consumer error middleware can
  still set its own status, `Content-Type` and body: `go test -run TestGinRefusal -count=1 ./...`.
- [x] 12.4 Implement the bare `c.Abort()` for requests the chain answered itself. Verify a route
  writing 201 on the logout path does not run and the response stays 200, and that a consumer
  `NoRoute` handler does not append to the key set body: `go test -run TestGinSelfAnswered -count=1
  ./...`.
- [x] 12.5 Implement `ginsec.NewGuards` following the same refuse-and-abort rules, and
  `ginsec.WithForwardedClientIP()` opting into `c.ClientIP()` with the peer as the default. Verify a
  guard answers 403 with no error middleware, a forwarded header is ignored by default, and the
  opt-in with trusted proxies attributes the forwarded client: `go test -run 'TestGinGuards|
  TestGinClientIP' -count=1 ./...`.
- [x] 12.6 Write the `ginsec` godoc stating that gin trusts every proxy until `SetTrustedProxies` is
  called, and that middleware registered after the chain does not run for refused or self-answered
  requests. Verify `go doc ./...` shows both notes and `golangci-lint run ./...` is clean.

## 13. The fibersec integration module

- [x] 13.1 Create the `fibersec` nested module requiring fiber v3.5.0 and fasthttp with a replace
  onto the core, add it to `go.work`, and re-check the fiber accessor names against the pinned tag.
  Verify `TestModuleLayout` still reports no violations: `go test -run TestModuleLayout -count=1 .`.
- [x] 13.2 Implement `Request` and `ResponseWriter` directly over `fiber.Ctx` (`Method`, `Path`,
  `Get`, `Query`, `Cookies`, `FormValue`, `Body`, `IP`; `Set`, `Cookie`, `Status`, `Write`) with no
  conversion to net/http types, applying the login body limit as a length check on fiber's already
  buffered body. Verify no `*http.Request` is constructed for a secured request and that an
  oversized body is refused with `ErrRequestTooLarge`: `go test -run TestFiberExchange -count=1
  ./...` in `fibersec`.
- [x] 13.3 Implement fiber context seeding from `c.Context()` and `c.SetContext(...)` before
  `c.Next()`. Verify a route handler reads the principal from the handler context's request context
  and an upstream trace identifier survives: `go test -run TestFiberContext -count=1 ./...`.
- [x] 13.4 Implement `RefusalError` wrapping the original refusal and a `*fiber.Error{Code: status}`
  through `Unwrap() []error`, with `Error()` returning only `http.StatusText(status)`. Verify
  `errors.As` still reaches `*httpsec.ChallengeError`, and that fiber's built-in handler answers 500
  with at most `Internal Server Error` for a cause reading `connection refused to db-primary:5432`:
  `go test -run TestFiberRefusalError -count=1 ./...`.
- [x] 13.5 Implement `fibersec.ErrorHandler` answering the bare mapped status with an empty body and
  `fibersec.MapError(err) (int, any)` returning the status and a body holding only the status text.
  Verify the bare handler answers 401 with an empty body and the helper returns 403 with
  `Forbidden`: `go test -run 'TestFiberErrorHandler|TestFiberMapError' -count=1 ./...`.
- [x] 13.6 Implement `fibersec.NewGuards` returning refusals the same way. Verify a guard refusal
  reaches fiber's error handler identifiable as the original refusal: `go test -run TestFiberGuards
  -count=1 ./...`.
- [x] 13.7 Write the `fibersec` godoc giving the safe proxy configuration (`TrustProxy`, explicit
  `TrustProxyConfig.Proxies` with `UnixSocket` and `"0.0.0.0"` where needed, `ProxyHeader`,
  `EnableIPValidation`), the `UnixSocket`/`Loopback`/`Private`/`LinkLocal` pitfalls, the zero-copy
  accessor aliasing limit, the empty-versus-absent cookie limit, and the status-text body limit of
  fiber's built-in handler. Verify `go doc ./...` shows them and `golangci-lint run ./...` is clean.
- [x] 13.8 Verify the address rules apply to whatever address fiber returns: a request through
  `app.Test` with no proxy trust is refused as an unspecified client address, and with
  `TrustProxy` plus `EnableIPValidation` and a trusted 10.0.0.2 the forwarded 198.51.100.7 is used.
  `go test -run TestFiberClientIP -count=1 ./...`.

## 14. The adapter conformance suite

- [x] 14.1 Add `test/httpsecconformance` holding one scenario table covering login success and
  failure, lockout, bearer verification, rule and guard allow and deny, a challenge, an endpoint
  answered by the chain, context propagation and an unattributable address, exported for an adapter
  suite to run. Verify it compiles and the table is non-empty from a smoke test: `go test -count=1
  ./httpsecconformance/` in `test`.
- [x] 14.2 Run the suite against net/http through `httptest` from the `test` module. Verify every
  scenario passes: `go test -run TestConformanceNetHTTP -count=1 ./...` in `test`.
- [x] 14.3 Run the suite against gin from the `test` module, which requires `ginsec`. It must NOT
  live in `ginsec`: no scrty module may import `github.com/kartaladev/scrty/test`, even from a
  `_test.go` file, because that leaks the helpers' drivers into a consumer's module graph. Verify
  the same status, the same library-set headers, the same session and attempt side effects and the
  same refusal error as net/http: `go test -run TestConformanceGin -count=1 ./...` in `test`.
- [x] 14.4 Run the suite against fiber from the `test` module, which requires `fibersec`, through
  `app.Test`, with `TrustProxy` and `Proxies: {"0.0.0.0"}` plus a forwarded header where a throttled
  flow needs an address. It must NOT live in `fibersec`, for the same module-graph reason as 14.3.
  Verify every scenario matches net/http: `go test -run TestConformanceFiber -count=1 ./...` in
  `test`.
- [x] 14.5 Verify the same wiring mistake fails the same way on every adapter: a chain enabling form
  login without a session manager returns the identical construction error for net/http, gin and
  fiber. `go test -run TestConformanceConstruction -count=1 ./...` in `test`, which holds all three
  adapters' runs.
- [x] 14.6 Verify a consumer adapter for another framework works without changing any interceptor:
  implement `Request`/`ResponseWriter` over a stub framework in a test and run form login and bearer
  authentication through `Chain.Assemble`. `go test -run TestConsumerAdapter -count=1 ./httpsec/`.

## 15. Settle the open questions and reconcile the artifacts

- [x] 15.1 Confirm with gopls references that no `httpsec` call site uses `policy.ContextWithPhase`
  or `PhaseFromContext`, then unexport both. Verify `go build ./...` across every workspace module
  and `go test -count=1 ./policy/` stay green, and that the archived `security-policy` spec does not
  pin them as public — report it if it does rather than editing it.
- [x] 15.2 Verify `Chain.FlushRefusalLogs` flushes the chain's own sampler only, per the settled
  answer that no shared `RefusalLogFlusher` declaration is introduced in this change, and that its
  godoc says consumers flush `authenticate` and `policy` themselves: `go test -run
  TestFlushRefusalLogsScope -count=1 ./httpsec/`.
- [x] 15.3 Record in `design.md` the package-name corrections (`authenticate`/`authorize`), the
  generic `authorize.Rule[Request]` signature, the `httpsec`-owned session context key, the reuse of
  `internal/nilcheck.IsNil` and `signingkey.KeyManager.JWKS`, both settled open questions, and the
  decision that form login binds from the POST body only (a credential in the URL query never
  authenticates, because it would reach access logs, proxy logs and Referer headers).
  Rewrite Decision 6: `policy.Engine` already guarantees a deny carries a reason, so its departure
  (b) is retired and `policy.ErrPolicyDenied` is the mapped sentinel. Amend the
  `http-error-propagation` spec's refusal-contract requirement and status table to name it instead
  of a separate httpsec sentinel. Verify `openspec validate http-security` passes.
- [x] 15.4 Write the `httpsec` and `outbound` package godoc, naming for every option the default it
  replaces and for every port what the library uses when the consumer supplies none. State the two
  narrowings the body-only login binding carries: a login body is read only when it declares
  `application/x-www-form-urlencoded`, so a `multipart/form-data` login is refused with
  `ErrCredentialsMissing`; and a urlencoded body that does not parse yields no credential rather
  than the pairs that did parse. State on `WithErrorHandler` that it governs the net/http chain
  only: gin refusals go to gin's error channel and fiber's to fiber's error handler, each by
  design. Verify `go doc ./httpsec` and `go doc ./outbound` show them.
- [x] 15.5 Run the full gate across every module and confirm it is green: `make check`.
