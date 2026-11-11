# Tasks

Every task is test-first: write the failing test, run it, confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor with the suite green. Table tests follow the project's `table-test` skill; test doubles of `telemetry.Observer` come from `use-mockgen`, placed by the package that consumes them.

## 1. The seam (`observability`)

- [ ] 1.1 Create the core package `pkg/telemetry`, importing only the standard library:
  - `Observer` (`Start`, `End`, `Event`);
  - `Operation`, `Outcome` (success, refused with a name, error with a Go type) and `Event`;
  - the documented operation names and the event vocabulary as named constants;
  - a helper that starts an operation, runs a function under the returned context, and ends it exactly once, including on panic (it re-panics) and cancellation, calling nothing when the observer is nil.

  Tests:
  - a nil observer is never called;
  - one end per start on success, refusal, error and panic;
  - an error outcome carries `%T` and never the text;
  - the function runs under the context `Start` returned.

  (D2, D5; "Telemetry is off unless an observer is given", "Every instrumented operation is started and ended exactly once", "Outcomes are bounded and never carry error text", "Operations have stable names", "Security events use a fixed vocabulary".) Verify with `go test -race -count=1 ./pkg/telemetry/`

## 2. The chain (`http-security-chain`)

- [ ] 2.1 `httpsec.WithTelemetry(o)`. One operation per request a built-in endpoint answers:
  - the endpoint is matched from the endpoint list, by method and path under each entry's match kind;
  - the operation is named by its identifier without `scrty.`;
  - the outcome comes from the returned error: none is success, a library refusal is refused with its name, anything else is an error with its Go type;
  - the user and client address are handed over where resolved;
  - the exchange runs under the context `Start` returned.

  Tests: a successful and a refused login each give one `login` operation; a request to a consumer route starts none; a chain without the option calls nothing. (D2, D3; "The chain reports its endpoints and decisions to a telemetry observer", scenarios "Successful login" and "Consumer route not an operation".) Verify with `go test -race -count=1 -run 'TestTelemetry' ./httpsec/`
- [ ] 2.2 Report security events where the chain decides:
  - logins: `authn_login_success`, `authn_login_fail`, `authn_login_lock`;
  - throttles: `excess_rate_limit_exceeded`, including from the source guards the chain builds;
  - second factors: `authn_mfa_success`, `authn_mfa_fail`;
  - re-proofs: `authn_reauth_success`, `authn_reauth_fail`;
  - password changes: `authn_password_change`, `authn_password_change_fail`;
  - logout: `session_logout`;
  - authorization refusals: `authz_fail`.

  A table test has one row per event, including "Authorization refusal" and "Chain-built source guard". (D3, D5; same requirement, every remaining scenario.) Verify with `go test -race -count=1 -run 'TestTelemetryEvents' ./httpsec/`
- [ ] 2.3 Every chain log record written while serving a built-in endpoint uses the operation's context. A test observer adds a marker to the context, and a capturing `slog.Handler` asserts that the login refusal record carries it, while the suppressed-refusal summary keeps its own context. (D7; "Chain log records carry the operation's context".) Verify with `go test -race -count=1 -run 'TestTelemetryLogContext' ./httpsec/`

## 3. Components (`sessions`, `authentication`, `password-encoding`, `signing-keys`, `expiry-sweeping`)

- [ ] 3.1 `session.WithTelemetry(o)`: `session.create`, `session.rotate` and `session.renew` operations with the session's user, and the events `session_created`, `session_renewed` and `authn_token_reuse`. The reuse observer still receives its report when both are given, and no session identifier reaches the telemetry observer. (D3, D4; `sessions` "The session manager reports to a telemetry observer", every scenario.) Verify with `go test -race -count=1 ./session/`
- [ ] 3.2 `authenticate.WithPasswordTelemetry(o)` on `NewUsernamePasswordAuthenticator`: `password.verify` under the call's context around every match, the decoy included. Tests:
  - a wrong password and an unknown user each give one refused `password.verify`;
  - a right password gives success;
  - neither the password nor the hash reaches the observer.

  (D3; `authentication` "The password authenticator reports each verification", every scenario.) Verify with `go test -race -count=1 ./authenticate/`
- [ ] 3.3 `password.WithReuseTelemetry(o)` on the reuse guard: `password.verify` per history check and `password.hash` for the accepted hash. The guard's decisions are unchanged, and no candidate or hash reaches the observer. (D3; `password-encoding` "The reuse guard reports its password work", every scenario.) Verify with `go test -race -count=1 ./authenticate/password/`
- [ ] 3.4 `signingkey.WithTelemetry(o)`: a `signingkey.rotate` operation per rotation attempt, with the algorithm as its method. A failure ends with an error outcome and the event `crypt_key_rotate_fail`, and no key material reaches the observer. (D3; `signing-keys` "The key manager reports rotations to a telemetry observer", every scenario.) Verify with `go test -race -count=1 ./token/signingkey/`
- [ ] 3.5 `expiry.WithTelemetry(o)`: an `expiry.run` operation per task run, with the task name as its method. The result observer still receives every result, and one task's failure leaves the others' operations unaffected. (D3, D8; `expiry-sweeping` "The runner reports each task run to a telemetry observer", every scenario.) Verify with `go test -race -count=1 ./expiry/`

## 4. What the observer is handed (`observability`, `diagnostic-redaction`)

- [ ] 4.1 An end-to-end test plants known secrets and checks that none reaches a recording observer:
  - the secrets: a password, a TOTP code, the session identifier, the issued token, and a sender error quoting `alice@example.com`;
  - the flows: a login, a second-factor verification, a renewal and a failing magic-link send;
  - the observer *does* receive `u-1` and `203.0.113.7` for the login.

  Each component's godoc names the user reference and client address as deliberately handed. Show the red step by temporarily passing the dependency error's text into one outcome, and watching the test fail. (D4; "The observer receives the subject, never a secret", `diagnostic-redaction` "A telemetry observer receives no dependency error text", every scenario.) Verify with `go test -race -count=1 -run 'TestTelemetryHandsNoSecrets' ./httpsec/`

## 5. The OpenTelemetry adapter (`observability`, `module-layout`)

- [ ] 5.1 Create the module `github.com/kartaladev/scrty/pkg/telemetry/oteltelemetry` (package `oteltelemetry`):
  - it requires the root module and the OpenTelemetry API modules (`otel`, `otel/trace`, `otel/metric`), never the SDK;
  - `go.work` lists it;
  - the layout guard adds it to the listed integrations, refuses any `go.opentelemetry.io/` requirement in the core module, and refuses an SDK requirement in the adapter;
  - the red step is the guard's new rows failing before the module exists.

  (`module-layout` "The core module does not require OpenTelemetry", every scenario; "Integration modules are published under the concept they extend".) Verify with `go test -count=1 .` at the root and `go build ./...` in the new module
- [ ] 5.2 Implement the adapter:
  - `New(opts...)` with `WithTracerProvider` and `WithMeterProvider`, falling back to the globals, and the instrumentation scope named by module path and version;
  - internal spans `scrty.<operation>` as children of the given context's span, with `scrty.outcome` and `error.type`;
  - events added to the adapter's own span and counted;
  - `scrty.operation.duration` (seconds, with the HTTP duration bucket boundaries advised) and `scrty.security.events` (`{event}`), with the attributes D5 lists;
  - `WithUserAttribute()` and `WithClientAddressAttribute()`, spans only.

  Its tests live in the `test` module, which may require the SDK's in-memory exporter and reader. They cover:
  - span names, parents, attributes and `error.type`;
  - both instruments, their units and attributes;
  - fifty refused logins counted while the refusal log writes one record;
  - no `u-1` or address by default, `user.id` on spans only when enabled, never on metrics;
  - injected providers receiving everything and the globals nothing.

  (D6; "The OpenTelemetry adapter emits spans named for the operation", "The OpenTelemetry adapter records two metrics", "Personal data stays off by default, and never reaches metrics", "The adapter's providers are replaceable", every scenario.) Verify with `go test -race -count=1 ./...` in `test` and `go vet ./...` in the adapter module
- [ ] 5.3 `RouteLabeler(chain)` returns, for a request a chain endpoint answers, its listed route (`POST /auth/mfa/verify/totp` gives `/auth/mfa/verify/{method}`), and nothing for a consumer route. It never sets an attribute itself. An `Example` shows it beside the consumer's server instrumentation. A README telemetry section covers:
  - the operation names and the event vocabulary;
  - the attribute policy;
  - how to wire logs (`otelslog`), stores (`otelpgx`, `otelgorm`), Redis (`redisotel`) and outbound calls (`outbound.WithHTTPClient` with `otelhttp`).

  (D6, D7; "Chain routes can label the consumer's server span", every scenario.) Verify with `go test -race -count=1 ./...` in the adapter module, including the example

## 6. Conformance

- [ ] 6.1 Add a `test/httpsecconformance` scenario on net/http, gin and fiber: with a recording observer, a successful login and a refused one each give one `login` operation and the matching events, identically on every adapter. Verify with `go vet ./...` and `go test -race ./...` in `test`

## 7. Close-out

- [ ] 7.1 Run the whole-workspace gate:
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module listed by `go list -m`, the new adapter module included;
  - `gofmt -l` empty over tracked Go files;
  - `openspec validate observability --strict`.

  Verify that every command exits 0 and record its output.

## Workflow follow-up

- Implementation starts after `endpoint-inventory-base-path` is merged, because the chain's operations are named and matched from its endpoint list. It can run beside `openapi-document`.
- Run one whole-branch review against every spec requirement this change covers before the final gate and before archive.
- `openapi-document` also modifies `module-layout`'s requirement "Integration modules are published under the concept they extend". Whichever change archives second rebases its copy of that requirement onto the archived one first, so the listed modules include both `openapisec` and `oteltelemetry`.
- If `release-readiness` has fixed the list of lockstep-tagged modules by then, add `pkg/telemetry/oteltelemetry` to it.
- At archive, update `openspec/config.yaml`:
  - `pkg/telemetry` joins the non-security helpers;
  - `pkg/telemetry/oteltelemetry` joins the Layout integrations;
  - `observability` joins the capability map.
