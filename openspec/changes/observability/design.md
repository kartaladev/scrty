# Design

## Context

See proposal.md for the motivation.

- **Logs.** scrty logs through `slog` (`WithLogger` on each component). The chain's refusal records are sampled (`log-sampling`). Dependency error text never reaches a record (`diagnostic-redaction`), apart from its stated exceptions: the throttled source address, the opaque user reference in second-factor and policy records, and the email domain in linking records.
- **Three domain observers already exist:** `lockout.WithObserver` (lock, hold and release reports), `expiry.WithObserver` (one result per task run) and `session.WithReuseObserver` (detected reuse, carrying the user). Two of them are named `WithObserver`.
- **There are no metrics and no traces.**
- **Outbound calls already have a seam.** `outbound.WithHTTPClient` accepts a consumer's `*http.Client`, so an instrumented transport is possible today.
- **The endpoint inventory** (`endpoint-inventory-base-path`) gives each built-in endpoint a stable operation identifier and a resolved route.
- **The core's dependencies are guarded.** The OTel API module currently requires `logr`, `stdr`, `xxhash`, `auto/sdk`, `otel/log`, `otel/metric` and `otel/trace` (read from its `main` branch on 2026-11-01).

## Goals / Non-Goals

**Goals:**
- Traces, metrics and correlated logs for the signals only scrty can produce, with no cost and no dependency for a consumer who does not use them.
- The safe default for personal data, and an explicit way to opt in.

**Non-Goals:**
- Instrumenting stores, Redis, SMTP or outbound HTTP, which already have OTel adapters.
- HTTP server metrics such as `http.server.request.duration`, which belong to the consumer's server instrumentation around their whole application.
- Replacing or folding the three domain observers. That is a later question.
- An OTel SDK, exporters or their configuration. Those are the application's.

## Decisions

### D1. A seam in the core, OpenTelemetry in a nested module

- **Placement.** A new core package `pkg/telemetry` holds the seam.
  - It is a non-security helper, so it sits under `pkg/` beside `pkg/logsample`, as the project's layout convention places such helpers.
  - It imports nothing outside the standard library, so `httpsec`, `session`, `authenticate`, `authenticate/password`, `token/signingkey` and `expiry` can all import it without a cycle.
  - The OTel implementation is the nested module `pkg/telemetry/oteltelemetry` (package `oteltelemetry`), placed under the concept it extends, as `module-layout` requires.
- **Precedent:**
  - pgx v5's `QueryTracer` (`TraceQueryStart` returning a context, `TraceQueryEnd`), with `otelpgx` as a separate module;
  - grpc-go's `stats.Handler` (`TagRPC` returning a context, `HandleRPC`), with `otelgrpc` in opentelemetry-go-contrib;
  - go-redis's `Hook`, with `extra/redisotel` and `extra/redisprometheus` as nested modules.
- **Naming.** The options are `WithTelemetry`, not `WithObserver`. `lockout.WithObserver` and `expiry.WithObserver` already take domain observers of other types, and one name must not mean two things.
- **Alternatives rejected:**
  - *The OTel API in the core.* It is OTel's preferred native shape, but about eight modules would land in every consumer's graph, including those who never use OTel. It would also be inconsistent with `openapi-document`'s nested module.
  - *Events only, with no spans.* That drops traces and durations.

### D2. The seam

```go
package telemetry // github.com/kartaladev/scrty/pkg/telemetry

type Observer interface {
    // Start begins op and returns the context the operation runs under; an
    // implementation puts its span there, so everything downstream inherits it.
    Start(ctx context.Context, op Operation) context.Context
    // End finishes the operation ctx was returned for, exactly once.
    End(ctx context.Context, out Outcome)
    // Event reports a point-in-time security event.
    Event(ctx context.Context, ev Event)
}
```

- **Types:**
  - `Operation` carries a name from the bounded set (D5), the method, and the user reference and client address where known;
  - `Outcome` is success, a refusal, or an error (its Go type, never its text). A refusal's name comes from the sentinel registry: the identifier without `Err`, in snake case. There is one exception: a `password.verify` that did not match is refused as `password_mismatch`, because the encoder answers with a boolean and no sentinel;
  - `Event` carries a vocabulary name (D5), the method, the outcome and the same optional subject fields.
- **Contract:**
  - calls are synchronous, on the caller's goroutine, and must not block;
  - `End` runs exactly once per `Start`, including on refusal, error, cancellation or panic, through a deferred call;
  - scrty writes its own log records with the context `Start` returned.
- **Default:** no observer. The instrumented code checks for nil and calls nothing, so a consumer pays a nil check.
- **Override:** any implementation of `Observer`, for example an audit sink or a Prometheus mapping. `oteltelemetry` is one implementation.

### D3. Reach

| Component | Seam | Reports |
|---|---|---|
| `httpsec` chain | `WithTelemetry(o)` | Start/End around every built-in endpoint (operation = inventory identifier); events for logins, refusals, lockouts, throttles, MFA and re-proof outcomes; handed to the components the chain builds (challenge managers, recovery, source guards) |
| `session` | `WithTelemetry(o)` | `session_created`, rotations (Start/End), renewals, `authn_token_reuse` |
| `authenticate` (password authenticator) | `WithPasswordTelemetry(o)` | Start/End (`password.verify`) around every match, the decoy check included |
| `authenticate/password` (reuse guard) | `WithReuseTelemetry(o)` | Start/End (`password.verify`) per history check; `password.hash` for the new hash |
| `token/signingkey` | `WithTelemetry(o)` | Start/End around each rotation; failures |
| `expiry` | `WithTelemetry(o)` | Start/End around each task run |

- **Why passwords are observed at their callers, not with a decorator.**
  - **A decorator would lose the trace.** `password.Encoder`'s methods take no context (`Encode(input)`, `Match(input, encoded)`). A decorator over it would start every `password.verify` span without the request's context, so the span would be an orphan, detached from the login it belongs to.
  - **The callers hold the context.** The encoder's two request-time callers are `UsernamePasswordAuthenticator.Authenticate` and `VerifyDecoy`, and `ReuseGuard.Check` and `Change`. Each takes the observer through an option of its own.
  - **The decoy is reported like a real check.** The decoy match runs for an unknown user so that timing reveals nothing. It is reported as `password.verify` too, so telemetry timing gives away nothing the response doesn't.
  - **Cost:** a consumer's own `Authenticator` is not covered. They instrument it themselves, as with any component of their own.
  - **Alternative rejected: a context on `Encoder`.** It would break every encoder, including consumers', for telemetry alone, and hashing cannot be cancelled, so a context buys nothing else.
- **What the chain hands on.** It gives its observer to the components it builds itself, as it already gives them its logger and clock. Components the consumer builds take their own option, so no option governs a subsystem it does not own.
- **Not instrumented:** stores, Redis, notification senders and outbound HTTP. The README shows `otelpgx`, `otelgorm`, `redisotel` and `outbound.WithHTTPClient` with an `otelhttp` transport. That follows OTel's guidance not to duplicate instrumentation of the underlying client.

### D4. What the observer is handed

- **Handed:** the operation, the method, the outcome, and the **user reference and client address** where the component knows them.
  - An audit observer needs the subject and the source, as OWASP's vocabulary expects.
  - `session.ReuseReport` already hands the user to a consumer observer.
  - The observer is consumer code, and its godoc says that it receives personal data.
- **Never handed:** tokens, session identifiers, codes, passwords, password hashes, or a dependency's error text. A dependency failure is the fixed reason and the error's Go type, exactly as `diagnostic-redaction` requires of log records.
- **`diagnostic-redaction` gains a requirement of its own for the observer,** beside the existing one for log records. It names the observer and the two fields as a stated exception, which is what "stated exceptions are deliberate and documented" asks of any new personal data. The existing requirement governs log records and stays unchanged, so another change touching it cannot conflict with this one.

### D5. Names and attributes

- **Namespace.** `scrty.` is short and unique. OTel reserves `otel.*` and advises against prefixing with an existing convention namespace.
- **Spans.** Each span is named `scrty.<operation>` and is an internal span, a child of the consumer's server span. Examples: `scrty.login`, `scrty.mfa.verify`, `scrty.reauth.verify`, `scrty.password.verify`, `scrty.session.rotate`, `scrty.signingkey.rotate`, `scrty.expiry.run`.
- **Metrics:**
  - `scrty.operation.duration`: a histogram in `s`, with `scrty.operation`, `scrty.method`, `scrty.outcome` and `error.type`;
  - `scrty.security.events`: a counter in `{event}`, with `scrty.event`, `scrty.method`, `scrty.outcome` and `error.type`.

  These two cover every signal. A new event adds a value, not a metric. The names follow OTel's rules: dots between namespaces, a plural only for a count of discrete things, units on the instrument, and no `_total`.
- **Attributes:**
  - `scrty.operation`: the bounded operation set.
  - `scrty.method`: `password`, `passkey`, `totp`, `apikey`, or a configured provider name. All are configuration, and all are bounded.
  - `scrty.outcome`: `success`, `refused` or `error`.
  - `error.type`: the refusal name in snake case (`invalid_credentials`, `mfa_method_not_usable`) or the dependency error's Go type. It falls back to `_OTHER`, and is unset on success. It is stable in OTel's semantic conventions, which require it to be predictable and low-cardinality.
  - `scrty.event`: OWASP Logging Vocabulary names verbatim where one exists (`authn_login_success`, `authn_login_fail`, `authn_login_lock`, `authn_token_reuse`, `session_created`, `session_renewed`, ...). scrty additions use the same style (`authn_reauth_success`, `authn_mfa_fail`, ...). Both are listed in the spec.
- **No authentication convention exists in OTel.** `user.id` (and the older `enduser.id`) is at development stage and carries a PII warning. It is used only when the user opts in (D6).

### D6. The OpenTelemetry adapter

- **Providers.** `oteltelemetry.New(opts...)` takes `WithTracerProvider` and `WithMeterProvider` and falls back to the global providers, as OTel's library guidance describes. The instrumentation scope is the module path and its version.
- **Default:** bounded, non-personal attributes only.
- **Overrides:**
  - `WithUserAttribute()` adds `user.id` to spans;
  - `WithClientAddressAttribute()` adds `client.address` to spans;
  - neither ever reaches a metric. An option that would put either on a metric does not exist, because unbounded values break metrics. This is a stated limit, as `library-design` rule 4 requires.
- **Histogram buckets.** The adapter advises the explicit boundaries OTel's HTTP conventions use for durations. A consumer changes them with SDK views.
- **Refusals stay unsampled.** Metrics count every refusal, while the refusal logs stay sampled. The two complement each other.
- **Events.** Each event increments the counter and is added as a span event to the span the adapter itself started for that operation, never to the active span it did not create.
- **The adapter's tests live in the `test` module.** Asserting recorded spans and metrics needs the SDK's in-memory exporter and reader. A test-only requirement still enters a module's `go.mod`, so those tests live where integration tests already do, and the adapter module requires the API alone.
- **Routes, by explicit helper.** `oteltelemetry.RouteLabeler(chain)` returns a function the consumer passes to their server instrumentation. It names the inventory route of a chain endpoint. It is never applied implicitly.

### D7. Logs

- **`slog` is unchanged.** OTel logs come from the consumer passing a logger with the `otelslog` bridge's handler.
- **Correlation.** Every record scrty writes during an instrumented operation uses the context `Start` returned, so the bridge attaches the trace and span identifiers. A test asserts this for the chain's records.
- **Records not tied to a request** keep `context.Background()`, as `summariseRefusals` already does on purpose.

### D8. Existing observers

- `lockout.WithObserver`, `expiry.WithObserver` and `session.WithReuseObserver` keep their contracts and run as before.
- The components that have them also emit the matching telemetry events, so a consumer can use either or both.
- Folding them into the seam would break them, and is left as a later decision.

## Risks / Trade-offs

- **A slow observer slows every request.** → The godoc requires a fast, non-blocking observer. The OTel API is designed for that, and `oteltelemetry` adds nothing beyond it.
- **Personal data reaches a consumer's observer.** → Stated in its godoc and in `diagnostic-redaction`. The library's own adapter leaves it off by default.
- **The event vocabulary grows and dashboards drift.** → Names are a documented contract in the spec. Adding a value is additive. Renaming one is a compatibility decision.
- **OTel semantic conventions later define authentication attributes.** → The adapter can adopt them, with a compatibility note. The core's seam is unaffected.
- **Six components gain an option, and wiring them is repetitive.** → One observer value serves all of them. `di-wiring` can automate it later.

## Migration Plan

Nothing to migrate: telemetry is opt-in, and the existing observers are unchanged. A consumer:

1. Adds `pkg/telemetry/oteltelemetry`.
2. Builds one observer.
3. Passes it to the chain and to the components listed in D3.

## References

### Researched (accessed 2026-11-01)

**D1: seam in the core, adapter outside**
- [OpenTelemetry: Instrumenting libraries](https://opentelemetry.io/docs/concepts/instrumentation/libraries/): depend on the API only; native instrumentation is preferred, though a separate package is an option while it stabilises; providers may be injected with a global fallback; instrument public operations and not their underlying clients; "when in doubt, don't instrument".
- [opentelemetry-go `go.mod` (main branch)](https://raw.githubusercontent.com/open-telemetry/opentelemetry-go/main/go.mod): the API module's requirements. Read from `main`, so a tagged release may differ, and the figure drifts.
- [pgx v5 `tracer.go`](https://github.com/jackc/pgx/blob/master/tracer.go) and [exaring/otelpgx](https://github.com/exaring/otelpgx): a start/end tracer interface in the driver, with OTel in a separate module.
- [grpc-go `stats/handlers.go`](https://github.com/grpc/grpc-go/blob/master/stats/handlers.go): `TagRPC` returning a context, and `HandleRPC`.
- [go-redis `redis.go`](https://github.com/redis/go-redis/blob/master/redis.go) and [`extra/`](https://github.com/redis/go-redis/tree/master/extra): `Hook`, with `redisotel` and `redisprometheus` as nested modules.

**D5, D6: names, attributes, personal data**
- [OTel semantic conventions: naming](https://opentelemetry.io/docs/specs/semconv/general/naming/): dot namespaces, snake_case within them, plurals only for discrete counts, units on the instrument, no `_total`, `otel.*` reserved, an application prefix for custom names.
- [OTel attribute registry: error](https://opentelemetry.io/docs/specs/semconv/registry/attributes/error/): `error.type` is stable, predictable and low-cardinality, with an `_OTHER` fallback; `error.message` is deprecated and not recommended for spans or metrics.
- [OTel attribute registry: enduser](https://opentelemetry.io/docs/specs/semconv/registry/attributes/enduser/): `enduser.id` is at development stage with a PII warning; older releases point to `user.id`. Read through search summaries.
- [OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html): the `authn_`, `authz_` and `session_` event names reused for `scrty.event`.

**D7: logs**
- [otelslog bridge](https://github.com/open-telemetry/opentelemetry-go-contrib/tree/main/bridges/otelslog): an `slog` handler that sends records to the OTel logs API and correlates them through the context.

**D2, D3, D4, D8**
- Reasoned from scrty's own settled specs (`http-security-chain`, `sessions`, `authentication`, `password-encoding`, `signing-keys`, `expiry-sweeping`, `diagnostic-redaction`, `log-sampling`, `module-layout`) and the decisions taken while exploring this change.

### Primary documentation

- [OTel semantic conventions: HTTP metrics](https://opentelemetry.io/docs/specs/semconv/http/http-metrics/): the duration histogram's unit and advised bucket boundaries, reused in D6.
- [OpenTelemetry Go API](https://pkg.go.dev/go.opentelemetry.io/otel): `TracerProvider`, `MeterProvider` and the global providers.
