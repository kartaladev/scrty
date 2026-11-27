# Proposal

## Why

Operators running scrty see only sampled log lines. They cannot chart login failure rates, lockouts, session reuse, re-authentications or MFA outcomes. They cannot see how long password hashing takes, or whether key rotation and expiry sweeps are healthy. A consumer who traces with OpenTelemetry sees a gap wherever scrty works. Every consumer who wants these signals has to wrap scrty's components and guess at outcomes the library already knows.

OpenTelemetry's guidance for library authors is to emit telemetry natively and to do nothing when unconfigured. scrty's `module-layout` keeps protocol libraries out of the core. The established Go answer to both is a small hook interface in the library with the OTel adapter shipped separately, which is what pgx, grpc-go and go-redis do.

## What Changes

- **A telemetry seam in the core,** in a new dependency-free package `pkg/telemetry`, beside `pkg/logsample`:
  - an `Observer` with `Start(ctx, Operation) context.Context`, `End(ctx, Outcome)` and `Event(ctx, Event)`;
  - a bounded operation set and a security-event vocabulary that reuses OWASP's logging vocabulary names (`authn_login_fail`, `authn_login_lock`, `authn_token_reuse`, `session_created`, ...);
  - no observer means nothing is called.
- **Where it reaches:**
  - **the chain:** `httpsec.WithTelemetry(o)`. One operation per built-in endpoint, named by its inventory operation identifier, plus events for the decisions it makes, including the components the chain builds itself;
  - **sessions:** `session.WithTelemetry(o)`. Created, rotated, renewed, reuse detected;
  - **password work:** `authenticate.WithPasswordTelemetry(o)` on the library's password authenticator, and `password.WithReuseTelemetry(o)` on the reuse guard, the two callers of the password encoder that hold the request's context;
  - **signing keys:** `signingkey.WithTelemetry(o)`. Rotation and its failures;
  - **expiry:** `expiry.WithTelemetry(o)`. One operation per task run.
- **What it hands the observer:**
  - the operation, the method, the outcome (success, a refusal named from the bounded sentinel set, or an error with its Go type), and the user reference and client address where known;
  - never tokens, session identifiers, codes, passwords or a dependency's error text.
- **A new nested module, `github.com/kartaladev/scrty/pkg/telemetry/oteltelemetry`,** that implements the observer with OpenTelemetry traces and metrics:
  - **providers:** injected, falling back to the global ones;
  - **spans:** `scrty.<operation>`;
  - **metrics:** `scrty.operation.duration` (histogram, seconds) and `scrty.security.events` (counter);
  - **attributes:** `scrty.operation`, `scrty.method`, `scrty.outcome`, `scrty.event`, and `error.type` carrying the refusal name;
  - **personal data:** the user reference and client address are left off by default. An option adds them to spans only. They never become metric attributes;
  - **routes:** an explicit helper sets `http.route` on the consumer's own server span for chain endpoints, since the chain has no router to do it.
- **Logs stay on `slog`.** A consumer who wants OTel logs passes a logger backed by the `otelslog` bridge. Every record scrty writes during an operation carries that operation's context, so the bridge correlates it with the trace.
- **Infrastructure is not instrumented twice.** For stores, Redis and outbound calls the documentation shows the existing adapters (`otelpgx`, `otelgorm`, `redisotel`, an `otelhttp` transport through `outbound.WithHTTPClient`).
- **Existing observers are unchanged:** `lockout.WithObserver`, `expiry.WithObserver` and `session.WithReuseObserver` keep their contracts.

## Capabilities

### New Capabilities

- `observability`:
  - the telemetry seam, its operation set and event vocabulary;
  - what an observer is and is not handed;
  - the OpenTelemetry adapter, its names, attributes and defaults.

### Modified Capabilities

- `http-security-chain`: the chain reports its endpoints' operations and its security decisions to a telemetry observer.
- `sessions`: the session manager reports creation, rotation, renewal and detected reuse.
- `authentication`: the password authenticator reports each password verification, the decoy check included, with its duration.
- `password-encoding`: the reuse guard reports the history checks and the new hash.
- `signing-keys`: the key manager reports rotations and their failures.
- `expiry-sweeping`: the runner reports each task run as an operation.
- `diagnostic-redaction`: a new requirement for what a telemetry observer is handed, alongside the one for log records. A dependency failure reaches it as a fixed reason and a Go type, never as text. The user reference and client address are its only personal data, named as a stated exception.
- `module-layout`:
  - `pkg/telemetry/oteltelemetry` joins the listed integration modules;
  - the core module must not require `go.opentelemetry.io/otel` or any of its modules.

## Impact

- **New core package** `pkg/telemetry`, a leaf with no dependencies, so every instrumented package can import it without a cycle. It sits under `pkg/` with the project's other non-security helpers.
- **New module** `pkg/telemetry/oteltelemetry`, requiring the root module and the OTel API modules (`otel`, `otel/trace`, `otel/metric`). It never requires the OTel SDK.
- **Code:**
  - `httpsec`: the option, Start/End around each built-in endpoint, events at its decisions, and handing the observer to the components the chain builds;
  - `session`, `authenticate` (the password authenticator), `authenticate/password` (the reuse guard), `token/signingkey`, `expiry`: an option each, and their call sites.
- **Tests:**
  - unit tests per component, with a recording observer;
  - in the OTel module, an in-memory exporter and reader asserting names, attributes, units and the absence of personal data by default;
  - conformance on net/http, gin and fiber.
- **Docs:**
  - a README section on telemetry, the event vocabulary, the attribute policy;
  - how to wire logs, stores and outbound calls with the existing OTel adapters.
- **Builds on** `endpoint-inventory-base-path`, for operation identifiers and routes. Can run beside `openapi-document`.
- **No schema change.**
