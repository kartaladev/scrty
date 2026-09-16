## Why

scrty has its authentication, authorization, session, policy and token cores. None of them can yet be put in front of an HTTP handler. Every consumer would otherwise wire the same things by hand, and get them subtly different:
- which interceptor runs first;
- what reaches the handler's context;
- which status a refusal becomes;
- which address a rate limit is keyed on;
- what an outbound fetch to a provider may follow.

HTTP is also where refusals are most easily turned into oracles, open redirects or log floods. This change makes those decisions once, fails closed when nothing is configured, and leaves rendering to the consumer.

## What Changes

- Add `httpsec`, a framework-agnostic security core over a small request/response abstraction, with net/http as the default adapter and gin and fiber adapting natively:
  - an ordered around-interceptor chain whose interceptors can continue, stop the request, or act after the handler;
  - exported, spaced slots with before/after helpers, and consumer-registered interceptors at any slot;
  - chain assembly that reports every wiring mistake from the constructor, before traffic.
- Built-in interceptors:
  - form login;
  - HTTP Basic authentication;
  - bearer token authentication against a live session;
  - a password-change gate with an optional consumer resolve endpoint;
  - logout;
  - session activity write-back;
  - a public key set endpoint;
  - the authorization stage.
- Both authorization models:
  - centralized matcher rules enforced in the chain, which must be chosen explicitly or explicitly waived;
  - per-endpoint guards that fail closed.
- Error propagation instead of rendering:
  - refusals travel up the chain as errors, and the sentinels and the challenge error type are the public contract;
  - a public status-only mapping is provided, and a policy refusal with no reason maps to 403;
  - with nothing wired, a refusal is a bare status code with no body and no error text.
- Client address handling:
  - the transport peer is the default;
  - forwarded-header resolution is opt-in, only through gin's or fiber's own trusted-proxy configuration;
  - an empty, malformed or unspecified (`0.0.0.0`, `::`) address is refused, never pooled.
- Refusal logs from the chain are sampled with `pkg/logsample`. A summary reporter is always configured and can be replaced, and pending counts can be flushed.
- Seams for the redemption flows other changes add: named slots, a shared login completion step and a per-source throttle step. The magic-link, API-key, step-up and OIDC interceptors themselves are not in this change.
- Add the `ginsec` and `fibersec` integration modules:
  - each runs the same chain with the same outcomes;
  - security state reaches the framework's native request context;
  - refusals reach gin's error channel, with a fail-closed status when nothing handles them, or fiber's error handler, with an opaque error and a small mapping helper.
- Add outbound HTTP confinement for requests the library itself makes, such as key set fetches and provider discovery or token calls:
  - allowed schemes and hosts;
  - redirects capped and kept on the starting origin;
  - a re-check of the final URL;
  - no replay of a credential-bearing body to another origin;
  - timeouts and response-size limits.

  It also validates browser redirect targets: host-relative, or on an origin the consumer declared.
- Add an adapter conformance suite in the `test` module that runs every chain scenario through `net/http`, gin and fiber.

## Capabilities

### New Capabilities

- `http-security-chain`: the ordered interceptor chain, its slots and seams, the built-in authentication, session and authorization interceptors, client address resolution, and sampled refusal logging.
- `http-error-propagation`: how refusals leave the chain as errors, the public refusal contract, the status mapping, and the fail-closed default response with its net/http override.
- `framework-adapters`: running the same chain on gin and fiber with identical outcomes, native context propagation, and each framework's own error channel and override.
- `outbound-http-confinement`: bounding and confining the HTTP requests scrty itself sends, and validating redirect targets it hands to a browser.

### Modified Capabilities

None. No specs have been archived yet.

## Impact

- **New code in the core module:**
  - `httpsec`, with the chain, the built-in interceptors, guards, the client address resolvers and the status mapping;
  - `outbound`, the confined client;
  - `internal/origin`, the origin comparison and redirect-target validation.
- **New nested modules:**
  - `ginsec`, which depends on gin;
  - `fibersec`, which depends on fiber v3 and fasthttp.
  - The core module gains no third-party dependency.
- **Test module:** an HTTP adapter conformance suite in `github.com/kartaladev/scrty/test`.
- **Depends on other changes:**
  - `authentication`, `authorization`, `sessions`, `security-policy`, `rate-limiting` (authn-authz-core);
  - `identity-model`, `token-issuance`, `signing-keys` (identity-and-tokens);
  - `log-sampling` and `module-layout` (project-foundation).
- **Consumed by later changes:**
  - `auth-methods` plugs magic-link redemption, API keys and the second-factor step-up into the slots and seams defined here;
  - `oidc-brokering` plugs in the authorize, callback and handoff interceptors, and uses outbound confinement and redirect-target validation;
  - `bff-resource-server` builds on the chain.
- **Consumers:** none yet. Nothing is tagged, so every default here is recorded as a decision, not a compatibility obligation.
