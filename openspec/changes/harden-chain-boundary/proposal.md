# Proposal

## Why

An adversarial audit of how the `httpsec` chain is configured and mounted found three security defects in the published `v0.1.0`. Each was reproduced with a failing test against the tagged tree:

- **The chain can approve a different path from the one fiber routes.** Fiber removes `.` and `..` segments before routing; the chain's rules read the path as sent. `GET /public/../admin/users` is permitted by a `/public` rule and served by the `/admin/users` handler.
- **The recovery cool-down can be bypassed the same way.** `/x/../account/delete` reaches a marked route inside the cool-down, breaking the promise that no lenient routing reaches a marked route.
- **A consumer authenticator placed after the gates skips them.** A session owing a second factor, a password change or an enrolment, published from a slot past the gates, reaches the handler with 200.

The same audit found wiring gaps that are not exploitable on their own but make misconfiguration silent:
- a chain mounted twice runs twice on a successful request;
- five single-value chain options keep the last value given without saying so, among them a second policy engine that escapes the unenforced-challenge check;
- each request rebuilds the interceptor fold.

These go out as `v0.1.1`, a patch release that retracts `v0.1.0`. No consumer runs scrty in production yet, so the fix is developed on an ordinary public branch and merged through a normal pull request with CI. It is disclosed through the changelog's `Security` entry and the retraction only, without a repository security advisory or a Go vulnerability database report. That is a one-time departure from `SECURITY.md`, recorded in design decision 8.

## What Changes

- **Non-canonical paths are refused at the chain's entry.** In every adapter, the chain answers `400` (`ErrMalformedRequest`) to a request whose path holds a `.` or `..` segment. The check reads the path as sent and decoded once, so `%2e%2e` and segments joined by `%2F` count. It also refuses a path whose percent-encoding does not decode. It runs after client resolution and before any interceptor, so the refusal carries the same security headers as any other, and it has no opt-out.
- **A session cannot be published once the gates have begun.** When a request enters the first enabled gate, the chain marks the exchange. Gates here means the recovery gate, the enrolment gate, the second-factor gate and the password-change gate. After that mark, `Exchange.PublishSession` refuses to publish a session, with a configuration error, and publishes nothing. Built-ins that set a session at or after the gates do it through an internal path.
- **Defence in depth at the authorization stage.** The authorization stage refuses a published session that still owes a built-in challenge, with that challenge's error, unless a gate's own exemption let it through.
- **A chain mounted twice runs once.** A chain marks the request context it ran on. When the same chain is entered again on that context, it passes the request straight to the terminal. Two different chains still each run, and the adapters document it.
- **BREAKING (configuration only).** `WithLogger`, `WithClock`, `WithPolicyEngine`, `WithRateLimiterFactory` and `WithErrorHandler` given more than once are refused at construction, like the `Enable*` options. `EnableAuthorization` keeps its documented last-wins authorizer. Every call's authorizer is checked, so a nil one in an earlier call no longer hides.
- **Dependencies follow the open Dependabot updates, and a token header must name its algorithm.** `lestrrat-go/jwx/v4` moves to 4.6.0, `testcontainers-go` and its modules to 0.45.0 (test module only), and CodeQL to 4.39.3. jwx 4.6.0 accepts a header with no `alg` when one key is given, which loosened the ID token hint check. Token verification and the hint check now refuse a header with no `alg` themselves. `token.Verifier` had accepted such a header since `v0.1.0`, against its own documentation.
- **The interceptor fold is built once, at construction.** `Assemble` hands each request's terminal to a fold built when the chain was, instead of allocating a closure per interceptor on every request. Behaviour is unchanged, and so is the API.
- **Documentation:**
  - fiber's case-insensitive and trailing-slash routing, and a rule written on `GET` that also has to cover `HEAD`, are stated where rules are written (`EnableAuthorization`, `PathPrefix`);
  - registering after routes leaves them unguarded on gin and fiber;
  - a consumer interceptor at a built-in's slot runs in option order.
- **Release:**
  - `v0.1.1` of all nine modules, with a `Security` changelog entry and `retract v0.1.0` in the root module.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `http-security-chain`:
  - non-canonical request paths are refused at entry;
  - consumer interceptors may not publish a session once the gates have begun;
  - the authorization stage refuses a session owing a built-in challenge;
  - a chain entered twice on one request runs once;
  - single-value options given twice fail at construction.
- `framework-adapters`: every adapter refuses non-canonical paths alike; mounting a chain twice runs it once.
- `token-issuance`: verification refuses a token whose header names no algorithm.
- `oidc-provider-authorization`: an ID token hint whose header names no algorithm is refused.

## Impact

- **Code:**
  - core `httpsec`: `chain.go`, `exchange.go`, `options.go`, `authorization.go`, the four gate interceptors, and every built-in that publishes a session;
  - godoc in `httpsec/fibersec` and `httpsec/ginsec`;
  - the shared conformance suite in `test/httpsecconformance`.
- **API:**
  - no exported identifier is added or removed;
  - `PublishSession` gains a documented refusal;
  - five options gain a refusal of a second call;
  - requests with dot segments now get `400` where they used to be served.
- **Release:**
  - `v0.1.1` for the nine published modules, with `retract v0.1.0` in the root `go.mod`;
  - a `CHANGELOG.md` `Security` entry;
  - no repository security advisory and no Go vulnerability database report (design decision 8).
- **Process:**
  - development happens on the public branch `fix/harden-chain-boundary`, merged through an ordinary pull request with CI and branch protection;
  - `release-readiness` must land its release-probe trigger fix first, because `v0.1.1` is the first release to use the revised tag push.
