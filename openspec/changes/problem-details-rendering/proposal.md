# Proposal

## Why

scrty refuses requests with typed errors and, by design, renders nothing: a bare status, and a consumer error handler that owns the body. Every consumer who wants a useful body therefore writes the same mapper, and it is easy to get wrong in ways that matter to security. One example is a 401 that tells a wrong password apart from a user-store outage, which reopens the oracle `StatusForError` closes. Another is an MFA challenge that a client cannot tell from a failed login. A third is a challenged login whose new access token is never delivered.

`github.com/kartaladev/prblm` renders Go errors as RFC 9457 problem details for net/http, and ships gin and fiber adapters (`ginprblm`, `fiberprblm`). Its core is standard-library only, so it is a cheap dependency for an opt-in module. scrty should ship one tested mapping of its refusals onto prblm problems, so a consumer who adopts prblm gets correct client-facing errors on every framework scrty supports, without writing the mapping themselves.

## What Changes

- **New nested module `github.com/kartaladev/scrty/httpsec/prblmsec`**, package `prblmsec`. It requires `github.com/kartaladev/prblm` and the scrty core, and nothing else in production code.
  - `prblmsec.New(opts...) (*Problems, error)` builds a mapping, offered in three pieces and nothing else:
    - `Mapper()` returns the `prblm.Mapper`;
    - `Types()` returns the `[]*prblm.Type` definitions for prblm's discovery pages;
    - `Option()` returns one `prblm.Option` that registers both, for `prblm.NewHandler` and prblm's gin and fiber adapters.

    The handler, encoding, headers, hooks and framework adapters stay prblm's.
  - Every refusal the core recognises becomes a **typed problem**: a sub-type under a configurable prefix (default `security`), such as `security/mfa-required`. Its status is always the core's status for the error, and a type is chosen only among the types of that status. So a type never separates refusals the status table deliberately merges, such as a concealed lock or a user-store outage, which both stay `authentication-failed`.
  - Safe structured fields travel as extension members:
    - the challenge kind and the usable MFA methods;
    - the challenge's access token and token type (on by default, withheld by `WithoutChallengeToken`);
    - the reauthentication window;
    - the password rule that refused a candidate.
  - An error the core does not recognise is left to the consumer's later prblm mappers and to prblm's safe 500 fallback.
  - The mapper never sets `WWW-Authenticate`. The challenge header the chain already set is kept on net/http, gin and fiber.
- **Core additions (`httpsec`), both additive:**
  - `httpsec.LookupStatus(err) (status int, ok bool)`, the comma-ok companion of `StatusForError`, built on the same decision. `ok` reports whether the error is one the library recognises, including the dependency failures it deliberately answers 500.
  - `ChallengeError.TokenType`, set whenever `Token` is, so a renderer can name the token's type (`Bearer` or `DPoP`) without re-deriving it.
- **gin: refusals left for an error middleware.** `ginsec.Middleware(chain, opts ...Option)` gains its first option, `WithRefusalsRendered()`.
  - **What it declares:** an error middleware renders every refusal.
  - **What it changes:** with it, the 404 the chain gives at its own endpoints on a path gin has no route for is left open like every other refusal, instead of being sent immediately with an empty body. So an error middleware that writes immediately, such as a consumer's own JSON middleware, can render it.
  - **`ginprblm` does not need it:** its middleware defers the response header, so it renders that 404 with or without the option.
  - **Default:** unchanged.
  - **Without an error middleware:** gin's generic `404 page not found` text is sent. That is still a 404, and carries no scrty text.
- **Spec amendment:** the core still includes no body renderer. The settled "no problem-details renderer" requirement is narrowed to the core module, and the one renderer lives in the opt-in module.
- Module layout, release and supply-chain lists gain `httpsec/prblmsec`, including Dependabot and the module checks. The cross-framework parity tests (net/http, gin through `ginprblm`, fiber through `fiberprblm`) live in the test module.

## Capabilities

### New Capabilities
- `problem-details-rendering`: the opt-in mapping of scrty refusals to RFC 9457 problems through prblm. It covers problem types and their selection, extension members, challenge-token delivery, deferral of unrecognised errors, header preservation, and parity across net/http, gin and fiber.

### Modified Capabilities
- `http-error-propagation`: the "no problem-details renderer" clause is narrowed to the core module. A new requirement adds the recognising status lookup (`LookupStatus`). The challenge-error contents gain the token type.
- `module-layout`: `httpsec/prblmsec` is added to the listed integration modules and package names, and the core module must not require `github.com/kartaladev/prblm`.
- `framework-adapters`: the gin requirement that sends the no-route 404 immediately with an empty body gains the consumer's override, `WithRefusalsRendered()`.
- `release-policy`: `httpsec/prblmsec` is added to the modules released in lockstep.

## Impact

- **New module:** `httpsec/prblmsec` (`go.mod`, package, tests, godoc examples). `go.work` gains it.
- **Core:** `httpsec/errors.go` gains `LookupStatus`, with `StatusForError` re-expressed through it so the two cannot disagree. `ChallengeError` gains `TokenType`, set at its three construction sites (`complete.go`, `mfa_verify.go`).
- **`httpsec/ginsec`:** `Middleware` takes variadic options (existing calls compile unchanged), and gains `Option` and `WithRefusalsRendered`. `refuse` (`middleware.go:154`) honours the option.
- **Test module:** it gains parity tests that require `prblm`, `ginprblm` and `fiberprblm`.
- **Consumer documentation:** runnable examples and a package overview in `prblmsec`, and a new README section, "Problem details (RFC 9457)". It also adds pointers to `prblmsec` where `httpsec`, `ginsec`, `fibersec` and the README tell consumers to render refusals themselves.
- **Repository tooling:** `tools/repocheck`'s module list, `.github/dependabot.yml`, `RELEASING.md` and `CHANGELOG.md`.
- **Dependency:** `github.com/kartaladev/prblm` v0.2.0 (MIT, standard library only), in `httpsec/prblmsec` and `test` only.
- **Compatibility:** additive before the next tag, with no change to any default response. A consumer who does not import `prblmsec` sees no difference.

## References

See `design.md`.
