## Context

See proposal.md for why. What the audit found, by kind:

- **Log sites writing a dependency's error text** (`slog.String("error", err.Error())` or equivalent):
  - `httpsec`: `login.go` (attempt store record and reset), `basic.go` (attempt store), `sessiontouch.go` (session store), `oidc_callback.go` (handoff issue), `throttle.go` (limiter);
  - `authenticate/password.go`: the user loader;
  - `magiclink/manager.go`: issued-count, issue, send, resolver, user loader;
  - `notify/smtp.go`, `notify/queued.go`: delivery failure, inner sender;
  - `oidc/callback.go`: flow-store completion;
  - `ratelimit/guard.go`: limiter;
  - `onetime/manager.go`, `apikey/manager.go`, `signingkey/rotate.go`: their stores;
  - `policy/mfarequirement.go`: the requirement or enrolment lookup.
- **A username as typed:** `authenticate/password.go`, every refusal through `refuse`.
- **Returned errors wrapping a dependency's text** reach the consumer's error handler from: the pre-authentication lockout (`policy/lockout.go`), login completion (session create and save, token generation, policy reasons from `policy/concurrent.go`, `policy/mfarequirement.go`, `policy/mfa.go`), the bearer's per-request phase and save, the verify endpoint (TOTP store reads), logout (session delete), OIDC authorize (flow begin), the OIDC callback (flow abort, handoff issue) and back-channel logout (link lookups and session deletes). On gin, every such error is also printed by gin's default logger, because the adapter places refusals on gin's error channel.
- **Already redacted:** the enrolment path (`enrolmentFault`: fixed text, cause and sentinel unwrapped) and the OIDC broker (`redact`: substring scrubbing of the login's own values and of hash-shaped text, required by `identity-linking`).

## Goals / Non-Goals

**Goals:**
- No log record and no returned error carries a consumer dependency's text.
- Operators can still tell what failed, and consumers can still match an error by identity.
- One helper, so the rule is applied the same way everywhere.

**Non-Goals:**
- Changing the OIDC broker's redaction, which meets its own spec.
- Redacting the library's own protocol failures (token verification, discovery, key sets, the token endpoint's response); stated as exceptions.
- Removing the deliberate fields: the throttled source address, the opaque user reference in MFA and policy records, the email domain.
- A per-record detail hook for operators (decision 2).

## Decisions

### 1. Fixed text, not scrubbing

- **Rule:** a dependency's error is never rendered into a record or a returned error's text. A record carries `reason` (a fixed word naming what failed, such as `attempt-store`, `session-store`, `sender`, `limiter`) and `error_type` (the error's Go type, `%T`). A returned error's text is the library's own; the dependency's error is wrapped, not formatted.
- **Why not scrubbing:** the broker's approach removes values the library holds. A dependency's text can quote values the library never saw: another column of the row, a server's rewording of the address, a key built by the consumer's own limiter. Only fixed text is safe without knowing the dependency.
- **Default:** fixed text. **Override:** none for the text itself; decision 2.

### 2. The consumer keeps detail inside their own dependency

- **Rule:** every component that logs such failures says, in godoc, that a consumer who wants the dependency's full error logs it inside their implementation of the port, where they know what the text may contain. The returned error also keeps the cause reachable, so a consumer's error handler can inspect it deliberately.
- **Alternative rejected:** a `WithErrorDetail(func(error) slog.Attr)` hook on every component. It adds an option to a dozen constructors to hand the consumer something they already own, and a one-line wrapper around their store does the same.

### 3. One internal helper

- **Package:** `internal/diag` (the module already keeps `internal/nilcheck` and `internal/origin`).
- **Records:** `diag.Failure(reason string, err error) []slog.Attr` returns `reason`, `error_type`, and `cancelled=true` when the error is a context cancellation or deadline, which operators need to tell a hang-up from an outage.
- **Returned errors:** `diag.Fault(text string, kinds ...error)` builds an error whose `Error()` is `text` and whose `Unwrap() []error` returns the given library sentinels and the cause; `diag.Wrap(err, text string, kinds ...error)` returns `nil` for `nil`, and returns `err` unchanged when it is exactly one of `kinds` (a bare sentinel carries no dependency text). This generalises the enrolment path's `enrolmentFault`/`refusedAs`, which move onto it.
- **Why internal:** it is a rule the library applies to itself, not an API consumers need.

### 4. Usernames in the password authenticator's records

- **Default:** refusal records carry the reason only.
- **Override:** `authenticate.WithUsernameInRefusalLogs()`, whose godoc states that users type email addresses, and sometimes passwords, into the username field, and that every unknown username then reaches the log.
- **Sampling keys** stay per reason, as today; the username was never part of the key.

### 5. Returned errors: which paths, and which keep their errors

- **Wrapped with fixed text** (cause and sentinel reachable, status unchanged): every path listed in Context under returned errors, and the policy reasons that wrap a store error. Where a path already returns a library sentinel alone, it is unchanged.
- **Returned unchanged:** the consumer's own magic-link and handoff refusal checks, guards' extractors, ownership checkers and authorizers, authorization rule sets, and the consumer's own policies' reasons. They are the consumer's decisions in the consumer's words (`library-design` rule 5).
- **gin:** the adapter keeps placing the refusal on gin's error channel; with fixed text, gin's logger prints library text. No adapter change.

### 6. The deliberate fields stay, and are stated

The throttled `source` address (`rate-limiting`), the opaque user reference in MFA and policy records, the `email_domain` in identity-linking records, and the protocol-failure text listed above stay. Each component's godoc names what it logs, so an operator does not have to read the code to know.

### 7. Test pattern

Every site gets a table row with a dependency whose error text quotes `alice@example.com` and the user reference `u-123`, a capturing `slog` handler, and, for returned errors, an error handler that records `err.Error()`. The row asserts neither value appears, the fixed `reason` and `error_type` do, `errors.Is` still finds the original error, and `StatusForError` is unchanged. The red step is the same row against the unchanged site.

## Risks / Trade-offs

- [Operators lose the dependency's text in the library's records] → The reason and type say what failed; the consumer logs detail inside their own port (decision 2). This is the trade the enrolment path already made.
- [A consumer parsed a returned error's text] → **BREAKING**; identity and type matching are unchanged and are the documented contract (`http-error-propagation`).
- [An operator relied on usernames in authentication records] → **BREAKING**; one option restores them, with the risk stated.
- [A new log site added later writes `err.Error()` again] → The helper makes the right thing the easy thing; a lint rule (forbidding `err.Error()` inside `slog` attributes outside `internal/diag`) is worth considering and is left to the final review to recommend.

## Migration Plan

Not applicable: no consumers and no tags.
