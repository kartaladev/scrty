## Why

An audit of every log call and every error the HTTP paths return found personal data reaching logs, and consumer error handlers, through text the library does not control:
- **Dependency error text is logged verbatim.** A store, loader, resolver, sender or limiter the consumer supplied is free to quote what it was given, and real ones do: a PostgreSQL unique violation reads `DETAIL: Key (username)=(alice@example.com) already exists`, an SMTP refusal reads `550 5.1.1 <alice@example.com>: Recipient address rejected`, and a limiter's error names its key. Sixteen log sites write such text: form login and basic (attempt store), the session-touch step, the OIDC callback (flow store, handoff issue), the password authenticator (user loader), magic link (token store, sender, resolver, user loader), the email senders, and the rate limiter guard. Once `durable-persistence` lands, the library's own stores produce this text.
- **The password authenticator logs every username as typed.** Unknown usernames included. People type their email there, and sometimes their password.
- **Returned errors carry the same text.** On about ten HTTP paths the chain returns a dependency's error wrapped verbatim, so a consumer error handler that logs `err.Error()` — and gin's default logger, which prints every refusal the adapter places on its error channel — writes it out. Only the enrolment path and the OIDC broker scrub their errors today.

The enrolment path settled the rule this change applies everywhere: a record carries a fixed reason, and a returned error carries fixed library text with its cause still reachable. It should land before `durable-persistence`, whose stores would otherwise add to the problem.

## What Changes

- **Log records carry no dependency error text.** Where a log record reports a failure of a consumer-supplied port (a store, loader, resolver, sender, limiter or cipher), it carries a fixed `reason` naming what failed and the error's Go type, never the error's text. The consumer keeps full detail by logging inside their own port implementation.
- **Typed usernames are not logged by default.** The password authenticator's refusal records carry the refusal reason and no username. `WithUsernameInRefusalLogs()` puts it back, with godoc stating what that risks. **BREAKING** for an operator who relied on the username in those records.
- **Errors returned from the HTTP paths carry fixed library text.** Where an interceptor returns an error caused by a consumer-supplied port, the error's text is the library's own; the library sentinel it stands for and the original cause stay reachable through `errors.Is` and `errors.As`, so statuses and consumer matching are unchanged. The consumer's own refusal checks, guards, authorizers and rule sets are returned unchanged, as today. **BREAKING** for a consumer that parsed a returned error's text.
- **Policy refusal reasons wrapping a store error carry fixed text**, on the same terms, for the lockout, concurrent-session and MFA policies.
- **Stated exceptions, kept on purpose:** the throttled `source` address (`rate-limiting`), the opaque user reference in MFA and policy records, the `email_domain` in identity-linking records, and errors from the library's own protocol handling (token verification, discovery and key-set fetches, the provider's token-endpoint response). Godoc names each.

Not in this change: the OIDC broker's existing value-scrubbing redaction, which already meets `identity-linking`; request input and log flushing (`request-input-and-log-flush`).

## Capabilities

### New Capabilities

- `diagnostic-redaction`: what the library's log records and returned errors may carry when a consumer-supplied dependency fails, and the stated exceptions.

### Modified Capabilities

- `authentication`: the password provider's refusal records carry no username unless the consumer opts in.
- `email-notification`: the built-in senders' failure records carry no recipient address or server reply text.
- `http-error-propagation`: a refusal error caused by a consumer-supplied dependency carries fixed library text, with the cause reachable; consumer checks are returned unchanged.

## Impact

- **Code:** a small internal helper for failure attributes and fixed-text errors (generalising the enrolment path's), and the log and return sites in `httpsec`, `authenticate`, `magiclink`, `notify`, `oidc` (callback, handoff issue), `ratelimit`, `onetime`, `apikey`, `signingkey` and `policy`, each with tests using a capturing log handler and a dependency whose error quotes an address and a user reference.
- **Behaviour:** the two **BREAKING** items above. Nothing is tagged and there are no consumers yet.
- **Order:** before `durable-persistence`; independent of `request-input-and-log-flush`, which touches none of the same lines except in `httpsec/chain.go` godoc.
- **Dependencies:** none new.
