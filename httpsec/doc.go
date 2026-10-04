// Package httpsec puts scrty's authentication, session, policy and
// authorization decisions in front of an HTTP handler.
//
// The decisions run as one ordered chain of interceptors. Each one reads and
// writes only through the small Request and ResponseWriter ports carried on an
// Exchange, so the same chain runs unchanged behind net/http and behind an
// integration for another framework: adapting a framework means implementing
// those two ports, not rewriting an interceptor. The library's own adapter for
// net/http is NewHTTPRequest and NewHTTPResponseWriter.
//
// # Slots
//
// An interceptor is registered at an Order, and the chain runs in ascending
// order with the lowest slot outermost and the handler innermost. The named
// slots are spaced, and the positions either side of each are deliberately
// free, so a consumer registers immediately before or after a built-in with
// Before and After rather than picking a number a later release may want.
//
// # Defaults, and replacing them
//
// Every behaviour here has a default that needs no configuration: a chain built
// with New and nothing else runs, and every built-in an Enable option turns on
// arrives already wired to sensible values. Each of those defaults is named in
// the godoc of the option that replaces it, and each port says what the library
// supplies when a consumer wires none of their own. Where a default is the safe
// answer rather than the convenient one — the login body bound before it is
// parsed, an unmatched authorization rule denying, a client address that cannot
// be attributed refused — the convenient answer is the option, never the
// starting point.
//
// # Writing a first factor of your own
//
// An interceptor a consumer registers has everything a built-in has, including
// how the caller is published. An interceptor that authenticates a request
// calls WithCaller, which publishes the authentication result and the principal
// it resolved together. Publishing with authenticate.WithAuthentication alone
// announces the event without the caller, and every guard behind the
// interceptor — each of which reads identity.PrincipalFromContext — then
// refuses a caller that has just been authenticated, indistinguishably from a
// missing credential.
//
// # A credential field reads the body, and only the body
//
// Form login, the MFA verify endpoint and the MFA enrolment endpoints each
// bind a credential field from the parsed POST body. A credential in the URL
// query never authenticates, because a query string reaches access logs,
// proxy logs and the Referer header. Request.FormValue looks in the posted
// form first and falls back to the URL query, on every adapter, for consumer
// interceptors that legitimately read a query parameter; only these
// credential reads narrow to the body alone. The narrowing carries two
// consequences, both deliberate: a body is read as a form only when it
// declares "application/x-www-form-urlencoded", so a "multipart/form-data"
// submission is refused with ErrCredentialsMissing rather than parsed; and a
// urlencoded body that does not parse yields no credential at all, rather
// than the pairs that did parse before the error. An MFA method that declares
// a JSON body instead is read under the same rule: the body only, and only
// when it declares a JSON media type.
//
// # Failing closed
//
// A refusal leaves the chain as an error and nothing else: this package writes
// no body for one, and never renders the error's text. StatusForError is the
// one public mapping from a refusal to the status it is answered with, so a
// consumer's own error handling agrees with the library on everything it does
// not handle itself. An error the mapping does not recognise is a server
// fault, never a quiet success, and a request whose interceptor returned an
// error never reaches the downstream handler.
//
// The refusals this package defines itself are ErrAuthenticationRequired,
// ErrCredentialsMissing and ErrRequestTooLarge; everything else a consumer
// sees is the refusal the core that decided it returned, unwrapped and
// unrenamed. A request that must satisfy a challenge before it continues is
// refused with a *ChallengeError, which carries the challenge as fields and
// names only its kind in text.
//
// WithErrorHandler replaces what a refusal is answered with on the net/http
// chain only. A framework that already owns how a request is refused keeps that
// ownership: on gin the refusal goes to gin's error channel, and on fiber to
// fiber's error handler.
//
// # Rate limits
//
// Every limiter the chain builds comes from one factory: the in-memory default,
// a limiter of its own per flow in this process, or the consumer's
// (WithRateLimiterFactory), for example one backed by storage every replica
// shares. Each flow asks for its own namespace, limit and window, so replacing
// the storage keeps every flow's own policy. The sites, by namespace:
//
//   - "api-key": EnableAPIKey, failures per source, 20 per minute.
//   - "magic-link-redeem": EnableMagicLink, failures per source, 10 per 15
//     minutes.
//   - "oidc.handoff": EnableOIDCLogin's handoff redemption, failures per
//     source, 10 per 5 minutes unless WithHandoffRateLimit says otherwise.
//   - "passkey-login": EnablePasskeys' passwordless begin, every begin per
//     source, 30 per 15 minutes.
//   - "account-recovery": EnableAccountRecovery's complete endpoint, failures
//     per source, 10 per 15 minutes.
//   - "account-recovery-start": EnableAccountRecovery's start endpoint, every
//     start per source, 10 per hour.
//   - "mfa-verify": EnableMFA's verification throttle, failures per user, 5
//     per 15 minutes.
//   - "mfa-enrol-begin": EnableMFAEnrolment, every begin per user, 5 per hour.
//   - "mfa-enrol-confirm": EnableMFAEnrolment, failed confirmations per user,
//     5 per 15 minutes.
//   - "recovery-user": the recovery.Recoverer EnableAccountRecovery builds,
//     failed recoveries per user, 5 per 15 minutes.
//
// A flow given a limiter of its own (WithAPIKeyLimiter, WithMFAVerifyLimiter
// and the like) uses that one, and the factory is never asked for it. The
// components a consumer builds and hands the chain — the recovery.Codes of
// RecoveryDeps and the passkey.Manager of PasskeyDeps — build their limiters
// themselves, through their own factory options (recovery.WithCodeLimiterFactory,
// passkey.WithConfirmLimiterFactory). Every source guard the chain builds keys
// IPv6 clients by the chain's prefix (WithIPv6SourcePrefix), and also counts
// them by an aggregate: by default a /56 at 4 times the flow's limit, over the
// flow's window, built from the factory under "<flow>-ipv6-aggregate" even for
// a flow that was given a limiter of its own, so a client rotating through the
// /64s of its allocation cannot buy a fresh allowance with each. For a flow
// given its own limiter, the limit and window are that limiter's, read through
// ratelimit.PolicyReporter; one that reports none gets no default aggregate and
// a warning at construction, and refuses an explicit one. Set it with
// WithIPv6Aggregate, or turn it off with WithoutIPv6Aggregate; the default is
// skipped when the source prefix is /56 or wider.
//
// # A dependency's failure never reaches a record or a returned error's text
//
// When a consumer-supplied dependency fails — a store, a user loader, a
// contact resolver, a sender, a rate limiter — this package writes neither the
// dependency's error text nor a value it may quote into a log record or into
// the text of an error it returns. A record instead carries a fixed reason
// naming what failed and the error's Go type; a returned error carries fixed
// library text of its own. In both cases the dependency's error stays
// reachable: a record's message and WithLogger together tell an operator which
// check failed and with what kind of error, and a returned error still matches
// the original by errors.Is and errors.As, and StatusForError maps it exactly
// as it would have mapped the dependency's own error. A consumer who wants the
// dependency's full text — a row a store could not read, a bucket key a
// limiter quoted back — logs it inside their own implementation of the port
// the failure came from; that implementation is the only place that knows what
// the text may contain.
//
// A few records are a deliberate exception, and keep the library's own text on
// purpose because it is not a dependency's: EnableBearerToken's debug record
// of a token that failed verification, so an operator can tell an expired
// token from a wrong signature or a wrong audience; EnableOIDCLogin's WARN
// record of a back-channel logout token that failed verification, naming the
// rule it failed; and the OIDC manager's record of an invalid ID token. Each
// is named again on the option or method that writes it. No other dependency
// text, and no personal data beyond what a capability's own godoc names (the
// throttled source address, the opaque user reference in MFA and policy
// records), is ever added to a record.
package httpsec
