// Package event names the security events scrty reports, and the sink a
// consumer receives them on.
//
// scrty decides security outcomes: a login that succeeded or failed, a
// session created or ended, a request refused for a cross-site origin or an
// invalid proof. Each decision is reported to the consumer's Sink as one
// Event, under a standard name, so an application can record, alert on and
// investigate them without parsing logs.
//
// # Turning it on
//
// Nothing is reported until a sink is configured; the default is no sink.
// httpsec.EnableSecurityEvents gives the HTTP chain one, and the chain
// reaches every component a request passes through, the ones it builds and
// the ones the consumer built and registered on it, through the request's
// context. A component a consumer also calls outside a chain takes a sink of
// its own, which defaults to none:
//
//   - apikey.WithSecurityEvents, for an API key verified outside a chain;
//   - lockout.WithSecurityEvents, for a lock decided on a failure the
//     consumer's own login flow records;
//   - mfa.WithThrottleSecurityEvents and mfa.WithResetSecurityEvents, for a
//     throttled verification and a removed enrolment;
//   - recovery.WithSecurityEvents, for a recovery run outside a chain;
//   - session.WithSecurityEvents, for a reuse the session manager detects
//     outside a chain;
//   - signingkey.WithSecurityEvents, for a key rotation, which runs on no
//     request and reports only there.
//
// On a request a chain reports for, a component reports through the chain
// and its own sink is not called, so one outcome is reported once. A nil sink,
// or one option given twice, is a configuration error from the constructor.
//
// # The sink's contract
//
// The sink is called synchronously, on the request that decided the outcome,
// after the decision, with a context from which the request's cancellation
// has been removed, so a client that hangs up does not cut the delivery
// short. It cannot change the outcome, the status or the error the caller
// sees: it returns nothing, and a panic in it is recovered and logged without
// the event's contents, and the event is dropped. It may be called
// concurrently, from every request at once.
//
// A sink that blocks holds the request that is delivering to it, and that is
// the consumer's responsibility: a sink that does slow work, such as a network
// write, hands the event to its own queue and returns. The library keeps no
// queue of its own, because a queue must bound memory or lose events, and
// which to give up is the consumer's choice.
//
// A sink should do no work that depends on whether an account exists, such as
// looking the user up only when an event names one. Some outcomes are
// reported alike for an identifier that names an account and one that names
// none, a recovery start above all, so that the response's latency does not
// tell them apart; a sink whose time depends on the account would tell them
// apart again.
//
// # Names
//
// An event is named from the OWASP Logging Vocabulary where the vocabulary
// names the outcome, and under the scrty_ prefix where it does not. Names
// returns the same list, and each constant says more about when it is
// reported. From the vocabulary:
//
//   - authn_login_success: a first factor accepted and its sign-in stored,
//     once the session is stored and its credential handed out.
//   - authn_login_successafterfail: authn_login_success for a password login
//     whose identifier had recent failed attempts, reported in its place.
//   - authn_login_fail: a first factor refused for the credential presented,
//     at form login, Basic, an API key, a bearer token or session reference, a
//     passkey assertion or an OIDC callback.
//   - authn_login_fail_max: the failed attempt that took its identifier to a
//     lock in the account-lockout policy, once per lock, including the lock
//     again, for longer, after an escalating wait has run out.
//   - authn_login_lock: the same lock, reported beside authn_login_fail_max.
//   - authn_password_change: a password changed.
//   - authn_password_change_fail: a password change refused, for a wrong
//     current password or a new one the password policy rejected.
//   - authn_token_created: a credential handed out for a stored session.
//   - authn_token_revoked: a sign-in's credentials revoked at logout.
//   - authn_token_reuse: a superseded session identifier presented again,
//     and its family revoked.
//   - session_created: a session stored for a sign-in.
//   - session_renewed: a session rotated to a successor, by renewal or a
//     step-up.
//   - session_expired: a session refused for being idle past the idle
//     timeout.
//   - session_use_after_expire: a session presented after its lifetime ended.
//   - session_logout: a sign-in ended by its own logout.
//   - authz_fail: a request the authorization stage, a route guard or a
//     per-request policy denied.
//   - excess_rate_limit_exceeded: a request refused for a rate limit the
//     library keeps.
//   - malicious_csrf: a request the CSRF protection refused as cross-site.
//
// Under the scrty_ prefix:
//
//   - scrty_mfa_verified: a second factor verified.
//   - scrty_mfa_verify_fail: a second-factor response refused.
//   - scrty_mfa_enrolled: a second-factor method enrolled.
//   - scrty_mfa_removed: a user's second-factor enrolments removed.
//   - scrty_passkey_registered: a passkey bound to an account.
//   - scrty_passkey_removed: a passkey removed from an account.
//   - scrty_recovery_started: an account recovery start, for every start,
//     whether or not the username names an account.
//   - scrty_recovery_completed: an account recovery completed, and its
//     recovery-pending session stored.
//   - scrty_recovery_refused: an account recovery's completion refused for
//     its proofs.
//   - scrty_reauthenticated: a signed-in user who proved themselves again.
//   - scrty_reauthentication_fail: a re-authentication proof refused.
//   - scrty_signin_ended: a sign-in, or several, ended through session
//     management.
//   - scrty_host_refused: a request whose forwarded host is on none of the
//     allowed hosts.
//   - scrty_dpop_refused: a request refused for an invalid DPoP proof.
//   - scrty_certificate_binding_refused: a certificate-bound token presented
//     without its certificate.
//   - scrty_challenge_refused: a request the automation challenge refused.
//   - scrty_signing_key_rotated: a signing key minted and stored by
//     rotation.
//
// # What an event carries
//
// An Event carries its name, when it happened, its outcome, the user it
// concerns when one is known, the resolved client address, the first factor
// where one applies, and the digest of the session's identifier. It never
// carries the identifier itself, a password, a token, a one-time code, a link
// secret, a key, a DPoP proof, a certificate, a CSRF token or a stored hash.
//
// # Only what happened
//
// An event reports an outcome that happened, not one that was attempted. A
// creation event is reported only once the session it names is stored and its
// credential handed out: a credential issued and then discarded, because its
// session could not be stored or a racing request won, reports nothing. A
// request whose own context ended before a verdict, and a dependency that
// failed, report no failure or refusal. A verdict beside a hang-up is still a
// verdict: a bearer token the verifier refused on a request that had also
// ended is refused, and reported.
//
// # Limits
//
//   - A magic-link redemption and an OIDC handoff answer a refusal and an
//     outage with one error, by design, so neither reports a failure.
//   - A second factor's refusal is reported only when the method's error
//     wraps one of the mfa refusal sentinels (mfa.ErrInvalidCode,
//     mfa.ErrVerifyThrottled, mfa.ErrAuthenticatorRefused,
//     mfa.ErrSameChannel), the mfa.Method Verify contract; any other error is
//     taken for a dependency failure and reports nothing.
//   - Session is a digest of the session's identifier, never the identifier.
//   - A lock is reported once within one process. With an attempt store
//     several processes share, failures on different processes at the same
//     moment may each report it; a failure recorded straight into the store,
//     not through lockout.Policy.Attempts, is not reported; and a failure for
//     which the store could not say whether the identifier was already
//     locked loses its event, which the policy logs, while the failure
//     itself is recorded and counts.
package event
