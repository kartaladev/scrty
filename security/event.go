// Package security names the security events scrty reports, and the sink a
// consumer receives them on.
//
// scrty decides security outcomes: a login that succeeded or failed, a
// session created or ended, a request refused for a cross-site origin or an
// invalid proof. Each decision is reported to the consumer's Sink as one
// Event, under a standard name, so an application can record, alert on and
// investigate them without parsing logs. Nothing is reported until a sink is
// configured: httpsec.EnableSecurityEvents for the HTTP chain, and the
// component's own option for a component that also decides outside a chain
// (apikey.WithSecurityEvents, mfa.WithThrottleSecurityEvents,
// mfa.WithResetSecurityEvents, recovery.WithSecurityEvents,
// signingkey.WithSecurityEvents). On a request a chain reports for, a
// component reports through the chain and its own sink is not called, so one
// outcome is reported once.
//
// # Names
//
// An event is named from the OWASP Logging Vocabulary where the vocabulary
// names the outcome, and under the scrty_ prefix where it does not. Names
// lists every name the library uses, and each constant says when it is
// reported.
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
// failed, report no failure or refusal.
package security

import (
	"context"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
)

// Event is one security outcome scrty decided.
type Event struct {
	// Name is the event's name: one from the OWASP Logging Vocabulary, or one
	// under the scrty_ prefix. Names lists them all.
	Name string

	// At is when the outcome was decided, read from the deciding component's
	// time source.
	At time.Time

	// Outcome is OutcomeSuccess or OutcomeFailure.
	Outcome string

	// User is the user the outcome concerns, and empty when none is known: a
	// failed login names no user, so the event does not reveal whether the
	// submitted identifier is an account.
	User identity.UserID

	// ClientIP is the client address the chain resolved for the request,
	// through trusted proxies when the chain trusts them, and empty for an
	// outcome decided outside a request.
	ClientIP string

	// Factor is the first factor the outcome concerns, and empty where none
	// applies.
	Factor factor.Kind

	// Session is the lower-case hexadecimal SHA-256 digest of the identifier
	// of the session the outcome concerns, and empty when it concerns none.
	// It is never the identifier itself, which is a credential.
	Session string
}

// Sink receives security events.
//
// It is called synchronously, on the request that decided the outcome, with a
// context from which the request's cancellation has been removed, so a client
// that hangs up does not cut the delivery short. It cannot change the
// outcome: it returns nothing, and a panic in it is recovered and logged
// without the event's contents.
//
// A sink that blocks holds the request that is delivering to it. That is the
// consumer's to manage: a sink that does slow work, such as a network write,
// hands the event to its own queue and returns.
//
// A sink should do no work that depends on what the event says about an
// account, such as looking the user up only when the event names one. Some
// outcomes are reported alike whether or not the submitted identifier names an
// account, a recovery start above all, so that the response's latency does
// not tell them apart; a sink whose time depends on the account would tell
// them apart again.
//
// It may be called concurrently, from every request the chain serves at once.
type Sink func(ctx context.Context, e Event)

// The outcomes an event reports.
const (
	// OutcomeSuccess is an outcome the caller asked for and was granted.
	OutcomeSuccess = "success"

	// OutcomeFailure is a refusal or a failed attempt.
	OutcomeFailure = "failure"
)

// The names from the OWASP Logging Vocabulary.
const (
	// AuthnLoginSuccess is a first factor accepted and its sign-in stored:
	// reported once the session is stored and its credential handed out.
	AuthnLoginSuccess = "authn_login_success"

	// AuthnLoginSuccessAfterFail is AuthnLoginSuccess for a password login
	// whose identifier had recent failed attempts, reported in its place.
	AuthnLoginSuccessAfterFail = "authn_login_successafterfail"

	// AuthnLoginFail is a first factor refused for the credential presented:
	// a wrong password, an unknown user or a disabled account at form login
	// or Basic; an API key unknown, wrong, expired or revoked; a bearer token
	// the verifier refused, or a session reference the store does not hold;
	// a passkey assertion refused, for a disabled or unknown user included;
	// an OIDC callback whose ID token failed verification, whose identity is
	// linked to no account, or whose provisioning was refused.
	//
	// It is not reported for a dependency that failed (a user store, a key
	// store, a session store, a passkey challenge store, an identity provider
	// that could not be reached), nor for a request whose own context ended
	// before the verdict. That holds when the failure is answered as a
	// refusal: a challenge store that could not answer fails the assertion
	// like a wrong one, with the same status and text, and reports nothing. A
	// magic-link redemption and an OIDC handoff answer a refusal and an outage
	// with one error, by design, and so report no failure at all; nor does an
	// OIDC callback refused as an invalid state.
	AuthnLoginFail = "authn_login_fail"

	// AuthnLoginFailMax is a failed attempt that left its identifier locked
	// by the account-lockout policy.
	AuthnLoginFailMax = "authn_login_fail_max"

	// AuthnLoginLock is an account locked, as the lockout policy's observer
	// reports it.
	AuthnLoginLock = "authn_login_lock"

	// AuthnPasswordChange is a password changed.
	AuthnPasswordChange = "authn_password_change"

	// AuthnPasswordChangeFail is a password change refused: the current
	// password wrong, or the new one rejected by the password policy.
	AuthnPasswordChangeFail = "authn_password_change_fail"

	// AuthnTokenCreated is a credential handed out for a stored session.
	AuthnTokenCreated = "authn_token_created"

	// AuthnTokenRevoked is a sign-in's credentials revoked, at logout.
	AuthnTokenRevoked = "authn_token_revoked"

	// AuthnTokenReuse is a superseded session identifier presented again,
	// and its family revoked.
	AuthnTokenReuse = "authn_token_reuse"

	// SessionCreated is a session stored for a sign-in.
	SessionCreated = "session_created"

	// SessionRenewed is a session rotated to a successor, by renewal or by a
	// step-up that rotates it.
	SessionRenewed = "session_renewed"

	// SessionExpired is a session refused because it was idle for longer
	// than the idle timeout allows.
	SessionExpired = "session_expired"

	// SessionUseAfterExpire is a session presented after its lifetime ended.
	SessionUseAfterExpire = "session_use_after_expire"

	// SessionLogout is a sign-in ended by its own logout.
	SessionLogout = "session_logout"

	// AuthzFail is a request the authorization stage, a route guard or a
	// per-request policy denied.
	AuthzFail = "authz_fail"

	// ExcessRateLimitExceeded is a request refused because a rate limit the
	// library keeps was exceeded: a source over the login, recovery or renewal
	// limit, or a user over the second-factor verification throttle, the
	// second-factor challenge issue limit or the enrolment limit. A limiter
	// that could not answer refuses too, and is not reported: it decided
	// nothing.
	ExcessRateLimitExceeded = "excess_rate_limit_exceeded"

	// MaliciousCSRF is a request refused as cross-site by the CSRF
	// protection.
	MaliciousCSRF = "malicious_csrf"
)

// The names under the scrty_ prefix, for outcomes the OWASP Logging Vocabulary
// does not name.
const (
	// MFAVerified is a second factor verified.
	MFAVerified = "scrty_mfa_verified"

	// MFAVerifyFail is a second-factor response refused.
	MFAVerifyFail = "scrty_mfa_verify_fail"

	// MFAEnrolled is a second-factor method enrolled.
	MFAEnrolled = "scrty_mfa_enrolled"

	// MFARemoved is a user's second-factor enrolments removed.
	MFARemoved = "scrty_mfa_removed"

	// PasskeyRegistered is a passkey bound to an account.
	PasskeyRegistered = "scrty_passkey_registered"

	// PasskeyRemoved is a passkey removed from an account.
	PasskeyRemoved = "scrty_passkey_removed"

	// RecoveryStarted is an account recovery start posted. It is reported for
	// every start, for a username that names an account and for one that names
	// none alike, as the start's last step, carrying User only when the
	// username named an active account: the endpoint answers every start
	// alike, and a sink called only for real accounts would let the latency
	// tell them apart.
	RecoveryStarted = "scrty_recovery_started"

	// RecoveryCompleted is an account recovery completed, and its
	// recovery-pending session stored.
	RecoveryCompleted = "scrty_recovery_completed"

	// RecoveryRefused is an account recovery's completion refused for its
	// proofs (recovery.ErrRefused): a recovery code, an issued code, a
	// second-factor code or a completion token that is not good, a user at the
	// recovery limit, or a check that refused it. It names no user, as a
	// failed login does not. A recovery whose dependency failed, or whose
	// request ended before a verdict, is not reported, even when the failure
	// is answered as the same refusal (recovery.ErrRefused) a bad proof gets: a
	// store that could not answer, the user limiter that could not say, or a
	// risk hook that failed. The answer a caller sees is unchanged.
	RecoveryRefused = "scrty_recovery_refused"

	// Reauthenticated is a signed-in user who proved themselves again.
	Reauthenticated = "scrty_reauthenticated"

	// ReauthenticationFail is a re-authentication proof refused.
	ReauthenticationFail = "scrty_reauthentication_fail"

	// SignInEnded is a sign-in ended through session management, by its
	// handle, or one or more of the user's other sign-ins ended at once;
	// ending the others when there are none is not reported. User is the
	// signed-in user, and Session the digest of the caller's own session, the
	// one that asked: an ended sign-in is named by a handle, which is not a
	// session identifier, and one request may end several.
	SignInEnded = "scrty_signin_ended"

	// HostRefused is a request whose forwarded host is on none of the
	// allowed hosts.
	HostRefused = "scrty_host_refused"

	// DPoPRefused is a request refused for an invalid DPoP proof. A request
	// asked only to retry with the server's nonce is not reported: that is
	// the protocol's normal first step.
	DPoPRefused = "scrty_dpop_refused"

	// CertificateBindingRefused is a certificate-bound token presented
	// without its certificate.
	CertificateBindingRefused = "scrty_certificate_binding_refused"

	// ChallengeRefused is a request the automation challenge refused.
	ChallengeRefused = "scrty_challenge_refused"

	// SigningKeyRotated is a new signing key minted and stored by rotation.
	SigningKeyRotated = "scrty_signing_key_rotated"
)

// Names returns every event name the library reports: the OWASP Logging
// Vocabulary names first, then the scrty_ names, each in the order its
// constant is declared. The slice is the caller's own.
func Names() []string {
	return []string{
		AuthnLoginSuccess, AuthnLoginSuccessAfterFail, AuthnLoginFail, AuthnLoginFailMax,
		AuthnLoginLock, AuthnPasswordChange, AuthnPasswordChangeFail, AuthnTokenCreated,
		AuthnTokenRevoked, AuthnTokenReuse, SessionCreated, SessionRenewed, SessionExpired,
		SessionUseAfterExpire, SessionLogout, AuthzFail, ExcessRateLimitExceeded, MaliciousCSRF,

		MFAVerified, MFAVerifyFail, MFAEnrolled, MFARemoved, PasskeyRegistered, PasskeyRemoved,
		RecoveryStarted, RecoveryCompleted, RecoveryRefused, Reauthenticated, ReauthenticationFail,
		SignInEnded, HostRefused, DPoPRefused, CertificateBindingRefused, ChallengeRefused,
		SigningKeyRotated,
	}
}
