package event

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

	// Client is the identifier of the OAuth client the outcome concerns, as
	// the OpenID provider registered it, and empty where none applies or none
	// is known: a client authentication refused for an identifier the
	// registry does not hold names no client, as a failed login names no user.
	// A client identifier is public, never a credential.
	Client string

	// Cause is why the outcome came about, in a fixed word, and empty where
	// the name says it all. It is the cause a grant was revoked for, or the
	// reason a back-channel logout delivery failed. It is never the text of an
	// error, and never a value a request supplied. The one exception to the
	// fixed word is a cause a consumer named when it revoked a user's grants:
	// that is the consumer's own, and is carried unchanged.
	Cause string
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

	// AuthnLoginFailMax is the failed attempt that took its identifier to a
	// lock in the account-lockout policy: from allowed to locked by the
	// policy's own rule, to the window failure limit under the escalating
	// wait, or to a hold under a failure-streak limit. Under the default
	// escalating wait an identifier is allowed again once its wait has run
	// out, so the failure after that locks it again, for longer, and is
	// reported again. It is reported by the policy's view
	// (lockout.Policy.Attempts) where it records the failure, once per lock:
	// the failures that find the identifier still locked report no further
	// lock, except the one that sets a hold, which is a lock of its own and
	// reports even when the window already locked the identifier. A held
	// identifier stays locked whatever its window holds, so no failure while
	// the hold stands reports one, though it brings the window to the
	// threshold. It names no user, since the policy counts identifiers, and
	// carries the first factor that failed. Within one process concurrent
	// failures that lock together report it once; with an attempt store
	// several processes share, failures on different processes at the same
	// moment may each report it. A store that cannot say whether the
	// identifier was locked before the failure loses the event, never the
	// failure.
	AuthnLoginFailMax = "authn_login_fail_max"

	// AuthnLoginLock is the lock AuthnLoginFailMax reports, reported beside
	// it, after it, by the same failure: the identifier is now locked. The
	// lockout policy's observer is told of the same failure as before.
	AuthnLoginLock = "authn_login_lock"

	// AuthnPasswordChange is a password changed.
	AuthnPasswordChange = "authn_password_change"

	// AuthnPasswordChangeFail is a password change refused: the current
	// password wrong, or the new one rejected by the password policy.
	AuthnPasswordChangeFail = "authn_password_change_fail"

	// AuthnTokenCreated is a credential handed out for a stored session.
	AuthnTokenCreated = "authn_token_created" //nolint:gosec // G101: an event name, not a credential

	// AuthnTokenRevoked is a sign-in's credentials revoked, at logout.
	AuthnTokenRevoked = "authn_token_revoked" //nolint:gosec // G101: an event name, not a credential

	// AuthnTokenReuse is a superseded session identifier presented again,
	// and its family revoked: reported by the session manager where it
	// detects the reuse, once the revocation is stored, naming the session's
	// user and first factor and the presented session's digest. The session
	// manager's reuse observer is called as before.
	AuthnTokenReuse = "authn_token_reuse" //nolint:gosec // G101: an event name, not a credential

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
	PasskeyRegistered = "scrty_passkey_registered" //nolint:gosec // G101: an event name, not a credential

	// PasskeyRemoved is a passkey removed from an account.
	PasskeyRemoved = "scrty_passkey_removed" //nolint:gosec // G101: an event name, not a credential

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

	// GrantCreated is a grant stored for an authorization code exchanged, by
	// the OpenID provider, reported once everything the exchange answers with
	// is stored too, so that a failure handing out nothing reports nothing. It
	// names the client and the user.
	GrantCreated = "scrty_grant_created"

	// ConsentGiven is a user's consent to a client answered at the consent
	// stage, and the authorization code issued on it. It names the client and
	// the user.
	ConsentGiven = "scrty_consent_given"

	// ConsentDenied is a user's denial of a client at the consent stage, a
	// failure outcome as a refusal is. It names the client and the user.
	ConsentDenied = "scrty_consent_denied"

	// ConsentRevoked is a user's consent to a client withdrawn, reported
	// beside the revocation of the grants that came of it (GrantRevoked). It
	// names the client and the user.
	ConsentRevoked = "scrty_consent_revoked"

	// ClientAuthRefused is a client authentication the OpenID provider refused
	// as invalid_client: a wrong secret, an assertion that does not verify or
	// was replayed, a method the client did not register. It names the client
	// only when the registry holds the identifier presented, and no user. A
	// registry or store that failed, and a request refused as malformed
	// (invalid_request), are not reported.
	ClientAuthRefused = "scrty_client_auth_refused"

	// CodeReplayed is an authorization code presented after it was spent, by
	// the client it was issued to, reported once the grant it created stands
	// revoked. Each such presentation is one, and the one that revoked the
	// grant is reported beside GrantRevoked with the cause code_replay. It names
	// the client and the user.
	CodeReplayed = "scrty_code_replayed"

	// RefreshReused is a refresh token presented after its successor took
	// over and its grace window ended, reported once the grant stands revoked,
	// beside GrantRevoked with the cause reuse unless something else had
	// revoked it first. It names the client and the user, never the token. A
	// refresh token is no session, so it never reports AuthnTokenReuse too.
	RefreshReused = "scrty_refresh_reused"

	// GrantRevoked is a grant of the OpenID provider revoked, one event per
	// grant, by the first revocation alone, as a later one changes nothing,
	// with its cause in Cause: reuse, code_replay, sign_in_ended,
	// consent_revoked, revoked_by_client, user_disabled, or the cause a
	// consumer named when it revoked a user's grants, which it carries
	// unchanged. It names the client and the user.
	GrantRevoked = "scrty_grant_revoked"

	// LogoutDeliveryFailed is a back-channel logout token the OpenID provider
	// did not deliver to a client that registered a URI for it. Cause is one
	// of client, sign, post, status, delivery, timeout, panic, goexit, busy,
	// queue_full or shutdown. It names the client and the user, and never the
	// logout token, the URI or the error. A drop for a client with no URI to
	// tell is not reported, and the delivery's failure never undoes the
	// logout.
	LogoutDeliveryFailed = "scrty_logout_delivery_failed"
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
		SigningKeyRotated, GrantCreated, ConsentGiven, ConsentDenied, ConsentRevoked,
		ClientAuthRefused, CodeReplayed, RefreshReused, GrantRevoked, LogoutDeliveryFailed,
	}
}
