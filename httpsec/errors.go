package httpsec

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// The OpenID Provider's refusals the protocol does not let its endpoints answer
// themselves. Each wraps the oidcprovider refusal it reports, so a consumer matching
// either identity reaches it, and StatusForError answers the two alike.
var (
	// ErrOIDCInvalidAuthorization refuses an authorization request naming an invalid
	// client or redirect URI, which cannot be answered by redirecting to the client.
	// It maps to 400.
	ErrOIDCInvalidAuthorization = fmt.Errorf("httpsec: invalid authorization request: %w",
		oidcprovider.ErrInvalidAuthorization)

	// ErrOIDCUnknownHandle refuses a pending-request handle that is unknown, expired,
	// spent or not bound to the browser presenting it. It maps to 400.
	ErrOIDCUnknownHandle = fmt.Errorf("httpsec: unknown pending request: %w", oidcprovider.ErrUnknownHandle)

	// ErrOIDCConsentMalformed refuses a consent answer that does not fit its request,
	// such as one granting scopes that were not requested. It maps to 400.
	ErrOIDCConsentMalformed = fmt.Errorf("httpsec: malformed consent answer: %w", oidcprovider.ErrConsentMalformed)

	// ErrOIDCReauthenticate refuses a resume whose sign-in is not fresh enough for the
	// request's prompt or max_age. It maps to 401: the user signs in again.
	ErrOIDCReauthenticate = fmt.Errorf("httpsec: the sign-in must be repeated: %w", oidcprovider.ErrReauthenticate)

	// ErrOIDCThrottled refuses a request to the authorization, resume, end-session or
	// logout confirmation endpoint that the endpoint will not hear: its source is over the
	// limit, the limiter could not answer, or the source cannot be attributed. It fails closed, as ratelimit.ErrThrottled does,
	// and wraps it, so a consumer matching either identity reaches it.
	//
	// It maps to 429 (RFC 6585 section 4), where the chain's other throttled flows answer
	// 401. Those endpoints are visited by a browser, and a 401 there reads as "sign
	// the user in", which a page may answer by sending the browser back at once. The
	// token endpoints keep the 401 their clients are told to expect.
	ErrOIDCThrottled = fmt.Errorf("httpsec: too many requests: %w", ratelimit.ErrThrottled)

	// ErrOIDCInvalidEndSession refuses an end-session request that must end nothing and
	// must not be redirected: an id_token_hint failing its checks under a key still
	// published, a hint whose audience is not client_id, or parameters that cannot be
	// read. It maps to 400.
	ErrOIDCInvalidEndSession = fmt.Errorf("httpsec: invalid end-session request: %w",
		oidcprovider.ErrInvalidEndSession)

	// ErrOIDCForeignConsent refuses a consent listing or revocation for a user other
	// than the signed-in one. It maps to 404, as another user's passkey does.
	ErrOIDCForeignConsent = fmt.Errorf("httpsec: no such consent: %w", oidcprovider.ErrForeignConsent)
)

// The refusals this package defines itself. Every other refusal a consumer
// sees comes from the core that decided it — authenticate, authorize, policy
// or session — and this package neither restates nor renames those.
var (
	// ErrAuthenticationRequired refuses a request that presented nothing to
	// authenticate with, or whose session no longer exists, expired, or could
	// not be read. It is deliberately the same refusal in all of those cases:
	// telling them apart would say whether a session ever existed.
	//
	// authorize exports a refusal of the same name for an anonymous request
	// that matched a rule requiring authentication. The authorization stage
	// wraps that one with this, so a consumer matching either identity reaches
	// both and does not have to know which stage refused.
	ErrAuthenticationRequired = errors.New("httpsec: authentication required")

	// ErrCredentialsMissing refuses a login that carried no credentials, or a
	// JSON body that could not be decoded. It is the client's mistake, so it
	// maps to 400, and it says nothing about the account.
	ErrCredentialsMissing = errors.New("httpsec: missing or unreadable login credentials")

	// ErrMalformedRequest refuses a request whose fields are present but carry
	// a value the endpoint does not accept: an optional field given an
	// unknown value, an empty value, or more than once. Nothing has changed
	// when it is returned. It is the client's mistake, so it maps to 400.
	ErrMalformedRequest = errors.New("httpsec: malformed request")

	// ErrRequestTooLarge refuses a body over the configured bound before it is
	// parsed.
	ErrRequestTooLarge = errors.New("httpsec: request too large")

	// ErrUnknownMFAMethod refuses a second-factor request whose path names no
	// configured method: a segment naming nothing, an empty segment, or more
	// than one. The set of methods is configuration, not a secret, so it maps
	// to 404, as a federated-login path naming no provider does.
	ErrUnknownMFAMethod = errors.New("httpsec: unknown MFA method")

	// ErrMFAMethodNotUsable refuses a second factor on a configured method the
	// session's user may not use: one they are not enrolled on. It maps to
	// 403: the caller is known, and may not take this step.
	ErrMFAMethodNotUsable = errors.New("httpsec: MFA method not usable")

	// ErrNoMFAChallengePending refuses a method listing (WithMFAMethodListing)
	// asked for by a session that owes no second factor, a fully
	// authenticated one included. The endpoint exists only for the pending
	// state. It maps to 403: the caller is known, and has nothing to list
	// methods for.
	ErrNoMFAChallengePending = errors.New("httpsec: no MFA challenge pending")

	// ErrSessionRenewalConflict refuses a rotation of a session that a
	// concurrent renewal of the same session has already superseded, or that
	// a concurrent strict rotation (a second factor verified, or a re-proof)
	// has already rotated away, through this server or any other manager
	// sharing the session store, inside the winner's in-flight window: the
	// client lost a race with itself, or with whoever else holds the
	// credential. Nothing was written. It maps to 409, so the client retries
	// with the credential it now holds rather than signing in again.
	//
	// It wraps session.ErrRenewalConflict, so a consumer matching either
	// identity reaches both. Its text carries no session identifier.
	ErrSessionRenewalConflict = fmt.Errorf("httpsec: the session was renewed concurrently: %w",
		session.ErrRenewalConflict)

	// ErrRenewalThrottled refuses a renewal of a session family that has
	// renewed too often in the window, or whose renewal limiter could not
	// answer (the endpoint fails closed). Nothing was rotated. It maps to 429,
	// so the client backs off and retries with the credential it holds.
	//
	// Its text names neither the family nor the limiter's failure.
	ErrRenewalThrottled = errors.New("httpsec: too many renewals of this session family")

	// ErrReauthenticationRequired refuses a request to a route behind the
	// recency guard (Guards.RequireRecentAuthentication or
	// RequireAuthenticationWithin) whose session last proved the user's
	// identity longer ago than the guard allows. Nothing was changed. It maps
	// to 403: the caller is known and must prove identity again, which the
	// client does by calling a re-authentication endpoint.
	//
	// The guard returns it as a *ReauthenticationRequiredError, which carries
	// the window; errors.Is matches this sentinel through that type. A
	// consumer that wants "any re-authentication needed" matches this
	// together with recovery.ErrReauthenticationRequired and
	// passkey.ErrReauthenticationRequired. Its text names no session, user or
	// handle.
	ErrReauthenticationRequired = errors.New("httpsec: reauthentication required")

	// ErrReauthenticationMethodNotUsable refuses a re-authentication request
	// whose method the caller cannot use: the user has not enrolled it, it is
	// not among the methods the re-authentication endpoints
	// (EnableReauthentication) offer, or it is the password while the user
	// holds a usable second factor or a second factor is required for every
	// re-proof. Nothing was checked or counted. It maps to 403.
	// Its text names no method, session or user.
	ErrReauthenticationMethodNotUsable = errors.New("httpsec: reauthentication method not usable")

	// ErrHostNotAllowed refuses a request whose host a trusted proxy forwarded
	// (EnableTrustedProxies with ForwardedHost) and which is on none of the
	// allowed hosts. The chain refuses it before any interceptor runs. It maps
	// to 400. Its text never names the host.
	ErrHostNotAllowed = errors.New("httpsec: host not allowed")
)

// ReauthenticationRequiredError is the recency guard's refusal. It carries the
// window the session's last proof of identity fell outside of, so a client
// can say how recent a proof is needed.
//
// The guard (Guards.RequireRecentAuthentication, RequireAuthenticationWithin)
// returns it. It matches ErrReauthenticationRequired through errors.Is and
// maps to 403. Its text names the window and nothing else: no session, user
// or handle.
type ReauthenticationRequiredError struct {
	// Window is how recently the identity must have been proved.
	Window time.Duration
}

// Error names the window and nothing else.
func (e *ReauthenticationRequiredError) Error() string {
	return fmt.Sprintf("httpsec: reauthentication required within %s", e.Window)
}

// Is reports whether target is ErrReauthenticationRequired.
func (e *ReauthenticationRequiredError) Is(target error) bool {
	return target == ErrReauthenticationRequired
}

// ChallengeError refuses a request that must satisfy a challenge before it
// goes further.
//
// It carries what the consumer's error handling needs to prompt for: the kind
// asked for, the pending session when one was established, and the token
// issued alongside it when the challenge was raised at login. Its text names
// only the kind — a challenge is reported to a client, and a token or a
// session handle written into an error string reaches every log that records
// one.
type ChallengeError struct {
	// Kind is what the caller is being asked for.
	Kind policy.ChallengeKind

	// Session is the pending session the caller answers the challenge on, and
	// is nil for a stateless first factor that established none.
	Session *session.Session

	// Token is the access token issued alongside the pending session, and is
	// empty unless one was issued when the challenge was raised.
	Token string

	// Methods are the second-factor methods the session's user can answer a
	// challenge of kind policy.ChallengeMFA with, in the order EnableMFA was
	// given them, as policy.UsableMFAMethods decides — the same decision the
	// policies made. It is never a partial list: when that decision fails, the
	// request is refused with the failure instead of this challenge. It is
	// empty when the lookups succeeded and none is usable, which leaves the
	// caller only logout. It is nil for every other kind, and for a
	// second-factor challenge raised without a session.
	Methods []MFAMethod
}

// MFAMethod is one way the session's user can answer a second-factor
// challenge, for the consumer's handler to offer.
type MFAMethod struct {
	// Name is the method's name, the path segment its verify path, and its
	// begin path when it has one, end with.
	Name string

	// Channel is the medium the method's responses travel over.
	Channel factor.Channel

	// Begins reports that the method has a begin step: the client posts to its
	// begin path for a challenge before it can answer.
	Begins bool
}

// Error names the challenge kind and nothing else. The session handle and the
// token are fields, not text.
func (e *ChallengeError) Error() string {
	return fmt.Sprintf("httpsec: challenge required: %s", e.Kind)
}

// statusRow is one refusal and the status it answers with. The table is
// ordered, and the first row whose sentinel the error matches decides, so two
// rows can never disagree about an error that wraps both.
type statusRow struct {
	err    error
	status int
}

var statusTable = []statusRow{
	{ErrAuthenticationRequired, http.StatusUnauthorized},
	{authorize.ErrAuthenticationRequired, http.StatusUnauthorized},

	// The user store could not answer, so no credential was judged. It does
	// not match ErrAuthenticationFailed, so a consumer's handler can tell it
	// apart, but it is answered as that refusal is: an outage answered
	// otherwise would tell a held account from a free one, and a known user
	// from an unknown one, wherever the store fails for some rows only.
	{authenticate.ErrUnavailable, http.StatusUnauthorized},
	{authenticate.ErrAuthenticationFailed, http.StatusUnauthorized},
	{policy.ErrSessionIdle, http.StatusUnauthorized},

	// A browser endpoint of the OpenID Provider that will not hear its source. It wraps
	// ratelimit.ErrThrottled, so its row must stand ahead of the one below.
	{ErrOIDCThrottled, http.StatusTooManyRequests},
	{ratelimit.ErrThrottled, http.StatusUnauthorized},

	// A wrong second-factor code, at verification or enrolment, and the
	// per-user throttles in front of them. The caller is asked to try again
	// with a credential, which is what 401 says. An invalid, expired or voided
	// emailed code is the same refusal as a wrong device code: its sentinel
	// wraps mfa.ErrInvalidCode, so this row answers it too.
	{mfa.ErrInvalidCode, http.StatusUnauthorized},
	{mfa.ErrVerifyThrottled, http.StatusUnauthorized},
	{mfa.ErrEnrolmentThrottled, http.StatusUnauthorized},

	// A refused magic-link redemption: a wrong, spent or expired token and a
	// throttled source are one indistinguishable refusal, and the client is
	// asked to authenticate again.
	{magiclink.ErrInvalidLink, http.StatusUnauthorized},

	// A DPoP proof that is missing, does not verify or does not fit its
	// token: the client is asked to present a credential with a valid proof.
	// A proof without a current server nonce is one of them, and is asked to
	// retry with the nonce the response carries.
	{ErrDPoPNonceRequired, http.StatusUnauthorized},
	{ErrInvalidDPoPProof, http.StatusUnauthorized},

	// A certificate-bound credential on a request that does not present its
	// certificate (RFC 8705): the client is asked to present the credential
	// over a connection with the certificate it was bound to.
	{ErrCertificateBinding, http.StatusUnauthorized},

	// A refused recovery (recovery.ErrRefused) and a throttled saved-code
	// presentation (recovery.ErrCodeThrottled) need no rows: they wrap
	// authenticate.ErrAuthenticationFailed and ratelimit.ErrThrottled, so the
	// rows above answer them 401, exactly as a failed login.

	{ErrCredentialsMissing, http.StatusBadRequest},
	{ErrMalformedRequest, http.StatusBadRequest},
	{ErrHostNotAllowed, http.StatusBadRequest},
	{ErrCrossSiteRequest, http.StatusForbidden},

	// A request the automation-challenge verifier refused: the client must
	// pass the challenge, not present other credentials. A verifier that
	// could not answer (ErrChallengeUnavailable) is not here: it is answered
	// 500 before this table is read.
	{ErrChallengeRequired, http.StatusForbidden},

	// A passkey ceremony response the verifier could not read. The chain's
	// endpoints answer it as ErrCredentialsMissing, wrapping it; this row
	// answers it the same way where it reaches StatusForError alone.
	{passkey.ErrMalformedResponse, http.StatusBadRequest},
	{recovery.ErrMalformed, http.StatusBadRequest},
	{oidc.ErrInvalidLogoutToken, http.StatusBadRequest},
	{ErrRequestTooLarge, http.StatusRequestEntityTooLarge},

	// A new password refused as reused: the request is well formed and the
	// value is refused, so a client can show a field-level message. A history
	// that could not be read or recorded is a dependency failure, not a
	// refusal of the caller's input, and carries no row here: it falls through
	// to the unrecognised-error 500 below, like any other unrecognised error.
	//
	// Every other refusal of a password policy ([password.ErrPasswordRejected],
	// which [password.ErrReused] also matches) answers the same way. A breach
	// lookup that could not answer ([password.ErrLookupUnavailable]) is a
	// dependency failure and falls through to the 500 below.
	{password.ErrReused, http.StatusUnprocessableEntity},
	{password.ErrPasswordRejected, http.StatusUnprocessableEntity},

	// An account lock is a client that has sent too many failed attempts in a
	// span (RFC 6585 §4), not a locked WebDAV resource (RFC 4918 §11.3), so it
	// answers 429 beside too many sessions. This row answers only a lock the
	// consumer chose to disclose: by default form login and Basic join the lock
	// to authenticate.ErrAuthenticationFailed, which the row above answers 401
	// first, so a lock reads as a wrong password.
	{lockout.ErrAccountLocked, http.StatusTooManyRequests},
	// A held identifier is also a locked one; it answers the same way.
	{lockout.ErrAccountHeld, http.StatusTooManyRequests},
	{policy.ErrTooManySessions, http.StatusTooManyRequests},

	// A held recovery presented before its hold ends: well formed and
	// authentic, but in conflict with the record's state. A client can retry
	// once the hold is over, which a 403 would not say.
	{recovery.ErrNotYetCompletable, http.StatusConflict},

	// The OpenID Provider's refusals its endpoints do not answer themselves. The
	// provider's own sentinels are the rows, so the chain's, which wrap them, and
	// the provider's reaching here unwrapped answer alike.
	{oidcprovider.ErrInvalidAuthorization, http.StatusBadRequest},
	{oidcprovider.ErrUnknownHandle, http.StatusBadRequest},
	{oidcprovider.ErrConsentMalformed, http.StatusBadRequest},
	{oidcprovider.ErrInvalidEndSession, http.StatusBadRequest},
	{oidcprovider.ErrReauthenticate, http.StatusUnauthorized},
	{oidcprovider.ErrForeignConsent, http.StatusNotFound},

	// A rotation that lost a concurrent renewal of the same session. The
	// session core's sentinel is the row, so the chain's own, which wraps it,
	// and the core's reaching here unwrapped answer alike: the client retries
	// with the credential it holds. A reused session needs no row: it leaves
	// the chain joined with ErrAuthenticationRequired, answered 401 above.
	{session.ErrRenewalConflict, http.StatusConflict},

	// A rotation of an API key that is revoked, expired or was ended by a
	// concurrent rotation or revocation: well formed, but in conflict with
	// the key's state, and a retry with the same key will not succeed.
	{apikey.ErrRotationRefused, http.StatusConflict},

	// A family that renewed too often in the window, or a renewal limiter that
	// could not answer: the client backs off, as for any other 429.
	{ErrRenewalThrottled, http.StatusTooManyRequests},

	// A subject that asked for more one-time tokens within the issuance
	// window than the limit allows: the client backs off, as for any other
	// 429.
	{onetime.ErrIssueLimitReached, http.StatusTooManyRequests},

	// A federated-login path segment naming no registered provider, and a
	// second-factor path segment naming no configured method. Which providers
	// and methods exist is configuration, not a secret.
	{oidc.ErrUnknownProvider, http.StatusNotFound},
	{ErrUnknownMFAMethod, http.StatusNotFound},

	// A passkey identifier naming no passkey of the session's user: another
	// user's and none at all are deliberately the same refusal.
	{passkey.ErrNotFound, http.StatusNotFound},

	// An API key identifier naming no key of the caller: another owner's and
	// none at all are the same refusal, as for a passkey.
	{apikey.ErrKeyNotFound, http.StatusNotFound},

	// A sign-in handle naming no live sign-in of the session's user: a
	// malformed handle, an unknown one and another user's are the same
	// refusal. A store failure while listing or ending sign-ins has no row: it
	// is a dependency failure answered 500 with fixed text.
	{ErrSessionHandleNotFound, http.StatusNotFound},

	{authorize.ErrAccessDenied, http.StatusForbidden},
	{policy.ErrDenied, http.StatusForbidden},
	{policy.ErrMFARequired, http.StatusForbidden},
	{policy.ErrMFARequirementUnsatisfiable, http.StatusForbidden},
	{policy.ErrMFAEnrolmentRequired, http.StatusForbidden},
	{policy.ErrSecondFactorSameChannel, http.StatusForbidden},
	{policy.ErrFederatedAssuranceNotMet, http.StatusForbidden},
	{mfa.ErrSameChannel, http.StatusForbidden},
	{ErrMFAMethodNotUsable, http.StatusForbidden},
	{ErrNoMFAChallengePending, http.StatusForbidden},
	{mfa.ErrAlreadyEnrolled, http.StatusForbidden},

	// A second factor whose authenticator itself is refused: suspected to be
	// a clone, or suspended. The response was not a wrong guess, and trying
	// again with the same authenticator will not succeed, which 403 says.
	{mfa.ErrAuthenticatorRefused, http.StatusForbidden},
	{recovery.ErrCooldown, http.StatusForbidden},
	{recovery.ErrReauthenticationRequired, http.StatusForbidden},

	// Passkey refusals of an authenticated caller who must act differently,
	// not present credentials again: a passkey still pending its
	// confirmation, an attestation the policy refuses, a user at the passkey
	// limit, and a session too old or under-assured to change its passkeys.
	// A suspected clone and a suspended passkey need no rows: they wrap
	// mfa.ErrAuthenticatorRefused, answered 403 above. A throttled
	// registration begin needs none either: it wraps ratelimit.ErrThrottled,
	// answered 401.
	{passkey.ErrPending, http.StatusForbidden},
	{passkey.ErrAttestationRefused, http.StatusForbidden},
	{passkey.ErrPerUserLimitReached, http.StatusForbidden},
	{passkey.ErrReauthenticationRequired, http.StatusForbidden},

	// The recency guard's refusal and an unusable re-authentication method.
	// The guard's *ReauthenticationRequiredError matches the first through
	// its Is method, so it needs no row of its own.
	{ErrReauthenticationRequired, http.StatusForbidden},
	{ErrReauthenticationMethodNotUsable, http.StatusForbidden},
}

// StatusForError maps a refusal to the status it is answered with.
//
// It is the whole mapping contract: every default response this library
// writes, and every helper the integrations offer, goes through it, so a
// consumer's own error handler can fall back to it and agree with the library
// on everything it does not handle itself. It recognises wrapped and joined
// errors, and an error it does not recognise is a server fault, never a
// silent success.
//
// A credential the chain could not issue is checked before anything else, and
// is 500 whatever the token generator's error wraps: an issuing failure is a
// dependency failure, never a refusal, so a generator whose error wraps a
// sentinel below that is answered 401 still does not send the client back to
// log in. It is 500 as well when a refusal is joined beside the issuing
// failure, not only when its cause wraps one: the failure decides. The
// generator's error stays reachable for a consumer's own handler. An
// automation-challenge verifier that could not answer (ErrChallengeUnavailable)
// is 500 in the same way, whatever its own error wraps, while a request the
// verifier refused (ErrChallengeRequired) is 403. So is a dependency of the
// OpenID Provider that failed (oidcprovider.ErrDependency), and a dependency that
// stopped a recovery before any code but an MFA one was spent (recovery.ErrDependency).
//
// A challenge is checked next, so a challenge that also wraps a refusal
// sentinel is answered as the challenge: the caller can still satisfy it. A
// password-change, enrolment or account-recovery challenge is 403, because the
// caller is authenticated and must act rather than present credentials again;
// every other kind, a consumer's own included, is 401.
//
// A new password a consumer's password-change function refused as reused
// ([password.ErrReused]) is 422: the request is well formed and the
// value is refused, not 400 (malformed), 401 (authentication) or 403 (the
// password-change challenge itself, which would make the client unable to
// tell "you still owe a change" from "that password was used recently"). A
// history that could not be read or recorded ([password.ErrHistoryUnavailable])
// is a dependency failure, not a refusal of the caller's input, and maps to
// 500 like any other unrecognised error.
//
// A user store that could not answer a login, a Basic request, a recovery's
// password proof or an API key's owner check ([authenticate.ErrUnavailable])
// is 401, the answer a wrong password gets. It still does not match
// [authenticate.ErrAuthenticationFailed], so a consumer's own error handler,
// which replaces the default response, can match it and answer 503 instead.
// That handler brings back two oracles the 401 closes: with locks concealed,
// a held or locked account answers 401 during an outage while a free one
// answers 503, revealing lock state; and in a partial outage, where a found
// user's load reads more than a miss does, known users answer 503 and unknown
// ones 401, revealing which usernames exist.
func StatusForError(err error) int {
	if err == nil {
		return http.StatusInternalServerError
	}

	// An issuing failure is a dependency failure whatever its cause wraps,
	// so it is answered before the challenge and the refusal table are read.
	var issuing *issueFailure
	if errors.As(err, &issuing) {
		return http.StatusInternalServerError
	}

	// So is a challenge verifier that could not answer, whatever its own
	// error wraps: an outage never reads to the client as a refusal.
	if errors.Is(err, ErrChallengeUnavailable) {
		return http.StatusInternalServerError
	}

	// And a dependency of the OpenID Provider or of a recovery that failed,
	// whatever its own error wraps.
	if errors.Is(err, oidcprovider.ErrDependency) || errors.Is(err, recovery.ErrDependency) {
		return http.StatusInternalServerError
	}

	var ch *ChallengeError
	if errors.As(err, &ch) {
		switch ch.Kind {
		case policy.ChallengePasswordChange, policy.ChallengeMFAEnrolment, policy.ChallengeAccountRecovery:
			return http.StatusForbidden
		default:
			return http.StatusUnauthorized
		}
	}

	for _, row := range statusTable {
		if errors.Is(err, row.err) {
			return row.status
		}
	}

	return http.StatusInternalServerError
}
