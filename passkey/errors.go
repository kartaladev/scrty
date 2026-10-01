package passkey

import (
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/ratelimit"
)

// ErrConfig is wrapped by every error returned for a wiring mistake, such as a
// malformed relying party, so a consumer can tell a configuration error from a
// runtime failure without matching on message text.
var ErrConfig = errors.New("passkey: invalid configuration")

// ErrCloneSuspected is the refusal of an assertion whose signature counter did
// not move forward on a credential that is still active: the authenticator may
// have been cloned. By default the credential is suspended as well.
//
// It wraps mfa.ErrAuthenticatorRefused, so it is answered as forbidden and is
// not counted as a failed guess.
var ErrCloneSuspected = fmt.Errorf("passkey: suspected cloned authenticator: %w", mfa.ErrAuthenticatorRefused)

// ErrSuspended is the refusal of an assertion from a suspended credential.
// Suspension is terminal: the credential never verifies again.
//
// It wraps mfa.ErrAuthenticatorRefused, so it is answered as forbidden and is
// not counted as a failed guess.
var ErrSuspended = fmt.Errorf("passkey: credential suspended: %w", mfa.ErrAuthenticatorRefused)

// ErrPending is the refusal of a passwordless login from a credential that is
// still pending: it awaits a confirmation before it may be used.
var ErrPending = errors.New("passkey: credential pending confirmation")

// ErrAttestationRefused is the refusal of a registration whose attestation the
// configured attestation policy does not accept.
var ErrAttestationRefused = errors.New("passkey: attestation refused")

// ErrLimitReached is the refusal of a registration for a user who already
// holds the maximum number of passkeys.
var ErrLimitReached = errors.New("passkey: passkey limit reached")

// ErrReauthenticationRequired is the refusal of an action from a session whose
// latest authentication is older than the freshness window.
var ErrReauthenticationRequired = errors.New("passkey: reauthentication required")

// ErrNotFound reports a credential that does not exist, or that does not
// belong to the user asking. The two are deliberately one error.
var ErrNotFound = errors.New("passkey: credential not found")

// ErrRegistrationThrottled is the refusal of a registration begin for a user
// over the issuance limit, or when the limiter could not say whether they are.
//
// It wraps ratelimit.ErrThrottled, so a caller that already answers a
// throttled source answers it the same way.
var ErrRegistrationThrottled = fmt.Errorf("passkey: registrations throttled: %w", ratelimit.ErrThrottled)

// ErrDuplicateCredential is a CredentialStore's refusal of an insert whose
// WebAuthn credential ID is already stored, whatever user holds it. The write
// decides it, so of concurrent inserts of one credential ID exactly one
// succeeds.
var ErrDuplicateCredential = errors.New("passkey: credential ID already registered")
