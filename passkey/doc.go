// Package passkey adds WebAuthn passkeys to scrty: registration and
// management, passwordless login, the passkey as an MFA method, and clone
// handling.
//
// # Ports
//
// WebAuthn parsing and verification sit behind one port, Verifier. The core
// package carries no WebAuthn dependency, so it supplies no default Verifier;
// the library's implementation lives in the nested module
// github.com/kartaladev/scrty/passkey/webauthn. Any other Verifier may be used
// in its place, and is trusted exactly as the library's own.
//
// Credentials are kept by a CredentialStore and user handles by a HandleStore.
// The in-memory stores are the defaults; they hold one process's records only.
// Durable stores implement the same contracts and may be used in their place.
//
// # The relying party
//
// The relying party has no default: its ID, display name and allowed origins
// are required, and a malformed one is a configuration error at construction.
// Changing the relying-party ID orphans every registered passkey, because
// authenticators scope their credentials to it.
//
// # Admission
//
// Registering a passkey (Manager.BeginRegistration) and removing one
// (Manager.Remove) change the user's authenticators, so both admit the session
// first:
//
//   - a session with no user, or owing a password change, is refused;
//   - a full session — no pending challenge, never confined — must have met
//     its second factor when its account has one, and its latest
//     authentication, the later of its creation and its second factor, must
//     be within the management freshness window (WithManagementFreshness, 15
//     minutes by default);
//   - a recovery-pending or enrolment-only session may register without the
//     assurance and freshness checks, since the recovery is its
//     authentication and its life is short by construction; it may not
//     remove.
//
// The account has a second factor when its user can use a configured MFA
// method, as policy.UsableMFAMethods decides against the session's first
// factor. The configured MFA methods are RegistrationContext.MFAMethods, or
// Deps.MFAMethods when the context lists none. A chain with an MFA slot
// passes the slot's methods in the context, including the passkey MFA method
// when it is on the slot, which Deps.MFAMethods cannot list; a chain without
// an MFA slot passes none, so Deps.MFAMethods apply.
//
// The user's own active passkeys are a second factor the account has too,
// whatever the session's first factor, whenever a passkey route can meet the
// second factor: this manager's passkey MFA method is among the configured
// methods, or the caller serves passwordless login
// (RegistrationContext.PasswordlessLogin) and it proves the second factor
// (WithoutSecondFactorAtLogin not set). A password session of a passkey
// holder then steps up through the passkey MFA method. A session whose first
// factor is a passkey cannot: the method is on the same channel, which the
// security policies never offer as that session's second factor. It signs in
// again with user verification, or by password and then the passkey step-up.
// With no route a passkey meets no second factor, and counting it would leave
// its holder unable ever to manage passkeys. Pending and suspended passkeys
// never count.
//
// One limit is accepted and fails closed. When WithoutSecondFactorAtLogin is
// set, this manager's passkey MFA method is on the MFA slot, and a policy
// completes a passkey-first session without a second factor, that session
// cannot register or remove a passkey, and has no step-up to change that. It
// is refused, never admitted.
//
// The passkey MFA method is recognised as this manager's route by identity:
// the MFAMethod that (*Manager).MFAMethod returned, not a method that wraps or
// decorates it, and never one of another manager or the same name. A wrapped
// method still serves the MFA step-up, but it opens no route for admission.
// Passwordless login as a route, and the check of the configured methods, do
// not depend on it.
//
// Every refusal is ErrReauthenticationRequired, except that a failed MFA or
// passkey lookup refuses with fixed text that names no dependency's detail,
// and a nil entry in RegistrationContext.MFAMethods with ErrConfig for a
// session not already refused for having no user or owing a password change.
// Finishing a registration does not admit again: its challenge was issued only
// to an admitted session, bound to it, and lives one challenge TTL.
//
// # Secrets
//
// No error this package returns carries a challenge, user handle, public key,
// attestation statement, credential ID or emailed code. A credential is named
// only by its library identifier.
package passkey
