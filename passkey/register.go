package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// BeginRegistration starts a registration for s's user and returns the
// creation options for the browser, as the verifier renders them.
//
// It admits s first (see the package's admission rule): a stale or
// insufficiently assured full session is refused with
// ErrReauthenticationRequired. A user issued the registration challenge limit
// within the hour is refused with ErrRegistrationThrottled, as is one the
// challenge store cannot count for. Nothing is issued on any refusal.
//
// The user's one handle is assigned on their first begin and reused on every
// later one. The challenge is a one-time token of the purpose
// "passkey-registration", its subject the user and bound to s's ID, and its
// string is the challenge the options carry. Every credential the user holds,
// in any state, is listed for the authenticator to exclude.
func (m *Manager) BeginRegistration(ctx context.Context, s *session.Session) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := m.admit(ctx, s); err != nil {
		return nil, err
	}

	user := s.UserID

	count, err := m.registration.IssuedCount(ctx, string(user))
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not count registration challenges", ErrRegistrationThrottled)
	}

	if count >= m.issueLimit {
		return nil, ErrRegistrationThrottled
	}

	details, err := m.users.LoadByUserID(ctx, user)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not load the user")
	}

	name, display, err := m.names(ctx, details)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not resolve the user's names")
	}

	handle, err := m.handle(ctx, s)
	if err != nil {
		return nil, err
	}

	held, err := m.credentials.List(ctx, user)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not list the user's passkeys")
	}

	exclude := make([]Descriptor, 0, len(held))
	for _, c := range held {
		exclude = append(exclude, Descriptor{ID: c.CredentialID, Transports: c.Transports})
	}

	challenge, _, err := m.registration.Issue(ctx, string(user), onetime.WithBinding(s.ID))
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not issue a registration challenge")
	}

	return m.verifier.CreationOptions(ctx, CreationInput{
		UserHandle:  handle,
		UserName:    name,
		DisplayName: display,
		Challenge:   challenge,
		Timeout:     m.ttl,
		Exclude:     exclude,
		UV:          m.uv,
		ResidentKey: m.residentKey,
	})
}

// handle returns s's user's handle, assigning a new random one when they have
// none.
func (m *Manager) handle(ctx context.Context, s *session.Session) ([]byte, error) {
	offered := make([]byte, HandleSize)
	if _, err := io.ReadFull(m.random, offered); err != nil {
		return nil, diag.Wrap(err, "passkey: could not draw a user handle")
	}

	handle, err := m.handles.Assign(ctx, s.UserID, offered)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not assign a user handle")
	}

	return handle, nil
}

// ErrMalformedResponse is the refusal of a registration or assertion response
// the verifier could not read. Nothing is spent or stored: a response that
// cannot be read names no challenge to spend. An HTTP layer answers it as
// missing credentials.
var ErrMalformedResponse = errors.New("passkey: unreadable authenticator response")

// RegistrationContext carries what the caller decides about a registration
// that the manager cannot see from the session alone.
type RegistrationContext struct {
	// EmailConfirmation is the enrolment path's email-confirmation setting. It
	// applies only to an enrolment-only session: when true, the passkey waits
	// for a code emailed to the user's contact address.
	EmailConfirmation bool
	// ContactResolver resolves the address the emailed code goes to. Nil uses
	// the manager's, mfa.UsernameAsAddress by default.
	ContactResolver mfa.ContactResolver
	// ConfirmLimiter counts failed emailed-code confirmations under
	// EmailConfirmThrottleKey. Nil uses the manager's own, which allows 5 per
	// 15 minutes per user in this process.
	ConfirmLimiter ratelimit.Limiter
}

// RegistrationResult is a finished registration.
type RegistrationResult struct {
	// Credential is the stored passkey.
	Credential *Credential
	// Activated reports that the passkey is active now. A pending passkey
	// activates when its last confirmation is made.
	Activated bool
	// RecoveryCodes are the user's new saved recovery codes when the passkey
	// awaits their confirmation. This is the only time they are readable.
	RecoveryCodes []string
	// BackupEligible mirrors the new passkey's backup-eligible flag.
	BackupEligible bool
	// NoSyncedPasskey reports that neither the new passkey, active or
	// pending, nor any of the user's active passkeys is backup-eligible, for
	// the consumer's interface to advise registering a second one.
	NoSyncedPasskey bool
	// RecoveryNotSetUp reports, in the optional recovery-codes mode, that the
	// user has no other way back in.
	RecoveryNotSetUp bool
}

// FinishRegistration finishes a registration s began, in this order:
//
//  1. Read the response. One the verifier cannot read is ErrMalformedResponse,
//     and nothing is spent.
//  2. Spend the challenge it answers: it must be one this manager issued to
//     s's ID for s's user, unexpired and unspent. It is spent before the
//     response is verified, whatever happens next, so of racing finishes
//     presenting one challenge at most one is verified.
//  3. Verify the response against the relying party and the user-verification
//     requirement. A refused attestation is ErrAttestationRefused.
//  4. Run the consumer's registration check; its error is returned unchanged.
//  5. Refuse a user holding the passkey limit, counting every state, with
//     ErrLimitReached.
//  6. Store the credential. A credential ID already registered, to anyone, is
//     refused, leaving the existing record unchanged.
//
// Every other refusal of the ceremony is authenticate.ErrAuthenticationFailed,
// and no refusal stores anything.
//
// The passkey is named by the response's proposed name, normalised by
// NormaliseName: a name that is too long or holds a control character is
// replaced by the default date name, never truncated or refused.
func (m *Manager) FinishRegistration(
	ctx context.Context, s *session.Session, body []byte, rc RegistrationContext,
) (*RegistrationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if s == nil || s.UserID == "" {
		return nil, authenticate.ErrAuthenticationFailed
	}

	parsed, err := m.verifier.ParseRegistration(body)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: unreadable registration response", ErrMalformedResponse)
	}

	if nilcheck.IsNil(parsed) {
		return nil, ErrMalformedResponse
	}

	challenge, err := m.spendRegistration(ctx, s, parsed.Challenge())
	if err != nil {
		return nil, err
	}

	nc, err := m.verifier.VerifyRegistration(ctx, parsed, RegistrationExpectation{Challenge: challenge, UV: m.uv})

	switch {
	case errors.Is(err, ErrAttestationRefused):
		return nil, diag.Wrap(err, "passkey: attestation refused", ErrAttestationRefused)
	case err != nil:
		return nil, diag.Wrap(err, "passkey: registration response refused", authenticate.ErrAuthenticationFailed)
	case nc == nil:
		return nil, authenticate.ErrAuthenticationFailed
	case m.uv == UVRequired && !nc.UserVerified:
		return nil, authenticate.ErrAuthenticationFailed
	}

	if m.regCheck != nil {
		if err := m.regCheck(ctx, RegistrationFacts{
			User:               s.UserID,
			AAGUID:             nc.AAGUID,
			BackupEligible:     nc.BackupEligible,
			BackupState:        nc.BackupState,
			AttestationFormat:  nc.AttestationFormat,
			AttestationTrusted: nc.AttestationTrusted,
		}); err != nil {
			return nil, err
		}
	}

	held, err := m.credentials.Count(ctx, s.UserID)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not count the user's passkeys")
	}

	if held >= m.passkeyLimit {
		return nil, ErrLimitReached
	}

	now := m.clock.Now()

	plan, err := m.preparePending(ctx, s, rc, now)
	if err != nil {
		return nil, err
	}

	cid, err := m.ids.NewID()
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not mint a credential identifier")
	}

	c := &Credential{
		ID:                   cid,
		User:                 s.UserID,
		CredentialID:         nc.CredentialID,
		PublicKey:            nc.PublicKey,
		SignCount:            nc.SignCount,
		BackupEligible:       nc.BackupEligible,
		BackupState:          nc.BackupState,
		Transports:           nc.Transports,
		AAGUID:               nc.AAGUID,
		AttestationFormat:    nc.AttestationFormat,
		AttestationStatement: nc.AttestationStatement,
		Name:                 NormaliseName(parsed.Name(), now),
		CreatedAt:            now,
		State:                StateActive,
		Pending:              plan.reasons,
		EmailCode:            plan.emailCode,
	}

	if plan.reasons != 0 {
		c.State = StatePending
	}

	if err := m.credentials.Insert(ctx, c); err != nil {
		if errors.Is(err, ErrDuplicateCredential) {
			return nil, authenticate.ErrAuthenticationFailed
		}

		return nil, diag.Wrap(err, "passkey: could not store the passkey")
	}

	activated := c.State == StateActive
	if activated {
		m.activated(ctx, c, rc)
	}

	return &RegistrationResult{
		Credential:       c,
		Activated:        activated,
		RecoveryCodes:    plan.codes,
		BackupEligible:   c.BackupEligible,
		NoSyncedPasskey:  m.noSyncedPasskey(ctx, c),
		RecoveryNotSetUp: plan.recoveryNotSetUp,
	}, nil
}

// noSyncedPasskey reports whether neither the new passkey c nor any active
// passkey of its user is backup-eligible. The answer is advice for the
// consumer's interface, so a store that cannot list is logged and answered
// false rather than failing a registration already stored.
func (m *Manager) noSyncedPasskey(ctx context.Context, c *Credential) bool {
	if c.BackupEligible {
		return false
	}

	held, err := m.credentials.List(ctx, c.User)
	if err != nil {
		m.sampled(ctx, slog.LevelError, "list|synced", msgSyncedUnknown, diag.Failure("list", err)...)

		return false
	}

	for _, h := range held {
		if h.State == StateActive && h.BackupEligible {
			return false
		}
	}

	return true
}

// spendRegistration checks and spends the registration challenge presented,
// as clientDataJSON carries it, for s, and returns its token string. It must
// be one this manager issued for s's user, bound to s's ID. A challenge bound
// to s's ID is spent before its user is compared, so an attempt for another
// user spends it too. Every refusal is authenticate.ErrAuthenticationFailed.
func (m *Manager) spendRegistration(ctx context.Context, s *session.Session, presented string) (string, error) {
	challenge, err := DecodeChallenge(presented)
	if err != nil || challenge == "" {
		return "", authenticate.ErrAuthenticationFailed
	}

	checked, err := m.registration.Check(ctx, challenge, s.ID)
	if err != nil {
		return "", authenticate.ErrAuthenticationFailed
	}

	// Spent before the subject is compared: any attempt that presents a
	// challenge bound to s's ID spends it, whatever its outcome.
	if err := m.registration.Consume(ctx, checked); err != nil {
		return "", authenticate.ErrAuthenticationFailed
	}

	if checked.Token().Subject != string(s.UserID) {
		return "", authenticate.ErrAuthenticationFailed
	}

	return challenge, nil
}
