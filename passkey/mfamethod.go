package passkey

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/pkg/id"
)

// MethodName is the passkey MFA method's name: the path segment of its MFA
// begin and verify endpoints, and its name among the configured methods.
const MethodName = "passkey"

// The largest request bodies the library reads for a passkey ceremony: an
// assertion, at a passwordless finish or as a second factor, and a
// registration response, which carries an attestation and so is larger.
const (
	AssertionBodyLimit    = 16 << 10
	RegistrationBodyLimit = 64 << 10
)

// MFAMethod is the passkey as a second factor: an mfa.ChallengeMethod named
// MethodName on the factor.PublicKey channel, which also implements
// mfa.EnrolmentRemover for the operator reset. Build it with
// (*Manager).MFAMethod; the zero value is not usable.
//
// A user is enrolled on it while they hold at least one active passkey; a
// pending or suspended passkey does not count. Its channel is the passkey
// login's own, so the security policies never offer it as the second factor
// of a passkey login.
//
// Do not pass it to recovery.MFAEnrolments. The passkey kind, from
// (*Manager).RecoveryKind, takes part in the recovery reset and the way-back
// check one passkey at a time, and counts only active passkeys as a way back
// in. Passed to both, the user's passkeys would be listed twice, and in the
// reported-loss mode a report of the MFA method would remove all of them.
//
// It is safe for concurrent use.
type MFAMethod struct {
	m *Manager
}

var (
	_ mfa.ChallengeMethod  = (*MFAMethod)(nil)
	_ mfa.EnrolmentRemover = (*MFAMethod)(nil)
)

// MFAMethod returns the manager's passkeys as an MFA method, verified with the
// manager's verifier, user-verification requirement, login check and clone
// rule. Serve it on the MFA slot beside the other methods.
func (m *Manager) MFAMethod() *MFAMethod { return &MFAMethod{m: m} }

// Name reports MethodName.
func (*MFAMethod) Name() string { return MethodName }

// Channel reports factor.PublicKey, the channel of the passkey login.
func (*MFAMethod) Channel() factor.Channel { return factor.PublicKey }

// Response declares the assertion as a whole JSON body of at most
// AssertionBodyLimit bytes.
func (*MFAMethod) Response() mfa.ResponseFormat { return mfa.JSONBody(AssertionBodyLimit) }

// SupportsEnrolmentPath reports true: passkey registration enrols the method
// through the MFA enrolment path when the chain wires it to.
func (*MFAMethod) SupportsEnrolmentPath() bool { return true }

// Enrolled reports whether user holds at least one active passkey. A store
// failure is an error, never false.
func (pm *MFAMethod) Enrolled(ctx context.Context, user identity.UserID) (bool, error) {
	active, err := pm.m.activeCredentials(ctx, user)
	if err != nil {
		return false, err
	}

	return len(active) > 0, nil
}

// BeginChallenge renders the request options for a second-factor assertion
// answering challenge, the token string the MFA slot issued. They list every
// active passkey of user as an allowed credential, with its transports,
// whether or not it is discoverable, and ask for the configured user
// verification; their timeout is the challenge lifetime.
//
// A user with no active passkey is refused with ErrNotFound, and nothing is
// rendered: request options with no allowed credential would ask the client
// for any discoverable passkey at all.
func (pm *MFAMethod) BeginChallenge(
	ctx context.Context, user identity.UserID, challenge string,
) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	active, err := pm.m.activeCredentials(ctx, user)
	if err != nil {
		return nil, err
	}

	if len(active) == 0 {
		return nil, ErrNotFound
	}

	allow := make([]Descriptor, len(active))
	for i, c := range active {
		allow[i] = Descriptor{ID: c.CredentialID, Transports: c.Transports}
	}

	return pm.m.verifier.RequestOptions(ctx, RequestInput{
		Challenge: challenge, Timeout: pm.m.ttl, Allow: allow, UV: pm.m.uv,
	})
}

// PresentedChallenge returns the token string the assertion in response
// answers: its clientDataJSON challenge, decoded by DecodeChallenge. A
// response the verifier cannot read, or a challenge that does not decode to
// a non-empty string, is an error.
func (pm *MFAMethod) PresentedChallenge(response []byte) (string, error) {
	parsed, err := pm.m.verifier.ParseAssertion(response)
	if err != nil {
		return "", diag.Wrap(err, "passkey: unreadable assertion response", ErrMalformedResponse)
	}

	if nilcheck.IsNil(parsed) {
		return "", ErrMalformedResponse
	}

	challenge, err := DecodeChallenge(parsed.Challenge())
	if err != nil || challenge == "" {
		return "", ErrMalformedResponse
	}

	return challenge, nil
}

// Verify verifies the assertion in response as user's second factor. It takes
// the challenge from the response itself, so it is safe only behind the MFA
// slot's check-and-spend of that challenge: the slot issues the challenge
// bound to the session and spends it before calling Verify. A consumer must
// not call Verify on its own, since nothing else ties the challenge to the
// session or makes it single use.
//
// The assertion must come from one of user's active passkeys. It is verified
// as at a passwordless finish — signature, user verification, the stored
// backup-eligible flag, the consumer's login check, then the counter write
// under the clone rule — except that the user handle is not required, and,
// under UVPreferred, user presence without user verification is accepted,
// since a second factor proves possession. A user handle the response does
// carry must map to user (WebAuthn L3 section 7.2 step 6); an absent one is
// accepted.
//
// A suspected clone that suspends the credential also ends every session of
// user, the caller's pending one included, unless
// WithoutSessionRevocationOnClone was given.
//
// The refusals:
//   - a suspended passkey is ErrSuspended, and a suspected clone
//     ErrCloneSuspected; both wrap mfa.ErrAuthenticatorRefused, so the slot
//     does not count them as a wrong guess;
//   - the consumer's login check error is returned unchanged;
//   - an error from the verifier matching context.Canceled or
//     context.DeadlineExceeded is returned wrapped, still matchable, and is
//     not an invalid code, so the slot does not count it as a wrong guess;
//   - every other refusal — an unreadable response, an unknown, pending or
//     other user's credential, a signature that does not verify, missing user
//     verification under UVRequired — is mfa.ErrInvalidCode, so a caller
//     cannot tell which credentials exist;
//   - a store failure is returned as an error of its own.
func (pm *MFAMethod) Verify(ctx context.Context, user identity.UserID, response []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m := pm.m

	parsed, err := m.verifier.ParseAssertion(response)
	if err != nil || nilcheck.IsNil(parsed) {
		_ = m.refused(ctx, "malformed", id.Nil)
		return mfa.ErrInvalidCode
	}

	challenge, err := DecodeChallenge(parsed.Challenge())
	if err != nil || challenge == "" {
		_ = m.refused(ctx, "challenge", id.Nil)
		return mfa.ErrInvalidCode
	}

	c, err := m.credentials.FindByCredentialID(ctx, parsed.CredentialID())

	switch {
	case errors.Is(err, ErrNotFound):
		_ = m.refused(ctx, "unknown-credential", id.Nil)
		return mfa.ErrInvalidCode
	case err != nil:
		return diag.Wrap(err, "passkey: could not look up the credential")
	case c == nil:
		_ = m.refused(ctx, "unknown-credential", id.Nil)
		return mfa.ErrInvalidCode
	case c.User != user:
		_ = m.refused(ctx, "owner", c.ID)
		return mfa.ErrInvalidCode
	}

	switch c.State {
	case StateActive:
	case StateSuspended:
		_ = m.refused(ctx, "suspended", c.ID)
		return ErrSuspended
	case StatePending:
		_ = m.refused(ctx, "pending", c.ID)
		return mfa.ErrInvalidCode
	default:
		_ = m.refused(ctx, "state", c.ID)
		return mfa.ErrInvalidCode
	}

	// WebAuthn L3 §7.2 step 6: the user is known before the ceremony, so a
	// user handle the response carries must map to that user. An absent one
	// is accepted.
	if handle := parsed.UserHandle(); len(handle) > 0 {
		owner, ok, err := m.handles.UserFor(ctx, handle)
		if err != nil {
			return diag.Wrap(err, "passkey: could not look up the user handle")
		}

		if !ok || owner != user {
			_ = m.refused(ctx, "handle", c.ID)
			return mfa.ErrInvalidCode
		}
	}

	_, err = m.verifyAssertion(ctx, parsed, c, AssertionExpectation{Challenge: challenge, UV: m.uv})
	if errors.Is(err, authenticate.ErrAuthenticationFailed) {
		return mfa.ErrInvalidCode
	}

	return err
}

// RemoveEnrolment removes every passkey user holds, in every state, for the
// operator reset. A user with none is not an error.
func (pm *MFAMethod) RemoveEnrolment(ctx context.Context, user identity.UserID) error {
	if _, err := pm.m.credentials.DeleteUser(ctx, user); err != nil {
		return diag.Wrap(err, "passkey: could not remove the user's passkeys")
	}

	return nil
}

// activeCredentials lists user's active credentials, in the store's order. A
// store failure is an error, never an empty list.
func (m *Manager) activeCredentials(ctx context.Context, user identity.UserID) ([]*Credential, error) {
	all, err := m.credentials.List(ctx, user)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not list the user's passkeys")
	}

	active := all[:0:0]

	for _, c := range all {
		if c != nil && c.State == StateActive {
			active = append(active, c)
		}
	}

	return active, nil
}
