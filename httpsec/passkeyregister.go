package httpsec

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/session"
)

// begin starts a registration for the session's user and answers with the
// creation options. The manager admits the session, throttles the user and
// issues the challenge; its refusals are returned unchanged.
func (p *passkeyInterceptor) begin(ex *Exchange, s *session.Session) error {
	options, err := p.deps.Passkeys.BeginRegistration(ex.Context(), s)
	if err != nil {
		return err
	}

	return p.respondBegin(ex, options)
}

// finish reads the authenticator's response, finishes the registration and,
// when the passkey is active at once, moves a confined session on to its
// second factor.
//
// The body is read before anything is spent: an oversized or unreadable one
// refuses the request with the challenge still unspent. A response the
// verifier cannot read is answered as missing credentials, as an unreadable
// body is, with the core's refusal still reachable through errors.Is.
func (p *passkeyInterceptor) finish(ex *Exchange, s *session.Session) error {
	body, err := postedJSON(ex.Request, passkey.RegistrationBodyLimit)
	if err != nil {
		return err
	}

	ctx := ex.Context()

	res, err := p.deps.Passkeys.FinishRegistration(ctx, s, body, p.registrationContext(s))
	if errors.Is(err, passkey.ErrMalformedResponse) {
		return refusedAs(ErrCredentialsMissing, textCredentialsMissing, err)
	}

	if err != nil {
		return err
	}

	if res.Activated {
		if err := p.bound(ctx, s); err != nil {
			return err
		}
	}

	return p.respondRegistration(ex, res)
}

// bound moves a confined session whose passkey has just become active on to
// the MFA-pending state, and saves it. The confinement marker and the
// recovery time stay: the MFA verify endpoint restores the deadlines and
// rotates the session when the new passkey is proven there. A full session is
// left as it is.
//
// The passkey is active whatever happens here. A save that fails leaves the
// session as it was, in memory too, and fails the request; a new login then
// finds the user enrolled on the passkey method.
func (p *passkeyInterceptor) bound(ctx context.Context, s *session.Session) error {
	if s.MFA != session.MFAEnrolmentPending && s.MFA != session.MFARecoveryPending {
		return nil
	}

	was := s.MFA
	s.MFA = session.MFAPending

	if err := p.deps.Sessions.Save(ctx, s); err != nil {
		s.MFA = was

		return diag.Wrap(err, msgPasskeySessionUnsaved)
	}

	return nil
}

// msgPasskeySessionUnsaved is the fixed text of a session save that failed
// after a passkey bound on it became active. The session store's own text may
// carry the user reference, so it is reachable through errors.Is and
// errors.As, never repeated.
const msgPasskeySessionUnsaved = "httpsec: the session a passkey was bound on could not be saved"

// passkeyBeginDocument is the begin endpoints' default answer.
type passkeyBeginDocument struct {
	PublicKey json.RawMessage `json:"publicKey"`
}

// writePasskeyBegin is the default begin responder: 200 with
// {"publicKey":<options>}, which no cache may keep, since the options carry a
// live challenge.
func writePasskeyBegin(ex *Exchange, options json.RawMessage) error {
	return writePasskeyDocument(ex, passkeyBeginDocument{PublicKey: options})
}

// passkeyRegistrationDocument is the finish endpoint's default answer. Its
// member names are the endpoint's documented contract.
type passkeyRegistrationDocument struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	State            string   `json:"state"`
	Pending          []string `json:"pending"`
	RecoveryCodes    []string `json:"recovery_codes"`
	BackupEligible   bool     `json:"backup_eligible"`
	NoSyncedPasskey  bool     `json:"no_synced_passkey"`
	RecoveryNotSetUp bool     `json:"recovery_not_set_up"`
}

// writePasskeyRegistration is the default registration responder: 200 with
// the passkey's identifier, name and state, the confirmations it awaits, the
// saved recovery codes when it awaits them (null otherwise) and the advisory
// flags, which no cache may keep, since it may carry the codes.
func writePasskeyRegistration(ex *Exchange, res *passkey.RegistrationResult) error {
	c := res.Credential

	return writePasskeyDocument(ex, passkeyRegistrationDocument{
		ID:               c.ID.String(),
		Name:             c.Name,
		State:            passkeyStateName(c.State),
		Pending:          passkeyPendingNames(c.Pending),
		RecoveryCodes:    res.RecoveryCodes,
		BackupEligible:   res.BackupEligible,
		NoSyncedPasskey:  res.NoSyncedPasskey,
		RecoveryNotSetUp: res.RecoveryNotSetUp,
	})
}

// passkeyStateName is how the default documents write a passkey's state.
func passkeyStateName(s passkey.State) string {
	switch s {
	case passkey.StateActive:
		return "active"
	case passkey.StatePending:
		return "pending"
	case passkey.StateSuspended:
		return "suspended"
	default:
		return "unknown"
	}
}

// passkeyPendingNames are how the default documents write the confirmations
// a pending passkey awaits, in a fixed order; never null.
func passkeyPendingNames(r passkey.PendingReason) []string {
	names := []string{}

	if r&passkey.AwaitingSavedCodes != 0 {
		names = append(names, "saved_codes")
	}

	if r&passkey.AwaitingEmailCode != 0 {
		names = append(names, "email_code")
	}

	return names
}

// writePasskeyDocument answers 200 with body as JSON that no cache may keep.
// A failure carries fixed text: a transport's write error names the
// connection's addresses.
func writePasskeyDocument(ex *Exchange, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return diag.Wrap(err, msgPasskeyNotWritten)
	}

	ex.Writer.SetHeader("Content-Type", "application/json")
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.WriteHeader(http.StatusOK)

	if _, err := ex.Writer.Write(encoded); err != nil {
		return diag.Wrap(err, msgPasskeyNotWritten)
	}

	return nil
}

// msgPasskeyNotWritten is the fixed text of a passkey response that could not
// be written.
const msgPasskeyNotWritten = "httpsec: the passkey response could not be written"
