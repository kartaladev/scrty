package passkey

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// The emailed code: six digits, honoured for ten minutes.
const (
	emailCodeDigits = 6
	emailCodeSpace  = 1_000_000
	emailCodeTTL    = 10 * time.Minute
)

// emailTimeLayout is how the emailed code's message writes an instant: in UTC,
// with the zone named.
const emailTimeLayout = "2 January 2006 15:04 MST"

// msgLimiterNotRecorded is logged when a failed confirmation could not be
// counted.
const msgLimiterNotRecorded = "passkey: a failed confirmation was not counted"

// EmailConfirmThrottleKey is the bucket key failed emailed-code confirmations
// are counted under for user. It equals the MFA enrolment path's confirmation
// key, so one user's budget is shared between the two. The user reference
// travels through unparsed.
func EmailConfirmThrottleKey(user identity.UserID) string {
	return "mfa-enrol-confirm:" + string(user)
}

// pendingPlan is what a registration finish settled about its passkey's
// pending reasons before storing it, and, once settled, the saved codes it
// generated after.
type pendingPlan struct {
	reasons          PendingReason
	codes            []string
	emailCode        *EmailCode
	recoveryNotSetUp bool
}

// unsettledDeleteTimeout bounds the removal of a passkey whose finish failed
// after storing it. The removal runs under a context the caller cannot cancel,
// so a client that hangs up mid-finish does not leave the passkey behind; the
// bound keeps a store that does not answer from holding the request forever.
// It has no option: a removal that times out leaves a pending passkey the
// user's next registration replaces, and nothing a consumer could tune changes
// that.
const unsettledDeleteTimeout = 5 * time.Second

// planPending decides the pending reasons of s's new passkey and prepares,
// before the passkey is stored, what has no effect a refused finish could
// leave behind, in this order:
//
//  1. PendingEmailCode when s is enrolment-only and rc's email confirmation
//     is on.
//  2. PendingSavedCodes when saved codes are wired, the optional mode is off
//     and the user has no other way back in (see hasWayBack). A failed check
//     refuses. In the optional mode the answer is reported instead.
//  3. The user's abandoned registrations are deleted (see deleteAbandoned):
//     with PendingSavedCodes, their pending passkeys awaiting saved codes;
//     with PendingEmailCode, those awaiting an emailed code, since
//     registering again is the only way to replace a lost or expired code. A
//     passkey is abandoned only when it was created before issued, the
//     instant this finish's registration challenge was issued. These run
//     before the insert so the passkeys they replace no longer count against
//     the limit.
//  4. With PendingEmailCode, the code is drawn, and stored with the passkey.
//
// Generating saved codes and sending the emailed code wait for settlePending,
// after the insert: a finish the limit refuses must neither replace the set
// another finish showed its user nor send a code for a passkey never stored.
func (m *Passkeys) planPending(
	ctx context.Context, s *session.Session, rc RegistrationContext, now, issued time.Time,
) (*pendingPlan, error) {
	var p pendingPlan

	if s.MFA == session.MFAEnrolmentPending && rc.EmailConfirmation {
		p.reasons |= PendingEmailCode
	}

	if m.recovery != nil {
		back, err := m.hasWayBack(ctx, s.UserID)
		if err != nil {
			return nil, err
		}

		switch {
		case back:
		case m.optionalCodes:
			p.recoveryNotSetUp = true
		default:
			p.reasons |= PendingSavedCodes
		}
	}

	if err := m.deleteAbandoned(ctx, s.UserID, p.reasons, issued); err != nil {
		return nil, err
	}

	if p.reasons&PendingEmailCode != 0 {
		code, err := m.drawEmailCode()
		if err != nil {
			return nil, err
		}

		p.emailCode = &EmailCode{Code: code, ExpiresAt: now.Add(emailCodeTTL)}
	}

	return &p, nil
}

// settlePending does, once c is stored, what its pending reasons need that a
// refused finish must not do, in this order:
//
//  1. With PendingSavedCodes, a new set of saved codes is generated,
//     replacing the user's set, and kept in p for the response.
//  2. With PendingEmailCode, the drawn code is queued. A sender that refuses
//     to queue it fails the finish.
//
// A failure is returned for the caller to remove c, so no passkey is left
// awaiting codes nobody saw. The cost: a failure after the codes are generated
// leaves the user with a set they never saw, which the retry replaces.
func (m *Passkeys) settlePending(ctx context.Context, c *Credential, rc RegistrationContext, p *pendingPlan) error {
	if p.reasons&PendingSavedCodes != 0 {
		codes, err := m.recovery.Codes.Generate(ctx, c.User)
		if err != nil {
			return diag.Wrap(err, "passkey: could not generate saved recovery codes")
		}

		p.codes = codes
	}

	if p.reasons&PendingEmailCode != 0 {
		if err := m.sendEmailCode(ctx, c.User, rc, p.emailCode.Code, p.emailCode.ExpiresAt); err != nil {
			return err
		}
	}

	return nil
}

// removeUnsettled deletes c, stored by a finish that then failed to settle it,
// under a context the caller cannot cancel, bounded by unsettledDeleteTimeout.
// The context keeps the caller's values, so a consumer's transaction is still
// joined. A removal that fails is logged by a fixed reason, not returned: the
// finish already fails with the error that caused it, and the pending passkey
// left behind is one the user's next registration replaces.
func (m *Passkeys) removeUnsettled(ctx context.Context, c *Credential) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unsettledDeleteTimeout)
	defer cancel()

	if _, err := m.credentials.Delete(dctx, c.User, c.ID); err != nil {
		attrs := append([]slog.Attr{credentialAttr(c.ID)}, diag.Failure("delete", err)...)
		m.sampled(ctx, slog.LevelError, "delete|unsettled", msgUnsettledNotRemoved, attrs...)
	}
}

// deleteAbandoned deletes every pending passkey of user awaiting any of
// reasons that was created before issued, the instant the finishing
// registration's challenge was issued: only such a passkey belongs to a
// registration the user abandoned for this one. A pending passkey created at
// or after that instant was stored by a ceremony running concurrently with
// this one, possibly one whose finish has already returned its codes, and is
// kept; when the limit then has no room, this finish is the one refused. With
// no reasons it does nothing.
//
// It lists, then deletes each by its own write: a passkey a concurrent finish
// deleted first is passed over, and the list never sees one stored after it.
func (m *Passkeys) deleteAbandoned(
	ctx context.Context, user identity.UserID, reasons PendingReason, issued time.Time,
) error {
	if reasons == 0 {
		return nil
	}

	held, err := m.credentials.List(ctx, user)
	if err != nil {
		return diag.Wrap(err, "passkey: could not list the user's passkeys")
	}

	for _, c := range held {
		if c == nil || c.State != StatePending || c.Pending&reasons == 0 || !c.CreatedAt.Before(issued) {
			continue
		}

		if _, err := m.credentials.Delete(ctx, user, c.ID); err != nil {
			return diag.Wrap(err, "passkey: could not remove an abandoned registration")
		}
	}

	return nil
}

// hasWayBack reports whether user has a way back in other than the passkey
// being registered. A user who already holds a passkey awaiting saved codes
// has none by their saved codes: the set they hold is the one generated for
// that registration, which they never confirmed they kept. Such a user is
// therefore asked again, with a new set, without consulting the way-back
// check, which would count those unconfirmed codes. Otherwise the way-back
// check decides, and its failure refuses.
func (m *Passkeys) hasWayBack(ctx context.Context, user identity.UserID) (bool, error) {
	abandoned, err := m.awaiting(ctx, user, PendingSavedCodes)
	if err != nil {
		return false, err
	}

	if abandoned != nil {
		return false, nil
	}

	back, err := m.recovery.WayBack.HasWayBack(ctx, user)
	if err != nil {
		return false, diag.Wrap(err, "passkey: could not check the user's way back in")
	}

	return back, nil
}

// drawEmailCode draws a uniform 6-digit code from the manager's random source.
func (m *Passkeys) drawEmailCode() (string, error) {
	n, err := rand.Int(m.random, big.NewInt(emailCodeSpace))
	if err != nil {
		return "", diag.Wrap(err, "passkey: could not draw an emailed code")
	}

	return fmt.Sprintf("%0*d", emailCodeDigits, n.Int64()), nil
}

// sendEmailCode queues code, honoured until until, to user's contact address,
// resolved by rc's resolver or the manager's. The recipient is set here, never
// by the message's text.
func (m *Passkeys) sendEmailCode(
	ctx context.Context, user identity.UserID, rc RegistrationContext, code string, until time.Time,
) error {
	to, err := m.contactOf(ctx, user, rc.ContactResolver)
	if err != nil {
		return err
	}

	subject, body := m.messages.EmailCode(code, until)

	if err := m.sender.Send(ctx, notify.Message{To: to, Subject: subject, TextBody: body}); err != nil {
		return diag.Wrap(err, "passkey: could not queue the emailed code")
	}

	return nil
}

// ConfirmSavedCode confirms that s's user kept the saved recovery codes their
// pending passkey awaits, and clears that reason. It returns the passkey when
// the confirmation made it active, so the caller can finish the activation,
// or nil when another reason still holds it pending. rc is the registration's
// context: its contact resolver, when set, addresses the binding notice an
// activation sends.
//
// The code is checked with the saved-code check, which spends nothing and is
// throttled per user: a throttled presentation is returned unchanged, wrapping
// ratelimit.ErrThrottled. A wrong code, no passkey of the user awaiting saved
// codes, or a reason already cleared is mfa.ErrInvalidCode, and the passkey
// stays pending.
func (m *Passkeys) ConfirmSavedCode(
	ctx context.Context, s *session.Session, code string, rc RegistrationContext,
) (*Credential, error) {
	if s == nil || s.UserID == "" || m.recovery == nil {
		return nil, mfa.ErrInvalidCode
	}

	c, err := m.awaiting(ctx, s.UserID, PendingSavedCodes)
	if err != nil {
		return nil, err
	}

	if c == nil {
		return nil, mfa.ErrInvalidCode
	}

	if err := m.recovery.Codes.Confirm(ctx, s.UserID, code); err != nil {
		switch {
		case errors.Is(err, recovery.ErrCodeThrottled):
			return nil, err
		case errors.Is(err, recovery.ErrRefused):
			return nil, mfa.ErrInvalidCode
		default:
			return nil, diag.Wrap(err, "passkey: could not check the saved code")
		}
	}

	return m.clearReason(ctx, c, PendingSavedCodes, rc)
}

// ConfirmEmailCode redeems the code emailed for s's user's pending passkey,
// in the order that bounds guessing:
//
//  1. ask the confirmation limiter — rc's, or the manager's own — under
//     EmailConfirmThrottleKey; a user over it, or a limiter that cannot say,
//     is refused with mfa.ErrEnrolmentThrottled before anything is charged;
//  2. charge one attempt on the code, in the store's conditional write, which
//     succeeds only while the passkey awaits it, the code is unexpired and
//     fewer than MaxEmailCodeAttempts were charged;
//  3. compare the presented code in constant time;
//  4. clear the reason last, in one conditional write.
//
// Every presented code is charged before it is compared, so however many
// requests race, no more than MaxEmailCodeAttempts are compared against one
// code. A refusal is mfa.ErrEmailCodeInvalid, matching mfa.ErrInvalidCode,
// and is counted on the limiter under a context the caller cannot cancel.
//
// It returns the passkey when the confirmation made it active, or nil when
// another reason still holds it pending.
func (m *Passkeys) ConfirmEmailCode(
	ctx context.Context, s *session.Session, code string, rc RegistrationContext,
) (*Credential, error) {
	if s == nil || s.UserID == "" {
		return nil, mfa.ErrEmailCodeInvalid
	}

	limiter := rc.ConfirmLimiter
	if nilcheck.IsNil(limiter) {
		limiter = m.confirmLimiter
	}

	key := EmailConfirmThrottleKey(s.UserID)

	exceeded, err := limiter.Exceeded(ctx, key)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: the confirmation limiter could not decide", mfa.ErrEnrolmentThrottled)
	}

	if exceeded {
		return nil, mfa.ErrEnrolmentThrottled
	}

	c, err := m.awaiting(ctx, s.UserID, PendingEmailCode)
	if err != nil {
		return nil, err
	}

	if c == nil {
		return nil, m.refuseEmailCode(ctx, limiter, key)
	}

	stored, charged, err := m.credentials.ChargeEmailAttempt(ctx, s.UserID, c.ID, m.clock.Now())
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not charge an attempt against the emailed code")
	}

	if !charged || stored == nil || !isEmailCode(code) || !m.compare(stored.Code, code) {
		return nil, m.refuseEmailCode(ctx, limiter, key)
	}

	return m.clearReason(ctx, c, PendingEmailCode, rc)
}

// refuseEmailCode counts a refused emailed code on limiter, under a context
// the caller cannot cancel, and returns the refusal. A limiter that cannot
// record is logged by a fixed reason and does not change the outcome.
func (m *Passkeys) refuseEmailCode(ctx context.Context, limiter ratelimit.Limiter, key string) error {
	if err := limiter.RecordFailure(context.WithoutCancel(ctx), key); err != nil {
		m.logger.LogAttrs(ctx, slog.LevelError, msgLimiterNotRecorded, diag.Failure("limiter", err)...)
	}

	return mfa.ErrEmailCodeInvalid
}

// isEmailCode reports whether code is exactly six ASCII digits. A presented
// code is never trimmed or normalised into a match.
func isEmailCode(code string) bool {
	if len(code) != emailCodeDigits {
		return false
	}

	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}

	return true
}

// awaiting returns user's pending passkey whose reason r is set, or nil.
func (m *Passkeys) awaiting(ctx context.Context, user identity.UserID, r PendingReason) (*Credential, error) {
	held, err := m.credentials.List(ctx, user)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not list the user's passkeys")
	}

	for _, c := range held {
		if c != nil && c.State == StatePending && c.Pending&r != 0 {
			return c, nil
		}
	}

	return nil, nil
}

// clearReason clears r on c by the store's conditional write. A write the
// store refuses is mfa.ErrInvalidCode. When no reason remains, the passkey is
// active: it runs the activation and returns c; otherwise it returns nil.
func (m *Passkeys) clearReason(
	ctx context.Context, c *Credential, r PendingReason, rc RegistrationContext,
) (*Credential, error) {
	state, cleared, err := m.credentials.ClearReason(ctx, c.User, c.ID, r)
	if err != nil {
		return nil, diag.Wrap(err, "passkey: could not clear the pending reason")
	}

	if !cleared {
		return nil, mfa.ErrInvalidCode
	}

	c.State, c.Pending = state, c.Pending&^r
	if r == PendingEmailCode {
		c.EmailCode = nil
	}

	if state != StateActive {
		return nil, nil
	}

	m.activated(ctx, c, rc)

	return c, nil
}

// activated is the one place a passkey becoming active is handled, whether at
// finish or at the confirmation that clears its last reason: it queues the
// binding notice, addressed by rc's contact resolver when it has one. Moving a
// confined session on is the caller's: the manager does not hold the session
// store.
func (m *Passkeys) activated(ctx context.Context, c *Credential, rc RegistrationContext) {
	m.notify(ctx, noticeRegistered, c, rc.ContactResolver, false)
}
