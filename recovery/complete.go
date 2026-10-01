package recovery

//go:generate mockgen -source=records.go -destination=records_mock_test.go -package=recovery_test -typed

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// defaultSessionLifetime is how long a recovery-pending session lives.
const defaultSessionLifetime = 15 * time.Minute

// The messages the completion writes. None carries the username, the address,
// a code or a token.
const (
	msgRecordFailed         = "recovery: the recovery record could not be written"
	msgIDFailed             = "recovery: a recovery record identifier could not be minted"
	msgResetFailed          = "recovery: the authenticator reset failed"
	msgRevokeFailed         = "recovery: the user's sessions could not be revoked"
	msgReissueFailed        = "recovery: the saved codes could not be replaced"
	msgRemainingFailed      = "recovery: the remaining saved codes could not be counted"
	msgSessionFailed        = "recovery: the recovery session could not be created"
	msgSessionCleanupFailed = "recovery: the unsaved recovery session could not be deleted"
	msgNoticeContactFailed  = "recovery: the notice's contact address could not be resolved"
	msgNoticeSendFailed     = "recovery: the recovery notice could not be sent"
	msgNoticeUserLookupFail = "recovery: the user could not be loaded for the notice"
)

// The fixed texts of errors the completion returns for a failed dependency.
const (
	errTextRecordStore = "recovery: the recovery record store failed"
	errTextRecordID    = "recovery: a recovery record identifier could not be minted"
)

// Result is what a recovery produced: a confined session and the saved-code
// state when it completed, or a hold when it did not.
type Result struct {
	// Session is the recovery-pending session the recovery produced, already
	// saved. It becomes a full session only by binding a new authenticator.
	// Nil when the recovery is held.
	Session *session.Session

	// Codes is the user's new set of saved codes, when a saved code was one of
	// the proofs. This is the only time they exist in readable form.
	Codes []string

	// Remaining is how many saved codes the user holds once the recovery
	// completed, with Low judged by the saved-code manager's low threshold.
	// When a saved code was spent it counts the new set in Codes; otherwise
	// it counts what is left of the old one. It is the zero Count when saved
	// codes are not in use.
	Remaining Count

	// Details is the recovered user's account, as the recovery loaded it. A
	// caller that must name the user, such as when minting the credential for
	// Session, reads it here rather than loading the user again: a second
	// lookup could fail after the saved codes were replaced, and the new
	// codes would be lost with the response. Nil when the recovery is held.
	Details *identity.Details

	// Held is set, and nothing else is, when the recovery is held: it carries
	// the completion token Finish takes and the instant it can be presented.
	Held *Hold
}

// completion is what the completion sequence acts on, from a recovery that
// completes at once or from a held one finished later.
type completion struct {
	user       identity.UserID
	details    *identity.Details
	plan       []AuthenticatorRef
	savedSpent bool
}

// Recover runs a recovery: it checks both proofs without spending either,
// spends them, and then completes the recovery or, with a hold configured,
// holds it (see Finish).
//
// A recovery completes in this order, after the spends: a completed record is
// written; the planned authenticators are removed; every session of the user
// is deleted, unless WithoutSessionRevocation; when a saved code was spent, the
// saved set is replaced and the new codes returned; a recovery-pending session
// is created, confined to the session lifetime, and saved; and the user is
// notified at their contact address. The result counts the saved codes the
// user then holds (the new set after a reissue) and carries the user's
// details as the recovery loaded them. A failure at any step before the notice is returned, with the proofs
// spent and the earlier steps done; in particular a failed reset creates no
// session and revokes nothing. A notice the sender refuses is logged, and the
// recovery stands.
//
// Everything from the first spend on runs detached from ctx's cancellation,
// so a client that hangs up cannot leave a recovery half done.
func (r *Recoverer) Recover(ctx context.Context, req Request) (*Result, error) {
	v, err := r.verify(ctx, req)
	if err != nil {
		return nil, err
	}

	if err := r.spend(ctx, v); err != nil {
		return nil, err
	}

	ctx = context.WithoutCancel(ctx)
	now := r.clock.Now()

	rid, err := r.ids.NewID()
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgIDFailed, diag.Failure("id-generator", err)...)

		return nil, diag.Wrap(err, errTextRecordID)
	}

	rec := Record{
		ID:         rid,
		User:       v.user,
		StartedAt:  now,
		NotBefore:  now,
		Proven:     slices.Clone(v.proven),
		Reported:   slices.Clone(v.reported),
		SavedSpent: v.has(ProofSaved),
	}

	if hold := max(v.hold, r.delay); hold > 0 {
		rec.NotBefore = now.Add(hold)

		return r.startHold(ctx, v, rec, hold)
	}

	rec.CompletedAt = now
	if err := r.records.Insert(ctx, rec); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgRecordFailed, diag.Failure("record-store", err)...)

		return nil, diag.Wrap(err, errTextRecordStore)
	}

	return r.complete(ctx, completion{user: v.user, details: v.details, plan: v.plan, savedSpent: rec.SavedSpent}, now)
}

// complete runs the completion sequence from the reset on: reset, revoke,
// reissue or count, the confined session, and the notice. ctx is already
// detached from the caller's cancellation.
func (r *Recoverer) complete(ctx context.Context, c completion, now time.Time) (*Result, error) {
	if err := r.planner.execute(ctx, c.user, c.plan); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgResetFailed, diag.Failure("authenticator-remove", err)...)

		return nil, err
	}

	if r.revokeSessions {
		if err := r.sessions.DeleteByUser(ctx, c.user); err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgRevokeFailed, diag.Failure("session-store", err)...)

			return nil, err
		}
	}

	res := &Result{Details: c.details}

	switch {
	case c.savedSpent:
		codes, err := r.codes.Generate(ctx, c.user)
		if err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgReissueFailed, diag.Failure("codes", err)...)

			return nil, err
		}

		res.Codes = codes
		res.Remaining = Count{N: len(codes), Low: len(codes) <= r.codes.lowThreshold}
	case r.codes != nil:
		n, err := r.codes.Remaining(ctx, c.user)
		if err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgRemainingFailed, diag.Failure("codes", err)...)

			return nil, err
		}

		res.Remaining = n
	}

	s, err := r.sessions.Create(ctx, c.user, session.WithFirstFactor(factor.Recovery))
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgSessionFailed, diag.Failure("session-store", err)...)

		return nil, err
	}

	r.sessions.MarkRecoveryPending(s, r.sessionLifetime, now)

	if err := r.sessions.Save(ctx, s); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgSessionFailed, diag.Failure("session-store", err)...)

		if derr := r.sessions.Delete(ctx, s.ID); derr != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgSessionCleanupFailed, diag.Failure("session-store", derr)...)
		}

		return nil, err
	}

	res.Session = s

	subject, body := r.messages.Recovered(Notice{
		At:            now,
		Removed:       slices.Clone(c.plan),
		CodesReplaced: c.savedSpent,
		Repudiation:   r.repudiation,
	})
	r.notify(ctx, c.details, subject, body)

	return res, nil
}

// notify sends a notice to the user's contact address. A notice that cannot be
// addressed or queued is logged and otherwise ignored: it never undoes what it
// reports. The recipient is always the resolver's, whatever the builder wrote.
func (r *Recoverer) notify(ctx context.Context, details *identity.Details, subject, body string) {
	address, err := r.resolver(ctx, details)

	switch {
	case err != nil:
		r.logger.LogAttrs(ctx, slog.LevelError, msgNoticeContactFailed, diag.Failure("contact-resolver", err)...)

		return
	case address == "":
		r.logger.LogAttrs(ctx, slog.LevelError, msgNoticeContactFailed, slog.String("reason", "contact-resolver"))

		return
	}

	if err := r.sender.Send(ctx, notify.Message{To: address, Subject: subject, TextBody: body}); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgNoticeSendFailed, diag.Failure("sender", err)...)
	}
}

// WithoutSessionRevocation keeps the user's other sessions when a recovery
// completes. The default ends every one of them.
//
// This weakens recovery. A user recovers because they lost control of their
// authenticators, and whoever holds them may hold a session too: a session
// kept is a way back in that the reset did not close.
func WithoutSessionRevocation() Option {
	return func(c *config) { c.keepSessions = true }
}

// WithSessionLifetime replaces how long the recovery-pending session a
// completed recovery produces lives before it must become full by binding a
// new authenticator. The default is 15 minutes.
//
// Zero or less is a configuration error, and so is longer than the session
// manager's absolute timeout, which no session outlives. The default is held
// to the same bound.
func WithSessionLifetime(d time.Duration) Option {
	return func(c *config) { c.sessionLifetime = d }
}

// WithIDGenerator replaces the source of recovery record identifiers. The
// default is id.NewV7Generator. A nil generator is a configuration error.
func WithIDGenerator(g id.Generator) Option {
	return func(c *config) { c.ids, c.idsSet = g, true }
}

// validateCompletion checks the session lifetime and the identifier source.
func (r *Recoverer) validateCompletion(c *config) error {
	if c.sessionLifetime <= 0 || c.sessionLifetime > r.sessions.AbsoluteTimeout() {
		return fmt.Errorf("%w: the recovery session lifetime must be above zero and at most the session "+
			"manager's absolute timeout (%s), got %s", ErrConfig, r.sessions.AbsoluteTimeout(), c.sessionLifetime)
	}

	switch {
	case c.idsSet && nilcheck.IsNil(c.ids):
		return fmt.Errorf("%w: WithIDGenerator was given no generator", ErrConfig)
	case c.idsSet:
		r.ids = c.ids
	default:
		r.ids = id.NewV7Generator()
	}

	return nil
}
