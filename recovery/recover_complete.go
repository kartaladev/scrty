package recovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
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
	msgGrantsFailed         = "recovery: the user's application grants could not be revoked"
	msgReissueFailed        = "recovery: the saved codes could not be replaced"
	msgRemainingFailed      = "recovery: the remaining saved codes could not be counted"
	msgSessionFailed        = "recovery: the recovery session could not be created"
	msgIssueFailed          = "recovery: the recovery session's credential could not be issued"
	msgNoticeContactFailed  = "recovery: the notice's contact address could not be resolved"
	msgNoticeSendFailed     = "recovery: the recovery notice could not be sent"
	msgNoticeUserLookupFail = "recovery: the user could not be loaded for the notice"
)

// The fixed texts of errors the completion returns for a failed dependency.
const (
	errTextRecordStore = "recovery: the recovery record store failed"
	errTextRecordID    = "recovery: a recovery record identifier could not be minted"
	errTextIssue       = "recovery: the recovery session's credential could not be issued"
	errTextGrants      = "recovery: the user's application grants could not be revoked"
)

// IssueFunc issues the credential the holder of a recovery session carries
// away, such as a signed token naming s through its identifier, for user, the
// recovered account as the recovery loaded it. It is supplied with
// WithCredentialIssuer.
//
// It is called once the session is built and marked recovery-pending, and
// before the grants are revoked and anything is spent or stored: s loads
// nothing yet, and is stored only once the recovery's other effects have run.
// It must not modify s or user. A credential it returns for a recovery that
// then fails, such as one whose first grant revocation fails or that loses a
// racing recovery its saved code, names a session that is never stored, so it
// authenticates nothing and is discarded.
//
// An error is a dependency failure, never a refusal: the recovery revokes,
// spends, removes, ends, replaces, records and sends nothing, counts nothing
// against the user, and returns the error behind fixed text of this package, still
// matching it through errors.Is and errors.As.
type IssueFunc func(ctx context.Context, s *session.Session, user *identity.Details) (string, error)

// WithCredentialIssuer sets the step that issues the recovery session's
// credential, which Recover and Finish call before they spend anything and
// return in Result.Credential (see IssueFunc). The default issues none: the
// result's Credential is empty, and a caller that issues one itself once the
// recovery has returned does so after the proofs were spent and the saved codes
// replaced, so a credential it then cannot issue costs the user both. A nil
// issuer is a configuration error.
//
// The session is built, and its confined lifetime counted, before the issuer
// is called and the proofs are spent, which is what lets issuing come first.
// A recovery whose steps together take longer than that lifetime therefore
// stores a session that has already expired, and its credential authenticates
// nothing. The recovery still stands, and when it replaced the saved set the
// result still carries the new saved codes, so the user keeps them and can
// recover again. The lifetime is 15 minutes unless WithPendingSessionLifetime
// sets another, far beyond the steps' latency.
//
// httpsec's account recovery supplies its own, issuing the credential its
// chain's bearer accepts, and it replaces one given here.
func WithCredentialIssuer(issue IssueFunc) Option {
	return func(c *config) { c.issue, c.issueSet = issue, true }
}

// Result is what a recovery produced: a confined session and the saved-code
// state when it completed, or a hold when it did not.
type Result struct {
	// Session is the recovery-pending session the recovery produced, already
	// stored, in the one write that created it. It becomes a full session only
	// by binding a new authenticator. Nil when the recovery is held. It is
	// stored whether or not a credential was issued for it: without
	// WithCredentialIssuer, Credential is empty and the caller issues one.
	Session *session.Session

	// Credential is the credential the issuer (WithCredentialIssuer) issued
	// for Session, before anything was spent. Empty when the recovery is
	// held, or when no issuer is configured (the default; see
	// WithCredentialIssuer for what issuing it yourself afterwards costs).
	Credential string

	// Codes is the user's new set of saved codes, when a saved code was one of
	// the proofs. This is the only time they exist in readable form.
	Codes []string

	// Remaining is how many saved codes the user holds once the recovery
	// completed, with Low judged by the saved-code manager's low threshold.
	// When a saved code was spent it counts the new set in Codes; otherwise
	// it counts what is left of the old one. It is the zero RemainingCodes when saved
	// codes are not in use.
	Remaining RemainingCodes

	// Details is the recovered user's account, as the recovery loaded it and
	// handed it to the credential issuer. A caller that must name the user
	// reads it here rather than loading the user again: a second lookup could
	// fail after the saved codes were replaced, and the new codes would be
	// lost with the response. Nil when the recovery is held.
	Details *identity.Details

	// GrantsNotRevoked is set when the recovery completed but its second
	// revocation of the user's application grants failed (WithGrantRevoker), so
	// a grant minted before the sessions ended may stand. The failure was logged
	// and reported as event.GrantRevokeFailed. The consumer can tell the user,
	// and call the revoker's RevokeUserGrants again, which is idempotent. It is
	// false when no revoker is in use, when the grants were kept on purpose
	// (WithoutRecoveryGrantRevocation), and when the recovery is held.
	GrantsNotRevoked bool

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
	// issued is the recovery session, built and given its credential before
	// anything was spent, and stored last.
	issued *issuedSession
}

// issuedSession is a recovery session that is built, marked recovery-pending
// and given its credential, and not yet stored.
type issuedSession struct {
	prepared   *session.Prepared
	credential string
}

// Recover runs a recovery: it checks both proofs without spending either,
// spends them, and then completes the recovery or, with a hold configured,
// holds it (see Finish).
//
// A recovery that completes at once first builds its recovery-pending
// session, confined to the session lifetime, and issues its credential
// through the issuer (WithCredentialIssuer), after every check and before
// anything is spent. An issuing failure is a dependency failure, not a
// refusal: nothing is revoked, spent, removed, ended, replaced, recorded or
// sent, and nothing is counted against the user, so the same proofs recover
// once the issuer is healthy.
//
// With an MFA proof it then verifies the code, which spends it, so a wrong code
// ends nothing: the refusal spends nothing else and revokes nothing.
//
// It then revokes the user's application grants, when a revoker is present
// (WithGrantRevoker) and unless WithoutRecoveryGrantRevocation. A failure is a
// dependency failure as well (ErrDependency), with nothing counted against the
// user: the same proofs recover once the revoker is healthy, except that an MFA
// code was spent by its verification, so a retry needs the next one. Its issued
// and saved codes are not spent. A held recovery spends every proof when it
// starts, and revokes nothing until its finish.
//
// Then, in this order: the remaining proofs are spent, the issued code before
// the saved code; a completed record is written;
// the planned authenticators are removed; every session of the user is
// deleted, unless WithoutSessionRevocation; the grants are revoked again, as a
// live session could have minted one in between; when a saved code was spent,
// the saved set is replaced and the new codes returned; the recovery session is
// stored, already recovery-pending, in the one write that creates it; and the
// user is notified at their contact address. The result carries the
// credential, counts the saved codes the user then holds (the new set after a
// reissue) and carries the user's details as the recovery loaded them.
//
// A failure at any step from the record to the session's write is returned,
// with the proofs spent and the earlier steps done, and the credential
// discarded: it names a session that was never stored, so it authenticates
// nothing. In particular a failed reset revokes nothing further, and a session
// write that fails after the saved set was replaced loses the new codes with
// the error. The one exception is the second grant revocation: its failure is
// logged and reported as event.GrantRevokeFailed, Result.GrantsNotRevoked is
// set, and the recovery carries on. A notice the sender refuses is logged, and
// the recovery stands.
//
// Everything from the first spend on runs detached from ctx's cancellation,
// so a client that hangs up cannot leave a recovery half done. The issuer runs
// before that, on ctx itself, so a client that hangs up while it issues spends
// nothing. So does the first revocation when there is no MFA proof; with one it
// follows the verification, so it runs detached too.
//
// A refusal (ErrRefused) is reported as event.RecoveryRefused
// (WithSecurityEvents); a dependency failure, and a request whose own context
// ended before the verdict, are not, even when the failure is answered as
// ErrRefused (an issued-code store, the user limiter or the risk hook that
// failed): the error is still ErrRefused, with the failure beneath it.
func (r *Recoverer) Recover(ctx context.Context, req Request) (*Result, error) {
	res, err := r.recover(ctx, req)
	r.reportRefused(ctx, err)

	return res, err
}

// recover is Recover's work.
func (r *Recoverer) recover(ctx context.Context, req Request) (*Result, error) {
	v, err := r.verify(ctx, req)
	if err != nil {
		return nil, err
	}

	now := r.clock.Now()
	hold := max(v.hold, r.delay)

	// A recovery completing at once has its credential before anything is
	// spent; a held one creates no session until its finish.
	var issued *issuedSession
	if hold <= 0 {
		if issued, err = r.issueSession(ctx, v.details, now, req.KeyBinding, req.SessionOptions); err != nil {
			return nil, err
		}
	}

	// A held recovery may yet be cancelled by the real user, so it revokes at its
	// finish. One completing at once revokes as it spends, so an outage costs the
	// user as little as it can and they can retry.
	spend := r.spend
	if hold <= 0 {
		spend = r.revokeThenSpend
	}

	if err := spend(ctx, v); err != nil {
		return nil, err
	}

	ctx = context.WithoutCancel(ctx)

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

	if hold > 0 {
		rec.NotBefore = now.Add(hold)

		return r.startHold(ctx, v, rec, hold)
	}

	rec.CompletedAt = now
	if err := r.records.Insert(ctx, rec); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgRecordFailed, diag.Failure("record-store", err)...)

		return nil, diag.Wrap(err, errTextRecordStore)
	}

	return r.complete(ctx, completion{
		user: v.user, details: v.details, plan: v.plan, savedSpent: rec.SavedSpent, issued: issued,
	}, now)
}

// issueSession builds the recovery-pending session for the recovered user,
// recovered at now, with the caller's own attributes callerOpts and bound to
// binding unless it is the zero value, and issues its credential through the
// issuer. Nothing is stored: the session loads nothing until complete commits
// it. ctx is the caller's own, so an issuer bound to it fails when the client
// has left, and that failure spends nothing either.
//
// The recovery's own attributes are applied after callerOpts, so none of them
// can replace those: the first factor, the binding, the recovered user, no
// second factor met and no confinement marker (recoveryOwn), before the
// session is marked recovery-pending.
//
// An issuing failure is logged and returned behind fixed text, a dependency
// failure: at ERROR, or at DEBUG when ctx's own end cut it short.
func (r *Recoverer) issueSession(
	ctx context.Context, details *identity.Details, now time.Time,
	binding session.KeyBinding, callerOpts []session.CreateOption,
) (*issuedSession, error) {
	opts := make([]session.CreateOption, 0, len(callerOpts)+3)
	opts = append(opts, callerOpts...)
	if !binding.IsZero() {
		opts = append(opts, session.WithKeyBinding(binding))
	}
	opts = append(opts, session.WithFirstFactor(factor.Recovery), recoveryOwn(details.ID))

	p, err := r.sessions.Prepare(details.ID, opts...)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgSessionFailed, diag.Failure("session-build", err)...)

		return nil, err
	}

	// Marked before the credential exists, so the one write that stores the
	// session carries the state, and no credential ever names a full session.
	r.sessions.MarkRecoveryPending(p.Session(), r.sessionLifetime, now)

	if r.issue == nil {
		return &issuedSession{prepared: p}, nil
	}

	credential, err := r.issue(ctx, p.Session(), details)
	if err != nil {
		level := slog.LevelError
		if hangup.ByCaller(ctx, err) {
			level = slog.LevelDebug
		}

		r.logger.LogAttrs(ctx, level, msgIssueFailed, diag.Failure("credential-issuer", err)...)

		return nil, diag.Wrap(err, errTextIssue)
	}

	return &issuedSession{prepared: p, credential: credential}, nil
}

// recoveryOwn is the create option the recovery applies last, for user, the
// recovered one. A create option is a plain func a consumer may write by hand,
// so it also sets what none of the session's own options may decide:
//
//   - the user, which is the recovered user whatever a caller's option set;
//   - no second factor met, clearing one a caller's option recorded
//     (session.WithSecondFactorAtLogin): a recovery session becomes a full
//     session only by binding a new authenticator;
//   - no confinement marker, so MarkRecoveryPending records the deadline the
//     session holds now, and one a caller preset cannot be restored past the
//     manager's maximum lifetime when the session leaves its pending state.
func recoveryOwn(user identity.UserID) session.CreateOption {
	return func(s *session.Session) {
		s.UserID = user
		s.MFASatisfiedAt, s.MFAAtFirstFactor = time.Time{}, false
		s.EnrolmentOriginDeadline = time.Time{}
	}
}

// complete runs the completion sequence from the reset on: reset, revoke the
// sessions and the grants, reissue or count, the one write that stores the
// recovery session c.issued already holds a credential for, and the notice. ctx
// is already detached from the caller's cancellation.
//
// The revocation here is the second, and a failure does not stop the sequence:
// the proofs are spent, so returning would leave the user locked out with no way
// to retry, which is worse than one grant the consumer is told about.
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

	if r.grants != nil {
		if err := r.grants.RevokeUserGrants(ctx, c.user, grantRevocationCause); err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgGrantsFailed, diag.Failure("grant-revoker", err)...)
			r.events.Report(ctx, event.Event{
				Name: event.GrantRevokeFailed, At: r.clock.Now(), Outcome: event.OutcomeFailure, User: c.user,
			}, r.logger)

			res.GrantsNotRevoked = true
		}
	}

	switch {
	case c.savedSpent:
		codes, err := r.codes.Generate(ctx, c.user)
		if err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgReissueFailed, diag.Failure("codes", err)...)

			return nil, err
		}

		res.Codes = codes
		res.Remaining = RemainingCodes{N: len(codes), Low: len(codes) <= r.codes.lowThreshold}
	case r.codes != nil:
		n, err := r.codes.Remaining(ctx, c.user)
		if err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgRemainingFailed, diag.Failure("codes", err)...)

			return nil, err
		}

		res.Remaining = n
	}

	// Stored last, after the revocation, which would otherwise end it, and
	// after the saved set was replaced, so the credential that answers with
	// the new codes existed before the old ones were lost. A failure discards
	// the credential, which names a session that was never stored.
	s, err := c.issued.prepared.Commit(ctx)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgSessionFailed, diag.Failure("session-store", err)...)

		return nil, err
	}

	res.Session = s
	res.Credential = c.issued.credential

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

// WithPendingSessionLifetime replaces how long the recovery-pending session a
// completed recovery produces lives before it must become full by binding a
// new authenticator. The default is 15 minutes.
//
// Zero or less is a configuration error, and so is longer than the session
// manager's absolute timeout, which no session outlives. The default is held
// to the same bound.
func WithPendingSessionLifetime(d time.Duration) Option {
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

	if c.issueSet && c.issue == nil {
		return fmt.Errorf("%w: WithCredentialIssuer was given no issuer", ErrConfig)
	}

	r.issue = c.issue

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

// reportRefused reports err as event.RecoveryRefused when it is a refusal of
// the presented proofs (ErrRefused). A refusal that answers a dependency's
// failure (a store, the user limiter or the risk hook), and one the caller's
// own context cut short, report nothing. It names no user, as a failed login
// does not.
func (r *Recoverer) reportRefused(ctx context.Context, err error) {
	if !errors.Is(err, ErrRefused) || depfault.Silent(ctx, err) {
		return
	}

	r.events.Report(ctx, event.Event{
		Name: event.RecoveryRefused, At: r.clock.Now(), Outcome: event.OutcomeFailure,
	}, r.logger)
}
