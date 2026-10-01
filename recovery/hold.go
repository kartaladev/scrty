package recovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
)

// The one-time purposes of a held recovery's two tokens. Each token's subject
// is the recovery record's identifier.
const (
	// FinishTokenPurpose is the purpose of the completion token, which the
	// client presents to Finish once the hold is over.
	FinishTokenPurpose = "account-recovery-finish"
	// CancelTokenPurpose is the purpose of the token the cancel link carries,
	// which Cancel redeems.
	CancelTokenPurpose = "account-recovery-cancel"
)

// CancelLinkParam is the query parameter the cancel link carries the cancel
// token in. The consumer's page reads it and posts it back as the
// cancel_token form field.
const CancelLinkParam = "cancel_token"

// defaultCompletionWindow is how long after its hold a held recovery can still
// be finished.
const defaultCompletionWindow = 24 * time.Hour

// Hold is a recovery that is held rather than completed: the token that
// finishes it, and the instant from which it can be finished.
type Hold struct {
	CompletionToken string
	CompletableAt   time.Time
}

// WithDelay holds every recovery for d before it can complete. There is no
// default: a recovery completes at once. Zero or less is a configuration
// error. With WithRisk as well, the hold is the longer of the two.
//
// A hold needs WithCancelLink.
func WithDelay(d time.Duration) Option {
	return func(c *config) { c.delay, c.delaySet = d, true }
}

// WithCompletionWindow replaces how long after its hold a held recovery can
// still be finished. The default is 24 hours. Zero or less is a configuration
// error.
func WithCompletionWindow(d time.Duration) Option {
	return func(c *config) { c.window = d }
}

// WithCancelLink sets the page the held-recovery notice links to, which
// carries the cancel token in its CancelLinkParam query parameter and posts it
// back to cancel. There is no default: it is required with any hold, a delay
// or a risk hook.
//
// It must be absolute https, with one exception: http on a loopback host, for
// local development. It carries no userinfo and no fragment. A link over
// cleartext would carry a live credential past anyone on the path.
func WithCancelLink(baseURL string) Option {
	return func(c *config) { c.cancelLink = baseURL }
}

// WithHoldTokenStore replaces where the finish and cancel tokens of held
// recoveries are kept. The default is onetime.NewMemoryStore, which holds one
// process's tokens and forgets them on restart. A nil store is a
// configuration error.
//
// Nothing purges the default store: every hold adds two tokens, which stay in
// memory, spent or expired, for the life of the process. A consumer who holds
// recoveries in a long-running process supplies a store here and sweeps it,
// for example with onetime.Manager.PurgeExpired from a manager over this
// store for each of FinishTokenPurpose and CancelTokenPurpose, since the
// default store is not reachable from outside the Recoverer.
func WithHoldTokenStore(s onetime.Store) Option {
	return func(c *config) { c.holdStore, c.holdStoreSet = s, true }
}

// validateHolds checks the hold settings and builds the token managers.
func (r *Recoverer) validateHolds(c *config) error {
	if c.delaySet && c.delay <= 0 {
		return fmt.Errorf("%w: the recovery delay must be above zero, got %s", ErrConfig, c.delay)
	}
	if c.window <= 0 {
		return fmt.Errorf("%w: the completion window must be above zero, got %s", ErrConfig, c.window)
	}
	if c.holdStoreSet && nilcheck.IsNil(c.holdStore) {
		return fmt.Errorf("%w: WithHoldTokenStore was given no store", ErrConfig)
	}

	r.delay = c.delay
	r.window = c.window

	if c.cancelLink != "" {
		u, err := parseCancelLink(c.cancelLink)
		if err != nil {
			return err
		}

		r.cancelLink = u
	}

	if !r.Holds() {
		return nil
	}
	if r.cancelLink == nil {
		return fmt.Errorf("%w: a hold needs WithCancelLink, so the user can cancel a recovery they did not start", ErrConfig)
	}

	r.holdStore = c.holdStore
	if !c.holdStoreSet {
		r.holdStore = onetime.NewMemoryStore(onetime.WithMemoryStoreClock(c.clock))
	}

	var err error
	if r.finishTokens, err = r.holdTokens(FinishTokenPurpose, r.window); err != nil {
		return err
	}
	if r.cancelTokens, err = r.holdTokens(CancelTokenPurpose, r.window); err != nil {
		return err
	}

	return nil
}

// holdTokens builds a manager of purpose over the hold token store, issuing
// tokens that live for ttl.
func (r *Recoverer) holdTokens(purpose string, ttl time.Duration) (*onetime.Manager, error) {
	m, err := onetime.NewManager(purpose,
		onetime.WithStore(r.holdStore), onetime.WithTTL(ttl), onetime.WithClock(r.clock), onetime.WithLogger(r.logger))
	if err != nil {
		return nil, fmt.Errorf("%w: hold tokens: %w", ErrConfig, err)
	}

	return m, nil
}

// parseCancelLink accepts an absolute https URL, or http on a loopback host,
// with no userinfo and no fragment.
func parseCancelLink(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: the cancel link is not a URL", ErrConfig)
	}

	switch {
	case !u.IsAbs() || u.Host == "":
		return nil, fmt.Errorf("%w: the cancel link must be absolute", ErrConfig)
	case u.User != nil:
		return nil, fmt.Errorf("%w: the cancel link must carry no userinfo", ErrConfig)
	case u.Fragment != "" || strings.HasSuffix(raw, "#"):
		return nil, fmt.Errorf("%w: the cancel link must carry no fragment", ErrConfig)
	case u.Scheme == "https":
	case u.Scheme == "http" && loopbackHost(u.Hostname()):
	default:
		return nil, fmt.Errorf("%w: the cancel link must be https, or http on a loopback host", ErrConfig)
	}

	return u, nil
}

// loopbackHost reports whether host is localhost or a loopback address.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// Holds reports whether recoveries may be held: a delay or a risk hook is
// configured. The HTTP layer reads it to decide whether a login must cancel
// the user's pending recoveries.
func (r *Recoverer) Holds() bool { return r.delay > 0 || r.risk != nil }

// The messages the hold, finish and cancel write. None carries the username,
// the address, a code or a token.
const (
	msgHoldTokenFailed     = "recovery: a hold token could not be issued"
	msgFinishRefused       = "recovery: finish refused"
	msgFinishUserInactive  = "recovery: finish refused: no active account for the recovery's user"
	msgFinishLookupFailed  = "recovery: finish failed: the recovery's user could not be loaded"
	msgFinishPlanFailed    = "recovery: finish failed: the reset could not be planned"
	msgHoldTokenConsume    = "recovery: a hold token could not be consumed after its record was decided"
	msgCancelIgnored       = "recovery: cancel ignored"
	msgCancelFailed        = "recovery: cancel failed: the record store failed"
	msgHoldCodesFailed     = "recovery: hold: the voided saved codes could not be deleted"
	msgCancelPendingFailed = "recovery: pending recoveries could not be cancelled"
)

// The fixed texts of errors the hold and finish return for a failed dependency.
const errTextHoldToken = "recovery: a hold token could not be issued"

// startHold holds a verified, spent recovery: it writes the pending record,
// issues the finish and cancel tokens, both living for the hold plus the
// completion window, voids the user's saved set when a saved code was spent,
// and notifies the user with the cancel link. Nothing else changes: the
// authenticators and the sessions stay as they are until Finish. A failure
// before the notice is returned, with the earlier steps done. ctx is already
// detached from the caller's cancellation.
//
// The saved set is voided here rather than at the finish or the cancel
// because both end it anyway, and whoever holds a stolen sheet must not use
// its other codes while the hold runs.
func (r *Recoverer) startHold(ctx context.Context, v *verified, rec Record, hold time.Duration) (*Result, error) {
	if err := r.records.Insert(ctx, rec); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgRecordFailed, diag.Failure("record-store", err)...)

		return nil, diag.Wrap(err, errTextRecordStore)
	}

	ttl := hold + r.window

	finishToken, err := r.issueHoldToken(ctx, FinishTokenPurpose, rec.ID, ttl)
	if err != nil {
		return nil, err
	}

	cancelToken, err := r.issueHoldToken(ctx, CancelTokenPurpose, rec.ID, ttl)
	if err != nil {
		return nil, err
	}

	if rec.SavedSpent {
		if _, err := r.codes.store.DeleteUser(ctx, rec.User); err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgHoldCodesFailed, diag.Failure("code-store", err)...)

			return nil, diag.Wrap(err, errTextCodeStore)
		}
	}

	subject, body := r.messages.Held(Notice{
		At:          rec.StartedAt,
		Removed:     slices.Clone(v.plan),
		CodesVoided: rec.SavedSpent,
		Repudiation: r.repudiation,
	}, r.cancelURL(cancelToken), rec.NotBefore)
	r.notify(ctx, v.details, subject, body)

	return &Result{Held: &Hold{CompletionToken: finishToken, CompletableAt: rec.NotBefore}}, nil
}

// issueHoldToken issues a token of purpose for the record rid, living for
// ttl. The lifetime differs from hold to hold, so each issuance has a manager
// of its own over the shared store.
func (r *Recoverer) issueHoldToken(ctx context.Context, purpose string, rid id.ID, ttl time.Duration) (string, error) {
	m, err := r.holdTokens(purpose, ttl)
	if err == nil {
		var tok string
		if tok, _, err = m.Issue(ctx, rid.String()); err == nil {
			return tok, nil
		}
	}

	r.logger.LogAttrs(ctx, slog.LevelError, msgHoldTokenFailed, diag.Failure("token-issue", err)...)

	return "", diag.Wrap(err, errTextHoldToken)
}

// cancelURL returns the cancel link carrying token in its query.
func (r *Recoverer) cancelURL(token string) string {
	u := *r.cancelLink
	q := u.Query()
	q.Set(CancelLinkParam, token)
	u.RawQuery = q.Encode()

	return u.String()
}

// Finish completes a held recovery, given the completion token its hold
// returned.
//
// In order: the token is checked, not spent; its record is found, and a record
// that is unknown, cancelled or already completed is ErrRefused; before the
// record's NotBefore it is ErrNotYetCompletable, spending nothing, so the same
// token works once the hold is over; the user must still have an active
// account, or it is ErrRefused; the reset is planned again, from the proofs
// and reported losses the record kept, over what the user holds now, and in
// the reported mode a reported loss the user no longer holds is dropped rather
// than refused, since its loss is already remedied; a listing failure is
// returned with the record still pending; the
// record is completed by one conditional write, and losing it, to a racing
// cancel or finish, is ErrRefused; the token is consumed; and the completion
// sequence runs from the reset on, exactly as Recover's does.
//
// A token past the completion window, or of another purpose, is ErrRefused.
// Everything from the conditional write on runs detached from ctx's
// cancellation.
func (r *Recoverer) Finish(ctx context.Context, completionToken string) (*Result, error) {
	if r.finishTokens == nil {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgFinishRefused, slog.String("reason", "no-hold-configured"))

		return nil, ErrRefused
	}

	checked, rec, err := r.findHeld(ctx, r.finishTokens, completionToken, msgFinishRefused)
	if err != nil {
		return nil, err
	}

	now := r.clock.Now()
	if now.Before(rec.NotBefore) {
		return nil, ErrNotYetCompletable
	}

	details, err := r.users.LoadByUserID(ctx, rec.User)

	switch {
	case errors.Is(err, identity.ErrUserNotFound), err == nil && (details == nil || !details.Active):
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgFinishUserInactive)

		return nil, ErrRefused
	case err != nil:
		r.logger.LogAttrs(ctx, slog.LevelError, msgFinishLookupFailed, diag.Failure("user-loader", err)...)

		return nil, diag.Wrap(err, errTextUserLookup)
	}

	plan, err := r.planner.replan(ctx, rec.User, rec.Reported, rec.Proven)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgFinishPlanFailed, diag.Failure("reset-plan", err)...)

		return nil, err
	}

	ctx = context.WithoutCancel(ctx)

	completed, err := r.records.Complete(ctx, rec.ID, now)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgRecordFailed, diag.Failure("record-store", err)...)

		return nil, diag.Wrap(err, errTextRecordStore)
	}
	if !completed {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgFinishRefused, slog.String("reason", "record-not-pending"))

		return nil, ErrRefused
	}

	r.consumeHoldToken(ctx, r.finishTokens, checked)

	return r.complete(ctx, completion{user: rec.User, details: details, plan: plan, savedSpent: rec.SavedSpent}, now)
}

// findHeld checks a hold token with m, spending nothing, and finds the pending
// record it names. A token that is not good, a record that is unknown and one
// that is no longer pending are all ErrRefused; a record store outage is
// returned behind fixed text. refused is the message a refusal is logged
// under.
func (r *Recoverer) findHeld(ctx context.Context, m *onetime.Manager, token, refused string) (onetime.Checked, *Record, error) {
	checked, err := m.Check(ctx, token, "")
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelDebug, refused, slog.String("reason", "token"), slog.String("purpose", m.Purpose()))

		return onetime.Checked{}, nil, ErrRefused
	}

	rid, err := id.Parse(checked.Token().Subject)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, refused, slog.String("reason", "token-subject"))

		return onetime.Checked{}, nil, ErrRefused
	}

	rec, err := r.records.Find(ctx, rid)

	switch {
	case errors.Is(err, ErrRecordNotFound):
		r.logger.LogAttrs(ctx, slog.LevelDebug, refused, slog.String("reason", "record-not-found"))

		return onetime.Checked{}, nil, ErrRefused
	case err != nil:
		r.logger.LogAttrs(ctx, slog.LevelError, msgRecordFailed, diag.Failure("record-store", err)...)

		return onetime.Checked{}, nil, diag.Wrap(err, errTextRecordStore)
	case !pending(rec):
		r.logger.LogAttrs(ctx, slog.LevelDebug, refused, slog.String("reason", "record-not-pending"))

		return onetime.Checked{}, nil, ErrRefused
	}

	return checked, rec, nil
}

// consumeHoldToken spends a hold token once its record has been decided. The
// record's conditional write is what decided the race, and it already refuses
// the token's every later use, so a consume that fails is logged and ignored.
func (r *Recoverer) consumeHoldToken(ctx context.Context, m *onetime.Manager, checked onetime.Checked) {
	if err := m.Consume(ctx, checked); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgHoldTokenConsume, diag.Failure("token-consume", err)...)
	}
}

// Cancel cancels a held recovery, given the cancel token its notice's link
// carried.
//
// It returns nothing, by design: the cancel endpoint answers every request the
// same way, so it reveals nothing about which tokens or recoveries exist. A
// token that is not good or of another purpose, a finish token included, a
// recovery already completed or cancelled, and a store outage all do nothing
// but log.
//
// In order: the token is checked; its record is found; the record is
// cancelled by one conditional write, so of a racing cancel and finish at
// most one succeeds; the token is consumed; and the user is sent the Cancelled
// notice, whenever this call is the one that cancelled the record, unless the
// user cannot be loaded or has no contact address. Nothing else changes: a
// saved set the recovery spent a code of was already voided when the hold
// started. Everything from the conditional write on runs detached from ctx's
// cancellation.
func (r *Recoverer) Cancel(ctx context.Context, cancelToken string) {
	if r.cancelTokens == nil {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgCancelIgnored, slog.String("reason", "no-hold-configured"))

		return
	}

	checked, rec, err := r.findHeld(ctx, r.cancelTokens, cancelToken, msgCancelIgnored)
	if err != nil {
		return
	}

	ctx = context.WithoutCancel(ctx)
	now := r.clock.Now()

	n, err := r.records.Cancel(ctx, rec.ID, now)
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgCancelFailed, diag.Failure("record-store", err)...)

		return
	}
	if n == 0 {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgCancelIgnored, slog.String("reason", "record-not-pending"))

		return
	}

	r.consumeHoldToken(ctx, r.cancelTokens, checked)

	details, err := r.users.LoadByUserID(ctx, rec.User)

	switch {
	case err != nil:
		r.logger.LogAttrs(ctx, slog.LevelError, msgNoticeUserLookupFail, diag.Failure("user-loader", err)...)

		return
	case details == nil:
		r.logger.LogAttrs(ctx, slog.LevelError, msgNoticeUserLookupFail, slog.String("reason", "user-loader-no-details"))

		return
	}

	subject, body := r.messages.Cancelled(Notice{At: now, CodesVoided: rec.SavedSpent, Repudiation: r.repudiation})
	r.notify(ctx, details, subject, body)
}

// CancelPending cancels every pending recovery of user. The login path calls
// it, when Holds reports true, after a first factor is authenticated and
// before the session is created: a user who can still log in did not lose
// their account, so a recovery held for it is cancelled. An error is the
// record store's, behind fixed text; the caller refuses the login on it,
// which fails closed.
func (r *Recoverer) CancelPending(ctx context.Context, user identity.UserID) error {
	if _, err := r.records.CancelPending(ctx, user, r.clock.Now()); err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgCancelPendingFailed, diag.Failure("record-store", err)...)

		return diag.Wrap(err, errTextRecordStore)
	}

	return nil
}
