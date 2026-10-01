package recovery

//go:generate mockgen -destination=tokenstore_mock_test.go -package=recovery_test -typed -mock_names=Store=MockTokenStore github.com/kartaladev/scrty/onetime Store
//go:generate mockgen -destination=challenge_mock_test.go -package=recovery_test -typed github.com/kartaladev/scrty/mfa ChallengeMethod

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
)

// userThrottleFlow prefixes every per-user recovery bucket key.
const userThrottleFlow = "recovery"

// The messages the check and spend phases write. None carries the username, a
// code, a password or a token.
const (
	msgIssuedOtherUser     = "recovery: an issued code minted for another user was presented"
	msgRecoverUnknown      = "recovery: refused: no active account for the submitted username"
	msgRecoverLookupFailed = "recovery: the username could not be resolved"
	msgRecoverNoReference  = "recovery: the resolved account carries no user reference"
	msgUserThrottled       = "recovery: refused: the user is at the recovery limit"
	msgUserLimiterError    = "recovery: user limiter could not be consulted"
	msgUserRecordError     = "recovery: user failure could not be recorded"
	msgCodeThrottled       = "recovery: refused: saved-code presentations throttled"
	msgMFALookupFailed     = "recovery: mfa enrolment lookup failed"
	msgListingFailed       = "recovery: authenticator listing failed"
	msgRiskFailed          = "recovery: risk hook failed"
	msgSpendFailed         = "recovery: a proof could not be spent"
)

// The fixed texts of errors returned for a failed dependency.
const (
	errTextUserLookup = "recovery: user lookup failed"
	errTextRisk       = "recovery: risk assessment failed"
)

// Request is one recovery attempt, as the HTTP layer parsed it. A proof is
// present when its field is not empty; exactly two must be.
//
// No expensive work runs before the recovery codes pass, for any user. An
// unknown or disabled username is refused as soon as the lookup finds no
// active account, and a known user with a wrong recovery code is refused by
// the code check, before any password is verified; neither pays for a
// password hash. A small timing difference remains, as it does for Start: a
// known username goes through the per-user limiter and the saved-code and
// issued-code lookups, which an unknown one skips. The difference is stated
// rather than closed.
type Request struct {
	// Username names the account. Required.
	Username string
	// Saved is a saved recovery code.
	Saved string
	// Issued is an issued recovery code.
	Issued string
	// MFAMethod names the MFA method whose code MFACode is. Both or neither.
	MFAMethod string
	MFACode   string
	// Password is the user's password.
	Password []byte
	// Lost names the authenticators the user reports lost, each "kind:id".
	Lost []string
	// Source is the request's canonical client source, for the risk hook.
	Source string
}

// PasswordCheck checks a password proof for the username a recovery names. It
// is supplied with WithPasswordCheck.
//
// An error wrapping authenticate.ErrAuthenticationFailed is a wrong password
// and becomes ErrRefused. Any other error is returned by the recovery
// unchanged. Either way it is counted against the user, and marked as a
// refusal after a valid code (see RefusedAfterValidCode), so it is counted
// against the source too. The recovery cannot tell a check that met an outage
// from one that refused: an implementation should return a lockout or a
// refusal only for a genuine refusal, and let an outage be seen as one, by
// its own logging and monitoring, rather than disguise it as a wrong password.
type PasswordCheck func(ctx context.Context, username string, password []byte) error

// Check is a consumer's refusal check. It runs after every proof has been
// checked and before anything is spent, given the user and the proofs
// presented; an error refuses the recovery and is returned unchanged, leaving
// every code redeemable.
type Check func(ctx context.Context, user identity.UserID, proofs []ProofKind) error

// RiskInput is what the risk hook decides from.
type RiskInput struct {
	User   identity.UserID
	Source string
	Proofs []ProofKind
	Now    time.Time
}

// verified is a recovery whose every proof passed and whose every
// side-effect-free check allowed it. Nothing has been spent.
type verified struct {
	user      identity.UserID
	details   *identity.Details
	proofs    []ProofKind
	savedHash [32]byte
	issued    onetime.Checked
	mfa       mfa.Method
	mfaCode   []byte
	plan      []AuthenticatorRef
	proven    []AuthenticatorRef
	reported  []AuthenticatorRef
	hold      time.Duration
}

func (v *verified) has(k ProofKind) bool { return slices.Contains(v.proofs, k) }

// UserThrottleKey is the limiter key failed recoveries for user are counted
// under: "recovery|" followed by the user reference, unparsed.
//
// It is exported so a consumer who supplies their own limiter, shared with
// other flows, can read or clear this bucket and keep their own keys from
// colliding with it.
func UserThrottleKey(user identity.UserID) string {
	return userThrottleFlow + "|" + string(user)
}

// refusedAfterCode marks a refusal decided after every recovery code the
// request presented had passed its check. It is invisible otherwise: its text
// is the refusal's own, and errors.Is and errors.As see through it.
type refusedAfterCode struct{ err error }

func (e *refusedAfterCode) Error() string { return e.err.Error() } //nolint:forbidigo // an Error() method delegating to the refusal it marks, whose text is returned unchanged by design
func (e *refusedAfterCode) Unwrap() error { return e.err }

// RefusedAfterValidCode reports whether err refused a recovery after the
// recovery codes it presented had passed their check. It marks exactly these:
//   - any error from the password check, whether a wrong password, a lockout
//     or an outage the check reports (see PasswordCheck);
//   - an MFA method the user is not enrolled on;
//   - in the reported mode, a reported loss the user does not hold;
//   - a reset policy error;
//   - a risk hook error;
//   - a consumer check's error;
//   - a failed spend: a wrong MFA code, an issued code that could not be
//     consumed, or a saved code lost to a racing recovery.
//
// The HTTP layer counts such a refusal against the request's source unless the
// consumer turns that off, since a presenter holding a valid code is still
// trying the other proof. Everything else reports false: a refusal of the
// codes themselves, an unknown or throttled user, a malformed request
// (including the reported mode's empty report and a reported loss the request
// also proves), and a dependency outage the recovery can tell apart, such as a
// user lookup, MFA enrolment lookup, authenticator listing or saved-code store
// failure.
//
// The error it looks for wraps the refusal without changing it: its text is
// the refusal's own, and errors.Is and errors.As find the refusal, a consumer
// check's error included, exactly as they would unwrapped.
func RefusedAfterValidCode(err error) bool {
	var r *refusedAfterCode

	return errors.As(err, &r)
}

// verify runs a recovery's checks, spending nothing: the shape, the user, the
// per-user limit, the recovery codes, the password, and the side-effect-free
// checks.
//
// The shape is checked first and counted nowhere. Every refusal after the user
// is resolved is recorded on the per-user limiter; a dependency outage is not.
func (r *Recoverer) verify(ctx context.Context, req Request) (*verified, error) {
	proofs, method, reported, err := r.shape(req)
	if err != nil {
		return nil, err
	}

	details, err := r.resolveForRecover(ctx, req.Username)
	if err != nil {
		return nil, err
	}

	v := &verified{user: details.ID, details: details, proofs: proofs, mfa: method, reported: reported}
	if method != nil {
		v.mfaCode = []byte(req.MFACode)
		v.proven = []AuthenticatorRef{{Kind: MFAKind, ID: method.Name()}}
	}

	if err := r.checkUserLimit(ctx, v.user); err != nil {
		return nil, err
	}

	if err := r.checkCodes(ctx, v, req); err != nil {
		return nil, err
	}

	if v.has(ProofPassword) {
		if err := r.passwordCheck(ctx, req.Username, req.Password); err != nil {
			if errors.Is(err, authenticate.ErrAuthenticationFailed) {
				err = ErrRefused
			}

			return nil, r.refuse(ctx, v.user, err, true)
		}
	}

	if err := r.checkRest(ctx, v, req); err != nil {
		return nil, err
	}

	return v, nil
}

// shape checks the request's form: a username, exactly two proofs of
// different, enabled kinds with at least one recovery code, an MFA method named
// with its code and able to serve, and well-formed reported losses. In the
// reported mode it also needs at least one reported loss, none of them the MFA
// method presented as a proof. Anything else is ErrMalformed.
func (r *Recoverer) shape(req Request) ([]ProofKind, mfa.Method, []AuthenticatorRef, error) {
	if req.Username == "" {
		return nil, nil, nil, fmt.Errorf("%w: a username is required", ErrMalformed)
	}

	present := map[ProofKind]bool{
		ProofSaved:    req.Saved != "",
		ProofIssued:   req.Issued != "",
		ProofPassword: len(req.Password) > 0,
		ProofMFA:      req.MFAMethod != "" || req.MFACode != "",
	}

	if present[ProofMFA] && (req.MFAMethod == "" || req.MFACode == "") {
		return nil, nil, nil, fmt.Errorf("%w: an MFA proof needs both a method and a code", ErrMalformed)
	}

	var proofs []ProofKind
	for _, k := range proofOrder {
		if present[k] {
			proofs = append(proofs, k)
		}
	}

	if len(proofs) != 2 {
		return nil, nil, nil, fmt.Errorf("%w: a recovery needs exactly two proofs, got %d", ErrMalformed, len(proofs))
	}
	if !present[ProofSaved] && !present[ProofIssued] {
		return nil, nil, nil, fmt.Errorf("%w: one proof must be a recovery code", ErrMalformed)
	}
	for _, k := range proofs {
		if !slices.Contains(r.proofs, k) {
			return nil, nil, nil, fmt.Errorf("%w: proof kind %q is not enabled", ErrMalformed, k)
		}
	}

	var method mfa.Method
	if present[ProofMFA] {
		m, ok := r.mfaMethods[req.MFAMethod]
		if !ok {
			return nil, nil, nil, fmt.Errorf("%w: the MFA method named cannot serve as a recovery proof", ErrMalformed)
		}

		method = m
	}

	reported := make([]AuthenticatorRef, 0, len(req.Lost))
	for _, s := range req.Lost {
		ref, err := ParseAuthenticatorRef(s)
		if err != nil {
			return nil, nil, nil, err
		}

		reported = append(reported, ref)
	}

	// The reported mode's refusals that need no lookup belong here, counted
	// nowhere. The planner keeps its own guard as well.
	if r.planner.mode == resetReported {
		if len(reported) == 0 {
			return nil, nil, nil, fmt.Errorf("%w: the reported-loss mode needs at least one reported loss", ErrMalformed)
		}
		if method != nil && slices.Contains(reported, AuthenticatorRef{Kind: MFAKind, ID: method.Name()}) {
			return nil, nil, nil, fmt.Errorf("%w: the MFA method presented as a proof is reported lost", ErrMalformed)
		}
	}

	return proofs, method, reported, nil
}

// resolveForRecover loads the named user. An unknown, disabled or
// reference-less user is ErrRefused at once, with no further work: in
// particular the password check never runs for it, since a known user with a
// wrong recovery code never reaches that check either, and a hash paid only
// for unknown usernames would make them the slow ones.
func (r *Recoverer) resolveForRecover(ctx context.Context, username string) (*identity.Details, error) {
	details, err := r.users.LoadByUsername(ctx, username)

	switch {
	case errors.Is(err, identity.ErrUserNotFound), err == nil && (details == nil || !details.Active):
	case err != nil:
		level := slog.LevelError
		if causedByCaller(ctx, err) {
			level = slog.LevelDebug
		}

		r.logger.LogAttrs(ctx, level, msgRecoverLookupFailed, diag.Failure("user-loader", err)...)

		return nil, diag.Wrap(err, errTextUserLookup)
	case details.ID == "":
		r.logger.LogAttrs(ctx, slog.LevelError, msgRecoverNoReference)
	default:
		return details, nil
	}

	r.logger.LogAttrs(ctx, slog.LevelDebug, msgRecoverUnknown)

	return nil, ErrRefused
}

// checkUserLimit refuses a user at the recovery limit, or when the limiter
// cannot say. The refusal is ErrRefused, like any other, and is not recorded
// again.
func (r *Recoverer) checkUserLimit(ctx context.Context, user identity.UserID) error {
	exceeded, err := r.userLimiter.Exceeded(context.WithoutCancel(ctx), UserThrottleKey(user))
	if err != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgUserLimiterError, diag.Failure("limiter", err)...)

		return ErrRefused
	}
	if exceeded {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgUserThrottled)

		return ErrRefused
	}

	return nil
}

// checkCodes checks every recovery code presented, spending nothing. A code
// that is not good, another user's issued code and a throttled saved-code
// presentation are all ErrRefused. A store outage is returned, uncounted.
func (r *Recoverer) checkCodes(ctx context.Context, v *verified, req Request) error {
	if v.has(ProofSaved) {
		hash, err := r.codes.check(ctx, v.user, req.Saved)

		switch {
		case err == nil:
			v.savedHash = hash
		case errors.Is(err, ErrCodeThrottled):
			r.logger.LogAttrs(ctx, slog.LevelDebug, msgCodeThrottled)

			return r.refuse(ctx, v.user, ErrRefused, false)
		case errors.Is(err, ErrRefused):
			return r.refuse(ctx, v.user, ErrRefused, false)
		default:
			return err
		}
	}

	if v.has(ProofIssued) {
		checked, err := r.checkIssued(ctx, v.user, req.Issued)
		if err != nil {
			return r.refuse(ctx, v.user, err, false)
		}

		v.issued = checked
	}

	return nil
}

// checkIssued is the write-free check of an issued code presented for user.
// A code that is not good, and one minted for another user, are both
// ErrRefused.
func (r *Recoverer) checkIssued(ctx context.Context, user identity.UserID, presented string) (onetime.Checked, error) {
	checked, err := r.issued.Check(ctx, presented, "")
	if err != nil {
		return onetime.Checked{}, ErrRefused
	}

	if identity.UserID(checked.Token().Subject) != user {
		r.logger.LogAttrs(ctx, slog.LevelDebug, msgIssuedOtherUser)

		return onetime.Checked{}, ErrRefused
	}

	return checked, nil
}

// checkRest runs the side-effect-free checks, in order: the MFA method's
// enrolment, the reset plan, the risk hook and the consumer's checks.
func (r *Recoverer) checkRest(ctx context.Context, v *verified, req Request) error {
	if v.mfa != nil {
		enrolled, err := v.mfa.Enrolled(ctx, v.user)
		if err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgMFALookupFailed, diag.Failure("mfa-enrolment", err)...)

			return diag.Wrap(err, errTextMFALookup)
		}
		if !enrolled {
			return r.refuse(ctx, v.user, ErrRefused, true)
		}
	}

	plan, err := r.planner.plan(ctx, v.user, v.reported, v.proven)

	switch {
	case errors.Is(err, errListingFailed):
		r.logger.LogAttrs(ctx, slog.LevelError, msgListingFailed, diag.Failure("authenticator-listing", err)...)

		return err
	case err != nil:
		return r.refuse(ctx, v.user, err, true)
	}

	v.plan = plan

	if r.risk != nil {
		hold, err := r.risk(ctx, RiskInput{User: v.user, Source: req.Source, Proofs: slices.Clone(v.proofs), Now: r.clock.Now()})
		if err != nil {
			r.logger.LogAttrs(ctx, slog.LevelError, msgRiskFailed, diag.Failure("risk", err)...)

			return r.refuse(ctx, v.user, diag.Wrap(err, errTextRisk, ErrRefused), true)
		}

		v.hold = max(hold, 0)
	}

	for _, check := range r.checks {
		if err := check(ctx, v.user, slices.Clone(v.proofs)); err != nil {
			return r.refuse(ctx, v.user, err, true)
		}
	}

	return nil
}

// spend spends a verified recovery's proofs, last and in this order: the MFA
// proof, whose verification records its time step as it accepts it, so a
// wrong code spends nothing else; then the issued code; then the saved code.
// The first failure stops it. A refusal is ErrRefused, recorded on the
// per-user limiter; a saved-code store outage is returned uncounted. Of racing
// recoveries presenting the same code, at most one gets through.
//
// The whole phase runs detached from the caller's cancellation: once one
// proof is spent, a client that hangs up must not leave the others unspent
// and the recovery half done.
func (r *Recoverer) spend(ctx context.Context, v *verified) error {
	ctx = context.WithoutCancel(ctx)

	if v.mfa != nil {
		if err := v.mfa.Verify(ctx, v.user, v.mfaCode); err != nil {
			return r.spendFailed(ctx, v.user, "mfa-verify", err)
		}
	}

	if v.has(ProofIssued) {
		if err := r.issued.Consume(ctx, v.issued); err != nil {
			return r.spendFailed(ctx, v.user, "token-consume", err)
		}
	}

	if v.has(ProofSaved) {
		// Only this leg can tell a lost race from an outage: the MFA
		// method and onetime.Consume both report an outage as a refusal
		// (Consume as onetime.ErrInvalidToken, by design), so those legs
		// count every failure. codes.spend returns ErrRefused for a lost race
		// and, for an outage, an error it has already logged and whose text
		// it has replaced with fixed text; that error is returned uncounted
		// and unmarked.
		if err := r.codes.spend(ctx, v.user, v.savedHash); err != nil {
			if !errors.Is(err, ErrRefused) {
				return err
			}

			return r.spendFailed(ctx, v.user, "code-spend", err)
		}
	}

	return nil
}

// spendFailed logs a failed spend at debug level — the usual cause is a wrong
// MFA code or a racing recovery, not an outage, and each store logs its own
// outage — and refuses.
func (r *Recoverer) spendFailed(ctx context.Context, user identity.UserID, reason string, err error) error {
	r.logger.LogAttrs(ctx, slog.LevelDebug, msgSpendFailed, diag.Failure(reason, err)...)

	return r.refuse(ctx, user, ErrRefused, true)
}

// refuse records a failure for user and returns err, marked when the recovery
// codes had passed their check.
func (r *Recoverer) refuse(ctx context.Context, user identity.UserID, err error, afterCodes bool) error {
	if rerr := r.userLimiter.RecordFailure(context.WithoutCancel(ctx), UserThrottleKey(user)); rerr != nil {
		r.logger.LogAttrs(ctx, slog.LevelError, msgUserRecordError, diag.Failure("limiter", rerr)...)
	}

	if afterCodes {
		return &refusedAfterCode{err: err}
	}

	return err
}
