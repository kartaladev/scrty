package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// spendChallenge checks the challenge a challenge method's response presents
// against those issued to session s through mgr, and spends it. Only a nil
// return lets the method verify the response. The second-factor and the
// re-proof endpoints both spend their challenges here, so the two cannot
// drift apart.
//
// Every attempt that presents a live challenge spends it, whether the method
// then accepts the response or not. That departs from check-then-consume as
// the one-time package frames it — where a refusal between the two leaves the
// token redeemable — on purpose: a pending challenge is not a credential the
// user holds and would lose, only the server's nonce for one attempt, and one
// try per challenge is the simpler guarantee to state and to keep. It also
// settles a race: of several attempts presenting one challenge, the store's
// compare-and-set lets exactly one through to Verify.
//
// Every failure is mfa.ErrInvalidCode, the refusal the method itself gives a
// wrong response, so a caller learns only that the answer was not good. That
// includes a store that could not answer: the one-time manager reports its
// store's failures as an invalid token too, and logs them, so this fails
// closed rather than letting an attempt reach the method unspent. The store's
// failure is kept beneath that refusal (depfault.Refusal), so the status, the
// text and errors.Is(err, mfa.ErrInvalidCode) are those of a wrong code while
// no refusal event is reported for it: the manager's store is decorated by
// challengeManagers, which is what lets this tell the two apart.
func spendChallenge(
	ctx context.Context,
	mgr *onetime.Tokens,
	cm mfa.ChallengeMethod,
	s *session.Session,
	response []byte,
) error {
	presented, err := cm.PresentedChallenge(response)
	if err != nil || presented == "" {
		return mfa.ErrInvalidCode
	}

	wctx, watch := depfault.Watching(ctx)

	checked, err := mgr.Check(wctx, presented, s.ID)
	if err != nil {
		return refusedByChallengeStore(watch)
	}

	if err := mgr.Consume(wctx, checked); err != nil {
		return refusedByChallengeStore(watch)
	}

	return nil
}

// refusedByChallengeStore is the refusal of a challenge the one-time manager
// answered as invalid: mfa.ErrInvalidCode, carrying the failure of the store
// beneath it when watch saw one, so that no event is reported for a store that
// could not answer.
func refusedByChallengeStore(watch *depfault.Watch) error {
	if cause := watch.Failure(); cause != nil {
		return depfault.Refusal(cause, mfa.ErrInvalidCode)
	}

	return mfa.ErrInvalidCode
}

// sweepExpired purges method's expired challenges from mgr's store, when
// clock says a sweep is due. A sweep that fails is logged through the chain's
// sampler, under flow and msg, and otherwise ignored.
//
// It runs under the request's own context, so a store that stops answering
// holds the begin no longer than the request allows. A sweep that fails, or is
// cut short, gives its turn back, so a later begin sweeps again rather than
// waiting out the window; the exception is a store that cannot purge at all,
// which no retry would change, so its turn is kept and it is logged once per
// window.
func sweepExpired(
	ctx context.Context,
	mgr *onetime.Tokens,
	clock *sweepClock,
	now func() time.Time,
	flow, msg, method string,
	sampler *logsample.Sampler,
	log *slog.Logger,
) {
	claimed, due := clock.claim(now(), mgr.IssuanceWindow())
	if !due {
		return
	}

	_, err := mgr.PurgeExpired(ctx)
	if err == nil {
		return
	}

	reason := reasonStoreUnavailable
	if errors.Is(err, onetime.ErrReapUnsupported) {
		reason = reasonPurgeUnsupported
	} else {
		clock.release(claimed)
	}

	logSampled(ctx, sampler, log, slog.LevelWarn, now(),
		flow+sampleKeySeparator+method+sampleKeySeparator+reason, msg,
		slog.String("method", method), slog.String("reason", reason))
}

// checkResponse takes a second-factor response through the steps the
// second-factor and the re-proof verify endpoints share, once the endpoint has
// admitted the request and named method. Only a nil return lets the endpoint
// resolve; any other return is its refusal, unchanged. In order:
//
//  1. throttle refuses a user it has locked out, before the response is read.
//  2. The response is read the way the method declares.
//  3. For a challenge method, the challenge the response presents is checked
//     against the challenges issued to session s and spent (spendChallenge);
//     a failure there is mfa.ErrInvalidCode, recorded against the user.
//  4. The method verifies the response. A failure is recorded against the
//     user, unless it refused the authenticator rather than its response,
//     such as a suspected clone (mfa.ErrAuthenticatorRefused), or compared
//     nothing, such as a refused attempt charge
//     (mfa.ErrVerifyThrottled): neither is a guess.
//
// The two endpoints differ in the throttle and the challenges they pass, never
// in this order.
//
// A response refused at step 3 or 4 is reported on the session as the event
// named failed (security events); a refused attempt charge is reported as
// security.ExcessRateLimitExceeded instead, and a dependency that failed and a
// request whose own context ended report nothing here.
func checkResponse(
	ex *Exchange,
	throttle *mfa.VerifyThrottle,
	challenges map[string]*onetime.Tokens,
	method mfa.Method,
	s *session.Session,
	failed string,
) error {
	ctx := ex.Context()
	user := s.UserID

	if err := throttle.Check(ctx, user); err != nil {
		return err
	}

	response, err := readResponse(ex.Request, method.Response())
	if err != nil {
		return err
	}

	if cm, ok := method.(mfa.ChallengeMethod); ok {
		if err := spendChallenge(ctx, challenges[cm.Name()], cm, s, response); err != nil {
			throttle.RecordFailure(ctx, user)
			emitResponseRefused(ctx, err, failed, s)

			return err
		}
	}

	if err := method.Verify(ctx, user, response); err != nil {
		if !errors.Is(err, mfa.ErrAuthenticatorRefused) && !errors.Is(err, mfa.ErrVerifyThrottled) {
			throttle.RecordFailure(ctx, user)
		}

		emitResponseRefused(ctx, err, failed, s)

		return err
	}

	return nil
}

// emitResponseRefused reports a second-factor response refused with err on
// the session s. A refused attempt charge (mfa.ErrVerifyAttemptsExhausted) and
// a plain mfa.ErrVerifyThrottled the method answered are reported as
// security.ExcessRateLimitExceeded, since nothing else reports them; any other
// refusal as the event named failed. The built-in throttle's own refusal of a
// locked-out user returns before a response is judged, so it never reaches
// here and is reported once, by the throttle. A dependency failure, such as a
// challenge store that failed beneath the refusal, and a request whose own
// context ended, are not reported.
func emitResponseRefused(ctx context.Context, err error, failed string, s *session.Session) {
	if !refused(ctx, err) || depfault.Silent(ctx, err) {
		return
	}

	switch {
	case errors.Is(err, mfa.ErrVerifyAttemptsExhausted), errors.Is(err, mfa.ErrVerifyThrottled):
		emitEvent(ctx, sessionEvent(security.ExcessRateLimitExceeded, security.OutcomeFailure, s))
	default:
		emitEvent(ctx, sessionEvent(failed, security.OutcomeFailure, s))
	}
}

// challengeIssue is what one endpoint issues a challenge method's challenges
// with. The second-factor begin and the re-proof begin each fill it from their
// own configuration.
type challengeIssue struct {
	// throttle refuses a user it has locked out before anything is issued.
	throttle *mfa.VerifyThrottle

	// mgr issues the method's challenges, sweep spaces its sweeps, and limit
	// bounds the challenges one user is issued within mgr's issuance window.
	mgr   *onetime.Tokens
	sweep *sweepClock
	limit int

	// respond answers with the method's begin data.
	respond MFABeginResponder

	// notIssued is the fixed text a challenge that could not be issued, or
	// whose data could not be built, is refused with.
	notIssued string

	// sweepFlow and notPurged are the sampler flow and the record text of a
	// failed sweep; now, sampler and log are the endpoint's own.
	sweepFlow, notPurged string
	now                  func() time.Time
	sampler              *logsample.Sampler
	log                  *slog.Logger
}

// issueChallenge issues cm's challenge to session s and answers with the
// method's begin data: the steps the second-factor and the re-proof begin
// endpoints share once the endpoint has admitted the request. In order:
//
//  1. iss.throttle refuses a user it has locked out, so a locked-out user
//     cannot keep minting challenges.
//  2. The method's expired challenges are swept, when a sweep is due
//     (sweepExpired). A sweep that fails is logged, never refused.
//  3. One challenge is issued, bound to the session, unless the user already
//     holds iss.limit of them within the issuance window: then the refusal is
//     mfa.ErrVerifyThrottled and nothing is issued. A store that cannot decide
//     is refused behind iss.notIssued.
//  4. The method builds its begin data around the challenge, and iss.respond
//     answers with it. A method that fails is refused behind iss.notIssued.
func issueChallenge(ex *Exchange, s *session.Session, cm mfa.ChallengeMethod, iss challengeIssue) error {
	ctx := ex.Context()

	if err := iss.throttle.Check(ctx, s.UserID); err != nil {
		return err
	}

	sweepExpired(ctx, iss.mgr, iss.sweep, iss.now, iss.sweepFlow, iss.notPurged, cm.Name(), iss.sampler, iss.log)

	// One bounded issue, not a count and then an issue: of begins racing for
	// one user, on this process or on another replica, no more than the limit
	// are issued a challenge.
	challenge, _, err := iss.mgr.IssueWithin(ctx, string(s.UserID), iss.limit, onetime.WithBinding(s.ID))

	switch {
	case errors.Is(err, onetime.ErrIssueLimitReached):
		// Decided here, apart from a store that could not decide, so it is
		// reported as the limit it is.
		emitEvent(ctx, sessionEvent(security.ExcessRateLimitExceeded, security.OutcomeFailure, s))

		return mfa.ErrVerifyThrottled
	case err != nil:
		return diag.Wrap(err, iss.notIssued)
	}

	data, err := cm.BeginChallenge(ctx, s.UserID, challenge)
	if err != nil {
		return diag.Wrap(err, iss.notIssued)
	}

	return iss.respond(ex, data)
}

// challengeManagers builds one challenge manager and one sweep clock per
// challenge method of methods, keyed by the method's name, all over store, on
// the chain's clock and logger. purpose names each method's one-time purpose,
// which keeps managers sharing one store apart; refuse words the configuration
// error a manager that cannot be built is reported as. store may be nil only
// when methods hold no challenge method.
func challengeManagers(
	c *config,
	methods []mfa.Method,
	store onetime.Store,
	ttl time.Duration,
	purpose func(method string) string,
	refuse func(method string, err error) error,
) (map[string]*onetime.Tokens, map[string]*sweepClock, error) {
	managers := make(map[string]*onetime.Tokens)
	sweeps := make(map[string]*sweepClock)

	for _, m := range methods {
		if !isChallengeMethod(m) {
			continue
		}

		// The store is decorated so that spendChallenge can tell a store
		// that failed from a challenge that was not good.
		mgr, err := onetime.New(purpose(m.Name()),
			onetime.WithTokenTTL(ttl),
			onetime.WithStore(depfault.Store(store)),
			onetime.WithClock(c.clock),
			onetime.WithLogger(c.logger))
		if err != nil {
			return nil, nil, refuse(m.Name(), err)
		}

		managers[m.Name()] = mgr
		sweeps[m.Name()] = &sweepClock{}
	}

	return managers, sweeps, nil
}
