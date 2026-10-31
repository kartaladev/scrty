package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// reauthChallengePurpose is the one-time purpose a method's re-proof
// challenges are issued under. It differs from the login challenges' purpose
// (mfaChallengePurpose), so a challenge issued for one never answers the
// other, even in one shared store.
func reauthChallengePurpose(method string) string { return "reauth-challenge:" + method }

// reauthChallengeTaskPrefix starts the name of each challenge method's re-proof
// challenge expiry task; the method's name follows it.
const reauthChallengeTaskPrefix = "reauth-challenges:"

// msgReauthChallengeNotIssued is the fixed text a re-proof begin that could not
// issue its challenge or build its data is refused with. The failure is a
// dependency's, and its own text stays out of the refusal.
const msgReauthChallengeNotIssued = "httpsec: the re-authentication challenge could not be issued"

// msgReauthChallengesNotPurged is what a sweep of a method's expired re-proof
// challenges that failed is logged as.
const msgReauthChallengesNotPurged = "httpsec: expired re-authentication challenges could not be purged"

// reauthChallengeSweepFlow names the sampler keys of failed re-proof sweeps.
const reauthChallengeSweepFlow = "reauth-challenge-sweep"

// verify answers a second-factor re-proof at POST <prefix>/verify/<method>.
//
// The order is the requirement. Steps 1 to 3 are decided from the session and
// the path alone, before the body is read, and count nothing:
//
//  1. Admission: only a full session (admit).
//  2. The method the path names, matched exactly: an empty, unknown or
//     differently cased name is ErrUnknownMFAMethod.
//  3. The factor policy (offered): a method the user may not re-prove with is
//     ErrReauthenticationMethodNotUsable, and a lookup that fails refuses. The
//     same-channel rule of a login's second factor does not apply.
//  4. The MFA slot's verification throttle, the one instance a login's second
//     factor is counted on, so re-proof has no budget of its own.
//  5. The response, read the way the method declares.
//  6. For a challenge method, the re-proof challenge the response presents is
//     checked against those issued to this session and spent, whatever
//     happens next; any failure there is mfa.ErrInvalidCode, counted.
//  7. The method verifies the response.
//  8. A failure is counted, unless it refused the authenticator itself
//     (mfa.ErrAuthenticatorRefused) or compared nothing
//     (mfa.ErrVerifyThrottled), and is returned unchanged.
//  9. Success: resolve.
func (i *reauthInterceptor) verify(ex *Exchange) error {
	s, method, err := i.admitMethod(ex, i.paths().verify, anyMethod)
	if err != nil {
		return err
	}

	ctx := ex.Context()
	user := s.UserID
	throttle := i.mfa.throttle

	if err := throttle.Check(ctx, user); err != nil {
		return err
	}

	response, err := readResponse(ex.Request, method.Response())
	if err != nil {
		return err
	}

	if cm, ok := method.(mfa.ChallengeMethod); ok {
		if err := i.spendChallenge(ctx, cm, s, response); err != nil {
			throttle.RecordFailure(ctx, user)

			return err
		}
	}

	if err := method.Verify(ctx, user, response); err != nil {
		if !errors.Is(err, mfa.ErrAuthenticatorRefused) && !errors.Is(err, mfa.ErrVerifyThrottled) {
			throttle.RecordFailure(ctx, user)
		}

		return err
	}

	return i.resolve(ex, s, method)
}

// begin issues a re-proof challenge for a challenge method at POST
// <prefix>/begin/<method>, and answers with the method's begin data.
//
// It makes verify's refusals before reading anything, and reads no body at
// all; a path naming a method with no begin step is refused as unknown, as
// one naming no method is. A user the throttle refuses is refused here too, so
// a locked-out user cannot keep minting challenges. The challenge is a
// one-time token of the method's re-proof purpose, whose subject is the user
// and which is bound to the session, so only the session that asked can
// answer it. Issuance is bounded per user and method within the store's
// issuance window: a begin past the limit is mfa.ErrVerifyThrottled and issues
// nothing, the count and the issue being one decision of the store's.
func (i *reauthInterceptor) begin(ex *Exchange) error {
	s, method, err := i.admitMethod(ex, i.paths().begin, isChallengeMethod)
	if err != nil {
		return err
	}

	ctx := ex.Context()

	if err := i.mfa.throttle.Check(ctx, s.UserID); err != nil {
		return err
	}

	cm := method.(mfa.ChallengeMethod) // admitMethod checked it
	mgr := i.challenges[method.Name()]

	i.sweepExpired(ctx, method.Name(), mgr)

	challenge, _, err := mgr.IssueWithin(ctx, string(s.UserID), i.challengeCap, onetime.WithBinding(s.ID))

	switch {
	case errors.Is(err, onetime.ErrIssueLimitReached):
		return mfa.ErrVerifyThrottled
	case err != nil:
		return diag.Wrap(err, msgReauthChallengeNotIssued)
	}

	data, err := cm.BeginChallenge(ctx, s.UserID, challenge)
	if err != nil {
		return diag.Wrap(err, msgReauthChallengeNotIssued)
	}

	return i.beginRespond(ex, data)
}

// admitMethod makes the refusals begin and verify share, all decided before
// the body is read and none counted: admission, the method the path names
// under prefix, and the factor policy. serves reports whether the endpoint
// serves a configured method at all; one it does not is unknown.
func (i *reauthInterceptor) admitMethod(
	ex *Exchange,
	prefix string,
	serves func(mfa.Method) bool,
) (*session.Session, mfa.Method, error) {
	s, err := i.admit(ex)
	if err != nil {
		return nil, nil, err
	}

	if i.mfa == nil {
		return nil, nil, ErrUnknownMFAMethod
	}

	name, ok := methodSegment(ex.Request.Path(), prefix)
	method, known := i.mfa.byName[name]
	if !ok || !known || !serves(method) {
		return nil, nil, ErrUnknownMFAMethod
	}

	offered, _, err := i.offered(ex.Context(), s)
	if err != nil {
		return nil, nil, err
	}

	if !slices.ContainsFunc(offered, func(m mfa.Method) bool { return m.Name() == name }) {
		return nil, nil, ErrReauthenticationMethodNotUsable
	}

	return s, method, nil
}

// spendChallenge checks the re-proof challenge a challenge method's response
// presents against those issued to session s, and spends it. Only a nil return
// lets the method verify the response. Every failure, a store that could not
// answer included, is mfa.ErrInvalidCode, so it fails closed and a caller
// learns only that the answer was not good.
func (i *reauthInterceptor) spendChallenge(
	ctx context.Context,
	cm mfa.ChallengeMethod,
	s *session.Session,
	response []byte,
) error {
	presented, err := cm.PresentedChallenge(response)
	if err != nil || presented == "" {
		return mfa.ErrInvalidCode
	}

	mgr := i.challenges[cm.Name()]

	checked, err := mgr.Check(ctx, presented, s.ID)
	if err != nil {
		return mfa.ErrInvalidCode
	}

	if err := mgr.Consume(ctx, checked); err != nil {
		return mfa.ErrInvalidCode
	}

	return nil
}

// sweepExpired purges method's expired re-proof challenges from the store when
// a sweep is due, at most once per issuance window per method. A sweep that
// fails is logged through the chain's sampler and otherwise ignored; one that
// failed for any reason but the store's inability to purge gives its turn
// back.
func (i *reauthInterceptor) sweepExpired(ctx context.Context, method string, mgr *onetime.Tokens) {
	clock := i.sweeps[method]

	claimed, due := clock.claim(i.now(), mgr.IssuanceWindow())
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

	logSampled(ctx, i.sampler, i.log, slog.LevelWarn, i.now(),
		reauthChallengeSweepFlow+sampleKeySeparator+method+sampleKeySeparator+reason, msgReauthChallengesNotPurged,
		slog.String("method", method), slog.String("reason", reason))
}

// expiryTasks returns a task per challenge method, over the manager its
// re-proof begin issues challenges with, in the methods' configured order.
func (i *reauthInterceptor) expiryTasks() []expiry.Task {
	if i.mfa == nil {
		return nil
	}

	var tasks []expiry.Task

	for _, m := range i.mfa.methods {
		if mgr, ok := i.challenges[m.Name()]; ok {
			tasks = append(tasks, onetime.ExpiryTaskNamed(reauthChallengeTaskPrefix+m.Name(), mgr))
		}
	}

	return tasks
}
