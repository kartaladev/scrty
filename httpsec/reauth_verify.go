package httpsec

import (
	"errors"
	"time"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/policy"
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
//  3. The factor policy, through the named method's own enrolment lookup: a
//     method the user is not enrolled on is
//     ErrReauthenticationMethodNotUsable, and a lookup that fails refuses. No
//     other method is looked up. The same-channel rule of a login's second
//     factor does not apply.
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
//  9. The post-authentication policy phase, as the password re-proof applies
//     it (secondFactorPhase): a deny refuses with the policy's reason, except
//     the same-channel refusal, and a challenge does not refuse. A refusal
//     leaves the session as it was: nothing is rotated or refreshed, and
//     the verified response is not counted.
//  10. Success: resolve.
func (i *reauthInterceptor) verify(ex *Exchange) error {
	s, method, err := i.admitMethod(ex, i.paths().verify, anyMethod)
	if err != nil {
		return err
	}

	// Steps 4 to 8.
	if err := checkResponse(ex, i.mfa.throttle, i.challenges, method, s); err != nil {
		return err
	}

	if err := secondFactorPhase(ex, s, i.now()); err != nil {
		return err
	}

	return i.resolve(ex, s, method)
}

// secondFactorPhase applies the post-authentication phase to a verified
// second-factor re-proof of s, judged at now on the chain's engine, so a
// consumer's post-authentication denials and the session cap bind it as they
// bind a password re-proof.
//
// The input is the one a login builds for the session's user and first factor:
// the caller the chain resolved, its username, the password-change time the
// resolution read, and the session's own first factor rather than the method
// re-proved with. It is marked as the re-authentication of an existing session
// (policy.Input.Reauthenticating), so a policy counting sessions knows none is
// added.
//
// A deny refuses with the policy's reason, except one whose reason is
// policy.ErrSecondFactorSameChannel: re-proof does not apply the same-channel
// rule, so a passkey sign-in may re-prove with the passkey. A challenge does
// not refuse: the one a login's second factor answers is the factor being
// presented now, and the re-proof marks no session into a pending state.
// With no engine on the chain, the phase allows.
func secondFactorPhase(ex *Exchange, s *session.Session, now time.Time) error {
	var engine *policy.Engine
	if ex.perRequest != nil {
		engine = ex.perRequest.engine
	}

	// admit refused a session whose first factor published no caller.
	auth := ex.Authentication
	in := postAuthenticationInput(auth.Principal, s.FirstFactor, auth.Principal.Username, auth.PasswordChangedAt, now)
	in.Reauthenticating = true

	d := evaluatePhase(ex.Context(), engine, policy.PostAuthentication, in)
	if d.Outcome == policy.Deny && !errors.Is(d.Reason, policy.ErrSecondFactorSameChannel) {
		return policyDenyReason(d)
	}

	return nil
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

	return issueChallenge(ex, s, method.(mfa.ChallengeMethod), challengeIssue{ // admitMethod checked it
		throttle:  i.mfa.throttle,
		mgr:       i.challenges[method.Name()],
		sweep:     i.sweeps[method.Name()],
		limit:     i.challengeCap,
		respond:   i.beginRespond,
		notIssued: msgReauthChallengeNotIssued,
		sweepFlow: reauthChallengeSweepFlow,
		notPurged: msgReauthChallengesNotPurged,
		now:       i.now,
		sampler:   i.sampler,
		log:       i.log,
	})
}

// admitMethod makes the refusals begin and verify share, all decided before
// the body is read and none counted: admission, the method the path names
// under prefix, and the factor policy (the named method's enrolment only).
// serves reports whether the endpoint serves a configured method at all; one
// it does not is unknown.
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

	// Only the named method's enrolment is looked up: presenting an enrolled
	// second factor is already the strongest proof the policy can ask for, so
	// an unrelated method's lookup cannot cause a downgrade here. A failure of
	// this lookup refuses, behind fixed text.
	enrolled, err := method.Enrolled(ex.Context(), s.UserID)
	if err != nil {
		return nil, nil, diag.Wrap(err, msgReauthMethodsUnavailable)
	}

	if !enrolled {
		return nil, nil, ErrReauthenticationMethodNotUsable
	}

	return s, method, nil
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
