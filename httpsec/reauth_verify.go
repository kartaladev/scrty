package httpsec

import (
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/assurance"
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
//     factor does not decide which method may re-prove, though the
//     post-authentication phase (step 9) still refuses a re-proof a login of
//     the same user would now refuse as same-channel.
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
//  9. The post-authentication policy phase (secondFactorPhase): every deny
//     refuses with the policy's reason; a second-factor challenge does not
//     refuse, though what it hid is judged with the second factor satisfied,
//     and any other challenge refuses as at the password re-proof. A
//     refusal leaves the session as it was: nothing is rotated or refreshed,
//     and the verified response is not counted.
//  10. Success: resolve.
//
// Before step 4, and so before the throttle, a resolved caller who is not the
// session's own user (a consumer interceptor past the gates published another)
// is refused with ErrAuthenticationRequired: nothing is counted, verified or
// judged by the phase.
func (i *reauthInterceptor) verify(ex *Exchange) error {
	s, method, err := i.admitMethod(ex, i.paths().verify, anyMethod)
	if err != nil {
		return err
	}

	// admit refused a session whose first factor published no caller.
	if ex.Authentication.Principal.ID != s.UserID {
		return ErrAuthenticationRequired
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
// bind a password re-proof. The input is sessionLoginInput's, so the phase
// answers a re-proof as it answers a login of the same user now.
//
// Every deny refuses with the policy's reason, a same-channel refusal
// (policy.ErrSecondFactorSameChannel) included: the phase ends at its first
// deny, so discarding one would discard the denials it hid. A challenge for a
// second factor (policy.ChallengeMFA) does not refuse, since one is being
// presented now, but what it hid is judged (judgeBehindSecondFactor): the
// phase is asked again with the second factor satisfied, so a password change
// registered after the second-factor policy still refuses. Any other
// challenge refuses as the password re-proof refuses it
// (refuseReproofChallenge), and the re-proof marks no session into a pending
// state. With no engine on the chain, the phase allows.
func secondFactorPhase(ex *Exchange, s *session.Session, now time.Time) error {
	var (
		engine   *policy.Engine
		enforced map[policy.ChallengeKind]bool
	)

	if ex.perRequest != nil {
		engine = ex.perRequest.engine
		enforced = ex.perRequest.enforced
	}

	in := sessionLoginInput(ex.Authentication, s, now)

	ctx := ex.Context()
	d := judgeBehindSecondFactor(ctx, engine, in, evaluatePhase(ctx, engine, policy.PostAuthentication, in))

	switch d.Outcome {
	case policy.Deny:
		return policyDenyReason(d)
	case policy.Challenge:
		return refuseReproofChallenge(enforced, d.Challenge)
	case policy.Allow:
	}

	return nil
}

// sessionLoginInput is the post-authentication input a login of s's user on
// s's first factor builds, at now, for a phase judging s again after the user
// proved a factor on it: a second-factor re-proof, and MFA verification.
//
// It carries what that login carried: the caller the chain resolved from auth,
// the username the login named, the password-change time the resolution read,
// and the session's own first factor rather than the method just proved with.
// Two fields are rebuilt from what the library recorded on the session, as the
// session's own requests rebuild them. When the session records that its login
// met the second factor at its first (session.Session.MFAAtFirstFactor,
// library-owned and write-once), the input carries the library's proof of it
// (policy.Input.SecondFactorAtLogin) for that first factor, as that login's
// input carried it. The proof's time is the one the session records for its
// second factor as met, which a cross-channel re-proof moves; no policy reads
// it. And the input carries the evidence the login's provider asserted
// (policy.Input.FederatedAssurance), minted afresh from the session's
// provider, issuer, amr and acr, so the policies match it against the
// provider's configuration as it is now.
//
// The input is marked as the evaluation of a session that already exists
// (policy.Input.Reauthenticating): the session is already the user's and is
// among any a policy counts, so a policy counting sessions knows none is
// added. Whether a second factor was satisfied is the caller's to say.
func sessionLoginInput(auth *authenticate.Authentication, s *session.Session, now time.Time) *policy.Input {
	in := postAuthenticationInput(auth.Principal, s.FirstFactor, loginUsername(s.FirstFactor, auth.Principal),
		auth.PasswordChangedAt, now)
	in.Reauthenticating = true

	if s.MFAAtFirstFactor {
		in.SecondFactorAtLogin = assurance.New(s.FirstFactor, s.MFASatisfiedAt)
	}

	in.FederatedAssurance = sessionFederatedAssurance(s)

	return in
}

// loginUsername is the username a login on first named for p, as the
// post-authentication input of that login carried it: the principal's for a
// password login, which names the account it checks the password of, and for
// a passkey login, which names the account its credential resolved to; none
// for a magic-link or a federated login, which name no username, nor for any
// other first factor, whose session no library login built an input for.
//
// A password login's input names what the caller typed, which the session
// does not record; the principal's is the account that typing resolved to.
func loginUsername(first factor.Kind, p *identity.Principal) string {
	if p == nil {
		return ""
	}

	switch first {
	case factor.Password, factor.Passkey:
		return p.Username
	default:
		return ""
	}
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
