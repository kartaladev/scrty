package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// sessionResolver is the resolution core a session-bound authenticator joins
// once it has extracted, and where it applies verified, its credential: it
// loads and judges the session, reloads and checks the user, publishes the
// caller and the session through PublishSession, and runs the per-request
// phase with the challenge handling EvaluatePerRequest applies. Activity is
// left to the session-touch step, which records it for whatever was
// published.
//
// Every authenticator that resolves a session through it refuses the same
// way, with the same errors and the same records, whatever its credential.
type sessionResolver struct {
	sessions *session.Manager
	users    identity.UserLoader
	log      *slog.Logger

	// phase is the per-request phase the core runs, over the authenticator's
	// own session manager and the chain's engine and enforcer set.
	phase perRequestPhase

	// renewal is the chain's renewal endpoint, handed over at assembly, and
	// nil while it is off. A late session the manager says must be renewed is
	// let through to it, and to nothing else.
	renewal *sessionRenewal
}

// userLookup says how the core reloads the session's user.
//
// The signed bearer reloads by the username its token names, which is what
// lookupByUsername builds. The session-reference bearer has no token to name
// anyone, and reloads by the user reference the session itself records, which
// is what lookupBySessionUser builds.
type userLookup struct {
	username      string
	bySessionUser bool
}

// lookupByUsername reloads the user by username. The user it finds must still
// be the one the session records (see ownActiveUser), so a username reissued
// to another person does not carry the first one's session over to them.
func lookupByUsername(username string) userLookup { return userLookup{username: username} }

// lookupBySessionUser reloads the user by the reference the session records,
// never by username: a username is a reusable handle, and one reissued to
// another person would otherwise authenticate them on the first one's session.
func lookupBySessionUser() userLookup { return userLookup{bySessionUser: true} }

// load reloads the user the lookup names for s.
func (l userLookup) load(ctx context.Context, users identity.UserLoader, s *session.Session) (*identity.Details, error) {
	if l.bySessionUser {
		return users.LoadByUserID(ctx, s.UserID)
	}

	return users.LoadByUsername(ctx, l.username)
}

// ownActiveUser refuses with ErrAuthenticationRequired unless details is the
// active user s records.
//
// A loader that reported no error and no user has told us nothing, and a
// request judged on no principal is an anonymous one wearing a credential.
//
// A user other than the one the session records is refused: a username is a
// reusable handle, and a signed token naming one that has since been
// reassigned would otherwise authenticate its new owner on the old owner's
// session. A user who is not active is refused too, so disabling a user takes
// effect at the next request rather than when the session ends.
//
// The refusal revokes nothing. What disabling means for the consumer's other
// systems is the consumer's to decide, so a refused session stays stored and
// authenticates again if its user is re-enabled before it expires; a consumer
// that wants it gone calls the session store's DeleteByUser when disabling.
// There is no option to relax either check: a session that authenticates
// someone else, or a disabled user, is never a legitimate configuration.
func ownActiveUser(s *session.Session, details *identity.Details) error {
	if details == nil || details.ID != s.UserID || !details.Active {
		return ErrAuthenticationRequired
	}

	return nil
}

// resolve resolves the session id names, and its user by, onto ex.
//
// It returns nil when the request may go on, and the refusal otherwise.
func (r *sessionResolver) resolve(ex *Exchange, id string, by userLookup) error {
	ctx := ex.Context()

	s, err := r.sessions.Load(ctx, id)
	if err != nil {
		if errors.Is(err, session.ErrSessionUnreadable) {
			// Visible to an operator, because it means a sealing key was
			// retired while sessions sealed under it were still live. The
			// caller is answered "log in again", because that is the remedy
			// and a 500 storm is not.
			//
			// The record carries a fixed reason and the error's Go type, never
			// its text: the consumer's store may word the failure with the
			// row it could not read.
			r.log.LogAttrs(ctx, slog.LevelError, msgSessionUnreadable,
				diag.Failure("session-store", err)...)
		}

		// A superseded identifier presented after its window, under
		// unused-successor recovery: nothing was revoked, and only a renewal
		// may judge it. On the renewal endpoint's own request it goes on with
		// nothing published, no caller and no session, so nothing on the way
		// and no handler sees it authenticated; the endpoint, which always
		// answers its own requests, loads it for renewal. Every other request
		// is refused as for any ended session.
		if errors.Is(err, session.ErrSessionRenewalRequired) &&
			r.renewal != nil && r.renewal.answers(ex.Request) {
			ex.renewal = id

			return nil
		}

		// A superseded identifier presented after its window: the manager has
		// revoked the family by now. The caller is answered as for any ended
		// session, and the reuse stays identifiable, so a consumer that rolls
		// its request transaction back on a refusal can tell this is the one
		// refusal it must commit, or it would roll the revocation back too.
		// The manager's error names no identifier.
		if errors.Is(err, session.ErrSessionReused) {
			return errors.Join(ErrAuthenticationRequired, err)
		}

		// Missing, expired and unreadable are the same answer: telling them
		// apart would report whether a session ever existed.
		return ErrAuthenticationRequired
	}

	// Reloaded rather than taken from the credential, so a role revoked a
	// minute ago is not honoured for the rest of the credential's life.
	details, err := by.load(ctx, r.users, s)
	if err != nil {
		return ErrAuthenticationRequired
	}

	if err := ownActiveUser(s, details); err != nil {
		return err
	}

	principal := identity.PrincipalFromDetails(details)

	now := r.phase.now()

	if err := ex.PublishSession(&authenticate.Authentication{
		Principal:         principal,
		Time:              now,
		PasswordChangedAt: details.PasswordChangedAt,
	}, s); err != nil {
		return err
	}

	return ex.evaluatePerRequest(&r.phase, s, principal, details.PasswordChangedAt, now)
}

// perRequestPhase is what the per-request policy phase and its challenge
// handling need: the chain's engine, enforcer set and enrolment lifetime, the
// session manager a challenge mark is stored through, and the clock the phase
// is judged at.
type perRequestPhase struct {
	engine   *policy.Engine
	sessions *session.Manager

	// enrolmentLifetime is how long a session marked for an enrolment
	// challenge may live.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on the chain enforces; a
	// raised kind outside it refuses the request.
	enforced map[policy.ChallengeKind]bool

	now func() time.Time
}

// evaluatePerRequest runs the per-request phase for s and p on ex under ph,
// at now, and applies its outcome: a denial is returned, a challenge is
// marked where its gate reads it, and an allow returns nil.
func (ex *Exchange) evaluatePerRequest(
	ph *perRequestPhase,
	s *session.Session,
	p *identity.Principal,
	passwordChangedAt time.Time,
	now time.Time,
) error {
	ctx := ex.Context()

	d := evaluatePhase(ctx, ph.engine, policy.PerRequest, &policy.Input{
		User:               p.ID,
		Username:           p.Username,
		Principal:          p,
		Session:            s,
		FirstFactor:        s.FirstFactor,
		MFASatisfied:       s.MFA == session.MFASatisfied,
		PasswordChangedAt:  passwordChangedAt,
		FederatedAssurance: sessionFederatedAssurance(s),
		Now:                now,
	})

	switch d.Outcome {
	case policy.Deny:
		return policyDenyReason(d)
	case policy.Challenge:
		// A kind nothing on the chain enforces is refused before anything is
		// marked, whatever state the session is in; see refuseUnenforced.
		if err := refuseUnenforced(ph.enforced, d.Challenge); err != nil {
			return err
		}

		// A recovery-pending session is not marked: marking would move it out
		// of that state without a binding, and the recovery gate is its only
		// enforcer until one completes. It goes on to that gate, which
		// refuses it unless the request is one that can bind it. Only the
		// mark is skipped: the check above and the record below still apply.
		//
		// Otherwise it is marked and continued, not refused here: the gate for
		// this challenge enforces it at its own slot, and refusing at this one
		// would also block the very endpoint the caller must reach to resolve
		// it.
		if s.MFA != session.MFARecoveryPending {
			if err := ph.markChallenge(ctx, s, d.Challenge); err != nil {
				return err
			}
		}

		// A consumer kind has no field on the session to be marked in, so it
		// is recorded where the gate the consumer declared for it reads it.
		if _, builtIn := builtInEnforcers[d.Challenge]; !builtIn {
			ex.raised = d.Challenge
		}
	case policy.Allow:
	}

	return nil
}

// markChallenge records a per-request challenge on s.
//
// A session entering the enrolment-only state is saved here, before the
// request goes on. That mark lowers the session's deadlines, and the gate that
// enforces it refuses the request at a slot outside the session-touch step, so
// a mark left for that step to persist would never be stored: the session
// would keep its full lifetime while it is confined. A session already in the
// state is not written again, since marking it changes nothing. A failed save
// refuses the request rather than serving it on an unrecorded mark.
//
// The other kinds are marked in memory only, as before: the per-request phase
// raises them again on every request, and they change no deadline.
//
// A kind nothing on the chain enforces is refused with a configuration error
// before anything is marked; see refuseUnenforced.
func (ph *perRequestPhase) markChallenge(ctx context.Context, s *session.Session, kind policy.ChallengeKind) error {
	if err := refuseUnenforced(ph.enforced, kind); err != nil {
		return err
	}

	entering := kind == policy.ChallengeMFAEnrolment && s.MFA != session.MFAEnrolmentPending

	if entering && ph.sessions == nil {
		// Reached only through EvaluatePerRequest on a chain no built-in gave
		// a session manager: the mark could not be stored, and serving the
		// request on a mark held only in memory would leave the session its
		// full lifetime while it is confined.
		return newConfigError("a policy raised %s, but this chain has no session manager to "+
			"store the mark in: enable a built-in wired to the session manager, such as "+
			"EnableLogout", kind)
	}

	challengeMarker{sessions: ph.sessions, enrolmentLifetime: ph.enrolmentLifetime}.mark(s, kind)

	if !entering {
		return nil
	}

	return ph.sessions.Save(ctx, s)
}

// sessionFederatedAssurance is the evidence a federated session's login
// asserted, minted afresh on every request from the session's library-owned
// fields: the provider and issuer it was created with and the amr and acr
// recorded in the creating write. The policies match it against the
// provider's configuration as it is now, so a tightened or removed provider
// takes effect at the session's next request.
//
// A session whose first factor is not on the federated channel carries no
// evidence, whatever its fields hold. Nothing is read from the request, a
// header, a claim or the session's consumer data.
func sessionFederatedAssurance(s *session.Session) policy.FederatedAssurance {
	if s.FirstFactor.Channel() != factor.Federated {
		return policy.FederatedAssurance{}
	}

	return mintFederated(s.ExternalProvider, s.ExternalIssuer, s.FederatedAMR, s.FederatedACR)
}

// msgSessionUnreadable reports a session that could not be decrypted. It is
// at error because it is an outage of the deployment's own keys.
const msgSessionUnreadable = "httpsec: a session could not be decrypted"
