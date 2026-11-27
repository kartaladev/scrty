package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/porterr"
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
	sessions *session.Sessions
	users    identity.UserLoader
	log      *slog.Logger

	// phase is the per-request phase the core runs, over the authenticator's
	// own session manager and the chain's engine and enforcer set.
	phase perRequestPhase

	// renewal is the chain's renewal endpoint, handed over at assembly, and
	// nil while it is off. A late session the manager says must be renewed is
	// let through to it, and to nothing else.
	renewal *sessionRenewal

	// cookie is the chain's cookie session when this core resolves the
	// session cookie, and nil for a bearer. A role switch on a session it
	// resolved rotates the session and re-sets the cookie (Chain.
	// SwitchActiveRole).
	cookie *sessionCookie

	// admit, when set, judges the loaded session before its user is reloaded
	// or anything is published; an error it returns is the request's answer.
	// Both bearers judge the session's key binding here, and the signed bearer
	// its token's subject. A late renewal runs it too, at the endpoint.
	//
	// The record it returns is the user it loaded for this request, which the
	// caller uses rather than loading again. Nil means it loaded none, and the
	// caller loads the user by the reference the session records. Only a signed
	// bearer under WithBearerUsernameSubject returns one.
	admit func(ex *Exchange, s *session.Session) (*identity.Details, error)
}

// ownsSession reports whether details is the user s records. A loader that
// reported no error and no user owns nothing, and neither does a user with no
// identifier: an empty reference names no one, so it matches no user, not even
// one with no identifier of its own.
func ownsSession(s *session.Session, details *identity.Details) bool {
	return details != nil && details.ID != "" && details.ID == s.UserID
}

// ownActiveUser refuses with ErrAuthenticationRequired unless details is the
// active user s records.
//
// A loader that reported no error and no user has told us nothing, and a
// request judged on no principal is an anonymous one wearing a credential.
//
// A user other than the one the session records is refused (ownsSession): a
// username is a reusable handle, and a signed token read under
// WithBearerUsernameSubject naming one that has since been reassigned would
// otherwise authenticate its new owner on the old owner's session. A user who is
// not active is refused too, so disabling a user takes effect at the next request
// rather than when the session ends.
//
// The refusal revokes nothing. What disabling means for the consumer's other
// systems is the consumer's to decide, so a refused session stays stored and
// authenticates again if its user is re-enabled before it expires; a consumer
// that wants it gone calls the session store's DeleteByUser when disabling.
// There is no option to relax either check: a session that authenticates
// someone else, or a disabled user, is never a legitimate configuration.
func ownActiveUser(s *session.Session, details *identity.Details) error {
	if !ownsSession(s, details) || !details.Active {
		return ErrAuthenticationRequired
	}

	return nil
}

// resolve resolves the session id names, and its user, onto ex.
//
// The user is reloaded by the reference the session itself records, never by
// username: a username is a reusable handle, and one reissued to another person
// would otherwise authenticate them on the first one's session. Only a signed
// bearer configured with WithBearerUsernameSubject loads by the username its
// token names, and it does so in its admit step (admitSubject), which returns
// the record.
//
// It returns nil when the request may go on. Otherwise it returns a refusal,
// which matches ErrAuthenticationRequired unless the per-request phase refused
// on a policy's grounds, or a failure that matches neither: a dependency
// failure or the request's own context ending (classifyLoad, classifyReload).
func (r *sessionResolver) resolve(ex *Exchange, id string) error {
	ctx := ex.Context()

	s, err := r.sessions.Load(ctx, id)
	if err != nil {
		// The store is the consumer's, so its error is read through one
		// bounded walk. One the walk gives up on is no verdict on the
		// session: it is the store's failure, answered behind fixed text as
		// classifyLoad answers any other, with no event. Its error goes no
		// further, since every check of the refusal on the way out would
		// walk it again; errLoadUnreadable stands in its place. The dispatch
		// then cannot meet the abort, so it is reported here, once.
		load := readLoadFailure(err)
		if load.abort != nil {
			ex.answeringChain().reportAbort(ctx, load.abort)

			return diag.Wrap(errLoadUnreadable, textSessionNotResolved)
		}

		if load.unreadable {
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
		if load.renewalRequired && r.renewal != nil && r.renewal.answers(ex.Request) {
			// The session is judged once the endpoint loads it, as admit
			// judges one loaded here, so a late credential presented by the
			// wrong sender, or naming someone other than the session's user, is
			// refused there, and its proof recorded only if it is not.
			ex.renewal = id
			ex.admitRenewal = r.admit

			return nil
		}

		emitLoadRefusal(ctx, load)

		return classifyLoad(ctx, err, load)
	}

	// The session exactly as the store returned it, before anything on this
	// request marks it in memory (the per-request phase below marks its
	// challenges on s). Second-factor verification and re-authentication
	// compare the stored record with it, so a mark of this request's own is
	// never taken for another request's change.
	loaded := copySession(s)

	var details *identity.Details

	if r.admit != nil {
		details, err = r.admit(ex, s)
		if err != nil {
			return err
		}
	}

	// Reloaded rather than taken from the credential, so a role revoked a
	// minute ago is not honoured for the rest of the credential's life. A user
	// admit loaded for this request has just been read, so it is not read again.
	if details == nil {
		details, err = r.users.LoadByUserID(ctx, s.UserID)
		err = porterr.SanitizeTo(ctx, r.log, err, porterr.ErrUnwalkable)

		if err != nil {
			return classifyReload(ctx, err)
		}
	}

	if err := ownActiveUser(s, details); err != nil {
		return err
	}

	now := r.phase.now()

	// Built at the chain's clock, so a grant outside its dates is not honoured
	// for a request being authenticated now. A user left with no valid grant is
	// still authenticated, with no active role: the session is neither refused
	// nor revoked, and a privilege guard refuses for want of a role.
	principal := identity.PrincipalFromDetailsAt(details, now)

	// The chain running this resolution is the one the authenticator belongs
	// to. With switching on, the session's selection is applied to the grants
	// just kept, and the request remembers which resolution it was, so
	// Chain.SwitchActiveRole reloads and records through the same loader and
	// manager.
	switching := ex.publishingChain()
	if switching == nil || switching.perRequest == nil || !switching.perRequest.roleSwitching {
		switching = nil
	}

	if switching != nil {
		applySelectedRole(principal, s.SelectedRole)
	}

	if err := ex.publishSession(&authenticate.Authentication{
		Principal:         principal,
		Time:              now,
		PasswordChangedAt: details.PasswordChangedAt,
	}, s); err != nil {
		return err
	}

	ex.loadedSession = loaded

	if switching != nil {
		src := &roleSource{chain: switching, resolver: r, session: s, current: s}

		// A cookie session's switch rotates it and re-sets the cookie on this
		// request's response, so the source keeps the exchange, and the run
		// that tells whether the response is still being written.
		if r.cookie != nil {
			src.ex = ex
			src.run = runOf(ex.Context(), switching)
		}

		ex.SetContext(withRoleSource(ex.Context(), src))
	}

	return ex.evaluatePerRequest(&r.phase, s, principal, details.PasswordChangedAt, now)
}

// applySelectedRole makes the grant named selected p's active role, when p
// holds one. p's grants are the ones in force at the request's time, so a
// selection naming a grant since removed, ended or not yet started changes
// nothing, and the primary grant, or none, stays active: a selection never
// adds a role and never promotes another grant in place of the one it names.
// The first grant of that name wins, as two grants of one role may coexist.
// An empty selection changes nothing.
func applySelectedRole(p *identity.Principal, selected string) {
	if p == nil || selected == "" {
		return
	}

	if g := grantNamed(p, selected); g != nil {
		p.ActiveRole = g
	}
}

// grantNamed returns p's first grant named name, or nil when p holds none.
func grantNamed(p *identity.Principal, name string) *identity.AssignedRole {
	for _, g := range p.Roles {
		if g != nil && g.Name == name {
			return g
		}
	}

	return nil
}

// classifyLoad answers a session load that failed with err, on the request
// whose own context is ctx, with one of three outcomes:
//
//   - a refusal, which matches ErrAuthenticationRequired: a session not found,
//     expired or unreadable, and a superseded identifier presented after its
//     window. Missing, expired and unreadable are the same answer, since
//     telling them apart would report whether a session ever existed. Reuse
//     is joined to the manager's session.ErrReused, so a consumer that rolls
//     its request transaction back on a refusal can tell this is the one
//     refusal it must commit, or it would roll the family's revocation back
//     too. The manager's error names no identifier. A superseded identifier
//     the manager says must be renewed (unused-successor recovery) is joined
//     to session.ErrRenewalRequired, so a client can tell it should renew
//     rather than sign in again; only a holder of a real superseded
//     identifier gets that answer, so it reports nothing a guess could learn.
//   - a hang-up, when ctx ended and err is that ending, ctx's error or the
//     cause it was cancelled with (hangup.ByCaller): it matches ctx's error,
//     and neither ErrAuthenticationRequired nor anything an outage is told
//     by. No verdict was reached, and nothing failed.
//   - a dependency failure otherwise, a store or cipher outage or the store's
//     own deadline: fixed library text, with err reachable through errors.Is
//     and errors.As, which the default status mapping answers with 500. A
//     consumer wanting another answer, 503 for example, matches it in their
//     error handler.
//
// Only a refusal matches ErrAuthenticationRequired, which is how a caller
// tells a refused presentation, to be charged to its source, from a request
// that reached no verdict.
//
// load is err as readLoadFailure read it, so err is walked once.
func classifyLoad(ctx context.Context, err error, load loadFailure) error {
	switch {
	case load.reused:
		return errors.Join(ErrAuthenticationRequired, err)
	case load.renewalRequired:
		// Told apart from an ended session, so a client knows to renew and
		// the cookie session keeps the cookie it renews with. The manager's
		// sentinel is joined rather than err, which is the consumer store's.
		return errors.Join(ErrAuthenticationRequired, session.ErrRenewalRequired)
	case load.notFound, load.expired, load.unreadable:
		return ErrAuthenticationRequired
	case hangup.ByCaller(ctx, err):
		return diag.Wrap(err, textSessionLoadEnded, ctx.Err())
	default:
		return diag.Wrap(err, textSessionNotResolved)
	}
}

// classifyReload answers a user reload that failed with err, on the request
// whose own context is ctx, as classifyLoad answers a session load: a user
// not found, however the loader wraps identity.ErrUserNotFound, is refused
// with ErrAuthenticationRequired; a hang-up matches ctx's error; anything
// else is a dependency failure behind fixed text, err reachable, 500 by
// default. The identity model requires a loader to report a miss as
// identity.ErrUserNotFound and any other failure as an error that is not, so
// an outage of the user store no longer logs every caller out.
//
// A user that loads but is not the session's, or not active, is refused by
// ownActiveUser, not here.
func classifyReload(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return ErrAuthenticationRequired
	case hangup.ByCaller(ctx, err):
		return diag.Wrap(err, textUserReloadEnded, ctx.Err())
	default:
		return diag.Wrap(err, textUserNotReloaded)
	}
}

// The fixed texts resolution answers a failure that is not a refusal with.
// A hang-up has texts of its own, so an error handler that logs by text does
// not report a client that left as an outage.
const (
	textSessionNotResolved = "httpsec: session could not be resolved"
	textUserNotReloaded    = "httpsec: user could not be reloaded"
	textSessionLoadEnded   = "httpsec: the request ended while its session loaded"
	textUserReloadEnded    = "httpsec: the request ended while its user reloaded"
)

// perRequestPhase is what the per-request policy phase and its challenge
// handling need: the chain's engine, enforcer set and enrolment lifetime, the
// session manager a challenge mark is stored through, and the clock the phase
// is judged at.
type perRequestPhase struct {
	engine   *policy.Engine
	sessions *session.Sessions

	// enrolmentLifetime is how long a session marked for an enrolment
	// challenge may live.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on the chain enforces; a
	// raised kind outside it refuses the request.
	enforced map[policy.ChallengeKind]bool

	now func() time.Time

	// roleSwitching records WithSwitchableRoles: the resolution core
	// applies a session's selected role, and Chain.SwitchActiveRole records
	// one. It is read from the chain's own phase only, never from a built-in's
	// copy.
	roleSwitching bool

	// dpop is the chain's DPoP verifier, which every issuing endpoint
	// verifies a sign-in's proof with, and nil while DPoP is off.
	dpop *dpopVerifier

	// certBinding is the chain's certificate binding, which every issuing
	// endpoint binds a sign-in to a client certificate through, and nil while
	// it is off.
	certBinding *certBinding

	// signalsPath is where the chain's signal stream answers, "" without one. It is here
	// because this is what an exchange holds of its chain (RecordsSessionActivity).
	signalsPath string

	// signals is the chain's signal stream endpoint, which an endpoint raises a
	// credential_changed through (Exchange.credentialChanged), and nil without one.
	signals *sessionSignals
}

// evaluatePerRequest runs the per-request phase for s and p on ex under ph,
// at now, and applies its outcome: a denial is returned, a challenge is
// marked where its gate reads it, and an allow returns nil. A denial is the
// policy's reason, which a throttle on the signal stream's own path carries a
// mark on (markPerRequestThrottle).
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
		err := policyDenyReason(d)
		emitPerRequestDenial(ctx, ex.answeringChain(), err, s)

		return ex.markPerRequestThrottle(err)
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

// emitLoadRefusal reports a presented session the manager refused to load:
// one past its lifetime as event.SessionUseAfterExpire, and one it does
// not hold as event.AuthnLoginFail. A store that failed, a session that
// could not be decrypted, and a load the request's own context ended report
// nothing, and a superseded session presented again is the reuse observer's
// to report.
func emitLoadRefusal(ctx context.Context, load loadFailure) {
	switch {
	case load.reused:
	case load.expired:
		emitEvent(ctx, event.Event{Name: event.SessionUseAfterExpire, Outcome: event.OutcomeFailure})
	case load.notFound:
		emitEvent(ctx, event.Event{Name: event.AuthnLoginFail, Outcome: event.OutcomeFailure})
	}
}

// errLoadUnreadable stands, behind textSessionNotResolved, for a session
// store's error that the bounded walk gave up on, so nothing of it reaches the
// checks the refusal meets on its way out.
var errLoadUnreadable = errors.New("httpsec: the session store's error could not be read")

// loadFailure is a failed session load's error, read once: which of the
// manager's verdicts it matches, as errors.Is would answer each, or the abort
// that stopped the walk, when every verdict reads false.
type loadFailure struct {
	unreadable, renewalRequired, reused, expired, notFound bool

	abort error
}

// readLoadFailure reads err, a session load's failure, through one bounded
// walk. The store behind the manager is the consumer's, so err may be
// cyclic, fanned out or carry a panicking method; such an err matches no
// verdict, and its abort is returned for the caller to report.
func readLoadFailure(err error) loadFailure {
	walk := walkRefusal(err)

	f := loadFailure{
		unreadable:      walk.is(session.ErrUnreadable),
		renewalRequired: walk.is(session.ErrRenewalRequired),
		reused:          walk.is(session.ErrReused),
		expired:         walk.is(session.ErrExpired),
		notFound:        walk.is(session.ErrNotFound),
	}

	if walk.abort != nil {
		return loadFailure{abort: walk.abort}
	}

	return f
}

// emitPerRequestDenial reports a per-request policy's denial of s: an idle
// session as event.SessionExpired, and any other refusal as
// event.AuthzFail.
//
// err is the consumer's policy's reason, so it is read through one bounded
// walk. A reason the walk gives up on reports nothing; the abort is reported
// as the quiet sites report one, through c, the answering chain.
func emitPerRequestDenial(ctx context.Context, c *Chain, err error, s *session.Session) {
	walk := walkRefusal(err)
	idle := walk.is(policy.ErrSessionIdle)

	switch {
	case walk.abort != nil:
		c.reportQuietly(ctx, err, walk.abort)
	case idle:
		emitEvent(ctx, sessionEvent(event.SessionExpired, event.OutcomeFailure, s))
	case refused(ctx, c, err):
		emitEvent(ctx, sessionEvent(event.AuthzFail, event.OutcomeFailure, s))
	}
}
