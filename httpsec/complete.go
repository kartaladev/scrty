package httpsec

import (
	"context"
	"mime"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

//go:generate mockgen -destination=policy_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/policy Policy
//go:generate mockgen -destination=sessionstore_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/session Store
//go:generate mockgen -destination=tokengenerator_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/token Generator

// msgTokenNotIssued is the text an access token the consumer's generator could
// not issue is refused with, at login and at the second factor alike.
//
//nolint:gosec // G101: an error message naming what failed, not a credential
const msgTokenNotIssued = "httpsec: the access token could not be issued"

// policyDenyReason is the error a deny is refused with.
//
// policy.Engine already guarantees a deny carries a reason, substituting
// policy.ErrDenied where the policy left it nil, so this is a named
// reader rather than a fallback: every deny site refuses with the reason the
// engine reduced to, and none of them returns nil for a refusal.
func policyDenyReason(d policy.Decision) error { return d.Reason }

// credentialIssuer issues the credential a caller carries away for s, the
// session an endpoint has just established or rotated, held by p.
//
// The chain's bearer mode decides which one an endpoint is given: a signed
// token from the consumer's generator in the default mode (signedTokens), the
// session's own identifier in the session-reference mode
// (issueSessionReference). An endpoint never chooses for itself, so a
// credential it issues is always one the chain's bearer accepts.
type credentialIssuer func(ctx context.Context, s *session.Session, p *identity.Principal) (string, error)

// signedTokens issues a token from g naming s through its jti, which is how a
// later signed bearer request finds the session. The generator is the
// consumer's, so its error comes back behind fixed text, marked as an issuing
// failure (issuingFailure).
func signedTokens(g token.Generator) credentialIssuer {
	return func(ctx context.Context, s *session.Session, p *identity.Principal) (string, error) {
		tok, err := g.Generate(ctx, s.ID, p)
		if err != nil {
			return "", issuingFailure(err, msgTokenNotIssued)
		}

		return tok, nil
	}
}

// issueFailure marks a failure of the chain's credential issuer. It is a
// dependency failure on every path that issues, never a refusal: StatusForError
// answers it 500 before it consults its refusal table, so a consumer generator
// whose error wraps a sentinel that table answers 401
// (authenticate.ErrUnavailable, say) does not send the client back to log in
// during a key outage. Its text is fixed library text, and it unwraps to the
// failure it marks, so the cause stays reachable with errors.Is and errors.As.
//
// Build it with issuingFailure.
type issueFailure struct {
	text string
	err  error
}

// Error returns the fixed text, never the cause's.
func (f *issueFailure) Error() string { return f.text }

// Unwrap returns the failure it marks.
func (f *issueFailure) Unwrap() error { return f.err }

// issuingFailure is err behind text and kinds (diag.Wrap), marked as an
// issuing failure: nil when err is nil.
func issuingFailure(err error, text string, kinds ...error) error {
	if err == nil {
		return nil
	}

	return &issueFailure{text: text, err: diag.Wrap(err, text, kinds...)}
}

// issueSessionReference issues the session's own identifier, which is the
// credential the session-reference bearer accepts.
func issueSessionReference(_ context.Context, s *session.Session, _ *identity.Principal) (string, error) {
	return s.ID, nil
}

// credentialIssuer is the issuer an endpoint holding the token generator g
// issues through on this chain: the session reference when EnableSessionBearer
// is on, and g otherwise. Assembly has already refused a generator in the
// first case and a missing one in the second.
func (c *config) credentialIssuer(g token.Generator) credentialIssuer {
	if c.sessionBearer {
		return issueSessionReference
	}

	return signedTokens(g)
}

// loginTailDeps is what the login tail needs to end a login.
type loginTailDeps struct {
	engine   *policy.Engine
	sessions *session.Sessions
	tokens   token.Generator

	// issue issues the login's credential, as the chain's bearer mode
	// decides (config.credentialIssuer). Nil issues a signed token through
	// tokens, which is what a first factor not yet handed an issuer by
	// assembly uses.
	issue credentialIssuer

	// enrolmentLifetime is how long a session marked for an enrolment
	// challenge may live. The chain hands it to each first factor at assembly.
	enrolmentLifetime time.Duration

	// enforced holds the challenge kinds something on the chain enforces.
	enforced map[policy.ChallengeKind]bool

	// challengeMethods looks up the methods a raised challenge offers: the
	// chain's challengeMethods, handed to each first factor at assembly, so a
	// second-factor challenge carries the usable methods. Nil offers none,
	// which only a test seam leaves it.
	challengeMethods challengeMethodsFunc

	// decided is the post-authentication decision already made for this
	// login, nil when none was. A redemption decides in its policy check, and
	// hands that decision on here to the tail's first half, which it runs in
	// a later check of the same redemption (see redemptionLogin): evaluating
	// the policies a second time could reach a different verdict than the one
	// the checks passed on. Form login decides nothing in advance, so it
	// leaves this nil and the tail evaluates.
	decided *policy.Decision

	// cancelHeld cancels the user's held account recoveries, and is nil when
	// the chain holds none: account recovery is off, or configured with no
	// hold. The chain hands it to each first factor at assembly. The tail
	// calls it before anything else, ahead of the policy phase; a redemption
	// calls it once its credential is spent (see completeLogin).
	cancelHeld heldRecoveryCanceller
}

// heldRecoveryCanceller cancels every pending recovery of a user: the
// recovery core's CancelPending, which reports a store failure behind fixed
// text.
type heldRecoveryCanceller func(ctx context.Context, user identity.UserID) error

// postAuthenticationInput builds the policy input for a login that has just
// succeeded.
//
// Every field is a parameter rather than a struct literal each caller fills in,
// so an interceptor cannot quietly omit one: a missing passwordChangedAt
// disables a password-age gate on that interceptor's path alone, which is
// exactly the kind of hole nobody notices. first is a factor.Kind rather than a
// string so it cannot be transposed with username, and the two times are
// adjacent so every call site's argument order is pinned by a test that fires
// the challenge.
//
// username is the identifier the caller submitted, which is not always the one
// the principal resolved to: a policy keying on what was typed must see what
// was typed.
func postAuthenticationInput(
	p *identity.Principal,
	first factor.Kind,
	username string,
	passwordChangedAt, now time.Time,
) *policy.Input {
	in := &policy.Input{
		Username:          username,
		Principal:         p,
		FirstFactor:       first,
		PasswordChangedAt: passwordChangedAt,
		Now:               now,
	}
	if p != nil {
		in.User = p.ID
	}

	return in
}

// WithCaller publishes an authentication result and the caller it resolved on a
// context derived from ctx.
//
// A consumer writing their own first factor calls this rather than
// authenticate.WithAuthentication, which publishes only the event. The two
// answer different questions: an interceptor asks what authenticated this
// request, while a guard and the consumer's own handler ask who the caller is.
// Publishing only the event leaves every guard reading
// identity.PrincipalFromContext refusing a caller the chain has just
// authenticated, and that refusal is indistinguishable from a missing
// credential. They are published together here so no call site — the library's
// own or a consumer's — can publish one without the other.
//
// The built-in first factors publish through it, so an interceptor a consumer
// registers is left holding nothing a built-in has.
//
// A nil authentication, or one carrying no principal, publishes nothing under
// the principal key, so a reader that checks is never handed an absence
// dressed as a caller. It derives rather than replaces: everything already on
// ctx, including an upstream request identifier and the client's cancellation,
// is still there.
func WithCaller(ctx context.Context, a *authenticate.Authentication) context.Context {
	ctx = authenticate.WithAuthentication(ctx, a)
	if a == nil || a.Principal == nil {
		return ctx
	}

	return identity.WithPrincipal(ctx, a.Principal)
}

// challengeMarker records on a session that a challenge is owed, in the fields
// the gate enforcing it reads.
//
// sessions is the manager the session belongs to, whose clock an enrolment
// mark's deadlines are drawn from, and enrolmentLifetime is how long an
// enrolment-only session may live, handed over when the chain is built.
type challengeMarker struct {
	sessions          *session.Sessions
	enrolmentLifetime time.Duration
}

// refuseUnenforced refuses a challenge of a kind nothing on the chain
// enforces, with a configuration error, before anything is marked. A kind only
// a built-in gate raises is refused the same way, whatever is enabled; see
// refuseGateOnly.
//
// Chain assembly refuses a policy that declares such a kind, but it can only
// read the policies registered when the chain is built. A policy added to the
// engine afterwards escapes it, and a challenge it raises would otherwise be
// marked on the session and then served: the gate that should refuse the
// request is not there. Refusing the request instead makes the wiring mistake
// visible on the first request that reaches it, and satisfies nothing it
// should not.
func refuseUnenforced(enforced map[policy.ChallengeKind]bool, kind policy.ChallengeKind) error {
	if err := refuseGateOnly(kind, "a policy raised"); err != nil {
		return err
	}

	if enforced[kind] {
		return nil
	}

	if b, ok := builtInEnforcers[kind]; ok {
		return newConfigError("a policy raised %s, a challenge for %s, but nothing on this "+
			"chain enforces it: add %s, and register every policy before the chain is built "+
			"so assembly checks it", kind, b.what, b.option)
	}

	return newConfigError("a policy raised %s, but nothing on this chain enforces it: "+
		"register your gate for it and declare it with WithChallengeEnforcer, and register "+
		"every policy before the chain is built so assembly checks it", kind)
}

// mark records kind on s, in memory; the caller persists it.
//
// An enrolment challenge sets the enrolment-pending state and its marker and
// lowers the session's deadlines, in one change, so the session stored or
// saved next is already the short-lived, confined one.
//
// A kind this package does not know marks nothing: the session has no field
// for it. By the time mark runs, refuseUnenforced has already refused such a
// kind unless the consumer declared it with WithChallengeEnforcer. At login
// the caller then refuses with the challenge; per request the bearer records
// the kind on the exchange (Exchange.RaisedChallenge) and continues, and the
// consumer's declared gate enforces it.
func (m challengeMarker) mark(s *session.Session, kind policy.ChallengeKind) {
	switch kind {
	case policy.ChallengeMFA:
		s.MFA = session.MFAPending
	case policy.ChallengePasswordChange:
		s.PasswordChangePending = true
	case policy.ChallengeMFAEnrolment:
		m.sessions.MarkEnrolmentPending(s, m.enrolmentLifetime)
	case policy.ChallengeNone:
	}
}

// completeLogin is the tail every first factor shares: policy, session, token.
//
// It exists so a redemption flow added by another capability cannot end a login
// differently from form login — the same phase, the same marking and the same
// ordering guarantee, written once and reused rather than restated.
//
// It is the composition of two halves, which a redemption runs apart so that
// its single-use credential is spent between them: prepareLogin decides the
// phase, builds the session (session.Sessions.Prepare), marks any challenge on
// it and issues the credential for it, storing nothing; preparedLogin.commit
// then stores the session, mark and all, in the one write that creates it
// (session.Prepared.Commit), and only once that write has succeeded publishes
// the authentication and hands the credential out. So a credential is never
// handed out for a session that was not stored, a token never exists for a
// session whose challenge mark did not persist, and a credential that cannot
// be issued stores nothing and leaves unspent anything a redemption would
// have spent. A failure to issue, or of the creating write after issuing, is
// a dependency failure, never a refusal: the credential issued for a session
// that was never stored names nothing and is discarded with the error.
//
// It returns the token it issued alongside the challenge error, because a
// consumer prompting for a second factor needs the credential the prompt will
// be answered with.
//
// A dependency's failure comes back behind fixed text, never the dependency's
// own, because that text may quote values the library never saw: the session
// manager already words its store's failures so, and a token generator's error
// is wrapped here. The dependency's error still matches through errors.Is and
// errors.As, so the status it maps to is unchanged. A policy's reason is the
// policy's own, and is returned as itself.
//
// When the chain may hold account recoveries, the user's held recoveries are
// cancelled first, as soon as the first factor has authenticated: before the
// policy phase and before the session is built. A login the policy then
// denies or challenges has still cancelled them, since completing the first
// factor is the evidence the real user still has access. A failure to cancel
// refuses the login (see loginTailDeps.cancelHeld). A redemption, which
// decides the phase inside its redeemer's checks, cancels them once its
// credential is spent instead, as it did before issuing moved into the checks:
// a check must have no side effects.
//
// A caller that has already decided the phase for this login passes the
// decision in deps.decided, and the tail acts on it rather than evaluating
// again (see loginTailDeps.decided).
//
// With no policy engine wired the phase allows, which is the documented default
// of WithPolicyEngine: a consumer who registers no policies rests on
// authentication alone rather than on a phase that refuses everything.
//
// opts are the caller's own attributes for the session, applied in the write
// that creates it and before the first factor the tail records from in. Form
// login passes session.WithAbsoluteLifetime when WithLoginLifetime chooses a
// positive lifetime and none otherwise; magic-link, OIDC and passkey login
// pass none. An OIDC redemption records its provider session on the prepared
// session before it is committed (session.WithExternalSession), not through
// opts.
//
// The first factor recorded is always in.FirstFactor, the tail's own: it is
// applied last, so a caller's own session.WithFirstFactor in opts cannot
// replace the factor the policy phase was just evaluated on.
//
// When in.SecondFactorAtLogin holds — the library's proof, which only its
// passkey login mints — the phase sees it and the session is created with
// session.WithSecondFactorAtLogin, satisfied in the creating write. A
// challenge the phase still raises is marked on that session as for any
// login. A zero proof, which every other first factor passes, changes
// nothing.
//
// When in.FederatedAssurance asserts something — evidence only the library's
// OIDC redemption mints, from the record the callback wrote — the phase sees
// it, and its amr and acr are recorded on the session with
// session.WithFederatedAssurance in the creating write, after the caller's
// options so none of them can replace it. It is evidence, not a verdict: the
// second factor is not marked satisfied and the met-at-first-factor marker is
// not set, so every later request matches the stored values again. Zero
// evidence, which every other first factor passes, records nothing.
func completeLogin(ex *Exchange, deps loginTailDeps, in *policy.Input, opts ...session.CreateOption) (string, error) {
	// A user who completes a first factor can still get into their account,
	// so a recovery held for it is cancelled here, before the policy phase:
	// a login the policy denies still showed the user holds their first
	// factor. A cancellation that cannot be recorded refuses the login, which
	// fails closed: letting the recovery stand would let it finish later
	// against a user who showed they had not lost their account.
	if err := deps.cancelHeldRecoveries(ex.Context(), in.User); err != nil {
		return "", err
	}

	login, err := prepareLogin(ex.Context(), deps, in, opts...)
	if err != nil {
		return "", err
	}

	return login.commit(ex)
}

// cancelHeldRecoveries cancels user's held account recoveries, and does
// nothing when the chain holds none (see loginTailDeps.cancelHeld).
func (deps loginTailDeps) cancelHeldRecoveries(ctx context.Context, user identity.UserID) error {
	if deps.cancelHeld == nil {
		return nil
	}

	return deps.cancelHeld(ctx, user)
}

// preparedLogin is a login the tail has decided, built a session for and
// issued that session's credential, and not yet stored: the first half of
// completeLogin, which prepareLogin returns and commit finishes.
//
// Until commit stores it, the session loads nothing, so the credential names
// nothing and authenticates nothing either. A caller that does not commit, a
// redemption that lost its consume to a racing one or was refused after its
// checks, simply drops it: nothing was written, and nothing is undone.
type preparedLogin struct {
	// in is the input the login was decided and issued on.
	in *policy.Input

	// decision is what the phase decided for it: allow, or a challenge of an
	// enforced kind.
	decision policy.Decision

	// methods are the methods a raised challenge offers.
	methods []MFAMethod

	prepared *session.Prepared
	token    string
}

// prepareLogin is the first half of completeLogin: it decides the
// post-authentication phase for in (or acts on deps.decided), refuses a deny,
// an unenforced challenge and a failed methods lookup, builds the session with
// opts and the tail's own attributes, marks any challenge on it, and issues
// its credential. It stores nothing and spends nothing, so a redemption runs
// it inside its redeemer's refusal checks, before the consume.
//
// Its errors are completeLogin's for the same steps: a policy's reason as
// itself, a configuration error for an unenforced challenge, and a dependency
// failure behind fixed text for a methods lookup, the session's build or the
// credential's issue.
func prepareLogin(
	ctx context.Context,
	deps loginTailDeps,
	in *policy.Input,
	opts ...session.CreateOption,
) (*preparedLogin, error) {
	d := policy.Decision{Outcome: policy.Allow}

	switch {
	case deps.decided != nil:
		d = *deps.decided
	case deps.engine != nil:
		d = deps.engine.EvaluatePhase(ctx, policy.PostAuthentication, in)
	}

	if d.Outcome == policy.Deny {
		return nil, policyDenyReason(d)
	}

	// Refused before the session is built, so an unenforced challenge leaves
	// neither a marked session nor a token behind. The methods the challenge
	// offers are looked up here too, for the same reason: a lookup that fails
	// refuses the login before anything is issued, spent or stored.
	var methods []MFAMethod

	if d.Outcome == policy.Challenge {
		if err := refuseUnenforced(deps.enforced, d.Challenge); err != nil {
			return nil, err
		}

		if deps.challengeMethods != nil {
			var err error

			methods, err = deps.challengeMethods(ctx, d.Challenge, in.User, in.FirstFactor)
			if err != nil {
				return nil, err
			}
		}
	}

	// The caller's own attributes first, then the first factor, which is
	// applied last so it always wins, even if opts happens to carry its own
	// session.WithFirstFactor: the factor the policy phase was just evaluated
	// on is the one that gets recorded. A federated login's provider session
	// is not among these: an OIDC redemption learns it only from the
	// redeemer's result, so it sets it on the prepared session before
	// commit, ahead of the one write that creates the session.
	//
	// A login carrying the library's proof that its second factor was met at
	// the first is created satisfied, in that same write, so the session never
	// exists unsatisfied. It is applied after the caller's options, so none of
	// them can undo it, and before any challenge mark: a challenge the phase
	// still raises, such as a password change, is marked on the satisfied
	// session and refused as for any login.
	create := make([]session.CreateOption, 0, len(opts)+4)
	create = append(create, opts...)
	// A sign-in a cookie may carry gets the CSRF token its unsafe requests
	// must present, in the same creating write.
	if signInsCarryCSRFToken(ctx) {
		create = append(create, session.WithCSRFToken())
	}
	if ev := in.FederatedAssurance; ev.Asserted() {
		create = append(create, session.WithFederatedAssurance(ev.AMR(), ev.ACR()))
	}
	if in.SecondFactorAtLogin.Holds() {
		create = append(create, session.WithSecondFactorAtLogin())
	}
	create = append(create, session.WithFirstFactor(in.FirstFactor))

	p, err := deps.sessions.Prepare(in.User, create...)
	if err != nil {
		return nil, err
	}

	s := p.Session()

	if d.Outcome == policy.Challenge {
		// Marked before the token exists and before the session is stored,
		// so the one write that creates it carries the mark: a session stored
		// unmarked, or a token issued for one, would answer requests as though
		// the challenge had been met.
		challengeMarker{sessions: deps.sessions, enrolmentLifetime: deps.enrolmentLifetime}.
			mark(s, d.Challenge)
	}

	// Issued against the session just built: a signed token names it through
	// its jti, and a session reference is its identifier. It loads nothing
	// until commit stores it.
	issue := deps.issue
	if issue == nil {
		issue = signedTokens(deps.tokens)
	}

	tok, err := issue(ctx, s, in.Principal)
	if err != nil {
		return nil, err
	}

	return &preparedLogin{in: in, decision: d, methods: methods, prepared: p, token: tok}, nil
}

// session is the login's session as built and marked, not yet stored. A
// caller sets on it only what it can know no earlier than the spend, before
// commit; never the first factor, the assurance or the challenge state the
// tail recorded.
func (l *preparedLogin) session() *session.Session { return l.prepared.Session() }

// commit is the second half of completeLogin: the one creating write, then
// the authentication published and the credential handed out, with a
// challenge error when a challenge is pending.
//
// A failure of the write discards the credential: it names a session that was
// never stored, so it authenticates nothing, and is never handed out. It is a
// dependency failure, as the session manager words it. A redemption that
// reaches commit has already spent its single-use credential, which that
// failure does not give back.
func (l *preparedLogin) commit(ex *Exchange) (string, error) {
	ctx := ex.Context()

	s, err := l.prepared.Commit(ctx)
	if err != nil {
		return "", err
	}

	// Published on the challenge path too, so a consumer rendering the prompt
	// still reads who is being challenged.
	ex.Session = s
	ex.SetContext(withSession(WithCaller(ctx, ex.Authentication), s))

	if l.decision.Outcome == policy.Challenge {
		return l.token, &ChallengeError{Kind: l.decision.Challenge, Session: s, Token: l.token, Methods: l.methods}
	}

	return l.token, nil
}

// declaresJSON reports whether a content type names JSON, ignoring parameters
// such as a charset and accepting the +json structured suffix.
func declaresJSON(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}

	return media == "application/json" || strings.HasSuffix(media, "+json")
}
