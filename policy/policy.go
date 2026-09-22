package policy

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

//go:generate mockgen -source=policy.go -package=policy_test -destination=mocks_test.go -typed

// ErrConfig is wrapped by every error a constructor in this package returns for
// a configuration it will not accept.
//
// A policy that cannot do what it was configured to do is a mistake in how the
// library was assembled, not a property of a request, so it is reported once at
// wiring time rather than on every evaluation. Matching this sentinel lets a
// consumer tell a contradictory configuration from a runtime failure without
// reading message text.
var ErrConfig = errors.New("policy: invalid configuration")

// ErrPolicyDenied is the reason an Engine substitutes when a policy denies
// without giving one.
//
// A caller that refuses a request by returning the decision's reason as its own
// error returns nil for a reasonless deny, and so completes the very request it
// was refusing. Every deny therefore leaves the engine carrying a reason, and
// this is the one used when the policy supplied none.
var ErrPolicyDenied = errors.New("policy: denied by policy")

// DefaultLogInterval is how long one written refusal record suppresses further
// records about the same thing, for the policies here that sample their logs.
//
// A minute is short enough that an attack shows up while it is happening, and
// long enough that the attacker cannot choose how much the defender's logging
// costs. Each policy samples under its own option, so replacing this window for
// one policy leaves every other policy — and every other part of the library
// that samples — on its own window; one window never governs two subsystems.
const DefaultLogInterval = time.Minute

// Phase is a point in a request's life at which policies are evaluated.
//
// A policy declares the phases it runs in and is asked in no other, so a rule
// written for the moment of login does not quietly start running on every
// request. The phases are fixed by this package: they name points the library
// itself reaches, and a consumer's policy chooses among them rather than
// inventing one.
type Phase int

const (
	// PreAuthentication is reached before credentials are checked, when the
	// submitted identifier is known and the caller is not. Rules that must
	// apply whether or not the secret is correct, such as account lockout,
	// belong here.
	PreAuthentication Phase = iota

	// PostAuthentication is reached once a login has succeeded and before the
	// session is established, which is where a login may still be turned into
	// a challenge.
	PostAuthentication

	// PerRequest is reached on every request carrying an established session.
	PerRequest

	// PostHandler is reached after the application's handler has run, for
	// rules that judge what the request did rather than what it asked for.
	PostHandler

	// StatelessAuthentication is reached for a request that authenticates
	// itself and establishes no session, such as an API key or HTTP basic
	// credentials. There is no later phase in which such a request could
	// answer a challenge, so a rule here decides outright.
	StatelessAuthentication
)

// String returns the constant's own name, so a log line reads
// "PreAuthentication" rather than "0". A value that names no phase prints its
// number rather than passing itself off as one of the five.
func (p Phase) String() string {
	switch p {
	case PreAuthentication:
		return "PreAuthentication"
	case PostAuthentication:
		return "PostAuthentication"
	case PerRequest:
		return "PerRequest"
	case PostHandler:
		return "PostHandler"
	case StatelessAuthentication:
		return "StatelessAuthentication"
	default:
		return unnamed("Phase", int(p))
	}
}

// phaseContextKey is the unexported key the phase is carried under, so nothing
// outside this package can collide with it or overwrite it by accident.
type phaseContextKey struct{}

// ContextWithPhase returns a copy of ctx carrying phase, for the policies that
// answer differently depending on where in a request's life they are asked.
//
// Input carries what is known about the request, not where the question came
// from, and Policy.Evaluate is handed only the two — so the phase travels in
// the context instead. Engine.EvaluatePhase sets it on every evaluation it
// makes, which is why a consumer who registers a phase-sensitive policy with an
// engine never calls this: naming the phase in that call is already saying it.
//
// It is exported for the caller who evaluates a policy directly, with no engine
// to say the phase for them:
//
//	ctx = policy.ContextWithPhase(ctx, policy.PerRequest)
//	d := p.Evaluate(ctx, in)
//
// It is safe to set in every phase, and policies that do not read it ignore it.
func ContextWithPhase(ctx context.Context, phase Phase) context.Context {
	return context.WithValue(ctx, phaseContextKey{}, phase)
}

// PhaseFromContext reports the phase ctx carries, and whether it carries one at
// all. A context that reached the policy through neither Engine.EvaluatePhase
// nor ContextWithPhase reports false, which a policy must treat as "not
// identified" rather than as the zero phase.
func PhaseFromContext(ctx context.Context) (Phase, bool) {
	phase, ok := ctx.Value(phaseContextKey{}).(Phase)

	return phase, ok
}

// Outcome is what a policy, or a whole phase, decided.
//
// The zero value is Allow, which is what a phase with nothing registered
// evaluates to. That is safe only because a policy builds its Decision
// deliberately: a policy that means to refuse says so, and one that has nothing
// to say allows.
type Outcome int

const (
	// Allow raises no objection. It does not grant anything: another policy in
	// the same phase may still deny or challenge.
	Allow Outcome = iota

	// Deny refuses the request outright and ends the phase.
	Deny

	// Challenge lets the request continue only once the caller has satisfied
	// the challenge named by the decision's ChallengeKind.
	Challenge
)

// String returns the constant's own name, so a log line reads "Deny" rather
// than "1". A value that names no outcome prints its number.
func (o Outcome) String() string {
	switch o {
	case Allow:
		return "Allow"
	case Deny:
		return "Deny"
	case Challenge:
		return "Challenge"
	default:
		return unnamed("Outcome", int(o))
	}
}

// ChallengeKind names what a challenging decision asks the caller for.
//
// It is meaningful only on a Decision whose Outcome is Challenge; every other
// decision carries ChallengeNone.
type ChallengeKind int

const (
	// ChallengeNone is the zero value, carried by decisions that challenge for
	// nothing: every Allow and every Deny.
	ChallengeNone ChallengeKind = iota

	// ChallengeMFA asks for a second factor.
	ChallengeMFA

	// ChallengePasswordChange asks for a new password before the caller goes
	// any further.
	ChallengePasswordChange
)

// String returns the constant's own name, so a log line reads "ChallengeMFA"
// rather than "1". A value that names no challenge prints its number.
func (c ChallengeKind) String() string {
	switch c {
	case ChallengeNone:
		return "ChallengeNone"
	case ChallengeMFA:
		return "ChallengeMFA"
	case ChallengePasswordChange:
		return "ChallengePasswordChange"
	default:
		return unnamed("ChallengeKind", int(c))
	}
}

// Decision is one policy's answer, and the reduction of a phase's answers.
//
// It is a value, not an error, because allowing and challenging are ordinary
// outcomes that no policy should have to express as the absence of a failure.
type Decision struct {
	// Outcome is the answer itself.
	Outcome Outcome

	// Reason says why a Deny refused, and is what a caller reports when it
	// turns the denial into an error of its own. A Deny returned by an Engine
	// always carries one: where the policy left it nil the engine substitutes
	// ErrPolicyDenied. It is nil on an Allow, and on a Challenge, which refuses
	// nothing.
	Reason error

	// Challenge names what a challenging decision asks for, and is
	// ChallengeNone otherwise.
	Challenge ChallengeKind
}

// Policy is one rule a deployment applies at named points in a request's life.
//
// It is the port a consumer implements to add a rule of their own; the policies
// that ship with this package implement it in exactly the same way, and hold no
// privileged position in an Engine.
//
// An implementation is asked concurrently, once per request, so it must be safe
// for concurrent use and must not mutate the Input it is given.
type Policy interface {
	// Name identifies this policy in logs and in configuration errors. It is
	// not an identity an Engine enforces: two policies may share a name, and
	// registering the same policy twice evaluates it twice.
	Name() string

	// Phases reports the phases this policy runs in. An Engine reads it when
	// the policy is registered, so a later change to the returned slice
	// changes nothing; returning no phases registers a policy that is never
	// asked anything.
	Phases() []Phase

	// Evaluate answers for one request. It reports its answer as a Decision
	// rather than an error, and must not return a Deny it cannot explain: a
	// reason that reaches the caller as an error is what makes the refusal
	// visible.
	Evaluate(ctx context.Context, in *Input) Decision
}

// Input is everything a policy is told about the request it is judging.
//
// It is one struct across all phases, so a field a phase cannot know is simply
// zero there: there is no session before one is established, and no first
// factor before a login has one. A policy reads what it needs and treats the
// rest as absent; the meaning of an absent field is the policy's own decision,
// stated in its documentation.
//
// A policy is handed a pointer for the sake of the fields that are already
// pointers, and must treat it as read-only. An Engine hands the same Input to
// every policy in the phase, so a policy that wrote to it would be deciding for
// the policies after it.
type Input struct {
	// User is the authenticated user this request belongs to, and is empty
	// before authentication has resolved one. It is the consumer's own opaque
	// reference, matched byte-for-byte.
	User identity.UserID

	// Username is the identifier the caller submitted, which exists before any
	// user does — it may name no user at all. A pre-authentication policy has
	// this and nothing else to key on.
	Username string

	// Principal is the resolved caller once authentication has produced one,
	// and nil before that.
	Principal *identity.Principal

	// Session is the established session on a request that carries one, and
	// nil in the phases that precede it and in stateless authentication.
	Session *session.Session

	// FirstFactor is the kind of factor the login used. The empty kind means
	// none was recorded, which factor treats as unknown and never as exempt.
	FirstFactor factor.Kind

	// PasswordChangedAt is when the user's password was last changed, and the
	// zero time when that is unknown or was never recorded.
	PasswordChangedAt time.Time

	// MFASatisfied reports that this request has already satisfied a second
	// factor. It is a claim about the request, so a policy that must not be
	// talked out of a requirement states that it does not honour it.
	MFASatisfied bool

	// Now is the instant the phase is being evaluated at, taken from the
	// caller's clock. Every policy in the phase judges against the same
	// instant, so two policies cannot disagree about whether a deadline has
	// passed.
	Now time.Time
}

// unnamed renders a value that names no constant of an enumeration, as
// "Phase(7)". Printing the number is deliberately not the same as printing one
// of the names: a value the package does not recognise must not read in a log
// as one it does.
func unnamed(kind string, value int) string {
	return kind + "(" + strconv.Itoa(value) + ")"
}
