package policy

import (
	"context"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/internal/nilcheck"
)

// Engine evaluates the policies registered for one phase of a request and
// reduces their answers to a single Decision.
//
// It holds no rules of its own. What it contributes is the reduction: a deny
// outranks a challenge, a challenge outranks an allow, and a policy is asked
// only in the phases it declared. That is what lets independently written
// policies be composed without one of them being able to overrule another's
// refusal.
//
// An Engine is safe for concurrent evaluation once registration has finished.
// Registration itself is not concurrent — see Add.
type Engine struct {
	// byPhase holds, per phase, the policies that declared it, in registration
	// order. Indexing at registration keeps the request path from asking every
	// policy which phases it runs in, and fixes the order a phase is evaluated
	// in at the moment the consumer wrote it.
	byPhase map[Phase][]Policy

	// asked holds every policy registered for at least one phase, once, in
	// registration order. byPhase is a map, so it cannot say which policy came
	// first across phases; this can, and a policy asked in no phase is left
	// out because it can raise nothing.
	asked []Policy
}

// NewEngine returns an Engine holding policies, registered in the order given.
//
// There is no default set. Which rules a deployment applies is the consumer's
// decision, and an engine that registered rules of its own choosing would
// enforce something nobody asked for — or, worse, would look as if it were
// enforcing everything while the consumer's own list went unregistered.
//
// An engine with no policies is valid, and allows every phase. Unlike a manager
// with no delegates, it is not a mistake that shows up later as a refusal: it
// is a deployment that has not yet written a rule, and Add exists to fill it.
//
// An absent policy is a configuration error wrapping ErrConfig, in the position
// it was given in — see Add for why it is refused rather than skipped.
func NewEngine(policies ...Policy) (*Engine, error) {
	e := &Engine{byPhase: make(map[Phase][]Policy)}

	for i, p := range policies {
		if err := e.Add(p); err != nil {
			return nil, fmt.Errorf("argument %d: %w", i, err)
		}
	}

	return e, nil
}

// Add registers one more policy, after the ones already held.
//
// It is for use while the application is being wired, before it serves: it
// writes the engine's registration index, which every evaluation reads, and is
// not safe to call concurrently with EvaluatePhase. A consumer that must change
// the rules of a running application builds a new Engine and swaps it in.
//
// Register every policy before handing the engine to a component that checks
// its wiring at construction, such as an HTTP security chain. Such a check can
// only see the policies registered by then, so a challenge a later policy can
// raise, with nothing to enforce it, is found only when a request raises it,
// rather than before the application serves.
//
// An absent policy — nil, or a non-nil interface holding a nil pointer, which
// is what an unchecked constructor result hands over — is a configuration error
// wrapping ErrConfig. It is refused rather than skipped because skipping it
// would leave the engine making fewer checks than the consumer wrote, with
// nothing at all to show for the rule that went missing; and keeping it would
// panic at the first request, where a line of wiring reads as a runtime fault.
func (e *Engine) Add(p Policy) error {
	if nilcheck.IsNil(p) {
		return fmt.Errorf(
			"%w: a policy is absent, and registering it would leave the engine "+
				"making fewer checks than were written", ErrConfig)
	}

	phases := p.Phases()
	for _, phase := range phases {
		e.byPhase[phase] = append(e.byPhase[phase], p)
	}

	if len(phases) > 0 {
		e.asked = append(e.asked, p)
	}

	return nil
}

// CanChallenge reports whether any registered policy can raise this kind of
// challenge.
//
// It is how a component that enforces challenges checks its own wiring before
// it serves: a policy able to raise a challenge, with nothing registered to
// enforce it, marks sessions and has them served anyway. That failure is
// silent, so it is worth refusing at construction, and this is the question
// such a refusal rests on.
//
// The answer is drawn from the optional Challenger interface, and a policy
// that does not implement it is taken to raise nothing — see Challenger for
// why silence is read that way, and for what a consumer whose own policy
// challenges has to do about it.
//
// A policy registered for no phase is never asked anything, so it can raise
// nothing whatever it declares.
//
// It reads the registration index and is meant for wiring time, alongside Add,
// rather than for the request path.
func (e *Engine) CanChallenge(kind ChallengeKind) bool {
	return slices.Contains(e.DeclaredChallenges(), kind)
}

// DeclaredChallenges reports every challenge kind a registered policy can
// raise, each once, in the order it was first declared across the policies in
// registration order.
//
// It answers what CanChallenge answers, for every kind at once, so a component
// that enforces challenges can check that each one has an enforcer rather than
// asking about the kinds it happens to know. The same rules apply: a policy
// that does not implement Challenger declares nothing, a policy registered for
// no phase raises nothing, and ChallengeNone is never a challenge.
//
// It returns a fresh slice, and is meant for wiring time.
func (e *Engine) DeclaredChallenges() []ChallengeKind {
	var kinds []ChallengeKind

	for _, p := range e.asked {
		c, ok := p.(Challenger)
		if !ok {
			continue
		}

		for _, kind := range c.Challenges() {
			if kind != ChallengeNone && !slices.Contains(kinds, kind) {
				kinds = append(kinds, kind)
			}
		}
	}

	return kinds
}

// EvaluatePhase asks the policies that declared phase, in the order they were
// registered, and reduces their answers to one Decision.
//
// The reduction is the whole point of the engine:
//   - the first deny ends the phase and is returned, so nothing registered
//     after it can run, log or charge for a request that is already refused;
//   - a challenge is held while the remaining policies run, so a deny that
//     comes later still wins over it;
//   - with no deny, the first challenge in registration order is returned, and
//     otherwise the phase allows.
//
// A decision carrying an outcome this package does not define denies, with
// ErrPolicyDenied as the reason: an answer the engine cannot interpret is not
// an answer it may pass over, since passing it over would allow.
//
// A phase no policy declared allows. That is the same answer as a phase whose
// policies all allowed, deliberately: a phase is a point the library reaches,
// not a check the library requires something to be registered for.
//
// The Input is passed to every policy unchanged, so each of them judges the
// same request against the same instant. The context is not: the phase being
// evaluated is added to it, which is how a policy whose answer depends on the
// phase learns which one it is in. A consumer does not set it themselves, and
// this call is the only thing that publishes it: naming the phase here is
// already saying it. A consumer whose call path cannot reach the context
// replaces how a phase-sensitive policy learns the phase through that policy's
// own option — see WithMFARequirementPhaseSource.
func (e *Engine) EvaluatePhase(ctx context.Context, phase Phase, in *Input) Decision {
	// A policy that answers differently per phase has no other way to tell one
	// from another: Input's fields are fixed and carry no phase, and Evaluate is
	// handed nothing else. Such a policy must fail closed when it cannot
	// identify the phase, so an engine that passed ctx through unchanged would
	// have it refuse every request — including the ones the phase says to
	// challenge or allow. Saying the phase here says it once, for every policy
	// registered and every consumer, rather than asking each caller to repeat in
	// the context what it has just named in this argument.
	ctx = contextWithPhase(ctx, phase)

	held := Decision{}

	for _, p := range e.byPhase[phase] {
		d := p.Evaluate(ctx, in)

		switch d.Outcome {
		case Deny:
			// A deny must always carry a reason. A caller that refuses a
			// request by reporting the reason as its own error returns nil for
			// a reasonless deny — and nil is success, so the request the policy
			// meant to refuse is served. Substituting here closes that for
			// every policy at once, rather than asking each policy that will
			// ever be written to remember. A reason the policy did give is left
			// exactly as it was.
			if d.Reason == nil {
				d.Reason = ErrPolicyDenied
			}

			return d
		case Challenge:
			// Held, not returned: a policy further down the phase may still
			// deny, and a challenge that short-circuited would let the engine
			// ask a caller to satisfy a challenge for access it was never
			// going to be given.
			if held.Outcome != Challenge {
				held = d
			}
		case Allow:
			// An allow raises no objection and cannot clear another policy's
			// held challenge.
		default:
			// An outcome this engine does not recognise is not a decision it
			// can act on. Passing it over lets a policy that meant to refuse
			// be ignored — and the zero Decision this loop would otherwise
			// return is an Allow — so it denies. This is the case a later
			// Outcome constant creates if it is added without updating this
			// switch, which the compiler does not catch.
			return Decision{Outcome: Deny, Reason: ErrPolicyDenied}
		}
	}

	return held
}
