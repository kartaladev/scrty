package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// ErrMFARequired is the reason the requirement policy refuses a request from a
// user who must use a second factor but cannot be asked for one here: a
// stateless request that will never reach a challenge, a policy wired with no
// method to challenge against, or an evaluation in a phase the policy does not
// declare.
var ErrMFARequired = errors.New("policy: this request must present a second factor")

// ErrMFAEnrollmentRequired is the reason the requirement policy refuses a user
// who must use a second factor and has no usable enrolment to be challenged on.
//
// "No usable enrolment" covers a user who has not enrolled and a user whose
// only enrolment arrives on the channel the first factor already came from,
// which is one factor wearing two names.
var ErrMFAEnrollmentRequired = errors.New("policy: this user must enrol a second factor")

// ErrMFARequirementLookupMissing is the configuration error for a requirement
// policy built with no lookup and no instruction to require a second factor of
// everyone. Such a policy has no way to answer the only question it exists to
// ask.
var ErrMFARequirementLookupMissing = errors.New(
	"policy: the mfa requirement policy has neither a requirement lookup nor a requirement for all users")

// ErrMFARequirementUnsatisfiable is the configuration error for a requirement
// policy that requires a second factor of every user and was given no method
// they could satisfy it with. It would refuse every non-exempt request it ever
// saw.
var ErrMFARequirementUnsatisfiable = errors.New(
	"policy: the mfa requirement policy requires a second factor of everyone and has no method to satisfy it")

// MFARequirementOption configures the policy NewMFARequirementPolicy returns.
// Every default that constructor applies has an option that replaces it.
//
// It is an interface rather than a function type so that WithMFAExemption,
// which governs a rule both MFA policies hold, can be given to either
// constructor under one name. A consumer implements nothing.
type MFARequirementOption interface {
	applyMFARequirement(*mfaRequirementPolicy)
}

// mfaRequirementOption adapts a plain function into an MFARequirementOption.
type mfaRequirementOption func(*mfaRequirementPolicy)

func (f mfaRequirementOption) applyMFARequirement(p *mfaRequirementPolicy) { f(p) }

// WithMFARequiredForAll requires a second factor of every non-exempt user,
// without consulting the requirement lookup at all.
//
// The default is to ask the lookup per user. With this set the lookup is never
// called, so it may be omitted entirely — but a method must be configured, or
// the policy would demand of everyone something nobody could present.
//
// # Enrol users before enabling it
//
// By default this option locks out every user who has not enrolled. A user with
// no usable enrolment is refused at every non-exempt login, and a refusal is all
// they get: an enrolment offered to whoever just presented a first factor is a
// second factor an attacker can enrol for themselves, so it is not offered
// unless the consumer chooses to.
//
// So either enrol users first — out of band, or through a session established
// by a login this policy exempts — and enable this afterwards, or turn on the
// enrolment path with WithMFAEnrolmentPath, which sends such a user to a
// confined enrolment session instead, and accept what that path documents it
// gives a first factor. WithEnrolmentPathUntil closes the path again once the
// rollout is done.
func WithMFARequiredForAll() MFARequirementOption {
	return mfaRequirementOption(func(p *mfaRequirementPolicy) { p.requiredForAll = true })
}

// WithMFARequirementLogger replaces where the policy writes its refusal and
// lookup-failure records. The default is slog.Default.
//
// Every record names the user by the opaque reference in Input.User, on
// purpose. A lookup-failure record carries the fixed reason
// "requirement-lookup" and the error's Go type, never its text; a consumer who
// wants the lookup's full error logs it inside their own
// identity.MFARequirementLookup.
//
// A nil logger is ignored rather than refused, so configuring logging stays
// optional.
func WithMFARequirementLogger(l *slog.Logger) MFARequirementOption {
	return mfaRequirementOption(func(p *mfaRequirementPolicy) {
		if l != nil {
			p.logger = l
		}
	})
}

// WithMFARequirementLogInterval replaces how long one written record suppresses
// further records about the same thing. The default is DefaultLogInterval, one
// minute.
//
// An interval of zero or less writes every record. It governs this policy
// alone: the second-factor challenge policy keeps its own window under
// WithMFAPolicyLogInterval, so an outage of the requirement lookup cannot
// silence the same-channel warnings.
func WithMFARequirementLogInterval(d time.Duration) MFARequirementOption {
	return mfaRequirementOption(func(p *mfaRequirementPolicy) { p.logInterval = d })
}

// WithMFARequirementClock replaces the time source the policy samples its
// records by. The default is clock.System(), and a nil clock, typed nil
// included, is a configuration error.
//
// It is not the instant a decision is judged against — that is Input.Now, taken
// from the caller's clock so that every policy in a phase agrees.
func WithMFARequirementClock(clk clock.Clock) MFARequirementOption {
	return mfaRequirementOption(func(p *mfaRequirementPolicy) { p.clock = clk })
}

// WithMFARequirementPhaseSource replaces how the policy learns which phase it
// is being evaluated in. The default reads the phase from the context, where
// Engine.EvaluatePhase puts it.
//
// The policy answers differently per phase and Input carries no phase, so it
// has to be told. A consumer whose call path cannot reach the context — or who
// would rather derive the phase from the request itself — supplies a rule here
// instead. The rule reports the phase and whether it could identify one at all;
// reporting false refuses the evaluation with ErrMFARequired, which is the safe
// answer when a login and a stateless request cannot be told apart.
//
// A nil rule is a configuration error: the policy would refuse every request.
func WithMFARequirementPhaseSource(
	phaseOf func(ctx context.Context, in *Input) (Phase, bool),
) MFARequirementOption {
	return mfaRequirementOption(func(p *mfaRequirementPolicy) { p.phaseOf = phaseOf })
}

// mfaRequirementPolicy enforces a per-user or deployment-wide requirement to
// use a second factor. Every field is fixed at construction, so it is safe for
// concurrent use.
type mfaRequirementPolicy struct {
	required       identity.MFARequirementLookup
	methods        []MFAMethodLookup
	requiredForAll bool
	exempt         func(factor.Kind) bool
	phaseOf        func(context.Context, *Input) (Phase, bool)
	logger         *slog.Logger
	clock          clock.Clock
	logInterval    time.Duration
	sampler        *logsample.Sampler

	// enrolment is the enrolment path, or nil while it is off.
	enrolment *enrolmentPath
}

// NewMFARequirementPolicy returns the MFA requirement policy, which enforces
// that a user who must use a second factor is challenged for one or refused,
// and never simply let through.
//
// methods is the set of second-factor methods the deployment offers. It must be
// the same set as the chain's httpsec.EnableMFA was given, and as
// NewMFAPolicy was built with — mfa.LookupsFor builds this list from those
// methods. It may be empty, which means no method is configured: a required
// user is then refused with ErrMFARequired.
//
// # Register it beside NewMFAPolicy
//
// In the post-authentication phase this policy allows a required user with a
// usable enrolment, because the login challenge is the challenge policy's job.
// A deployment that registers this one alone therefore enforces nothing at
// login: the requirement takes hold only on the next request. Register both,
// over the same methods.
//
// # Which phase it is being asked in
//
// The policy answers differently per phase — a stateless request is refused
// where a per-request evaluation is challenged — and Input does not carry the
// phase. It reads the phase from the context, which Engine.EvaluatePhase puts
// there for every policy it asks, so a consumer evaluating through an engine
// has nothing to wire. A caller that evaluates this policy directly, with no
// engine to say the phase for it, supplies a rule of their own through
// WithMFARequirementPhaseSource.
//
// An evaluation whose phase it cannot identify is refused with ErrMFARequired.
// The two phases it could not tell apart, a login and a stateless request, want
// opposite answers, and guessing either way lets a required user through or
// refuses every login.
//
// # Evaluation order
//
//  1. an exempt first factor: allow, before anything is looked up;
//  2. is a second factor required? With WithMFARequiredForAll, yes, without
//     consulting the lookup. A lookup that fails denies, with a reason of fixed
//     text that wraps the lookup's error without repeating it;
//  3. not required: allow;
//  4. the stateless-authentication phase, or no method configured: deny
//     ErrMFARequired — there is no later point at which such a request could
//     answer a challenge;
//  5. the per-request phase with the second factor already satisfied: allow.
//     The post-authentication phase with a holding Input.SecondFactorAtLogin,
//     the library's proof that the second factor was met at the first: allow
//     too, before the usability check, so the enrolment challenge never fires
//     for such a login. No exemption rule is consulted for it;
//  6. no usable enrolment, as UsableMFAMethods decides — enrolled on no
//     method, or only on methods on the first factor's own channel: with the
//     enrolment path on (WithMFAEnrolmentPath) and admitting this login,
//     challenge ChallengeMFAEnrolment; otherwise deny
//     ErrMFAEnrollmentRequired. A failed enrolment lookup on any method denies
//     either way, even when another method is usable, with fixed text
//     wrapping its error;
//  7. the per-request phase: challenge for MFA;
//  8. the post-authentication phase: allow, leaving the login challenge to the
//     challenge policy;
//  9. any other phase: deny ErrMFARequired.
//
// In the post-authentication phase Input.MFASatisfied is not honoured. It is a
// claim the login makes about itself, and a policy that can be talked out of a
// requirement does not enforce one.
// Only the library's proof in Input.SecondFactorAtLogin is. A consumer who
// wants a separate second factor even after a user-verified passkey login
// sets passkey.WithoutSecondFactorAtLogin on the passkey login, so no proof is
// minted and this policy never sees one.
//
// Construction fails, wrapping ErrConfig, with ErrMFARequirementLookupMissing
// when there is no lookup and no requirement for all — the policy could answer
// nothing — and with ErrMFARequirementUnsatisfiable when a second factor is
// required of everyone and the set of methods is empty. It also fails,
// wrapping ErrConfig, when the set holds an absent method or two methods of the
// same Name, and when the enrolment path's allowlist is empty or names a kind
// that can never enter it (WithEnrolmentFirstFactors). An absent argument here
// means nil or a non-nil interface holding a nil pointer. The policy keeps its
// own copy of the set.
//
// Defaults: the per-user lookup (WithMFARequiredForAll replaces it),
// factor.Kind.MFAExempt (WithMFAExemption), the phase from the context
// (WithMFARequirementPhaseSource), slog.Default (WithMFARequirementLogger),
// clock.System() (WithMFARequirementClock), DefaultLogInterval for its sampled
// records (WithMFARequirementLogInterval) and no enrolment path
// (WithMFAEnrolmentPath).
func NewMFARequirementPolicy(
	required identity.MFARequirementLookup,
	methods []MFAMethodLookup,
	opts ...MFARequirementOption,
) (Policy, error) {
	p := &mfaRequirementPolicy{
		required:    required,
		exempt:      factor.Kind.MFAExempt,
		phaseOf:     phaseOfContext,
		logger:      slog.Default(),
		clock:       clock.System(),
		logInterval: DefaultLogInterval,
	}
	for _, opt := range opts {
		if opt != nil {
			opt.applyMFARequirement(p)
		}
	}

	if !p.requiredForAll && nilcheck.IsNil(p.required) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, ErrMFARequirementLookupMissing)
	}
	if p.requiredForAll && len(methods) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrConfig, ErrMFARequirementUnsatisfiable)
	}

	checked, err := checkMFAMethods(methods, "mfa requirement policy", false)
	if err != nil {
		return nil, err
	}
	p.methods = checked

	if p.exempt == nil {
		return nil, fmt.Errorf(
			"%w: the mfa requirement policy has no exemption rule, so it could not judge a "+
				"single request", ErrConfig)
	}
	if p.phaseOf == nil {
		return nil, fmt.Errorf(
			"%w: the mfa requirement policy has no source for the phase, so it would refuse "+
				"every request it was asked about", ErrConfig)
	}
	if nilcheck.IsNil(p.clock) {
		return nil, fmt.Errorf(
			"%w: the mfa requirement policy has no clock, so its records could not be "+
				"sampled", ErrConfig)
	}

	if p.enrolment != nil {
		if err := p.enrolment.validate(); err != nil {
			return nil, err
		}
	}

	p.sampler = logsample.New(p.logInterval, logsample.WithReporter(p.reportSuppressed))

	return p, nil
}

// Name identifies the policy in logs and in an engine's configuration errors.
func (p *mfaRequirementPolicy) Name() string { return "mfa-requirement" }

// Phases reports the three phases the requirement is enforced in.
func (p *mfaRequirementPolicy) Phases() []Phase {
	return []Phase{PostAuthentication, PerRequest, StatelessAuthentication}
}

// Challenges reports that this policy can ask for a second factor. It denies
// more often than it challenges, but a required user who has a usable
// enrolment is challenged rather than refused, and that challenge needs
// enforcing like any other.
//
// With the enrolment path on (WithMFAEnrolmentPath) it also reports
// ChallengeMFAEnrolment, so that a chain with no enrolment interceptor refuses
// to assemble rather than leaving the challenge unenforced. With the path off
// it never raises that kind, and does not declare it.
//
// A fresh slice every call, for the reason Challenger states.
func (p *mfaRequirementPolicy) Challenges() []ChallengeKind {
	if p.enrolment == nil {
		return []ChallengeKind{ChallengeMFA}
	}

	return []ChallengeKind{ChallengeMFA, ChallengeMFAEnrolment}
}

// Evaluate answers for one request, in the order NewMFARequirementPolicy
// documents. It reads the Input and never writes to it.
func (p *mfaRequirementPolicy) Evaluate(ctx context.Context, in *Input) Decision {
	// 1. An exempt first factor is decided before anything is looked up: a
	// machine caller has nobody to prompt, and a federated login already
	// authenticated where it came from.
	if p.exempt(in.FirstFactor) {
		return Decision{Outcome: Allow}
	}

	// 2. Is a second factor required of this user?
	required, err := p.isRequired(ctx, in)
	if err != nil {
		p.reportLookupFailure(ctx, in, err)

		return Decision{
			Outcome: Deny,
			Reason: diag.Wrap(err,
				"policy: whether this user must use a second factor could not be read, and "+
					"a requirement that cannot be read is not absent"),
		}
	}

	// 3. Nothing is required of this user, so this policy raises no objection.
	if !required {
		return Decision{Outcome: Allow}
	}

	phase, known := p.phaseOf(ctx, in)

	// 4. A stateless request will never reach a phase in which it could answer
	// a challenge, and a policy with no method has nothing to challenge
	// against. Either way the requirement can only be met by refusing. An
	// unidentifiable phase is refused here too: it might be a stateless
	// request, and the alternative is guessing in a required user's favour.
	if !known || phase == StatelessAuthentication || len(p.methods) == 0 {
		return p.denyRequired(ctx, in, phaseName(phase, known))
	}

	// 5. A session that has already satisfied its second factor is done. The
	// claim is honoured here and nowhere else: in the post-authentication phase
	// it is the login's own word for itself.
	if phase == PerRequest && in.MFASatisfied {
		return Decision{Outcome: Allow}
	}

	// 5, at login. A login carrying the library's proof that its second factor was met
	// at the first factor is done, before the usability check, so the
	// enrolment challenge never fires for it. Unlike the claim in step 5 the
	// proof cannot be made by the login itself, and it is not an exemption:
	// no exemption rule is consulted for it.
	if phase == PostAuthentication && in.SecondFactorAtLogin.Holds() {
		return Decision{Outcome: Allow}
	}

	// 6. A user with no usable enrolment cannot be challenged for a second
	// factor. With the enrolment path on and the login admitted by it, they are
	// challenged for enrolment instead; otherwise the refusal says what is
	// missing rather than repeating that a second factor is due.
	usable, err := p.hasUsableEnrolment(ctx, in)
	if err != nil {
		return Decision{
			Outcome: Deny,
			Reason: diag.Wrap(err,
				"policy: the second-factor enrolment of a user required to use one could not "+
					"be read"),
		}
	}
	if !usable {
		// 6a. With the enrolment path on, a user it admits is sent to enrol
		// rather than refused.
		if p.enrolment != nil && p.enrolment.admits(in, phase, p.methods) {
			return Decision{Outcome: Challenge, Challenge: ChallengeMFAEnrolment}
		}

		return p.denyEnrolment(ctx, in, phaseName(phase, known))
	}

	switch phase {
	// 7. A session that has not satisfied its second factor is asked for one.
	case PerRequest:
		return Decision{Outcome: Challenge, Challenge: ChallengeMFA}

	// 8. At login the challenge belongs to the policy NewMFAPolicy returns,
	// which is why the two are registered together.
	case PostAuthentication:
		return Decision{Outcome: Allow}

	// 9. Any phase this policy never declared. Being asked in one is a wiring
	// mistake, and a requirement is not waived because the question arrived
	// from the wrong place.
	default:
		return p.denyRequired(ctx, in, phaseName(phase, known))
	}
}

// isRequired answers step 2. With a requirement for everyone the lookup is not
// consulted at all, which is what lets that mode be configured without one.
func (p *mfaRequirementPolicy) isRequired(ctx context.Context, in *Input) (bool, error) {
	if p.requiredForAll {
		return true, nil
	}

	return p.required.Required(ctx, in.User)
}

// hasUsableEnrolment answers step 6 through UsableMFAMethods, the one
// definition of "usable" the challenge policy and the chain share. An
// enrolment on the first factor's own channel is not usable: whoever holds
// that channel holds both factors, so challenging on it would prove nothing the
// first factor had not already proved. A lookup failure on any method is an
// error, never a shorter list.
func (p *mfaRequirementPolicy) hasUsableEnrolment(ctx context.Context, in *Input) (bool, error) {
	usable, err := UsableMFAMethods(ctx, p.methods, in.User, in.FirstFactor)
	if err != nil {
		return false, err
	}

	return len(usable) > 0, nil
}

// denyRequired refuses a required request that cannot be asked for a second
// factor here, and records it. The record is keyed by user, first factor and
// phase, so one user retrying does not hide another, and a flood from one entry
// point does not hide a second.
func (p *mfaRequirementPolicy) denyRequired(ctx context.Context, in *Input, phase string) Decision {
	p.sampled(ctx, slog.LevelWarn, msgMFARequired,
		strings.Join([]string{sampleMFARequired, string(in.User), string(in.FirstFactor), phase},
			mfaKeySeparator),
		slog.String("user", string(in.User)),
		slog.String("first_factor", string(in.FirstFactor)),
		slog.String("phase", phase))

	return Decision{Outcome: Deny, Reason: ErrMFARequired}
}

// denyEnrolment refuses a required user who has nothing usable to be challenged
// on, and records it.
func (p *mfaRequirementPolicy) denyEnrolment(ctx context.Context, in *Input, phase string) Decision {
	p.sampled(ctx, slog.LevelWarn, msgMFAEnrollmentRequired,
		strings.Join([]string{sampleMFAEnrollment, string(in.User), phase}, mfaKeySeparator),
		slog.String("user", string(in.User)),
		slog.String("first_factor", string(in.FirstFactor)),
		slog.String("phase", phase))

	return Decision{Outcome: Deny, Reason: ErrMFAEnrollmentRequired}
}

// reportLookupFailure writes about a requirement that could not be read.
//
// A failure on a request whose context has already ended is the caller leaving,
// not an outage: it is written at debug level and without sampling, so ordinary
// disconnections neither raise alarms nor consume the window a real outage
// needs. Everything else is written at error level under one key shared by every
// user, because the lookup is either reachable or it is not, and keying it per
// user would turn one outage into one record per user in the window.
func (p *mfaRequirementPolicy) reportLookupFailure(ctx context.Context, in *Input, err error) {
	attrs := append([]slog.Attr{slog.String("user", string(in.User))},
		diag.Failure("requirement-lookup", err)...)

	if ctx.Err() != nil {
		p.logger.LogAttrs(ctx, slog.LevelDebug, msgRequirementLookupEnded, attrs...)

		return
	}

	p.sampled(ctx, slog.LevelError, msgRequirementLookupFailed, sampleLookupFailed, attrs...)
}

// phaseName renders a phase for a record and a sampler key. A phase that was
// never identified is named as such rather than printed as the zero value,
// which would read in a log as a phase the policy had actually been asked in.
func phaseName(phase Phase, known bool) string {
	if !known {
		return "unknown"
	}

	return phase.String()
}

// sampled writes one record unless the sampler is holding this key's window
// open, in which case the event is counted and reported later.
func (p *mfaRequirementPolicy) sampled(
	ctx context.Context, level slog.Level, msg, key string, attrs ...slog.Attr,
) {
	write, suppressed := p.sampler.Allow(key, p.clock.Now())
	if !write {
		return
	}

	p.logger.LogAttrs(ctx, level, msg, append(attrs, slog.Int("suppressed", suppressed))...)
}

// reportSuppressed accounts for counts the sampler is about to discard.
func (p *mfaRequirementPolicy) reportSuppressed(key string, suppressed int) {
	p.logger.LogAttrs(context.Background(), slog.LevelWarn, msgRequirementSuppressed,
		slog.String("key", key),
		slog.Int("suppressed", suppressed))
}

// FlushRefusalLogs reports every record held back but not yet counted, then
// forgets every key. It reports no error.
func (p *mfaRequirementPolicy) FlushRefusalLogs() error {
	p.sampler.Flush()

	return nil
}

// phaseOfContext is the default source of the phase: whatever the engine
// evaluating this policy put in the context. It is replaceable with
// WithMFARequirementPhaseSource.
func phaseOfContext(ctx context.Context, _ *Input) (Phase, bool) {
	return phaseFromContext(ctx)
}

// The messages the policy writes.
const (
	msgMFARequired             = "policy: refusing a request that is required to present a second factor"
	msgMFAEnrollmentRequired   = "policy: refusing a required user with no usable second-factor enrolment"
	msgRequirementLookupFailed = "policy: the mfa requirement lookup failed"
	msgRequirementLookupEnded  = "policy: the mfa requirement lookup ended with its request"
	msgRequirementSuppressed   = "policy: mfa requirement records suppressed"
)

// The sampler key families for this policy.
const (
	sampleMFARequired   = "mfa-required"
	sampleMFAEnrollment = "enrolment-required"

	// sampleLookupFailed is deliberately one key for every user. A requirement
	// lookup is either reachable or it is not, and keying the record per user
	// would turn one outage into one record per user in the window.
	sampleLookupFailed = "lookup-failed"
)

var (
	_ Policy            = (*mfaRequirementPolicy)(nil)
	_ RefusalLogFlusher = (*mfaRequirementPolicy)(nil)
)
