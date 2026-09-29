package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/logsample"
)

//go:generate mockgen -source=mfa.go -package=policy_test -destination=mfa_mock_test.go -typed -exclude_interfaces=MFAOption,RefusalLogFlusher
//go:generate mockgen -destination=requirementlookup_mock_test.go -package=policy_test -typed github.com/kartaladev/scrty/identity MFARequirementLookup

// ErrSecondFactorSameChannel is the reason the second-factor challenge policy
// refuses a login whose only enrolled second factor arrives on the very channel
// the first factor came from.
//
// Two factors on one channel are one factor: whoever holds the mailbox holds
// both. The enrolment therefore cannot be challenged for, and the user who
// created it asked for two factors rather than one, so the login is refused
// instead of quietly completing at the assurance they did not choose.
var ErrSecondFactorSameChannel = errors.New(
	"policy: the enrolled second factor arrives on the first factor's own channel")

// MFAMethodLookup reports whether a user has a usable enrolment on one
// second-factor method, and which channel that method delivers on.
//
// # The contract an implementation must keep
//
// Enrolled reports true only for an enrolment that is confirmed and whose
// secret can be read. An enrolment that was started and never confirmed is not
// an enrolment: it reports false. A store failure, or a stored secret that will
// not decrypt, is an error — never a false.
//
// That last clause is the whole point of the port. A policy reads false as "this
// user has no second factor" and lets the login through on its first factor, so
// an implementation that reported a lost row or an unreadable secret as false
// would silently downgrade exactly the users who had enrolled. Both policies
// here refuse on the error instead.
//
// Channel is asked on the request path and must be constant for the life of the
// lookup: it describes the method the implementation was built for, not the
// user being looked up. It is compared with the login's own first-factor
// channel, which is how a second factor that would arrive the same way as the
// first is detected.
//
// Name identifies the method among the others configured beside it. It must be
// constant, and unique within one set: the policies refuse a set in which two
// methods share a name, because nothing downstream could tell them apart.
//
// scrty ships no implementation. An implementation is expected to be safe for
// concurrent use.
type MFAMethodLookup interface {
	// Name identifies the method within the configured set.
	Name() string

	// Enrolled reports whether user has a confirmed, readable enrolment on
	// this method.
	Enrolled(ctx context.Context, user identity.UserID) (bool, error)

	// Channel reports the medium this method delivers on.
	Channel() factor.Channel
}

// RefusalLogFlusher reports every refusal a policy has suppressed but not yet
// counted in a written record.
//
// Sampling keeps a burst of refusals from burying every other record, but the
// count of what was held back is only written when the same refusal recurs. A
// consumer flushes at shutdown, or before reading the logs of an incident, so a
// burst that stopped is still accounted for rather than silently discarded.
//
// The constructors here return Policy, so a consumer reaches this with a type
// assertion. The error is part of the contract for implementations whose
// reporter can fail; the policies in this package only write a log record, and
// always report none.
type RefusalLogFlusher interface {
	FlushRefusalLogs() error
}

// SameChannelMode is what the second-factor challenge policy does with a login
// whose only enrolled second factor would arrive on the first factor's channel.
//
// The zero value is SameChannelRefuse, so a consumer who configures nothing
// gets the safe answer rather than the convenient one.
type SameChannelMode int

const (
	// SameChannelRefuse denies the login with ErrSecondFactorSameChannel and
	// writes a sampled warning. It is the default.
	SameChannelRefuse SameChannelMode = iota

	// SameChannelCompleteOnFirstFactor allows the login on its first factor
	// alone, records no satisfied second factor, and still writes a sampled
	// warning naming the completion.
	SameChannelCompleteOnFirstFactor
)

// String returns the constant's own name, so a log line reads
// "SameChannelRefuse" rather than "0". A value that names no mode prints its
// number rather than passing itself off as one of the two.
func (m SameChannelMode) String() string {
	switch m {
	case SameChannelRefuse:
		return "SameChannelRefuse"
	case SameChannelCompleteOnFirstFactor:
		return "SameChannelCompleteOnFirstFactor"
	default:
		return unnamed("SameChannelMode", int(m))
	}
}

// MFAOption configures the policy NewMFAPolicy returns. Every default that
// constructor applies has an option that replaces it.
//
// It is an interface rather than a function type so that WithMFAExemption,
// which governs a rule both MFA policies hold, can be given to either
// constructor under one name. A consumer implements nothing: the options are
// the values this package returns.
type MFAOption interface {
	applyMFA(*mfaPolicy)
}

// mfaOption adapts a plain function into an MFAOption.
type mfaOption func(*mfaPolicy)

func (f mfaOption) applyMFA(p *mfaPolicy) { f(p) }

// MFAExemptionOption is returned by WithMFAExemption. It is accepted by both
// NewMFAPolicy and NewMFARequirementPolicy, so a deployment states its
// exemption rule once and gives the same value to each.
type MFAExemptionOption struct {
	exempt func(factor.Kind) bool
}

func (o MFAExemptionOption) applyMFA(p *mfaPolicy) { p.exempt = o.exempt }

func (o MFAExemptionOption) applyMFARequirement(p *mfaRequirementPolicy) { p.exempt = o.exempt }

// WithMFAExemption replaces the rule that decides which first factors are
// exempt from a second factor. The default is factor.Kind.MFAExempt, which
// exempts a federated login and a machine caller and enforces every other kind,
// including the empty kind and kinds the library does not name.
//
// A consumer replaces it to enforce a second factor on a kind the library
// exempts, or to exempt a kind of their own. A nil rule is a configuration
// error: it would panic on the first login rather than at the line that was
// wrong.
//
// The value it returns is accepted by both MFA policy constructors, because a
// deployment that exempts a kind from the requirement and not from the login
// challenge would be enforcing two different rules under one name.
func WithMFAExemption(exempt func(factor.Kind) bool) MFAExemptionOption {
	return MFAExemptionOption{exempt: exempt}
}

// WithSameChannelEnrolment replaces what the policy does with an enrolment on
// the first factor's own channel. The default is SameChannelRefuse.
//
// SameChannelCompleteOnFirstFactor is the documented alternative, for a
// deployment that would rather complete such logins than refuse them. It cannot
// be used to let a user who is required to use a second factor through: that
// user is governed by the policy NewMFARequirementPolicy returns, which counts
// a same-channel enrolment as no usable enrolment whatever this is set to.
//
// A mode naming neither constant is a configuration error.
func WithSameChannelEnrolment(mode SameChannelMode) MFAOption {
	return mfaOption(func(p *mfaPolicy) { p.sameChannel = mode })
}

// WithMFAPolicyLogger replaces where the policy writes its same-channel
// warnings. The default is slog.Default.
//
// Its records name the user by the opaque reference in Input.User, on purpose,
// with the first factor and the channel; they never carry a dependency's error
// text.
//
// A nil logger is ignored rather than refused: it has an obvious safe reading —
// the caller does not want to choose this policy's logger — and refusing it
// would make configuring logging mandatory.
func WithMFAPolicyLogger(l *slog.Logger) MFAOption {
	return mfaOption(func(p *mfaPolicy) {
		if l != nil {
			p.logger = l
		}
	})
}

// WithMFAPolicyLogInterval replaces how long one written same-channel record
// suppresses further records about the same user. The default is
// DefaultLogInterval, one minute.
//
// Every written record says how many events it stands for, and
// RefusalLogFlusher reports what is still pending, so suppressing a record
// never loses the count. An interval of zero or less writes every record, for a
// consumer whose own handler samples.
//
// It governs this policy alone. The policy NewMFARequirementPolicy returns
// keeps its own window under WithMFARequirementLogInterval, so one subsystem's
// flood cannot silence another's.
func WithMFAPolicyLogInterval(d time.Duration) MFAOption {
	return mfaOption(func(p *mfaPolicy) { p.logInterval = d })
}

// WithMFAPolicyClock replaces the time source the policy samples its records
// by. The default is clock.System().
//
// It is not the instant a decision is judged against — that is Input.Now, taken
// from the caller's clock so that every policy in a phase agrees. This clock
// measures the sampling window alone, which is how a test crosses a window
// boundary without waiting for one. A nil clock, typed nil included, is a
// configuration error.
func WithMFAPolicyClock(clk clock.Clock) MFAOption {
	return mfaOption(func(p *mfaPolicy) { p.clock = clk })
}

// mfaPolicy challenges a login whose user is enrolled on a usable second
// factor. Every field is fixed at construction, so it is safe for concurrent
// use.
type mfaPolicy struct {
	methods     []MFAMethodLookup
	sameChannel SameChannelMode
	exempt      func(factor.Kind) bool
	logger      *slog.Logger
	clock       clock.Clock
	logInterval time.Duration
	sampler     *logsample.Sampler
}

// NewMFAPolicy returns the second-factor challenge policy, which turns a
// successful login into an MFA challenge when the user can use at least one of
// methods.
//
// methods is the set of second-factor methods the deployment offers, in the
// order it prefers them. It must be the same set, over the same methods, as the
// chain's httpsec.EnableMFA was given — mfa.LookupsFor builds this list from
// those methods — or the policy would challenge for a method the chain cannot
// verify, or let a login through that the chain could have challenged.
//
// It runs in the post-authentication phase alone, which is the last point at
// which a login can still be turned into a challenge. It answers:
//
//   - a login that has already satisfied a second factor: allow;
//   - an exempt first factor: allow;
//   - any method's enrolment lookup failed: deny, even when another method
//     reports the user enrolled, so a lost or unreadable enrolment never
//     downgrades a user to a single factor. The reason is fixed text and wraps
//     the lookup's error, reachable through errors.Is and errors.As but not
//     repeated in the text;
//   - the user can use at least one method, as UsableMFAMethods decides — one
//     they are enrolled on whose channel differs from the first factor's:
//     challenge for MFA, whatever else they are enrolled on;
//   - enrolled only on methods on the first factor's own channel: whatever
//     WithSameChannelEnrolment says, which by default is a refusal;
//   - enrolled on no method: allow.
//
// It decides nothing about users who are *required* to use a second factor;
// that is the policy NewMFARequirementPolicy returns, and a deployment that
// enforces a requirement registers both, over the same methods.
//
// An empty set is a configuration error wrapping ErrConfig: a policy with
// nothing to look enrolments up in would allow every login while reading, at
// the call site, exactly like one that challenges. So is an absent method —
// nil, or a non-nil interface holding a nil pointer, which is what an
// unchecked constructor result hands over — and two methods of the same Name,
// which nothing downstream could tell apart. The policy keeps its own copy of
// the set.
//
// Defaults: SameChannelRefuse (WithSameChannelEnrolment),
// factor.Kind.MFAExempt (WithMFAExemption), slog.Default
// (WithMFAPolicyLogger), clock.System() (WithMFAPolicyClock) and DefaultLogInterval
// for its sampled records (WithMFAPolicyLogInterval).
func NewMFAPolicy(methods []MFAMethodLookup, opts ...MFAOption) (Policy, error) {
	p := &mfaPolicy{
		sameChannel: SameChannelRefuse,
		exempt:      factor.Kind.MFAExempt,
		logger:      slog.Default(),
		clock:       clock.System(),
		logInterval: DefaultLogInterval,
	}
	for _, opt := range opts {
		if opt != nil {
			opt.applyMFA(p)
		}
	}

	checked, err := checkMFAMethods(methods, "second-factor challenge policy", true)
	if err != nil {
		return nil, err
	}
	p.methods = checked

	if p.exempt == nil {
		return nil, fmt.Errorf(
			"%w: the second-factor challenge policy has no exemption rule, so it could not "+
				"judge a single login", ErrConfig)
	}
	if nilcheck.IsNil(p.clock) {
		return nil, fmt.Errorf(
			"%w: the second-factor challenge policy has no clock, so its records could not "+
				"be sampled", ErrConfig)
	}
	if p.sameChannel != SameChannelRefuse && p.sameChannel != SameChannelCompleteOnFirstFactor {
		return nil, fmt.Errorf(
			"%w: %s names neither same-channel mode, and guessing which was meant would "+
				"decide whether a login is refused", ErrConfig, p.sameChannel)
	}

	p.sampler = logsample.New(p.logInterval, logsample.WithReporter(p.reportSuppressed))

	return p, nil
}

// Name identifies the policy in logs and in an engine's configuration errors.
func (p *mfaPolicy) Name() string { return "second-factor-challenge" }

// Phases reports that the policy runs at the moment a login has succeeded and
// may still be turned into a challenge.
func (p *mfaPolicy) Phases() []Phase { return []Phase{PostAuthentication} }

// Evaluate answers for one login, in the order NewMFAPolicy documents.
//
// It reads the Input and never writes to it: an allow here records no satisfied
// second factor, because none happened.
// Challenges reports that this policy can ask for a second factor, so a chain
// that composes it can refuse to assemble when nothing would enforce one.
//
// A fresh slice every call: what a caller does with it is their business, and
// this policy keeps no state a caller could reach through it.
func (p *mfaPolicy) Challenges() []ChallengeKind { return []ChallengeKind{ChallengeMFA} }

func (p *mfaPolicy) Evaluate(ctx context.Context, in *Input) Decision {
	if in.MFASatisfied || p.exempt(in.FirstFactor) {
		return Decision{Outcome: Allow}
	}

	usable, err := UsableMFAMethods(ctx, p.methods, in.User, in.FirstFactor)
	if err != nil {
		return denyUnreadableEnrolment(err)
	}

	if len(usable) > 0 {
		return Decision{Outcome: Challenge, Challenge: ChallengeMFA}
	}

	// No usable method. Either the user is enrolled on nothing, or every
	// method they are enrolled on arrives on the first factor's own channel.
	enrolled, err := p.enrolledOnAny(ctx, in.User)
	if err != nil {
		return denyUnreadableEnrolment(err)
	}

	if !enrolled {
		return Decision{Outcome: Allow}
	}

	return p.decideSameChannel(ctx, in, in.FirstFactor.Channel())
}

// enrolledOnAny reports whether user is enrolled on any configured method,
// whatever its channel. It is asked only once UsableMFAMethods found none, so a
// true here means every enrolment is on the first factor's own channel.
func (p *mfaPolicy) enrolledOnAny(ctx context.Context, user identity.UserID) (bool, error) {
	for _, m := range p.methods {
		enrolled, err := m.Enrolled(ctx, user)
		if err != nil || enrolled {
			return enrolled, err
		}
	}

	return false, nil
}

// denyUnreadableEnrolment refuses a login whose enrolment on some method could
// not be read.
//
// The error is wrapped rather than replaced, so a caller can still match what
// failed; but under fixed text, because the lookup's error is the consumer's
// text and may quote what this package never saw.
func denyUnreadableEnrolment(err error) Decision {
	return Decision{
		Outcome: Deny,
		Reason: diag.Wrap(err,
			"policy: the second-factor enrolment could not be read, so this login "+
				"cannot be completed on one factor"),
	}
}

// decideSameChannel answers a login whose only enrolments arrive on the first
// factor's own channel.
//
// Both modes write a record. The enrolment is unusable either way, and a login
// that completes at a lower assurance than the user enrolled for — or one that
// is refused — is worth knowing about; neither may happen silently. The records
// are sampled, so a deployment where this is the normal case pays one record per
// window rather than one per login.
func (p *mfaPolicy) decideSameChannel(ctx context.Context, in *Input, channel factor.Channel) Decision {
	attrs := []slog.Attr{
		slog.String("user", string(in.User)),
		slog.String("first_factor", string(in.FirstFactor)),
		slog.String("channel", string(channel)),
	}

	if p.sameChannel == SameChannelCompleteOnFirstFactor {
		p.sampled(ctx, slog.LevelWarn, msgSameChannelAllowed,
			sampleSameChannelAllowed+mfaKeySeparator+string(in.User), attrs...)

		// An allow, and nothing more: the Input is not written to, so this
		// login records no satisfied second factor. It did not happen.
		return Decision{Outcome: Allow}
	}

	p.sampled(ctx, slog.LevelWarn, msgSameChannelRefused,
		sampleSameChannelRefused+mfaKeySeparator+string(in.User), attrs...)

	return Decision{
		Outcome: Deny,
		Reason: fmt.Errorf("%w: both would arrive on channel %q",
			ErrSecondFactorSameChannel, channel),
	}
}

// sampled writes one record unless the sampler is holding this key's window
// open, in which case the event is counted and reported later.
func (p *mfaPolicy) sampled(ctx context.Context, level slog.Level, msg, key string, attrs ...slog.Attr) {
	write, suppressed := p.sampler.Allow(key, p.clock.Now())
	if !write {
		return
	}

	p.logger.LogAttrs(ctx, level, msg, append(attrs, slog.Int("suppressed", suppressed))...)
}

// reportSuppressed accounts for counts the sampler is about to discard, so a
// burst that stops before its window elapses is still reported in full.
func (p *mfaPolicy) reportSuppressed(key string, suppressed int) {
	p.logger.LogAttrs(context.Background(), slog.LevelWarn, msgMFASuppressed,
		slog.String("key", key),
		slog.Int("suppressed", suppressed))
}

// FlushRefusalLogs reports every same-channel record held back but not yet
// counted, then forgets every key, so the next record of each is written.
//
// It reports no error: this policy's reporter only writes a log record, which
// cannot fail in a way it could report.
func (p *mfaPolicy) FlushRefusalLogs() error {
	p.sampler.Flush()

	return nil
}

// The messages the policy writes. They are stable text, with everything that
// varies carried as an attribute, so a log pipeline can group on them.
const (
	msgSameChannelRefused = "policy: refusing a login whose second factor is same-channel with its first"
	msgSameChannelAllowed = "policy: completing a login on its first factor, its second factor being same-channel"
	msgMFASuppressed      = "policy: second-factor records suppressed"
)

// The sampler key families for this policy. Each is held back independently, so
// a flood of refusals cannot bury the record of a completion.
const (
	sampleSameChannelRefused = "same-channel-refused"
	sampleSameChannelAllowed = "same-channel-allowed"
)

// mfaKeySeparator joins the parts of a sampler key written by the two MFA
// policies.
const mfaKeySeparator = ":"

var (
	_ Policy            = (*mfaPolicy)(nil)
	_ RefusalLogFlusher = (*mfaPolicy)(nil)
)
