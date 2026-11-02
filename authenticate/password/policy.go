package password

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
)

// ErrPasswordRejected matches every refusal of a candidate password by a
// [Policy] rule. The refusal itself is a [RejectedError], which names the
// rule. Its text is fixed per rule and carries no candidate, hash, context
// word or user reference.
var ErrPasswordRejected = errors.New("password: rejected")

// Rule names the policy rule that refused a candidate.
type Rule string

// The rules a [Policy] refuses a candidate by, cheapest first.
const (
	// RuleTooShort: fewer code points than the minimum, or empty.
	RuleTooShort Rule = "too short"
	// RuleTooLong: more code points than the maximum, or more bytes than the
	// policy's encoder accepts.
	RuleTooLong Rule = "too long"
	// RuleCommon: an entry of the common-password list.
	RuleCommon Rule = "common"
	// RuleContextWord: equal to, or containing, a word tied to the user or
	// the service.
	RuleContextWord Rule = "context word"
	// RuleBreached: found in the breach corpus.
	RuleBreached Rule = "breached"
	// RuleReused: the user's current password or a recent one ([ErrReused]).
	RuleReused Rule = "reused"
)

// RejectedError is a [Policy] refusal. It matches [ErrPasswordRejected]
// through [errors.Is], and is reached with [errors.As] to learn the rule.
type RejectedError struct {
	// Rule is the rule that refused the candidate.
	Rule Rule
}

// Error returns fixed text naming the rule only.
func (e RejectedError) Error() string { return "password: rejected: " + string(e.Rule) }

// Is reports whether target is [ErrPasswordRejected], so every refusal
// matches it whatever its rule.
func (e RejectedError) Is(target error) bool { return target == ErrPasswordRejected }

// Defaults of a [Policy] built with no options, and the floors an option may
// not go below.
const (
	// DefaultMinLength is the minimum length, in code points.
	DefaultMinLength = 15
	// MinLengthFloor is the lowest minimum a policy accepts.
	MinLengthFloor = 8
	// DefaultMaxLength is the maximum length, in code points.
	DefaultMaxLength = 128
	// MaxLengthFloor is the lowest maximum a policy accepts.
	MaxLengthFloor = 64
)

// Policy decides whether a new password may be set, and runs the change that
// stores it.
//
// With no options it applies a minimum length of [DefaultMinLength] code
// points, a maximum of [DefaultMaxLength], and the bundled common-password
// list, and nothing else: no composition rule, no breach check, no history.
// Each option replaces or adds only the rule it names, so setting one never
// removes another default; removing the common-password list takes
// [WithoutCommonPasswords].
//
// Rules run cheapest first: length, then the common-password list, then
// context words, then the breach check, then reuse. The first refusal ends the
// check, and no later rule runs.
//
// The policy writes no log record, and does not keep the candidate after a
// call returns. A Policy is safe for concurrent use.
type Policy struct {
	minLength int
	maxLength int
	byteLimit int                 // 0: no byte limit below maxLength
	common    map[string]struct{} // nil: the common-password rule is off
	words     ContextWordsFunc    // nil: the context-word rule is off
	breach    *breachRule         // nil: the breach check is off
	reuse     *reuseRule          // nil: the reuse rule is off
	enc       Encoder
	clock     clock.Clock
}

// PolicyOption configures a [Policy].
type PolicyOption func(*policyConfig)

type policyConfig struct {
	minLength int
	maxLength int

	enc    Encoder
	encSet bool // WithEncoder was applied

	clock clock.Clock

	common    []string
	commonSet bool // CommonPasswords was applied
	noCommon  bool // WithoutCommonPasswords was applied

	words    ContextWordsFunc
	wordsSet bool // ContextWords was applied

	breach *breachRule
	reuse  *reuseSpec
}

// NewPolicy returns a policy with the defaults [Policy] describes, changed
// only by what opts name. A nil option is ignored.
//
// With no options the policy is:
//
//   - a minimum of [DefaultMinLength] (15) and a maximum of [DefaultMaxLength]
//     (128) code points, replaced by [MinLength] and [MaxLength];
//   - the bundled common-password list, replaced by [CommonPasswords] and
//     removed by [WithoutCommonPasswords];
//   - no context words ([ContextWords] adds the rule);
//   - no breach check ([Breached] adds it, and requires the choice between
//     [Refuse] and [Accept] for a lookup that fails; [PwnedPasswords] is the
//     ready-made source);
//   - no reuse rule ([NoReuse] adds it);
//   - the Argon2id encoder at its defaults, which encodes a change and is the
//     first matcher of the reuse rule ([WithEncoder] replaces it); and
//   - the system clock ([WithClock] replaces it).
//
// Every option replaces or adds only what it names. The same encoder's
// [Upgrader] decides, at a login, whether a stored hash is outdated: see
// [ConditionalProvisionerRehash] for the write that stores the upgrade.
//
// A configuration that cannot work is refused with an error wrapping
// [ErrConfig] that names the mistake, before any password is checked.
func NewPolicy(opts ...PolicyOption) (*Policy, error) {
	cfg := policyConfig{
		minLength: DefaultMinLength,
		maxLength: DefaultMaxLength,
		clock:     clock.System(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if err := cfg.validateRules(); err != nil {
		return nil, err
	}

	if cfg.encSet && nilcheck.IsNil(cfg.enc) {
		return nil, fmt.Errorf("%w: the encoder is nil", ErrConfig)
	}

	if nilcheck.IsNil(cfg.clock) {
		return nil, fmt.Errorf("%w: the clock is nil", ErrConfig)
	}

	if cfg.breach != nil {
		if err := cfg.breach.validate(); err != nil {
			return nil, err
		}
	}

	enc := cfg.enc
	if !cfg.encSet {
		var err error
		if enc, err = NewArgon2idEncoder(); err != nil {
			return nil, err
		}
	}

	p := &Policy{
		minLength: cfg.minLength,
		maxLength: cfg.maxLength,
		byteLimit: encoderByteLimit(enc),
		words:     cfg.words,
		breach:    cfg.breach,
		enc:       enc,
		clock:     cfg.clock,
	}

	if cfg.reuse != nil {
		var err error
		if p.reuse, err = cfg.reuse.build(enc); err != nil {
			return nil, err
		}
	}

	switch {
	case cfg.noCommon:
	case cfg.commonSet:
		p.common = commonSet(cfg.common)
	default:
		p.common = bundledCommonPasswords()
	}

	return p, nil
}

// validateRules refuses lengths, a list or a word function the policy cannot
// work with.
func (c *policyConfig) validateRules() error {
	if c.minLength < MinLengthFloor {
		return fmt.Errorf("%w: the minimum length must be at least %d", ErrConfig, MinLengthFloor)
	}

	if c.maxLength < MaxLengthFloor {
		return fmt.Errorf("%w: the maximum length must be at least %d", ErrConfig, MaxLengthFloor)
	}

	if c.maxLength < c.minLength {
		return fmt.Errorf("%w: the maximum length is below the minimum length", ErrConfig)
	}

	if c.commonSet && len(commonSet(c.common)) == 0 {
		return fmt.Errorf("%w: the replacement common-password list is empty; "+
			"use WithoutCommonPasswords to remove the rule", ErrConfig)
	}

	if c.wordsSet && c.words == nil {
		return fmt.Errorf("%w: the context-word function is nil", ErrConfig)
	}

	return nil
}

// MinLength replaces the minimum length, counted in code points.
//
// Default: [DefaultMinLength]. A minimum below [MinLengthFloor] fails
// construction.
func MinLength(n int) PolicyOption {
	return func(c *policyConfig) { c.minLength = n }
}

// MaxLength replaces the maximum length, counted in code points. A longer
// candidate is refused, never truncated.
//
// Default: [DefaultMaxLength]. A maximum below [MaxLengthFloor], or below the
// minimum, fails construction.
func MaxLength(n int) PolicyOption {
	return func(c *policyConfig) { c.maxLength = n }
}

// WithoutCommonPasswords removes the common-password rule.
//
// Default: the rule is on, over the bundled list.
func WithoutCommonPasswords() PolicyOption {
	return func(c *policyConfig) {
		c.noCommon, c.commonSet, c.common = true, false, nil
	}
}

// CommonPasswords replaces the bundled common-password list with list,
// compared case-insensitively.
//
// Default: the bundled list. An empty list fails construction; use
// [WithoutCommonPasswords] to remove the rule.
func CommonPasswords(list []string) PolicyOption {
	list = append([]string(nil), list...)

	return func(c *policyConfig) {
		c.noCommon, c.commonSet, c.common = false, true, list
	}
}

// ContextWordsFunc returns the words tied to user and the service, such as
// the username, the user's name and the service's name, that a new password
// must not equal or contain. Its error fails the check unchanged, as a
// dependency failure rather than a refusal.
type ContextWordsFunc func(ctx context.Context, user *identity.Details) ([]string, error)

// contextWordMinContained is the shortest word a candidate is refused for
// containing; a shorter one refuses only a candidate equal to it, so a short
// service name does not refuse ordinary passphrases.
const contextWordMinContained = 4

// ContextWords adds the context-word rule: a candidate is refused when it
// equals a word fn returns, or contains one of at least 4 characters,
// compared case-insensitively. fn runs on every check that reaches the rule.
//
// Default: no context words. A nil fn fails construction.
func ContextWords(fn ContextWordsFunc) PolicyOption {
	return func(c *policyConfig) { c.words, c.wordsSet = fn, true }
}

// WithEncoder replaces the encoder a change encodes the new password with,
// which is also the first matcher of the [NoReuse] rule.
//
// An encoder that states a byte limit through [InputLimiter], as the bcrypt
// encoder's 72 bytes, has a longer candidate refused as too long by the check,
// so a check and a change agree. For an encoder that states none, the check
// cannot know its limit: a candidate it would refuse passes the check, and
// [Policy.Change] answers the encoder's [ErrTooLong] as a too-long rejection.
// Implement [InputLimiter] to have the check refuse it first.
//
// Default: the library's Argon2id encoder at its default parameters
// ([NewArgon2idEncoder]). A nil encoder, typed nil included, fails
// construction.
func WithEncoder(e Encoder) PolicyOption {
	return func(c *policyConfig) { c.enc, c.encSet = e, true }
}

// WithClock replaces the clock [Policy.Change] reads the time of the change
// from, which it hands to the [WriteFunc].
//
// Default: clock.System(). A nil clock, typed nil included, fails
// construction.
func WithClock(c clock.Clock) PolicyOption {
	return func(cfg *policyConfig) { cfg.clock = c }
}

// Check refuses candidate for user with a [RejectedError] naming the first
// rule that refuses it, and returns nil when every rule accepts it.
//
// Length is counted in code points of candidate as given: it is never
// trimmed, normalised or truncated, and an empty candidate is too short.
//
// Errors other than a refusal: a context-word function's error, unchanged;
// [ErrLookupUnavailable] from a failed breach lookup with [Refuse];
// [ErrHistoryUnavailable] from a history the reuse rule could not read; and
// the context's error when ctx ended during the breach lookup. A nil user is
// an error wrapping [ErrConfig], and nothing is read.
//
// Check alone records nothing.
func (p *Policy) Check(ctx context.Context, user *identity.Details, candidate string) error {
	if user == nil {
		return fmt.Errorf("%w: a user record is required", ErrConfig)
	}

	switch n := utf8.RuneCountInString(candidate); {
	case n < p.minLength:
		return RejectedError{Rule: RuleTooShort}
	case n > p.maxLength, p.byteLimit > 0 && len(candidate) > p.byteLimit:
		return RejectedError{Rule: RuleTooLong}
	}

	if p.common != nil {
		if _, ok := p.common[strings.ToLower(candidate)]; ok {
			return RejectedError{Rule: RuleCommon}
		}
	}

	if p.words != nil {
		words, err := p.words(ctx, user)
		if err != nil {
			return err
		}

		if containsContextWord(candidate, words) {
			return RejectedError{Rule: RuleContextWord}
		}
	}

	if p.breach != nil {
		if err := p.breach.check(ctx, candidate); err != nil {
			return err
		}
	}

	if p.reuse != nil {
		return p.reuse.check(ctx, user, candidate)
	}

	return nil
}

// Change replaces user's password with candidate. It runs these steps and
// stops at the first failure:
//
//  1. every rule's check, as [Policy.Check];
//  2. encode candidate with the policy's encoder; an encoder error, such as
//     [ErrContainsNUL], is returned as is, except [ErrTooLong], which is
//     refused as too long ([RuleTooLong]);
//  3. with the [NoReuse] rule, retire user.Password, keeping only the newest
//     depth−1 retired hashes; a failure refuses with [ErrHistoryUnavailable]
//     and the password is unchanged. A user with no current hash retires
//     nothing;
//  4. call write with user, the new hash and the time from the policy's
//     clock, and return its error unchanged.
//
// Encoding comes before retiring, so a refusal of any kind, an encoder's
// included, leaves the history as it was; and retiring comes before writing,
// so every failure before step 4 leaves the password untouched. If write
// fails, the retired entry stays; it holds the hash that is still current, and
// retiring the same bytes again adds nothing, so a retry is not refused and
// does not count the password twice. With the default identity store backing
// both the user and the history, run Change with [ProvisionerWrite](store)
// inside one transaction attached to ctx with the store's WithTx (or a
// configured WithTxResolver), so the retire, the prune it carries and the
// write commit or roll back together.
//
// The one record keys everything: user.ID keys the history, user.Password is
// the current hash, and write receives the same pointer. A nil user or a nil
// write is an error wrapping [ErrConfig], and nothing is read or written.
//
// To record the change time with an [identity.UserProvisioner], pass
// [ProvisionerWrite]. A write that ignores the time it is handed leaves the
// stored password-changed time as it was, which exempts the user from
// password-age policy.
func (p *Policy) Change(ctx context.Context, user *identity.Details, candidate string, write WriteFunc) error {
	if write == nil {
		return fmt.Errorf("%w: a write function is required", ErrConfig)
	}

	if err := p.Check(ctx, user, candidate); err != nil {
		return err
	}

	// Encode before retiring: a refusal, an encoder's too-long one included,
	// must leave the history untouched.
	hash, err := p.enc.Encode(candidate)
	if errors.Is(err, ErrTooLong) {
		// An encoder that states no limit through InputLimiter reaches here: the
		// candidate is too long for it, which is the user's to fix, not a failure.
		return RejectedError{Rule: RuleTooLong}
	}

	if err != nil {
		return err
	}

	if p.reuse != nil {
		if err := p.reuse.retire(ctx, user); err != nil {
			return err
		}
	}

	return write(ctx, user, hash, p.clock.Now())
}

// containsContextWord reports whether candidate equals any of words, or
// contains one of at least contextWordMinContained characters, ignoring case.
func containsContextWord(candidate string, words []string) bool {
	lower := strings.ToLower(candidate)

	for _, w := range words {
		w = strings.ToLower(w)

		if lower == w {
			return true
		}

		if utf8.RuneCountInString(w) >= contextWordMinContained && strings.Contains(lower, w) {
			return true
		}
	}

	return false
}

// encoderByteLimit returns the most bytes enc states it accepts through
// [InputLimiter], or 0 for no limit below the policy's maximum.
func encoderByteLimit(enc Encoder) int {
	if l, ok := enc.(InputLimiter); ok {
		return max(l.MaxInputBytes(), 0)
	}

	return 0
}
