package password

//go:generate mockgen -source=reuse.go -destination=reuse_mock_test.go -package=password_test -typed
//go:generate mockgen -destination=provisioner_mock_test.go -package=password_test -typed github.com/kartaladev/scrty/identity UserProvisioner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// History keeps the hashes a user's password had before its current one.
//
// It is the storage behind the [NoReuse] rule. The library ships no
// in-process implementation: a consumer supplies one over their own storage,
// or uses a store that implements it. Nothing reads or writes history unless
// the consumer adds the rule over it, so password history is off by default.
//
// The hashes are credential material. An implementation must never log them or
// quote them in an error, and returns them only through RecentPasswords.
type History interface {
	// RecentPasswords returns up to limit of the user's retired hashes, newest
	// first. A user with none returns an empty slice and no error. A failure,
	// including a user reference the store cannot read, is an error, never an
	// empty history: the policy refuses the change rather than check nothing.
	RecentPasswords(ctx context.Context, user identity.UserID, limit int) ([][]byte, error)

	// RetirePassword records hash as the user's newest retired hash, then keeps
	// only the newest keep entries. Recording the same bytes as the current
	// newest entry adds nothing, so a retried change does not count one password
	// twice. keep == 0 records nothing and removes every entry.
	RetirePassword(ctx context.Context, user identity.UserID, hash []byte, keep int) error

	// ForgetPasswords removes every retired hash of the user. A consumer's user
	// deletion calls it together with deleting the user.
	ForgetPasswords(ctx context.Context, user identity.UserID) error
}

var (
	// ErrReused refuses a new password that matches the user's current
	// password or one of their recent ones. It is the [RejectedError] of
	// [RuleReused], so it also matches [ErrPasswordRejected]. Its text is fixed
	// and carries no password, hash or user reference.
	ErrReused error = RejectedError{Rule: RuleReused}

	// ErrHistoryUnavailable refuses a change whose history could not be read or
	// recorded. The policy fails closed: it never reads a failure as "no
	// history". The error it returns reports this fixed text only, while the
	// [History] port's own error stays reachable through [errors.Is] and
	// [errors.As], so text a store put in its error never reaches a response or
	// a log line through the policy.
	ErrHistoryUnavailable = errors.New("password: password history could not be read or written")

	// ErrConfig reports a wiring mistake: a missing port, encoder, matcher or
	// clock, a depth below one, a length or list a policy cannot work with, or
	// a missing user record or write function handed to a check or change. The
	// message names the mistake, never a value.
	ErrConfig = errors.New("password: invalid configuration")
)

// WriteFunc stores user's new password hash and the time it changed.
//
// [Policy.Change] calls it last, after every rule and after the current hash
// has been retired, and returns its error unchanged. user is the record the
// caller passed to Change; hash is the new hash, already encoded; changedAt is
// read from the policy's clock ([WithClock], default clock.System()).
//
// [ProvisionerWrite] builds one over any [identity.UserProvisioner] that
// records both the hash and changedAt. That is the only path on which the time
// is recorded by default. A WriteFunc that ignores changedAt leaves the stored
// password-changed time as it was, which exempts the user from password-age
// policy: a password-age check keeps reading the old time, or none, however
// often the password changes.
type WriteFunc func(ctx context.Context, user *identity.Details, hash []byte, changedAt time.Time) error

// ReuseOption configures the [NoReuse] rule.
type ReuseOption func(*reuseConfig)

type reuseConfig struct {
	extras    []Encoder
	extrasSet bool // WithReuseMatchers was applied, replacing the default extras
}

// reuseSpec is the NoReuse rule as configured, before the policy's encoder is
// known.
type reuseSpec struct {
	history History
	depth   int
	cfg     reuseConfig
}

// reuseRule refuses the user's current password and their depth−1 most recent
// retired ones.
type reuseRule struct {
	history  History
	matchers []Encoder // the policy's encoder first, then the extras
	depth    int
}

// NoReuse adds the reuse rule: a candidate matching the user's current hash
// or one of their depth−1 most recent retired hashes, read through history, is
// refused with [ErrReused], and a successful [Policy.Change] retires the
// replaced hash into history, keeping only the newest depth−1.
//
// Nothing checks or records password history unless a consumer adds this
// rule and calls the policy from their own password-change code, with the
// plaintext they already hold. The rule is not wired into any store or
// endpoint on its own: a store cannot tell a local change from a password
// mirrored from an identity provider, and checking a mirror would fail a
// federated login.
//
// With depth N the rule compares the candidate against the user's current
// hash and their N−1 most recent retired hashes, so N = 1 refuses only
// "changing" to the same password, and reads no history. It compares by
// verifying the candidate against each stored hash, never by encoding it
// again, since every hash carries its own salt. A user with no current hash
// and no history, as at sign-up, has nothing to reuse.
//
// By default the matchers are the policy's encoder followed by the library's
// Argon2id, bcrypt and scrypt encoders, less the one of the policy encoder's
// own algorithm: it already matches those hashes, and a second built-in would
// only derive the same key again. So a stored hash of a built-in algorithm
// costs exactly one key derivation per check. [WithReuseMatchers] replaces
// the extras.
//
// depth is required and has no default: published guidance ranges from no
// history at all to 24 passwords, and a library default would present one of
// them as the right answer. There is no upper bound; a large depth costs one
// key derivation per stored hash on every change, run one after another
// rather than in parallel, so peak memory stays at one derivation's cost.
// With Argon2id at 64 MiB and a depth of 24, a change can still take over a
// second: the cost falls on a rare, authenticated action, not on login.
//
// The rule fails closed: a history it cannot read or record refuses the
// change with [ErrHistoryUnavailable].
//
// It does not serialise two changes of one user. Two changes submitted at the
// same instant both pass the check, the last write wins, and the losing new
// password is never retired. Only that user can use this, and only to reuse a
// password they chose moments earlier.
//
// Default: no reuse rule. A nil or typed-nil history or matcher, or a depth below
// one, fails construction with an error wrapping [ErrConfig] that names the
// mistake.
func NoReuse(history History, depth int, opts ...ReuseOption) PolicyOption {
	spec := &reuseSpec{history: history, depth: depth}
	for _, opt := range opts {
		if opt != nil {
			opt(&spec.cfg)
		}
	}

	return func(c *policyConfig) { c.reuse = spec }
}

// WithReuseMatchers replaces the extra matchers the [NoReuse] rule verifies
// stored hashes with. The policy's own encoder is always one of the matchers,
// whatever this option says.
//
// Default: the library's Argon2id, bcrypt and scrypt encoders, used only to
// match, less the one of the policy encoder's own algorithm. Each reads its
// parameters from the stored hash, so a hash any of them ever wrote matches,
// whatever its cost; a rule that stopped seeing history after an algorithm
// migration would fail open.
//
// Pass the encoders of any algorithm of your own that wrote stored hashes.
// They are used as given, even one of the policy encoder's own type, since a
// consumer encoder's Match may depend on its own configuration.
// Calling it with no encoders leaves only the policy's own encoder. A nil
// encoder fails construction with [ErrConfig].
func WithReuseMatchers(encs ...Encoder) ReuseOption {
	encs = append([]Encoder(nil), encs...)

	return func(c *reuseConfig) {
		c.extras = encs
		c.extrasSet = true
	}
}

// build validates the spec and returns the rule over the policy's encoder.
func (s *reuseSpec) build(enc Encoder) (*reuseRule, error) {
	if nilcheck.IsNil(s.history) {
		return nil, fmt.Errorf("%w: the reuse rule needs a password history port", ErrConfig)
	}

	if s.depth < 1 {
		return nil, fmt.Errorf("%w: the reuse depth must be at least 1", ErrConfig)
	}

	for _, m := range s.cfg.extras {
		if nilcheck.IsNil(m) {
			return nil, fmt.Errorf("%w: a reuse matcher is nil", ErrConfig)
		}
	}

	extras := s.cfg.extras
	if !s.cfg.extrasSet {
		var err error
		if extras, err = defaultMatchers(enc); err != nil {
			return nil, err
		}
	}

	return &reuseRule{
		history:  s.history,
		matchers: append([]Encoder{enc}, extras...),
		depth:    s.depth,
	}, nil
}

// check refuses candidate with ErrReused when it matches user.Password or one
// of the depth−1 most recent retired hashes of user.ID. With depth 1 history
// is not read at all.
func (r *reuseRule) check(ctx context.Context, user *identity.Details, candidate string) error {
	var retired [][]byte
	if n := r.depth - 1; n > 0 {
		var err error
		if retired, err = r.history.RecentPasswords(ctx, user.ID, n); err != nil {
			return historyError(err)
		}
	}

	if r.matches(candidate, user.Password) {
		return ErrReused
	}

	for _, hash := range retired {
		if r.matches(candidate, hash) {
			return ErrReused
		}
	}

	return nil
}

// retire records user.Password as the newest retired hash, keeping depth−1.
// A user with no current hash retires nothing.
func (r *reuseRule) retire(ctx context.Context, user *identity.Details) error {
	if len(user.Password) == 0 {
		return nil
	}

	if err := r.history.RetirePassword(ctx, user.ID, user.Password, r.depth-1); err != nil {
		return historyError(err)
	}

	return nil
}

// matches reports whether any matcher verifies candidate against hash. An
// absent hash matches nothing.
func (r *reuseRule) matches(candidate string, hash []byte) bool {
	if len(hash) == 0 {
		return false
	}

	for _, m := range r.matchers {
		if m.Match(candidate, hash) {
			return true
		}
	}

	return false
}

// defaultMatchers returns the built-in encoders at their defaults, used only
// to match: each reads the parameters from the stored hash. It leaves out the
// built-in of own's concrete type, since own already matches that algorithm and
// a second built-in Match would answer alike at the cost of another derivation.
func defaultMatchers(own Encoder) ([]Encoder, error) {
	builders := []struct {
		skip bool
		make func() (Encoder, error)
	}{
		{skip: isType[*Argon2idEncoder](own), make: func() (Encoder, error) { return NewArgon2idEncoder() }},
		{skip: isType[*BcryptEncoder](own), make: func() (Encoder, error) { return NewBcryptEncoder() }},
		{skip: isType[*ScryptEncoder](own), make: func() (Encoder, error) { return NewScryptEncoder() }},
	}

	matchers := make([]Encoder, 0, len(builders))
	for _, b := range builders {
		if b.skip {
			continue
		}

		m, err := b.make()
		if err != nil {
			return nil, err
		}

		matchers = append(matchers, m)
	}

	return matchers, nil
}

// isType reports whether enc's concrete type is T.
func isType[T Encoder](enc Encoder) bool {
	_, ok := enc.(T)
	return ok
}

// historyUnavailableText is ErrHistoryUnavailable's text, repeated here
// as the fixed text of the error a failed read or record returns.
const historyUnavailableText = "password: password history could not be read or written"

// historyError refuses a change whose history could not be read or recorded.
// Its text is ErrHistoryUnavailable's alone, so whatever the port put in its
// own error, a stored hash included, never reaches a response or a log line
// through the policy. Both ErrHistoryUnavailable and the port's error stay
// reachable through errors.Is and errors.As.
func historyError(cause error) error {
	return diag.Wrap(cause, historyUnavailableText, ErrHistoryUnavailable)
}

// ProvisionerWrite returns the default [WriteFunc] for [Policy.Change]: it
// calls provisioner.Update for user.Username with
// [identity.WithUserPasswordChange](hash, changedAt), naming the new hash and
// the time of the change and nothing else, and returns Update's error
// unchanged.
//
// This is the path on which a change records its time by default, so
// password-age policy sees every change made through the policy. It joins a
// transaction attached to ctx exactly when provisioner's Update does, so with a store
// that backs both the users and the [History], one transaction covers the
// retire and the write.
//
// A consumer whose users live in their own storage passes their own WriteFunc
// instead. One that ignores changedAt leaves the stored password-changed time
// as it was, and so gives up password-age policy for that user.
//
// A nil or typed-nil provisioner is refused here, at wiring time, with an error wrapping
// [ErrConfig]. The returned write refuses a nil user the same way and updates
// nothing.
func ProvisionerWrite(provisioner identity.UserProvisioner) (WriteFunc, error) {
	if nilcheck.IsNil(provisioner) {
		return nil, fmt.Errorf("%w: a user provisioner is required", ErrConfig)
	}

	return func(ctx context.Context, user *identity.Details, hash []byte, changedAt time.Time) error {
		if user == nil {
			return fmt.Errorf("%w: a user record is required", ErrConfig)
		}

		_, err := provisioner.Update(ctx, user.Username, identity.WithUserPasswordChange(hash, changedAt))

		return err
	}, nil
}
