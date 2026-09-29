package password

import (
	"context"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// ReuseGuard refuses a new password that matches the user's current one or one
// of their recent ones, and records the password it replaces.
//
// Nothing checks or records password history until a consumer builds a guard
// and calls it from their own password-change code, with the plaintext they
// already hold. The guard is not wired into any store or endpoint on its own:
// a store cannot tell a local change from a password mirrored from an identity
// provider, and checking a mirror would fail a federated login.
//
// With depth N the guard compares the candidate against the user's current
// hash and their N−1 most recent retired hashes, so N = 1 refuses only
// "changing" to the same password. It compares by verifying the candidate
// against each stored hash, never by encoding it again, since every hash
// carries its own salt.
//
// The guard fails closed: a history it cannot read or record refuses the
// change with [ErrHistoryUnavailable]. It writes no log record, and it does not
// keep the candidate after a call returns.
//
// It does not serialise two changes of one user. Two changes submitted at the
// same instant both pass the check, the last write wins, and the losing new
// password is never retired. Only that user can use this, and only to reuse a
// password they chose moments earlier.
//
// A ReuseGuard is safe for concurrent use.
type ReuseGuard struct {
	history  History
	enc      Encoder
	matchers []Encoder // enc first, then the extras
	depth    int
	now      func() time.Time
}

// ReuseOption configures a [ReuseGuard].
type ReuseOption func(*reuseConfig)

type reuseConfig struct {
	extras    []Encoder
	extrasSet bool // WithReuseMatchers was applied, replacing the default extras
	now       func() time.Time
}

// NewReuseGuard returns a guard that refuses the user's current password and
// their depth−1 most recent retired ones, reading and recording them through h.
// enc encodes the new password on [ReuseGuard.Change], and is always the first
// matcher.
//
// By default the other matchers are the library's Argon2id, bcrypt and scrypt
// encoders, less the one of enc's own algorithm: enc already matches those
// hashes, and a second built-in would only derive the same key again. So a
// stored hash of a built-in algorithm, or of enc's own, costs exactly one key
// derivation per check. [WithReuseMatchers] replaces the defaults, and its
// matchers are used as given, never left out.
//
// depth is required and has no default: published guidance ranges from no
// history at all to 24 passwords, and a library default would present one of
// them as the right answer. There is no upper bound; a large depth costs one
// key derivation per stored hash on every change, run one after another
// rather than in parallel, so peak memory stays at one derivation's cost.
// With Argon2id at 64 MiB and a depth of 24, a change can still take over a
// second: the cost falls on a rare, authenticated action, not on login.
//
// A nil or typed-nil h, enc or matcher, a depth below one, or a nil clock is
// refused with an error wrapping [ErrConfig] that names the mistake.
func NewReuseGuard(h History, enc Encoder, depth int, opts ...ReuseOption) (*ReuseGuard, error) {
	if nilcheck.IsNil(h) {
		return nil, fmt.Errorf("%w: a password history port is required", ErrConfig)
	}

	if nilcheck.IsNil(enc) {
		return nil, fmt.Errorf("%w: an encoder is required", ErrConfig)
	}

	if depth < 1 {
		return nil, fmt.Errorf("%w: the reuse depth must be at least 1", ErrConfig)
	}

	cfg := reuseConfig{now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	for _, m := range cfg.extras {
		if nilcheck.IsNil(m) {
			return nil, fmt.Errorf("%w: a reuse matcher is nil", ErrConfig)
		}
	}

	if cfg.now == nil {
		return nil, fmt.Errorf("%w: the reuse clock is nil", ErrConfig)
	}

	extras := cfg.extras
	if !cfg.extrasSet {
		var err error
		if extras, err = defaultMatchers(enc); err != nil {
			return nil, err
		}
	}

	return &ReuseGuard{
		history:  h,
		enc:      enc,
		matchers: append([]Encoder{enc}, extras...),
		depth:    depth,
		now:      cfg.now,
	}, nil
}

// WithReuseMatchers replaces the extra matchers a [ReuseGuard] verifies stored
// hashes with. The guard's own encoder is always one of the matchers, whatever
// this option says.
//
// Default: the library's Argon2id, bcrypt and scrypt encoders, used only to
// match, less the one of the guard encoder's own algorithm. Each reads its
// parameters from the stored hash, so a hash any of them ever wrote matches,
// whatever its cost; a guard that stopped seeing history after an algorithm
// migration would fail open.
//
// Pass the encoders of any algorithm of your own that wrote stored hashes.
// They are used as given, even one of the guard encoder's own type, since a
// consumer encoder's Match may depend on its own configuration.
// Calling it with no encoders leaves only the guard's own encoder. A nil
// encoder is refused by [NewReuseGuard] with [ErrConfig].
func WithReuseMatchers(encs ...Encoder) ReuseOption {
	encs = append([]Encoder(nil), encs...)

	return func(c *reuseConfig) {
		c.extras = encs
		c.extrasSet = true
	}
}

// WithReuseClock replaces the clock [ReuseGuard.Change] reads the time of the
// change from, which it hands to the [WriteFunc].
//
// Default: [time.Now]. A nil clock is refused by [NewReuseGuard] with
// [ErrConfig].
func WithReuseClock(now func() time.Time) ReuseOption {
	return func(c *reuseConfig) { c.now = now }
}

// Check refuses candidate with [ErrPasswordReused] when it matches user.Password
// or one of the depth−1 most recent retired hashes of user.ID.
//
// A user with no current hash (nil or empty) matches nothing on that count,
// which is not an error. With depth 1 history is not read at all. A history
// that cannot be read refuses with [ErrHistoryUnavailable]; a nil user is an
// error wrapping [ErrConfig], and nothing is read.
//
// Check alone records nothing. [ReuseGuard.Change] runs it and then records
// the replaced hash in the order that keeps every failure on the safe side.
func (g *ReuseGuard) Check(ctx context.Context, user *identity.Details, candidate string) error {
	if user == nil {
		return fmt.Errorf("%w: a user record is required", ErrConfig)
	}

	var retired [][]byte
	if n := g.depth - 1; n > 0 {
		var err error
		if retired, err = g.history.RecentPasswords(ctx, user.ID, n); err != nil {
			return historyError(err)
		}
	}

	if g.matches(candidate, user.Password) {
		return ErrPasswordReused
	}

	for _, hash := range retired {
		if g.matches(candidate, hash) {
			return ErrPasswordReused
		}
	}

	return nil
}

// matches reports whether any matcher verifies candidate against hash. An
// absent hash matches nothing.
func (g *ReuseGuard) matches(candidate string, hash []byte) bool {
	if len(hash) == 0 {
		return false
	}

	for _, m := range g.matchers {
		if m.Match(candidate, hash) {
			return true
		}
	}

	return false
}

// Change replaces user's password with candidate, refusing a recent one. It
// runs these steps and stops at the first failure:
//
//  1. read the user's recent history; a failure refuses with
//     [ErrHistoryUnavailable] and nothing is written;
//  2. check for reuse, as [ReuseGuard.Check] does; a match refuses with
//     [ErrPasswordReused];
//  3. retire user.Password, keeping only the newest depth−1 retired hashes; a
//     failure refuses with [ErrHistoryUnavailable] and the password is
//     unchanged. A user with no current hash retires nothing;
//  4. encode candidate with the guard's encoder; an encoder error, such as
//     [ErrPasswordTooLong], is returned as is;
//  5. call write with user, the new hash and the time from the guard's clock,
//     and return its error unchanged.
//
// Retiring comes before writing, so every failure before step 5 leaves the
// password untouched. If write fails, the retired entry stays; it holds the
// hash that is still current, and retiring the same bytes again adds nothing,
// so a retry is not refused and does not count the password twice. With the
// default identity store backing both the user and the history, run Change
// with [ProvisionerWrite](store) inside one transaction attached to ctx with
// the store's WithTx (or a configured WithTxResolver), so the retire, the
// prune it carries and the write commit or roll back together.
//
// The one record keys everything: user.ID keys the history, user.Password is
// the current hash, and write receives the same pointer. A nil user or a nil
// write is an error wrapping [ErrConfig], and nothing is read or written.
//
// To record the change time with an [identity.UserProvisioner], pass
// [ProvisionerWrite]. A write that ignores the time it is handed leaves the
// stored password-changed time as it was, which exempts the user from
// password-age policy.
func (g *ReuseGuard) Change(ctx context.Context, user *identity.Details, candidate string, write WriteFunc) error {
	if write == nil {
		return fmt.Errorf("%w: a write function is required", ErrConfig)
	}

	if err := g.Check(ctx, user, candidate); err != nil {
		return err
	}

	if len(user.Password) > 0 {
		if err := g.history.RetirePassword(ctx, user.ID, user.Password, g.depth-1); err != nil {
			return historyError(err)
		}
	}

	hash, err := g.enc.Encode(candidate)
	if err != nil {
		return err
	}

	return write(ctx, user, hash, g.now())
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
		{skip: isType[*argon2idEncoder](own), make: func() (Encoder, error) { return NewArgon2idEncoder() }},
		{skip: isType[*bcryptEncoder](own), make: func() (Encoder, error) { return NewBcryptEncoder() }},
		{skip: isType[*scryptEncoder](own), make: func() (Encoder, error) { return NewScryptEncoder() }},
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
// through the guard. Both ErrHistoryUnavailable and the port's error stay
// reachable through errors.Is and errors.As.
func historyError(cause error) error {
	return diag.Wrap(cause, historyUnavailableText, ErrHistoryUnavailable)
}
