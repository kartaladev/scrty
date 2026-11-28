package admin

import (
	"fmt"

	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/id"
)

//go:generate mockgen -destination=idgenerator_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/pkg/id Generator
//go:generate mockgen -destination=history_mock_test.go -package=admin_test -typed github.com/kartaladev/scrty/authenticate/password History

// The defaults of NewUsers. Each is replaceable by the option named beside it.
const (
	// DefaultPageSize is the page size of a list that names none (WithPageSize).
	DefaultPageSize = 50
	// DefaultMaxPageSize is the largest page a list may ask for (WithPageSize).
	DefaultMaxPageSize = 500
	// DefaultMaxListOffset is the largest offset a list may skip
	// (WithMaxListOffset).
	DefaultMaxListOffset = 10_000
	// DefaultAttributeNameBytes bounds an attribute name (WithAttributeLimits).
	DefaultAttributeNameBytes = 64
	// DefaultAttributeValueBytes bounds an attribute value (WithAttributeLimits).
	DefaultAttributeValueBytes = 1024
	// DefaultAttributeCount bounds the attributes of one user (WithAttributeLimits).
	DefaultAttributeCount = 64
)

// UsersOption configures NewUsers. The options of this file, WithPageSize to
// WithIDGenerator, are UsersOptions; every Option, such as WithEventSink, is
// one too.
type UsersOption interface {
	applyUsers(c *usersConfig) error
}

// usersOption is a UsersOption only NewUsers accepts.
type usersOption func(*usersConfig) error

func (o usersOption) applyUsers(c *usersConfig) error {
	if o == nil {
		return nil
	}

	return o(c)
}

type usersConfig struct {
	common
	attributeLimits

	pageDefault, pageMax int
	// offsetMax bounds UserFilter.Offset; offsetGiven records that
	// WithMaxListOffset set it, which a store without UserPager cannot honour.
	offsetMax   int
	offsetGiven bool
	encoder     password.Encoder
	policy      *password.Policy
	ids         id.Generator
	revoker     SessionRevoker
}

// attributeLimits are the bounds on profile attributes Users and Importer
// enforce.
type attributeLimits struct {
	attrNameBytes, attrValueBytes, attrN int
}

func defaultAttributeLimits() attributeLimits {
	return attributeLimits{
		attrNameBytes: DefaultAttributeNameBytes, attrValueBytes: DefaultAttributeValueBytes, attrN: DefaultAttributeCount,
	}
}

// AttributeLimitsOption is the option WithAttributeLimits returns. Both
// NewUsers and NewImporter accept it, so the two enforce the same bounds.
type AttributeLimitsOption func(*attributeLimits) error

func (o AttributeLimitsOption) applyUsers(c *usersConfig) error {
	return o.apply(&c.attributeLimits)
}

func (o AttributeLimitsOption) applyImporter(c *importerConfig) error {
	return o.apply(&c.attributeLimits)
}

func (o AttributeLimitsOption) apply(l *attributeLimits) error {
	if o == nil {
		return nil
	}

	return o(l)
}

// WithPageSize sets the page size of a list that names none, and the largest
// page it may name. Both must be at least one and def must not exceed maxSize, or
// NewUsers fails with an error matching ErrConfig.
//
// Default: DefaultPageSize and DefaultMaxPageSize.
func WithPageSize(def, maxSize int) UsersOption {
	return usersOption(func(c *usersConfig) error {
		if def < 1 || maxSize < 1 || def > maxSize {
			return fmt.Errorf("%w: page sizes need 1 <= default <= maximum", ErrConfig)
		}

		c.pageDefault, c.pageMax = def, maxSize

		return nil
	})
}

// WithAttributeLimits sets the bounds on profile attributes: the bytes of a
// name, the bytes of a value, and the attributes of one user. Each must be at
// least one, or the constructor fails with an error matching ErrConfig. The
// bounds belong to the service: a store behind it may hold more. NewUsers and
// NewImporter both accept the option; give it to both so an imported user can
// be edited afterwards.
//
// Default: DefaultAttributeNameBytes, DefaultAttributeValueBytes and
// DefaultAttributeCount.
func WithAttributeLimits(nameBytes, valueBytes, count int) AttributeLimitsOption {
	return func(c *attributeLimits) error {
		if nameBytes < 1 || valueBytes < 1 || count < 1 {
			return fmt.Errorf("%w: attribute limits must be at least one", ErrConfig)
		}

		c.attrNameBytes, c.attrValueBytes, c.attrN = nameBytes, valueBytes, count

		return nil
	}
}

// WithPasswordEncoder sets the encoder SetPassword hashes a new password with,
// by building the default policy with it (password.WithEncoder), whatever the
// order of the options; that policy also refuses a password longer than the
// encoder's stated input limit before any hashing. A nil encoder fails
// NewUsers with an error matching ErrConfig.
//
// The policy is what encodes, so this option cannot be combined with
// WithPasswordPolicy: giving both fails NewUsers with an error matching
// ErrConfig rather than ignore the encoder. With a policy of your own, build
// it with password.WithEncoder instead; when it has a reuse rule
// (password.NoReuse), that is also the encoder its rule matches stored hashes
// with, so a hash of a consumer's own encoding is detected on reuse.
//
// Default: password.NewArgon2idEncoder at its defaults.
func WithPasswordEncoder(encoder password.Encoder) UsersOption {
	return usersOption(func(c *usersConfig) error {
		if nilcheck.IsNil(encoder) {
			return fmt.Errorf("%w: password encoder is nil", ErrConfig)
		}

		c.encoder = encoder

		return nil
	})
}

// WithPasswordPolicy sets the policy SetPassword changes a password through
// (password.Policy.Change): its rules check the new password, its encoder
// hashes it, and its reuse rule, when it has one, retires the replaced hash
// through the consumer's history and prunes it to the rule's depth. The store
// writes only the new hash and the change time, which is WithClock's. A nil
// policy fails NewUsers with an error matching ErrConfig, and so does giving
// WithPasswordEncoder too: build the policy with password.WithEncoder instead,
// which is also the encoder its reuse rule matches stored hashes with.
//
// Default: password.NewPolicy(password.WithEncoder(e), password.WithClock(c)),
// where e is the configured encoder and c the service clock; it has no reuse
// rule, so no history is recorded.
func WithPasswordPolicy(policy *password.Policy) UsersOption {
	return usersOption(func(c *usersConfig) error {
		if policy == nil {
			return fmt.Errorf("%w: password policy is nil", ErrConfig)
		}

		c.policy = policy

		return nil
	})
}

// WithIDGenerator sets the generator of user identifiers. A nil generator fails
// NewUsers with an error matching ErrConfig. The identifier is stored in a
// column of the store's type: the default store's is a UUID, which the default
// generator's text form satisfies.
//
// Default: id.NewV7Generator.
func WithIDGenerator(generator id.Generator) UsersOption {
	return usersOption(func(c *usersConfig) error {
		if nilcheck.IsNil(generator) {
			return fmt.Errorf("%w: identifier generator is nil", ErrConfig)
		}

		c.ids = generator

		return nil
	})
}

// WithSessionRevocation makes Update end every session of a user whose
// username it changed: after the store commits an update that names a username
// and for which UserStore.UpdateUser reports renamed, Update calls
// r.DeleteByUser with the user's identifier, on the caller's context. An update
// that names no username, re-sends the current one byte for byte, or fails or
// is refused, revokes nothing, even when a store reports renamed for an update
// naming no username, so a profile form that sends every field on each
// save does not sign the user out.
//
// *session.Sessions satisfies SessionRevoker as it is: its DeleteByUser
// removes the user's sessions and the refresh families kept with them. Give
// NewUsers the same *session.Sessions the application signs users in with.
//
// When the revocation fails, the update stays committed and its event and
// audit record are delivered: Update returns the renamed user together with an
// error matching ErrSessionsNotRevoked that wraps the cause (the revoker's
// error, or the context's when it was cancelled after the store committed), so
// the caller can retry the revocation.
//
// The revoker runs when the store returns, not when a transaction the caller
// holds commits. A caller that wraps updates in its own transaction, which
// scrty's stores join, leaves this option out and revokes the sessions itself
// after its own commit; otherwise a later rollback leaves the sessions ended
// for a rename that never happened.
//
// A nil revoker, typed nil included, fails NewUsers with an error matching
// ErrConfig.
//
// Default: no revoker; a rename ends no session. Sessions are keyed by the user
// identifier, which a rename does not change.
func WithSessionRevocation(r SessionRevoker) UsersOption {
	return usersOption(func(c *usersConfig) error {
		if nilcheck.IsNil(r) {
			return fmt.Errorf("%w: session revoker is nil; leave admin.WithSessionRevocation out to revoke nothing", ErrConfig)
		}

		c.revoker = r

		return nil
	})
}

// WithMaxListOffset sets the largest UserFilter.Offset a list may name,
// inclusive; a larger offset is refused with ErrInvalidInput before the store
// is called. The bound limits the cost of a deep offset page, which a store
// reads and discards row by row. Zero allows only the first page; a negative
// bound fails NewUsers with an error matching ErrConfig, and so does giving the
// option over a store that does not implement UserPager, since the bound could
// never apply there.
//
// Default: DefaultMaxListOffset.
func WithMaxListOffset(n int) UsersOption {
	return usersOption(func(c *usersConfig) error {
		if n < 0 {
			return fmt.Errorf("%w: the maximum list offset must not be negative", ErrConfig)
		}

		c.offsetMax, c.offsetGiven = n, true

		return nil
	})
}
