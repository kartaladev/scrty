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
	encoder              password.Encoder
	policy               *password.Policy
	ids                  id.Generator
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
func WithIDGenerator(g id.Generator) UsersOption {
	return usersOption(func(c *usersConfig) error {
		if nilcheck.IsNil(g) {
			return fmt.Errorf("%w: identifier generator is nil", ErrConfig)
		}

		c.ids = g

		return nil
	})
}
