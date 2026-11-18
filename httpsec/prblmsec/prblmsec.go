package prblmsec

import (
	"errors"
	"fmt"

	"github.com/kartaladev/prblm"
)

// DefaultTypePrefix is the type prefix used when WithTypePrefix is not given.
const DefaultTypePrefix = "security"

// ErrConfig is wrapped by every error New returns for a nil option, a repeated
// option or an invalid prefix.
var ErrConfig = errors.New("prblmsec: invalid configuration")

// Problems answers scrty's refusals as problems. It does not change after New
// returns and is safe for concurrent use.
type Problems struct {
	prefix  string
	noToken bool
	types   []*prblm.Type
	bySub   map[string]*prblm.Type
}

type config struct {
	prefix     string
	prefixSet  bool
	noToken    bool
	noTokenSet bool
}

// Option configures New.
type Option func(*config) error

// WithTypePrefix replaces the default type prefix, "security", under which
// every problem type is defined. The prefix must be a valid prblm sub-type,
// which may be nested, such as "auth/v1"; New refuses any other. Giving the
// option twice is refused.
func WithTypePrefix(prefix string) Option {
	return func(c *config) error {
		if c.prefixSet {
			return fmt.Errorf("%w: WithTypePrefix given twice", ErrConfig)
		}
		c.prefix, c.prefixSet = prefix, true
		return nil
	}
}

// WithoutChallengeToken stops the integration from putting a challenge's
// access token in the problem. By default the token is included. Giving the
// option twice is refused.
func WithoutChallengeToken() Option {
	return func(c *config) error {
		if c.noTokenSet {
			return fmt.Errorf("%w: WithoutChallengeToken given twice", ErrConfig)
		}
		c.noToken, c.noTokenSet = true, true
		return nil
	}
}

// New builds the integration. It returns an error wrapping ErrConfig, and a
// nil *Problems, for a nil or repeated option or an invalid type prefix.
func New(opts ...Option) (*Problems, error) {
	cfg := config{prefix: DefaultTypePrefix}
	for i, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("%w: option %d is nil", ErrConfig, i)
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	types, bySub, err := defineTypes(cfg.prefix)
	if err != nil {
		return nil, err
	}
	return &Problems{prefix: cfg.prefix, noToken: cfg.noToken, types: types, bySub: bySub}, nil
}

// defineTypes builds the type table under prefix. prblm.DefineType owns the
// grammar of a valid sub-type and panics on a bad one; that panic is the only
// thing recovered, and it becomes ErrConfig.
func defineTypes(prefix string) (types []*prblm.Type, bySub map[string]*prblm.Type, err error) {
	defer func() {
		if r := recover(); r != nil {
			types, bySub = nil, nil
			err = fmt.Errorf("%w: type prefix %q: %v", ErrConfig, prefix, r)
		}
	}()
	types = make([]*prblm.Type, 0, len(typeTable))
	bySub = make(map[string]*prblm.Type, len(typeTable))
	for _, row := range typeTable {
		t := prblm.DefineType(prefix+"/"+row.sub, row.status, row.title, row.description)
		types = append(types, t)
		bySub[row.sub] = t
	}
	return types, bySub, nil
}

// Types returns the problem type definitions, under the configured prefix, for
// prblm's discovery. Each call returns a new slice.
func (p *Problems) Types() []*prblm.Type {
	return append([]*prblm.Type(nil), p.types...)
}

// Option returns the prblm option that registers the type definitions and the
// mapper together, so both use the same prefix. The handler it is given to
// needs a namespace (prblm.WithNamespace).
func (p *Problems) Option() prblm.Option {
	types, mappers := prblm.WithTypes(p.Types()...), prblm.WithMappers(p.Mapper())
	return func(h *prblm.Handler) {
		types(h)
		mappers(h)
	}
}
