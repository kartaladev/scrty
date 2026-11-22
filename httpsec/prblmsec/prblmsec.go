package prblmsec

import (
	"errors"
	"fmt"

	"github.com/kartaladev/prblm"
)

// DefaultTypePrefix is the type prefix every problem type is defined under
// when WithTypePrefix is not given: the default types are "security/<name>",
// such as "security/access-denied", resolved against the prblm handler's
// namespace.
const DefaultTypePrefix = "security"

// ErrConfig is wrapped by every error New returns: for a nil option, an option
// given twice, a type prefix that is not a valid prblm sub-type, or an
// extension member name prblm refuses. An invalid prefix's error names the
// prefix as written.
var ErrConfig = errors.New("prblmsec: invalid configuration")

// Problems answers scrty's refusals as RFC 9457 problems through prblm.
//
// A *Problems comes only from New. A nil *Problems is not usable: Mapper,
// Types and Option panic on it at once, when the handler is wired, before any
// traffic. A zero value built without New registers no types and its mapper
// maps nothing, leaving every error to the handler's later mappers.
//
// It does not change after New returns and is safe for concurrent use by any
// number of handlers and requests.
type Problems struct {
	noToken  bool
	types    []*prblm.Type
	byStatus map[int]*statusTypes
}

type config struct {
	prefix     string
	prefixSet  bool
	noToken    bool
	noTokenSet bool
}

// Option configures New: it is how a consumer replaces one of the
// integration's defaults. It is not a prblm.Option; the prblm option that
// registers the integration with a prblm handler is returned by the
// Problems.Option method.
type Option func(*config) error

// WithTypePrefix replaces the default type prefix, DefaultTypePrefix
// ("security"), under which every problem type is defined, for the mapper and
// for discovery alike. The prefix must be a valid prblm sub-type, which may be
// nested, such as "auth/v1"; New refuses any other with ErrConfig, as it
// refuses the option given twice.
func WithTypePrefix(prefix string) Option {
	return func(c *config) error {
		if c.prefixSet {
			return fmt.Errorf("%w: WithTypePrefix given twice", ErrConfig)
		}
		c.prefix, c.prefixSet = prefix, true
		return nil
	}
}

// WithoutChallengeToken withholds a challenge's access token. By default a
// challenge problem whose *httpsec.ChallengeError carries a Token delivers it
// as the access_token member, with token_type when the challenge names the
// token's type, and sets Cache-Control: no-store on the response. With this
// option no problem carries either member, and the rest of the problem is
// unchanged. Use it for cookie-only deployments, for a consumer who delivers
// the token another way, or where prblm hooks (OnError, AddErrorHook) log
// problem extensions: a hook sees the access_token member of every problem it
// is given. New refuses the option given twice with ErrConfig.
func WithoutChallengeToken() Option {
	return func(c *config) error {
		if c.noTokenSet {
			return fmt.Errorf("%w: WithoutChallengeToken given twice", ErrConfig)
		}
		c.noToken, c.noTokenSet = true, true
		return nil
	}
}

// New builds the integration with the defaults (the prefix
// DefaultTypePrefix, and the challenge token delivered) and opts applied in
// order. It returns an error wrapping ErrConfig, and a nil *Problems, for a nil
// option, an option given twice or an invalid type prefix, so a wiring mistake
// fails at construction, never at the first refusal. It never panics.
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
	if err := checkMembers(); err != nil {
		return nil, fmt.Errorf("%w: extension member: %w", ErrConfig, err)
	}
	return &Problems{
		noToken:  cfg.noToken,
		types:    types,
		byStatus: groupByStatus(bySub),
	}, nil
}

// defineTypes builds the type table under prefix. prblm.DefineType owns the
// grammar of a valid sub-type and panics on a bad one; that panic is the only
// thing recovered, and it becomes ErrConfig.
func defineTypes(prefix string) (types []*prblm.Type, bySub map[string]*prblm.Type, err error) {
	defer func() {
		if r := recover(); r != nil {
			types, bySub = nil, nil
			err = fmt.Errorf("%w: type prefix %q is not a valid prblm sub-type (%v)", ErrConfig, prefix, r)
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
// prblm.WithTypes and prblm's discovery: one for every type the mapper can
// produce. Each call returns a new slice; the definitions themselves are
// immutable and shared.
func (p *Problems) Types() []*prblm.Type {
	p.mustBeBuilt()
	return append([]*prblm.Type(nil), p.types...)
}

// Option returns the prblm.Option that registers the integration with a prblm
// handler: the type definitions (prblm.WithTypes) and the mapper
// (prblm.WithMappers) together, so both use the same prefix. It is unrelated to
// the Option type, which configures New.
//
// Option registers the mapper where it appears among the handler's options; it
// does not move it ahead of any. Give it to prblm.NewHandler (or to prblm's
// framework adapters) before the application's own mappers: prblm runs mappers
// in registration order, so a mapper registered ahead of it that matches one of
// scrty's refusals answers that refusal instead. That is also how a consumer
// replaces a single problem on purpose.
//
// The handler needs a namespace (prblm.WithNamespace). Without one, types are
// sent relative and prblm reports prblm.ErrInvalidType to its hooks.
//
// A consumer port (a user store, a verifier, any dependency scrty calls) must
// not return a *prblm.Problem or a prblm.Describer, nor wrap one: prblm
// answers a describer in the error chain before any mapper, so its problem
// would replace the integration's, and could tell apart refusals whose status
// is shared to conceal them, such as an outage and a wrong password. Nor may a
// port return an error wrapping one of scrty's own refusal sentinels (such as
// authorize.ErrAccessDenied or lockout.ErrAccountLocked): that can steer which
// type a refusal gets within its status.
func (p *Problems) Option() prblm.Option {
	p.mustBeBuilt()
	types, mappers := prblm.WithTypes(p.Types()...), prblm.WithMappers(p.Mapper())
	return func(h *prblm.Handler) {
		types(h)
		mappers(h)
	}
}
