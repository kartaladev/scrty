package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/password"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// Broker is the library's IdentityBroker. It resolves a verified external
// identity through a LinkStore keyed by provider, issuer and subject, loads
// the linked user by its user reference, and, where a consumer enabled it for
// the provider, provisions a user for an identity with no link.
//
// Build one with NewBroker. A Broker is safe for concurrent use.
type Broker struct {
	links   LinkStore
	users   identity.UserLoader
	log     *slog.Logger
	sampler *logsample.Sampler
	ids     id.Generator
	clock   clock.Clock

	// Provisioning, per provider. jitDomains tells "configured empty" from
	// "not configured" by the presence of the key.
	provisioner   identity.UserProvisioner
	jit           map[string]bool
	jitUnverified map[string]bool
	jitDomains    map[string][]string
	nameClaims    map[string]string
	defaultRole   string

	// Password-hash claims, per provider, and the band a mapped hash's cost
	// must lie in. passwordWarned records the (provider, reason) pairs already
	// logged at WARN.
	passwordClaims  map[string]string
	passwordEncoder password.Encoder
	passwordMinCost int
	passwordMaxCost int
	passwordWarned  sync.Map

	// mirrors records, per provider, whether claim mirroring is on.
	mirrors map[string]bool

	// Roles from claims, per provider. roleClaims, roleMappings and
	// allowedRoles tell "configured empty" from "not configured" by the
	// presence of the key.
	roleClaims   map[string]string
	roleMappings map[string]map[string]string
	allowedRoles map[string][]string
	roleSync     map[string]bool

	// providers is every provider an option named, in the order first named.
	providers []string
}

var _ IdentityBroker = (*Broker)(nil)

// NewBroker returns a broker that resolves identities through links and loads
// linked users through users.
//
// Both are required: a nil link store or user loader, including a nil pointer
// inside a non-nil interface, fails with ErrConfig and identity.ErrMissingPort
// naming the port. The library's in-memory link store is NewMemoryLinkStore.
// With no options the broker provisions no one (see WithJIT), logs to slog.Default(), reads
// time from clock.System() and draws link identifiers from id.NewV7Generator().
func NewBroker(links LinkStore, users identity.UserLoader, opts ...BrokerOption) (*Broker, error) {
	if nilcheck.IsNil(links) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("link store"))
	}
	if nilcheck.IsNil(users) {
		return nil, fmt.Errorf("%w: %w", ErrConfig, identity.MissingPort("user loader"))
	}

	b := &Broker{
		links: links, users: users,
		jit: map[string]bool{}, jitUnverified: map[string]bool{},
		jitDomains: map[string][]string{}, nameClaims: map[string]string{},
		passwordClaims: map[string]string{}, mirrors: map[string]bool{},
		roleClaims: map[string]string{}, roleMappings: map[string]map[string]string{},
		allowedRoles: map[string][]string{}, roleSync: map[string]bool{},
		passwordMinCost: defaultPasswordClaimMinCost, passwordMaxCost: defaultPasswordClaimMaxCost,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(b); err != nil {
			return nil, err
		}
	}

	if b.log == nil {
		b.log = slog.Default()
	}
	if b.clock == nil {
		b.clock = clock.System()
	}
	if b.ids == nil {
		b.ids = id.NewV7Generator()
	}
	b.sampler = logsample.New(refusalLogInterval, logsample.WithReporter(b.reportSuppressed))

	if err := b.checkProvisioning(); err != nil {
		return nil, err
	}
	if err := b.checkPasswordClaims(); err != nil {
		return nil, err
	}
	if err := b.checkMirroring(); err != nil {
		return nil, err
	}
	if err := b.checkRoles(); err != nil {
		return nil, err
	}
	return b, nil
}

// checkProvisioning refuses a provisioning configuration that could never
// apply as written: provisioning with nothing to create users through, or a
// gate for a provider that provisioning is not enabled for.
func (b *Broker) checkProvisioning() error {
	if len(b.jit) > 0 && b.provisioner == nil {
		return fmt.Errorf("%w: WithJIT: %w", ErrConfig, identity.MissingPort("user provisioner"))
	}
	for p := range b.jitUnverified {
		if !b.jit[p] {
			return fmt.Errorf("%w: WithJITAllowUnverifiedEmail names provider %q, which WithJIT does not enable",
				ErrConfig, p)
		}
	}
	for p := range b.jitDomains {
		if !b.jit[p] {
			return fmt.Errorf("%w: WithJITEmailDomains names provider %q, which WithJIT does not enable",
				ErrConfig, p)
		}
	}
	return nil
}

// nameProvider records that an option named provider.
func (b *Broker) nameProvider(provider string) {
	if !slices.Contains(b.providers, provider) {
		b.providers = append(b.providers, provider)
	}
}

// Broker returns the principal ext resolves to.
//
// An identity with no link is provisioned when the consumer enabled that for
// its provider; otherwise it fails with ErrNoLinkedAccount, as does a link
// whose user is missing, disabled or loads as another user, and a provisioned
// user the provisioner returns inactive, which is not linked. A refused
// provisioning fails with ErrProvisioningRefused. A link store, loader or
// provisioner failure is returned wrapped, and is not an authentication
// failure; its text has the login's subject, email (kept as its domain),
// username and user reference redacted.
func (b *Broker) Broker(ctx context.Context, ext ExternalIdentity) (*identity.Principal, error) {
	l, err := b.links.FindByExternal(ctx, ext.Provider, ext.Issuer, ext.Subject)
	switch {
	case errors.Is(err, ErrLinkNotFound):
		return b.provision(ctx, ext)
	case err != nil:
		return nil, fmt.Errorf("oidc: finding a link: %w",
			redact(err, identifying{subject: ext.Subject, emails: []string{ext.Email}}))
	case l == nil:
		b.refusal(ctx, slog.LevelWarn, "the link store returned no link and no error", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	}

	det, err := b.resolveLinked(ctx, ext, l)
	if err != nil {
		return nil, err
	}
	det = b.mirror(ctx, ext, l, det)
	return b.principalFor(ctx, ext, det), nil
}

// resolveLinked loads the user l, the link of ext, names, by its user
// reference.
func (b *Broker) resolveLinked(ctx context.Context, ext ExternalIdentity, l *Link) (*identity.Details, error) {
	det, err := b.users.LoadByUserID(ctx, l.UserID)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		b.refusal(ctx, slog.LevelWarn, "a link names a user that no longer exists", l.Provider, l.Email)
		return nil, ErrNoLinkedAccount
	case err != nil:
		return nil, fmt.Errorf("oidc: loading a linked user: %w", redact(err, identifying{
			subject: ext.Subject,
			emails:  []string{ext.Email, l.Email},
			names:   []string{l.Username, string(l.UserID)},
		}))
	case det == nil || det.ID != l.UserID:
		b.refusal(ctx, slog.LevelWarn, "a link resolved to another user", l.Provider, l.Email)
		return nil, ErrNoLinkedAccount
	case !det.Active:
		b.refusal(ctx, slog.LevelDebug, "a linked user is inactive", l.Provider, l.Email)
		return nil, ErrNoLinkedAccount
	}
	return det, nil
}

// Links returns the link store the broker was built with.
func (b *Broker) Links() LinkStore { return b.links }

// ConfiguredProviders returns every provider any option names, deduplicated,
// so NewManager can refuse one its registry does not hold. The returned slice
// is the caller's own.
func (b *Broker) ConfiguredProviders() []string { return slices.Clone(b.providers) }

// RoleSyncProviders returns the providers WithRoleSync turned on, sorted.
// The HTTP chain reads it to refuse role sync over a conveyance that would
// drop the synced roles. The returned slice is the caller's own.
func (b *Broker) RoleSyncProviders() []string {
	var providers []string
	for p, on := range b.roleSync {
		if on {
			providers = append(providers, p)
		}
	}
	slices.Sort(providers)
	return providers
}

// refusal logs one refusal through the sampler, naming the provider and the
// domain of the email, never the email itself, a subject or a reference.
func (b *Broker) refusal(ctx context.Context, level slog.Level, msg, provider, email string) {
	write, suppressed := b.sampler.Allow("oidc.broker:"+msg+":"+provider, b.clock.Now())
	if !write {
		return
	}
	b.log.LogAttrs(ctx, level, "oidc: "+msg,
		slog.String("provider", provider),
		slog.String("email_domain", emailDomain(email)),
		slog.Int("suppressed", suppressed))
}

// reportSuppressed writes the count of refusal records the sampler held back.
func (b *Broker) reportSuppressed(key string, suppressed int) {
	b.log.LogAttrs(context.Background(), slog.LevelInfo, "oidc broker refusals suppressed",
		slog.String("reason", key),
		slog.Int("suppressed", suppressed))
}

// FlushRefusalLogs reports every refusal record the broker's sampler has
// suppressed but not yet counted, then forgets every key, so the next
// refusal of a reason already reported is written again rather than held
// back. It always returns nil; the signature matches the shape
// authenticate.RefusalLogFlusher and policy.RefusalLogFlusher already use.
//
// It is safe to call at shutdown, including while logins are still in
// flight, and safe to call more than once: a second flush with nothing new
// pending reports nothing. Call it directly, or let
// httpsec.Chain.FlushRefusalLogs reach it through the OIDC login manager it
// was given (oidc.Manager.FlushRefusalLogs), when the manager's broker is
// this one.
func (b *Broker) FlushRefusalLogs() error {
	b.sampler.Flush()

	return nil
}

// bcryptShaped matches a bcrypt hash anywhere in a string.
var bcryptShaped = regexp.MustCompile(`\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}`)

// redactedMark replaces a redacted value in error text.
const redactedMark = "[redacted]"

// identifying names the values of the current login that must not reach logs
// or error text: the external subject, emails (kept as their domain), and
// usernames and user references. Empty values are skipped.
type identifying struct {
	subject string
	emails  []string
	names   []string // usernames and user references
}

// replacer returns the replacements for the values in v, longest first so a
// username that is part of an email does not break the email's replacement,
// or nil when v names nothing.
func (v identifying) replacer() *strings.Replacer {
	type pair struct{ old, repl string }
	var pairs []pair
	if v.subject != "" {
		pairs = append(pairs, pair{v.subject, redactedMark})
	}
	for _, e := range v.emails {
		if e != "" {
			pairs = append(pairs, pair{e, redactedMark + "@" + emailDomain(e)})
		}
	}
	for _, n := range v.names {
		if n != "" {
			pairs = append(pairs, pair{n, redactedMark})
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	slices.SortStableFunc(pairs, func(a, b pair) int { return len(b.old) - len(a.old) })
	args := make([]string, 0, 2*len(pairs))
	for _, p := range pairs {
		args = append(args, p.old, p.repl)
	}
	return strings.NewReplacer(args...)
}

// redact wraps err, an error from a consumer port, so its text has every
// bcrypt-shaped substring and every value v names replaced, while errors.Is
// and errors.As still reach the original. It is best effort: a caller that
// unwraps into a driver's own error type reads the original text, and a value
// the error spells differently (another letter case, say) is not matched.
func redact(err error, v identifying) error {
	if err == nil {
		return nil
	}
	return &redactedError{err: err, values: v.replacer()}
}

// redactedError is an error whose text has bcrypt-shaped substrings and the
// login's identifying values removed.
type redactedError struct {
	err    error
	values *strings.Replacer // nil when the login named no values
}

func (e *redactedError) Error() string {
	text := bcryptShaped.ReplaceAllString(e.err.Error(), redactedMark) //nolint:forbidigo // stated exception (design decision 6): the broker's own scrubbing of its cause's text
	if e.values != nil {
		text = e.values.Replace(text)
	}
	return text
}

func (e *redactedError) Unwrap() error { return e.err }
