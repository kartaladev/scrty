package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
)

// ErrUpstreamRequired is returned when a provider with a sign-in hook is
// brokered without the provider's upstream access, through Broker rather than
// BrokerUpstream. The hook is not called. It is a broker failure, not an
// authentication failure.
var ErrUpstreamRequired = errors.New("oidc: the provider's sign-in hook needs upstream access")

// SignInDecision is what a SignInHook decides: the user a verified identity
// belongs to, and the consumer's writes for that user.
//
// The decision itself writes nothing. The broker first checks it against the
// identity's link and the user store, links the identity, and only then runs
// Apply, so a decision the broker refuses leaves no trace.
type SignInDecision struct {
	// User is the user reference the identity belongs to. A decision naming
	// no user is a broker failure.
	User identity.UserID

	// Provision marks User as a reference that does not exist yet, which
	// Apply creates. The default, false, adopts an existing user only.
	Provision bool

	// Apply holds the consumer's writes for User, such as storing a password
	// hash fetched through Upstream. It is optional unless Provision is set,
	// and runs only after the broker accepted the decision and the link is
	// final. Its error is a broker failure.
	Apply func(ctx context.Context) error
}

// SignInHook decides which user a verified identity of one provider belongs
// to, on every login through that provider. ext is the verified identity, up
// the provider's upstream access for this callback, and linked the user the
// identity is already linked to, or empty when it has none.
//
// It returns a decision, or an error: ErrNoLinkedAccount or
// ErrProvisioningRefused refuses the login as that authentication failure;
// any other error fails it as a broker failure whose text is fixed: the
// error's own text reaches neither the caller nor a log, since it may quote
// the identity's subject or email or the access token, so a consumer who
// wants it logs it inside the hook. The error stays reachable through
// errors.As for concrete types the consumer declares. It runs within the
// request, bounded only by ctx.
type SignInHook func(ctx context.Context, ext ExternalIdentity, up Upstream, linked identity.UserID) (SignInDecision, error)

// WithBrokerSignInHook sets the sign-in hook that decides, for provider
// only, which user each verified identity belongs to. The default is no hook:
// an identity resolves through its link alone. A hooked provider is brokered
// through BrokerUpstream; Broker refuses it with ErrUpstreamRequired.
//
// A nil hook, an empty provider and a second hook for one provider are
// refused with ErrConfig. So is a hook on a provider that WithBrokerJIT,
// WithBrokerClaimMirror or WithBrokerRoleSync also turns on, since two writers
// of one user would contradict each other, and a hook over a link store that
// does not implement LinkLister, which the one-link-per-user rule needs,
// unless WithBrokerSignInHookAllowManyLinks lifts that rule for provider. A
// provider the relying party's registry does not hold is refused by
// NewRelyingParty.
func WithBrokerSignInHook(provider string, hook SignInHook) BrokerOption {
	return func(b *Broker) error {
		switch {
		case provider == "":
			return fmt.Errorf("%w: WithBrokerSignInHook was given an empty provider name", ErrConfig)
		case hook == nil:
			return fmt.Errorf("%w: WithBrokerSignInHook was given a nil hook for provider %q", ErrConfig, provider)
		}
		if _, taken := b.hooks[provider]; taken {
			return fmt.Errorf("%w: WithBrokerSignInHook was given a second hook for provider %q", ErrConfig, provider)
		}
		b.hooks[provider] = hook
		b.nameProvider(provider)
		return nil
	}
}

// WithBrokerSignInHookAllowManyLinks lets provider's sign-in hook link one
// user to more than one identity of the same provider and issuer. The default
// refuses a decision that would give a user a second such link. Allowing many
// links also removes the hook's need for a link store that implements
// LinkLister. An empty provider, or one with no WithBrokerSignInHook, is
// refused with ErrConfig.
func WithBrokerSignInHookAllowManyLinks(provider string) BrokerOption {
	return func(b *Broker) error {
		if provider == "" {
			return fmt.Errorf("%w: WithBrokerSignInHookAllowManyLinks was given an empty provider name", ErrConfig)
		}
		b.hookManyLinks[provider] = true
		b.nameProvider(provider)
		return nil
	}
}

// checkSignInHooks refuses a hook configuration that contradicts itself or
// another option (D6, D11): a second writer of the hooked provider's users
// (JIT provisioning, claim mirroring or role sync), a one-link rule the link
// store cannot enforce, or an allowance for a provider with no hook. Providers
// are checked in the order options named them, so the error is stable.
func (b *Broker) checkSignInHooks() error {
	_, lists := b.links.(LinkLister)
	for _, p := range b.providers {
		if _, hooked := b.hooks[p]; !hooked {
			if b.hookManyLinks[p] {
				return fmt.Errorf("%w: WithBrokerSignInHookAllowManyLinks names provider %q, which WithBrokerSignInHook does not hook",
					ErrConfig, p)
			}
			continue
		}
		var other string
		switch {
		case b.jit[p]:
			other = "WithBrokerJIT"
		case b.mirrors[p]:
			other = "WithBrokerClaimMirror"
		case b.roleSync[p]:
			other = "WithBrokerRoleSync"
		}
		if other != "" {
			return fmt.Errorf("%w: WithBrokerSignInHook and %s both write the users of provider %q",
				ErrConfig, other, p)
		}
		if !lists && !b.hookManyLinks[p] {
			return fmt.Errorf("%w: WithBrokerSignInHook for provider %q needs a link store with ListByUser (LinkLister) "+
				"to keep one link per user, or WithBrokerSignInHookAllowManyLinks(%q)", ErrConfig, p, p)
		}
	}
	return nil
}

var _ UpstreamBroker = (*Broker)(nil)

// BrokerUpstream returns the principal ext resolves to, given the provider's
// upstream access for this callback. RelyingParty.Callback calls it in place
// of Broker, since Broker implements UpstreamBroker.
//
// A provider with no sign-in hook resolves exactly as through Broker, and up
// is not read. A hooked provider's identity is looked up by provider, issuer
// and subject, and the hook is called with the linked user, or none; its
// decision is then checked before anything is written. A link store fault
// before the hook is a broker failure, never "no link", and the hook is not
// called.
func (b *Broker) BrokerUpstream(ctx context.Context, ext ExternalIdentity, up Upstream) (*identity.Principal, error) {
	hook, hooked := b.hooks[ext.Provider]
	if !hooked {
		return b.Broker(ctx, ext)
	}

	l, err := b.links.FindByExternal(ctx, ext.Provider, ext.Issuer, ext.Subject)
	// Before the ErrLinkNotFound check: a chain that cannot be walked is a
	// store fault, never "no link", which would hand the hook an unlinked
	// identity that is in fact linked.
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	var linked identity.UserID
	switch {
	case errors.Is(err, ErrLinkNotFound):
		l = nil
	case err != nil:
		return nil, fmt.Errorf("oidc: finding a link: %w", redact(err, hookIdentifying(ext, up, "")))
	case l == nil:
		b.refusal(ctx, slog.LevelWarn, "the link store returned no link and no error", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	case l.UserID == "":
		// An empty linked user would read to the hook as no link at all (F43).
		return nil, errLinkNamesNoUser
	default:
		linked = l.UserID
	}

	d, err := hook(ctx, ext, up, linked)
	if err != nil {
		return nil, b.hookError(ctx, ext, hookStageDecide, err)
	}
	if d.User == "" {
		return nil, errHookDecidedNoUser
	}
	return b.acceptDecision(ctx, ext, up, l, d)
}

// hookIdentifying names the values of a hooked login that must not reach
// error text or a log: the identity's subject and email, the user it is
// linked to, and the upstream access token.
func hookIdentifying(ext ExternalIdentity, up Upstream, linked identity.UserID) identifying {
	return identifying{
		subject: ext.Subject,
		emails:  []string{ext.Email},
		names:   []string{string(linked)},
		secrets: []string{up.AccessToken()},
	}
}

// acceptDecision checks the hook's decision d for ext, whose link is l (nil
// when it has none), links the identity, runs d.Apply and resolves the user
// (D5 steps 3 to 6, D11, D13). d.User is not empty.
//
// Until those steps are implemented it accepts nothing: every decision fails
// as a broker failure, before anything is written and without running Apply.
func (b *Broker) acceptDecision(_ context.Context, _ ExternalIdentity, _ Upstream, _ *Link, _ SignInDecision) (*identity.Principal, error) {
	return nil, errors.New("oidc: accepting a sign-in decision is not implemented")
}

// errLinkNamesNoUser is the broker failure of a link store that returned a
// link naming no user (F43). The hook is not called.
var errLinkNamesNoUser = errors.New("oidc: the link store returned a link naming no user")

// errHookDecidedNoUser is the broker failure of a decision that names no
// user and carries no error (F7). Nothing is written and Apply does not run.
var errHookDecidedNoUser = errors.New("oidc: the sign-in hook decided no user")

// hookStage names where a consumer's error came from, in fixed text.
type hookStage string

const (
	hookStageDecide hookStage = "the sign-in hook"
	hookStageApply  hookStage = "the sign-in decision's apply step"
)

// hookError classifies err, returned by a sign-in hook or its decision's
// apply step, for the login it failed (D10):
//
//   - an error whose chain cannot be walked is a broker failure with no
//     chain, never a refusal it might claim;
//   - from the hook only, ErrNoLinkedAccount and ErrProvisioningRefused
//     pass through as that bare sentinel: an authentication failure, with
//     none of the consumer's text;
//   - with the request's context done, the context's error, wrapped in fixed
//     text;
//   - anything else is a *hookFailure: a broker failure whose text is fixed,
//     so none of the consumer's text (which may quote the identity's subject
//     or email, the linked user or the upstream access token) reaches a
//     caller or a log, and whose chain no library outcome can be read from,
//     while the consumer's own error types stay reachable through errors.As.
//     A consumer who wants its own text logs it inside the hook.
func (b *Broker) hookError(ctx context.Context, ext ExternalIdentity, stage hookStage, err error) error {
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	if errors.Is(err, porterr.ErrUnwalkable) {
		return &hookFailure{text: "oidc: " + string(stage) + " failed with an error that could not be inspected"}
	}
	if stage == hookStageDecide {
		for _, sentinel := range []error{ErrNoLinkedAccount, ErrProvisioningRefused} {
			if errors.Is(err, sentinel) {
				b.refusal(ctx, slog.LevelDebug, "the sign-in hook refused the identity", ext.Provider, ext.Email)
				return sentinel
			}
		}
	}
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("oidc: %s stopped: %w", stage, cerr)
	}
	return &hookFailure{text: "oidc: " + string(stage) + " failed", cause: err}
}

// hookFailure is a broker failure carrying a consumer's error. Its text is
// fixed and never includes the consumer's.
//
// It has no Unwrap and no Is method, so neither errors.Is nor the library's
// own error walk reads a library outcome (ErrExchangeFailed, ErrFlowUnspent,
// ErrNoLinkedAccount, ...) the consumer's error happens to wrap. Its As method
// reaches the consumer's own concrete error types only: a target of
// interface type, or of a type the library defines, matches nothing, since
// either could hand back a chain holding a library outcome.
type hookFailure struct {
	text  string // fixed text naming the stage; never the cause's text
	cause error  // the consumer's error, its chain shown walkable; nil when it was not
}

func (e *hookFailure) Error() string { return e.text }

// Format writes the fixed text whatever the verb and flags, so no fmt verb,
// %#v included, reaches the consumer's error held in cause.
func (e *hookFailure) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.text) }

// As sets target to the first error in the consumer's chain assignable to it,
// as errors.As does, for a target that is a non-nil pointer to a concrete
// error type defined outside the library.
func (e *hookFailure) As(target any) bool {
	if e.cause == nil || target == nil {
		return false
	}
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	elem := v.Type().Elem()
	if elem.Kind() == reflect.Interface || !elem.Implements(errorType) || definedInLibrary(elem) {
		return false
	}
	return errors.As(e.cause, target)
}

// errorType is the reflect type of the error interface.
var errorType = reflect.TypeFor[error]()

// libraryModule is the import path every package of the library lies under.
const libraryModule = "github.com/kartaladev/scrty"

// definedInLibrary reports whether t, or the type it points to, is declared
// in a package of the library. An external test package ("…_test") is not
// library code, and a type declared there counts as the consumer's.
func definedInLibrary(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	pkg := t.PkgPath()
	if strings.HasSuffix(pkg, "_test") {
		return false
	}
	return pkg == libraryModule || strings.HasPrefix(pkg, libraryModule+"/")
}
