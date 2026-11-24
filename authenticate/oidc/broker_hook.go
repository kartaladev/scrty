package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/idgen"
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
// The decision itself writes nothing. The broker accepts it in this order,
// and refuses it at the first step that fails:
//
//  1. checks, with nothing written: a link the identity already has must name
//     User; User must load with that reference and be active; and, unless
//     WithBrokerSignInHookAllowManyLinks allows it, User must have no link
//     from another subject of the same provider and issuer, whether the
//     identity is linked already or not;
//  2. the identity is linked to User, unless its link already names User;
//  3. Apply runs, after the link is inserted and confirmed; a concurrent
//     sign-in may still remove that link, so it is not yet final;
//  4. User is loaded again, must still be active, and is the login's
//     principal.
//
// A decision the broker refuses therefore runs no Apply and leaves no trace:
// that covers a link to another user, a lost race, a second link and a
// missing or inactive user, all refused as ErrNoLinkedAccount.
//
// A decision with Provision set runs the same steps for a user that does not
// exist yet (see Provision): step 1 requires User not to load instead, the
// link of step 2 comes before the user exists, Apply creates the user in
// step 3, and step 4 requires it to exist.
type SignInDecision struct {
	// User is the user reference the identity belongs to. A decision naming
	// no user is a broker failure.
	User identity.UserID

	// Provision marks User as a reference that does not exist yet, which
	// Apply creates: a first sign-in through the provider that creates its
	// user, under a reference the hook chose, such as a fresh UUID. The
	// default, false, adopts an existing user only.
	//
	// The reference must be fresh: named by no link of another identity, of
	// this provider or any other. A user that another identity's link names
	// is refused as ErrNoLinkedAccount, whether or not it exists yet, since
	// provisioning would give this identity access to what that identity
	// reaches. A link store that implements LinkLister is checked before
	// anything is written, and, when it also implements LinkRemover, again
	// after this sign-in's own link is inserted: of two identities racing to
	// provision one reference, a sign-in that then finds the other's link
	// removes its own and is refused, so at most one keeps a link (both may
	// be refused; the next sign-in succeeds). A store that does not
	// (possible only under WithBrokerSignInHookAllowManyLinks) is not
	// checked, or not re-checked, so a hook there must choose references
	// that are fresh. Freshness is checked on a first provisioning, and
	// on a resume only while the user does not load: once the identity's own
	// link names the reference, provisioning it again resumes, and when the
	// user exists a link another identity gained to it since, such as another
	// provider's hook adopting it, does not refuse the resume. While the user
	// is still absent, another identity's link to it refuses the resume, so
	// two identities never share one pending user. The one-link rule still
	// applies to a resume.
	//
	// References must be fresh values that no other writer can produce,
	// such as a new random UUID: the broker cannot tell a user that another
	// writer creates under the reference, between its checks and Apply, from
	// a resume. On a first sign-in Apply must therefore create the user
	// only, failing when it already exists; then such a sign-in fails as a
	// broker failure and the link stays for an operator. Only a resume, a
	// sign-in through the identity's own link, may meet a user that already
	// exists. admin.Importer creates or updates, so it is not create-only on
	// its own: an Apply built on it should at least fail on an outcome other
	// than admin.ImportCreated, though the existing user is updated by then.
	//
	// Provisioning never adopts. Apply is required; without it the login is
	// a broker failure and nothing is written. User must not load
	// (identity.ErrUserNotFound): a user that loads is refused as
	// ErrNoLinkedAccount, unless the identity's own link already names it,
	// and a loader fault is a broker failure. A link of the identity to
	// another user, and the one-link-per-user rule, refuse it as they refuse
	// any decision.
	//
	// The identity is linked to User before Apply runs, with an empty
	// username, since no user exists yet to name; the username of a link is
	// for operators and is never a lookup key. Linking first is what keeps
	// two racing first sign-ins of one identity, which choose two
	// references, from both creating a user: only one link insert wins, and
	// the other login is refused before its Apply runs.
	//
	// When Apply fails, or returns without creating User, the login is a
	// broker failure and the link stays. On a later sign-in the hook receives
	// User as linked, and deciding to provision it again resumes: no link is
	// inserted, and Apply runs again, so it must be safe to repeat. A user
	// that Apply leaves inactive, or that loads as another user, is refused
	// as ErrNoLinkedAccount, and the link stays. A user that exists through
	// the identity's own link must be active before Apply runs again.
	Provision bool

	// Apply holds the consumer's writes for User, such as storing a password
	// hash fetched through Upstream. It is optional unless Provision is set,
	// and runs only after the broker accepted the decision and the link was
	// inserted and confirmed, so it writes only for the user the login resolves to; it should
	// close over User, not over a user its own lookup found. It runs within
	// the request, bounded only by ctx.
	//
	// Its error fails the login as a broker failure with fixed text, as a
	// hook's error does, and the link stays: the next sign-in decides and
	// applies again, so Apply must be safe to repeat. So does an Apply that
	// leaves User inactive, which fails the login as ErrNoLinkedAccount.
	//
	// For a provisioning decision (see Provision), Apply on a first sign-in,
	// with linked empty, must create User only and fail when User already
	// exists, never update or adopt it: a user that exists by then was created
	// by another writer, which the broker cannot see. Only on a resume, with
	// linked naming User, may Apply meet a user that exists, and finish it.
	Apply func(ctx context.Context) error
}

// SignInHook decides which user a verified identity of one provider belongs
// to, on every login through that provider. ext is the verified identity, up
// the provider's upstream access for this callback, and linked the user the
// identity is already linked to, or empty when it has none. A hook should
// prefer linked when it is set: the broker refuses a decision that names
// another user, since a link is re-pointed only by an operator.
//
// The hook decides; it does not write. Its writes belong in the decision's
// Apply, which the broker runs only after it accepted the decision (see
// SignInDecision). The library never matches an identity to a user by email:
// a hook that does so owns that choice, and should match only an email whose
// email_verified claim is true, and only at a provider that controls the
// email's domain, or anyone who registers that address at the provider takes
// over the matching account. The one-link-per-user default limits what a
// mistaken match can reach.
//
// It returns a decision, or an error: ErrNoLinkedAccount or
// ErrProvisioningRefused refuses the login as that authentication failure;
// any other error fails it as a broker failure whose text is fixed: the
// error's own text reaches neither the caller nor a log, since it may quote
// the identity's subject or email or the access token, so a consumer who
// wants it logs it inside the hook. The error stays reachable through
// errors.As for concrete types the consumer declares.
//
// A hook may also provision: decide a user reference that does not exist
// yet, with Provision set and an Apply that creates the user under it. The
// identity is linked to that reference first, with an empty username, and
// Apply then creates the user; a reference that already exists is refused,
// never adopted. A provisioning sign-in whose Apply did not create the user
// leaves the link, and the next sign-in hands that reference to the hook as
// linked, so a hook that provisions it again resumes (see
// SignInDecision.Provision).
//
// It runs within the request, on every login of the provider, bounded only by
// ctx: a slow hook, UserInfo fetch or Apply holds the login for as long, so
// a consumer bounds its own calls.
type SignInHook func(ctx context.Context, ext ExternalIdentity, up Upstream, linked identity.UserID) (SignInDecision, error)

// WithBrokerSignInHook sets the sign-in hook that decides, for provider
// only, which user each verified identity belongs to. The default is no hook:
// an identity resolves through its link alone. A hooked provider is brokered
// through BrokerUpstream; Broker refuses it with ErrUpstreamRequired.
//
// By default the broker keeps one link per user for each provider and issuer:
// a decision that would link a second subject to a user already linked is
// refused as ErrNoLinkedAccount before Apply runs, and a link inserted while a
// racing sign-in linked the same user is removed again, alone, before the
// login is refused. That removal is detached from the request's cancellation,
// so a client that goes away cannot leave the second link behind, and is
// bounded by five seconds of its own. Two such sign-ins may then both be refused, and
// the next one succeeds. A sign-in through an existing link applies the rule
// too, so a user who holds two links of one provider and issuer, by a failed
// removal or an operator's write, is refused through either until one is
// removed. WithBrokerSignInHookAllowManyLinks lifts the rule. Switching the
// rule on for a provider whose users already hold several links from one
// provider and issuer therefore refuses those users until the extra links are
// removed.
//
// A nil hook, an empty provider and a second hook for one provider are
// refused with ErrConfig. So is a hook on a provider that WithBrokerJIT,
// WithBrokerClaimMirror or WithBrokerRoleSync also turns on, since two writers
// of one user would contradict each other; a hook on a provider that
// WithBrokerNameClaim, WithBrokerPasswordClaim, WithBrokerRoleClaim,
// WithBrokerRoleMapping, WithBrokerAllowedRoles,
// WithBrokerJITAllowUnverifiedEmail or WithBrokerJITEmailDomains also names,
// since the hooked login never applies them; and a hook over a link store that
// does not implement both LinkLister and LinkRemover, which the
// one-link-per-user rule needs, unless WithBrokerSignInHookAllowManyLinks
// lifts that rule for provider. A
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
// LinkLister and LinkRemover. Identities of other providers and issuers never
// count against the rule. Switching it off again, by omitting this option,
// refuses every user who already holds several links from one provider and
// issuer, through any of them, until the extra links are removed. An empty provider, or one with no
// WithBrokerSignInHook, is refused with ErrConfig.
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
// (JIT provisioning, claim mirroring or role sync), a per-provider option the
// hooked login never applies (see unappliedOption), a one-link rule the link
// store cannot enforce, or an allowance for a provider with no hook. Providers
// are checked in the order options named them, so the error is stable.
func (b *Broker) checkSignInHooks() error {
	_, lists := b.links.(LinkLister)
	_, removes := b.links.(LinkRemover)
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
		if unapplied := b.unappliedOption(p); unapplied != "" {
			return fmt.Errorf("%w: %s names provider %q, whose WithBrokerSignInHook login never applies it",
				ErrConfig, unapplied, p)
		}
		if b.hookManyLinks[p] {
			continue
		}
		if !lists {
			return fmt.Errorf("%w: WithBrokerSignInHook for provider %q needs a link store with ListByUser (LinkLister) "+
				"to keep one link per user, or WithBrokerSignInHookAllowManyLinks(%q)", ErrConfig, p, p)
		}
		if !removes {
			return fmt.Errorf("%w: WithBrokerSignInHook for provider %q needs a link store with DeleteLink (LinkRemover) "+
				"to keep one link per user, or WithBrokerSignInHookAllowManyLinks(%q)", ErrConfig, p, p)
		}
	}
	return nil
}

// unappliedOption names the first per-provider option set for provider that
// a hooked login never applies (D6, F14), or returns "" when there is none.
// Accepting one would let a consumer believe, for example, that an allowlist
// limits a hooked provider's roles when nothing applies it.
func (b *Broker) unappliedOption(provider string) string {
	_, name := b.nameClaims[provider]
	_, pwd := b.passwordClaims[provider]
	_, roleClaim := b.roleClaims[provider]
	_, mapping := b.roleMappings[provider]
	_, allowed := b.allowedRoles[provider]
	_, domains := b.jitDomains[provider]
	switch {
	case name:
		return "WithBrokerNameClaim"
	case pwd:
		return "WithBrokerPasswordClaim"
	case roleClaim:
		return "WithBrokerRoleClaim"
	case mapping:
		return "WithBrokerRoleMapping"
	case allowed:
		return "WithBrokerAllowedRoles"
	case b.jitUnverified[provider]:
		return "WithBrokerJITAllowUnverifiedEmail"
	case domains:
		return "WithBrokerJITEmailDomains"
	}
	return ""
}

var _ UpstreamBroker = (*Broker)(nil)

// AcceptsUpstream reports whether a login through provider is brokered by
// BrokerUpstream: true only for a provider WithBrokerSignInHook hooks, which
// needs the upstream access. Every other provider's logins go to Broker, so a
// consumer type that embeds the library broker, under a name other than
// Broker, and overrides Broker keeps its override there.
func (b *Broker) AcceptsUpstream(provider string) bool {
	_, hooked := b.hooks[provider]
	return hooked
}

// BrokerUpstream returns the principal ext resolves to, given the provider's
// upstream access for this callback. RelyingParty.Callback calls it in place
// of Broker for the providers AcceptsUpstream accepts, the hooked ones.
//
// A consumer type that embeds the library broker and overrides Broker, to
// audit or refuse more, has this method promoted: a hooked provider's login
// runs it and not the override. The broker is embedded by pointer under
// another name, since a field named Broker clashes with the method (a type
// alias such as "type libraryBroker = oidc.Broker", embedded as
// *libraryBroker). Such a wrapper overrides BrokerUpstream too when it means to
// intercept hooked sign-ins.
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
// (D5 steps 3 to 6, D11). d.User is not empty.
//
// The order is the security property: every check runs before anything is
// written, and d.Apply runs only once the link to d.User is final, so a
// decision the broker refuses leaves no trace.
func (b *Broker) acceptDecision(ctx context.Context, ext ExternalIdentity, up Upstream, l *Link, d SignInDecision) (*identity.Principal, error) {
	if d.Provision && d.Apply == nil {
		// Nothing would create the user the link would name (F33).
		return nil, errProvisionWithoutApply
	}
	values := hookIdentifying(ext, up, d.User)
	if l != nil {
		values.names = append(values.names, string(l.UserID))
	}

	// Step 3: checks, with nothing written.
	if l != nil && l.UserID != d.User {
		b.refusal(ctx, slog.LevelWarn, "the sign-in hook decided a user other than the identity's link", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	}
	// username is what a new link records: the loaded user's, or none for a
	// user being provisioned (D13), since no user exists yet to name.
	var username string
	// listed is true once a provisioning check listed the reference's links
	// and found none but the identity's own, which also answers the
	// one-link check that would come before the insert.
	var listed bool
	if d.Provision {
		loaded, err := b.checkProvisioned(ctx, ext, d.User, l != nil, values)
		if err != nil {
			return nil, err
		}
		// Freshness guards a first provisioning, and a resume while the user
		// does not load (F48): a pending user is shared by no two identities.
		// Once the user loads through the identity's own link, the identity
		// owns it, and another provider's link to it, an adoption made after
		// it was created, must not refuse the resume (F56). The one-link
		// rule below still applies to a resume.
		if l == nil || !loaded {
			if listed, err = b.checkFresh(ctx, ext, d.User, values); err != nil {
				return nil, err
			}
		}
	} else {
		det, err := b.loadDecided(ctx, ext, d.User, values, loadBeforeApply)
		if err != nil {
			return nil, err
		}
		username = det.Username
		values.names = append(values.names, username)
	}
	if l != nil && !listed && !b.hookManyLinks[ext.Provider] {
		// The existing link may be one a racing login inserted against the
		// rule and is about to remove: signing in through it would issue a
		// session through a link that then vanishes. A user holding two links
		// is refused through either until one is removed (fail closed).
		if err := b.checkOneLink(ctx, ext, d.User, values); err != nil {
			return nil, err
		}
	}

	// Step 4: link, unless the identity's own link already names the user.
	// A provisioned user is linked before it exists, so that of two racing
	// first sign-ins only the one whose link won creates its user.
	if l == nil {
		var err error
		if l, err = b.linkDecided(ctx, ext, d.User, username, d.Provision, listed, values); err != nil {
			return nil, err
		}
	}

	// Step 5: the consumer's writes, after the link was inserted and confirmed.
	if d.Apply != nil {
		if err := d.Apply(ctx); err != nil {
			return nil, b.hookError(ctx, ext, hookStageApply, err)
		}
	}

	// Step 6: the apply step may have changed, or created, the user; the
	// link stays whatever the reload finds.
	values.names = append(values.names, l.Username)
	stage := loadAfterApply
	if d.Provision {
		stage = loadAfterProvision
	}
	det, err := b.loadDecided(ctx, ext, l.UserID, values, stage)
	if err != nil {
		return nil, err
	}
	return b.principalFor(ctx, ext, det), nil
}

// checkFresh refuses, as ErrNoLinkedAccount, a provisioning decision whose
// reference user is named by a link other than ext's own (D13 step 3). It runs
// on a first provisioning, and on a resume through ext's own link only while
// the user does not load (F48); a resumed user that loads is owned by the
// identity, and another provider's later adoption of it does not refuse the
// resume (F56). The reference must be fresh, or provisioning would give the
// identity a user that another identity, or another provider's, already
// reaches. A listing
// fault is a broker failure with values redacted.
//
// listed reports that the links were listed and none of ext's provider and
// issuer but its own was found, so the one-link check need not list again.
// A store that cannot list skips the check, unchecked (F52): that wiring is
// possible only with WithBrokerSignInHookAllowManyLinks, and the one-link
// rule's own check is not made either.
func (b *Broker) checkFresh(ctx context.Context, ext ExternalIdentity, user identity.UserID, values identifying) (listed bool, err error) {
	lister, ok := b.links.(LinkLister)
	if !ok {
		return false, nil
	}
	links, err := lister.ListByUser(ctx, user)
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	if err != nil {
		return false, fmt.Errorf("oidc: listing the user to provision's links: %w", redact(err, values))
	}
	for _, o := range links {
		if o.Provider == ext.Provider && o.Issuer == ext.Issuer && o.Subject == ext.Subject {
			continue
		}
		b.refusal(ctx, slog.LevelDebug, "the sign-in hook decided to provision a user that another identity's link names",
			ext.Provider, ext.Email)
		return false, ErrNoLinkedAccount
	}
	return true, nil
}

// checkProvisioned checks a provisioning decision for user, a login of ext,
// before anything is written (D13 step 3): provisioning never adopts a user
// that exists. user must not load, unless linked, the identity's own link
// naming user, says an earlier provisioning sign-in stored that link and its
// apply step has not yet created the user, or has. A user that loads through
// the identity's link must match and be active, as an adopted user must. A
// user that loads without that link is refused as ErrNoLinkedAccount; a
// loader fault is a broker failure with values redacted.
//
// loaded reports that the user loaded, which only a resume can answer true.
func (b *Broker) checkProvisioned(ctx context.Context, ext ExternalIdentity, user identity.UserID, linked bool,
	values identifying,
) (loaded bool, err error) {
	if linked {
		det, err := b.loadDecided(ctx, ext, user, values, loadBeforeResume)
		return det != nil, err
	}
	_, err = b.users.LoadByUserID(ctx, user)
	// A chain that cannot be walked is a loader fault, never ErrUserNotFound.
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("oidc: loading the user to provision: %w", redact(err, values))
	default:
		// The reference loads (or the loader answered neither a user nor an
		// error): provisioning it would hand the identity a user it was never
		// linked to (F32).
		b.refusal(ctx, slog.LevelWarn, "the sign-in hook decided to provision a user that already exists", ext.Provider, ext.Email)
		return false, ErrNoLinkedAccount
	}
}

// linkDecided links ext to user, the decided user, recording username, and
// returns the link that is final for ext (D5 step 4, D11). provision says user
// is being provisioned (D13), and username is then empty.
//
// Unless the provider allows many links, det must have no other link from
// ext's provider and issuer, both before the insert and after it: a sign-in
// of another identity racing for the same user may insert between the two,
// and the link this call inserted is then removed again, by its identifier
// and identity alone, before the login is refused. When the insert finds the
// identity already linked, by a racing sign-in of the same identity, the
// stored link is re-read: one naming another user is refused, one naming user
// is final, subject to the same one-link rule, and is never removed here.
// listed says the caller just listed user's links and found no other of
// ext's provider and issuer, so the check before the insert is skipped.
//
// A link this call inserted for a user being provisioned is checked again for
// freshness (D13, F52): two identities of any providers racing to provision
// one reference may each pass the check before the other's insert, so after
// its own insert each re-lists the reference's links, and one that finds a
// link of another identity removes its own and is refused. Of two such
// sign-ins at most one keeps its link; both may be refused. The re-check is a
// superset of the one-link re-check, which it replaces. It needs a store that
// both lists and removes links; over one that does not (possible only under
// WithBrokerSignInHookAllowManyLinks) it is skipped, accepted under F52, and
// the hook's references must be fresh values.
func (b *Broker) linkDecided(ctx context.Context, ext ExternalIdentity, user identity.UserID, username string,
	provision, listed bool, values identifying,
) (*Link, error) {
	one := !b.hookManyLinks[ext.Provider]
	if one && !listed {
		if err := b.checkOneLink(ctx, ext, user, values); err != nil {
			return nil, err
		}
	}

	linkID, err := idgen.New(b.ids)
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	if err != nil {
		return nil, fmt.Errorf("oidc: generating a link identifier: %w", redact(err, values))
	}
	link := Link{
		ID: linkID, Provider: ext.Provider, Issuer: ext.Issuer, Subject: ext.Subject,
		UserID: user, Username: username, Email: ext.Email,
		CreatedAt: b.clock.Now(),
	}
	err = b.links.Insert(ctx, link)
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrLinkExists):
		return b.rereadLink(ctx, ext, user, values)
	case err != nil:
		return nil, fmt.Errorf("oidc: linking the decided user: %w", redact(err, values))
	}

	// Only this call's own insert is re-checked here: a link found by the
	// ErrLinkExists re-read belongs to the login that inserted it, which
	// re-checks it itself.
	switch {
	case provision && b.canRecheckFresh():
		if _, err := b.checkFresh(ctx, ext, user, values); err != nil {
			return nil, b.undoLink(ctx, link, values, err)
		}
	case one:
		if err := b.checkOneLink(ctx, ext, user, values); err != nil {
			return nil, b.undoLink(ctx, link, values, err)
		}
	}
	return &link, nil
}

// canRecheckFresh reports whether the link store can both list a user's links
// and remove one, which re-checking a provisioned reference after the insert
// needs (F52).
func (b *Broker) canRecheckFresh() bool {
	_, lists := b.links.(LinkLister)
	_, removes := b.links.(LinkRemover)
	return lists && removes
}

// rereadLink reads the link of ext after an insert found it already linked,
// and accepts it only when it names user (D5 step 4).
func (b *Broker) rereadLink(ctx context.Context, ext ExternalIdentity, user identity.UserID, values identifying) (*Link, error) {
	l, err := b.links.FindByExternal(ctx, ext.Provider, ext.Issuer, ext.Subject)
	// Before the ErrLinkNotFound check: a chain that cannot be walked is a
	// store fault.
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrLinkNotFound):
		// The insert found the identity linked and a concurrent sign-in's
		// undo removed the link before this re-read: a lost race, refused.
		b.refusal(ctx, slog.LevelDebug, "the identity's link was removed by a concurrent sign-in before it was re-read", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	case err == nil && l == nil:
		// A store that reports neither a link nor an error breaks its
		// contract, and nothing can be accepted.
		return nil, errLinkNilFound
	case err != nil:
		return nil, fmt.Errorf("oidc: re-reading a link: %w", redact(err, values))
	case l.UserID != user:
		b.refusal(ctx, slog.LevelWarn, "the sign-in hook decided a user other than the identity's link", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	}
	if !b.hookManyLinks[ext.Provider] {
		// Not this call's link, so it is not removed; the login that
		// inserted it applies the rule to it.
		if err := b.checkOneLink(ctx, ext, user, values); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// checkOneLink refuses, as ErrNoLinkedAccount, a user that has a link from
// ext's provider and issuer for another subject (D11). A listing fault is a
// broker failure.
func (b *Broker) checkOneLink(ctx context.Context, ext ExternalIdentity, user identity.UserID, values identifying) error {
	lister, ok := b.links.(LinkLister)
	if !ok {
		// NewBroker refuses this wiring; reaching it is a defect, refused.
		return errNoLinkLister
	}
	links, err := lister.ListByUser(ctx, user)
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	if err != nil {
		return fmt.Errorf("oidc: listing the decided user's links: %w", redact(err, values))
	}
	for _, o := range links {
		if o.Provider == ext.Provider && o.Issuer == ext.Issuer && o.Subject != ext.Subject {
			b.refusal(ctx, slog.LevelWarn, "the sign-in hook decided a user already linked to another identity of the provider",
				ext.Provider, ext.Email)
			return ErrNoLinkedAccount
		}
	}
	return nil
}

// linkUndoTimeout bounds the removal of a link inserted against the one-link
// rule (D11). The removal is detached from the request's cancellation, so it
// needs a bound of its own: one row deleted by its key, which a healthy store
// finishes well within it. A removal that runs out of time is a broker
// failure, logged at ERROR, and the user keeps two links, which the one-link
// check then refuses through either (F48).
const linkUndoTimeout = 5 * time.Second

// undoLink removes link, which this login inserted and whose re-check (the
// one-link rule, or a provisioned reference's freshness) failed with cause, and returns the login's error: cause once the
// link is removed, or else a broker failure, never the refusal cause may be,
// since the link may still stand. Only link itself is removed, by its
// identifier and identity; the user's other links stay.
//
// The removal keeps ctx's values but not its cancellation, under
// linkUndoTimeout: a client that disconnects just after the insert must not
// leave the duplicate behind.
func (b *Broker) undoLink(ctx context.Context, link Link, values identifying, cause error) error {
	remover, ok := b.links.(LinkRemover)
	if !ok {
		// NewBroker refuses this wiring; reaching it is a defect, refused.
		return errNoLinkRemover
	}
	undoCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), linkUndoTimeout)
	defer cancel()
	_, err := remover.DeleteLink(undoCtx, link)
	err = porterr.SanitizeTo(undoCtx, b.log, err, porterr.ErrUnwalkable)
	if err != nil {
		b.log.LogAttrs(ctx, slog.LevelError,
			"oidc: a link this sign-in inserted and then refused could not be removed; the user may keep it, "+
				"beside another identity's link, until an operator removes it",
			slog.String("provider", link.Provider),
			slog.String("email_domain", emailDomain(link.Email)))
		return fmt.Errorf("oidc: removing a duplicate link: %w", redact(err, values))
	}
	return cause
}

// loadStage says when loadDecided runs: before the decision's apply step (D5
// step 3) or after it (step 6), for a decision adopting a user or one
// provisioning it (D13).
type loadStage uint8

const (
	// loadBeforeApply checks an adopted user before anything is written.
	loadBeforeApply loadStage = iota
	// loadBeforeResume checks a user being provisioned that the identity's
	// own link already names, before anything is written: it may be absent,
	// since the apply step that creates it may not have run, or failed.
	loadBeforeResume
	// loadAfterApply reloads an adopted user after the apply step.
	loadAfterApply
	// loadAfterProvision reloads a provisioned user after the apply step
	// that was to create it.
	loadAfterProvision
)

// loadDecided loads user, the decided user of a login of ext, and requires it
// to exist, match its reference and be active. A refusal is
// ErrNoLinkedAccount; a loader fault is a broker failure with values redacted.
// A user missing after the apply step was there before it, so its refusal is
// a warning of its own rather than a decision for a missing user. A user being
// provisioned may be missing before its apply step, and its link alone is
// returned as nil details; one missing after it is a broker failure, since
// the consumer's apply step did not do what the decision said (F34).
func (b *Broker) loadDecided(ctx context.Context, ext ExternalIdentity, user identity.UserID, values identifying,
	stage loadStage,
) (*identity.Details, error) {
	det, err := b.users.LoadByUserID(ctx, user)
	// A chain that cannot be walked is a loader fault, never ErrUserNotFound.
	err = porterr.SanitizeTo(ctx, b.log, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, identity.ErrUserNotFound) && stage == loadBeforeResume:
		return nil, nil
	case errors.Is(err, identity.ErrUserNotFound) && stage == loadAfterProvision:
		return nil, errProvisionedUserMissing
	case errors.Is(err, identity.ErrUserNotFound) && stage == loadAfterApply:
		b.refusal(ctx, slog.LevelWarn, "the user disappeared during the sign-in hook's apply step", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	case errors.Is(err, identity.ErrUserNotFound):
		b.refusal(ctx, slog.LevelDebug, "the sign-in hook decided a user that does not exist", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	case err != nil:
		return nil, fmt.Errorf("oidc: loading the decided user: %w", redact(err, values))
	case det == nil || det.ID != user:
		b.refusal(ctx, slog.LevelWarn, "the sign-in hook's decided user loaded as another user", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	case !det.Active:
		b.refusal(ctx, slog.LevelDebug, "the sign-in hook decided an inactive user", ext.Provider, ext.Email)
		return nil, ErrNoLinkedAccount
	}
	return det, nil
}

// errLinkNilFound is the broker failure of a link store that refused an
// insert as already linked, then returned neither a link nor an error for the
// identity.
var errLinkNilFound = errors.New("oidc: the link store reported the identity linked, then returned no link and no error")

// errNoLinkLister and errNoLinkRemover are the broker failures of a one-link
// check over a store that cannot list or remove one link, which NewBroker
// refuses; they are reached only if that check is bypassed.
var (
	errNoLinkLister  = errors.New("oidc: the link store cannot list a user's links")
	errNoLinkRemover = errors.New("oidc: the link store cannot remove one link")
)

// errProvisionWithoutApply is the broker failure of a provisioning decision
// with no apply step to create its user (F33). Nothing is written.
var errProvisionWithoutApply = errors.New("oidc: the sign-in hook decided to provision a user with no apply step to create it")

// errProvisionedUserMissing is the broker failure of a provisioning decision
// whose apply step returned without creating the user (F34). The link to the
// user stays, and a later provisioning decision for it resumes.
var errProvisionedUserMissing = errors.New("oidc: the sign-in decision's apply step did not create the user it provisions")

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
