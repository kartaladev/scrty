package authenticate

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/logsample"
)

// FirstOf resolves credentials by offering them to ordered providers.
//
// It is safe for concurrent use: the provider list is fixed at construction and
// never written afterwards.
//
// It forwards the decoy check and the refusal-log flush to its delegates: it is
// a logsample.Flusher, and FlushRefusalLogs reaches every delegate that is one.
type FirstOf struct {
	delegates []Authenticator
	// resolver is the one delegate that logs in by email, nil when none does.
	resolver IdentifierResolver
}

// NewFirstOf returns a FirstOf that offers credentials to delegates in the
// order given.
//
// There is no default list. Which methods a deployment accepts, and in which
// order, is the consumer's decision, and a manager that invented one would
// accept a credential the consumer never meant to accept.
//
// No delegates is a configuration error rather than a manager that refuses
// everything, because the two are indistinguishable at the first request while
// only one of them is what anyone meant.
//
// An absent delegate is refused rather than skipped, and that includes a
// non-nil interface holding a nil pointer — what an unchecked constructor error
// hands over. Skipping it would run fewer providers than the consumer wrote,
// silently; keeping it would panic on the first request, where the mistake
// looks like a runtime fault rather than a line of wiring.
//
// At most one delegate, counted through nested FirstOfs, may log in by email
// (see ResolverOf); more is a configuration error, because a login endpoint
// resolves an identifier through one resolver only. Any number of username-only
// providers is allowed after it.
//
// One of scrty's own password providers (a UsernamePasswordAuthenticator)
// without login by email, placed before the email-login member in the order
// credentials are offered, nested FirstOfs included, is a configuration error
// too. The login endpoint keys lockout on the account the identifier resolved
// to, and that provider, deciding first, would authenticate the identifier as
// typed against its own load: one account judged by lockout, another
// authenticated. Place the email-login member first. A consumer's own
// Authenticator in that position cannot be recognised as a password handler,
// so it is allowed, and keeping it from authenticating an account other than
// the resolved one is the consumer's responsibility.
func NewFirstOf(delegates ...Authenticator) (*FirstOf, error) {
	if len(delegates) == 0 {
		return nil, fmt.Errorf("%w: a manager with no delegates authenticates nobody", ErrConfig)
	}
	for i, d := range delegates {
		if nilcheck.IsNil(d) {
			return nil, fmt.Errorf("%w: delegate %d is nil", ErrConfig, i)
		}
	}

	// A login endpoint runs one resolution before its pre-authentication
	// phase, so only one member may need it. A nested FirstOf reports its own
	// member, so the count reaches every depth.
	var resolver IdentifierResolver
	for _, d := range delegates {
		r, ok := ResolverOf(d)
		if !ok {
			continue
		}
		if resolver != nil {
			return nil, fmt.Errorf("%w: more than one delegate logs in by email, and an identifier can be resolved by only one", ErrConfig)
		}
		resolver = r
	}

	if resolver != nil && passwordBeforeResolver(delegates) {
		return nil, fmt.Errorf("%w: a username-only password provider is offered credentials before the member that logs in by email, "+
			"so it would authenticate an account the lockout did not judge; place the email-login member first", ErrConfig)
	}

	// Cloned so a caller that keeps and rewrites the slice it passed cannot
	// change which providers run, or in which order, after construction.
	return &FirstOf{delegates: slices.Clone(delegates), resolver: resolver}, nil
}

// Authenticate offers credentials to each delegate in turn and returns the first answer
// that is not a refusal to handle the credentials.
//
// A delegate reporting ErrUnsupportedCredentials is skipped, and so is one
// reporting ErrNoEligibleAuthenticator, which is what a nested FirstOf whose
// delegates all skipped reports: a skip stays a skip however deep it is
// nested. Any other error
// ends the walk and is returned unchanged, so an outage inside one provider
// reaches the caller as itself rather than being retried by the next provider
// or collapsed into a refusal. When every delegate skips,
// ErrNoEligibleAuthenticator says so.
//
// A delegate error whose chain cannot be walked (a cycle, a fan-out past the
// walk's budget, an Unwrap that panics) is never read as a skip, whatever it
// claims: it is replaced by a fixed fault matching porterr.ErrUnwalkable and
// no sentinel of this package, which ends the walk as any other outage does,
// and one record of the abort is written to the logger of the chain handling the
// request, else to slog.Default() when the record is written.
//
// A deciding delegate that reports no error but no result, or a result with no
// principal, is turned into ErrAuthenticationFailed here. This is the single
// choke point that lets every caller read Principal after a nil error without
// checking it; leaving the check to each provider would let the next provider
// written reopen it for everyone.
func (m *FirstOf) Authenticate(ctx context.Context, credentials identity.Credentials) (*Authentication, error) {
	for _, d := range m.delegates {
		a, err := d.Authenticate(ctx, credentials)
		// The delegate is the consumer's, and so is its error. One whose
		// chain cannot be walked becomes a fault that matches no skip, so a
		// hostile delegate is never passed over for a later one to
		// authenticate: it stops the walk as a plain outage from it does.
		// FirstOf holds no logger, so the abort record goes to the chain's logger,
		// else the default, as SanitizeTo routes it.
		err = porterr.SanitizeTo(ctx, nil, err, porterr.ErrUnwalkable)
		if errors.Is(err, ErrUnsupportedCredentials) || errors.Is(err, ErrNoEligibleAuthenticator) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if a == nil || a.Principal == nil {
			return nil, ErrAuthenticationFailed
		}

		return a, nil
	}

	return nil, ErrNoEligibleAuthenticator
}

var _ Authenticator = (*FirstOf)(nil)

// VerifyDecoy offers credentials to each delegate that implements DecoyVerifier, in
// order, and stops at the first that reports it handled credentials. It returns false
// when no delegate does, including when none implements DecoyVerifier.
//
// Delegates that do not implement DecoyVerifier are skipped, and no delegate's
// Authenticate is called.
func (m *FirstOf) VerifyDecoy(ctx context.Context, credentials identity.Credentials) bool {
	for _, d := range m.delegates {
		if v, ok := d.(DecoyVerifier); ok && v.VerifyDecoy(ctx, credentials) {
			return true
		}
	}

	return false
}

var _ DecoyVerifier = (*FirstOf)(nil)

// OffersDecoy reports whether any delegate offers a decoy verification, so a
// caller can tell whether VerifyDecoy will ever spend any work: a FirstOf
// always implements DecoyVerifier, and that alone says nothing about its
// delegates.
//
// A delegate offers one when it implements DecoyVerifier and, if it also
// reports OffersDecoy, as a nested FirstOf does, that reports true. It is
// answered from the delegates' types alone, and calls neither VerifyDecoy nor
// Authenticate.
func (m *FirstOf) OffersDecoy() bool {
	return slices.ContainsFunc(m.delegates, offersDecoy)
}

// decoyOfferer is a DecoyVerifier that can report whether it will ever spend
// a decoy, as a FirstOf can.
type decoyOfferer interface {
	OffersDecoy() bool
}

// offersDecoy reports whether a may spend a decoy verification.
func offersDecoy(a Authenticator) bool {
	if _, ok := a.(DecoyVerifier); !ok {
		return false
	}

	if o, ok := a.(decoyOfferer); ok {
		return o.OffersDecoy()
	}

	return true
}

// FlushRefusalLogs flushes each delegate that implements logsample.Flusher, in
// the order the delegates were given, so a delegate's suppressed refusals are
// reported when the FirstOf is flushed. A nested FirstOf is a flusher too, so
// the flush reaches delegates however deep they sit. Delegates that do not
// implement logsample.Flusher are skipped.
//
// A delegate whose flush fails does not stop the later ones: every flusher is
// called, and the errors come back joined. It returns nil when every flush
// succeeded or no delegate flushes.
func (m *FirstOf) FlushRefusalLogs() error {
	var errs []error
	for _, d := range m.delegates {
		if f, ok := d.(logsample.Flusher); ok {
			if err := f.FlushRefusalLogs(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

var _ logsample.Flusher = (*FirstOf)(nil)

// EmailLogin reports whether a member, at any depth, logs in by email. See
// IdentifierResolver.
func (m *FirstOf) EmailLogin() bool { return m.resolver != nil }

// ResolveIdentifier forwards to the one member that logs in by email, found at
// construction however deeply it is nested. The resolution it returns is that
// member's: handed to Authenticate through WithResolved, it is honoured by that
// member alone, and every other member ignores it and loads for itself.
//
// With no such member there is nothing to resolve: it returns the identifier
// as typed as the Key, no Details and a nil error, loading nothing. Every
// member ignores that result.
func (m *FirstOf) ResolveIdentifier(ctx context.Context, identifier string) (ResolvedIdentifier, error) {
	if m.resolver == nil {
		return ResolvedIdentifier{Key: identifier}, nil
	}

	return m.resolver.ResolveIdentifier(ctx, identifier)
}

var _ IdentifierResolver = (*FirstOf)(nil)

// passwordBeforeResolver reports whether one of scrty's username-only password
// providers is offered credentials before the member that logs in by email,
// walking delegates in the order Authenticate does, through nested FirstOfs.
func passwordBeforeResolver(delegates []Authenticator) bool {
	found := false
	walkMembers(delegates, func(d Authenticator) bool {
		if _, ok := ResolverOf(d); ok {
			return false
		}
		if p, ok := d.(*UsernamePasswordAuthenticator); ok && !p.EmailLogin() {
			found = true

			return false
		}

		return true
	})

	return found
}

// walkMembers calls visit on each member that is not a FirstOf, in the order
// Authenticate offers credentials, descending into nested FirstOfs, until
// visit returns false. It reports whether the walk ran to the end. A FirstOf
// is immutable and built only from existing authenticators, so the nesting
// has no cycle.
func walkMembers(delegates []Authenticator, visit func(Authenticator) bool) bool {
	for _, d := range delegates {
		if m, ok := d.(*FirstOf); ok {
			if !walkMembers(m.delegates, visit) {
				return false
			}

			continue
		}
		if !visit(d) {
			return false
		}
	}

	return true
}
