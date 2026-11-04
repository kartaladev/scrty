package oidcprovider

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// ClientToNotify is one client to tell that one sign-in has ended, with what its logout token states.
// A client holding several grants from a sign-in is told once, and a client holding grants from two
// ended sign-ins is told of each (oidc-provider-logout).
//
// It lists a client holding a grant from that sign-in, whether or not the client registered a
// back-channel logout URI: that is read as the client stands when the token is delivered, so that a
// registry outage here cannot cost an end its grants.
type ClientToNotify struct {
	// ClientID is the client that held a grant from the sign-in.
	ClientID string
	// User is the sign-in's user, and the token's sub.
	User identity.UserID
	// SignInFamily is the sign-in's session family, and the token's sid.
	SignInFamily id.ID
}

// EndSignIn ends the sign-ins sel selects, and returns the clients to notify, each of which has also
// been handed on for back-channel delivery. This is what the chain's own logout calls, before it
// deletes the session, so that a failure here can fail the logout.
//
// A grant without offline_access ends with its sign-in, and so does any grant of a client registered
// with [Client].EndGrantsWithSignIn. A grant with offline_access otherwise survives, marked as having
// outlived its sign-in, and its client is told all the same, as it held a grant from that sign-in. An
// outstanding code is treated as the grant it would become (R7). The browser sessions of the sign-ins
// go too, through their own store (R2). Grants report their client until their own deadline, a lineage
// gone idle or not, since nothing removes a grant earlier (R19).
//
// The same end asked for twice returns nothing the second time, so a client is told once.
//
// A selector of no valid shape is refused with an error matching ErrConfig, before anything is read
// or written. Each store is written whatever became of the other, and neither depends on the caller
// still listening, and each has a budget of its own. A failure of either matches ErrDependency, with the clients of whatever did end
// still returned and handed on, and asking again finishes the work and tells no one twice. It has no
// override: what ends is decided per client, by [Client].EndGrantsWithSignIn.
func (p *Provider) EndSignIn(ctx context.Context, sel SignInSelector) ([]ClientToNotify, error) {
	if err := sel.Validate(); err != nil {
		return nil, err
	}
	// Each store, and the hand-on, spends a budget of its own, so that one hanging until its budget ends
	// leaves the others a live context.
	grantCtx, endGrants := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	ended, grantErr := p.stores.grants.EndSignIns(grantCtx, sel, p.cfg.clock.Now())
	endGrants()
	clients := clientsToNotify(ended)

	handCtx, endHandOn := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	p.handOn(handCtx, clients)
	endHandOn()

	browserCtx, endBrowsers := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer endBrowsers()
	_, browserErr := p.stores.browserSessions.DeleteBySignIn(browserCtx, sel)

	return clients, dependencyFailure(ctx, errors.Join(grantErr, browserErr), "oidcprovider: end the sign-ins")
}

// handOn is where the clients of an ended sign-in leave for back-channel delivery. It never waits for a
// delivery, however many clients there are and however their deliveries fare, so it spends none of the
// logout's time on them.
func (p *Provider) handOn(ctx context.Context, clients []ClientToNotify) {
	if len(clients) > 0 && p.cfg.logoutNotices != nil {
		p.cfg.logoutNotices(ctx, clients)
	}
	for _, c := range clients {
		p.logouts.enqueue(ctx, c)
	}
}

// clientsToNotify lists what the grants say, once per client per sign-in, in an order of its own.
func clientsToNotify(ended []Grant) []ClientToNotify {
	clients := make([]ClientToNotify, 0, len(ended))
	for i := range ended {
		clients = append(clients, ClientToNotify{
			ClientID: ended[i].ClientID, User: ended[i].User, SignInFamily: ended[i].SignInFamily,
		})
	}
	slices.SortFunc(clients, func(a, b ClientToNotify) int {
		return cmp.Or(cmp.Compare(a.ClientID, b.ClientID), cmp.Compare(a.SignInFamily.String(), b.SignInFamily.String()))
	})

	return slices.Compact(clients)
}

// SignInsEnded implements session.EndObserver: a session manager built with
// session.WithEndObserver(provider) tells the provider of each explicit end, after its own store
// write, and the provider then does what EndSignIn does. A sign-in that merely expires is not
// reported, so it ends nothing here.
//
// The selection comes from what the report names and not from its cause, so a cause added later ends
// what it names with no change here. A family names that family; an upstream issuer with its session
// names that session, and a session without its issuer names nothing; a user with a kept family names the user but that family; a user with an upstream
// issuer names that pair; a user alone names the user, so a nil KeptFamily spares nothing. A report
// naming none of those, as a deletion of a session that had already gone does, ends nothing, and is
// logged.
//
// It runs inside the session manager's call, on a context its caller cannot cancel, and each store
// has its own budget of 10 seconds, so hanging stores can delay a logout's answer by up to 20 seconds.
// Back-channel delivery adds nothing to that, as handing it on never waits.
//
// It has no error to return, and the sign-in has already ended, so a failure is logged and leaves the
// sign-in ended, with the grants left as they stand until the next end selecting them.
func (p *Provider) SignInsEnded(ctx context.Context, r session.EndReport) {
	sel, ok := selectorOf(r)
	if !ok {
		p.cfg.logger.LogAttrs(ctx, slog.LevelWarn, "oidcprovider: a report of an ended sign-in names no one, so no grant can be matched",
			slog.Int("cause", int(r.Cause)))

		return
	}

	if _, err := p.EndSignIn(ctx, sel); err != nil {
		// A security event reporting this belongs here, beside the log line.
		p.cfg.logger.LogAttrs(ctx, slog.LevelError, "oidcprovider: an ended sign-in's grants could not be ended",
			append(diag.Failure("end_sign_ins", err), slog.Int("cause", int(r.Cause)))...)
	}
}

// selectorOf reads what a report names, the narrowest selection first.
func selectorOf(r session.EndReport) (SignInSelector, bool) {
	switch {
	case r.Family != id.Nil:
		return SignInSelector{Family: r.Family}, true
	case r.ExternalIssuer != "" && r.ExternalSessionID != "":
		return SignInSelector{ExternalIssuer: r.ExternalIssuer, ExternalSessionID: r.ExternalSessionID}, true
	case r.User == "" || r.ExternalSessionID != "":
		// A session without its issuer names no sign-in, and must not widen to the user's.
		return SignInSelector{}, false
	case r.KeptFamily != id.Nil:
		return SignInSelector{User: r.User, ExceptFamily: r.KeptFamily}, true
	case r.ExternalIssuer != "":
		return SignInSelector{User: r.User, ExternalIssuer: r.ExternalIssuer}, true
	default:
		return SignInSelector{User: r.User}, true
	}
}

// RevokeUserGrants revokes every grant of user, offline_access included, and every outstanding code,
// recording cause, for what a security event leaves in doubt: an account recovery, an MFA reset, a
// passkey clone. No sign-in ended, so no client is told one did.
//
// cause is a string, one of the RevocationCause values or the consumer's own, so that a package
// declaring its own one-method port needs no import of this one. It is recorded unchanged. An empty
// user or cause is refused with an error matching ErrConfig, before anything is written.
//
// The write does not depend on the caller still listening, and failing matches ErrDependency: the
// event that asked may ask again, as a revocation changes nothing the second time. Whether an event
// revokes at all is the option of the package raising it.
func (p *Provider) RevokeUserGrants(ctx context.Context, user identity.UserID, cause string) error {
	if user == "" || cause == "" {
		return fmt.Errorf("%w: RevokeUserGrants: a user and a cause are required", ErrConfig)
	}
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()

	if _, err := p.stores.grants.RevokeByUser(detached, user, RevocationCause(cause), p.cfg.clock.Now()); err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: revoke the user's grants")
	}

	return nil
}

// ConsentView is one application the user has allowed.
type ConsentView struct {
	// ClientID is the client allowed.
	ClientID string
	// ClientName is its name, and empty for a client no longer registered.
	ClientName string
	// Scopes is every scope given so far.
	Scopes []string
	// Offline reports that offline access was given explicitly.
	Offline bool
	// LastGivenAt is when consent was last given.
	LastGivenAt time.Time
}

// Consents lists the applications user has allowed, and no other user's. A consent to a client no
// longer registered stays listed with no name, so that it can still be revoked. A store or registry
// that cannot answer matches ErrDependency, and a caller who left matches its own context's error.
func (p *Provider) Consents(ctx context.Context, user identity.UserID) ([]ConsentView, error) {
	consents, err := p.stores.consents.ListByUser(ctx, user)
	if err != nil {
		return nil, dependencyFailure(ctx, err, "oidcprovider: list the user's consents")
	}

	views := make([]ConsentView, 0, len(consents))
	for i := range consents {
		c := &consents[i]
		view := ConsentView{ClientID: c.ClientID, Scopes: c.Scopes, Offline: c.Offline, LastGivenAt: c.LastGivenAt}
		rc, err := p.client(ctx, c.ClientID)
		switch {
		case errors.Is(err, ErrClientNotFound):
		case err != nil:
			return nil, err
		default:
			view.ClientName = rc.Name
		}
		views = append(views, view)
	}

	return views, nil
}

// RevokeConsent forgets what user allowed clientID, and revokes every grant and outstanding code of
// that user and client, offline_access included, with CauseConsentRevoked, so their refresh tokens
// stop working at once and the next authorization asks again. Another client's, and another user's,
// are left alone.
//
// A user holding neither a consent to the client nor a grant of it that this ended is refused with
// ErrForeignConsent, with that user's outstanding codes for the client still revoked, so a user naming a client cannot end what nothing of theirs
// ever gave. A first-party client is never asked, so it holds no consent; its grants for the user
// are ended all the same, and RevokeUserGrants is only for ending every client's.
//
// The grants go first, so that a failure leaves the consent listed, to be revoked again. Neither write
// depends on the caller still listening. A failure matches ErrDependency, and an empty user or client
// is refused with an error matching ErrConfig.
func (p *Provider) RevokeConsent(ctx context.Context, user identity.UserID, clientID string) error {
	if user == "" || clientID == "" {
		return fmt.Errorf("%w: RevokeConsent: a user and a client are required", ErrConfig)
	}

	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()
	ended, err := p.stores.grants.RevokeByUserAndClient(detached, user, clientID, CauseConsentRevoked, p.cfg.clock.Now())
	if err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: revoke the consent's grants")
	}
	forgotten, err := p.stores.consents.Revoke(detached, user, clientID)
	if err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: forget the consent")
	}
	if !forgotten && len(ended) == 0 {
		return ErrForeignConsent
	}

	return nil
}
