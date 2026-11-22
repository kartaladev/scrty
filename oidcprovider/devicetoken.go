package oidcprovider

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// paramDeviceCode is the token request's device code (RFC 8628 section 3.4).
const paramDeviceCode = "device_code"

// slowDownStep is what a poll inside its interval adds to the interval, for every later poll
// (RFC 8628 section 3.5). It has no override.
const slowDownStep = 5 * time.Second

// errUnknownDeviceState stands for a device record whose state is none the provider writes,
// which only a store breaking its contract answers. It carries no consumer data.
var errUnknownDeviceState = errors.New("oidcprovider: a device authorization is in an unknown state")

// errNoApproval stands for an approved device record holding no approval, or one naming the
// nil grant family, which only a store breaking its contract answers. Nothing is spent for it.
var errNoApproval = errors.New("oidcprovider: an approved device authorization holds no usable approval")

// pollDevice answers a device-code token request (RFC 8628 section 3.4), for a client Token
// has authenticated, found registered for the grant, and checked for its required binding. It
// runs in this order, so a refusal before the spend leaves the record as it was:
//
//  1. a missing device_code is invalid_request, and one the provider could not have minted is
//     invalid_grant, with no lookup;
//  2. the record is read by the code's digest. An unknown code is invalid_grant, and a store
//     failure a dependency failure, never authorization_pending;
//  3. another client's code is invalid_grant, with nothing written;
//  4. a spent code goes to replayDeviceCode, whatever its expiry, so a replay is seen for as
//     long as the store keeps the record;
//  5. a record expired by the provider's clock (now >= ExpiresAt) is expired_token;
//  6. a denied record is access_denied, and an approved one is exchanged (exchangeDevice);
//  7. a pending record is paced (paceDevicePoll).
//
// Approved, denied and expired records are answered by their state, without the pace check: a
// client that polled too fast is not made to wait for what it is owed.
func (p *Provider) pollDevice(ctx context.Context, r TokenRequest, rc *RegisteredClient) (*TokenResponse, error) {
	raw := r.Form.Get(paramDeviceCode)
	if raw == "" {
		return nil, refuseRequest()
	}
	digest, ok := digestEncoded(raw)
	if !ok {
		return nil, refuseGrant()
	}
	store := p.cfg.device.store

	record, err := store.LoadByDeviceCode(ctx, digest)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, refuseGrant()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: load the device authorization")
	case record == nil:
		return nil, dependencyFailure(ctx, errNoRecord, "oidcprovider: load the device authorization")
	}
	// Read after the load, so what it judges expired is expired by now.
	now := p.cfg.clock.Now()

	if record.ClientID != rc.ID {
		return nil, refuseGrant()
	}
	if record.State == DeviceSpent {
		return nil, p.replayDeviceCode(ctx, r, rc, record, now)
	}
	if !now.Before(record.ExpiresAt) {
		return nil, &Error{Code: CodeExpiredToken}
	}

	switch record.State {
	case DeviceDenied:
		return nil, &Error{Code: CodeAccessDenied}
	case DeviceApproved:
		return p.exchangeDevice(ctx, r, rc, record, now)
	case DeviceIssued, DeviceClaimed:
		return nil, p.paceDevicePoll(ctx, record, now)
	default:
		return nil, dependencyFailure(ctx, errUnknownDeviceState, "oidcprovider: load the device authorization")
	}
}

// paceDevicePoll answers a poll of an authorization the user has not answered (RFC 8628
// section 3.5). A poll sooner than Interval after LastPolledAt is too soon: it is recorded with
// the interval grown by slowDownStep, for every later poll, and answered slow_down. A clock
// behind LastPolledAt, as a replica's may be, counts as too soon, and is recorded as
// LastPolledAt itself, so LastPolledAt never moves backwards and no skew lets a client poll
// faster. Otherwise the poll is recorded and answered authorization_pending.
//
// Each record is one conditional write on PollCount, so of polls racing on one version at most
// one passes, and a write that lost its compare is answered slow_down. Any other failure is a
// dependency failure, never an answer that keeps the client polling.
func (p *Provider) paceDevicePoll(ctx context.Context, record *DeviceAuthorization, now time.Time) error {
	tooSoon := !record.LastPolledAt.IsZero() && now.Before(record.LastPolledAt.Add(record.Interval))
	interval, answer := record.Interval, CodeAuthorizationPending
	if tooSoon {
		interval, answer = record.Interval+slowDownStep, CodeSlowDown
	}

	polledAt := now
	if record.LastPolledAt.After(polledAt) {
		polledAt = record.LastPolledAt
	}

	err := p.cfg.device.store.RecordPoll(ctx, record.ID, record.PollCount, polledAt, interval)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return &Error{Code: CodeSlowDown}
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: record the device's poll")
	}

	return &Error{Code: answer}
}

// replayDeviceCode answers a spent device code its own client presented again, and always with
// invalid_grant unless a store cannot answer (design D11). A valid replay first revokes what the
// exchange issued: the grant named by the approval's GrantFamily, and its lineage, which ends its
// refresh tokens and every access token, since those read their grant.
//
// A grant bound to a key (a public client's DPoP proof at the exchange) or to a certificate (its
// thumbprint, when no proof was given) is revoked only by a replay proving that key or presenting
// that certificate, as a code's binding is required of its replay, so whoever holds only
// a leaked device code cannot end the user's grant. A confidential client's grant is bound by its
// authentication, which Token has checked. A grant with no row yet is revoked all the same,
// because the exchange that spent the code may still be writing it: the revocation is stored
// first, and the row is created over it, revoked. Which grant that row would have bound is not
// known then, so such a replay is believed without a proof.
//
// A replay is seen for as long as the device store keeps the spent record, until one minute
// past its expiry (DeviceAuthorizationStore.DeleteExpired), which is why pollDevice judges a
// spent record before its expiry. From the first grant read to the last write, none of this
// depends on the caller still listening.
func (p *Provider) replayDeviceCode(
	ctx context.Context, r TokenRequest, rc *RegisteredClient, record *DeviceAuthorization, now time.Time,
) error {
	a := record.Approval
	if a == nil || a.GrantFamily == id.Nil {
		return dependencyFailure(ctx, errNoApproval, "oidcprovider: load the device authorization")
	}
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()

	grant, err := p.stores.grants.Load(detached, a.GrantFamily)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		// No row yet: revoke, so the row is created revoked.
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the replayed device code's grant")
	case grant == nil:
		return dependencyFailure(ctx, errNoRecord, "oidcprovider: read the replayed device code's grant")
	case !replayHoldsBinding(grant, r.Binding):
		return refuseGrant()
	}

	err = p.revokeReplayedFamily(ctx, detached, a.GrantFamily, now, func(newly bool) {
		if newly {
			p.reportGrantRevoked(ctx, rc.ID, a.User, CauseCodeReplay)
		}
	})
	if err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: revoke what a replayed device code issued")
	}

	return refuseGrant()
}

// exchangeDevice exchanges an approved, unexpired device authorization of rc's for tokens. Every
// check comes before the spend, so a refusal leaves the record approved:
//
//  1. the approval is read, and one missing or naming the nil family is a dependency failure;
//  2. the approving user must still exist and be active;
//  3. the grant's life is judged: unless the grant survives its sign-in's end
//     (Offline or SurvivesSignInEnd, without EndsWithSignIn) and holds a lineage, a sign-in past
//     its absolute deadline refuses it, and the grant ends at that deadline;
//  4. the resources are judged against the client as it stands now, as a code's are;
//  5. the tokens are signed, which writes nothing, so a key failure leaves the record to retry;
//  6. the record is spent, by one conditional write of which one racing poll wins;
//  7. the grant row is written, over any revocation already recorded for its family, and read
//     back: one found revoked (a sign-in end, a consent revocation or a withdrawn approval that
//     came before the exchange) answers invalid_grant, and nothing is handed out;
//  8. the lineage and an opaque access token's record are written, as for a code.
//
// A failure after the spend answers an error and burns the record, and no token is issued
// without its grant.
func (p *Provider) exchangeDevice(
	ctx context.Context, r TokenRequest, rc *RegisteredClient, record *DeviceAuthorization, now time.Time,
) (*TokenResponse, error) {
	a := record.Approval
	if a == nil || a.GrantFamily == id.Nil {
		return nil, dependencyFailure(ctx, errNoApproval, "oidcprovider: load the device authorization")
	}
	if err := p.judgeDeviceUser(ctx, a.User); err != nil {
		return nil, err
	}
	expiresAt, holdsLineage, ok := deviceGrantLife(a, rc, now)
	if !ok {
		return nil, refuseGrant()
	}
	audience, err := resolveAudience(r.Form, record.Resources, rc, p.issuer, a.GrantedScopes)
	if err != nil {
		return nil, err
	}

	grant := newDeviceGrant(record, rc, r.Binding, holdsLineage, now, expiresAt)
	access, err := p.mintAccessToken(ctx, grant, rc, r.Binding, audience, now)
	if err != nil {
		return nil, err
	}
	res := &TokenResponse{
		AccessToken: access.value,
		TokenType:   access.tokenType,
		ExpiresIn:   access.expiresIn,
		Scope:       strings.Join(grant.Scopes, " "),
	}
	if slices.Contains(grant.Scopes, scopeOpenID) {
		// A device request carries no nonce, so the ID token has none.
		if res.IDToken, err = p.mintIDToken(ctx, grant, "", rc); err != nil {
			return nil, err
		}
	}

	err = p.cfg.device.store.Spend(ctx, record.ID, now)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, refuseGrant()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: spend the device authorization")
	}

	if err := p.storeDeviceGrant(ctx, grant); err != nil {
		return nil, err
	}
	if holdsLineage {
		if res.RefreshToken, err = p.writeLineage(ctx, grant, rc); err != nil {
			return nil, err
		}
	}
	if access.record != nil {
		err := p.stores.accessTokens.Create(ctx, access.record)
		if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
			return nil, dependencyFailure(ctx, err, "oidcprovider: store the access token")
		}
	}
	p.reportGrantCreated(ctx, grant)

	return res, nil
}

// storeDeviceGrant writes grant and reads it back. A store keeps a revocation recorded for the
// family before the row, so a row read back revoked was revoked before the exchange, and the
// exchange answers invalid_grant with nothing handed out.
func (p *Provider) storeDeviceGrant(ctx context.Context, grant *Grant) error {
	err := p.stores.grants.Create(ctx, grant)
	if err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable); err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: store the grant")
	}

	stored, err := p.stores.grants.Load(ctx, grant.Family)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case err != nil:
		// A row just written that cannot be read, or reads as missing, is the store failing.
		return dependencyFailure(ctx, err, "oidcprovider: read the grant back")
	case stored == nil:
		return dependencyFailure(ctx, errNoRecord, "oidcprovider: read the grant back")
	case stored.Revoked:
		return refuseGrant()
	}

	return nil
}

// judgeDeviceUser refuses an approving user who no longer exists, is disabled, or whom the
// loader names as someone else, and answers a loader failure as a dependency failure.
func (p *Provider) judgeDeviceUser(ctx context.Context, user identity.UserID) error {
	details, err := p.users.LoadByUserID(ctx, user)
	err = porterr.SanitizeTo(ctx, p.cfg.logger, err, porterr.ErrUnwalkable)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		return refuseGrant()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: load the device approval's user")
	case details == nil:
		return dependencyFailure(ctx, errNoRecord, "oidcprovider: load the device approval's user")
	case details.ID != user || !details.Active:
		return refuseGrant()
	}

	return nil
}

// deviceGrantLife is grantLife for a device approval: how long the grant lives, whether it
// holds a lineage, and false for a grant that would be over before it began.
//
// A grant survives its sign-in's end unless it ends with it by the one rule (design D8): tied
// to it by EndsWithSignIn, or holding neither offline_access nor SurvivesSignInEnd, so a tie
// wins over both. One that ends with it, and any grant holding no lineage, expires by the
// sign-in's absolute deadline, and is refused once it has passed, as a code is.
func deviceGrantLife(a *DeviceApproval, rc *RegisteredClient, now time.Time) (time.Time, bool, bool) {
	deadline := a.SignIn.AbsoluteExpiresAt
	holdsLineage := slices.Contains(rc.GrantTypes, GrantRefreshToken)
	capped := endsWithSignIn(a.Offline, a.EndsWithSignIn, a.SurvivesSignInEnd) || !holdsLineage
	if capped && !now.Before(deadline) {
		return time.Time{}, false, false
	}
	if !holdsLineage {
		return deadline, false, true
	}

	expiresAt := now.Add(rc.GrantAbsoluteLifetime)
	if capped && deadline.Before(expiresAt) {
		expiresAt = deadline
	}

	return expiresAt, true, true
}
