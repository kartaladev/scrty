package oidcprovider

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// paramRefreshToken is the parameter a refresh names its token by.
const paramRefreshToken = "refresh_token"

// refreshAttempts bounds how often one refresh tries to rotate. Losing a race means another
// rotation of the same token has just landed, so the next attempt rotates what that one left.
// Each round has one winner, so this many racers are all served, and more than this many in
// one instant are told to try again rather than kept waiting. It is a proposed value, with no
// override: a client has nothing to gain from racing itself.
const refreshAttempts = 8

// errRefreshContended stands for a rotation that lost every one of its attempts. It says nothing
// of the token, which still has the standing it had.
var errRefreshContended = errors.New("oidcprovider: a refresh token's rotations kept racing")

// refresh answers a refresh request, in the order Token describes.
func (p *Provider) refresh(ctx context.Context, r TokenRequest, rc *RegisteredClient) (*TokenResponse, error) {
	raw := r.Form.Get(paramRefreshToken)
	if raw == "" {
		return nil, refuseRequest()
	}
	family, secret, ok := parseRefreshToken(raw)
	if !ok {
		return nil, refuseGrant()
	}
	now := p.cfg.clock.Now()

	grant, err := p.liveGrant(ctx, family, rc, now)
	if err != nil {
		return nil, err
	}
	if grant.KeyBinding != "" && r.Binding.JKT != grant.KeyBinding {
		return nil, &Error{Code: CodeInvalidDPoPProof}
	}
	if err := p.requireFamilyMember(ctx, secret, family); err != nil {
		return nil, err
	}

	manager, err := p.lineages(rc)
	if err != nil {
		return nil, dependencyFailure(ctx, err, "oidcprovider: build the lineage manager")
	}
	current, err := manager.LoadForRenewal(ctx, secret)
	if err != nil {
		return nil, p.answerLineage(ctx, err, family, now, "oidcprovider: read the refresh token")
	}

	if err := p.judgeGrantUser(ctx, grant, now); err != nil {
		return nil, err
	}
	scopes, err := refreshScopes(r.Form.Get(paramScope), grant, rc, p.cfg.bounds.Scope)
	if err != nil {
		return nil, err
	}
	audience, err := resolveAudience(r.Form, grant.Resources, rc, p.issuer, scopes)
	if err != nil {
		return nil, err
	}

	issued := *grant
	issued.Scopes = scopes
	mint := refreshMint{p: p, grant: &issued, rc: rc, binding: r.Binding, audience: audience, now: now}

	refreshToken := raw
	if rc.DisableRotation && current.SupersededAt.IsZero() {
		if err := mint.once(ctx); err != nil {
			return nil, err
		}
		if err := manager.Touch(ctx, current); err != nil {
			return nil, p.answerLineage(ctx, err, family, now, "oidcprovider: record the refresh")
		}
	} else if refreshToken, err = p.rotateLineage(ctx, manager, current, rc, &mint, now); err != nil {
		return nil, err
	}

	if err := p.requireStillLive(ctx, family); err != nil {
		return nil, err
	}
	if mint.access.record != nil {
		if err := p.stores.accessTokens.Create(ctx, mint.access.record); err != nil {
			return nil, dependencyFailure(ctx, err, "oidcprovider: store the access token")
		}
	}
	mint.res.RefreshToken = refreshToken

	return mint.res, nil
}

// parseRefreshToken reads rt.<family>.<secret>, in the one spelling the provider mints. A value
// of any other shape costs no lookup. The family is not a secret, and proves nothing.
func parseRefreshToken(raw string) (id.ID, string, bool) {
	rest, ok := strings.CutPrefix(raw, refreshTokenPrefix)
	if !ok {
		return id.Nil, "", false
	}
	family, secret, ok := splitCode(rest)
	if !ok || family.IsZero() || !strings.HasPrefix(rest, family.String()+".") || !session.ValidIdentifier(secret) {
		return id.Nil, "", false
	}

	return family, secret, true
}

// liveGrant reads the row a refresh token names, before anything changes state. What it refuses
// writes nothing, because the family a request names is no proof of anything (R8).
func (p *Provider) liveGrant(ctx context.Context, family id.ID, rc *RegisteredClient, now time.Time) (*Grant, error) {
	grant, err := p.stores.grants.Load(ctx, family)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, refuseGrant()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: read the refresh token's grant")
	case grant.Revoked || grant.ClientID != rc.ID || !now.Before(grant.ExpiresAt):
		return nil, refuseGrant()
	}

	return grant, nil
}

// requireFamilyMember refuses a secret that is no record of family, writing nothing. It reads
// the store directly, because the manager's load is a verdict with effects: it marks a live
// record presented, and revokes the family of a superseded one past its grace. Those belong to
// whoever presents a token naming that family, whose grant was just checked to be the client's.
// Without this, a client could end another client's grant by naming its own family beside a
// stale secret of the other's.
//
// A secret with no record is what a forged one and a revoked grant's look like alike (H4, R8).
// Neither is a revocation to record, and the row's being live changes nothing: a failure between
// an exchange's two writes leaves exactly that, for a client that was given no token (R19).
func (p *Provider) requireFamilyMember(ctx context.Context, secret string, family id.ID) error {
	record, err := oplineage.Sessions(p.stores.lineage).Load(ctx, secret)
	switch {
	case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired):
		return refuseGrant()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the refresh token")
	case record == nil || record.FamilyID != family:
		return refuseGrant()
	}

	return nil
}

// answerLineage turns what the lineage manager said into what the request ends with.
//
// Reuse has revoked the family and, through revokeOnReuse, marked the row, and is refused. When
// the family could not be deleted, the manager tells no observer, so the row is marked here, as
// it alone ends the grant, and the failure is answered as what it is. A gone or expired record is
// refused, and any other failure is no verdict on the token.
func (p *Provider) answerLineage(ctx context.Context, err error, family id.ID, now time.Time, text string) error {
	switch {
	case errors.Is(err, session.ErrReused):
		//nolint:errorlint // identity: the bare sentinel is the manager's word that the family went
		if err == session.ErrReused {
			return refuseGrant()
		}
		detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
		defer cancel()

		return dependencyFailure(ctx,
			errors.Join(err, p.stores.grants.Revoke(detached, family, CauseReuse, now)),
			"oidcprovider: revoke a reused refresh token's family")
	case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrExpired):
		return refuseGrant()
	default:
		return dependencyFailure(ctx, err, text)
	}
}

// judgeGrantUser refuses a user who no longer exists or is disabled, and revokes the grant.
// It runs once the token is known to be real, so a forged one cannot revoke. A loader that cannot
// answer is no verdict on the user. The revocation does not depend on the caller still listening.
func (p *Provider) judgeGrantUser(ctx context.Context, grant *Grant, now time.Time) error {
	details, err := p.users.LoadByUserID(ctx, grant.User)
	switch {
	case errors.Is(err, identity.ErrUserNotFound):
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: load the grant's user")
	case details != nil && details.ID == grant.User && details.Active:
		return nil
	}

	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()
	if err := p.revokeGrant(detached, grant.Family, CauseUserDisabled, now); err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: revoke a grant whose user has gone")
	}

	return refuseGrant()
}

// refreshScopes decides what a refresh's tokens carry: what it asked for, or the grant's own when
// it asked for nothing. Asking outside the grant is invalid_scope. A scope of the grant the
// client is no longer allowed is left out, and comes back when it is allowed again, since the
// grant keeps it (R13). A refresh left with nothing is invalid_scope too, because no token can
// state it. A value past the bound an authorization request meets is invalid_request.
func refreshScopes(raw string, grant *Grant, rc *RegisteredClient, bound int) ([]string, error) {
	if len(raw) > bound {
		return nil, refuseRequest()
	}
	asked := words(raw)
	if len(asked) == 0 {
		asked = grant.Scopes
	}
	kept := make([]string, 0, len(asked))
	for _, scope := range asked {
		if !slices.Contains(grant.Scopes, scope) {
			return nil, &Error{Code: CodeInvalidScope}
		}
		if slices.Contains(rc.Scopes, scope) {
			kept = append(kept, scope)
		}
	}
	if len(kept) == 0 {
		return nil, &Error{Code: CodeInvalidScope}
	}

	return kept, nil
}

// refreshMint signs a refresh's tokens, at most once however many attempts its rotation takes.
// None of them names the lineage record, so an attempt that lost a race leaves them good. grant
// is a copy whose scopes are what this refresh was given, and the stored one stays as it is.
type refreshMint struct {
	p        *Provider
	grant    *Grant
	rc       *RegisteredClient
	binding  Binding
	audience []string
	now      time.Time

	access *mintedAccessToken
	res    *TokenResponse
	err    error
}

// once signs the tokens, unless it already has. An ID token has no nonce to repeat, and keeps the
// authentication facts and sid of the grant, which copied them from the sign-in.
func (m *refreshMint) once(ctx context.Context) error {
	if m.res != nil {
		return nil
	}
	access, err := m.p.mintAccessToken(ctx, m.grant, m.rc, m.binding, m.audience, m.now)
	if err != nil {
		m.err = err

		return err
	}
	res := &TokenResponse{
		AccessToken: access.value,
		TokenType:   access.tokenType,
		ExpiresIn:   access.expiresIn,
		Scope:       strings.Join(m.grant.Scopes, " "),
	}
	if slices.Contains(m.grant.Scopes, scopeOpenID) {
		if res.IDToken, err = m.p.mintIDToken(ctx, m.grant, "", m.rc); err != nil {
			m.err = err

			return err
		}
	}
	m.access, m.res = access, res

	return nil
}

// rotateLineage supersedes current and returns its successor's refresh token. The tokens are
// signed in the rotation's step, ahead of its only write, so a key failure leaves the presented
// token with the standing it had, and an outage is no theft alarm when it is presented later.
//
// The store's conditional write is what makes one successor of many racers: the manager holds
// no lock over this. A loser tries again, which reads the record the winner left and rotates it
// again if it is still inside its grace, so that two tabs presenting one token both get tokens.
// That knocks out the winner's successor, leaving one live head, and presenting a knocked-out
// token is reuse, as RotateWithGrace documents. A record past its grace by then is reuse, and one
// gone by then has been revoked.
func (p *Provider) rotateLineage(
	ctx context.Context, manager *session.Sessions, current *session.Session, rc *RegisteredClient, mint *refreshMint, now time.Time,
) (string, error) {
	step := func(*session.Session) (string, error) { return "", mint.once(ctx) }

	for range refreshAttempts {
		next, _, _, err := manager.RotateWithGraceIssuing(ctx, current, rc.RefreshGrace, step)
		switch {
		case mint.err != nil:
			return "", mint.err
		case err == nil:
			return refreshTokenPrefix + next.FamilyID.String() + "." + next.ID, nil
		case !errors.Is(err, session.ErrRenewalConflict):
			return "", p.answerLineage(ctx, err, current.FamilyID, now, "oidcprovider: rotate the refresh token")
		}
	}

	return "", dependencyFailure(ctx, errRefreshContended, "oidcprovider: rotate the refresh token")
}

// requireStillLive reads the row again once the lineage has moved, so a revocation or a sign-in's
// end that landed since the first read answers no tokens. What this leaves stored is unusable
// anyway, since every refresh reads the row first. What the read saves is a JWT access token
// that a resource server verifying offline would accept until its exp. A revocation landing after
// this read is one the refresh came before, and its deletion of the family takes the successor.
func (p *Provider) requireStillLive(ctx context.Context, family id.ID) error {
	grant, err := p.stores.grants.Load(ctx, family)
	switch {
	case errors.Is(err, ErrNotFound):
		return refuseGrant()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the refresh token's grant")
	case grant.Revoked:
		return refuseGrant()
	}

	return nil
}

// revokeOnReuse is the lineage manager's reuse observer: the family has gone, and this marks its
// grant, which is what ends its opaque access tokens and the JWTs read through the provider. It
// does not depend on the caller still listening. It can return nothing, so a failure is logged,
// and the grant reads as revoked at every later refresh regardless, its lineage being gone (H4).
func (p *Provider) revokeOnReuse(ctx context.Context, r session.ReuseReport) {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()

	if err := p.stores.grants.Revoke(detached, r.Family, CauseReuse, r.DetectedAt); err != nil {
		p.cfg.logger.LogAttrs(ctx, slog.LevelError, "oidcprovider: a reused refresh token's grant could not be marked revoked",
			append(diag.Failure("revoke_grant", err), slog.String("family", r.Family.String()))...)
	}
}
