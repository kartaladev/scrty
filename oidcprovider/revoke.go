package oidcprovider

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
)

// The parameter revocation and introspection read a token from, and what an introspection says a
// refresh token is. token_type_hint needs no constant: T6's prefixes say what a value is, so there
// is no lookup for a hint to order, and one of any value is ignored, as RFC 7009 §2.1 lets it be.
const (
	paramToken = "token"

	tokenTypeRefresh = "refresh_token"
)

// Revoke ends the token form names, for the client that holds it (RFC 7009).
//
// A refresh token ends its whole grant, and an opaque access token ends itself. A superseded
// refresh token still names its grant, so presenting one here ends the grant as its client asked,
// recording CauseRevokedByClient: it is no reuse, which only a refresh detects, and its secret never
// reaches the lineage manager's judgement.
//
// A refresh token counts only when its secret is a record of the family it names, because a family
// is no credential. A value that fails that, a JWT access token, an unknown value and an expired
// token all answer success with nothing revoked. A JWT reads no key: there is nothing it could end,
// so whose it is goes unasked, and it is answered success whichever client presents it.
//
// A token the secret proves is another client's is refused with invalid_grant, revoking nothing. A
// public client may revoke by naming its client_id alone (RFC 7009 §2.1).
//
// The writes do not depend on the caller still listening. A refresh token's grant row is marked
// first, and its family deleted next. A row that cannot be marked leaves the family alone, as a
// family gone would answer the retry success with the row still live, and a family that cannot be
// deleted leaves the row marked: either failure is a dependency failure, and presenting the token
// again finishes the work. Nothing here has an override, since each is the standard's or R8's.
func (p *Provider) Revoke(ctx context.Context, c ClientCredentials, form url.Values) error {
	rc, raw, err := p.readTokenRequest(ctx, c, form, false)
	if err != nil {
		return err
	}

	switch {
	case strings.HasPrefix(raw, refreshTokenPrefix):
		return p.revokeRefreshToken(ctx, raw, rc)
	case strings.HasPrefix(raw, accessTokenPrefix):
		return p.revokeOpaqueToken(ctx, raw, rc)
	default:
		return nil
	}
}

// readTokenRequest is what revocation and introspection share: a repeated parameter is refused, the
// client authenticates, a public client is refused when refusePublic is set, and a token must be
// named, in that order, so that an unauthenticated request learns nothing of what it sent, and a
// public client is refused whatever it names.
func (p *Provider) readTokenRequest(ctx context.Context, c ClientCredentials, form url.Values, refusePublic bool) (*RegisteredClient, string, error) {
	if repeatedParam(form) {
		return nil, "", refuseRequest()
	}
	if c.Form == nil {
		c.Form = form
	}
	rc, err := p.AuthenticateClient(ctx, c)
	if err != nil {
		return nil, "", err
	}
	if refusePublic && rc.Type == Public {
		p.reportClientRefused(ctx, rc.ID)

		return nil, "", refuseClient()
	}
	raw := form.Get(paramToken)
	if raw == "" {
		return nil, "", refuseRequest()
	}

	return rc, raw, nil
}

// revokeRefreshToken runs the secret's check before the client's, so a client naming another's
// family beside a made-up secret hears what any unknown token hears, and cannot tell that the
// family is real. A row already revoked is ended again, as that is how a family left behind by an
// earlier failure goes, and is not reported again, as the store says nothing newly happened to it.
func (p *Provider) revokeRefreshToken(ctx context.Context, raw string, rc *RegisteredClient) error {
	family, secret, ok := parseRefreshToken(raw)
	if !ok {
		return nil
	}
	if _, err := p.requireFamilyMember(ctx, secret, family); err != nil {
		return nilIfRefused(err)
	}

	now := p.cfg.clock.Now()
	grant, err := p.stores.grants.Load(ctx, family)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the refresh token's grant")
	case !now.Before(grant.ExpiresAt):
		return nil
	case grant.ClientID != rc.ID:
		return refuseGrant()
	}

	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()
	newly, err := p.stores.grants.Revoke(detached, family, CauseRevokedByClient, now)
	if err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: revoke the refresh token's grant")
	}
	if newly {
		p.reportGrantRevoked(ctx, grant.ClientID, grant.User, CauseRevokedByClient)
	}
	manager, err := p.lineages(nil)
	if err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: build the lineage manager")
	}
	if _, err := manager.RevokeFamily(detached, family); err != nil {
		return dependencyFailure(ctx, err, "oidcprovider: delete the refresh token's family")
	}

	return nil
}

// revokeOpaqueToken marks one token, and no other of its grant. A token swept since it was read is
// what an unknown one is.
func (p *Provider) revokeOpaqueToken(ctx context.Context, raw string, rc *RegisteredClient) error {
	at, err := p.readOpaqueAccessToken(ctx, strings.TrimPrefix(raw, accessTokenPrefix))
	if err != nil {
		return nilIfRefused(err)
	}
	if at.ClientID != rc.ID {
		return refuseGrant()
	}

	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationBudget)
	defer cancel()
	if err := p.stores.accessTokens.Revoke(detached, at.ID); err != nil && !errors.Is(err, ErrNotFound) {
		return dependencyFailure(ctx, err, "oidcprovider: revoke the access token")
	}

	return nil
}

// nilIfRefused answers success for a token the provider refused to read, and leaves a failure, which
// is no verdict on the token, as it is.
func nilIfRefused(err error) error {
	if isRefusal(err) {
		return nil
	}

	return err
}

func isRefusal(err error) bool {
	var refusal *Error

	return errors.As(err, &refusal)
}

// Introspect says what the token form names is, for a client allowed to see it (RFC 7662).
//
// The endpoint requires authentication of its caller (RFC 7662 §2.1 and §4, against token scanning).
// A public client has no credential to authenticate with, so refusing it with invalid_client,
// whatever it names, is this provider's own rule, which the RFC leaves to the server. A request with
// no client authentication is refused the same way, as the RFC requires.
//
// A client sees a token issued to it, and an access token whose audience includes its
// [Client].ResourceIdentifier. A token it may not see, and an unknown,
// expired or revoked one, a JWT of a revoked grant included, answers exactly {"active": false}, so
// the answer does not say which it was.
//
// An active answer holds active, scope, client_id, sub, exp, iat, iss, aud and token_type, and cnf
// when the token is bound. token_type is DPoP for a token bound to a proof's key, Bearer for any other
// access token, and refresh_token for a refresh token, whose aud is the issuer, the only party it is
// presented to, and whose exp is the first of its grant's end, its own deadlines and the client's idle timeout and
// absolute lifetime as they stand.
//
// It writes nothing, and does not reach the lineage manager's judgement. A superseded refresh token
// is inactive, inside its grace too, though a refresh would still take it there, and is no reuse. It
// loads no user, so a disabled user's token reads as active until its grant is revoked.
//
// A store or key source that cannot answer is no verdict on the token: it matches ErrDependency, and
// a caller who left matches its own context's error. No error carries the token.
func (p *Provider) Introspect(ctx context.Context, c ClientCredentials, form url.Values) (map[string]any, error) {
	rc, raw, err := p.readTokenRequest(ctx, c, form, true)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(raw, refreshTokenPrefix) {
		return p.introspectRefreshToken(ctx, raw, rc)
	}

	at, err := p.VerifyAccessToken(ctx, raw)
	switch {
	case isRefusal(err):
		return inactiveToken(), nil
	case err != nil:
		return nil, err
	case !mayIntrospect(rc, at, p.issuer):
		return inactiveToken(), nil
	}

	return describeAccessToken(at), nil
}

// inactiveToken is the whole of what is said of a token that is not active.
func inactiveToken() map[string]any { return map[string]any{"active": false} }

// mayIntrospect is the visibility rule for an access token. A resource identifier equal to the
// issuer, which the registry's read already refuses, grants nothing here either: the issuer is in
// nearly every token's audience.
func mayIntrospect(rc *RegisteredClient, at *AccessToken, issuer string) bool {
	return at.ClientID == rc.ID ||
		rc.ResourceIdentifier != "" && rc.ResourceIdentifier != issuer && slices.Contains(at.Audience, rc.ResourceIdentifier)
}

func describeAccessToken(at *AccessToken) map[string]any {
	tokenType := tokenTypeBearer
	if at.Confirmation["jkt"] != "" {
		tokenType = tokenTypeDPoP
	}
	answer := map[string]any{
		"active":     true,
		"scope":      strings.Join(at.Scopes, " "),
		"client_id":  at.ClientID,
		"sub":        string(at.Subject),
		"exp":        at.ExpiresAt.Unix(),
		"iat":        at.IssuedAt.Unix(),
		"iss":        at.Issuer,
		"aud":        at.Audience,
		"token_type": tokenType,
	}
	if len(at.Confirmation) > 0 {
		answer["cnf"] = at.Confirmation
	}

	return answer
}

// introspectRefreshToken reads as a refresh's first steps do, and stops where a refresh would refuse
// or write: a holder alone sees the token, and every failed check answers the same.
func (p *Provider) introspectRefreshToken(ctx context.Context, raw string, rc *RegisteredClient) (map[string]any, error) {
	family, secret, ok := parseRefreshToken(raw)
	if !ok {
		return inactiveToken(), nil
	}
	now := p.cfg.clock.Now()

	grant, err := p.liveGrant(ctx, family, rc, now)
	if err != nil {
		return introspectionOf(err)
	}
	record, err := p.requireFamilyMember(ctx, secret, family)
	if err != nil {
		return introspectionOf(err)
	}
	if !record.SupersededAt.IsZero() || lifetimeOver(record, rc, now) {
		return inactiveToken(), nil
	}

	// The client's limits as they stand are what a refresh would judge by, so they bound exp as well as
	// the record's own, which a client shortening them since cannot reach.
	expiresAt := earliest(grant.ExpiresAt, record.IdleExpiresAt, record.AbsoluteExpiresAt,
		record.LastAccessedAt.Add(rc.GrantIdleTimeout), record.FamilyCreatedAt.Add(rc.GrantAbsoluteLifetime))
	answer := map[string]any{
		"active":     true,
		"scope":      strings.Join(grant.Scopes, " "),
		"client_id":  grant.ClientID,
		"sub":        string(grant.User),
		"exp":        expiresAt.Unix(),
		"iat":        record.CreatedAt.Unix(),
		"iss":        p.issuer,
		"aud":        []string{p.issuer},
		"token_type": tokenTypeRefresh,
	}
	switch {
	case grant.CertBinding != "":
		answer["cnf"] = map[string]string{"x5t#S256": grant.CertBinding}
	case grant.KeyBinding != "":
		answer["cnf"] = map[string]string{"jkt": grant.KeyBinding}
	}

	return answer, nil
}

// introspectionOf answers a refusal as a token that is not active, and leaves a failure as it is.
func introspectionOf(err error) (map[string]any, error) {
	if isRefusal(err) {
		return inactiveToken(), nil
	}

	return nil, err
}

func earliest(first time.Time, rest ...time.Time) time.Time {
	for _, at := range rest {
		if at.Before(first) {
			first = at
		}
	}

	return first
}
