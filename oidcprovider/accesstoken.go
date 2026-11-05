package oidcprovider

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

//go:generate mockgen -destination=accesstoken_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/oidcprovider AccessTokenStore

// accessTokenPrefix is the prefix of an opaque access token (T6).
const accessTokenPrefix = "at."

// The ways a token response says its access token is presented.
const (
	tokenTypeBearer = "Bearer"
	tokenTypeDPoP   = "DPoP"
)

// AccessToken is what a verified access token states.
type AccessToken struct {
	// Subject is the user the token speaks for.
	Subject identity.UserID
	// ClientID is the client the token was issued to.
	ClientID string
	// Scopes and Audience are what the token allows, and where. Nothing here checks the
	// audience: whoever accepts the token compares it with its own identifier.
	Scopes, Audience []string
	// Confirmation is the token's cnf claim, jkt or x5t#S256, and empty for a token bound
	// to no key. Whoever accepts the token checks the presenter holds the key.
	Confirmation map[string]string
	// Opaque says the token is an at.<id>.<secret> rather than a JWT.
	Opaque bool
	// GrantFamily names the grant the token was issued from.
	GrantFamily id.ID
	// ID is an opaque token's record, which nothing but the provider reads, and the nil
	// identifier for a JWT, whose jti names no record.
	ID id.ID
	// Issuer is the provider that issued the token.
	Issuer string
	// IssuedAt and ExpiresAt bound the token's own life.
	IssuedAt, ExpiresAt time.Time
}

// resolveAudience decides what an access token is for, from a request's resource values
// (RFC 8707). An empty value counts as omitted, a repeat counts once, and more values than an
// authorization request may carry are invalid_request.
//
// A resource must be one the client may ask for, and of the grant when it holds any, so a
// token narrows its grant and never widens it (R15). The grant itself keeps them all, for a
// later refresh to ask for another. What was asked for is exactly the audience: a client
// wanting UserInfo too asks for the issuer as well, which it can only do when it lists the
// issuer in Client.Resources (R4).
//
// With none asked for and a grant that holds one, that one is the audience, exactly as if it
// had been named, with no issuer even for an openid token (R15). With several held, none is
// chosen for the client: the request is invalid_target, and the client names what it wants.
// Both are judged here, before a code is spent.
//
// With none asked for and none held, the audience is the client's default, with the issuer
// added for an openid token so it stays usable at UserInfo (R4), or else the issuer alone.
// Client.Resources is never a default. Neither has an override beyond the client's own
// DefaultAudience and Resources: RFC 9068 §4 leaves no room for a token of any audience.
func resolveAudience(form url.Values, granted []string, rc *RegisteredClient, issuer string, scopes []string) ([]string, error) {
	values := form[paramResource]
	if len(values) > maxResources {
		return nil, refuseRequest()
	}

	named := slices.DeleteFunc(slices.Clone(values), func(value string) bool { return value == "" })
	if len(named) == 0 {
		switch {
		case len(granted) == 1:
			named = granted
		case len(granted) > 1:
			return nil, &Error{Code: CodeInvalidTarget}
		}
	}

	var asked []string
	for _, value := range named {
		if slices.Contains(asked, value) {
			continue
		}
		if !slices.Contains(rc.Resources, value) || len(granted) > 0 && !slices.Contains(granted, value) {
			return nil, &Error{Code: CodeInvalidTarget}
		}
		asked = append(asked, value)
	}
	if len(asked) > 0 {
		return asked, nil
	}

	if len(rc.DefaultAudience) == 0 {
		return []string{issuer}, nil
	}
	audience := slices.Clone(rc.DefaultAudience)
	if slices.Contains(scopes, scopeOpenID) && !slices.Contains(audience, issuer) {
		audience = append(audience, issuer)
	}

	return audience, nil
}

// mintedAccessToken is an access token ready to hand over. An opaque one also has its record
// to store, which happens only once the grant it reads is written (R18).
type mintedAccessToken struct {
	value, tokenType string
	expiresIn        int
	record           *AccessTokenRecord
}

// confirmationOf is the one key a token is bound to. A proof with a certificate binds the
// proof's key, because a token carries one binding and the proof is what the client asked for.
func confirmationOf(b Binding) token.Confirmation {
	if b.JKT != "" {
		return token.Confirmation{JKT: b.JKT}
	}

	return token.Confirmation{X5TS256: b.X5T}
}

// confirmationMembers is a confirmation as AccessToken and AccessTokenRecord hold it.
func confirmationMembers(c token.Confirmation) map[string]string {
	switch {
	case c.JKT != "":
		return map[string]string{"jkt": c.JKT}
	case c.X5TS256 != "":
		return map[string]string{"x5t#S256": c.X5TS256}
	default:
		return nil
	}
}

// errMalformedBinding stands for a binding that is no thumbprint, which only a failing caller
// of the provider can hand it: httpsec computes both from a verified proof or certificate.
var errMalformedBinding = errors.New("oidcprovider: a binding is not a SHA-256 thumbprint")

// bindingWellFormed says whether every key the binding names is a thumbprint a token can carry.
// It is judged for a token of either kind, because an opaque one is read back through a store
// that would otherwise keep the junk, and a public client's grant keeps the key beside it.
func bindingWellFormed(b Binding) bool {
	return (b.JKT == "" || token.WellFormedThumbprint(b.JKT)) &&
		(b.X5T == "" || token.WellFormedThumbprint(b.X5T))
}

// mintAccessToken makes grant's access token for audience. It writes nothing, so a failure
// costs nothing but the attempt: a code is still unspent (R18). A binding that is no
// thumbprint fails alike for every kind of token. Nothing caps the token at its grant's end,
// so a token may outlive its grant at a resource server that verifies it offline; expires_in
// states the token's own lifetime. A JWT carries gid so whoever
// holds the provider's store can tell its grant has ended (R4), and sub is the grant's user
// identifier (R6). It is signed with the algorithm the client's ID tokens use, the one
// algorithm the client's registration has checked the keys can produce.
func (p *Provider) mintAccessToken(
	ctx context.Context, grant *Grant, rc *RegisteredClient, binding Binding, audience []string, now time.Time,
) (*mintedAccessToken, error) {
	if !bindingWellFormed(binding) {
		return nil, dependencyFailure(ctx, errMalformedBinding, "oidcprovider: read the request's binding")
	}

	minted := &mintedAccessToken{tokenType: tokenTypeBearer, expiresIn: int(rc.AccessTokenLifetime / time.Second)}
	if binding.JKT != "" {
		minted.tokenType = tokenTypeDPoP
	}
	confirmation := confirmationOf(binding)

	if rc.OpaqueAccessTokens {
		tokenID, err := p.cfg.ids.NewID()
		if err != nil {
			return nil, dependencyFailure(ctx, err, "oidcprovider: mint an access token's identifier")
		}
		secret, digest, err := p.mintSecret()
		if err != nil {
			return nil, dependencyFailure(ctx, err, "oidcprovider: mint an access token's secret")
		}
		minted.value = accessTokenPrefix + tokenID.String() + "." + secret
		minted.record = &AccessTokenRecord{
			ID:           tokenID,
			Digest:       digest,
			GrantFamily:  grant.Family,
			ClientID:     rc.ID,
			User:         grant.User,
			Scopes:       slices.Clone(grant.Scopes),
			Audience:     slices.Clone(audience),
			Confirmation: confirmationMembers(confirmation),
			IssuedAt:     now,
			ExpiresAt:    now.Add(rc.AccessTokenLifetime),
		}

		return minted, nil
	}

	claims := authenticationClaims(grant)
	claims[claimClientID] = rc.ID
	claims[claimScope] = strings.Join(grant.Scopes, " ")
	claims[claimGID] = grant.Family.String()
	if confirmationMembers(confirmation) != nil {
		claims[claimCNF] = confirmation
	}

	raw, err := p.issue(ctx, rc, token.Issue{
		Type:     token.TypeAccessToken,
		Subject:  string(grant.User),
		Audience: audience,
		Lifetime: rc.AccessTokenLifetime,
		Claims:   claims,
	})
	if err != nil {
		return nil, dependencyFailure(ctx, err, "oidcprovider: sign the access token")
	}
	minted.value = raw

	return minted, nil
}

// buildAccessVerifier returns what reads the provider's own JWT access tokens: its keys, its
// issuer, its clock and the at+jwt type alone, so a first-party token, an ID token or a logout
// token under the same keys is refused. Audience is left to whoever accepts the token.
//
// Its size bound follows the request bounds, because a token states its scope and its resources:
// they go through base64url and JSON, which at most doubles them, and the rest of a token fits
// in the 8 KiB a verifier allows by default.
func buildAccessVerifier(keys signingkey.KeySource, issuer string, cfg *config) (*token.JWTVerifier, error) {
	verifier, err := token.NewVerifier(
		token.WithVerifyKeySource(keys),
		token.WithVerifyIssuer(issuer),
		token.WithoutVerifyAudience(),
		token.WithVerifyClock(cfg.clock),
		token.WithVerifyTokenType(token.TypeAccessToken),
		token.WithVerifyMaxTokenSize(2*(cfg.bounds.Scope+maxResources*cfg.bounds.Resource)+8<<10),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: Keys: %w", ErrConfig, err)
	}

	return verifier, nil
}

func refuseToken() error { return &Error{Code: CodeInvalidToken} }

// VerifyAccessToken reads an access token the provider issued, JWT or opaque, and says what it
// states, provided its grant is still live. Anything else presented as one, whether another type
// of token under the same keys, a refresh token or a code, is refused alike with invalid_token,
// and so is a token past its expiry, or naming no grant that holds it.
//
// A grant whose row is gone counts as revoked, because a revoked row is swept while a token set
// to a longer lifetime can outlive it, and so does a grant past its expiry, which the sweep would
// remove next. A JWT reads its grant through gid, so this is one store read per call, which
// resource servers verifying offline do not make: for them a JWT lasts until its exp.
//
// A store or key source that cannot answer is no verdict on the token: it matches ErrDependency
// behind fixed text, and a caller who left matches its own context's error. No error carries the
// token.
func (p *Provider) VerifyAccessToken(ctx context.Context, raw string) (*AccessToken, error) {
	read := p.readJWTAccessToken
	rest, opaque := strings.CutPrefix(raw, accessTokenPrefix)
	if opaque {
		read = p.readOpaqueAccessToken
		raw = rest
	}
	at, err := read(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err := p.requireGrantHolds(ctx, at); err != nil {
		return nil, err
	}

	return at, nil
}

// requireGrantHolds refuses a token whose grant is revoked, expired or gone, or names another
// client or user. Its row is what ends a token, and a store that cannot answer is no verdict.
func (p *Provider) requireGrantHolds(ctx context.Context, at *AccessToken) error {
	grant, err := p.stores.grants.Load(ctx, at.GrantFamily)
	switch {
	case errors.Is(err, ErrNotFound):
		return refuseToken()
	case err != nil:
		return dependencyFailure(ctx, err, "oidcprovider: read the access token's grant")
	case grant.Revoked || !p.cfg.clock.Now().Before(grant.ExpiresAt):
		return refuseToken()
	case grant.ClientID != at.ClientID || grant.User != at.Subject:
		return refuseToken()
	}

	return nil
}

// readOpaqueAccessToken reads <id>.<secret>. A secret of no shape the provider mints is refused
// with no lookup, and the digest is compared in constant time. The record's own expiry and mark
// are judged here, as a store judges neither.
func (p *Provider) readOpaqueAccessToken(ctx context.Context, raw string) (*AccessToken, error) {
	tokenID, secret, ok := splitCode(raw)
	if !ok || !strings.HasPrefix(raw, tokenID.String()+".") {
		// A token has the one spelling the provider mints, as its secret has.
		return nil, refuseToken()
	}
	digest, ok := digestEncoded(secret)
	if !ok {
		return nil, refuseToken()
	}

	record, err := p.stores.accessTokens.Load(ctx, tokenID)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, refuseToken()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: read the access token")
	case subtle.ConstantTimeCompare(digest, record.Digest) != 1:
		return nil, refuseToken()
	case record.Revoked || !p.cfg.clock.Now().Before(record.ExpiresAt):
		return nil, refuseToken()
	}

	return &AccessToken{
		Subject:      record.User,
		ClientID:     record.ClientID,
		Scopes:       slices.Clone(record.Scopes),
		Audience:     slices.Clone(record.Audience),
		Confirmation: maps.Clone(record.Confirmation),
		Opaque:       true,
		GrantFamily:  record.GrantFamily,
		ID:           record.ID,
		Issuer:       p.issuer,
		IssuedAt:     record.IssuedAt,
		ExpiresAt:    record.ExpiresAt,
	}, nil
}

// readJWTAccessToken verifies a JWT and reads the claims the provider always puts there, so one
// lacking any of them was not minted by this provider, whatever signed it: an audience, a jti, an
// iat, an exp, a scope, a grant. A confirmation holding a member the library cannot check, or naming both
// a DPoP key and a certificate when the provider binds a token to one, is refused rather than
// read as the one it kept or as no binding.
func (p *Provider) readJWTAccessToken(ctx context.Context, raw string) (*AccessToken, error) {
	claims, err := p.accessVerifier.Verify(ctx, raw)
	switch {
	case errors.Is(err, token.ErrInvalid):
		return nil, refuseToken()
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: verify the access token")
	}

	// An absent gid parses as nothing, and an absent client_id matches no grant's.
	gid, _ := stringClaim(claims, claimGID)
	clientID, _ := stringClaim(claims, claimClientID)
	scope, hasScope := stringClaim(claims, claimScope)
	confirmation := claims.Confirmation()
	if !hasScope || len(confirmation.Other) > 0 || confirmation.JKT != "" && confirmation.X5TS256 != "" {
		return nil, refuseToken()
	}
	audience := claims.Audience()
	issuedAt, hasIssuedAt := timeClaim(claims, "iat")
	expiresAt, hasExpiry := timeClaim(claims, "exp")
	if len(audience) == 0 || claims.ID() == "" || !hasIssuedAt || !hasExpiry {
		return nil, refuseToken()
	}
	family, err := id.Parse(gid)
	if err != nil {
		return nil, refuseToken()
	}

	return &AccessToken{
		Subject:      identity.UserID(claims.Subject()),
		ClientID:     clientID,
		Scopes:       strings.Fields(scope),
		Audience:     audience,
		Confirmation: confirmationMembers(confirmation),
		GrantFamily:  family,
		Issuer:       p.issuer,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
	}, nil
}

// timeClaim reads a registered time claim, which a verified token carries as a time.
func timeClaim(claims *token.Claims, name string) (time.Time, bool) {
	value, ok := claims.Claim(name)
	if !ok {
		return time.Time{}, false
	}
	at, ok := value.(time.Time)

	return at, ok
}

// stringClaim reads a further claim that must be a string.
func stringClaim(claims *token.Claims, name string) (string, bool) {
	value, ok := claims.Claim(name)
	if !ok {
		return "", false
	}
	text, ok := value.(string)

	return text, ok
}
