package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// BackchannelLogoutEvent is the member of a logout token's events claim that
// marks it as an OpenID Connect back-channel logout.
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// DefaultLogoutTokenMaxAge is how old a logout token's issued-at time may be,
// beyond the clock leeway, when WithLogoutTokenMaxAge is not given.
const DefaultLogoutTokenMaxAge = 2 * time.Minute

// LogoutClaims is what a verified back-channel logout token asserts.
type LogoutClaims struct {
	// Issuer is the issuer the token was verified against.
	Issuer string

	// Subject is the provider's subject the logout names, or empty when the
	// token names only a provider session.
	Subject string

	// SessionID is the provider session (sid) the logout names, or empty when
	// the token names only a subject.
	SessionID string

	// JTI is the token's unique identifier. The manager keeps no record of
	// the identifiers it has seen; it is returned so a caller can.
	JTI string
}

// VerifyLogoutToken verifies raw as a back-channel logout token from the
// named provider and returns what it asserts.
//
// The token's signature, algorithm, key id, issuer, audience and authorized
// party pass the same checks as an ID token of that provider. Beyond them it
// must carry an issued-at time no older than the maximum age
// (WithLogoutTokenMaxAge, default DefaultLogoutTokenMaxAge) plus the clock
// leeway (WithClockSkew) and no later than now plus the leeway; an expiry,
// which is optional, that has not passed; a non-empty string jti; an events
// claim whose BackchannelLogoutEvent member is a JSON object, whose contents
// are ignored; no nonce; and a non-empty sub, sid or both. Unknown claims are
// ignored.
//
// Replay is bounded by the issued-at window alone: no jti is recorded, so a
// captured token is accepted again until its issued-at is older than the
// maximum age plus the leeway. For a token naming only a subject, each such
// replay ends the user's matching sessions established since. Widening the
// maximum age widens that window.
//
// Every refusal wraps ErrInvalidLogoutToken, with a cause that names the rule
// that failed and never a claim value. A name the registry does not hold is
// ErrUnknownProvider, a key set that could not be fetched is
// ErrDiscoveryFailed, and a context error is returned as itself.
func (m *Manager) VerifyLogoutToken(ctx context.Context, provider, raw string) (LogoutClaims, error) {
	p, ok := m.registry.Lookup(provider)
	if !ok {
		return LogoutClaims{}, ErrUnknownProvider
	}
	c, err := m.checkLogoutToken(ctx, p, raw)
	if errors.Is(err, errTokenRefused) {
		return LogoutClaims{}, fmt.Errorf("%w: %w", ErrInvalidLogoutToken, err)
	}
	if err != nil {
		return LogoutClaims{}, err
	}
	return c, nil
}

func (m *Manager) checkLogoutToken(ctx context.Context, p Provider, raw string) (LogoutClaims, error) {
	tok, err := m.parseProviderJWT(ctx, p, raw, false)
	if err != nil {
		return LogoutClaims{}, err
	}

	// The issued-at window is checked here in both directions rather than
	// left to the parser, since exp is optional and iat is the replay bound.
	iat, ok := tok.IssuedAt()
	if !ok {
		return LogoutClaims{}, refused("no issued-at")
	}
	now := m.now()
	// The future-iat check below duplicates jwx's own default IsIssuedAtValid
	// validator (run inside parseProviderJWT's jwt.Parse); it is kept as
	// defence in depth rather than relied on as the only guard.
	if iat.After(now.Add(m.skew)) {
		return LogoutClaims{}, refused("issued in the future")
	}
	if now.Sub(iat) > m.logoutMaxAge+m.skew {
		return LogoutClaims{}, refused("issued too long ago")
	}

	claims, err := payloadClaims(raw)
	if err != nil {
		return LogoutClaims{}, err
	}
	if _, ok := claims["nonce"]; ok {
		return LogoutClaims{}, refused("carries a nonce")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return LogoutClaims{}, refused("no jti")
	}
	events, _ := claims["events"].(map[string]any)
	if _, ok := events[BackchannelLogoutEvent].(map[string]any); !ok {
		return LogoutClaims{}, refused("no back-channel logout event")
	}

	sub, err := optionalString(claims, "sub", "subject")
	if err != nil {
		return LogoutClaims{}, err
	}
	sid, err := optionalString(claims, "sid", "session id")
	if err != nil {
		return LogoutClaims{}, err
	}
	if sub == "" && sid == "" {
		return LogoutClaims{}, refused("neither a subject nor a session id")
	}

	return LogoutClaims{Issuer: p.Issuer, Subject: sub, SessionID: sid, JTI: jti}, nil
}

// optionalString returns the named claim, which may be absent but when
// present must be a string. what names it in the refusal.
func optionalString(claims map[string]any, name, what string) (string, error) {
	v, ok := claims[name]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", refused("the %s is not a string", what)
	}
	return s, nil
}
