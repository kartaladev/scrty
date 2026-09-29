package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// errTokenRefused marks a provider token that parseProviderJWT judged and
// refused, as opposed to one it could not judge (a key set that could not be
// fetched, a canceled context). Each verifier turns it into its own sentinel.
var errTokenRefused = errors.New("oidc: provider token refused")

// refused returns a refusal of a provider token with a cause for logs. The
// cause names the rule that failed, never a claim value.
func refused(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errTokenRefused, fmt.Sprintf(format, args...))
}

// idClaims is what a verified ID token asserts, as the callback needs it.
type idClaims struct {
	Subject, SessionID, Email string
	EmailVerified             bool

	// Claims holds every claim of the token, decoded from its payload and
	// otherwise unchanged.
	Claims map[string]any
}

// verifyIDToken verifies raw as an ID token of p for the flow whose nonce is
// given, and returns what it asserts.
//
// Beyond parseProviderJWT's checks it requires exp, a string nonce equal to
// the flow's (compared in constant time; an empty flow nonce fails closed) and
// a non-empty sub. Every refusal wraps ErrInvalidIDToken with the failed rule;
// a key set that could not be fetched is returned as ErrDiscoveryFailed, and a
// context error as itself.
func (m *Manager) verifyIDToken(ctx context.Context, p Provider, raw, nonce string) (idClaims, error) {
	c, err := m.checkIDToken(ctx, p, raw, nonce)
	if errors.Is(err, errTokenRefused) {
		return idClaims{}, fmt.Errorf("%w: %w", ErrInvalidIDToken, err)
	}
	if err != nil {
		return idClaims{}, err
	}
	return c, nil
}

func (m *Manager) checkIDToken(ctx context.Context, p Provider, raw, nonce string) (idClaims, error) {
	tok, err := m.parseProviderJWT(ctx, p, raw, true)
	if err != nil {
		return idClaims{}, err
	}

	got, _ := stringField(tok, "nonce")
	if nonce == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return idClaims{}, refused("nonce does not match the flow")
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return idClaims{}, refused("no subject")
	}

	claims, err := payloadClaims(raw)
	if err != nil {
		return idClaims{}, err
	}
	c := idClaims{Subject: sub, Claims: claims}
	c.SessionID, _ = stringField(tok, "sid")
	c.Email, _ = stringField(tok, "email")
	verified, _ := tok.Field("email_verified")
	c.EmailVerified = verified == true // a JSON true only; "true" is not verified

	return c, nil
}

// parseProviderJWT verifies a token p signed and returns it for the caller's
// own claim checks. It is shared by the ID-token and logout-token verifiers,
// which differ on nonce, sub, events and jti and check those themselves.
//
// It requires a compact JWS with one signature, whose header algorithm is in
// p.SigningAlgs. An asymmetric algorithm needs a kid naming a key in the
// provider's key set that fits that algorithm; a symmetric one (listed only
// when the consumer chose it) is verified with p.ClientSecret and never
// consults the key set. Then the issuer must equal p.Issuer exactly, the
// audience must contain p.ClientID, and an azp, which several audiences
// require, must equal p.ClientID. exp, iat and nbf are judged against the
// manager's clock within its skew (WithClockSkew), and requireExp makes exp
// mandatory.
//
// A refusal wraps errTokenRefused, including a kid the key set does not hold.
// A key set that cannot be fetched is returned as ErrDiscoveryFailed, and a
// context error as itself: neither is a verdict on the token.
func (m *Manager) parseProviderJWT(ctx context.Context, p Provider, raw string, requireExp bool) (jwt.Token, error) {
	if !compactJWS(raw) {
		return nil, refused("not a compact JWS")
	}
	msg, err := jws.Parse([]byte(raw))
	if err != nil || len(msg.Signatures()) != 1 {
		return nil, refused("unreadable header")
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()
	algValue, ok := hdr.Algorithm()
	if !ok || !slices.Contains(p.SigningAlgs, algValue.String()) {
		return nil, refused("signature algorithm not accepted for the provider")
	}
	alg, ok := jwa.LookupSignatureAlgorithm(algValue.String())
	if !ok {
		return nil, refused("signature algorithm not accepted for the provider")
	}

	var key any
	if slices.Contains(symmetricAlgs, alg.String()) {
		key = []byte(p.ClientSecret)
	} else {
		kid, ok := hdr.KeyID()
		if !ok || kid == "" {
			return nil, refused("no key id")
		}
		set, err := m.keysFor(ctx, p.Name, kid)
		switch {
		case errors.Is(err, errUnknownSigningKey):
			return nil, refused("unknown signing key")
		case err != nil:
			return nil, err
		}
		k, ok := set.LookupKeyID(kid)
		if !ok || !signsWith(k, []string{alg.String()}) {
			return nil, refused("the signing key does not fit the algorithm")
		}
		key = k
	}

	opts := []jwt.ParseOption{
		jwt.WithKey(alg, key),
		jwt.WithValidate(true),
		jwt.WithIssuer(p.Issuer),
		jwt.WithAudience(p.ClientID),
		jwt.WithAcceptableSkew(m.skew),
		jwt.WithClock(jwt.ClockFunc(m.clock.Now)),
		// Judged at the clock's own resolution, whatever process-wide
		// truncation another package may have set.
		jwt.WithTruncation(0),
	}
	if requireExp {
		opts = append(opts, jwt.WithRequiredClaim(jwt.ExpirationKey))
	}
	tok, err := jwt.Parse([]byte(raw), opts...)
	if err != nil {
		return nil, refused("%s", jwtRule(err))
	}

	// Presence is decided on the raw claim, so an azp that is not a string
	// is refused rather than read as absent.
	aud, _ := tok.Audience()
	rawAzp, hasAzp := tok.Field("azp")
	azp, isString := rawAzp.(string)
	if (len(aud) > 1 && !hasAzp) || (hasAzp && (!isString || azp != p.ClientID)) {
		return nil, refused("authorized party is not the client")
	}
	return tok, nil
}

// jwtRule names the rule a jwt.Parse failure broke. It never returns the
// library's own text, which can repeat a malformed claim's value.
func jwtRule(err error) string {
	switch {
	case errors.Is(err, jwt.InvalidIssuerError{}):
		return "issuer is not the provider"
	case errors.Is(err, jwt.InvalidAudienceError{}):
		return "audience does not name the client"
	case errors.Is(err, jwt.MissingRequiredClaimError{}):
		return "a required claim is missing"
	case errors.Is(err, jwt.TokenExpiredError{}):
		return "the token has expired"
	case errors.Is(err, jwt.TokenNotYetValidError{}):
		return "the token is not yet valid"
	case errors.Is(err, jwt.InvalidIssuedAtError{}):
		return "the token was issued in the future"
	default:
		return "the token failed parsing or validation"
	}
}

// stringField returns the named claim when it is a string, and whether it is.
func stringField(tok jwt.Token, name string) (string, bool) {
	v, ok := tok.Field(name)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// payloadClaims decodes a verified compact JWS's payload as a JSON object, so
// the claims reach the consumer as the provider wrote them.
func payloadClaims(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, refused("unreadable payload")
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil || claims == nil {
		return nil, refused("the payload is not a JSON object")
	}
	return claims, nil
}

// compactJWS reports whether raw is exactly three base64url segments with a
// non-empty header and signature: the one presentation of a signed token
// accepted, so an unsigned or JSON-serialised one is refused before parsing.
func compactJWS(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return false
	}
	for _, s := range parts {
		for i := range len(s) {
			switch c := s[i]; {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}
