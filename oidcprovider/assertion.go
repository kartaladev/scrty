package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
)

//go:generate mockgen -source=assertion.go -package=oidcprovider_test -destination=assertion_mock_test.go -typed

// AssertionIDStore remembers the client assertions already accepted, so none is
// accepted twice. The provider records an identifier only after the assertion's
// signature and every other check have passed, so nobody who cannot sign for a client
// can fill the store. WithAssertionIDStore supplies one; with none, the provider keeps
// them in a MemoryAssertionIDStore.
type AssertionIDStore interface {
	// Record notes jti for clientID until until. It answers true when the pair was
	// not held, and false when it was, and a pair is one client's alone. It must decide
	// with one conditional write, so that of any number of concurrent calls exactly one
	// answers true. A refused call leaves the first until as it was, in either direction.
	//
	// A pair stays held until DeleteExpired removes it, whatever its until: Record judges
	// by no clock of its own. The provider refuses an expired assertion before it gets here,
	// and again after a Record that answers true, so a pair past its until is either a new
	// assertion reusing an old identifier or a replay that stalled on the way here.
	Record(ctx context.Context, clientID, jti string, until time.Time) (bool, error)

	// DeleteExpired removes the pairs whose until is strictly before before, and returns
	// how many it removed. It judges only by before, never by a clock of its own.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

const (
	// assertionTypeJWT is the client_assertion_type of RFC 7523 §2.2.
	assertionTypeJWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// assertionNotBeforeLeeway is how far ahead an assertion's nbf may lie, for a
	// client whose clock runs ahead.
	assertionNotBeforeLeeway = 60 * time.Second

	// tokenEndpointPath is where the token endpoint sits under the issuer by default,
	// and so the audience AudienceIssuerOrTokenEndpoint accepts unless told otherwise.
	tokenEndpointPath = "/oauth2/token" //nolint:gosec // a path, and no credential
)

// assertionAlgs are the signature algorithms an assertion may use. Every one is
// asymmetric: a client's registered keys are public, so nothing symmetric could be
// keyed by them without letting anyone who reads them sign.
var assertionAlgs = []string{
	"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512", "EdDSA",
}

// assertionTypes are the typ values an assertion may carry, besides none at all. Any
// other is refused, so an access token cannot authenticate a client (R13).
var assertionTypes = []string{"client-authentication+jwt", "JWT"}

// assertion is a client assertion as read, before its signature is checked. Nothing
// in it is believed until verifiedBy answers true.
type assertion struct {
	raw       string
	alg       jwa.SignatureAlgorithm
	kid       string
	issuer    string
	subject   string
	audience  []string
	jti       string
	expires   time.Time
	notBefore time.Time
}

// readAssertion takes the compact serialization alone. A JSON document can carry
// headers outside the signature and several signatures, and it reads as claims from
// its top level while its signature covers the payload inside, so a signature could
// vouch for claims it never saw. What would name a key from inside the token (jwk, jku,
// x5u, x5c) is ignored: keys only ever come from the client's registration.
func readAssertion(raw string) (*assertion, bool) {
	if !compactSerialization(raw) {
		return nil, false
	}
	msg, err := jws.ParseString(raw)
	if err != nil || len(msg.Signatures()) != 1 {
		return nil, false
	}

	hdr := msg.Signatures()[0].ProtectedHeaders()
	algValue, ok := hdr.Algorithm()
	if !ok || !slices.Contains(assertionAlgs, algValue.String()) {
		return nil, false
	}
	alg, ok := jwa.LookupSignatureAlgorithm(algValue.String())
	if !ok {
		return nil, false
	}
	if hdr.Has(jws.TypeKey) {
		if typ, _ := hdr.Type(); !slices.Contains(assertionTypes, typ) {
			return nil, false
		}
	}

	// The payload must be the claims themselves. ParseInsecure reads through a payload
	// that is a token of its own, so a wrapped one would supply the claims while its own
	// typ and alg went unseen.
	if payload := msg.Payload(); len(payload) == 0 || payload[0] != '{' {
		return nil, false
	}

	tok, err := jwt.ParseInsecure([]byte(raw))
	if err != nil {
		return nil, false
	}

	a := &assertion{raw: raw, alg: alg}
	a.kid, _ = hdr.KeyID()
	a.issuer, _ = tok.Issuer()
	a.subject, _ = tok.Subject()
	a.audience, _ = tok.Audience()
	a.jti, _ = tok.JwtID()
	a.expires, _ = tok.Expiration()
	a.notBefore, _ = tok.NotBefore()

	return a, true
}

// compactSerialization reports whether raw is three base64url parts. Counting periods
// alone would not do: a JSON document naming a URL can hold exactly two.
func compactSerialization(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if strings.ContainsFunc(part, notBase64URL) {
			return false
		}
	}

	return true
}

func notBase64URL(r rune) bool {
	switch {
	case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z', '0' <= r && r <= '9', r == '-', r == '_':
		return false
	}

	return true
}

// verifiedBy reports whether a key of set signed the assertion. A named kid selects
// its key and no other. With none, each key is tried.
func (a *assertion) verifiedBy(set jwk.Set) bool {
	if a.kid != "" {
		key, ok := set.LookupKeyID(a.kid)

		return ok && a.signedWith(key)
	}
	for _, key := range set.All() {
		if a.signedWith(key) {
			return true
		}
	}

	return false
}

// signedWith pins the algorithm to the one already allowed, so the token's header
// cannot choose how the key is used. A key that names its algorithm is used with no
// other.
func (a *assertion) signedWith(key jwk.Key) bool {
	if named, ok := key.Algorithm(); ok && named.String() != a.alg.String() {
		return false
	}
	_, err := jws.Verify([]byte(a.raw), jws.WithKey(a.alg, key))

	return err == nil
}

// authenticateAssertion verifies a private_key_jwt assertion (RFC 7523 §3, and
// rfc7523bis on the audience). The checks that cost nothing run first, so a stranger's
// assertion reaches neither the network nor the store: the signature is checked only
// once the claims would do, and the jti recorded only once the signature holds.
func (p *Provider) authenticateAssertion(ctx context.Context, got presented) (*RegisteredClient, error) {
	if got.assertionType != assertionTypeJWT {
		return nil, refuseClient()
	}
	a, ok := readAssertion(got.assertion)
	if !ok || (got.id != "" && got.id != a.issuer) {
		return nil, refuseClient()
	}

	rc, err := p.client(ctx, a.issuer)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, refuseClient()
	case err != nil:
		return nil, err
	case rc.AuthMethod != PrivateKeyJWT:
		return nil, refuseClient()
	}
	if !p.assertionClaimsHold(a) {
		return nil, refuseClient()
	}

	set, err := p.assertionKeys(ctx, rc, a.kid)
	if err != nil {
		return nil, err
	}
	if !a.verifiedBy(set) {
		return nil, refuseClient()
	}

	fresh, err := p.stores.assertionIDs.Record(ctx, rc.ID, a.jti, a.expires)
	switch {
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: record client assertion")
	case !fresh:
		return nil, refuseClient()
	}

	// Time has passed since assertionClaimsHold read the clock, over the signature and the
	// store. A store may forget a pair once its until is reached, and then a replay that
	// passed that check just before exp is told new here. No store's sweep can be relied on
	// to close that, so the expiry is judged again, after the answer.
	if !a.expires.After(p.cfg.clock.Now()) {
		return nil, refuseClient()
	}

	return rc, nil
}

// assertionClaimsHold checks what the signature does not. The caller has already found
// the client iss names.
func (p *Provider) assertionClaimsHold(a *assertion) bool {
	if a.subject != a.issuer || a.jti == "" || !p.assertionAudienceHolds(a.audience) {
		return false
	}

	now := p.cfg.clock.Now()
	if a.expires.IsZero() || !a.expires.After(now) || a.expires.After(now.Add(p.cfg.assertionMax)) {
		return false
	}

	return a.notBefore.IsZero() || !a.notBefore.After(now.Add(assertionNotBeforeLeeway))
}

// assertionAudienceHolds requires one value, whichever the rule, so an assertion
// naming two servers is never accepted by either (CVE-2025-27370).
func (p *Provider) assertionAudienceHolds(audience []string) bool {
	if len(audience) != 1 {
		return false
	}
	if audience[0] == p.issuer {
		return true
	}

	return p.cfg.assertionAudience == AudienceIssuerOrTokenEndpoint &&
		audience[0] == p.cfg.assertionTokenEndpoint
}

// assertionKeys returns the keys that may verify rc's assertion naming kid.
func (p *Provider) assertionKeys(ctx context.Context, rc *RegisteredClient, kid string) (jwk.Set, error) {
	if rc.JWKSURI != "" {
		return p.keySets.get(ctx, rc.ID, rc.JWKSURI, kid)
	}

	set, err := jwk.Parse(rc.JWKS)
	if err != nil {
		// A client read back has passed validation, which parsed this same value.
		return nil, fmt.Errorf("%w: a registered key set does not parse", ErrDependency)
	}

	return verificationKeys(set), nil
}

// verificationKeys keeps what can verify an assertion: public keys whose use and
// key_ops, when they name any, allow verifying a signature. A symmetric or private key in a fetched set is dropped and never
// used, whatever the document that held it says.
func verificationKeys(set jwk.Set) jwk.Set {
	usable := jwk.NewSet()
	for _, key := range set.All() {
		if isSymmetricKey(key) || isPrivateKey(key) {
			continue
		}
		if use, ok := key.KeyUsage(); ok && use != string(jwk.ForSignature) {
			continue
		}
		// RFC 7517 section 4.3: a key naming its operations is used for those alone.
		if ops, ok := key.KeyOps(); ok && !slices.Contains(ops, jwk.KeyOpVerify) {
			continue
		}
		// Only an exact repeat can fail to add, and that loses nothing.
		_ = usable.AddKey(key)
	}

	return usable
}

// dependencyFailure answers a failing dependency behind fixed text. A caller who left
// matches its own context's error instead, because that is no outage.
func dependencyFailure(ctx context.Context, err error, text string) error {
	if hangup.ByCaller(ctx, err) {
		return diag.Wrap(err, text+": the caller left", ctx.Err())
	}

	return diag.Wrap(err, text, ErrDependency)
}

// AssertionTokenEndpoint returns the token endpoint URL an assertion may name as its
// audience: the one WithAssertionTokenEndpoint gave, or the issuer followed by
// /oauth2/token under AudienceIssuerOrTokenEndpoint. Under the default issuer-only rule
// it is empty, because no endpoint is accepted. The chain compares it with the path it
// serves the token endpoint on.
func (p *Provider) AssertionTokenEndpoint() string { return p.cfg.assertionTokenEndpoint }
