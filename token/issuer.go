package token

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/token/signingkey"
)

// Issue is one token an Issuer is asked for.
type Issue struct {
	// Type is the token's typ header: TypeAccessToken, TypeIDToken,
	// TypeLogoutToken or a type of the consumer's own. There is no default,
	// because a token's kind is what a verifier tells it apart by. An empty or
	// blank one fails with ErrConfig, and so does TypeFirstParty, compared
	// without regard to case and with an "application/" prefix ignored: an
	// issuer must not stand in for a Generator, which alone issues first-party
	// tokens, and nothing is issued.
	Type string

	// Subject is the token's sub, exactly as given. Empty fails with
	// ErrNoSubject.
	Subject string

	// ID is the token's jti. Empty fails with ErrNoTokenID.
	ID string

	// Audience is the token's aud, for this token alone. There is no default:
	// no values, or a blank one, fails with ErrConfig.
	Audience []string

	// Lifetime is how long this token is valid. Zero takes the issuer's, set
	// by WithTokenLifetime. A negative one, one that is not a whole number of
	// seconds, and one past the cap of a key source that reports its lifetimes
	// each fail with ErrConfig.
	Lifetime time.Duration

	// Claims are the further claims, carried as given, such as client_id, scope,
	// nonce, auth_time, acr, amr, azp, sid, gid and events.
	//
	// iss, sub, aud, iat, exp and jti are the token's own: naming one fails with
	// ErrConfig. So does a value that cannot be encoded as JSON, or that the
	// claim's registered type refuses.
	//
	// cnf, the confirmation claim, is either a Confirmation or a map of its
	// members, held to what WithConfirmation allows, because Verify refuses a
	// malformed one. The zero Confirmation is no claim.
	Claims map[string]any
}

// Issuer issues tokens of a declared type, for a subject its caller names, with
// further claims and an audience for each token. It is for the tokens a Generator
// does not issue, such as an OAuth access token or an ID token.
//
// It is separate from Generator so that Generator's interface and subject modes
// stay as they are: an issuer takes no principal, and has no subject mode.
//
// One issuer signs with one algorithm under one issuer identifier. It is safe for
// concurrent use. Build it with NewIssuer; the zero value is not usable.
type Issuer struct{ cfg *config }

// NewIssuer returns an Issuer signing with keys under alg, naming issuer as the
// iss of every token. All three are required, because a token's verifier relies
// on them: there is no default algorithm here and no waiver of the issuer.
//
// Defaults: a 15-minute lifetime, replaced by WithTokenLifetime or by
// Issue.Lifetime; the system clock, replaced by WithClock. A nil option is
// skipped.
//
// Construction fails with ErrConfig when no key source is supplied, including a
// non-nil interface holding a nil pointer; when the algorithm is one this
// library's key sources cannot produce; when issuer is empty or blank; when the
// clock is nil; and when the lifetime cannot be honoured, as for NewGenerator.
//
// It also fails with ErrConfig for any Option other than WithTokenLifetime and
// WithClock, whatever value the option carries, even one equal to the default.
// WithIssuer, WithoutIssuer and WithSigningAlg would contradict the arguments; WithAudience,
// WithoutAudience and WithTokenType name what each Issue declares; and
// WithUsernameSubject names a mode an issuer does not have.
func NewIssuer(keys signingkey.KeySource, alg signingkey.Alg, issuer string, opts ...Option) (*Issuer, error) {
	cfg := newConfig()
	cfg.keys = keys
	cfg.alg = alg
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if err := cfg.refuseGeneratorOptions(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, fmt.Errorf("%w: the issuer given to NewIssuer is empty or blank", ErrConfig)
	}
	cfg.issuer = issuer
	cfg.hasIssuer = true

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.validateLifetime(); err != nil {
		return nil, err
	}

	return &Issuer{cfg: cfg}, nil
}

// refuseGeneratorOptions reports an option that means something for a generator
// and nothing, or something contradictory, for an issuer.
func (c *config) refuseGeneratorOptions() error {
	switch {
	case c.hasIssuer || c.issuerWaived:
		return fmt.Errorf("%w: NewIssuer takes the issuer as its argument: "+
			"WithIssuer and WithoutIssuer do not apply", ErrConfig)
	case c.hasAudience || c.audienceWaived:
		return fmt.Errorf("%w: an issuer's audience is each Issue's own: "+
			"WithAudience and WithoutAudience do not apply", ErrConfig)
	case c.algSet:
		return fmt.Errorf("%w: NewIssuer takes the algorithm as its argument: "+
			"WithSigningAlg does not apply", ErrConfig)
	case c.subjectSet:
		return fmt.Errorf("%w: an issuer's subject is each Issue's own: "+
			"WithUsernameSubject does not apply", ErrConfig)
	case c.tokenTypeSet:
		return fmt.Errorf("%w: an issuer's type is each Issue's own: "+
			"WithTokenType does not apply", ErrConfig)
	default:
		return nil
	}
}

// reservedClaims are the claims a token takes from its Issue and its issuer.
// aud is among them because Issue.Audience states it, so a further claim naming
// it could only contradict that field.
var reservedClaims = [...]string{"iss", "sub", "aud", "iat", "exp", "jti"}

// Issue signs the token in with the key source's current key for the issuer's
// algorithm. Every refusal returns an empty string, and a refused request never
// reaches the key source.
//
// ctx is passed to the key source, which is asked for a signer once for this
// token. The key source's failures are reported as Generate reports them: a
// missing key as "no current key for algorithm", anything else as an outage
// behind fixed library text. No failure here matches ErrInvalid.
func (i *Issuer) Issue(ctx context.Context, in Issue) (string, error) {
	cfg := i.cfg

	if err := checkIssue(in); err != nil {
		return "", fmt.Errorf("token: issue: %w", err)
	}
	lifetime := in.Lifetime
	if lifetime == 0 {
		lifetime = cfg.lifetime
	}
	if err := cfg.checkLifetime(lifetime); err != nil {
		return "", fmt.Errorf("token: issue: %w", err)
	}
	further, err := furtherClaims(in.Claims)
	if err != nil {
		return "", fmt.Errorf("token: issue: %w", err)
	}

	now := cfg.clock.Now()
	builder := jwt.NewBuilder().
		Issuer(cfg.issuer).
		Subject(in.Subject).
		Audience(in.Audience).
		JwtID(in.ID).
		IssuedAt(now).
		Expiration(now.Add(lifetime))
	for name, value := range further {
		builder = builder.Claim(name, value)
	}

	claims, err := builder.Build()
	if err != nil {
		// Only a further claim can fail this. Its value is the caller's and may be
		// sensitive, so the cause's text, which can quote it, is not kept.
		return "", fmt.Errorf("token: issue: %w: a further claim has a value its claim does not allow", ErrConfig)
	}

	kid, signer, err := cfg.currentSigner(ctx)
	if err != nil {
		return "", err
	}

	return cfg.sign(claims, kid, signer, in.Type)
}

// checkIssue refuses a request for a token that names no one, or no kind, or no
// audience.
func checkIssue(in Issue) error {
	if in.Subject == "" {
		return ErrNoSubject
	}
	if in.ID == "" {
		return ErrNoTokenID
	}
	typ := normalizeTokenType(in.Type)
	if strings.TrimSpace(typ) == "" {
		return fmt.Errorf("%w: a token must declare a type", ErrConfig)
	}
	if typ == normalizeTokenType(TypeFirstParty) {
		return fmt.Errorf("%w: an issuer does not issue first-party tokens: use a Generator", ErrConfig)
	}
	if len(in.Audience) == 0 {
		return fmt.Errorf("%w: a token must name an audience", ErrConfig)
	}
	for _, audience := range in.Audience {
		if strings.TrimSpace(audience) == "" {
			return fmt.Errorf("%w: an audience value is empty or blank", ErrConfig)
		}
	}

	return nil
}

// furtherClaims returns the claims to carry besides the token's own, with cnf in
// the form Verify reads, or reports why they cannot be carried. The map it was
// given is not changed. Values are never rendered: they are the caller's.
func furtherClaims(claims map[string]any) (map[string]any, error) {
	for _, name := range reservedClaims {
		if _, named := claims[name]; named {
			return nil, fmt.Errorf("%w: a further claim cannot replace %s", ErrConfig, name)
		}
	}

	// Asked here because signing would otherwise report it as a signing failure.
	if _, err := json.Marshal(claims); err != nil {
		return nil, fmt.Errorf("%w: a further claim cannot be encoded", ErrConfig)
	}

	value, hasConfirmation := claims[confirmationClaim]
	if !hasConfirmation {
		return claims, nil
	}

	cnf, err := issuableConfirmation(value)
	if err != nil {
		return nil, err
	}

	further := make(map[string]any, len(claims))
	for name, carried := range claims {
		if name != confirmationClaim {
			further[name] = carried
		}
	}
	if cnf != nil {
		further[confirmationClaim] = cnf
	}

	return further, nil
}

// issuableConfirmation renders a further cnf claim as Confirmation.claim does,
// so an issuer mints no binding that a generator would refuse to mint or that
// Verify would refuse to read.
func issuableConfirmation(value any) (map[string]any, error) {
	switch cnf := value.(type) {
	case Confirmation:
		return cnf.claim()
	case map[string]any:
		read, err := readConfirmation(cnf, true)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}

		return read.claim()
	default:
		return nil, fmt.Errorf("%w: a cnf claim is a Confirmation or a map of its members", ErrConfig)
	}
}
