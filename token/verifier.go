package token

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/token/signingkey"
)

//go:generate mockgen -destination=keysource_mock_test.go -package=token_test -typed github.com/kartaladev/scrty/token/signingkey KeySource

// Verifier checks a token and returns its claims.
type Verifier interface {
	// Verify reports the claims of a token that passed every check. Every
	// rejection is an error matching ErrInvalid that wraps the cause; a
	// failure to obtain the key set, and a context cancelled before the check
	// finished, do not match it. A key-source failure comes back behind fixed
	// library text rather than as itself, with the key source's own error
	// still reachable through errors.Is and errors.As; a context cancellation
	// is returned as itself.
	//
	// The token must be presented exactly as it was issued: one compact JWS,
	// three unpadded base64url segments, and nothing around it. A re-encoded
	// presentation of an otherwise valid token is rejected, so one issued
	// token has one string that verifies and a consumer may key a revocation
	// list, a replay cache or a rate-limit bucket on it. No option relaxes
	// this.
	//
	// A token that does not declare the type this verifier is for, in its typ
	// header, is rejected too. See WithVerifyTokenType.
	Verify(ctx context.Context, token string) (*Claims, error)
}

// VerifyOption configures a Verifier. Every default NewVerifier applies has an
// option here that replaces it. The key source, the issuer and the audience
// have no default: the key source must be supplied, and the issuer and the
// audience must each be configured or explicitly waived.
type VerifyOption func(*config)

// WithVerifyKeySource sets where verification keys come from. Required: there
// is no default, because something has to hold the keys, so constructing a
// verifier without it is a configuration error.
func WithVerifyKeySource(keys signingkey.KeySource) VerifyOption {
	return func(c *config) { c.keys = keys }
}

// WithVerifyIssuer enforces iss: a token whose issuer is absent or different is
// rejected. There is no default issuer: NewVerifier fails with ErrConfig unless
// it is given either this option or WithoutVerifyIssuer, and fails when it is
// given both. An empty or blank iss (one made only of white space) is refused
// at construction with ErrConfig; any other value is enforced exactly as given,
// white space around it included. A verifier meant to accept any issuer uses
// WithoutVerifyIssuer.
func WithVerifyIssuer(iss string) VerifyOption { return VerifyOption(setIssuer(iss)) }

// WithVerifyAudience enforces aud: a token whose audience is absent or does not
// contain it is rejected. There is no default audience: NewVerifier fails with
// ErrConfig unless it is given either this option or WithoutVerifyAudience, and
// fails when it is given both. An empty or blank aud (one made only of white
// space) is refused at construction with ErrConfig; any other value is enforced
// exactly as given, white space around it included. A verifier meant to accept
// any audience uses WithoutVerifyAudience.
func WithVerifyAudience(aud string) VerifyOption { return VerifyOption(setAudience(aud)) }

// WithoutVerifyIssuer waives the issuer check, which NewVerifier otherwise
// requires through WithVerifyIssuer. It gives that check up entirely: any token
// signed by a key in the source is accepted whatever its issuer, including a
// token that carries none.
//
// Waive it only when every token signed by a key in the source is meant for
// this verifier. Given together with WithVerifyIssuer, it fails construction
// with ErrConfig.
func WithoutVerifyIssuer() VerifyOption { return VerifyOption(waiveIssuer()) }

// WithoutVerifyAudience waives the audience check, which NewVerifier otherwise
// requires through WithVerifyAudience. It gives that check up entirely: any
// token signed by a key in the source is accepted whatever its audience,
// including a token that carries none, so a token minted for another service
// that shares the key source verifies here.
//
// Waive it only when every token signed by a key in the source is meant for
// this verifier. Given together with WithVerifyAudience, it fails construction
// with ErrConfig.
func WithoutVerifyAudience() VerifyOption { return VerifyOption(waiveAudience()) }

// WithVerifyMaxTokenSize sets the largest token, in bytes, that Verify will
// look at. Default: 8192, which is generous for a compact JWS carrying an
// RS256 signature.
//
// A longer string is refused as an invalid token before anything is decoded
// and before the key source is consulted, so the work an unauthenticated
// request can buy stays bounded. Raise it for a consumer whose own claims are
// large; a size of zero or less fails construction, because a verifier that
// accepts nothing is a wiring mistake rather than a policy.
func WithVerifyMaxTokenSize(size int) VerifyOption {
	return func(c *config) { c.maxTokenSize = size }
}

// WithVerifyClock sets the time source for every time check. Default:
// clock.System(). No clock skew is tolerated, so this is the only way to move
// the instant a token is judged against.
//
// A nil clock, typed nil included, fails construction with ErrConfig: a
// verifier with no clock could not judge exp, nbf or iat at all.
func WithVerifyClock(clk clock.Clock) VerifyOption { return VerifyOption(setClock(clk)) }

// WithVerifyTokenType sets the one type the verifier accepts in a token's typ
// header. Default: TypeFirstParty, "scrty+jwt". A token declaring another type,
// or none, is refused as an invalid token, whatever else about it is valid. So
// a verifier for first-party tokens refuses an access token signed with the same
// keys, issuer and audience, and one for access tokens takes TypeAccessToken.
//
// The comparison ignores case and an "application/" prefix on either side. The
// value is otherwise taken literally: no option or value makes a verifier accept
// any type, because that would give up the separation between kinds of token
// this check exists for. An empty or blank typ fails construction with ErrConfig.
func WithVerifyTokenType(typ string) VerifyOption {
	return func(c *config) { c.tokenType = typ }
}

// JWTVerifier is the Verifier this package provides: it checks a JWT's
// signature against the keys of a signingkey.KeySource, and its claims against
// the configured issuer, audience and clock.
//
// Build it with NewVerifier; the zero value is not usable, because it has no
// key source and no validated configuration.
type JWTVerifier struct{ cfg *config }

// NewVerifier returns a JWTVerifier.
//
// WithVerifyKeySource is required. So is a decision on the issuer and on the
// audience: each is enforced, with WithVerifyIssuer and WithVerifyAudience, or
// waived by name, with WithoutVerifyIssuer and WithoutVerifyAudience. There is
// no default that checks neither. Defaults: the system clock; an 8192-byte
// maximum token size; TypeFirstParty as the one accepted type. Each is a
// VerifyOption naming its own default.
//
// A nil option is skipped, so a consumer may build the slice conditionally.
// Construction fails with ErrConfig when no key source is supplied, when the
// clock is nil, when the maximum token size is not positive, when the issuer
// or the audience is neither configured nor waived, when either is both
// configured and waived, when either is configured empty or blank (the empty
// string, or white space alone; the refusal names the waiver to use instead),
// and when the accepted type is empty or blank. A port given as a non-nil interface holding a nil
// pointer — what an unchecked constructor error hands over — counts as
// absent.
func NewVerifier(opts ...VerifyOption) (*JWTVerifier, error) {
	cfg := newConfig()
	for _, opt := range opts {
		// A consumer who builds the slice conditionally leaves an entry nil
		// without thinking about it; every other constructor in this library
		// skips one rather than panicking.
		if opt != nil {
			opt(cfg)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.validateClaims(verifierClaims); err != nil {
		return nil, err
	}
	if strings.TrimSpace(normalizeTokenType(cfg.tokenType)) == "" {
		return nil, fmt.Errorf("%w: the token type given to WithVerifyTokenType is empty or blank", ErrConfig)
	}

	return &JWTVerifier{cfg: cfg}, nil
}

// Verify checks raw's signature against the key source, its claims against the
// configured issuer, audience and clock, and its declared type against the one
// this verifier is for, and returns the claims. See Verifier.
func (v *JWTVerifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	return v.cfg.verify(ctx, raw)
}

// verify is the one verification path, shared by Verifier and Generator so a
// generator verifies under exactly the rules it issues under.
func (c *config) verify(ctx context.Context, raw string) (*Claims, error) {
	// First, and before anything is decoded: jws.Parse base64-decodes all
	// three segments before it checks a signature, so an unbounded string
	// buys roughly three times its own length in allocations per
	// unauthenticated request.
	if len(raw) > c.maxTokenSize {
		return nil, fmt.Errorf("%w: longer than the %d-byte maximum",
			ErrInvalid, c.maxTokenSize)
	}

	// Before the keys, because this is decidable from the string alone and
	// says nothing about the key source.
	if !canonicalCompact(raw) {
		return nil, fmt.Errorf("%w: not a canonical compact JWS", ErrInvalid)
	}

	keys, err := c.keys.VerificationKeys(ctx)
	if err != nil {
		// Not a rejection of the token: the keys could not be obtained. This
		// deliberately does not match ErrInvalid, so a key-service
		// outage is never reported as a failed authentication. The key
		// source's own error is returned behind fixed library text; it stays
		// reachable through errors.Is and errors.As, but its text never is.
		return nil, diag.Wrap(err, "token: obtain key set")
	}

	// The port permits a nil result and an empty one alike, and a KMS- or
	// HSM-backed source may well produce either while it is warming up or has
	// lost its backend. Neither is a verdict on the token: with nothing to
	// check against, the check did not happen. Reported as an outage, and
	// stopped here rather than rendered — jwt.WithKeySet on an empty set
	// panics inside the JOSE stack.
	if len(keys) == 0 {
		return nil, fmt.Errorf("token: obtain key set: %w", ErrNoVerificationKeys)
	}

	set, err := keySet(keys)
	if err != nil {
		return nil, err
	}

	// The header is read once, here, by the parser that reads the signature's
	// header. It must name an algorithm, and the one recorded on the key its kid
	// selects, before anything is verified: the JOSE stack's own answers to a
	// header naming none, or another, are its defaults and have changed between
	// releases, so the refusal is this package's, and holds whatever the stack
	// does next.
	header, err := readHeader(raw)
	if err != nil {
		return nil, err
	}
	if err := header.matchesKey(keys); err != nil {
		return nil, err
	}

	// The key is selected by the token's kid, and the algorithm recorded on
	// that key checks the signature. Requiring the kid is the default; it is
	// never relaxed.
	//
	// The validation rules were built once, at construction. They are only
	// read from here, never appended to, because the slice is shared by every
	// concurrent verification.
	opts := make([]jwt.ParseOption, len(c.parseOpts)+2)
	opts[0] = jwt.WithKeySet(set)
	opts[1] = jwt.WithContext(ctx)
	copy(opts[2:], c.parseOpts)

	tok, err := jwt.Parse([]byte(raw), opts...)
	if err != nil {
		return nil, classify(err)
	}

	// After the signature, so what is judged is what the key signed, and before
	// anything is handed back.
	if err := c.checkTokenType(header); err != nil {
		return nil, err
	}

	// Read once, here, so a malformed binding is a refusal of the token
	// rather than a binding that silently reads as none.
	cnf, err := readConfirmation(tok.Field(confirmationClaim))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	return &Claims{tok: tok, cnf: cnf}, nil
}

// errOtherTokenType is the cause every refused type wraps. The presented type is
// never rendered: it is the presenter's input.
var errOtherTokenType = errors.New("the token does not declare the type this verifier is for")

// errNoAlgorithm is the cause a header naming no algorithm wraps. Its text
// carries no header value. An error the JOSE stack returns for a header it
// cannot read is wrapped as it is, and may quote what the header held.
var errNoAlgorithm = errors.New("the token header does not name its algorithm")

// errOtherAlgorithm is the cause a header naming an algorithm other than its
// key's wraps. Its text carries neither algorithm.
var errOtherAlgorithm = errors.New("the token header names an algorithm other than its key's")

// tokenHeader is what verification reads from a token's protected header.
type tokenHeader struct {
	alg         string
	kid         string
	typ         string
	declaresTyp bool
}

// matchesKey refuses a header whose alg is not the algorithm recorded on the
// key its kid selects, as RFC 8725 section 3.1 asks a verifier to check. A key
// source publishes one key per kid, but should it publish more, every one of
// them must record the header's algorithm, so no key is tried under another.
// A kid no key carries, or none at all, is left to the JOSE stack, which
// refuses it as a token no published key signed.
func (h tokenHeader) matchesKey(keys []signingkey.PublicKey) error {
	for _, pk := range keys {
		if pk.Kid == h.kid && pk.Alg != h.alg {
			return fmt.Errorf("%w: %w", ErrInvalid, errOtherAlgorithm)
		}
	}

	return nil
}

// readHeader reads raw's one protected header and refuses it when it names no
// algorithm, or an empty one, as RFC 7515 section 4.1.1 requires it to. A header
// whose alg is empty, unknown or not a string does not parse, and is refused here
// too; the emptiness check below holds whatever the parser accepts next.
//
// It parses with the JOSE stack rather than decoding the header here, so the
// header judged is the one the signature covers, and a member spelled TYP or ALG
// stays a member of another name.
func readHeader(raw string) (tokenHeader, error) {
	message, err := jws.Parse([]byte(raw))
	if err != nil {
		return tokenHeader{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	// canonicalCompact has held raw to a single signature; this holds whatever
	// the parser makes of it.
	signatures := message.Signatures()
	if len(signatures) != 1 {
		return tokenHeader{}, fmt.Errorf("%w: not exactly one signature", ErrInvalid)
	}
	protected := signatures[0].ProtectedHeaders()

	alg, ok := protected.Algorithm()
	if !ok || alg.String() == "" {
		return tokenHeader{}, fmt.Errorf("%w: %w", ErrInvalid, errNoAlgorithm)
	}

	kid, _ := protected.KeyID()
	typ, declared := protected.Type()

	return tokenHeader{alg: alg.String(), kid: kid, typ: typ, declaresTyp: declared}, nil
}

// checkTokenType refuses a verified token whose typ is not the verifier's, so one
// kind of token is not accepted as another where keys, issuer and audience are
// shared.
func (c *config) checkTokenType(header tokenHeader) error {
	if !header.declaresTyp || normalizeTokenType(header.typ) != normalizeTokenType(c.tokenType) {
		return fmt.Errorf("%w: %w", ErrInvalid, errOtherTokenType)
	}

	return nil
}

// keySet renders the keys a source supplied as the set the JOSE stack selects
// from. Each key carries the identifier verification matches on, the one
// algorithm it verifies, and signature use, which is what stops a key being
// tried under an algorithm it was not published for.
//
// Building the set here rather than taking one from the source is what keeps
// the JOSE stack out of KeySource: a consumer implementing the port describes
// its keys with crypto and this package's own types, and a major version bump
// in the stack is this file's problem and nobody else's.
func keySet(keys []signingkey.PublicKey) (jwk.Set, error) {
	set := jwk.NewSet()

	for _, pk := range keys {
		// A nil pointer inside the key interface is a key the source failed
		// to build. The JOSE stack dereferences it, so it is refused here as
		// the outage it is, in the same terms as a key it cannot read.
		if nilcheck.IsNil(pk.Key) {
			return nil, fmt.Errorf("token: obtain key set: key %q is nil", pk.Kid)
		}
		key, err := jwk.Import[jwk.Key](pk.Key)
		if err != nil {
			// An outage, not a rejection, and never a skip. Dropping the key
			// would leave the check to run against whatever else the source
			// published, so a token signed by one of those would be accepted
			// and the misconfigured key would go unreported for as long as
			// the process lived.
			return nil, fmt.Errorf("token: obtain key set: read key %q: %w", pk.Kid, err)
		}
		if err := key.Set(jwk.KeyIDKey, pk.Kid); err != nil {
			return nil, fmt.Errorf("token: obtain key set: set kid %q: %w", pk.Kid, err)
		}
		if err := key.Set(jwk.AlgorithmKey, pk.Alg); err != nil {
			return nil, fmt.Errorf("token: obtain key set: set alg %q on key %q: %w",
				pk.Alg, pk.Kid, err)
		}
		if err := key.Set(jwk.KeyUsageKey, string(jwk.ForSignature)); err != nil {
			return nil, fmt.Errorf("token: obtain key set: set use on key %q: %w", pk.Kid, err)
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("token: obtain key set: add key %q: %w", pk.Kid, err)
		}
	}

	return set, nil
}

// classify turns a failed parse into the error a caller acts on.
//
// A token is only invalid when it was actually judged. A check the caller
// abandoned says nothing about the token, so a context failure is reported as
// itself — read from the error, not from whether the context happens to be
// dead by now, which would relabel a genuine rejection on a request whose
// deadline lapsed a moment later.
func classify(err error) error {
	for _, infrastructure := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, infrastructure) {
			return fmt.Errorf("token: verify: %w", err)
		}
	}

	return fmt.Errorf("%w: %w", ErrInvalid, err)
}

// canonicalCompact reports whether raw is the single presentation of a compact
// JWS this package accepts: exactly three "."-separated segments, each one
// RFC 7515 base64url with no padding, and a non-empty header and signature.
//
// It exists because jwt.Parse is lenient. It trims surrounding whitespace and
// verifies against a signing input it rebuilds from the decoded segments, so
// base64 padding, the standard "+/" alphabet and stray Unicode space all
// survive it: one issued token would otherwise have unboundedly many distinct
// strings that verify as it, and a consumer keying a revocation list, a replay
// cache, an idempotency record or a rate-limit bucket on the presented string
// would not recognise a re-encoded presentation of a token it already refused.
//
// An empty payload is left to the JOSE stack, which rejects it as it is not
// JSON. This check is about the encoding, not the content.
func canonicalCompact(raw string) bool {
	header, rest, ok := strings.Cut(raw, ".")
	if !ok {
		return false
	}
	payload, signature, ok := strings.Cut(rest, ".")
	if !ok {
		return false
	}
	if header == "" || signature == "" {
		return false
	}

	// A fourth segment lands inside signature, where its "." fails here.
	return base64URL(header) && base64URL(payload) && base64URL(signature)
}

// base64URL reports whether s is entirely RFC 7515 base64url characters. It
// reads bytes, so every byte of a multi-byte rune fails it.
func base64URL(s string) bool {
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}

	return true
}

var _ Verifier = (*JWTVerifier)(nil)
