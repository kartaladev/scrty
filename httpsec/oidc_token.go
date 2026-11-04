package httpsec

import (
	"errors"
	"net/http"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
)

// oidcTokenFlow names the token endpoint's rate-limit buckets and sampler keys.
const oidcTokenFlow = "oidc-token"

// oidcTokenGroup serves the token endpoint.
type oidcTokenGroup struct {
	oidcGroupBase

	throttle  oidcClientThrottle
	bodyLimit int64
}

// bind takes the provider's state, and the defaults the options replace.
func (g *oidcTokenGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
}

func (g *oidcTokenGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCToken], handle: g.serve},
	}
}

func (g *oidcTokenGroup) settle(c *config) error {
	return g.throttle.settle(c, oidcTokenFlow)
}

func (g *oidcTokenGroup) wire(ch *Chain) {
	g.throttle.wire(ch)
}

func (g *oidcTokenGroup) flushRefusalLogs() error {
	g.throttle.flush()

	return nil
}

// WithOIDCTokenLimiter counts the token endpoint's failed client authentications and
// invalid DPoP proofs through l.
//
// Default: the chain's rate-limiter factory (WithRateLimiterFactory) under namespace
// "oidc-token", or else an in-memory limiter of 10 failures per source in 15 minutes. A
// deployment of more than one replica supplies a factory or a limiter its replicas
// share, or the limit is per process.
//
// A source past its limit, a limiter that cannot answer and a source that cannot be
// attributed are all refused as invalid_client: the limit fails closed, and a client
// cannot tell it from a wrong credential. Unlike the authorization and resume endpoints,
// which answer 429, this endpoint's clients are told to expect that.
//
// A nil limiter, including an interface holding a nil pointer, is refused: it would read
// as no limit while the consumer believed they had replaced one.
func WithOIDCTokenLimiter(l ratelimit.Limiter) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if err := requireDep("WithOIDCTokenLimiter", "limiter", l); err != nil {
			return err
		}

		op.token.throttle.limiter = l

		return nil
	}
}

// WithOIDCTokenBodyLimit reads at most n bytes of a token request's body.
//
// Default: DefaultLoginBodyLimit. The bound applies before anything is parsed or any
// client is known, and a body over it answers ErrRequestTooLarge. A client's assertion
// and its resource parameters are what a body needs room for. A limit of zero or less is
// refused, because it would refuse every request.
func WithOIDCTokenBodyLimit(n int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if n <= 0 {
			return newConfigError("WithOIDCTokenBodyLimit takes a positive bound, and %d would refuse every "+
				"token request", n)
		}

		op.token.bodyLimit = n

		return nil
	}
}

// oidcTokenDocument is a successful token response (RFC 6749 section 5.1).
type oidcTokenDocument struct {
	AccessToken  string `json:"access_token"` //nolint:gosec // G117: the token is the document's purpose
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"` //nolint:gosec // G117: as AccessToken
}

// serve answers a request to the token endpoint. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. anything but POST is refused, and so is a request not made over TLS, as the chain
//     reports the connection, unless the provider was built with the loopback issuer, each
//     with nothing read from it;
//  3. the source is asked before anything else is read, so a throttled source costs no
//     parsing, no proof and no secret comparison;
//  4. the body is read, bounded, and the query only for credentials to refuse it for;
//  5. a DPoP proof is verified and recorded, so that a bad proof or one owing a nonce
//     reaches no client lookup and leaves a code unspent and a refresh token unrotated;
//  6. the provider authenticates the client and judges the grant, once. A client's
//     assertion is single-use, so nothing here authenticates it beforehand, and a nonce
//     round trip in step 5 has not spent one.
//
// A protocol refusal is answered here in its form. invalid_client and an invalid proof are
// charged to the source; a refused grant, a nonce asked for and any failure are not. A
// failure goes to the chain's error handling, and the provider reports its own security
// events, so nothing here reports one.
func (g *oidcTokenGroup) serve(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	if ex.Request.Method() != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return writeOIDCRefusal(ex, oidcprovider.CodeInvalidRequest)
	}

	src, ok := g.throttle.admit(ex, g.op)
	if !ok {
		return writeOIDCRefusal(ex, oidcprovider.CodeInvalidClient)
	}

	creds, err := readOIDCClientRequest(ex.Request, g.bodyLimit)
	if err != nil {
		return g.throttle.answer(ex, src, err)
	}

	ctx := ex.Context()

	binding, err := issuingBinding(ctx, ex.dpop(), ex.certBinding(), ex.Request, ex.bearerCredential)
	if err != nil {
		return g.refuseProof(ex, src, err)
	}

	res, err := g.op.provider.Token(ctx, oidcprovider.TokenRequest{
		Credentials: creds,
		Form:        creds.Form,
		Query:       creds.Query,
		Binding:     oidcBinding(binding),
	})
	if err != nil {
		return g.throttle.answer(ex, src, err)
	}

	return writeSuccessDocument(ex, oidcTokenDocument{
		AccessToken:  res.AccessToken,
		TokenType:    res.TokenType,
		ExpiresIn:    res.ExpiresIn,
		Scope:        res.Scope,
		IDToken:      res.IDToken,
		RefreshToken: res.RefreshToken,
	})
}

// oidcBinding states a request's proved key as the provider reads it.
func oidcBinding(b session.KeyBinding) oidcprovider.Binding {
	return oidcprovider.Binding{JKT: b.JKT, X5T: b.X5TS256}
}

// refuseProof answers the failure of a request's proof. RFC 9449 section 8 gives a token
// endpoint 400 where a resource server's answer is 401, and neither of them a challenge
// here, because the chain's challenge interceptor only sees what is returned to it.
//
// Asking for a nonce is the protocol's first step, and is charged to no one. A cipher that
// cannot seal the nonce, like a replay store that failed, is a dependency failure.
func (g *oidcTokenGroup) refuseProof(ex *Exchange, src ratelimit.Source, err error) error {
	switch {
	case errors.Is(err, ErrDPoPNonceRequired):
		nonce, _, serr := ex.dpop().issueNonce(ex.Context(), false)
		if serr != nil {
			return serr
		}

		setNonce(ex.Writer, nonce)

		return writeOIDCRefusal(ex, oidcprovider.CodeUseDPoPNonce)
	case chargesProofRefusal(err):
		g.throttle.charge(ex.Context(), src)

		return writeOIDCRefusal(ex, oidcprovider.CodeInvalidDPoPProof)
	default:
		return err
	}
}
