package httpsec

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/kartaladev/scrty/oidcprovider"
)

//go:generate mockgen -destination=claimsource_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/oidcprovider ClaimSource

const (
	// oidcAccessTokenParam is the form parameter a POST may carry the token in (RFC 6750 section
	// 2.2).
	oidcAccessTokenParam = "access_token"

	// The members of an access token's confirmation UserInfo holds it to.
	oidcConfirmationJKT = "jkt"
	oidcConfirmationX5T = "x5t#S256"

	// oidcNoTokenChallenge answers a request with no token. RFC 6750 section 3 has the scheme
	// followed by at least one parameter, and section 3.1 no code here, so what follows is a realm.
	oidcNoTokenChallenge = `Bearer realm="oauth2"` //nolint:gosec // G101: a challenge's name for a scheme, and no credential
)

// oidcUserInfoGroup serves the UserInfo endpoint.
type oidcUserInfoGroup struct {
	oidcGroupBase

	bodyLimit int64
}

// bind takes the provider's state, and the defaults the options replace.
func (g *oidcUserInfoGroup) bind(op *oidcEndpoints) {
	g.oidcGroupBase.bind(op)
	g.bodyLimit = DefaultLoginBodyLimit
}

func (g *oidcUserInfoGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCUserInfo], handle: g.serve},
	}
}

// WithOIDCUserInfoBodyLimit reads at most limit bytes of a POST's body at UserInfo.
//
// Default: DefaultLoginBodyLimit. The bound applies before anything is parsed, and a body over it
// answers ErrRequestTooLarge. Only a body that declares a form is read at all. A limit of zero or
// less is refused, because it would refuse every token sent in a form.
func WithOIDCUserInfoBodyLimit(limit int64) OIDCProviderOption {
	return func(op *oidcEndpoints) error {
		if limit <= 0 {
			return newConfigError("WithOIDCUserInfoBodyLimit takes a positive bound, and %d would refuse "+
				"every token sent in a form", limit)
		}

		op.userinfo.bodyLimit = limit

		return nil
	}
}

// serve answers a request to UserInfo. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. anything but GET and POST is refused, and so is a request not made over TLS, as the chain
//     reports the connection, unless the provider was built for a loopback issuer, each with no
//     token read;
//  3. the token is read from the header or a POST's form, never the query, and a token in the query
//     beside one of those is two methods, which is malformed;
//  4. the provider reads the token, so a proof's work is spent only on a token it issued;
//  5. the token is held to its key: a proof is verified over it, the binding is judged, and the
//     proof is recorded last, so a replayed one reads no user and no claims;
//  6. the provider answers with the claims.
//
// A refusal is answered here as a resource server's, in a challenge and no body: 400 for
// invalid_request, which is a malformed request and one refused for plain http, 403 for
// insufficient_scope, and 401 for any other (RFC 6750 section 3.1). A malformed request that
// presented its token under the DPoP scheme is challenged under that scheme too (RFC 9449 section
// 7.2). Any failure goes to the chain's error handling, whose answer holds no text, and charges no one: nothing
// here spends a credential, so no source is counted.
//
// None of this has an override, each step being a standard's: a consumer replaces where claims come
// from (oidcprovider.WithClaimSource) and the bound on a body (WithOIDCUserInfoBodyLimit).
func (g *oidcUserInfoGroup) serve(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	method := ex.Request.Method()
	if method != http.MethodGet && method != http.MethodPost {
		ex.Writer.SetHeader("Allow", http.MethodGet+", "+http.MethodPost)
		ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

		return nil
	}

	v := ex.dpop()

	if !ex.Request.Secure() && !g.op.plainHTTPAllowed() {
		return writeOIDCMalformed(ex, v, false)
	}

	raw, underDPoP, err := g.readToken(ex)
	if err != nil {
		var refusal *oidcprovider.Error
		if errors.As(err, &refusal) && refusal.Code == oidcprovider.CodeInvalidRequest {
			return writeOIDCMalformed(ex, v, underDPoP)
		}

		return err
	}

	if raw == "" {
		return writeOIDCNoToken(ex, v)
	}

	ctx := ex.Context()

	at, err := g.op.provider.VerifyAccessToken(ctx, raw)
	if err != nil {
		return g.refuse(ex, oidcDPoPChallenged(v, underDPoP, nil), err)
	}

	asDPoP := oidcDPoPChallenged(v, underDPoP, at)

	if answered, err := holdToKey(ex, v, underDPoP, raw, at, asDPoP); answered {
		return err
	}

	claims, err := g.op.provider.UserInfo(ctx, at)
	if err != nil {
		return g.refuse(ex, asDPoP, err)
	}

	return writeSuccessDocument(ex, claims)
}

// readToken reads the token from the request, and "" when it carries none: no header, a scheme this
// endpoint does not read, or an empty parameter, which counts as omitted. RFC 6750 section 3.1 makes a
// repeated parameter, a repeated header and more than one way of sending the token invalid_request,
// and section 2 makes a token in the query beside another method one of those, though a token in the
// query alone is no token. The query is judged by name in its raw form, whether or not the framework
// parsed the pair, so that a value that does not decode, a bare name and an empty value each count as
// a second method: the client sent one. A body is read only for a POST that declares a form, because section 2.2
// reads a token from nothing else. underDPoP is reported with an error too, so that the refusal can be
// challenged in the scheme the token came in.
func (g *oidcUserInfoGroup) readToken(ex *Exchange) (raw string, underDPoP bool, err error) {
	raw, underDPoP, err = g.readHeaderOrForm(ex)
	if err != nil {
		return "", underDPoP, err
	}

	if raw != "" && queryNamesAny(ex.Request.RawQuery(), []string{oidcAccessTokenParam}) {
		return "", underDPoP, &oidcprovider.Error{Code: oidcprovider.CodeInvalidRequest}
	}

	return raw, underDPoP, nil
}

// readHeaderOrForm is readToken's reading of the two places a token may be sent.
func (g *oidcUserInfoGroup) readHeaderOrForm(ex *Exchange) (raw string, underDPoP bool, err error) {
	r := ex.Request

	if len(r.HeaderValues(oidcAuthorizationHeader)) > 1 {
		return "", false, &oidcprovider.Error{Code: oidcprovider.CodeInvalidRequest}
	}

	raw, underDPoP, claimed := presentedBearer(r.Header(oidcAuthorizationHeader), "Bearer", false, ex.dpop())

	if r.Method() != http.MethodPost || !declaresForm(r.Header("Content-Type")) {
		return raw, underDPoP, nil
	}

	body, err := r.Body(g.bodyLimit)

	switch {
	case errors.Is(err, ErrRequestTooLarge):
		return "", false, ErrRequestTooLarge
	case err != nil:
		return "", underDPoP, &oidcprovider.Error{Code: oidcprovider.CodeInvalidRequest}
	}

	form, err := url.ParseQuery(string(body))
	if err != nil {
		return "", underDPoP, &oidcprovider.Error{Code: oidcprovider.CodeInvalidRequest}
	}

	values := form[oidcAccessTokenParam]
	if len(values) > 1 || (claimed && form.Get(oidcAccessTokenParam) != "") {
		return "", underDPoP, &oidcprovider.Error{Code: oidcprovider.CodeInvalidRequest}
	}

	if claimed {
		return raw, underDPoP, nil
	}

	return form.Get(oidcAccessTokenParam), false, nil
}

// refuse answers err in a challenge when the protocol names it, and leaves a failure, which is no
// verdict on the token, to the chain.
func (g *oidcUserInfoGroup) refuse(ex *Exchange, asDPoP bool, err error) error {
	var refusal *oidcprovider.Error
	if !errors.As(err, &refusal) {
		return err
	}

	return writeOIDCChallenge(ex, asDPoP, refusal.Code)
}

// holdToKey is D8's check of a presented credential, for a token the provider read rather than the
// chain's bearer: a certificate binding is judged against the request's certificate, a DPoP binding
// against a proof over the token, and an unbound token is held to whether DPoP is required. It refuses
// what the chain's bearer modes refuse, and tells a proof that failed (invalid_dpop_proof) from a key
// that does not fit (invalid_token), as RFC 9449 section 7.1 does.
//
// When answered is true the request has had its answer, and err is what to return.
func holdToKey(ex *Exchange, v *dpopVerifier, underDPoP bool, raw string, at *oidcprovider.AccessToken, asDPoP bool) (bool, error) {
	ctx := ex.Context()

	var known int
	binding := keyBinding{jkt: at.Confirmation[oidcConfirmationJKT], x5tS256: at.Confirmation[oidcConfirmationX5T]}

	if binding.jkt != "" {
		known++
	}
	if binding.x5tS256 != "" {
		known++
	}

	binding.other = len(at.Confirmation) > known

	var proof *dpopProof

	switch {
	case binding.x5tS256 != "" || binding.other:
		// Judged with no proof verified. Under the DPoP scheme it is refused for that alone, when the
		// chain can judge certificates at all.
		if underDPoP && ex.certBinding() != nil && binding.jkt == "" && !binding.other {
			return true, writeOIDCChallenge(ex, asDPoP, oidcprovider.CodeInvalidToken)
		}
	default:
		var err error

		proof, err = presentedProof(ctx, v, ex.Request, underDPoP, raw)
		if err != nil {
			return true, refuseOIDCProof(ex, v, err)
		}
	}

	if err := admitBinding(ex, v, proof, binding); err != nil {
		return true, writeOIDCChallenge(ex, asDPoP, oidcprovider.CodeInvalidToken)
	}

	if err := recordProof(ctx, v, proof); err != nil {
		return true, refuseOIDCProof(ex, v, err)
	}

	return false, nil
}

// refuseOIDCProof answers the failure of a request's proof in the form a resource server does (RFC
// 9449 sections 7.1 and 9), which UserInfo keeps where the token endpoint answers 400 (R12). A nonce
// asked for comes with a fresh one. A cipher that cannot seal one, like a replay store that failed,
// is a dependency failure, and goes to the chain.
func refuseOIDCProof(ex *Exchange, v *dpopVerifier, err error) error {
	switch {
	case errors.Is(err, ErrDPoPNonceRequired):
		nonce, _, serr := v.issueNonce(ex.Context(), false)
		if serr != nil {
			return serr
		}

		setNonce(ex.Writer, nonce)

		return writeOIDCChallenge(ex, true, oidcprovider.CodeUseDPoPNonce)
	case errors.Is(err, ErrInvalidDPoPProof):
		return writeOIDCChallenge(ex, true, oidcprovider.CodeInvalidDPoPProof)
	default:
		return err
	}
}

// oidcDPoPChallenged reports whether a refusal is challenged under the DPoP scheme: for a token
// presented under it, for a token bound to a DPoP key whichever way it came, and for any request once
// DPoP is required, when the Bearer scheme would ask for what cannot be accepted. at is nil when no
// token has been read.
func oidcDPoPChallenged(v *dpopVerifier, underDPoP bool, at *oidcprovider.AccessToken) bool {
	return underDPoP || (at != nil && at.Confirmation[oidcConfirmationJKT] != "") || (v != nil && v.cfg.Require)
}

// writeOIDCChallenge answers code as a resource server does: 401, or 403 for insufficient_scope, a
// challenge and no body. invalid_request is 400 (RFC 6750 section 3.1). By default no error_description is sent, so a client learns no more than
// the code.
func writeOIDCChallenge(ex *Exchange, asDPoP bool, code string) error {
	ex.Writer.AddHeader(headerWWWAuthenticate, oidcChallenge(ex.dpop(), asDPoP, code))

	status := http.StatusUnauthorized

	switch code {
	case oidcprovider.CodeInsufficientScope:
		status = http.StatusForbidden
	case oidcprovider.CodeInvalidRequest:
		status = http.StatusBadRequest
	}

	ex.Writer.WriteHeader(status)

	return nil
}

// writeOIDCMalformed answers a request that cannot be read as one (RFC 6750 section 3.1): 400, a
// challenge naming invalid_request and no body. A request that presented its token under the DPoP
// scheme is challenged under that scheme as well as Bearer (RFC 9449 section 7.2), unless DPoP is
// required, when the Bearer scheme is not offered at all.
func writeOIDCMalformed(ex *Exchange, v *dpopVerifier, underDPoP bool) error {
	asDPoP := oidcDPoPChallenged(v, underDPoP, nil)

	if underDPoP && !asDPoPRequired(v) {
		ex.Writer.AddHeader(headerWWWAuthenticate, oidcChallenge(v, false, oidcprovider.CodeInvalidRequest))
	}

	return writeOIDCChallenge(ex, asDPoP, oidcprovider.CodeInvalidRequest)
}

// asDPoPRequired says DPoP is on and required, so that Bearer is not a scheme to offer.
func asDPoPRequired(v *dpopVerifier) bool { return v != nil && v.cfg.Require }

// oidcChallenge is the challenge naming code. A DPoP challenge names the accepted algorithms when the
// chain has any: with DPoP off, a token bound while it was on is still refused under its scheme.
func oidcChallenge(v *dpopVerifier, asDPoP bool, code string) string {
	param := "error=" + strconv.Quote(code)

	switch {
	case !asDPoP:
		return "Bearer " + param
	case v == nil:
		return dpopScheme + " " + param
	default:
		return dpopScheme + " " + param + ", algs=" + strconv.Quote(v.algorithmNames())
	}
}

// writeOIDCNoToken answers a request that carried no token, with no code (RFC 6750 section 3.1). With
// DPoP on it names that scheme too (RFC 9449 section 7.2), and that scheme alone once it is required.
func writeOIDCNoToken(ex *Exchange, v *dpopVerifier) error {
	if v != nil {
		ex.Writer.AddHeader(headerWWWAuthenticate, dpopScheme+" algs="+strconv.Quote(v.algorithmNames()))
	}

	if v == nil || !v.cfg.Require {
		ex.Writer.AddHeader(headerWWWAuthenticate, oidcNoTokenChallenge)
	}

	ex.Writer.WriteHeader(http.StatusUnauthorized)

	return nil
}
