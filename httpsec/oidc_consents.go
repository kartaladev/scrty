package httpsec

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
)

// oidcConsentsGroup serves the user's consents: the list at the OIDCConsents path, and a
// revocation at that path followed by "/" and the client's identifier. It answers behind the
// bearer and the gates, and reads the sign-in from ex.Session.
//
// The list is an exact path, so the router takes it. The router matches paths exactly, and a
// revocation's path holds a client's identifier, so the group registers a second interceptor in the
// same slot for the paths under the list's.
type oidcConsentsGroup struct{ oidcGroupBase }

func (g *oidcConsentsGroup) routes() []oidcRoute {
	return []oidcRoute{
		{path: g.op.paths[OIDCConsents], inner: true, handle: g.serveList},
	}
}

// settle registers the interceptor answering the paths under the list's, at the slot the list is
// answered in, so both are judged by the same bearer, gates and session touch.
func (g *oidcConsentsGroup) settle(c *config) error {
	c.register(&oidcConsentClients{group: g}, OrderOIDCProviderSession)

	return nil
}

// oidcConsentDocument is one member of the list. Its member names are the documented contract of
// the default; a consumer who wants other names serves its own page from Provider.Consents.
type oidcConsentDocument struct {
	ClientID    string    `json:"client_id"`
	ClientName  string    `json:"client_name"`
	Scopes      []string  `json:"scopes"`
	Offline     bool      `json:"offline_access"`
	LastGivenAt time.Time `json:"last_given_at"`
}

// serveList answers the list of the caller's own consents. The order is the guarantee:
//
//  1. no answer may be cached, whatever follows, the chain's error handling included;
//  2. anything but GET is refused, with nothing read from the request;
//  3. the caller is the sign-in the chain judged and no one else: a user named in the query, the
//     path or the body is never read;
//  4. the provider lists what that user has allowed.
//
// A failure of a store or the registry goes to the chain's error handling, whose answer holds no text.
func (g *oidcConsentsGroup) serveList(ex *Exchange, _ Next) error {
	setOIDCNoStore(ex.Writer)

	if ex.Request.Method() != http.MethodGet {
		return writeOIDCMethodNotAllowed(ex, http.MethodGet)
	}

	user, err := g.caller(ex)
	if err != nil {
		return err
	}

	views, err := g.op.provider.Consents(ex.Context(), user)
	if err != nil {
		return err
	}

	doc := make([]oidcConsentDocument, 0, len(views))
	for _, v := range views {
		scopes := v.Scopes
		if scopes == nil {
			scopes = []string{}
		}

		doc = append(doc, oidcConsentDocument{
			ClientID:    v.ClientID,
			ClientName:  v.ClientName,
			Scopes:      scopes,
			Offline:     v.Offline,
			LastGivenAt: v.LastGivenAt,
		})
	}

	return writeSuccessDocument(ex, doc)
}

// caller is the user the request is made by: the one the sign-in the chain judged belongs to.
//
// A 401 it returns is challenged on its way out of the provider's outer router, as is any the bearer
// ahead of it answers.
//
// Anything that authenticated without a session, an API key or Basic credentials, is no sign-in.
// The provider cannot tell that a session owes a step, so that is judged here: the gates ahead of
// this endpoint refuse such a session first on a chain enabling them, and this holds the line on one
// that does not.
func (g *oidcConsentsGroup) caller(ex *Exchange) (identity.UserID, error) {
	s := ex.Session
	if s == nil || ex.Authentication == nil {
		return "", ErrAuthenticationRequired
	}

	if err := fullSessionOnly(s); err != nil {
		return "", err
	}

	if err := raisedChallengeRefusal(ex, s); err != nil {
		return "", err
	}

	if err := requireSessionUser(ex, s); err != nil {
		return "", err
	}

	return s.UserID, nil
}

// oidcConsentClients answers the paths under the list's, one client each.
type oidcConsentClients struct {
	group *oidcConsentsGroup
}

// Intercept answers DELETE at the list's path followed by a client's identifier, and passes on
// every other path. The path is read at the request, so the group's paths are final.
//
// The order is the guarantee:
//
//  1. no answer may be cached;
//  2. anything but DELETE is refused, with nothing read from the request;
//  3. the caller is judged as the list judges it;
//  4. the identifier is the path's remainder, decoded. A remainder that is empty, or holds a "/"
//     (a client identifier holding one cannot be named here), is answered as a consent the caller
//     never gave: the same refusal, so the answer tells no one which clients exist;
//  5. the provider forgets what the caller allowed that client and revokes the caller's grants of
//     it. A caller holding neither a consent nor a grant of it is refused with
//     ErrOIDCForeignConsent, 404, and nothing of anyone else's is touched.
func (c *oidcConsentClients) Intercept(ex *Exchange, next Next) error {
	g := c.group

	prefix := g.op.consentClientPrefix()
	if !strings.HasPrefix(ex.Request.Path(), prefix) {
		return next(ex)
	}

	setOIDCNoStore(ex.Writer)

	if ex.Request.Method() != http.MethodDelete {
		return writeOIDCMethodNotAllowed(ex, http.MethodDelete)
	}

	user, err := g.caller(ex)
	if err != nil {
		return err
	}

	client := strings.TrimPrefix(ex.Request.Path(), prefix)
	if client == "" || strings.Contains(client, "/") {
		return ErrOIDCForeignConsent
	}

	if err := g.op.provider.RevokeConsent(ex.Context(), user, client); err != nil {
		if errors.Is(err, oidcprovider.ErrForeignConsent) {
			return ErrOIDCForeignConsent
		}

		return err
	}

	ex.Writer.WriteHeader(http.StatusNoContent)

	return nil
}

// challengeOIDCSignIn adds to a 401 of an endpoint resting on a sign-in the challenge RFC 9110 section
// 15.5.2 requires, and returns err as it came. It is the one place that challenges those endpoints: the
// outer router calls it for whatever comes back from the chain, the bearer's refusals included, so a
// response is challenged once.
//
// With DPoP off, a request presenting one Authorization line with the Bearer scheme, whose token left
// no session published, was refused for the token, and is told so with error="invalid_token" (RFC 6750
// section 3.1). That code is defined for the Bearer scheme, so it is answered only on a chain with a
// built-in bearer reading that scheme: under WithBearerScheme or WithSessionBearerScheme naming another,
// neither a line under that scheme nor a Bearer line, which nothing read, gets it. Anything else, no
// credential, a session owing a step, a repeated line, a sign-in to redo, gets the challenge with no
// code. Nothing about the sign-in is named, as with a request bearing no token at UserInfo.
//
// With DPoP on, it names that scheme too, and that scheme alone once it is required (RFC 9449 section
// 7.2). A refusal DPoP's own challenge answers on its way back through the chain is left to it
// (dpopAnswersChallenge): this one would stand ahead of it, and a client reading the first line would
// not see the error it has to act on.
func (op *oidcEndpoints) challengeOIDCSignIn(ex *Exchange, err error) error {
	if err == nil || StatusForError(err) != http.StatusUnauthorized {
		return err
	}

	v := ex.dpop()
	if v == nil {
		ex.Writer.AddHeader(headerWWWAuthenticate, op.bearerRefusalChallenge(ex))

		return err
	}

	if dpopAnswersChallenge(err) {
		return err
	}

	ex.Writer.AddHeader(headerWWWAuthenticate, dpopScheme+" algs="+strconv.Quote(v.algorithmNames()))
	if !v.cfg.Require {
		ex.Writer.AddHeader(headerWWWAuthenticate, oidcNoTokenChallenge)
	}

	return err
}

// dpopAnswersChallenge reports whether dpopVerifier.challenge sets a challenge for err, which it does
// for exactly these errors. A test holds the two to one set.
func dpopAnswersChallenge(err error) bool {
	return errors.Is(err, ErrDPoPNonceRequired) || errors.Is(err, ErrInvalidDPoPProof) ||
		errors.Is(err, ErrAuthenticationRequired) || errors.Is(err, authorize.ErrAuthenticationRequired)
}

// bearerRefusalChallenge is the challenge for a 401 with DPoP off: invalid_token for a request that
// presented its one Authorization line under the Bearer scheme, on a chain whose bearer reads that scheme,
// and has no session, which is a token the chain refused, and the code-less challenge for every other.
func (op *oidcEndpoints) bearerRefusalChallenge(ex *Exchange) string {
	if !op.readsBearerScheme {
		return oidcNoTokenChallenge
	}

	lines := ex.Request.HeaderValues(oidcAuthorizationHeader)
	if len(lines) == 1 && ex.Session == nil {
		if _, ok := presentedCredential(lines[0], DefaultBearerScheme, false); ok {
			return oidcChallenge(nil, false, oidcprovider.CodeInvalidToken)
		}
	}

	return oidcNoTokenChallenge
}

// writeOIDCMethodNotAllowed refuses a method the endpoint does not serve, naming the one it does.
func writeOIDCMethodNotAllowed(ex *Exchange, allow string) error {
	ex.Writer.SetHeader("Allow", allow)
	ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

	return nil
}
