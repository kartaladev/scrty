package httpsec

import (
	"errors"
	"net/http"
	"strings"
	"time"

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

	prefix := strings.TrimSuffix(g.op.paths[OIDCConsents], "/") + "/"
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

// writeOIDCMethodNotAllowed refuses a method the endpoint does not serve, naming the one it does.
func writeOIDCMethodNotAllowed(ex *Exchange, allow string) error {
	ex.Writer.SetHeader("Allow", allow)
	ex.Writer.WriteHeader(http.StatusMethodNotAllowed)

	return nil
}
