package oidcprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// The parameters a request authenticates its client with.
const (
	paramClientID            = "client_id"
	paramClientSecret        = "client_secret"
	paramClientAssertion     = "client_assertion"
	paramClientAssertionType = "client_assertion_type"
)

// ClientCredentials is what a request presented to authenticate its client. It holds the
// client's secret, so it prints and logs redacted; read its fields to use it.
type ClientCredentials struct {
	// Authorization is the request's Authorization header.
	Authorization string
	// Form is the parsed request body. A parameter with no value counts as omitted.
	Form url.Values
	// Query is the parsed query string. It may name no credential, since a secret in a URL is logged, so a caller
	// hands it over for that check, and nothing is read from it otherwise.
	Query url.Values
}

// Format writes the redacted form under every verb.
func (ClientCredentials) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue is the redacted form.
func (ClientCredentials) LogValue() slog.Value { return slog.StringValue(redacted) }

// presented is what a request says about its client, before anything is looked up.
type presented struct {
	method AuthMethod
	id     string
	secret string

	assertion, assertionType string
}

// AuthenticateClient decides which client a request comes from, and that it proved
// so by the one method the client registered: client_secret_basic, client_secret_post,
// private_key_jwt, or none for a public client naming itself.
//
// A refusal is an *Error. It is invalid_client when the credential is wrong, the
// client is unknown, the method is not the client's or the header does not decode,
// with the same text whichever it was. It is invalid_request when two methods are used
// at once, two identifiers disagree, a parameter is repeated, or a credential is in
// the query.
//
// Any other error is not a verdict on the client. A failing registry, assertion
// identifier store or key-set fetch matches ErrDependency, and a caller who left
// matches its own context's error.
//
// The comparison of a secret is the same work for an unknown client, a client using
// another method and a wrong secret. What a registry takes to answer is not something
// this package can even out: a client it finds is validated as it is read, and one it
// does not find is not.
//
// A refusal as invalid_client is reported as a security event (WithSecurityEvents), naming the client
// only when the registry held the identifier presented. A malformed request (invalid_request) and a
// dependency that failed are not reported.
func (p *Provider) AuthenticateClient(ctx context.Context, c ClientCredentials) (*RegisteredClient, error) {
	got, err := readCredentials(c)
	if err != nil {
		p.noteClientRefusal(ctx, nil, err)

		return nil, err
	}

	var rc *RegisteredClient
	switch got.method {
	case PrivateKeyJWT:
		rc, err = p.authenticateAssertion(ctx, got)
	case AuthMethodNone:
		rc, err = p.authenticatePublic(ctx, got)
	default:
		rc, err = p.authenticateSecret(ctx, got)
	}
	if err != nil {
		p.noteClientRefusal(ctx, rc, err)

		return nil, err
	}

	return rc, nil
}

// noteClientRefusal reports err when it is a refusal of the client's credentials. known is the client
// the registry held for the identifier presented, and nil when it held none.
func (p *Provider) noteClientRefusal(ctx context.Context, known *RegisteredClient, err error) {
	var refusal *Error
	if !errors.As(err, &refusal) || refusal.Code != CodeInvalidClient {
		return
	}
	clientID := ""
	if known != nil {
		clientID = known.ID
	}
	p.reportClientRefused(ctx, clientID)
}

// readCredentials settles what the request presented without reading any client, so
// a malformed request costs no lookup.
func readCredentials(c ClientCredentials) (presented, error) {
	for _, name := range []string{paramClientSecret, paramClientAssertion, paramClientAssertionType} {
		if anyValue(c.Query[name]) {
			return presented{}, refuseRequest()
		}
	}
	for _, name := range []string{paramClientID, paramClientSecret, paramClientAssertion, paramClientAssertionType} {
		if len(c.Form[name]) > 1 {
			return presented{}, refuseRequest()
		}
	}

	got := presented{
		id:            c.Form.Get(paramClientID),
		secret:        c.Form.Get(paramClientSecret),
		assertion:     c.Form.Get(paramClientAssertion),
		assertionType: c.Form.Get(paramClientAssertionType),
	}
	usesAssertion := got.assertion != "" || got.assertionType != ""

	methods := 0
	for _, used := range []bool{c.Authorization != "", got.secret != "", usesAssertion} {
		if used {
			methods++
		}
	}
	if methods > 1 {
		return presented{}, refuseRequest()
	}

	switch {
	case c.Authorization != "":
		return readBasic(c.Authorization, got.id)
	case usesAssertion:
		got.method = PrivateKeyJWT
	case got.id == "":
		return presented{}, refuseClient()
	case got.secret != "":
		got.method = ClientSecretPost
	default:
		got.method = AuthMethodNone
	}

	return got, nil
}

// readBasic decodes the header as RFC 6749 §2.3.1 says: Base64, split at the first
// colon, and then each half URL-decoded, so an encoded colon stays in its half.
func readBasic(header, formID string) (presented, error) {
	scheme, encoded, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return presented{}, refuseClient()
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return presented{}, refuseClient()
	}
	rawID, rawSecret, found := strings.Cut(string(decoded), ":")
	if !found {
		return presented{}, refuseClient()
	}
	id, err := url.QueryUnescape(rawID)
	if err != nil || id == "" {
		return presented{}, refuseClient()
	}
	secret, err := url.QueryUnescape(rawSecret)
	if err != nil {
		return presented{}, refuseClient()
	}
	if formID != "" && formID != id {
		return presented{}, refuseRequest()
	}

	return presented{method: ClientSecretBasic, id: id, secret: secret}, nil
}

// authenticateSecret always runs the comparison, against a client holding nothing
// when the identifier is unknown or the client uses another method, so a stranger
// cannot tell those from a wrong secret by what the comparison costs.
//
// Like the other two, it returns the client the registry held beside a refusal, so the refusal can be
// reported by name, and AuthenticateClient hands none of it to its caller.
func (p *Provider) authenticateSecret(ctx context.Context, got presented) (*RegisteredClient, error) {
	rc, err := p.client(ctx, got.id)
	if err != nil && !errors.Is(err, ErrClientNotFound) {
		return nil, err
	}

	holder := &RegisteredClient{}
	if err == nil && rc.AuthMethod == got.method {
		holder = rc
	}
	if !holder.matchesSecret([]byte(got.secret), p.cfg.clock.Now()) {
		return rc, refuseClient()
	}

	return holder, nil
}

func (p *Provider) authenticatePublic(ctx context.Context, got presented) (*RegisteredClient, error) {
	rc, err := p.client(ctx, got.id)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, refuseClient()
	case err != nil:
		return nil, err
	case rc.AuthMethod != AuthMethodNone:
		return rc, refuseClient()
	}

	return rc, nil
}

func anyValue(values []string) bool {
	for _, v := range values {
		if v != "" {
			return true
		}
	}

	return false
}

func refuseClient() error { return &Error{Code: CodeInvalidClient} }

func refuseRequest() error { return &Error{Code: CodeInvalidRequest} }
