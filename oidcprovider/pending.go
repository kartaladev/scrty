package oidcprovider

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/kartaladev/scrty/pkg/id"
)

//go:generate mockgen -destination=pending_mock_test.go -package=oidcprovider_test -typed github.com/kartaladev/scrty/oidcprovider PendingRequestStore,ConsentStore

// HandleParam is the query parameter that carries a pending request's handle to the
// consumer's login and consent pages.
const HandleParam = "req"

// handlePrefix opens a handle, rh.<id>.<secret>, so it cannot be mistaken for any other
// credential the provider issues.
const handlePrefix = "rh"

// flowSecretBytes is the size of a handle's secret and of a flow secret: 256 bits.
const flowSecretBytes = 32

// secretEncoding refuses a form that decodes to the same bytes as another, so a secret
// has one spelling.
var secretEncoding = base64.RawURLEncoding.Strict()

// decodeSecret returns the bytes of an encoded secret, and answers false for anything
// the provider could not have minted: exactly flowSecretBytes bytes in unpadded
// base64url, in the one spelling that decodes to them. The standard decoder skips CR and
// LF, so the alphabet is checked first, and a count of characters alone is not a length.
func decodeSecret(encoded string) ([]byte, bool) {
	if len(encoded) != secretEncoding.EncodedLen(flowSecretBytes) ||
		strings.ContainsFunc(encoded, func(c rune) bool { return !isSecretChar(c) }) {
		return nil, false
	}
	raw, err := secretEncoding.DecodeString(encoded)
	if err != nil || len(raw) != flowSecretBytes {
		return nil, false
	}

	return raw, true
}

// isSecretChar reports whether c is in the base64url alphabet.
func isSecretChar(c rune) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// digestEncoded returns the digest of an encoded secret's bytes. It answers false for
// anything the provider could not have minted, with no lookup behind it.
func digestEncoded(encoded string) ([]byte, bool) {
	raw, ok := decodeSecret(encoded)
	if !ok {
		return nil, false
	}

	return digestSecret(raw), true
}

// mintSecret returns a new secret, encoded, and its digest.
func (p *Provider) mintSecret() (string, []byte, error) {
	raw := make([]byte, flowSecretBytes)
	if _, err := io.ReadFull(p.cfg.random, raw); err != nil {
		return "", nil, err
	}

	return secretEncoding.EncodeToString(raw), digestSecret(raw), nil
}

// flowFor keeps a browser's flow secret, so that requests parked in several of its tabs
// can each be resumed, and mints one for a browser holding none. What it keeps, it judges
// by shape alone: the cookie's __Host- prefix is what stops anyone else planting a value,
// and the store cannot be asked who holds a digest.
func (p *Provider) flowFor(given string) (string, []byte, error) {
	if digest, ok := digestEncoded(given); ok {
		return given, digest, nil
	}

	return p.mintSecret()
}

// park stores a validated request under a new handle, and answers with the login page.
func (p *Provider) park(ctx context.Context, req *PendingRequest, flowSecret string) (AuthorizeResult, error) {
	handle, flow, err := p.parkRequest(ctx, req, flowSecret)
	if err != nil {
		return AuthorizeResult{}, err
	}

	return AuthorizeResult{Location: withQuery(p.loginURL, url.Values{HandleParam: {handle}}), FlowSecret: flow}, nil
}

// parkRequest stores a validated request at the login stage under a new handle, and returns
// the handle and the browser's flow secret, which leave here and are stored only as digests.
func (p *Provider) parkRequest(ctx context.Context, req *PendingRequest, flowSecret string) (string, string, error) {
	secret, handleDigest, err := p.mintSecret()
	if err != nil {
		return "", "", dependencyFailure(ctx, err, "oidcprovider: mint a handle")
	}
	flow, flowDigest, err := p.flowFor(flowSecret)
	if err != nil {
		return "", "", dependencyFailure(ctx, err, "oidcprovider: mint a flow secret")
	}
	recordID, err := p.cfg.ids.NewID()
	if err != nil {
		return "", "", dependencyFailure(ctx, err, "oidcprovider: mint a pending request identifier")
	}

	now := p.cfg.clock.Now()
	req.ID = recordID
	req.HandleDigest = handleDigest
	req.FlowDigest = flowDigest
	req.ParkedAt = now
	req.ExpiresAt = now.Add(p.cfg.pendingLifetime)
	req.Stage = StageLogin
	if err := p.stores.pendingRequests.Create(ctx, req); err != nil {
		return "", "", dependencyFailure(ctx, err, "oidcprovider: park the authorization request")
	}

	return handlePrefix + "." + recordID.String() + "." + secret, flow, nil
}

// splitHandle reads a handle into its identifier and its secret's digest.
func splitHandle(handle string) (id.ID, []byte, bool) {
	parts := strings.Split(handle, ".")
	if len(parts) != 3 || parts[0] != handlePrefix {
		return id.Nil, nil, false
	}
	recordID, err := id.Parse(parts[1])
	if err != nil {
		return id.Nil, nil, false
	}
	digest, ok := digestEncoded(parts[2])

	return recordID, digest, ok
}

// loadPending returns the unexpired request the handle names, when the flow secret is
// the one it was parked with. Every way of failing that is the requester's answers
// ErrUnknownHandle, so a guess learns nothing from which it was. The stage is the
// caller's to judge.
func (p *Provider) loadPending(ctx context.Context, handle, flowSecret string) (*PendingRequest, error) {
	recordID, handleDigest, ok := splitHandle(handle)
	if !ok {
		return nil, ErrUnknownHandle
	}
	flowDigest, ok := digestEncoded(flowSecret)
	if !ok {
		return nil, ErrUnknownHandle
	}

	r, err := p.stores.pendingRequests.Load(ctx, handleDigest)
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, ErrUnknownHandle
	case err != nil:
		return nil, dependencyFailure(ctx, err, "oidcprovider: load the pending request")
	}

	bound := subtle.ConstantTimeCompare(r.FlowDigest, flowDigest) == 1
	if !bound || r.ID != recordID || !p.cfg.clock.Now().Before(r.ExpiresAt) {
		return nil, ErrUnknownHandle
	}

	return r, nil
}

// PendingView is what the consumer's login and consent pages may know of a pending
// request. It holds nothing that could answer the request: never the PKCE challenge, the
// nonce, the state, the redirect URI, the handle or the flow secret.
type PendingView struct {
	// ClientID and ClientName say who is asking.
	ClientID, ClientName string
	// Scopes are the scopes asked for.
	Scopes []string
	// GrantedScopes are those this user already gave the client. They are empty until
	// the login stage has named a user.
	GrantedScopes []string
	// Prompt lists the request's prompt values the provider defines.
	Prompt []string
	// MaxAge is the request's max_age in seconds, and nil when it had none.
	MaxAge *int
	// LoginHint is the request's login_hint, which the provider does not act on.
	LoginHint string
	// UILocales, ClaimsLocales and ACRValues are the request's lists, which the provider
	// does not act on. A page may ask for more than the sign-in reached.
	UILocales, ClaimsLocales, ACRValues []string
	// Stage says which page should be answering: StageLogin or StageConsent.
	Stage Stage
}

// PendingRequest returns the view of a pending request, for the consumer's pages. It
// needs the handle and the browser's flow secret. A wrong flow secret, an unknown or
// expired handle, a request already answered, an end-session request and a client since
// removed all fail alike, with ErrUnknownHandle. A failing store or registry is a
// dependency failure. It looks up no account, and leaves the request as it was, so a page
// may read a request any number of times before it calls Resume.
func (p *Provider) PendingRequest(ctx context.Context, handle, flowSecret string) (*PendingView, error) {
	r, err := p.loadPending(ctx, handle, flowSecret)
	if err != nil {
		return nil, err
	}
	if r.Stage != StageLogin && r.Stage != StageConsent {
		return nil, ErrUnknownHandle
	}

	rc, err := p.client(ctx, r.ClientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil, ErrUnknownHandle
	case err != nil:
		return nil, err
	}

	granted, err := p.grantedScopes(ctx, r)
	if err != nil {
		return nil, err
	}

	return &PendingView{
		ClientID:      r.ClientID,
		ClientName:    rc.Name,
		Scopes:        slices.Clone(r.Scopes),
		GrantedScopes: granted,
		Prompt:        slices.Clone(r.Prompt),
		MaxAge:        r.MaxAge,
		LoginHint:     r.LoginHint,
		UILocales:     slices.Clone(r.UILocales),
		ClaimsLocales: slices.Clone(r.ClaimsLocales),
		ACRValues:     slices.Clone(r.ACRValues),
		Stage:         r.Stage,
	}, nil
}

// grantedScopes reads what the signed-in user already gave the client. Before a sign-in
// there is no one to ask about.
func (p *Provider) grantedScopes(ctx context.Context, r *PendingRequest) ([]string, error) {
	if r.SignIn == nil {
		return nil, nil
	}

	remembered, err := p.rememberedConsent(ctx, r.SignIn.User, r.ClientID)
	if err != nil || remembered == nil {
		return nil, err
	}

	return remembered.Scopes, nil
}
