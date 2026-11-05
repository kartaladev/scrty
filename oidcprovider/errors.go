package oidcprovider

import "errors"

// ErrConfig reports a wiring mistake found at construction. Every failure of
// New and of client validation matches it, and names the setting at fault.
var ErrConfig = errors.New("oidcprovider: invalid configuration")

// ErrClientNotFound reports that the registry holds no such client, or holds
// one that failed validation as it was read. Callers treat both as an unknown
// client.
var ErrClientNotFound = errors.New("oidcprovider: client not found")

// ErrDependency reports that a store, key source, registry or outbound fetch
// failed. It is wrapped behind fixed text, so the dependency's own text is never
// repeated, and is answered as a server error, charged to no throttle.
var ErrDependency = errors.New("oidcprovider: dependency failure")

// The refusals of the authorization and consent flows, which httpsec maps to
// statuses.
var (
	// ErrInvalidAuthorization reports an authorization request that cannot be
	// answered by redirecting to the client.
	ErrInvalidAuthorization = errors.New("oidcprovider: invalid authorization request")

	// ErrUnknownHandle reports a pending-request handle that is unknown, expired
	// or already spent.
	ErrUnknownHandle = errors.New("oidcprovider: unknown handle")

	// ErrReauthenticate reports a resume whose sign-in cannot answer the pending
	// request.
	ErrReauthenticate = errors.New("oidcprovider: reauthentication required")

	// ErrConsentMalformed reports a consent answer that does not fit its request.
	ErrConsentMalformed = errors.New("oidcprovider: malformed consent")

	// ErrForeignConsent reports a consent record that belongs to another user.
	ErrForeignConsent = errors.New("oidcprovider: foreign consent")

	// ErrInvalidEndSession reports an end-session request that must end nothing and
	// must not be redirected: an id_token_hint failing its checks under a key still
	// published, a hint whose audience is not client_id, or parameters that cannot be
	// read.
	ErrInvalidEndSession = errors.New("oidcprovider: invalid end-session request")
)

// The protocol error codes an Error carries, as the standards spell them.
const (
	CodeInvalidRequest          = "invalid_request"
	CodeInvalidClient           = "invalid_client"
	CodeInvalidGrant            = "invalid_grant"
	CodeUnauthorizedClient      = "unauthorized_client"
	CodeUnsupportedGrantType    = "unsupported_grant_type"
	CodeInvalidScope            = "invalid_scope"
	CodeInvalidTarget           = "invalid_target"
	CodeAccessDenied            = "access_denied"
	CodeUnsupportedResponseType = "unsupported_response_type"
	CodeLoginRequired           = "login_required"
	CodeConsentRequired         = "consent_required"
	CodeUseDPoPNonce            = "use_dpop_nonce"
	CodeRequestNotSupported     = "request_not_supported"
	CodeRequestURINotSupported  = "request_uri_not_supported"
	CodeInvalidToken            = "invalid_token"
	CodeInsufficientScope       = "insufficient_scope"
	CodeInvalidDPoPProof        = "invalid_dpop_proof"
)

// Error is a refusal the protocol names: httpsec answers it with the standard's
// body and status. It carries the code alone, so it can hold no request value.
type Error struct {
	// Code is one of the Code constants.
	Code string
}

// Error returns "oidcprovider: " followed by the code.
func (e *Error) Error() string { return "oidcprovider: " + e.Code }
