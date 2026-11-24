package httpsec

import "fmt"

// errRepeatedAuthorization refuses a request carrying more than one Authorization header: which
// one a credential mode reads would be a guess (RFC 9110 section 11.6.2 defines the field as one
// credential), so it is a malformed request (RFC 6750 section 3.1, invalid_request), answered 400.
var errRepeatedAuthorization = fmt.Errorf("httpsec: the request carries more than one Authorization header: %w",
	ErrMalformedRequest)

// readAuthorization reads an access token from the Authorization header, under the DPoP scheme
// when DPoP is on (v not nil) or under Bearer, each matched without regard to case. claimed is
// false when the request carries no header or one under another scheme, which is no token. A
// repeated header is errRepeatedAuthorization, whatever its values.
//
// It reads only the header: a form body or a query is the reader's own business.
func readAuthorization(r Request, v *dpopVerifier) (raw string, underDPoP, claimed bool, err error) {
	if len(r.HeaderValues(oidcAuthorizationHeader)) > 1 {
		return "", false, false, errRepeatedAuthorization
	}

	raw, underDPoP, claimed = presentedBearer(r.Header(oidcAuthorizationHeader), DefaultBearerScheme, false, v)

	return raw, underDPoP, claimed, nil
}
