package httpsec

// This file holds the second of the two readers an MFA method's response is
// read with — a whole JSON body — and the dispatch that picks between it and
// the form-field reader from the format the method declared. A method never
// sees the request: the library reads it here, under one set of rules, and
// hands the method only the bytes.

import (
	"encoding/json"
	"errors"

	"github.com/kartaladev/scrty/mfa"
)

// readResponse reads a method's verification response the way its format
// declares: the named field of a URL-encoded body, or the whole of a JSON
// body, each bounded at the declared limit.
//
// Both read the body only, never the URL. A response that cannot be read is
// ErrCredentialsMissing and one over the limit is ErrRequestTooLarge; the
// caller counts neither against the verification throttle, because no response
// was presented. A format neither constructor built is refused as unreadable
// rather than read some default way; mfa.LookupsFor refuses such a method at
// construction, so this is a guard, not a path.
func readResponse(r Request, f mfa.ResponseFormat) ([]byte, error) {
	switch f.Kind() {
	case mfa.ResponseFormField:
		value, err := postedFieldLimited(r, f.Field(), f.Limit())
		if err != nil {
			return nil, err
		}

		return []byte(value), nil
	case mfa.ResponseJSONBody:
		return postedJSON(r, f.Limit())
	default:
		return nil, ErrCredentialsMissing
	}
}

// postedJSON reads the whole POST body as a JSON document of at most limit
// bytes, and only the body.
//
// The body must declare a JSON media type — "application/json" or a
// structured "+json" type, parameters ignored — and hold one valid JSON
// document. Anything else, an empty body included, is ErrCredentialsMissing: a
// response nobody could read was not presented. A body over the limit is
// ErrRequestTooLarge. The document is returned byte for byte; what it means is
// the method's business.
func postedJSON(r Request, limit int64) ([]byte, error) {
	body, err := r.Body(limit)
	if errors.Is(err, ErrRequestTooLarge) {
		return nil, ErrRequestTooLarge
	}

	if err != nil {
		// The transport's failure, whose text is not the library's.
		return nil, refusedAs(ErrCredentialsMissing, textCredentialsMissing, err)
	}

	if !declaresJSON(r.Header("Content-Type")) || len(body) == 0 || !json.Valid(body) {
		return nil, ErrCredentialsMissing
	}

	return body, nil
}
