package httpsec

import (
	"encoding/json"
	"errors"
	"mime"
	"net/url"

	"github.com/kartaladev/scrty/authenticate/mfa"
)

// postedFieldBodyLimit is how many request body bytes postedField reads. A
// code is a few bytes; nothing an endpoint reads through it comes near it.
const postedFieldBodyLimit int64 = 4 << 10

// postedField reads name from the POST body, bounded at postedFieldBodyLimit.
// See postedFieldLimited for the rules.
func postedField(r Request, name string) (string, error) {
	return postedFieldLimited(r, name, postedFieldBodyLimit)
}

// postedFieldLimited reads name from the POST body, and only from it, reading
// at most limit bytes of the body.
//
// Request.FormValue looks in the posted form first and falls back to the URL
// query, on every adapter; a code in a URL has already reached access logs,
// proxy logs and the Referer the next page sends. So the query is not
// consulted here, and a body is read as a form only when it declares
// "application/x-www-form-urlencoded".
//
// A value the endpoint cannot read — a body that is not such a form, multipart
// included, one that does not parse, or one without the field or with it empty
// — is ErrCredentialsMissing, never an empty value: a code nobody could read
// was not presented, so it must not be judged, or charged, as a wrong one. A
// body over the limit is ErrRequestTooLarge.
func postedFieldLimited(r Request, name string, limit int64) (string, error) {
	body, err := r.Body(limit)
	if errors.Is(err, ErrRequestTooLarge) {
		return "", ErrRequestTooLarge
	}

	if err != nil {
		// The transport's failure, whose text is not the library's.
		return "", refusedAs(ErrCredentialsMissing, textCredentialsMissing, err)
	}

	if !declaresForm(r.Header("Content-Type")) {
		return "", ErrCredentialsMissing
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		// A body that parses only in part yields nothing: a field read from
		// the half that parsed is not what the client sent.
		return "", ErrCredentialsMissing
	}

	value := values.Get(name)
	if value == "" {
		return "", ErrCredentialsMissing
	}

	return value, nil
}

// declaresForm reports whether a content type names the URL-encoded form
// media type, ignoring parameters such as a charset.
func declaresForm(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}

	return media == "application/x-www-form-urlencoded"
}

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
