package httpsec

// This file holds the reader every library endpoint uses for a credential
// posted as a single form field — the MFA verify endpoint and the enrolment
// endpoints — so that each reads it the same way: from a URL-encoded POST
// body, and never from the URL.

import (
	"errors"
	"mime"
	"net/url"
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
