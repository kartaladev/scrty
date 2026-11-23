package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/outbound"
)

// Upstream is the provider's upstream access for one callback: the access
// token of the token response that carried the verified ID token, bound to
// that token's subject.
//
// It prints, formats and logs as "[redacted]" under every fmt verb and as a
// slog value, also when it is a field of the consumer's own struct, exported
// or not: its only field is a pointer, so reflection reaches an address, never
// the token. It is safe for concurrent use.
//
// The library builds one per callback, hands it to an UpstreamBroker, and
// keeps no reference once the callback returns. The refresh token is never
// held. The zero value holds no token and no endpoint: HasAccessToken is false
// and UserInfo fails with ErrUserInfoFailed.
type Upstream struct{ s *upstreamState }

// upstreamState is what an Upstream points to. It is never copied out.
type upstreamState struct {
	token    string                                // the access token; empty when the response had none
	subject  string                                // the verified ID token's sub
	endpoint func(context.Context) (string, error) // resolves the UserInfo endpoint; nil means none
	out      *outbound.Client                      // the confined client UserInfo is fetched through
	log      *slog.Logger                          // where the client writes its records; nil keeps the context's
}

// newUpstream builds the upstream access of one callback. endpoint resolves
// the UserInfo endpoint, empty when none is known; a nil endpoint or out makes
// UserInfo fail.
func newUpstream(token, subject string, endpoint func(context.Context) (string, error), out *outbound.Client) Upstream {
	return Upstream{s: &upstreamState{token: token, subject: subject, endpoint: endpoint, out: out}}
}

// AccessToken returns the provider's access token, or the empty string when
// the token response carried none (see HasAccessToken).
//
// It is the escape hatch for provider APIs other than UserInfo; prefer
// UserInfo when it is enough. The library never writes the token to a log, an
// event, an error, a record or a response, but the string returned here is
// plain text: keeping it out of logs, errors and storage is the caller's duty
// from here on. A broker may keep the value it was handed; the library keeps
// no reference to it once the callback returns, and it stays valid for as long
// as the provider says, not the callback.
func (u Upstream) AccessToken() string {
	if u.s == nil {
		return ""
	}
	return u.s.token
}

// HasAccessToken reports whether the token response carried an access token.
// A provider that issues none still logs the user in; only UserInfo and
// AccessToken have nothing to offer.
func (u Upstream) HasAccessToken() bool { return u.AccessToken() != "" }

// Format writes "[redacted]" whatever the verb and flags, so no fmt verb
// prints the token.
func (Upstream) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedMark) }

// String returns "[redacted]".
func (Upstream) String() string { return redactedMark }

// LogValue returns "[redacted]", so a slog attribute never carries the token.
func (Upstream) LogValue() slog.Value { return slog.StringValue(redactedMark) }

// UserInfo fetches the provider's UserInfo for the access token, and returns
// the JSON object's members unchanged, decoded as encoding/json decodes into
// map[string]any except that every number is a json.Number holding its exact
// text, never a float64. An answer that repeats a member name, at any depth
// (also through a JSON escape such as \u0073ub), is refused: decoders disagree
// on which repeat wins. So is an answer that nests deeper than 64 levels, the
// top-level object counting as the first, and one with data after the object
// (trailing whitespace is fine). Invalid UTF-8 inside a string is returned as
// U+FFFD, as encoding/json decodes it.
//
// The endpoint is the provider's pinned Provider.UserInfoEndpoint, else the
// userinfo_endpoint of its discovery document. The request is one GET with
// "Authorization: Bearer <token>" through the relying party's outbound
// client (WithOutboundClient), so its scheme, origin, timeout and response
// size bounds apply. Nothing is cached: every call is a request.
//
// The answer must be a 200 whose body is a JSON object with a string sub equal
// to the verified ID token's subject (OpenID Connect Core 1.0, section 5.3.2).
// A signed or encrypted answer (application/jwt) is refused. Every failure —
// no access token, no endpoint known, a refused or failed request, another
// status, a body that is not one JSON object, a missing or different sub —
// wraps ErrUserInfoFailed with fixed text that carries neither the token nor
// any part of the body, and nothing is logged. A failure to resolve the
// endpoint also matches the resolver's error (ErrDiscoveryFailed).
//
// When ctx is cancelled or its deadline passes, the context's error is
// returned, not ErrUserInfoFailed: the caller gave up, the provider did not
// fail.
//
// The members are the provider's statements about the user, not verified
// claims: assurance is read from the ID token alone.
func (u Upstream) UserInfo(ctx context.Context) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := u.s
	if s == nil || s.token == "" {
		return nil, userInfoFailed("no access token is held", nil)
	}
	if s.endpoint == nil || s.out == nil {
		return nil, userInfoFailed("no UserInfo endpoint is known", nil)
	}
	endpoint, err := s.endpoint(ctx)
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, userInfoFailed("the UserInfo endpoint could not be resolved", err)
	case endpoint == "":
		return nil, userInfoFailed("no UserInfo endpoint is known", nil)
	}

	res, err := s.out.Get(ctxlog.With(ctx, s.log), endpoint, http.Header{
		"Authorization": {"Bearer " + s.token},
		"Accept":        {"application/json"},
	})
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, userInfoFailed("the request failed", err)
	case res.Status != http.StatusOK:
		return nil, userInfoFailed(fmt.Sprintf("status %d", res.Status), nil)
	}
	if mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err == nil && mt == "application/jwt" {
		return nil, userInfoFailed("a signed or encrypted answer is not accepted", nil)
	}

	members, ok := decodeMembers(res.Body)
	if !ok {
		return nil, userInfoFailed("the answer is not a JSON object", nil)
	}
	if sub, _ := members["sub"].(string); sub == "" || sub != s.subject {
		return nil, userInfoFailed("the answer's sub is not the ID token's subject", nil)
	}
	return members, nil
}

// maxMembersDepth bounds how deeply a UserInfo answer may nest.
const maxMembersDepth = 64

// decodeMembers decodes body as exactly one JSON object, with numbers as
// json.Number so their text is exact. It refuses a repeated member name at any
// depth (decoders disagree on which repeat wins, so an answer using one is
// ambiguous), data after the object, and nesting beyond maxMembersDepth.
func decodeMembers(body []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	obj, ok := decodeObject(dec, 1)
	if !ok {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return obj, true
}

// decodeObject reads the members of an object whose opening brace is consumed.
func decodeObject(dec *json.Decoder, depth int) (map[string]any, bool) {
	if depth > maxMembersDepth {
		return nil, false
	}
	obj := map[string]any{}
	for dec.More() {
		keyTok, err := dec.Token()
		key, isString := keyTok.(string)
		if err != nil || !isString {
			return nil, false
		}
		if _, dup := obj[key]; dup {
			return nil, false
		}
		v, ok := decodeValue(dec, depth)
		if !ok {
			return nil, false
		}
		obj[key] = v
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return nil, false
	}
	return obj, true
}

// decodeValue reads one value: a scalar, an array or an object.
func decodeValue(dec *json.Decoder, depth int) (any, bool) {
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, true // string, json.Number, bool or nil
	}
	switch d {
	case '{':
		obj, ok := decodeObject(dec, depth+1)
		return obj, ok
	case '[':
		if depth+1 > maxMembersDepth {
			return nil, false
		}
		arr := []any{}
		for dec.More() {
			v, ok := decodeValue(dec, depth+1)
			if !ok {
				return nil, false
			}
			arr = append(arr, v)
		}
		if end, err := dec.Token(); err != nil || end != json.Delim(']') {
			return nil, false
		}
		return arr, true
	}
	return nil, false
}

// userInfoFailed returns a UserInfo failure: ErrUserInfoFailed with fixed
// text naming reason, matching cause by identity without carrying its text,
// so a transport error that echoes a header cannot leak the token.
func userInfoFailed(reason string, cause error) error {
	return &userInfoError{reason: reason, cause: cause}
}

// userInfoError is a UserInfo failure. Its text is the library's own.
type userInfoError struct {
	reason string
	cause  error // may be nil
}

func (e *userInfoError) Error() string { return userInfoFailedText + ": " + e.reason }

func (e *userInfoError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrUserInfoFailed}
	}
	return []error{ErrUserInfoFailed, e.cause}
}
