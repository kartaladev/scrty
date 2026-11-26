package httpsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kartaladev/scrty/session"
)

// DefaultSessionCookieNextParam is the form field, or JSON member, a browser
// sign-in on a cookie chain names its destination in, unless
// WithSessionCookieNextParam replaces it.
const DefaultSessionCookieNextParam = "next"

// sessionCookieNextBodyLimit bounds how much of a sign-in's body is read to
// find its destination. A body over it, which no issuing endpoint accepts by
// default, names no destination, and the sign-in lands on "/".
const sessionCookieNextBodyLimit int64 = 64 << 10

// maxAcceptRanges bounds how many media ranges of an Accept header are read.
// A header with more is read as malformed, and so as preferring JSON.
const maxAcceptRanges = 64

// The media types a sign-in on a cookie chain negotiates between.
const (
	mediaHTML = "text/html"
	mediaJSON = "application/json"
)

// errSignInWithoutSession is the cause of a default answer asked to answer a
// sign-in that names no session, which no issuing endpoint does.
var errSignInWithoutSession = errors.New("httpsec: a sign-in was answered without its session")

// cookieSignInDocument is the default JSON answer of a sign-in on a cookie chain:
// the session's idle expiry, and no credential. Its member name is the
// documented contract of that default.
type cookieSignInDocument struct {
	IdleExpiresAt time.Time `json:"idle_expires_at"`
}

// prefersHTML reports whether r is a browser's form post or navigation,
// which a sign-in on a cookie chain answers with a redirect rather than a
// document: its Content-Type is a form (application/x-www-form-urlencoded or
// multipart/form-data), or its Accept ranks text/html above
// application/json.
//
// Each type's rank is the q-value of the most specific range that matches it
// (type/subtype, then type/*, then */*), 0 when none does; parameters other
// than q are ignored. A tie, an absent Accept, and one that does not parse (a
// range that is not a media type, a q outside RFC 9110's qvalue grammar or
// given as a quoted string, a parameter given twice, more than
// maxAcceptRanges ranges) answer JSON: a script that cannot say what it wants
// is not sent a redirect it may not follow.
func prefersHTML(r Request) bool {
	if media, _, err := mime.ParseMediaType(r.Header("Content-Type")); err == nil {
		if media == "application/x-www-form-urlencoded" || media == "multipart/form-data" {
			return true
		}
	}

	html, js, ok := acceptRanks(r.HeaderValues("Accept"))

	return ok && html > js
}

// acceptRanks reads the q-values lines give text/html and application/json.
// ok is false when the header does not parse.
func acceptRanks(lines []string) (html, js float64, ok bool) {
	var (
		htmlSpecific, jsSpecific int
		ranges                   int
	)

	for _, line := range lines {
		for rng := range strings.SplitSeq(line, ",") {
			rng = strings.TrimSpace(rng)
			if rng == "" {
				continue
			}

			if ranges++; ranges > maxAcceptRanges {
				return 0, 0, false
			}

			media, q, valid := acceptRange(rng)
			if !valid {
				return 0, 0, false
			}

			if s := rangeSpecificity(media, mediaHTML); s > htmlSpecific {
				htmlSpecific, html = s, q
			}

			if s := rangeSpecificity(media, mediaJSON); s > jsSpecific {
				jsSpecific, js = s, q
			}
		}
	}

	return html, js, true
}

// acceptRange parses one media range and its q-value, 1 when it names none.
func acceptRange(rng string) (media string, q float64, ok bool) {
	media, params, err := mime.ParseMediaType(rng)
	if err != nil {
		return "", 0, false
	}

	if typ, sub, found := strings.Cut(media, "/"); !found || typ == "" || sub == "" || (typ == "*" && sub != "*") {
		return "", 0, false
	}

	q = 1

	if raw, given := params["q"]; given {
		// RFC 9110 writes a weight as a bare token, never a quoted string,
		// which mime.ParseMediaType would unquote unseen; a quoted one is
		// malformed.
		if quotedWeight(rng) {
			return "", 0, false
		}

		if q, ok = qvalue(raw); !ok {
			return "", 0, false
		}
	}

	return media, q, true
}

// quotedWeight reports whether rng gives its q parameter as a quoted string,
// read from the raw range. A parameter list whose quoted value holds a ';'
// may be split inside it, which can only report a quoted weight that is not
// there: the range is then refused, the safe reading.
func quotedWeight(rng string) bool {
	_, params, _ := strings.Cut(rng, ";")

	for param := range strings.SplitSeq(params, ";") {
		name, value, _ := strings.Cut(param, "=")
		if strings.EqualFold(strings.TrimSpace(name), "q") && strings.HasPrefix(strings.TrimSpace(value), `"`) {
			return true
		}
	}

	return false
}

// qvalue parses a q-value by RFC 9110's grammar: "0", optionally followed by
// "." and up to three digits, or "1", optionally followed by "." and up to
// three zeros. Anything else strconv would accept (an exponent, a hexadecimal
// float, a sign, a missing leading digit, more digits) is not one.
func qvalue(raw string) (float64, bool) {
	whole, frac, dotted := strings.Cut(raw, ".")
	if len(frac) > 3 || (dotted && frac == "") {
		return 0, false
	}

	for i := range len(frac) {
		if frac[i] < '0' || frac[i] > '9' || (whole == "1" && frac[i] != '0') {
			return 0, false
		}
	}

	if whole != "0" && whole != "1" {
		return 0, false
	}

	q, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}

	return q, true
}

// rangeSpecificity is how specifically media matches target: 3 for the type
// itself, 2 for its type's wildcard, 1 for */*, 0 when it does not match.
func rangeSpecificity(media, target string) int {
	typ, _, _ := strings.Cut(target, "/")

	switch media {
	case target:
		return 3
	case typ + "/*":
		return 2
	case "*/*":
		return 1
	default:
		return 0
	}
}

// answerSignIn is a cookie chain's default answer to a sign-in that stored s
// and set its cookie: 303 See Other to destination, which the caller has
// already resolved, for a request that prefers HTML (prefersHTML), and 200
// with cookieSignInDocument otherwise. Either is marked no-store, and neither
// carries a credential.
func answerSignIn(ex *Exchange, s *session.Session, destination string) error {
	if s == nil {
		return errSignInWithoutSession
	}

	if prefersHTML(ex.Request) {
		redirectSignIn(ex, destination)

		return nil
	}

	return writeSuccessDocument(ex, cookieSignInDocument{IdleExpiresAt: s.IdleExpiresAt})
}

// answerSignInRequested is answerSignIn for an endpoint that has no
// destination of its own: the request's body is read for one
// (requestedDestination) only once the request is known to prefer HTML, since
// a script answered a document has no use for it.
func (c *sessionCookie) answerSignInRequested(ex *Exchange, s *session.Session) error {
	if s == nil {
		return errSignInWithoutSession
	}

	if !prefersHTML(ex.Request) {
		return writeSuccessDocument(ex, cookieSignInDocument{IdleExpiresAt: s.IdleExpiresAt})
	}

	redirectSignIn(ex, c.destination(c.requestedDestination(ex.Request)))

	return nil
}

// redirectSignIn sends the browser to destination by 303 See Other, which a
// browser follows with a GET whatever method it posted with, on a response
// no cache may keep.
func redirectSignIn(ex *Exchange, destination string) {
	ex.Writer.SetHeader("Cache-Control", "no-store")
	ex.Writer.SetHeader("Location", destination)
	ex.Writer.WriteHeader(http.StatusSeeOther)
}

// answer is the cookie chain's default answer to a sign-in that stored s, sent
// to the destination the request named in its body (requestedDestination),
// resolved by the chain's rules (destination), when it prefers HTML.
func (c *sessionCookie) answer(ex *Exchange, s *session.Session) error {
	return c.answerSignInRequested(ex, s)
}

// answerLogin is answer as a LoginResponder, for the passwordless passkey
// login of a cookie chain.
func (c *sessionCookie) answerLogin(ex *Exchange, r LoginResult) error {
	return c.answer(ex, r.Session)
}

// recoverySignInDocument is a cookie chain's default JSON answer to a
// completed recovery: the session's idle expiry, the user's new saved codes
// when reissued, and how many saved codes the user holds and whether that is low.
// It carries no credential.
type recoverySignInDocument struct {
	IdleExpiresAt time.Time `json:"idle_expires_at"`
	RecoveryCodes []string  `json:"recovery_codes,omitempty"`
	Remaining     int       `json:"remaining"`
	Low           bool      `json:"low"`
}

// answerRecovery is a cookie chain's default answer to a completed recovery.
// A recovery that reissued the user's saved codes is answered
// recoverySignInDocument whatever the request prefers: the codes exist in
// readable form only in this response, and a redirect would lose them. Any
// other is answered as every sign-in is (answer), its document carrying the
// saved-code count beside the idle expiry.
func (c *sessionCookie) answerRecovery(ex *Exchange, r RecoveryResult) error {
	s := recoverySession(r.Recovery)
	if s == nil {
		return errSignInWithoutSession
	}

	res := r.Recovery
	if len(res.Codes) == 0 && prefersHTML(ex.Request) {
		redirectSignIn(ex, c.destination(c.requestedDestination(ex.Request)))

		return nil
	}

	return writeSuccessDocument(ex, recoverySignInDocument{
		IdleExpiresAt: s.IdleExpiresAt,
		RecoveryCodes: res.Codes,
		Remaining:     res.Remaining.N,
		Low:           res.Remaining.Low,
	})
}

// signInResponder is the responder an issuing endpoint answers a sign-in
// with: fallback, the endpoint's own, when the consumer replaced it
// (consumer) or the chain is no cookie chain; otherwise the cookie chain's
// negotiated answer (sessionCookie.answer), for the session sessionOf reads
// off the result.
func signInResponder[R any, F ~func(*Exchange, R) error](
	d credentialDelivery, consumer bool, fallback F, sessionOf func(R) *session.Session,
) F {
	if consumer || d.cookie == nil {
		return fallback
	}

	c := d.cookie

	return func(ex *Exchange, result R) error { return c.answer(ex, sessionOf(result)) }
}

// requestedDestination reads the destination field from r's body: the one
// value of the form field of that name in a URL-encoded body, or the one
// string member of that name in a JSON object. Anything else, a missing,
// repeated or non-string field, a body of another type, one that does not
// parse, and one over sessionCookieNextBodyLimit, is "", which resolves to
// "/". The URL query is never read.
func (c *sessionCookie) requestedDestination(r Request) string {
	body, err := r.Body(sessionCookieNextBodyLimit)
	if err != nil || len(body) == 0 {
		return ""
	}

	contentType := r.Header("Content-Type")

	switch {
	case declaresForm(contentType):
		values, err := url.ParseQuery(string(body))
		if err != nil || len(values[c.nextParam]) != 1 {
			return ""
		}

		return values.Get(c.nextParam)
	case declaresJSON(contentType):
		return jsonStringMember(body, c.nextParam)
	default:
		return ""
	}
}

// jsonStringMember is the string value of the one top-level member of body
// named name, "" when body is not a JSON object alone (anything but
// whitespace after the object is refused), holds no such member, holds it more
// than once, or holds it as anything but a string.
func jsonStringMember(body []byte, name string) string {
	dec := json.NewDecoder(bytes.NewReader(body))

	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return ""
	}

	var (
		value string
		found int
	)

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}

		key, _ := tok.(string)

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return ""
		}

		if key != name {
			continue
		}

		if found++; found > 1 {
			return ""
		}

		if err := json.Unmarshal(raw, &value); err != nil {
			return ""
		}
	}

	// The closing brace, then nothing: a body that goes on after its object
	// is not one JSON value, and what it names is not trusted.
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return ""
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ""
	}

	return value
}

// destination resolves requested, a destination a sign-in's request named,
// to where the browser is sent: requested itself when the consumer
// allowlisted it exactly (WithSessionCookieRedirects) or when it is a path on
// this origin (sameOriginPath), and "/" otherwise.
func (c *sessionCookie) destination(requested string) string {
	if _, ok := c.redirects[requested]; ok {
		return requested
	}

	if sameOriginPath(requested) {
		return requested
	}

	return "/"
}

// sameOriginPath reports whether p sends a browser nowhere but this origin:
// printable ASCII with no space, beginning with exactly one "/", and, once
// percent-decoded (once), still beginning with exactly one "/" and holding no
// "\" and no control character. Every browser reads "//host" and "/\host" as
// another host, and ignores a tab, carriage return or line feed inside a URL,
// so "/\t/host" is "//host"; a "\" or a control character anywhere is
// refused rather than judged by position, and an escape that does not decode
// is refused too.
func sameOriginPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || !printableASCII(p) || strings.Contains(p, `\`) {
		return false
	}

	decoded, err := url.PathUnescape(p)
	if err != nil {
		return false
	}

	if strings.HasPrefix(decoded, "//") || strings.ContainsFunc(decoded, func(r rune) bool {
		return r == '\\' || r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0)
	}) {
		return false
	}

	return true
}

// printableASCII reports whether s holds only the visible ASCII characters,
// '!' to '~'.
func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}

	return true
}

// WithSessionCookieNextParam names the form field, or JSON member, a browser
// sign-in names its destination in.
//
// Default: DefaultSessionCookieNextParam ("next"). The field is read from the
// sign-in's URL-encoded form or JSON body alone, never its URL or a multipart
// body, and at most its first 64 KiB, at the issuing endpoints that have no
// destination of their own (form login, passwordless passkey login,
// second-factor verification, re-authentication, recovery completion and
// session renewal); magic link redemption and the federated callback keep
// theirs, resolved through their own allowlists. An empty name is a
// configuration error from New.
func WithSessionCookieNextParam(name string) SessionCookieOption {
	return func(s *sessionCookie) error {
		if name == "" {
			return newConfigError("WithSessionCookieNextParam was given no name; omit it to keep %q",
				DefaultSessionCookieNextParam)
		}

		s.nextParam = name

		return nil
	}
}

// WithSessionCookieRedirects allows a browser sign-in on the cookie chain to
// be sent to each of targets, absolute URLs on other origins.
//
// Default: none, so a sign-in is sent only to a path on this origin: a
// destination beginning with exactly one "/", holding no "\" and no control
// character before or after it is percent-decoded once. Anything else, "/".
//
// The line: a requested destination is sent to a target only when it equals
// the target exactly, with no prefix matching, case folding or
// normalisation. Each target must be an absolute https URL with a host, and
// with no userinfo, no fragment and no space or control character; anything
// else is a configuration error from New, naming the target. Calls
// accumulate.
func WithSessionCookieRedirects(targets ...string) SessionCookieOption {
	return func(s *sessionCookie) error {
		for _, target := range targets {
			if err := checkRedirectTarget(target); err != nil {
				return err
			}

			if s.redirects == nil {
				s.redirects = make(map[string]struct{}, len(targets))
			}

			s.redirects[target] = struct{}{}
		}

		return nil
	}
}

// checkRedirectTarget refuses an allowlist entry that is not an absolute
// https URL with a host and no userinfo or fragment.
func checkRedirectTarget(target string) error {
	refuse := func(why string) error {
		return newConfigError("WithSessionCookieRedirects was given %q, which %s; each target must be an "+
			"absolute https URL with a host, and no userinfo or fragment", target, why)
	}

	if !printableASCII(target) {
		return refuse("is empty or holds a space, a control or a non-ASCII character")
	}

	if strings.Contains(target, "#") {
		return refuse("carries a fragment")
	}

	u, err := url.Parse(target)

	switch {
	case err != nil:
		return refuse("does not parse")
	case u.Scheme != "https":
		return refuse("is not an https URL")
	case u.Opaque != "", u.Host == "":
		return refuse("names no host")
	case u.User != nil:
		return refuse("carries userinfo")
	}

	return nil
}
