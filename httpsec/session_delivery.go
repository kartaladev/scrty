package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/session"
)

// credentialDelivery hands out the credential an issuing endpoint issued for
// a session it has just stored: form login, magic link redemption, federated
// handoff redemption, passwordless passkey login, second-factor
// verification, re-authentication, recovery completion and session renewal
// all hand theirs out through it, once the session is stored and before
// anything publishes or reports it.
//
// On a cookie chain it sets the session cookie to the stored session's
// identifier and leaves nothing for the body; the issuer of such a chain has
// issued nothing an endpoint could write (issueNoCredential) either. On any
// other chain it hands the issued credential back unchanged, for the
// endpoint's responder to write. Its zero value is the latter, which is also
// what an endpoint whose credential is dropped is given.
type credentialDelivery struct {
	// cookie is the chain's cookie session, nil on a chain without one.
	cookie *sessionCookie

	// log is the chain's logger.
	log *slog.Logger
}

// delivery is how this chain's issuing endpoints hand out their credentials.
// Every caller asks for it once the options have all been applied, so it
// sees the cookie session wherever in the options it was enabled, and the
// logger the chain settled on.
func (c *config) delivery() credentialDelivery {
	d := credentialDelivery{log: c.logger}

	_ = eachInterceptor(c, func(s *sessionCookie) error {
		d.cookie = s

		return nil
	})

	return d
}

// deliver hands out credential, issued for s, which sessions has just
// stored, and returns what the endpoint may write to the response body: the
// credential unchanged on a chain without the cookie session, and nothing on
// a cookie chain, which sets the session cookie to s's identifier instead.
//
// A cookie that cannot be delivered (a consumer's SessionDelivery failing or
// breaking its contract) is an issuing failure, and nothing the delivery
// wrote reaches the response. The sign-in s belongs to is then ended
// (session.Sessions.RevokeFamily), the session the request presented
// included when it rotated: the client never learns the stored identifier,
// and the delivery has seen it, so leaving it live would leave a sign-in
// nobody holds that whoever reads the delivery's records could use. The end
// is written on a context the client's hang-up does not cancel. An end that
// fails is logged, and the issuing failure is returned all the same.
func (d credentialDelivery) deliver(
	ex *Exchange, sessions *session.Sessions, s *session.Session, credential string,
) (string, error) {
	if d.cookie == nil {
		return credential, nil
	}

	// A delivery that panics (or ends its goroutine) has not delivered
	// either: the sign-in is ended exactly as for any other failure, and the
	// panic then goes on with its original value, since the library does not
	// swallow a consumer's panic.
	returned := false

	defer func() {
		if returned {
			return
		}

		r := recover()

		d.endUndelivered(ex.Context(), sessions, s)

		if r != nil {
			panic(r)
		}
	}()

	err := d.cookie.deliver(ex, s, d.log)

	returned = true

	if err != nil {
		d.endUndelivered(ex.Context(), sessions, s)

		return "", err
	}

	return "", nil
}

// endUndelivered ends the sign-in of s, whose cookie could not be delivered.
func (d credentialDelivery) endUndelivered(ctx context.Context, sessions *session.Sessions, s *session.Session) {
	if sessions == nil {
		return
	}

	// Detached, so the client's hang-up cannot leave the sign-in live, and
	// bounded, so a store that hangs cannot hold the request for ever.
	ctx, cancel := detach.Bounded(ctx, detach.RevocationTimeout)
	defer cancel()

	if _, err := sessions.RevokeFamily(ctx, s.FamilyID); err != nil && d.log != nil {
		d.log.LogAttrs(ctx, slog.LevelWarn, msgUndeliveredNotEnded, diag.Failure("session-store", err)...)
	}
}

// msgUndeliveredNotEnded is the record of a sign-in whose cookie could not be
// delivered and that could not be ended either. It names no session.
const msgUndeliveredNotEnded = "httpsec: a sign-in whose session cookie could not be delivered could not be ended; " +
	"it ends at its own deadlines"

// msgSessionNotDelivered is the text an undelivered session cookie fails
// with.
const msgSessionNotDelivered = "httpsec: the session cookie could not be delivered"

// The causes of a delivery that broke its contract.
var (
	errDeliveredBodyCredential = errors.New("httpsec: the session delivery returned a credential for the body")
	errDeliveredBody           = errors.New("httpsec: the session delivery wrote to the response body")
	errDeliveredElsewhere      = errors.New("httpsec: the session delivery wrote the session identifier " +
		"somewhere other than the HttpOnly, Secure session cookie")
	errDeliveredNoCookie = errors.New("httpsec: the session delivery set no session cookie")
	errDeliveredAltered  = errors.New("httpsec: the session delivery set the session cookie with other " +
		"attributes than the chain's own")
	errDeliveredRawCookie = errors.New("httpsec: the session delivery set a cookie through a raw header")
)

// deliver sets the session cookie to sess's identifier, through the
// consumer's SessionDelivery when one was given, on a response no cache may
// keep: the response carries the browser's credential, in Set-Cookie.
//
// The consumer's delivery is handed its own copy of the session and of the
// exchange, whose writer is a staging writer for good: what it writes is
// copied to the response only once it returned nothing for the body, no
// error, no body of its own, the chain's own session cookie exactly
// (sessionCookie.cookie: name, value, path, domain, SameSite, Secure,
// HttpOnly and Max-Age), and the identifier nowhere else. Any other outcome is
// an issuing failure, and the response is left as it was. The identifier is
// read before the delivery runs, so nothing it does to its copy changes what
// it is judged against, what the endpoint publishes or what the store holds.
func (s *sessionCookie) deliver(ex *Exchange, sess *session.Session, log *slog.Logger) error {
	id := sess.ID
	want := s.cookie(id, s.maxAgeOf(sess))

	if s.delivery == nil {
		ex.Writer.SetCookie(want)
		ex.Writer.SetHeader("Cache-Control", "no-store")

		return nil
	}

	staged := &stagedWriter{}
	body, err := s.consumerDelivery(ex, staged, sess, id)

	err = porterr.SanitizeTo(ex.Context(), log, err, porterr.ErrUnwalkable)
	switch {
	case err != nil:
		return issuingFailure(err, msgSessionNotDelivered)
	case body != "":
		return issuingFailure(errDeliveredBodyCredential, msgSessionNotDelivered)
	}

	if err := staged.check(want, id); err != nil {
		return issuingFailure(err, msgSessionNotDelivered)
	}

	staged.replay(ex.Writer)
	ex.Writer.SetHeader("Cache-Control", "no-store")

	return nil
}

// consumerDelivery runs the consumer's delivery on copies: of the exchange,
// with staged as its writer for good, and of the sessions it is handed and
// reads, so what it does to them reaches neither the response nor what the
// endpoint stores or publishes.
func (s *sessionCookie) consumerDelivery(
	ex *Exchange, staged *stagedWriter, sess *session.Session, id string,
) (string, error) {
	// Whatever the delivery writes once it has returned, or panicked, on a
	// goroutine it started or through an exchange it kept, is not judged and
	// goes nowhere.
	defer staged.seal()

	return s.delivery.Deliver(detachedCopy(ex, staged), copySession(sess), id)
}

// detachedCopy returns the exchange a consumer's delivery is handed: staged
// is its writer for good, its session is a copy, and it shares no per-request
// state with ex. The per-request phase is dropped and the stack of runs is
// copied, so nothing the delivery does through it reaches the request's own
// exchange, the store or the chain's policies, and PublishSession and
// EvaluatePerRequest refuse on it (Exchange.detached).
func detachedCopy(ex *Exchange, staged *stagedWriter) *Exchange {
	port := *ex
	port.Writer = staged
	port.Session = copySession(ex.Session)
	port.perRequest = nil
	port.detached = true
	port.extra = slices.Clone(ex.extra)

	return &port
}

// copySession returns a session sharing no map or slice with s, nil for nil.
func copySession(s *session.Session) *session.Session {
	if s == nil {
		return nil
	}

	out := *s
	out.FederatedAMR = slices.Clone(s.FederatedAMR)
	out.SuccessorDigest = slices.Clone(s.SuccessorDigest)

	if s.Data != nil {
		out.Data = maps.Clone(s.Data)
	}

	return &out
}

// maxAgeOf is the Max-Age the cookie of sess is set with, read as
// sessionCookie.cookie reads it: zero, so the browser keeps the cookie for
// its own session and the server's idle and absolute deadlines decide how
// long the sign-in lasts. It is the seam a persistent sign-in's Max-Age is
// computed at.
func (*sessionCookie) maxAgeOf(*session.Session) int {
	return 0
}

// stagedWriter is the writer a consumer's SessionDelivery writes to. It keeps
// the headers and cookies set on it, in order, for replay onto the response
// once they are judged, and refuses a body. Once sealed it ignores every
// write, so a delivery that outlives its call cannot change what was judged.
type stagedWriter struct {
	mu      sync.Mutex
	sealed  bool
	ops     []func(ResponseWriter)
	headers []stagedHeader
	cookies []Cookie
	wrote   bool
}

// stagedHeader is a header the delivery set.
type stagedHeader struct{ name, value string }

// seal makes every later write a no-op.
func (w *stagedWriter) seal() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.sealed = true
}

func (w *stagedWriter) SetHeader(name, value string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.sealed {
		return
	}

	w.headers = append(w.headers, stagedHeader{name, value})
	w.ops = append(w.ops, func(rw ResponseWriter) { rw.SetHeader(name, value) })
}

func (w *stagedWriter) AddHeader(name, value string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.sealed {
		return
	}

	w.headers = append(w.headers, stagedHeader{name, value})
	w.ops = append(w.ops, func(rw ResponseWriter) { rw.AddHeader(name, value) })
}

func (w *stagedWriter) SetCookie(cookie *Cookie) {
	if cookie == nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.sealed {
		return
	}

	c := *cookie
	c.Unparsed = slices.Clone(cookie.Unparsed)
	w.cookies = append(w.cookies, c)
	w.ops = append(w.ops, func(rw ResponseWriter) {
		replayed := c

		rw.SetCookie(&replayed)
	})
}

func (w *stagedWriter) WriteHeader(int) { w.markWrote() }

func (w *stagedWriter) Write([]byte) (int, error) {
	w.markWrote()

	return 0, errDeliveredBody
}

func (w *stagedWriter) Stream(context.Context, string, func(context.Context, EventWriter) error) error {
	w.markWrote()

	return ErrStreamingUnsupported
}

// markWrote records an attempt to write a status or body, unless sealed.
func (w *stagedWriter) markWrote() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.sealed {
		w.wrote = true
	}
}

// check judges what the delivery wrote against want, the session cookie the
// chain would have set itself, which carries the identifier id: every cookie
// under want's name must be want exactly, at least one must be set, the
// identifier may appear in no other cookie (name, value, path, domain) and no
// header (name or value), and no cookie may be set through a raw header,
// which cannot be judged.
//
// The identifier is matched literally. The check guards against a delivery's
// mistakes, not against a hostile one: a transformed copy of the identifier
// (base64 in a header, say) is not recognised. A delivery is trusted code,
// which the consumer wrote and wired.
func (w *stagedWriter) check(want *Cookie, id string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.wrote {
		return errDeliveredBody
	}

	for _, h := range w.headers {
		switch {
		case strings.EqualFold(h.name, "Set-Cookie"):
			return errDeliveredRawCookie
		case strings.Contains(h.name, id), strings.Contains(h.value, id):
			return errDeliveredElsewhere
		}
	}

	var delivered bool

	for i := range w.cookies {
		c := &w.cookies[i]

		if c.Name == want.Name {
			if !sameCookie(c, want) {
				return errDeliveredAltered
			}

			delivered = true

			continue
		}

		if carries(c, id) {
			return errDeliveredElsewhere
		}
	}

	if !delivered {
		return errDeliveredNoCookie
	}

	return nil
}

// sameCookie reports whether a and b would set the same cookie.
func sameCookie(a, b *Cookie) bool {
	return a.Name == b.Name && a.Value == b.Value && a.Path == b.Path && a.Domain == b.Domain &&
		a.Expires.Equal(b.Expires) && a.MaxAge == b.MaxAge && a.Secure == b.Secure &&
		a.HttpOnly == b.HttpOnly && a.SameSite == b.SameSite && a.Partitioned == b.Partitioned
}

// carries reports whether any text of c contains id.
func carries(c *Cookie, id string) bool {
	if strings.Contains(c.Name, id) || strings.Contains(c.Value, id) || strings.Contains(c.Path, id) ||
		strings.Contains(c.Domain, id) || strings.Contains(c.Raw, id) {
		return true
	}

	return slices.ContainsFunc(c.Unparsed, func(u string) bool { return strings.Contains(u, id) })
}

// replay writes what the delivery set onto rw, in the order it set it.
func (w *stagedWriter) replay(rw ResponseWriter) {
	w.mu.Lock()
	ops := slices.Clone(w.ops)
	w.mu.Unlock()

	for _, op := range ops {
		op(rw)
	}
}

// SessionDelivery replaces how a cookie chain writes a new session's cookie
// (WithSessionDelivery).
//
// A delivery is trusted code: the chain's check of what it wrote guards
// against its mistakes, not against a hostile delivery. The identifier is
// matched literally, so an encoded copy of it (base64 in a header, say) is
// not detected.
type SessionDelivery interface {
	// Deliver writes the session cookie carrying credential, the identifier of
	// s, which the chain has just stored, through ex.Writer, and returns what
	// the endpoint may write to the response body, which on a cookie chain is
	// always "".
	//
	// ex is a detached copy of the request's exchange: it shares no
	// per-request state with it, carries no per-request phase, and
	// PublishSession and EvaluatePerRequest on it return an error wrapping
	// ErrConfig and change nothing. A Deliver that panics ends the sign-in
	// like any other failure, and the panic then goes on with its value.
	//
	// ex and s are Deliver's own copies: ex.Writer is a staging writer that
	// the chain judges once Deliver returns and then ignores for good, so a
	// write made after Deliver returned, on a goroutine it started or through
	// an exchange it kept, goes nowhere; and changing s changes neither what
	// the chain judges the delivery against nor the session it stores and
	// publishes. Deliver runs on the request's goroutine.
	//
	// What Deliver may do: set the cookie the way the chain would (credential
	// as the value, the chain's own name, path, domain, SameSite, Secure,
	// HttpOnly and Max-Age), record what it needs (an audit entry), and set
	// headers and other cookies that do not carry credential. What it may not
	// do, on pain of an issuing failure: change any attribute of the session
	// cookie, set a cookie through a raw Set-Cookie header, write a body or a
	// status, or put credential anywhere else, in a header's name or value or
	// in another cookie's name, value or path.
	Deliver(ex *Exchange, s *session.Session, credential string) (bodyCredential string, err error)
}

// WithSessionDelivery replaces how the cookie chain writes a new session's
// cookie with d, which every issuing endpoint then hands its stored session
// to: form login, magic link and federated handoff redemption, passwordless
// passkey login, second-factor verification, re-authentication, recovery
// completion and session renewal.
//
// Default: the chain sets the session cookie itself, under the name and
// attributes the other options settled, and leaves the body without a
// credential. A delivery customises how the cookie is written (an audit
// record, extra headers or cookies that carry no credential), not what the
// cookie is: its attributes are the chain's decision (Max-Age, once a
// persistent sign-in is chosen, included), and not whether a script may read
// the identifier.
//
// The line: what d writes is held back and judged once it returns, and it
// reaches the response only when d returned no error and no body credential,
// wrote no body (WriteHeader, Write or Stream), set no cookie through a raw
// Set-Cookie header, set every cookie under this chain's name exactly as the
// chain would (value the identifier; path, domain, SameSite, Secure, HttpOnly
// and Max-Age as the chain's), at least one, and put the identifier in no
// other header or cookie. Anything else is an issuing failure (answered 500
// by default, with d's own error reachable through errors.Is behind the
// library's text): nothing d wrote, and no credential, reaches the response,
// and the sign-in d was handed is ended, so the identifier it saw
// authenticates nothing. The response is set no-store after d's headers are
// copied.
//
// d is trusted code. The line is checked literally and guards against d's
// mistakes, not against a hostile d: an encoded copy of the identifier (base64
// in a header, say) is not detected.
//
// A nil delivery, including an interface holding a nil pointer, is refused.
func WithSessionDelivery(d SessionDelivery) SessionCookieOption {
	return func(s *sessionCookie) error {
		if err := requireDep("WithSessionDelivery", "session delivery", d); err != nil {
			return err
		}

		s.delivery = d

		return nil
	}
}
