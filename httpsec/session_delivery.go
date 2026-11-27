package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/hangup"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/session"
)

// credentialDelivery hands out the credential an issuing endpoint issued for
// a session it has just stored: form login, magic link redemption, federated
// handoff redemption or, on a cookie chain, the federated callback,
// passwordless passkey login, second-factor
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

	// grace is the window a privilege change's rotation on a cookie chain
	// keeps the old identifier working for (privilegeRotationGrace), read
	// when delivery is called; it means nothing on a chain without the
	// cookie session.
	grace time.Duration
}

// delivery is how this chain's issuing endpoints hand out their credentials.
// Every caller asks for it once the options have all been applied, so it
// sees the cookie session wherever in the options it was enabled, and the
// logger the chain settled on.
func (c *config) delivery() credentialDelivery {
	d := credentialDelivery{log: c.logger, grace: privilegeRotationGrace(c.renewal)}

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
// is written on a context the client's hang-up does not cancel, bounded by
// the revocation timeout logout's revocation uses (detach.RevocationTimeout),
// so a store that hangs cannot hold the request for ever. It also runs when
// the delivery panics, before the panic goes on with its value, and when it
// ends its goroutine (runtime.Goexit). An end that fails is logged, and the
// issuing failure is returned all the same.
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
// HttpOnly, quoting and Max-Age, the last allowed to be one second under; see
// sameCookie), and the identifier nowhere else. Any other outcome is
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
// is its writer for good, its session and its authentication result are
// copies, and it shares no per-request state with ex. The authentication
// result is copied shallowly: what its fields point to (the principal) is
// still shared, so replacing a field on the copy is safe and editing the
// principal in place is not. The per-request phase is dropped and the stack
// of runs is copied, so nothing the delivery does through it reaches the
// request's own exchange, the store or the chain's policies, and
// PublishSession and EvaluatePerRequest refuse on it (Exchange.detached).
func detachedCopy(ex *Exchange, staged *stagedWriter) *Exchange {
	port := *ex
	port.Writer = staged
	port.Session = copySession(ex.Session)

	if ex.Authentication != nil {
		// A shallow copy: the delivery may replace the copy's fields, the
		// caller among them, without reaching the request's own result.
		authn := *ex.Authentication
		port.Authentication = &authn
	}

	port.perRequest = nil
	port.detached = true

	// The copy has no role-switch guard and takes none from the run it is
	// nested in (Chain.Assemble): the delivery is called inside a switch's
	// rotation, under the guard's lock, so a chain it runs on the copy would
	// wait for that lock and never get it, and its handler's return would
	// mark the request's own handler as returned. Its context marks the same
	// boundary for every exchange built over it or a context derived from it
	// (inheritedGuard), as an adapter's mount builds one.
	port.roleSwitch = nil
	port.ctx = newDetachedBoundary(ex.ctx)
	port.extra = slices.Clone(ex.extra)

	return &port
}

// detachedBoundaryKey is the context key a detachedBoundary answers to.
type detachedBoundaryKey struct{}

// detachedBoundary is the context of a session delivery's detached copy. It
// records the run, finished or not, marked nearest on the context the copy was
// made from: no exchange whose context derives from the boundary takes a
// role-switch guard carried by that run or by any run it began inside
// (inheritedGuard). Every other key, the runs themselves included, is answered
// by the context it wraps, so a chain run under the boundary is judged as it
// would be on the request.
type detachedBoundary struct {
	context.Context //nolint:containedctx // the boundary marks the context it wraps, and is that context

	run *chainRun
}

// newDetachedBoundary wraps ctx in a boundary at the run marked nearest on it.
func newDetachedBoundary(ctx context.Context) *detachedBoundary {
	r, _ := ctx.Value(chainRunKey{}).(*chainRun)

	return &detachedBoundary{Context: ctx, run: r}
}

// Value answers detachedBoundaryKey with the boundary, the nearest one when
// boundaries nest, and every other key from the context it wraps.
func (b *detachedBoundary) Value(key any) any {
	if _, ok := key.(detachedBoundaryKey); ok {
		return b
	}

	return b.Context.Value(key)
}

// covers reports whether r is the boundary's run or a run it began inside.
// The innermost boundary covers every run an outer one does, since its run
// began inside the outer one's.
func (b *detachedBoundary) covers(r *chainRun) bool {
	for a := b.run; a != nil; a = a.parent {
		if a == r {
			return true
		}
	}

	return false
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
// sessionCookie.cookie reads it. A sign-in that did not choose a persistent
// cookie gets zero, so the browser keeps the cookie for its own session and
// the server's idle and absolute deadlines decide how long the sign-in lasts.
// One that did (session.Session.PersistentCookie) gets the seconds from the
// chain's clock to its absolute deadline, rounded up, and at least 1 however
// close or past the deadline is: zero would set no Max-Age, and a negative
// one would expire the very cookie being set. The server's deadlines still
// decide whether the session loads.
func (s *sessionCookie) maxAgeOf(sess *session.Session) int {
	if !sess.PersistentCookie || s.ref.now == nil {
		return 0
	}

	left := sess.AbsoluteExpiresAt.Sub(s.ref.now())
	if left <= time.Second {
		return 1
	}

	// Capped before rounding, so the count fits an int on every platform and
	// the rounding below cannot overflow a deadline centuries away (Sub
	// saturates at about 292 years): browsers cap a cookie's lifetime far
	// below it anyway.
	if left >= time.Duration(math.MaxInt32)*time.Second {
		return math.MaxInt32
	}

	// Rounded up in whole seconds.
	return int((left + time.Second - 1) / time.Second)
}

// privilegeRotationGrace is the grace window the cookie session's rotations at
// a privilege change (an active-role switch, a password change) keep the old
// identifier working for: the renewal endpoint's (WithRenewalGrace) when the
// chain has one, so one chain has one window, and session.DefaultRenewalGrace
// otherwise.
func privilegeRotationGrace(renewal *sessionRenewal) time.Duration {
	if renewal != nil {
		return renewal.grace
	}

	return defaultRenewalGrace
}

// cookieRotationTexts are the fixed texts a cookie rotation that reached no
// verdict is answered with: failed for a dependency failure, ended for the
// request's own end.
type cookieRotationTexts struct{ failed, ended string }

// rotateCookie rotates current, the cookie session a request is on, into a
// successor in the same sign-in that keeps current's identifier working for
// grace (session.Sessions.RotateWithGrace), and re-sets the session cookie to
// it on ex's response through deliver. It returns the successor. ctx is the
// context the rotation is written on. opts are the rotation's own options,
// such as session.WithSuccessorRole, which a failed option fails the rotation
// with before any cookie is set.
//
// It is the one place a privilege change on a cookie chain rotates, so a
// consumer's opt-out of a rotation is decided by its callers, before it runs.
//
// deadline, when not zero, is the absolute deadline the session will have once
// the caller has saved its change, which is later than the successor's own
// when the change restores deadlines a recovery lowered. The cookie, and the
// session a consumer's delivery is handed, carry it, so a persistent cookie's
// Max-Age is that of the session the sign-in is left with, not of the
// confinement it is leaving. The stored successor is not changed here.
//
// A rotation that fails sets no cookie, so current's identifier keeps
// working: a refusal (the session gone, expired or reused, or a concurrent
// rotation won) as refusedRenewal words it, the request's own end matching
// ctx's error behind texts.ended, and anything else a dependency failure
// behind texts.failed, its cause reachable through errors.Is. It stores
// nothing, except when it fails with session.ErrStoreContract (a store that
// wrote the successor back without what opts asked for): the store has
// written by then, current is superseded and the successor live, so current's
// identifier works through grace only and is reuse after it. A cookie that
// cannot be delivered ends the sign-in (deliver).
func (d credentialDelivery) rotateCookie(
	ctx context.Context, ex *Exchange, sessions *session.Sessions, current *session.Session,
	grace time.Duration, deadline time.Time, texts cookieRotationTexts, opts ...session.RotateOption,
) (*session.Session, error) {
	successor, _, err := sessions.RotateWithGrace(ctx, current, grace, opts...)
	if err != nil {
		if refusal := refusedRenewal(err); refusal != nil {
			return nil, refusal
		}

		if hangup.ByCaller(ctx, err) {
			return nil, diag.Wrap(err, texts.ended, ctx.Err())
		}

		return nil, diag.Wrap(err, texts.failed)
	}

	delivered := successor
	if !deadline.IsZero() {
		withDeadline := *successor
		withDeadline.AbsoluteExpiresAt = deadline
		delivered = &withDeadline
	}

	if _, err := d.deliver(ex, sessions, delivered, ""); err != nil { //nolint:contextcheck // the cookie is delivered on the request's own exchange, as every issuing endpoint delivers it
		return nil, err
	}

	return successor, nil
}

// persists reports whether the sign-in ex is creating chose a persistent
// cookie (WithSessionCookiePersistence): false on a chain without the cookie
// session or without a decision. The decision is asked once per call.
func (d credentialDelivery) persists(ex *Exchange) bool {
	return d.cookie != nil && d.cookie.persist != nil && d.cookie.persist(ex)
}

// signInOptions are the create options a new sign-in on ex takes from the
// cookie session: session.WithPersistentCookie when it chose a persistent
// cookie, and none otherwise.
func (d credentialDelivery) signInOptions(ex *Exchange) []session.CreateOption {
	if d.persists(ex) {
		return []session.CreateOption{session.WithPersistentCookie()}
	}

	return nil
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

// sameCookie reports whether got, the cookie a delivery set, is the cookie
// want the chain would set. Every attribute must match, with one tolerance: a
// delivery that works out Max-Age by reading a clock itself reads it a moment
// after the chain did and may cross a second's boundary, so got's Max-Age may
// also be exactly one second under want's, but never below 1: that would be
// no Max-Age at all.
func sameCookie(got, want *Cookie) bool {
	a, b := got, want

	return a.Name == b.Name && a.Value == b.Value && a.Quoted == b.Quoted && a.Path == b.Path && a.Domain == b.Domain &&
		a.Expires.Equal(b.Expires) && maxAgeWithinASecond(a.MaxAge, b.MaxAge) && a.Secure == b.Secure &&
		a.HttpOnly == b.HttpOnly && a.SameSite == b.SameSite && a.Partitioned == b.Partitioned
}

// maxAgeWithinASecond reports whether got is want, or one second under it
// when that leaves at least 1. A want of zero (no Max-Age) accepts only zero.
func maxAgeWithinASecond(got, want int) bool {
	return got == want || (want > 1 && got == want-1)
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

//go:generate mockgen -destination=sessiondelivery_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec SessionDelivery

// SessionDelivery replaces how a cookie chain writes a new session's cookie
// (WithSessionDelivery).
//
// A delivery is trusted code: the chain's check of what it wrote guards
// against its mistakes, not against a hostile delivery. The identifier is
// matched literally, so an encoded copy of it (base64 in a header, say) is
// not detected. A delivery must not switch the active role (SwitchActiveRole):
// a role switch delivers through it, so a switch made with the delivery's
// context, or one derived from it, is refused with an error wrapping
// ErrConfig and stores nothing.
type SessionDelivery interface {
	// Deliver writes the session cookie carrying credential, the identifier of
	// signIn, which the chain has just stored, through ex.Writer, and returns what
	// the endpoint may write to the response body, which on a cookie chain is
	// always "".
	//
	// ex is a detached copy of the request's exchange: it shares no
	// per-request state with it, carries no per-request phase, and
	// PublishSession and EvaluatePerRequest on it return an error wrapping
	// ErrConfig and change nothing. A Deliver that panics ends the sign-in
	// like any other failure, and the panic then goes on with its value.
	//
	// ex and signIn are Deliver's own copies: ex.Writer is a staging writer that
	// the chain judges once Deliver returns and then ignores for good, so a
	// write made after Deliver returned, on a goroutine it started or through
	// an exchange it kept, goes nowhere; and changing signIn changes neither what
	// the chain judges the delivery against nor the session it stores and
	// publishes. ex.Authentication is a shallow copy: the principal it points
	// to is shared with the request, so Deliver must not edit the principal in
	// place. Deliver runs on the request's goroutine.
	//
	// What Deliver may do: set the cookie the way the chain would (credential
	// as the value, the chain's own name, path, domain, SameSite, Secure,
	// HttpOnly and Max-Age), record what it needs (an audit entry), and set
	// headers and other cookies that do not carry credential. What it may not
	// do, on pain of an issuing failure: change any attribute of the session
	// cookie, its quoting included, set a cookie through a raw Set-Cookie
	// header, write a body or a status, or put credential anywhere else, in a
	// header's name or value or in another cookie's name, value or path.
	//
	// Max-Age is none for a session whose signIn.PersistentCookie is false, and
	// otherwise the seconds from the chain's clock to signIn.AbsoluteExpiresAt,
	// rounded up and at least 1, read by the chain just before Deliver runs.
	// A Deliver that works it out by reading a clock itself reads it later,
	// and across a second's boundary comes one second short: the chain
	// accepts a Max-Age equal to that value or exactly one second under it,
	// never below 1. Any other Max-Age, and a Max-Age on a cookie that has
	// none, is refused as an altered cookie.
	Deliver(ex *Exchange, signIn *session.Session, credential string) (bodyCredential string, err error)
}

// WithSessionDelivery replaces how the cookie chain writes a new session's
// cookie with delivery, which every issuing endpoint then hands its stored session
// to: form login, magic link redemption, the federated callback,
// passwordless passkey login, second-factor verification, re-authentication,
// recovery completion, session renewal, and the rotations at an active-role
// switch and at a password change.
//
// Default: the chain sets the session cookie itself, under the name and
// attributes the other options settled, and leaves the body without a
// credential. A delivery customises how the cookie is written (an audit
// record, extra headers or cookies that carry no credential), not what the
// cookie is: its attributes are the chain's decision (Max-Age, once a
// persistent sign-in is chosen, included), and not whether a script may read
// the identifier.
//
// The line: what delivery writes is held back and judged once it returns, and
// it reaches the response only when delivery returned no error and no body
// credential, wrote no body (WriteHeader, Write or Stream), set no cookie
// through a raw Set-Cookie header, set every cookie under this chain's name
// exactly as the chain would (value the identifier; path, domain, SameSite,
// Secure, HttpOnly, quoting and Max-Age as the chain's), at least one, and put the
// identifier in no other header or cookie. Anything else is an issuing
// failure (answered 500 by default, with delivery's own error reachable
// through errors.Is behind the library's text): nothing delivery wrote, and no
// credential, reaches the response, and the sign-in delivery was handed is
// ended, so the identifier it saw authenticates nothing. The response is set
// no-store after delivery's headers are copied.
//
// delivery is trusted code. The line is checked literally and guards against
// its mistakes, not against a hostile delivery: an encoded copy of the
// identifier (base64 in a header, say) is not detected.
//
// A nil delivery, including an interface holding a nil pointer, is refused.
func WithSessionDelivery(delivery SessionDelivery) SessionCookieOption {
	return func(s *sessionCookie) error {
		if err := requireDep("WithSessionDelivery", "session delivery", delivery); err != nil {
			return err
		}

		s.delivery = delivery

		return nil
	}
}
