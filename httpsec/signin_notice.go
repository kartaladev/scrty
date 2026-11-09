package httpsec

//go:generate mockgen -destination=seendevices_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec SeenDevices

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/session"
)

// OrderSignInNotice is the unseen-device sign-in notice
// (EnableSignInNotice). It is outside every login endpoint, so it sees the
// sign-in any of them stores on the request.
const OrderSignInNotice = OrderJWKS - 1

// SeenDevices is the consumer's record of the devices a user signed in from
// before: what the unseen-device notice consults beside the user's other live
// sign-ins, for a consumer who keeps device history longer than sessions
// live. The library supplies none, and without one only the live sign-ins
// are consulted.
type SeenDevices interface {
	// Seen reports whether user signed in from userAgent before. An error
	// sends no notice for the sign-in, and is logged without its text.
	Seen(ctx context.Context, user identity.UserID, userAgent string) (bool, error)
}

// SignInNoticeFacts is what a sign-in notice says: when the sign-in happened
// and a coarse description of its device. It never carries a token, a link
// secret, a session handle, the client address or the raw user agent.
type SignInNoticeFacts struct {
	// At is when the sign-in was stored.
	At time.Time

	// Device names the sign-in's browser and platform family, such as
	// "Firefox on Linux", or the browser alone when the platform is not
	// recognised, or "an unrecognised device". It is always drawn from the
	// library's fixed vocabulary, never copied from the user agent, so a
	// crafted user agent cannot put text of its own into the notice.
	Device string
}

// DefaultSignInNoticeTimeout is how long a sign-in notice's work may run
// before it is abandoned (WithSignInNoticeTimeout).
const DefaultSignInNoticeTimeout = 30 * time.Second

// unrecognisedDevice is the device description of a sign-in whose user agent
// names no browser the notice recognises, or that recorded none.
const unrecognisedDevice = "an unrecognised device"

// SignInNoticeOption configures the unseen-device sign-in notice.
type SignInNoticeOption func(*signInNotice) error

// signInNotice sends a user a notice when a sign-in comes from a device none
// of their other live sign-ins came from.
type signInNotice struct {
	sender   notify.Sender
	sessions *session.Sessions

	// logger and sampler are the chain's, and now reads the chain's clock,
	// handed over once the chain exists.
	logger  *slog.Logger
	sampler *logsample.Sampler
	now     func() time.Time

	matches   func(signedIn, known session.SignIn) bool
	seen      SeenDevices
	recipient func(ctx context.Context, p *identity.Principal) (string, error)
	message   func(f SignInNoticeFacts) (subject, body string)

	// timeout bounds the notice's work (WithSignInNoticeTimeout).
	timeout time.Duration

	// concurrency is how many notices may be in progress at once
	// (WithSignInNoticeConcurrency), and slots holds one value per notice in
	// progress.
	concurrency int
	slots       chan struct{}

	// track, when set, counts the notice's work in flight
	// (withSignInNoticeTracker).
	track *sync.WaitGroup
}

// WithSignInNoticeTimeout bounds the notice's work: the listing, the
// seen-devices port, the recipient lookup and the send together. When it
// passes, the context they were given ends, and a notice not yet sent is
// abandoned and logged. The ports must honour their context for the work to
// end there.
//
// Default: DefaultSignInNoticeTimeout, 30 seconds. A zero or negative
// duration is refused; omit the option to keep the default.
func WithSignInNoticeTimeout(timeout time.Duration) SignInNoticeOption {
	return func(n *signInNotice) error {
		if timeout <= 0 {
			return newConfigError("WithSignInNoticeTimeout was given %s, which is not positive; omit "+
				"the option to keep the default of %s", timeout, DefaultSignInNoticeTimeout)
		}

		n.timeout = timeout

		return nil
	}
}

// DefaultSignInNoticeConcurrency is how many sign-in notices may be in
// progress at once (WithSignInNoticeConcurrency).
const DefaultSignInNoticeConcurrency = 32

// WithSignInNoticeConcurrency bounds how many notices may be in progress at
// once. A sign-in that completes while that many are in progress is not
// notified: its notice is dropped, never queued, and the drop is logged at
// WARN, sampled, naming no user. The sign-in itself is not delayed.
//
// Default: DefaultSignInNoticeConcurrency, 32, about one store connection
// pool's worth. A value below 1 is refused; omit the option to keep the
// default.
func WithSignInNoticeConcurrency(concurrency int) SignInNoticeOption {
	return func(n *signInNotice) error {
		if concurrency < 1 {
			return newConfigError("WithSignInNoticeConcurrency was given %d, which is below 1; omit "+
				"the option to keep the default of %d", concurrency, DefaultSignInNoticeConcurrency)
		}

		n.concurrency = concurrency

		return nil
	}
}

// withSignInNoticeTracker counts the notice's work in flight on wg, so a
// test can wait for it.
func withSignInNoticeTracker(wg *sync.WaitGroup) SignInNoticeOption {
	return func(n *signInNotice) error {
		n.track = wg

		return nil
	}
}

// WithSignInMatcher replaces how a sign-in is matched with one of the user's
// other live sign-ins: fn reports whether signedIn, the sign-in just stored,
// came from the same device as known. A sign-in that matches any of them is
// not notified.
//
// Default: the two user agents are equal. A nil function is refused; omit the
// option to keep the default.
func WithSignInMatcher(fn func(signedIn, known session.SignIn) bool) SignInNoticeOption {
	return func(n *signInNotice) error {
		if fn == nil {
			return newConfigError("WithSignInMatcher was given no function; omit the option " +
				"to match equal user agents")
		}

		n.matches = fn

		return nil
	}
}

// WithSeenDevices supplies the consumer's record of devices seen earlier,
// consulted beside the live sign-ins: a sign-in from a device it reports seen
// is not notified.
//
// Default: none, and only the live sign-ins are consulted. A nil or typed-nil
// port is refused; omit the option instead.
func WithSeenDevices(devices SeenDevices) SignInNoticeOption {
	return func(n *signInNotice) error {
		if nilcheck.IsNil(devices) {
			return newConfigError("WithSeenDevices was given no port; omit the option to " +
				"consult only the live sign-ins")
		}

		n.seen = devices

		return nil
	}
}

// WithSignInNoticeRecipient replaces where a notice is sent: fn answers the
// address of the user p, who just signed in. An error sends no notice, and is
// logged without its text.
//
// The principal fn receives carries the user's ID, display name, username and
// kind; it is a copy, not the request's own.
//
// Default: the principal's username, as the second-factor and passkey notices
// use the username as the address by default. A nil function is refused.
func WithSignInNoticeRecipient(fn func(ctx context.Context, principal *identity.Principal) (string, error)) SignInNoticeOption {
	return func(n *signInNotice) error {
		if fn == nil {
			return newConfigError("WithSignInNoticeRecipient was given no function; omit the " +
				"option to send to the username")
		}

		n.recipient = fn

		return nil
	}
}

// WithSignInNoticeMessage replaces the notice's subject and plain-text body.
//
// Default: plain English naming no brand, with the time in UTC and the
// device. A nil function is refused; omit the option to keep the default.
func WithSignInNoticeMessage(fn func(facts SignInNoticeFacts) (subject, body string)) SignInNoticeOption {
	return func(n *signInNotice) error {
		if fn == nil {
			return newConfigError("WithSignInNoticeMessage was given no function; omit the " +
				"option to keep the default text")
		}

		n.message = fn

		return nil
	}
}

// EnableSignInNotice sends a user a notice when they sign in from a device
// none of their other live sign-ins came from. It is off until called.
//
// After a login endpoint stores a sign-in, form, passkey, magic-link and
// federated login alike, the notice lists the user's live sign-ins
// (session.Sessions.ListSignIns) and compares the new one with each of the
// others through the matcher: equal user agents by default, replaced with
// WithSignInMatcher. When none matches and the consumer's seen-devices port
// (WithSeenDevices), if any, does not report the device seen, the user is
// sent a notice. A sign-in still owing a second factor is notified like any
// other, since an unknown pending sign-in is what a user most needs to see.
//
// Nothing is sent:
//   - for a user's first sign-in, with no other live sign-in, whatever the port
//     answers: there is nothing to compare it with;
//   - for a sign-in whose session was never stored;
//   - when the listing, the port or the recipient fails, which is logged
//     without the dependency's text.
//
// The notice carries the time and a coarse device description, the browser
// and platform family (SignInNoticeFacts), never a token, a link secret, a
// session handle, the client address or the raw user agent. It is sent to
// the principal's username by default (WithSignInNoticeRecipient), with
// plain-English text by default (WithSignInNoticeMessage).
//
// All of its work (the listing, the port, the recipient and the send) runs
// after the sign-in's response is decided, off the request path, so it never
// delays the response. It runs on a context the request's end does not
// cancel, bounded by WithSignInNoticeTimeout (DefaultSignInNoticeTimeout by
// default), and a panic in it is recovered and logged. A failure, a timeout
// or a panic is logged without its text and changes nothing about the
// sign-in. At most DefaultSignInNoticeConcurrency notices are in progress at
// once (WithSignInNoticeConcurrency); a sign-in that completes while that many
// are is not notified, and the drop is logged at WARN, sampled, naming no
// user. A dropped notice is never queued, and its sign-in's response is the
// same as a notified one's.
//
// The chain's session manager must record sign-in metadata
// (session.WithSessionMetadata), since the user agents it compares are that
// metadata; the login endpoints supply the client address and user agent the
// chain resolved for every sign-in, which a manager not recording metadata
// discards. New refuses with a configuration error naming this option a
// chain with no session manager, a manager that records no metadata, a nil
// sender and a second call. A sender that waits for delivery is accepted: the
// notice's work runs off the request path, so such a sender holds that work,
// and its goroutine, for a round trip, up to the notice's timeout, and never
// delays a response.
func EnableSignInNotice(sender notify.Sender, opts ...SignInNoticeOption) Option {
	const option = "EnableSignInNotice"

	return func(c *config) error {
		n := &signInNotice{
			sender:    sender,
			matches:   equalUserAgents,
			recipient: usernameRecipient,
			message:   defaultSignInNoticeMessage,
			timeout:   DefaultSignInNoticeTimeout,

			concurrency: DefaultSignInNoticeConcurrency,
		}

		for _, opt := range opts {
			if opt == nil {
				continue
			}
			if err := opt(n); err != nil {
				return err
			}
		}

		n.slots = make(chan struct{}, n.concurrency)

		if err := eachInterceptor(c, func(*signInNotice) error {
			return newConfigError("%s was given twice; one chain has one sign-in notice", option)
		}); err != nil {
			return err
		}

		c.enable(option, func() error {
			if err := requireDep(option, "sender", n.sender); err != nil {
				return err
			}
			if c.sessions == nil {
				return newConfigError("%s needs a session manager: give the chain one with "+
					"WithSessions, or enable a built-in wired to one", option)
			}
			if !c.sessions.RecordsMetadata() {
				return newConfigError("%s compares sign-in metadata, which the chain's session "+
					"manager does not record: build it with session.WithSessionMetadata", option)
			}

			n.sessions = c.sessions

			return nil
		})
		c.wire(func(ch *Chain) {
			n.logger = c.logger
			n.sampler = ch.sampler
			n.now = c.now
		})
		c.register(n, OrderSignInNotice)

		return nil
	}
}

// Intercept lets the request's login, if any, run, then starts the notice's
// work for the sign-in it stored, off the request path.
func (n *signInNotice) Intercept(ex *Exchange, next Next) error {
	stored := &storedSignIn{}
	ex.SetContext(withSignInObserver(ex.Context(), stored))

	err := next(ex)

	if stored.session != nil {
		n.start(ex.Context(), stored.session, stored.principal)
	}

	return err
}

// start runs the notice for s, stored for p, in a goroutine of its own, on a
// context derived from parent that parent's cancellation does not end, ended
// instead by the notice's timeout. The request goes on to own s and p, so the
// goroutine is handed only the few values it needs, copied here, and shares
// no map or slice with them. It recovers a panic, which it logs without its
// value.
//
// The goroutine holds one of the notice's slots, taken here without waiting
// and freed as it ends, whatever ended it. When every slot is taken the
// notice is dropped and logged, and nothing else happens: the sign-in's
// response is the same either way.
func (n *signInNotice) start(parent context.Context, s *session.Session, p *identity.Principal) {
	select {
	case n.slots <- struct{}{}:
	default:
		n.dropped(parent)

		return
	}

	signedIn := noticeSignIn{user: s.UserID, family: s.FamilyID, at: s.CreatedAt}

	var principal *identity.Principal
	if p != nil {
		principal = &identity.Principal{ID: p.ID, Name: p.Name, Username: p.Username, Kind: p.Kind}
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), n.timeout)

	if n.track != nil {
		n.track.Add(1)
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				n.failed(ctx, "the notice's work panicked", errNoticePanicked)
			}

			cancel()
			// Free the slot before Done, so whoever waits on the tracker
			// finds it free.
			<-n.slots

			if n.track != nil {
				n.track.Done()
			}
		}()

		n.notify(ctx, signedIn, principal)
	}()
}

// The sampler key and message of the record a dropped notice leaves.
const (
	signInNoticeDroppedKey = "signin-notice" + sampleKeySeparator + "dropped"
	msgSignInNoticeDropped = "httpsec: a sign-in notice was dropped: too many are in progress"
)

// dropped logs a notice that was not started because every slot was taken,
// sampled through the chain's sampler, naming no user, device or address.
func (n *signInNotice) dropped(ctx context.Context) {
	logger := n.logger
	if logger == nil {
		logger = slog.Default()
	}

	logSampled(ctx, n.sampler, logger, slog.LevelWarn, n.now(), signInNoticeDroppedKey, msgSignInNoticeDropped,
		slog.Int("concurrency", n.concurrency))
}

// errNoticePanicked is what a recovered panic in the notice's work is logged
// as; the panic's value is not, since it may carry anything.
var errNoticePanicked = errors.New("httpsec: the sign-in notice's work panicked")

// noticeSignIn is what the notice's work keeps of the sign-in just stored:
// the user, the sign-in's family, which names it among the user's live
// sign-ins, and when it was stored.
type noticeSignIn struct {
	user   identity.UserID
	family id.ID
	at     time.Time
}

// notify sends the notice for s, the sign-in just stored for p, when it came
// from an unseen device.
func (n *signInNotice) notify(ctx context.Context, s noticeSignIn, p *identity.Principal) {
	list, err := n.sessions.ListSignIns(ctx, s.user, &session.Session{UserID: s.user, FamilyID: s.family})
	if err != nil {
		n.failed(ctx, "the sign-ins could not be listed", err)

		return
	}

	var signedIn session.SignIn

	others := make([]session.SignIn, 0, len(list))
	for _, si := range list {
		if si.Current {
			signedIn = si

			continue
		}

		others = append(others, si)
	}

	if !signedIn.Current || len(others) == 0 {
		// The sign-in is no longer live, or is the user's only one: there is
		// nothing to compare it with.
		return
	}

	for _, known := range others {
		if n.matches(signedIn, known) {
			return
		}
	}

	if n.seen != nil {
		seen, err := n.seen.Seen(ctx, s.user, signedIn.UserAgent)
		if err != nil {
			n.failed(ctx, "the seen-devices port could not answer", err)

			return
		}
		if seen {
			return
		}
	}

	to, err := n.recipient(ctx, p)
	if err != nil {
		n.failed(ctx, "the recipient could not be resolved", err)

		return
	}

	subject, body := n.message(SignInNoticeFacts{At: s.at, Device: deviceDescription(signedIn.UserAgent)})
	if err := n.sender.Send(ctx, notify.Message{To: to, Subject: subject, TextBody: body}); err != nil {
		n.failed(ctx, "the notice could not be sent", err)
	}
}

// failed logs a notice that was not sent, with a fixed reason and the
// error's type, never its text, the user, the device or the address.
func (n *signInNotice) failed(ctx context.Context, reason string, err error) {
	logger := n.logger
	if logger == nil {
		logger = slog.Default()
	}

	logger.LogAttrs(ctx, slog.LevelError, "httpsec: a sign-in notice was not sent",
		diag.Failure(reason, err)...)
}

// equalUserAgents is the default matcher: the same user agent is the same
// device.
func equalUserAgents(signedIn, known session.SignIn) bool {
	return signedIn.UserAgent == known.UserAgent
}

// usernameRecipient is the default recipient: the principal's username.
func usernameRecipient(_ context.Context, p *identity.Principal) (string, error) {
	if p == nil || p.Username == "" {
		return "", errNoUsername
	}

	return p.Username, nil
}

// errNoUsername is why the default recipient finds no address.
var errNoUsername = errors.New("httpsec: the principal has no username to send the notice to")

// noticeTimeLayout is how the default text writes the sign-in's time.
const noticeTimeLayout = "2006-01-02 15:04 MST"

// defaultSignInNoticeMessage is the library's own text: plain English, naming
// no brand.
func defaultSignInNoticeMessage(f SignInNoticeFacts) (string, string) {
	return "New sign-in to your account",
		"Your account was signed in to from a device not used by your other sessions, on " +
			f.At.UTC().Format(noticeTimeLayout) + ".\n\n" +
			"Device: " + f.Device + "\n\n" +
			"If this was you, there is nothing to do. If it was not, change your password and " +
			"sign out your other sessions at once.\n"
}

// deviceDescription names ua's browser and platform family from a fixed
// vocabulary: "Firefox on Linux", the browser alone when the platform is not
// recognised, or unrecognisedDevice. No part of ua is copied into it.
func deviceDescription(ua string) string {
	browser := matchFamily(ua, browserFamilies)
	if browser == "" {
		return unrecognisedDevice
	}

	if platform := matchFamily(ua, platformFamilies); platform != "" {
		return browser + " on " + platform
	}

	return browser
}

// family is one browser or platform family: its name, and the user-agent
// tokens that identify it.
type family struct {
	name   string
	tokens []string
}

// browserFamilies are the browsers a notice names, most specific first: an
// Edge, Opera or Samsung Internet user agent also carries Chrome's token, and
// a Chrome one Safari's.
var browserFamilies = []family{
	{name: "Edge", tokens: []string{"Edg/", "EdgA/", "EdgiOS/"}},
	{name: "Opera", tokens: []string{"OPR/", "OPiOS/", "Opera/"}},
	{name: "Samsung Internet", tokens: []string{"SamsungBrowser/"}},
	{name: "Firefox", tokens: []string{"Firefox/", "FxiOS/"}},
	{name: "Chrome", tokens: []string{"Chrome/", "CriOS/", "Chromium/"}},
	{name: "Safari", tokens: []string{"Version/"}},
}

// platformFamilies are the platforms a notice names, most specific first: an
// iOS user agent also says "Mac OS X", and an Android or ChromeOS one
// "Linux".
var platformFamilies = []family{
	{name: "iOS", tokens: []string{"iPhone", "iPad", "iPod"}},
	{name: "Android", tokens: []string{"Android"}},
	{name: "ChromeOS", tokens: []string{"CrOS"}},
	{name: "Windows", tokens: []string{"Windows"}},
	{name: "macOS", tokens: []string{"Macintosh"}},
	{name: "Linux", tokens: []string{"Linux", "X11"}},
}

// matchFamily is the name of the first of families whose tokens ua holds,
// or "".
func matchFamily(ua string, families []family) string {
	for _, f := range families {
		for _, tok := range f.tokens {
			if strings.Contains(ua, tok) {
				return f.name
			}
		}
	}

	return ""
}

// storedSignIn is where the login tail records the sign-in it stored on a
// request the notice watches.
type storedSignIn struct {
	session   *session.Session
	principal *identity.Principal
}

// signInObserverKey is the context key the notice's record is stored under.
type signInObserverKey struct{}

// withSignInObserver returns ctx carrying rec, which the login tail fills
// when it stores a sign-in (observeSignIn).
func withSignInObserver(ctx context.Context, rec *storedSignIn) context.Context {
	return context.WithValue(ctx, signInObserverKey{}, rec)
}

// observeSignIn records s, stored for p, on the notice's record ctx
// carries, and does nothing on a request no notice watches.
func observeSignIn(ctx context.Context, s *session.Session, p *identity.Principal) {
	if rec, ok := ctx.Value(signInObserverKey{}).(*storedSignIn); ok {
		rec.session, rec.principal = s, p
	}
}
