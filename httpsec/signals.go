package httpsec

//go:generate mockgen -destination=signalbus_mock_test.go -package=httpsec_test -typed github.com/kartaladev/scrty/httpsec SignalBus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/nilcheck"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/session"
)

// Signal names one of the library's own signals on the session-signal stream
// (EnableSessionSignals). The set is closed: a name other than these four fails
// construction. A consumer's own signals have names of their own, under "app."
// (Chain.PublishSignal).
type Signal string

// The library's signals. A stream also always sends the session event, which is
// not a Signal and cannot be turned off.
const (
	// SignalSessionEnded says the sign-in ended, and why. A stream sends it
	// whatever its set says, because the stream cannot continue without it.
	SignalSessionEnded Signal = "session_ended"

	// SignalSessionExpiring says a deadline of the sign-in is within
	// SessionSignals.ExpiryWarning, and which one.
	SignalSessionExpiring Signal = "session_expiring"

	// SignalAssuranceLapsed says the sign-in last authenticated longer ago than
	// SessionSignals.AssuranceWindow.
	SignalAssuranceLapsed Signal = "assurance_lapsed"

	// SignalCredentialChanged says the user's password, a passkey or a second
	// factor changed, naming only the kind.
	SignalCredentialChanged Signal = "credential_changed"
)

// DefaultSessionSignalsPath is where the stream answers when
// SessionSignals.Path names no other.
const DefaultSessionSignalsPath = "/session/signals"

// OrderSessionSignals is the session-signal stream (EnableSessionSignals). It is
// inside every authenticating interceptor and every gate that confines a session,
// so a stream opens only on the identity the chain resolved and only for a sign-in
// that owes nothing, and below OrderSessionTouch and OrderAuthorizer, neither of
// which ever runs for it: the endpoint is terminal.
//
// It is Before(OrderSessionManagement), the slot the chain's slot spacing leaves
// free for a consumer. A consumer interceptor registered there shares it, and
// slot-mates run in the order they were registered. One registered after
// EnableSessionSignals is not reached by a request for the stream's path, whatever
// its method.
const OrderSessionSignals = OrderSessionManagement - 1

// NoMaxAge is the value of SessionSignals.MaxAge that turns the maximum age off.
const NoMaxAge time.Duration = -1

// The refusals the signal stream adds. ErrCrossSiteStream is the one a client is
// answered with. The others are what a consumer's own calls return, or are internal
// to the stream's answer, so none of them maps to a status of its own.
var (
	// ErrSessionSignalsDisabled is what Chain.PublishSignal, Chain.ReportCredentialChange
	// and Chain.CloseSessionSignals return on a chain without EnableSessionSignals.
	ErrSessionSignalsDisabled = errors.New("httpsec: session signals are not enabled")

	// ErrInvalidSignal refuses a consumer's signal whose name or data is outside
	// what a stream can carry, or a credential change of an unknown kind. Nothing
	// was sent. Its text names neither the signal nor its data.
	ErrInvalidSignal = errors.New("httpsec: invalid signal")

	// ErrTooManyStreams is why a stream over a cap was not opened. It never reaches
	// a client as a status: such a request is answered 200 with only a longer
	// reconnection delay, because an EventSource gives up for good on anything else.
	ErrTooManyStreams = errors.New("httpsec: too many signal streams")

	// ErrCrossSiteStream refuses a stream a page on an origin the chain does not
	// trust asked for. It maps to 403, before the stream is registered, so it costs
	// the sign-in no place. It is not ErrCrossSiteRequest, because a page that merely
	// tried is not reported as a CSRF attack.
	ErrCrossSiteStream = errors.New("httpsec: cross-site signal stream refused")

	// ErrSignalsBusy is what a consumer's signal returns when a consumer's bus has
	// fallen so far behind that the signal was dropped. It is also what one returns after
	// CloseSessionSignals, on either bus, because nil would say the signal was sent.
	ErrSignalsBusy = errors.New("httpsec: session signals are busy, and the signal was dropped")
)

// errSignalsMethod refuses any method but GET on the stream's path. It is answered
// 405, with an Allow header the endpoint has set.
var errSignalsMethod = errors.New("httpsec: the signal stream answers only GET")

// errStreamNeedsSignIn refuses a caller the chain authenticated with no sign-in:
// HTTP Basic, an API key, or a token bound to no session. A stream has nothing to
// report without one. It matches authorize.ErrAccessDenied, so it is answered 403:
// the caller is known, and may not take this step.
var errStreamNeedsSignIn = fmt.Errorf("httpsec: the signal stream needs a sign-in: %w", authorize.ErrAccessDenied)

// errReloadContextMissing is a SessionSignals.ReloadContext that returned no
// context, answered as a dependency failure: reads with no tenant must not run.
var errReloadContextMissing = errors.New("httpsec: SessionSignals.ReloadContext returned no context")

// The defaults of SessionSignals, each stated on its field.
const (
	defaultSignalsHeartbeat      = 15 * time.Second
	minSignalsHeartbeat          = 5 * time.Second
	maxSignalsHeartbeat          = 60 * time.Second
	defaultSignalsExpiryWarning  = 2 * time.Minute
	defaultSignalsMaxPerSignIn   = 4
	defaultSignalsMaxPerUser     = 16
	defaultSignalsMaxStreams     = 10_000
	defaultSignalsMaxAge         = time.Hour
	defaultSignalsReconnectDelay = 5 * time.Second
	defaultSignalsBusyDelay      = 30 * time.Second
	minSignalsRetryDelay         = time.Millisecond
	minSignalsReloadTimeout      = 2 * time.Second
	maxSignalsReloadTimeout      = 10 * time.Second
	defaultSignalsBusQueue       = 1024
	maxSignalsBusQueue           = 1 << 20
	defaultSignalsBusTimeout     = 5 * time.Second

	// streamQueueSize is how many credential_changed and app.* signals a stream
	// holds before it drops its own, and streamWakeSize how many wake-ups, so that
	// several coalesce into one reload.
	streamQueueSize = 32
	streamWakeSize  = 1
)

// SessionSignals configures the session-signal stream (EnableSessionSignals).
//
// The zero value of every field means its default, so SessionSignals{} is a working
// configuration and a field is set only to change it. A value that is set is checked
// when the chain is built, and one outside its range is refused with ErrConfig
// naming the field.
type SessionSignals struct {
	// Path is where the stream answers GET.
	//
	// Default: DefaultSessionSignalsPath, "/session/signals". It must start with "/",
	// must not end with one, must hold no "?", "#", "%" or white space, because a request's
	// path is compared decoded and such a path would never be served, and must be a path
	// no other enabled endpoint of the chain answers.
	Path string

	// Signals is the chain's set: what a stream may send. A client can narrow it for
	// its own connection and never widen it. The session event and session_ended are
	// sent whatever it says.
	//
	// Default: SignalSessionEnded and SignalSessionExpiring. A name other than the
	// library's four is refused, and SignalAssuranceLapsed is refused on a chain
	// without EnableReauthentication, whose front end could not re-prove when told to.
	Signals []Signal

	// Heartbeat is how often a stream sends a comment and reads its sign-in and its
	// user, each stream with ±10% of jitter. It is what ends a stream on any number of
	// replicas with no shared bus.
	//
	// Default: 15 seconds. It must be between 5 and 60 seconds.
	Heartbeat time.Duration

	// ExpiryWarning is how long before the earlier of the sign-in's two deadlines
	// session_expiring is sent.
	//
	// Default: 2 minutes. It must not be negative, and setting it without
	// SignalSessionExpiring in the set is refused, because nothing would read it. It must
	// also be shorter than the session manager's idle timeout, and leave at least its touch
	// interval before that timeout, or a user who is working would be warned between two
	// recorded activities.
	ExpiryWarning time.Duration

	// AssuranceWindow is how long after the sign-in last authenticated
	// assurance_lapsed is sent. Set it to the window of the guards the front end must
	// satisfy (Guards.RequireRecentAuthentication, RequireAuthenticationWithin). The
	// chain cannot compare the two, because guards are built apart from it.
	//
	// Default: DefaultRecentAuthenticationWindow, 15 minutes, the guards' default. It
	// must not be negative, and setting it without SignalAssuranceLapsed in the set is
	// refused, because nothing would read it.
	AssuranceWindow time.Duration

	// MaxPerSignIn caps the open streams of one sign-in, on this replica.
	//
	// Default: 4. It must be at least 1 and no more than MaxPerUser.
	MaxPerSignIn int

	// MaxPerUser caps the open streams of one user, on this replica, so with N
	// replicas a user can hold N times this many.
	//
	// Default: 16. It must be at least 1 and no more than MaxStreams.
	MaxPerUser int

	// MaxStreams caps the open streams of this replica.
	//
	// Default: 10 000. It must be at least 1.
	MaxStreams int

	// MaxPerSource caps the open streams of one client address, as the chain resolved
	// it. Behind a proxy with no trusted-proxy setting every client shares one address,
	// which is why it is off unless set.
	//
	// Default: 0, off. It must not be negative, and no more than MaxStreams.
	MaxPerSource int

	// MaxAge is how long a stream stays open before it closes with no event, so that
	// the client reconnects and every admission check runs again, each stream with
	// ±10% of jitter. Admission is judged once, so with no limit a stream can outlive
	// the client's bearer token or certificate, a policy that would now refuse it, and
	// a store outage, for up to the session's absolute lifetime.
	//
	// A stream follows its family, so it goes on through a renewal it took no part in, a
	// thief's stream opened before the victim renewed included. This is what bounds that.
	//
	// Default: 1 hour. It must be at least twice Heartbeat. NoMaxAge turns it off, and
	// gives up all of that. Any other negative value is refused.
	MaxAge time.Duration

	// ReconnectDelay is the retry a stream states when it opens, so a browser
	// reconnects after it when the stream drops, ±30% per stream, so that a replica's
	// clients do not all come back at one moment. Chain.CloseSessionSignals states a retry
	// of its own, between 1 second and 3 times this, and exactly 1 second when that range
	// is empty.
	//
	// Default: 5 seconds. It must be at least 1 millisecond, the smallest retry a stream
	// can state.
	ReconnectDelay time.Duration

	// BusyDelay is the retry a request is answered with, ±30% per refusal, when a cap
	// is reached or a dependency fails at admission (EnableSessionSignals says which).
	//
	// Default: 30 seconds. It must be at least 1 millisecond, the smallest retry a stream
	// can state.
	BusyDelay time.Duration

	// Users reads the stream's user at its first read and at each heartbeat, so a stream ends when its user
	// stops being active. Disabling a user revokes no session, so the session read
	// would not notice.
	//
	// Default: the user loader of the chain's built-in bearer (EnableBearerToken or
	// EnableSessionBearer). A chain with no built-in bearer must set it.
	Users identity.UserLoader

	// ReloadContext makes the context a stream's reads run on, from the context of the
	// request that opened it, and is called once, at admission. A multi-tenant consumer
	// uses it to carry the tenant over. The request's cancellation is removed from what
	// it returns, and it must not carry a transaction or anything else that ends with
	// the request. Copy what it keeps, strings included: on fiber the request's values
	// are reused buffers once the chain has returned. Returning nil is answered as a
	// dependency failure.
	//
	// Build what it returns from context.Background(), and never return its argument: the
	// request's context holds the session and its raw identifier, so returning it keeps
	// them for the stream's life.
	//
	// Default: nil, a context with none of the request's values, so a store that needs
	// a tenant fails at admission, where it can be seen, and reads no other tenant's
	// data.
	ReloadContext func(context.Context) context.Context

	// RetryableError decides whether a failure on the stream's path is one a client should
	// come back from. It is asked only about an error StatusForError maps to a 5xx, returned
	// to the chain on GET at Path, and not about what a client's hang-up or a writer that
	// cannot stream returned. Returning true answers 200 with only a retry, as a dependency
	// failure is, counted in SessionSignalStats.ReloadFailures. Returning false sends the
	// error through the chain's error mapping, as any other request's, and counts nothing:
	// use it for a refusal of your own that maps to a 5xx. Mind what that answer does: a 5xx
	// stops a browser's EventSource for good, and no later request of that page is made.
	//
	// An authenticate.ErrUnavailable from a consumer's authenticator on this path is 401, to keep
	// a refusal from telling an account's existence, so it is not asked about and not retried:
	// an EventSource stops for good on it. A consumer's authenticator that wants a browser to
	// retry through an outage returns an error that maps to a 5xx on this path.
	//
	// A panic in it is recovered and logged without its value, and the failure is retried.
	//
	// Default: nil, every such failure is retried, because a store failure in a consumer's
	// authenticator cannot be told from any other and must not end an EventSource for good.
	RetryableError func(error) bool

	// ReloadTimeout bounds one reload, the session read and the user read sharing it. A
	// reload runs beside the stream, so that a store that hangs stops neither the heartbeat,
	// MaxAge, CloseSessionSignals nor a client leaving, and past this timeout it counts as a
	// failure. A store that ignores its context costs one goroutine per stream until it
	// returns, since a goroutine cannot be stopped from outside, and no further reload of that
	// stream starts until then. The first read runs on the request, which such a store holds
	// until it returns.
	//
	// Default: half of Heartbeat, kept within 2 to 10 seconds. It must not be negative,
	// and must be shorter than Heartbeat.
	ReloadTimeout time.Duration

	// Bus carries signals between replicas. A shared one should authenticate its
	// transport: the chain treats what it delivers as untrusted, and an end message
	// only makes a stream read the store, so a holder of the bus cannot end a stream.
	// It can still wake a user's streams at will, which costs store reads, and label a
	// real end as reuse inside its window. See SignalBus for what else a bus costs.
	//
	// Default: nil, an in-process bus, so with several replicas session_ended still
	// arrives within a heartbeat and half a second, while credential_changed and a
	// consumer's signals reach only the streams on the replica that raised them.
	Bus SignalBus

	// BusQueue is how many signals wait for a consumer's Bus before new ones are
	// dropped and counted.
	//
	// Default: 1024. It is for a consumer's Bus only, and setting it without one is
	// refused. It must be at least 1 and at most 1048576, so that a mistaken value
	// cannot reserve memory the process does not have.
	BusQueue int

	// BusTimeout bounds one Publish to a consumer's Bus.
	//
	// Default: 5 seconds. It is for a consumer's Bus only, and setting it without one
	// is refused. It must not be negative.
	BusTimeout time.Duration
}

// SignalBus is the port signals cross replicas through. There is one subscription
// per replica, not per stream, so an implementation can use one channel.
//
// A signal raised while no consumer's bus is set reaches the streams of the same
// process only (SessionSignals.Bus). A bus may be lossy: what a dropped message costs
// is a heartbeat for session_ended, because the store decides, and the signal itself
// for any other, so a consumer must not rely on one alone.
//
// What a bus costs, and what it is trusted with:
//
//   - A shared bus should authenticate its transport. A holder of it can wake a user's
//     streams at will, which costs store reads, and can label a real end as reuse inside
//     its window. It cannot end a stream, since the store decides.
//   - An envelope still queued when CloseSessionSignals runs can be lost.
//   - A Publish that ignores its context keeps the publisher's goroutine for as long as it
//     hangs, and a goroutine cannot be stopped from outside. The queue then fills, and later
//     signals are dropped and counted.
//   - A chain that is never closed keeps its bus's goroutines, the publisher and the
//     subscription.
type SignalBus interface {
	// Publish hands e to the other replicas and to this one. It is called from one
	// goroutine, under SessionSignals.BusTimeout, on a context with none of the raising
	// request's values. An error is logged, and changes nothing for that request.
	Publish(ctx context.Context, e SignalEnvelope) error

	// Subscribe calls deliver with each envelope until ctx ends, and blocks until then.
	// It is called once per chain, and retried with backoff if it fails, returns early
	// or panics. deliver never blocks, and is safe to call from several goroutines.
	Subscribe(ctx context.Context, deliver func(SignalEnvelope)) error
}

// SignalEnvelope is one signal on the bus. An envelope from a shared bus is untrusted:
// session_ended only wakes the streams it names to read the store, and anything else
// is checked again on receipt.
type SignalEnvelope struct {
	// User is whose streams it reaches, and empty only for an end report that names no
	// user.
	User identity.UserID

	// Family is the sign-in an end report ended, and the nil family for a signal to the
	// whole user.
	Family id.ID

	// Kept is the sign-in a user-wide end report spared, and the nil family when it
	// spared none, or could not say which.
	Kept id.ID

	// Upstream routes a provider's logout of one upstream session. It is the SHA-256 of
	// the issuer, a separator and the upstream session, in hexadecimal, and never the
	// raw value, which identifies a session at the provider. It is empty for anything
	// else.
	Upstream string

	// Name is the signal: one of the library's four, or a consumer's "app." name.
	Name string

	// Reason is why a session_ended was raised, and empty for any other signal.
	Reason string

	// Data is a signal's JSON, and nil for session_ended.
	Data json.RawMessage
}

// EnableSessionSignals serves a text/event-stream at s.Path, telling a front end what
// changes about the signed-in user's own session as it happens. It is off until
// called. Every SessionSignals field says its default and its range, and the zero
// value of each means that default.
//
// GET on the path opens a stream for the sign-in the chain resolved: 200, with
// Cache-Control: no-store, no-transform and X-Accel-Buffering: no. Any other method is
// 405 with Allow: GET, and any other path passes through. The chain's other layers
// apply as on any protected route: security headers, trusted proxies, CORS, CSRF, rate
// limits, authentication and the pending-session gates.
//
// Only a sign-in opens a stream. A request with no credential, or one naming a session
// only in its query string, is ErrAuthenticationRequired (401). A caller authenticated
// with no sign-in, by HTTP Basic, an API key or a token bound to no session, is refused
// with 403. A sign-in owing a second factor, an enrolment, a recovery or a password
// change is refused by its gate, or with the ChallengeError it owes on a chain without
// that gate. A consumer's CookieAuthenticator opens one, once it has called
// Exchange.PublishSession. The first read reads the sign-in and its user, on the
// ReloadContext and under one ReloadTimeout: a sign-in the store does not hold, or a user
// who is not found or not active, is ErrAuthenticationRequired, and a failure of either
// store is a dependency failure.
//
// What a retry could fix is answered 200 with only a retry, within SessionSignals.BusyDelay
// ±30%, and then the response ends, because an EventSource gives up for good on any other
// status and cannot tell one from another. That is a request over a cap, and a dependency
// failure at any point on the stream's path, an authenticator's read of the session store
// or the user store included: anything the chain's error mapping would answer with a 5xx.
// So a consumer's interceptor that refuses this path with an error of its own that
// StatusForError does not know is taken for a failure, and should write its answer itself;
// a rate limit answered that way stays the consumer's. An answer begun before the failure
// is not written over. It takes no place, closes no stream and charges nothing, and only GET
// on the stream's path is answered so, so every other 5xx of the chain stands. A fetch() client
// sees a 200 with no session event. It hides from a dashboard of statuses, so it is logged
// at WARN with sampling, and counted in Chain.SessionSignalStats.
//
// The caps and the default bus are per replica: with N replicas a user can hold N times
// SessionSignals.MaxPerUser streams, and a signal other than session_ended reaches only the
// replica that raised it. A shared SessionSignals.Bus changes the second and not the first.
//
// Register Chain.CloseSessionSignals to shut a server down: with no such call an open stream
// holds http.Server.Shutdown until its deadline, and a consumer's bus keeps its goroutines.
//
// A writer that cannot stream answers 501 (ErrStreamingUnsupported). Behind a consumer's
// middleware that wraps the http.ResponseWriter, that takes an Unwrap method on the
// wrapper. A consumer's interceptor that already wrote the response gets the chain's
// error mapping with ErrStreamingStarted, a 500.
//
// The stream records no activity on its sign-in, so a tab left open does not keep an
// idle sign-in alive. See RecordsSessionActivity.
//
// The session manager is the chain's own: the one WithSessions sets, or the first an
// enabled built-in was wired to. New adds its observer to that manager last of all
// (session.Sessions.AddEndObserver), beside any the consumer gave it, so a failed build
// leaves nothing on the manager. A chain with no manager, a second call, a chain clock
// (WithClock) that cannot wait (clock.Timed), and any field outside its range are
// refused with ErrConfig naming what is at fault.
func EnableSessionSignals(s SessionSignals) Option {
	const option = "EnableSessionSignals"

	return func(c *config) error {
		if err := eachInterceptor(c, func(*sessionSignals) error {
			return newConfigError("%s was given twice; one chain has one signal stream", option)
		}); err != nil {
			return err
		}

		e := &sessionSignals{cfg: s}

		c.enable(option, func() error { return e.settle(c, option) })
		c.register(e, OrderSessionSignals)
		c.register(sessionSignalsRetry{e: e}, orderSessionSignalsRetry)
		c.wire(func(ch *Chain) { e.wire(c, ch) })

		return nil
	}
}

// RecordsSessionActivity reports whether a request records activity on its session. It
// is false for the signal stream's path, and true otherwise, also on an exchange run
// through no chain.
//
// The chain's own session-touch step needs no answer from it: the stream's endpoint is
// terminal and sits below OrderSessionTouch, so that step never runs for it. It is for a
// consumer's interceptor that records activity itself, or moves a session's deadlines,
// and runs before the stream: a stream held open must not keep an idle sign-in alive.
func RecordsSessionActivity(ex *Exchange) bool {
	ph := ex.perRequest

	return ph == nil || ph.signalsPath == "" || ex.Request.Path() != ph.signalsPath
}

// sessionSignals is the stream's endpoint, and what the rest of the feature hangs from.
type sessionSignals struct {
	// cfg is what the consumer gave, with every default filled by settle.
	cfg SessionSignals

	// set is the chain's set of library signals, from cfg.Signals.
	set map[Signal]bool

	sessions *session.Sessions
	clock    clock.Timed

	registry *signalRegistry
	hub      *signalHub

	// reloads is what this replica's streams counted of their reloads.
	reloads streamReloadCounts

	// cors is the chain's CORS layer, and nil without one. log and sampler are the
	// chain's. All three are settled last, by wire.
	cors    *corsLayer
	log     *slog.Logger
	sampler *logsample.Sampler
}

// settle fills the defaults and refuses what cannot work, once every option has
// applied, so the session manager, re-authentication, the bearers and the clock are
// known. It leaves nothing on the session manager: wire does that.
func (e *sessionSignals) settle(c *config, option string) error {
	if c.sessions == nil {
		return newConfigError("%s needs a session manager: give the chain one with "+
			"WithSessions, or enable a built-in wired to one", option)
	}

	e.sessions = c.sessions

	timed, ok := c.clock.(clock.Timed)
	if !ok {
		return newConfigError("%s needs a chain clock that can wait (clock.Timed), because a "+
			"controlled Now with real waits fires a stream's timers at the wrong moments: "+
			"give WithClock one with an After method", option)
	}

	e.clock = timed

	if err := e.settlePath(c, option); err != nil {
		return err
	}

	if err := e.settleSignals(c, option); err != nil {
		return err
	}

	if err := e.settleTimes(option); err != nil {
		return err
	}

	if err := e.settleCaps(option); err != nil {
		return err
	}

	if err := e.settleUsers(c, option); err != nil {
		return err
	}

	if err := e.settleBus(option); err != nil {
		return err
	}

	e.registry = newSignalRegistry(signalLimits{
		perSignIn: e.cfg.MaxPerSignIn,
		perUser:   e.cfg.MaxPerUser,
		total:     e.cfg.MaxStreams,
		perSource: e.cfg.MaxPerSource,
	})
	e.hub = &signalHub{
		registry: e.registry,
		bus:      e.cfg.Bus,
		queue:    e.cfg.BusQueue,
		timeout:  e.cfg.BusTimeout,
		clock:    e.clock,
	}

	return nil
}

// settlePath refuses a path that could never be served, or that another endpoint of
// the chain answers.
func (e *sessionSignals) settlePath(c *config, option string) error {
	if e.cfg.Path == "" {
		e.cfg.Path = DefaultSessionSignalsPath
	}

	path := e.cfg.Path
	if path[0] != '/' || strings.HasSuffix(path, "/") || strings.ContainsAny(path, "?#% \t\r\n") {
		return newConfigError("%s was given SessionSignals.Path %q: a path starts with \"/\", does "+
			"not end with one, and holds no \"?\", \"#\", \"%%\" or white space, or it would never be served",
			option, path)
	}

	own := claimedPath{name: "the signal stream", path: path}

	taken := claimedPaths(c, c.mfaOf(), c.formLogin())

	_ = eachInterceptor(c, func(r *reauthInterceptor) error {
		taken = append(taken, claimedPath{name: "the re-authentication prefix", path: r.prefix, under: true})

		return nil
	})

	_ = eachInterceptor(c, func(m *sessionManagement) error {
		taken = append(taken, claimedPath{name: "the session management prefix", path: m.prefix, under: true})

		return nil
	})

	for _, other := range taken {
		if collides(own, other) {
			return newConfigError("%s was given SessionSignals.Path %q, which %s %q already answers: "+
				"whichever endpoint matched first would swallow the other", option, path, other.name, other.path)
		}
	}

	return nil
}

// settleSignals builds the chain's set.
func (e *sessionSignals) settleSignals(c *config, option string) error {
	names := e.cfg.Signals
	if len(names) == 0 {
		names = []Signal{SignalSessionEnded, SignalSessionExpiring}
	}

	e.set = make(map[Signal]bool, len(names))

	for _, name := range names {
		switch name {
		case SignalSessionEnded, SignalSessionExpiring, SignalAssuranceLapsed, SignalCredentialChanged:
			e.set[name] = true
		default:
			return newConfigError("%s was given %q in SessionSignals.Signals, which is not one of the "+
				"library's four signals", option, string(name))
		}
	}

	if e.set[SignalAssuranceLapsed] && !c.hasReauthentication() {
		return newConfigError("%s has %s in SessionSignals.Signals on a chain without "+
			"EnableReauthentication: the front end would be told to re-prove, with no way to do it",
			option, SignalAssuranceLapsed)
	}

	e.cfg.Signals = names

	return nil
}

// settleTimes fills the durations and refuses one outside its range. Heartbeat comes
// first, because MaxAge and ReloadTimeout are judged against it.
func (e *sessionSignals) settleTimes(option string) error {
	cfg := &e.cfg

	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = defaultSignalsHeartbeat
	}

	if cfg.Heartbeat < minSignalsHeartbeat || cfg.Heartbeat > maxSignalsHeartbeat {
		return newConfigError("%s was given SessionSignals.Heartbeat %s, which must be between %s and %s",
			option, cfg.Heartbeat, minSignalsHeartbeat, maxSignalsHeartbeat)
	}

	if err := e.settleExpiryWarning(option); err != nil {
		return err
	}

	if cfg.AssuranceWindow < 0 {
		return newConfigError("%s was given SessionSignals.AssuranceWindow %s, which must be above zero",
			option, cfg.AssuranceWindow)
	}

	if cfg.AssuranceWindow != 0 && !e.set[SignalAssuranceLapsed] {
		return newConfigError("%s was given SessionSignals.AssuranceWindow with no %s in "+
			"SessionSignals.Signals, so nothing would read it", option, SignalAssuranceLapsed)
	}

	if cfg.AssuranceWindow == 0 {
		cfg.AssuranceWindow = DefaultRecentAuthenticationWindow
	}

	if cfg.MaxAge == 0 {
		cfg.MaxAge = defaultSignalsMaxAge
	}

	if cfg.MaxAge != NoMaxAge && cfg.MaxAge < 2*cfg.Heartbeat {
		return newConfigError("%s was given SessionSignals.MaxAge %s, which must be at least twice the "+
			"heartbeat (%s), or NoMaxAge to turn it off", option, cfg.MaxAge, cfg.Heartbeat)
	}

	if cfg.ReconnectDelay == 0 {
		cfg.ReconnectDelay = defaultSignalsReconnectDelay
	}

	if cfg.ReconnectDelay < minSignalsRetryDelay {
		return newConfigError("%s was given SessionSignals.ReconnectDelay %s, which must be at least %s",
			option, cfg.ReconnectDelay, minSignalsRetryDelay)
	}

	if cfg.BusyDelay == 0 {
		cfg.BusyDelay = defaultSignalsBusyDelay
	}

	if cfg.BusyDelay < minSignalsRetryDelay {
		return newConfigError("%s was given SessionSignals.BusyDelay %s, which must be at least %s",
			option, cfg.BusyDelay, minSignalsRetryDelay)
	}

	if cfg.ReloadTimeout == 0 {
		cfg.ReloadTimeout = min(max(cfg.Heartbeat/2, minSignalsReloadTimeout), maxSignalsReloadTimeout)
	}

	if cfg.ReloadTimeout < 0 || cfg.ReloadTimeout >= cfg.Heartbeat {
		return newConfigError("%s was given SessionSignals.ReloadTimeout %s, which must be above zero and "+
			"shorter than the heartbeat (%s)", option, cfg.ReloadTimeout, cfg.Heartbeat)
	}

	return nil
}

// settleExpiryWarning fills the warning window and judges it against the session
// manager. A window set without its signal is refused, because nothing would read it. The
// two comparisons apply only when the signal is in the set, because refusing the default
// without it would make a chain with a short idle timeout set a field it does not use.
func (e *sessionSignals) settleExpiryWarning(option string) error {
	cfg := &e.cfg

	if cfg.ExpiryWarning < 0 {
		return newConfigError("%s was given SessionSignals.ExpiryWarning %s, which must be above zero",
			option, cfg.ExpiryWarning)
	}

	if cfg.ExpiryWarning != 0 && !e.set[SignalSessionExpiring] {
		return newConfigError("%s was given SessionSignals.ExpiryWarning with no %s in "+
			"SessionSignals.Signals, so nothing would read it", option, SignalSessionExpiring)
	}

	if cfg.ExpiryWarning == 0 {
		cfg.ExpiryWarning = defaultSignalsExpiryWarning
	}

	if !e.set[SignalSessionExpiring] {
		return nil
	}

	idle := e.sessions.IdleTimeout()
	if cfg.ExpiryWarning >= idle {
		return newConfigError("%s has SessionSignals.ExpiryWarning %s, which must be shorter than the "+
			"session manager's idle timeout (%s)", option, cfg.ExpiryWarning, idle)
	}

	if touch := e.sessions.TouchInterval(); cfg.ExpiryWarning > idle-touch {
		return newConfigError("%s has SessionSignals.ExpiryWarning %s, which must leave the session "+
			"manager's touch interval (%s) before its idle timeout (%s): a user who is working would "+
			"be warned between two recorded activities", option, cfg.ExpiryWarning, touch, idle)
	}

	return nil
}

// settleCaps fills the caps and refuses a combination where one could never be reached.
func (e *sessionSignals) settleCaps(option string) error {
	cfg := &e.cfg

	if cfg.MaxPerSignIn == 0 {
		cfg.MaxPerSignIn = defaultSignalsMaxPerSignIn
	}

	if cfg.MaxPerUser == 0 {
		cfg.MaxPerUser = defaultSignalsMaxPerUser
	}

	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = defaultSignalsMaxStreams
	}

	switch {
	case cfg.MaxPerSignIn < 1:
		return newConfigError("%s was given SessionSignals.MaxPerSignIn %d, which must be at least 1",
			option, cfg.MaxPerSignIn)
	case cfg.MaxPerUser < 1:
		return newConfigError("%s was given SessionSignals.MaxPerUser %d, which must be at least 1",
			option, cfg.MaxPerUser)
	case cfg.MaxStreams < 1:
		return newConfigError("%s was given SessionSignals.MaxStreams %d, which must be at least 1",
			option, cfg.MaxStreams)
	case cfg.MaxPerSource < 0:
		return newConfigError("%s was given SessionSignals.MaxPerSource %d, which must not be negative",
			option, cfg.MaxPerSource)
	case cfg.MaxPerSignIn > cfg.MaxPerUser:
		return newConfigError("%s has SessionSignals.MaxPerSignIn %d above SessionSignals.MaxPerUser %d",
			option, cfg.MaxPerSignIn, cfg.MaxPerUser)
	case cfg.MaxPerUser > cfg.MaxStreams:
		return newConfigError("%s has SessionSignals.MaxPerUser %d above SessionSignals.MaxStreams %d",
			option, cfg.MaxPerUser, cfg.MaxStreams)
	case cfg.MaxPerSource > cfg.MaxStreams:
		return newConfigError("%s has SessionSignals.MaxPerSource %d above SessionSignals.MaxStreams %d",
			option, cfg.MaxPerSource, cfg.MaxStreams)
	}

	return nil
}

// settleUsers settles the loader a stream reads its user through.
func (e *sessionSignals) settleUsers(c *config, option string) error {
	if e.cfg.Users != nil {
		return requireDep(option, "SessionSignals.Users that is not a nil pointer", e.cfg.Users)
	}

	e.cfg.Users = bearerUsers(c)
	if nilcheck.IsNil(e.cfg.Users) {
		return newConfigError("%s needs SessionSignals.Users on a chain with no built-in bearer: "+
			"a stream could not tell that its user was disabled", option)
	}

	return nil
}

// bearerUsers is the user loader of the chain's built-in bearer, whichever mode is
// enabled, and nil when neither is.
func bearerUsers(c *config) identity.UserLoader {
	var users identity.UserLoader

	_ = eachInterceptor(c, func(b *sessionBearer) error {
		users = b.users

		return nil
	})
	_ = eachInterceptor(c, func(b *bearerToken) error {
		users = b.users

		return nil
	})

	return users
}

// settleBus fills the settings of a consumer's bus, and refuses them without one: as
// with every option, a setting takes effect or is refused.
func (e *sessionSignals) settleBus(option string) error {
	cfg := &e.cfg

	switch {
	case cfg.BusQueue < 0:
		return newConfigError("%s was given SessionSignals.BusQueue %d, which must be at least 1",
			option, cfg.BusQueue)
	case cfg.BusQueue > maxSignalsBusQueue:
		return newConfigError("%s was given SessionSignals.BusQueue %d, which must be at most %d",
			option, cfg.BusQueue, maxSignalsBusQueue)
	case cfg.BusTimeout < 0:
		return newConfigError("%s was given SessionSignals.BusTimeout %s, which must be above zero",
			option, cfg.BusTimeout)
	}

	if cfg.Bus == nil {
		if cfg.BusQueue != 0 || cfg.BusTimeout != 0 {
			return newConfigError("%s was given SessionSignals.BusQueue or SessionSignals.BusTimeout with "+
				"no SessionSignals.Bus, and the in-process bus has neither a queue nor a timeout", option)
		}

		return nil
	}

	if err := requireDep(option, "SessionSignals.Bus that is not a nil pointer", cfg.Bus); err != nil {
		return err
	}

	if cfg.BusQueue == 0 {
		cfg.BusQueue = defaultSignalsBusQueue
	}

	if cfg.BusTimeout == 0 {
		cfg.BusTimeout = defaultSignalsBusTimeout
	}

	return nil
}

// wire is the chain's last step for the stream. Nothing after it can fail, which is
// why the hub joins the session manager here, so a failed build leaves no observer on a
// manager the consumer goes on using.
func (e *sessionSignals) wire(c *config, ch *Chain) {
	e.log = ch.logger
	e.sampler = ch.sampler
	e.hub.log = ch.logger
	e.hub.sampler = ch.sampler

	_ = eachInterceptor(c, func(l *corsLayer) error {
		e.cors = l

		return nil
	})

	ch.perRequest.signalsPath = e.cfg.Path
	ch.perRequest.signals = e

	// It refuses only a nil observer, and the hub is not one.
	_ = e.sessions.AddEndObserver(e.hub)
}

// signalsEndpoint is the chain's stream endpoint, and nil on a chain without one.
func (c *Chain) signalsEndpoint() *sessionSignals {
	for _, r := range c.registrations {
		if e, ok := r.interceptor.(*sessionSignals); ok {
			return e
		}
	}

	return nil
}

// The reasons a session_ended names on the wire.
const (
	reasonLogout         = "logout"
	reasonEnded          = "ended"
	reasonReuse          = "reuse"
	reasonAllEnded       = "all_ended"
	reasonProviderLogout = "provider_logout"
	reasonExpired        = "expired"
)

// endReason maps an explicit end to the reason session_ended names. session knows only
// the cause, and the wire reason is the stream's. A cause this table has not heard of
// names no one's fault: "ended" is also what a stream says with no report at all.
func endReason(cause session.EndCause) string {
	switch cause {
	case session.EndLogout, session.EndDeleted:
		return reasonLogout
	case session.EndReuse:
		return reasonReuse
	case session.EndUserSessions, session.EndUserSessionsExcept, session.EndOtherSignIns:
		return reasonAllEnded
	case session.EndUserExternalIssuer, session.EndExternalSession:
		return reasonProviderLogout
	case session.EndByHandle, session.EndFamilyRevoked:
		return reasonEnded
	default:
		return reasonEnded
	}
}

// upstreamDigestSeparator keeps an issuer and an upstream session from running into
// each other. A digest keeps the raw session out of a broker's logs and replays, which
// is all it is for: an unkeyed hash does not resist guessing, and need not.
const upstreamDigestSeparator = "\x00"

// upstreamDigest is what routes a provider's logout of one upstream session: the
// hexadecimal SHA-256 of issuer, a separator and session. It is "" when there is no
// upstream session.
func upstreamDigest(issuer, upstream string) string {
	if upstream == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(issuer + upstreamDigestSeparator + upstream))

	return hex.EncodeToString(sum[:])
}

// envelopeForEnd builds what an end report raises, and false for a report naming no
// one, which no stream could be woken for: the heartbeat ends those streams instead. A
// nil KeptFamily stays nil, meaning nothing was spared.
func envelopeForEnd(r session.EndReport) (SignalEnvelope, bool) {
	upstream := upstreamDigest(r.ExternalIssuer, r.ExternalSessionID)
	if r.User == "" && r.Family.IsZero() && upstream == "" {
		return SignalEnvelope{}, false
	}

	return SignalEnvelope{
		User:     r.User,
		Family:   r.Family,
		Kept:     r.KeptFamily,
		Upstream: upstream,
		Name:     string(SignalSessionEnded),
		Reason:   endReason(r.Cause),
	}, true
}

// A stream as the registry holds it, and the shapes that reach it.
//
// endNotice is the reason the latest end report named, with when this replica received
// it. It says why, if the store then says gone within two heartbeats of at, so a report
// whose end did not happen cannot name a later real end. The wake channel carries
// nothing, so it has its own field.
type endNotice struct {
	reason string
	at     time.Time
}

// queuedSignal is one credential_changed or app.* signal on a stream's queue.
type queuedSignal struct {
	name string
	data json.RawMessage
}

// signalStream is one open stream as the registry and the stream's own goroutine share
// it. Everything in it was copied from the exchange before Stream was called. It holds
// no session identifier and no credential.
type signalStream struct {
	user   identity.UserID
	family id.ID

	// upstream is upstreamDigest of the sign-in's provider session, "" for none. source
	// is the client address MaxPerSource counts, as the chain resolved it. wanted is
	// what the client's narrowing left.
	upstream string
	source   string
	wanted   signalFilter

	// queue holds what the publisher offered with a non-blocking send. A full queue
	// drops the signal for this stream only.
	queue chan queuedSignal

	// wake is filled with a non-blocking send to make the stream reload at once, and
	// several coalesce into one. noteEnd sets notice or reuse first, so the reload can read
	// them. reuse is kept apart, so that a later report cannot overwrite it: within its
	// window it outranks whatever else arrived, which the stream's loop decides. notes counts
	// the reports that kept a reason, which is how the loop knows one has not been answered
	// (streamLoop.holding). It is added to before the wake is sent, so a read that starts on
	// the wake counts the report.
	wake   chan struct{}
	notice atomic.Pointer[endNotice]
	reuse  atomic.Pointer[endNotice]
	notes  atomic.Uint64

	// closing is closed once by the registry when CloseSessionSignals ends the stream.
	closing chan struct{}
}

// newSignalStream builds a stream with its queue and wake channel, not yet registered.
func newSignalStream(user identity.UserID, family id.ID, upstream, source string, wanted signalFilter) *signalStream {
	return &signalStream{
		user:     user,
		family:   family,
		upstream: upstream,
		source:   source,
		wanted:   wanted,
		queue:    make(chan queuedSignal, streamQueueSize),
		wake:     make(chan struct{}, streamWakeSize),
		closing:  make(chan struct{}),
	}
}

// noteEnd keeps what an end report said, reuse apart from every other reason, and then wakes
// the stream without blocking. A report with no reason keeps nothing, and still wakes, and holds
// nothing on the queue: every end the session manager reports has a reason, so only a bus's
// sender sends one without.
//
// A notice is counted before the wake is sent, so a read that starts on the wake sees the notice
// it was woken for. Counted after, the read could start and answer, leaving the notice unanswered.
func (s *signalStream) noteEnd(n endNotice) {
	switch n.reason {
	case "":
		// An unknown reason says nothing, so it must not erase one that was kept.
	case reasonReuse:
		s.reuse.Store(&n)
		s.notes.Add(1)
	default:
		s.notice.Store(&n)
		s.notes.Add(1)
	}

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// offer puts sig on the stream's queue, and reports false when it was dropped because the
// queue is full. It never blocks, and a drop costs only this stream the signal.
func (s *signalStream) offer(sig queuedSignal) bool {
	select {
	case s.queue <- sig:
		return true
	default:
		return false
	}
}
