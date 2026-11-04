package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/lifecycle"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token"
)

const (
	// logoutEvent is the one member a logout token's events claim holds (Back-Channel Logout §2.4).
	logoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	claimEvents = "events"

	// logoutTokenLifetime is how long a logout token lasts, the longest oidc-provider-logout allows.
	// Keys with a shorter usable window cut it to theirs.
	logoutTokenLifetime = 2 * time.Minute

	logoutTokenParam = "logout_token" //nolint:gosec // G101: a form parameter's name, not a credential

	defaultLogoutWorkers = 8
	defaultLogoutQueue   = 1024
	defaultLogoutTimeout = 5 * time.Second
)

// The fixed words a failed delivery is logged and reported under.
const (
	failureClient    = "client"     // the registry could not say who the client is
	failureSign      = "sign"       // the keys could not sign the token
	failurePost      = "post"       // the default delivery got no answer
	failureStatus    = "status"     // the default delivery got an answer that is no success
	failureDelivery  = "delivery"   // a consumer's delivery answered an error
	failureTimeout   = "timeout"    // the bound on one delivery ended it
	failurePanic     = "panic"      // a delivery panicked
	failureGoexit    = "goexit"     // a delivery ended its goroutine
	failureBusy      = "busy"       // calls left behind take every place a new one could run in
	failureQueueFull = "queue_full" // nothing could take it, and the queue had no room
	failureShutdown  = "shutdown"   // Shutdown came first
)

// logoutFailure is one client not told, as the seam for a failed delivery is told of it.
type logoutFailure struct {
	ClientID     string
	User         identity.UserID
	SignInFamily id.ID
	// Reason is one of the failure words.
	Reason string
	// Err is what failed, when something answered, and its text is never logged.
	Err error
	// PanicType is the Go type of what a delivery panicked with.
	PanicType string
}

func failureOf(c ClientToNotify, reason string, err error) *logoutFailure {
	return &logoutFailure{ClientID: c.ClientID, User: c.User, SignInFamily: c.SignInFamily, Reason: reason, Err: err}
}

// LogoutDelivery hands one logout token to a client. WithLogoutDelivery supplies one; with none, the
// provider posts the token to uri as a form, through its outbound client (WithLogoutOutbound).
//
// Deliver runs on the provider's pool, one call per ended sign-in per client, on a context holding the
// caller's values and not its cancellation, and ending at the delivery's bound (5 seconds by default,
// WithLogoutDeliveryTimeout). Its error is logged and reported as a failed delivery, with its type and
// no text, and undoes nothing. A consumer wanting retries returns once the token is on its own queue.
type LogoutDelivery interface {
	Deliver(ctx context.Context, uri, logoutToken string) error
}

// LogoutDeliveryFunc lets a function serve as a LogoutDelivery.
type LogoutDeliveryFunc func(ctx context.Context, uri, logoutToken string) error

// Deliver calls f.
func (f LogoutDeliveryFunc) Deliver(ctx context.Context, uri, logoutToken string) error {
	return f(ctx, uri, logoutToken)
}

// mintLogoutToken signs what c's client is told, through the issuers ID tokens go through, so that the
// algorithm is the client's and sid is the same family text as the ID tokens from that sign-in.
func (p *Provider) mintLogoutToken(ctx context.Context, c ClientToNotify, rc *RegisteredClient) (string, error) {
	lifetime := logoutTokenLifetime
	if p.limits.capped {
		lifetime = min(lifetime, p.limits.window.Truncate(time.Second))
	}

	return p.issue(ctx, rc, token.Issue{
		Type:     token.TypeLogoutToken,
		Subject:  string(c.User),
		Audience: []string{rc.ID},
		Lifetime: lifetime,
		Claims: map[string]any{
			claimSID:    c.SignInFamily.String(),
			claimEvents: map[string]any{logoutEvent: map[string]any{}},
		},
	})
}

// deliverLogout tells one client, reading it as it stands now. A client deleted since, or one that
// registered no URI, has no one to tell, so that is no failure.
func (p *Provider) deliverLogout(ctx context.Context, c ClientToNotify) *logoutFailure {
	rc, err := p.client(ctx, c.ClientID)
	switch {
	case errors.Is(err, ErrClientNotFound):
		return nil
	case err != nil:
		return failureOf(c, failureClient, err)
	case rc.BackChannelLogoutURI == "":
		return nil
	}

	raw, err := p.mintLogoutToken(ctx, c, rc)
	if err != nil {
		return failureOf(c, failureSign, err)
	}
	if err := p.logoutDelivery.Deliver(ctx, rc.BackChannelLogoutURI, raw); err != nil {
		return failureOf(c, deliveryReason(err), err)
	}

	return nil
}

// deliveryReason tells the default delivery's two failures from a consumer's.
func deliveryReason(err error) string {
	var status *logoutStatusError
	switch {
	case errors.As(err, &status):
		return failureStatus
	case errors.Is(err, errLogoutPost):
		return failurePost
	default:
		return failureDelivery
	}
}

// reportLogoutFailure logs a failed delivery with fixed text and no value of its cause, tells the test seam,
// and reports it as a security event (reportLogoutFailed). It undoes nothing.
func (p *Provider) reportLogoutFailure(ctx context.Context, f logoutFailure) {
	attrs := []slog.Attr{slog.String("client_id", f.ClientID)}
	if f.Err != nil {
		attrs = append(attrs, diag.Failure(f.Reason, f.Err)...)
	} else {
		attrs = append(attrs, slog.String("reason", f.Reason))
	}
	if f.PanicType != "" {
		attrs = append(attrs, slog.String("value_type", f.PanicType))
	}
	var status *logoutStatusError
	if errors.As(f.Err, &status) {
		attrs = append(attrs, slog.Int("status", status.status))
	}
	p.cfg.logger.LogAttrs(ctx, slog.LevelError, "oidcprovider: a logout token was not delivered", attrs...)

	if p.cfg.logoutFailed != nil {
		p.cfg.logoutFailed(ctx, f)
	}
	p.reportLogoutFailed(ctx, f)
}

// logCutOffLogout notes a delivery Shutdown ended part way, which is no failure, so it is not reported.
func (p *Provider) logCutOffLogout(ctx context.Context, clientID string) {
	p.cfg.logger.LogAttrs(ctx, slog.LevelInfo, "oidcprovider: shutdown cut off a logout token's delivery",
		slog.String("client_id", clientID))
}

// logLateLogoutFailure notes how a delivery ended after its bound had already reported it failed.
func (p *Provider) logLateLogoutFailure(ctx context.Context, f *logoutFailure) {
	p.cfg.logger.LogAttrs(ctx, slog.LevelError, "oidcprovider: a logout token's delivery ended its goroutine after its bound",
		slog.String("client_id", f.ClientID), slog.String("reason", f.Reason), slog.String("value_type", f.PanicType))
}

// outboundLogoutDelivery is the default: one form POST through a confined client.
type outboundLogoutDelivery struct {
	out *outbound.Client
}

// Deliver implements LogoutDelivery. 200 and 204 are success (Back-Channel Logout §2.8).
func (d outboundLogoutDelivery) Deliver(ctx context.Context, uri, logoutToken string) error {
	res, err := d.out.PostForm(ctx, uri, url.Values{logoutTokenParam: {logoutToken}}, nil)
	if err != nil {
		return diag.Wrap(err, logoutPostText, errLogoutPost)
	}
	if res.Status != http.StatusOK && res.Status != http.StatusNoContent {
		return &logoutStatusError{status: res.Status}
	}

	return nil
}

// logoutPostText is what a logout token getting no answer says, as a transport's error names its target.
const logoutPostText = "oidcprovider: post the logout token"

// errLogoutPost says a logout token got no answer.
var errLogoutPost = errors.New(logoutPostText)

// logoutStatusError is an answer that is no success.
type logoutStatusError struct {
	status int
}

func (e *logoutStatusError) Error() string {
	return "oidcprovider: the relying party answered a logout token with " + strconv.Itoa(e.status)
}

// buildLogoutDelivery returns what tells a client: the consumer's delivery, or a POST through the client
// that WithOutbound gave, or through a client of its own that follows no redirect. A client built
// elsewhere cannot be changed from here, which is the limit WithOutbound states.
func (c *config) buildLogoutDelivery() (LogoutDelivery, error) {
	switch {
	case c.logoutDeliverySet:
		return c.logoutDelivery, nil
	case c.outboundSet && !c.logoutOutboundSet:
		return outboundLogoutDelivery{out: c.outbound}, nil
	}

	// Later options win, so the cap goes last, and what a consumer gives cannot bring redirects back.
	opts := append([]outbound.Option{outbound.WithHTTPClient(&http.Client{Transport: newLogoutTransport()})}, c.logoutOutbound...)
	out, err := outbound.New(append(opts, outbound.WithMaxRedirects(0))...)
	if err != nil {
		return nil, fmt.Errorf("%w: WithLogoutOutbound: %w", ErrConfig, err)
	}

	return outboundLogoutDelivery{out: out}, nil
}

// newLogoutTransport keeps no connection: a logout token is rare, and a kept connection is goroutines
// outliving Shutdown.
func newLogoutTransport() *http.Transport {
	return &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}
}

// logoutJob is one client to tell, and the detached context it travels with.
type logoutJob struct {
	client ClientToNotify
	ctx    context.Context //nolint:containedctx // the delivery outlives the call that queued it
}

// logoutPool runs deliveries on a bounded number of workers, with a bounded queue.
//
// Workers come as they are needed and leave when the queue is empty, so a provider that nothing has
// ended a sign-in for runs no goroutine, and one that is never shut down holds none once its deliveries
// are over. No channel carries the queue, so there is none to close under a late enqueue.
//
// Each delivery runs on a goroutine of its own, which a worker waits for no longer than the bound. So
// nothing a consumer's code does, a panic and a call that never returns included, can take a worker or
// keep it, and a replaced goroutine is what every delivery has anyway. A call left behind holds its
// goroutine until it returns, as Go has no way to stop one, so the calls are counted, and at twice the
// workers a delivery fails at once rather than start another.
type logoutPool struct {
	deliver func(context.Context, ClientToNotify) *logoutFailure
	report  func(context.Context, logoutFailure)
	cutOff  func(context.Context, string)
	late    func(context.Context, *logoutFailure)

	workers, capacity int
	timeout           time.Duration

	// stopped ends with Shutdown's patience, and cuts off what is running.
	stopped context.Context //nolint:containedctx // what Shutdown ends, read by each delivery's context
	stop    context.CancelFunc

	// drained closes once Shutdown has been asked and nothing is left running.
	drained chan struct{}

	// mu guards everything below, and is never held across a call out. A delivery either lands in the
	// queue before closed is set, and the drain delivers it, or it sees closed and is reported.
	mu       sync.Mutex
	queue    []logoutJob
	running  int
	calls    int
	reports  int
	started  bool
	closed   bool
	finished bool
}

func newLogoutPool(cfg *config, p *Provider) *logoutPool {
	stopped, stop := context.WithCancel(context.Background())

	return &logoutPool{
		deliver:  p.deliverLogout,
		report:   p.reportLogoutFailure,
		cutOff:   p.logCutOffLogout,
		late:     p.logLateLogoutFailure,
		workers:  cfg.logoutWorkers,
		capacity: cfg.logoutQueue,
		timeout:  cfg.logoutTimeout,
		stopped:  stopped,
		stop:     stop,
		drained:  make(chan struct{}),
	}
}

// enqueue never waits. A full queue, or one that Shutdown has closed, drops and reports, and the report
// runs with no lock held.
func (q *logoutPool) enqueue(ctx context.Context, c ClientToNotify) {
	job := logoutJob{client: c, ctx: context.WithoutCancel(ctx)}
	if reason := q.accept(job); reason != "" { //nolint:contextcheck // a worker's context is the job's
		q.report(job.ctx, *failureOf(c, reason, nil)) //nolint:contextcheck // the job's context is ctx, detached
	}
}

func (q *logoutPool) accept(job logoutJob) (refused string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	switch {
	case q.closed:
		return failureShutdown
	case len(q.queue) >= q.capacity:
		return failureQueueFull
	}
	q.queue = append(q.queue, job)
	if q.running < q.workers {
		q.running++
		go q.work()
	}

	return ""
}

// work takes jobs until there are none. Nothing a delivery does reaches it, but a report runs a
// consumer's log handler, and so will its event sink: a report ending this goroutine has it replaced
// by another, which takes up the running count this one held.
func (q *logoutPool) work() {
	finished := false
	defer func() {
		if !finished {
			_ = recover() //nolint:errcheck // whatever a report panicked with is not looked at
			go q.work()
		}
	}()

	for {
		job, ok := q.next()
		if !ok {
			finished = true

			return
		}
		q.attempt(job)
	}
}

// next takes the oldest job, or takes this worker off the count, with no gap between finding the queue
// empty and leaving in which a job could be queued and no worker started for it.
func (q *logoutPool) next() (logoutJob, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) == 0 {
		q.queue = nil
		q.running--
		q.settle()

		return logoutJob{}, false
	}
	job := q.queue[0]
	q.queue[0] = logoutJob{} // A delivered job's context should not stay reachable from the queue.
	q.queue = q.queue[1:]

	return job, true
}

// settle closes drained once there is nothing left to wait for, and needs mu held.
func (q *logoutPool) settle() {
	if q.closed && !q.finished && q.running == 0 && q.calls == 0 && q.reports == 0 {
		q.finished = true
		close(q.drained)
	}
}

// attempt runs one delivery, waiting no longer than its bound. A failure ending with the delivery's own
// context, however it arrives, comes to one verdict: the bound's, or that Shutdown cut it off.
func (q *logoutPool) attempt(job logoutJob) {
	if !q.enterCall() {
		q.report(job.ctx, *failureOf(job.client, failureBusy, nil))

		return
	}

	ctx, cancel := context.WithTimeout(job.ctx, q.timeout)
	defer cancel()
	defer context.AfterFunc(q.stopped, cancel)()

	done := make(chan *logoutFailure, 1)
	go q.call(ctx, job.client, done)

	var failure *logoutFailure
	select {
	case failure = <-done:
	case <-ctx.Done():
		select {
		case failure = <-done:
		default:
			failure = failureOf(job.client, failureTimeout, ctx.Err())
		}
	}

	switch {
	case failure == nil:
	case ctx.Err() == nil:
		q.report(job.ctx, *failure)
	case errors.Is(ctx.Err(), context.Canceled):
		q.cutOff(job.ctx, job.client.ClientID)
	default:
		q.report(job.ctx, *failureOf(job.client, failureTimeout, ctx.Err()))
	}
}

// call is one delivery's own goroutine. Its place is given back before it answers, so that a worker
// moving on cannot find it still taken.
func (q *logoutPool) call(ctx context.Context, c ClientToNotify, done chan<- *logoutFailure) {
	var failure *logoutFailure
	returned := false
	defer func() {
		if !returned {
			failure = failureOf(c, failureGoexit, nil)
			if r := recover(); r != nil {
				failure.Reason, failure.PanicType = failurePanic, fmt.Sprintf("%T", r)
			}
			if ctx.Err() != nil {
				q.noteLate(ctx, failure)
			}
		}
		q.leaveCall()
		done <- failure
	}()

	failure = q.deliver(ctx, c)
	returned = true
}

// noteLate logs what a call left behind ended with, as no worker is left to report it. Nothing is
// above this goroutine to survive a log handler's panic, so it stops here.
func (q *logoutPool) noteLate(ctx context.Context, failure *logoutFailure) {
	defer func() { _ = recover() }() //nolint:errcheck // whatever a log handler panicked with is not looked at
	q.late(context.WithoutCancel(ctx), failure)
}

func (q *logoutPool) enterCall() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.calls >= 2*q.workers {
		return false
	}
	q.calls++

	return true
}

func (q *logoutPool) leaveCall() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.calls--
	q.settle()
}

func (q *logoutPool) start() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	switch {
	case q.closed:
		return ErrAlreadyShutdown
	case q.started:
		return ErrAlreadyStarted
	}
	q.started = true

	return nil
}

func (q *logoutPool) shutdown(ctx context.Context) error {
	q.mu.Lock()
	q.closed = true
	q.settle()
	q.mu.Unlock()

	err := lifecycle.Await(ctx, q.drained)
	if err == nil {
		return nil
	}

	q.mu.Lock()
	left := q.queue
	q.queue = nil
	q.mu.Unlock()
	q.stop()
	for _, job := range left {
		q.report(job.ctx, *failureOf(job.client, failureShutdown, nil)) //nolint:contextcheck // the job's context is its own, detached from its caller's
	}

	return err
}

// ErrAlreadyStarted is returned by Start on a provider already started.
var ErrAlreadyStarted = errors.New("oidcprovider: already started")

// ErrAlreadyShutdown is returned by Start on a provider that has been shut down. Shutdown is terminal.
var ErrAlreadyShutdown = errors.New("oidcprovider: already shut down")

// Start states that the provider's background work may begin, for a consumer who starts and stops its
// components together. It is optional, and launches nothing: back-channel delivery starts itself at the
// first ended sign-in, so that the minimum wiring gets it and a provider with nothing to deliver runs no
// goroutine. Neither the context's end nor its deadline ends anything.
//
// A provider is started at most once. Starting one already started returns ErrAlreadyStarted, and one
// that has been shut down ErrAlreadyShutdown. A delivery coming first is no start, because traffic may
// reach a provider before its consumer calls this. A nil ctx is refused with an error matching ErrConfig,
// and changes nothing.
func (p *Provider) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: Start needs a non-nil context", ErrConfig)
	}

	return p.logouts.start()
}

// Shutdown stops back-channel delivery, for no longer than ctx allows. A sign-in ending after it still
// ends, and its delivery is dropped and reported. It returns nil once what was queued has been delivered
// and every delivery's goroutine has ended, so nil means no goroutine of the provider's is left. When
// that is already so, it returns nil even if ctx is done.
//
// If ctx ends first, Shutdown returns its error, reports what is still queued as failed, and cuts off
// what is running, which is logged and not reported, as signingkey treats a store call it cuts off. A
// consumer's delivery ignoring its context cannot be stopped, and holds its goroutine until it returns.
// A later Shutdown waits again under its own context, and returns nil once it has.
//
// Shutdown is terminal, and safe to call more than once and at the same time as anything else: the first
// context to end cuts off the rest for all of them. Never having started the provider changes nothing. A
// nil ctx is refused with an error matching ErrConfig, and changes nothing. Do not call it from inside a
// LogoutDelivery, which would wait for itself until ctx ends.
func (p *Provider) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: Shutdown needs a non-nil context", ErrConfig)
	}

	return p.logouts.shutdown(ctx)
}
