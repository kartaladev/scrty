package oidcprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
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

	// logoutOutboundMargin is how far past a delivery's bound the outbound client's own default deadline
	// lies, so that the bound is what ends a post, and says so. Equal deadlines would each win some of the time.
	logoutOutboundMargin = time.Second

	// maxLogoutSinkReports bounds the goroutines at the sink, and with it what a sink that does not return
	// can hold. A log handler has one goroutine, so that its records keep their order.
	maxLogoutSinkReports = 64
	// maxLogoutReportsWaiting bounds what waits for a goroutine, for the sink and for the log each.
	maxLogoutReportsWaiting = 1024
	// maxLostCountTries is how many times a log handler is offered a count of what found no room before the
	// count waits for the next time the lane has work, so that one that always fails cannot keep it turning.
	maxLostCountTries = 3
)

// The fixed words a failed delivery is logged and reported under.
const (
	failureClient    = "client"     // the registry could not say who the client is
	failureSign      = "sign"       // the keys could not sign the token
	failurePost      = "post"       // the default delivery got no answer it could judge, or was refused where it was sent
	failureStatus    = "status"     // the default delivery got an answer that is no success
	failureDelivery  = "delivery"   // a consumer's delivery answered an error
	failureTimeout   = "timeout"    // the bound on one delivery ended it
	failurePanic     = "panic"      // a delivery panicked
	failureGoexit    = "goexit"     // a delivery ended its goroutine
	failureBusy      = "busy"       // calls left behind take every place a new one could run in
	failureQueueFull = "queue_full" // nothing could take it, and the queue had no room
	failureShutdown  = "shutdown"   // Shutdown came first, before the token was on its way or as it was
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
	// refused says the pool turned the job away, so its report takes none of the room Shutdown holds.
	refused bool
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
//
// posting is set as the token leaves, for a worker with no answer to know how deep the delivery got.
func (p *Provider) deliverLogout(ctx context.Context, c ClientToNotify, posting *atomic.Bool) *logoutFailure {
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
	posting.Store(true)
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

// reportLogoutFailure hands a failed delivery to the log and to the sink, and returns at once: nothing here
// calls a consumer's code on the goroutine that found the failure. It undoes nothing.
func (p *Provider) reportLogoutFailure(ctx context.Context, f logoutFailure) {
	p.logouts.toLog(f.refused, func() {
		if p.cfg.logoutFailed != nil {
			defer p.cfg.logoutFailed(ctx, f)
		}
		p.logLogoutFailure(ctx, f)
	})
	p.reportLogoutFailed(ctx, f)
}

// logLogoutFailure logs a failed delivery with fixed text and no value of its cause.
func (p *Provider) logLogoutFailure(ctx context.Context, f logoutFailure) {
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
}

// logCutOffLogout notes a read of a client or a signature Shutdown ended, before any token left, which is no
// failure, so it is not reported.
func (p *Provider) logCutOffLogout(ctx context.Context, clientID string) {
	p.logouts.noteToLog(func() {
		p.cfg.logger.LogAttrs(ctx, slog.LevelInfo, "oidcprovider: shutdown cut off a logout token's delivery",
			slog.String("client_id", clientID))
	})
}

// logLateLogoutFailure notes how a delivery ended after its bound had already reported it failed.
func (p *Provider) logLateLogoutFailure(ctx context.Context, f *logoutFailure) {
	p.logouts.noteToLog(func() {
		p.cfg.logger.LogAttrs(ctx, slog.LevelError, "oidcprovider: a logout token's delivery ended its goroutine after its bound",
			slog.String("client_id", f.ClientID), slog.String("reason", f.Reason), slog.String("value_type", f.PanicType))
	})
}

// logLostLogoutReports says what found no room: how many failures lost their log line, how many lost their
// event, and, apart from those, how many notes of how a delivery ended were lost, which are no failure's report.
func (p *Provider) logLostLogoutReports(lost lostReports) {
	p.cfg.logger.LogAttrs(context.Background(), slog.LevelError, "oidcprovider: reports of logout deliveries found no room",
		slog.Int("lost_records", lost.records), slog.Int("lost_events", lost.events), slog.Int("lost_notes", lost.notes))
}

// outboundLogoutDelivery is the default: one form POST through a confined client.
type outboundLogoutDelivery struct {
	out *outbound.Client
}

// Deliver implements LogoutDelivery. 200 and 204 are success (Back-Channel Logout §2.8), whatever body
// comes with them, none of which is read.
func (d outboundLogoutDelivery) Deliver(ctx context.Context, uri, logoutToken string) error {
	status, err := d.out.PostFormStatus(ctx, uri, url.Values{logoutTokenParam: {logoutToken}}, nil)
	if err != nil {
		return diag.Wrap(err, logoutPostText, errLogoutPost)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return &logoutStatusError{status: status}
	}

	return nil
}

// logoutPostText is what a logout token that was not answered says, as a transport's error names its target.
const logoutPostText = "oidcprovider: post the logout token"

// errLogoutPost says a logout token got no answer that could be judged, or was refused where it was sent.
var errLogoutPost = errors.New(logoutPostText)

// logoutStatusError is an answer that is no success.
type logoutStatusError struct {
	status int
}

func (e *logoutStatusError) Error() string {
	return "oidcprovider: the relying party answered a logout token with " + strconv.Itoa(e.status)
}

// buildLogoutDelivery returns what tells a client: the consumer's delivery, or a POST through the client
// that WithOutbound gave, or through a client of its own. Either way the POST follows no redirect.
func (c *config) buildLogoutDelivery() (LogoutDelivery, error) {
	switch {
	case c.logoutDeliverySet:
		return c.logoutDelivery, nil
	case c.outboundSet && !c.logoutOutboundSet:
		return outboundLogoutDelivery{out: c.outbound.WithoutRedirects()}, nil
	}

	// Later options win, so the cap goes last, and what a consumer gives cannot bring redirects back. The
	// time bound goes first, so that a consumer can shorten it, and its default does not cut a longer
	// delivery short.
	opts := append([]outbound.Option{
		outbound.WithHTTPClient(&http.Client{Transport: newLogoutTransport()}),
		outbound.WithTimeout(min(c.logoutTimeout, math.MaxInt64-logoutOutboundMargin) + logoutOutboundMargin),
	}, c.logoutOutbound...)
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
// Each delivery runs on a goroutine of its own, which a worker waits for no longer than the bound, and
// each report runs on a reportLane. So nothing a consumer's code does, a panic and a call that never
// returns included, can take a worker or keep it, and a replaced goroutine is what every delivery has
// anyway. A call left behind holds its goroutine until it returns, as Go has no way to stop one, so the
// calls are counted, and at twice the workers a delivery fails at once rather than start another.
type logoutPool struct {
	deliver func(context.Context, ClientToNotify, *atomic.Bool) *logoutFailure
	report  func(context.Context, logoutFailure)
	cutOff  func(context.Context, string)
	late    func(context.Context, *logoutFailure)
	lost    func(lostReports)

	workers, capacity int
	timeout           time.Duration

	// stopped ends with Shutdown's patience, and cuts off what is running.
	stopped context.Context //nolint:containedctx // what Shutdown ends, read by each delivery's context
	stop    context.CancelFunc

	// mu guards everything below, and is never held across a call out. A delivery either lands in the
	// queue before closed is set, and the drain delivers it, or it sees closed and is reported.
	mu      sync.Mutex
	queue   []logoutJob
	running int
	calls   int
	started bool
	closed  bool

	// records runs what is logged, and events what reaches a sink. They are apart so that a sink that does
	// not return costs no failure its log line, and a log handler that does not return costs none its event.
	records, events reportLane
	// unsaid counts what found no room, until records can log how many, and lostTries how many times in a row
	// that has been offered to the log handler and not taken.
	unsaid    lostReports
	lostTries int
	// shutdownRoom is the place in each lane held for what Shutdown found: each job it took from the queue, and
	// one for each worker and each call still running as it stopped them, which may each report once. It is
	// set once, as nothing starts afterwards, and a refused job has no share of it. flushed says it has been.
	shutdownRoom int
	flushed      bool
	// reporting counts the reports being handed to the lanes, by those with no goroutine counted above: an end
	// whose job was refused, and Shutdown with what it took from the queue.
	reporting int

	// drained is closed while Shutdown has been asked and nothing is left running, which a report of a
	// later drop reopens with a new channel, so that nil from Shutdown goes on meaning nothing is left.
	drained  chan struct{}
	finished bool
}

// reportLane runs what a report calls out to, on goroutines of its own, which come as they are needed and
// leave when nothing waits. What finds no room is the newest, as what is waiting has been promised a place.
type reportLane struct {
	limit, capacity int
	running         int
	waiting         []func()
}

// lostReports is what found no room, by what it is.
type lostReports struct {
	records, events, notes int
}

func (l lostReports) any() bool { return l != lostReports{} }

func newLogoutPool(cfg *config, p *Provider) *logoutPool {
	stopped, stop := context.WithCancel(context.Background())

	return &logoutPool{
		deliver:  p.deliverLogout,
		report:   p.reportLogoutFailure,
		cutOff:   p.logCutOffLogout,
		late:     p.logLateLogoutFailure,
		lost:     p.logLostLogoutReports,
		workers:  cfg.logoutWorkers,
		capacity: cfg.logoutQueue,
		timeout:  cfg.logoutTimeout,
		stopped:  stopped,
		stop:     stop,
		records:  reportLane{limit: 1, capacity: maxLogoutReportsWaiting},
		events:   reportLane{limit: maxLogoutSinkReports, capacity: maxLogoutReportsWaiting},
		drained:  make(chan struct{}),
	}
}

// enqueue never waits. A full queue, or one that Shutdown has closed, drops and reports, and the report
// waits for nothing either.
func (q *logoutPool) enqueue(ctx context.Context, c ClientToNotify) {
	job := logoutJob{client: c, ctx: context.WithoutCancel(ctx)}
	if reason := q.accept(job); reason != "" { //nolint:contextcheck // a worker's context is the job's
		defer q.endReporting()
		failure := failureOf(c, reason, nil)
		failure.refused = true
		q.report(job.ctx, *failure) //nolint:contextcheck // the job's context is ctx, detached
	}
}

func (q *logoutPool) accept(job logoutJob) (refused string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	switch {
	case q.closed:
		q.beginReporting()

		return failureShutdown
	case len(q.queue) >= q.capacity:
		q.beginReporting()

		return failureQueueFull
	}
	q.queue = append(q.queue, job)
	if q.running < q.workers {
		q.running++
		go q.work()
	}

	return ""
}

// work takes jobs until there are none. Nothing a delivery or a report does runs on this goroutine, so
// nothing reaches it.
func (q *logoutPool) work() {
	for {
		job, ok := q.next()
		if !ok {
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
	if q.closed && !q.finished && q.reporting == 0 && q.running == 0 && q.calls == 0 && q.records.running == 0 && q.events.running == 0 {
		q.finished = true
		close(q.drained)
	}
}

// reopen takes back a nil from Shutdown that has not been said yet, as there is something to wait for again,
// and needs mu held.
func (q *logoutPool) reopen() {
	if q.finished {
		q.finished = false
		q.drained = make(chan struct{})
	}
}

// beginReporting says a report is on its way to the lanes, so that its log line and its event are one step
// for Shutdown, and needs mu held.
func (q *logoutPool) beginReporting() {
	q.reporting++
	q.reopen()
}

func (q *logoutPool) endReporting() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.reporting--
	q.settle()
}

// toLog hands what logs a failure to the records lane. Past its room the failure is counted.
func (q *logoutPool) toLog(refused bool, task func()) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.push(&q.records, refused, task) {
		q.unsaid.records++
	}
}

// noteToLog hands a line that is no failure's report to the records lane. Past its room it is counted apart.
func (q *logoutPool) noteToLog(task func()) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.push(&q.records, false, task) {
		q.unsaid.notes++
	}
}

// toSink hands what reports a failure to the events lane. Past its room the failure is counted.
func (q *logoutPool) toSink(refused bool, task func()) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.push(&q.events, refused, task) {
		q.countLostEvent()
	}
}

// eventLost counts an event lost on its way to the sink.
func (q *logoutPool) eventLost() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.countLostEvent()
}

// countLostEvent counts an event, and starts the records lane to log how many, which may be idle as its own log
// line has already gone, and is how a lost event still gets said. It needs mu held.
func (q *logoutPool) countLostEvent() {
	q.unsaid.events++
	q.startLane(&q.records)
}

// push adds a task unless the lane has no room, and needs mu held.
func (q *logoutPool) push(lane *reportLane, refused bool, task func()) bool {
	room := lane.capacity
	if !refused {
		room += q.shutdownRoom
	}
	if len(lane.waiting) >= room {
		return false
	}
	lane.waiting = append(lane.waiting, task)
	q.startLane(lane)

	return true
}

// startLane starts a goroutine on the lane if it may have another, and needs mu held.
func (q *logoutPool) startLane(lane *reportLane) {
	if lane.running >= lane.limit {
		return
	}
	lane.running++
	q.reopen()
	go q.runLane(lane)
}

// runLane takes tasks until there are none. A task that panics or ends its goroutine, as a consumer's log
// handler or sink may, has it replaced by another, which takes up the running count this one held.
func (q *logoutPool) runLane(lane *reportLane) {
	finished := false
	defer func() {
		if !finished {
			_ = recover() //nolint:errcheck // whatever a report panicked with is not looked at
			go q.runLane(lane)
		}
	}()

	for {
		task, ok := q.nextTask(lane)
		if !ok {
			finished = true

			return
		}
		task()
	}
}

// nextTask takes the oldest task, or takes this goroutine off the count. The records lane says how much found
// no room before it leaves, so that the count is the last thing said of a burst. A count the log handler would
// not take after its tries stays counted, and goes with the next time this lane has work.
func (q *logoutPool) nextTask(lane *reportLane) (func(), bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(lane.waiting) > 0 {
		task := lane.waiting[0]
		lane.waiting[0] = nil // A task's context should not stay reachable from the lane.
		lane.waiting = lane.waiting[1:]

		return task, true
	}
	if lane == &q.records && q.unsaid.any() && q.lostTries < maxLostCountTries {
		lost := q.unsaid
		q.unsaid = lostReports{}
		q.lostTries++

		return func() { q.sayLost(lost) }, true
	}
	if lane == &q.records {
		q.lostTries = 0
	}
	lane.waiting = nil
	lane.running--
	q.settle()

	return nil, false
}

// sayLost logs a count, and puts it back if the log handler panics or ends the goroutine instead of taking it.
func (q *logoutPool) sayLost(lost lostReports) {
	said := false
	defer func() {
		q.mu.Lock()
		defer q.mu.Unlock()

		if said {
			q.lostTries = 0

			return
		}
		q.unsaid.records += lost.records
		q.unsaid.events += lost.events
		q.unsaid.notes += lost.notes
	}()

	q.lost(lost)
	said = true
}

// attempt runs one delivery, waiting no longer than its bound. A job taken as Shutdown stopped everything
// is not started: its client is one more not told, as those left in the queue are.
func (q *logoutPool) attempt(job logoutJob) {
	if q.stopped.Err() != nil {
		q.report(job.ctx, *failureOf(job.client, failureShutdown, nil))

		return
	}
	if !q.enterCall() {
		q.report(job.ctx, *failureOf(job.client, failureBusy, nil))

		return
	}

	ctx, cancel := context.WithTimeout(job.ctx, q.timeout)
	defer cancel()
	defer context.AfterFunc(q.stopped, cancel)()

	done := make(chan *logoutFailure, 1)
	var posting atomic.Bool
	go q.call(ctx, job.client, &posting, done)

	answer, answered := awaitCall(ctx, done)
	failure, cutOff := judgeAttempt(ctx, job.client, posting.Load(), answer, answered)
	switch {
	case cutOff:
		q.cutOff(job.ctx, job.client.ClientID)
	case failure != nil:
		q.report(job.ctx, *failure)
	}
}

// awaitCall waits for a delivery's answer, no longer than its context. An answer that has arrived by then
// stands, even if the context ended with it: a delivery finishing as the bound fires is no timeout.
func awaitCall(ctx context.Context, done <-chan *logoutFailure) (answer *logoutFailure, answered bool) {
	select {
	case answer = <-done:
		return answer, true
	case <-ctx.Done():
		select {
		case answer = <-done:
			return answer, true
		default:
			return nil, false
		}
	}
}

// judgeAttempt comes to one verdict on a delivery, however it ended. A delivery answering of itself, with a
// status, a panic or its goroutine ending, keeps what it said, whatever its context did. Any other failure
// with its context ended, or no answer, is the context's: the bound's, or Shutdown's. What Shutdown cut off
// before the token left is no failure, and is only noted, and cutOff says so. Past that it is a client not
// told, and is reported as one.
func judgeAttempt(ctx context.Context, c ClientToNotify, posting bool, answer *logoutFailure, answered bool) (failure *logoutFailure, cutOff bool) {
	if answered && answer == nil {
		return nil, false
	}
	ended := ctx.Err()
	switch {
	case ended == nil:
		return answer, false
	case answered && answersOfItself(answer):
		return answer, false
	case errors.Is(ended, context.DeadlineExceeded):
		return failureOf(c, failureTimeout, ended), false
	case !posting:
		return nil, true
	default:
		return failureOf(c, failureShutdown, ended), false
	}
}

// answersOfItself says a failure is what the delivery came to, and no effect of its context ending.
func answersOfItself(f *logoutFailure) bool {
	return f.Reason == failureStatus || f.Reason == failurePanic || f.Reason == failureGoexit
}

// call is one delivery's own goroutine. Its place is given back before it answers, so that a worker
// moving on cannot find it still taken.
func (q *logoutPool) call(ctx context.Context, c ClientToNotify, posting *atomic.Bool, done chan<- *logoutFailure) {
	var failure *logoutFailure
	returned := false
	defer func() {
		if !returned {
			failure = failureOf(c, failureGoexit, nil)
			if r := recover(); r != nil {
				failure.Reason, failure.PanicType = failurePanic, fmt.Sprintf("%T", r)
			}
			if ctx.Err() != nil {
				q.late(context.WithoutCancel(ctx), failure)
			}
		}
		q.leaveCall()
		done <- failure
	}()

	failure = q.deliver(ctx, c, posting)
	returned = true
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
	drained := q.drained
	q.mu.Unlock()

	err := lifecycle.Await(ctx, drained)
	if err == nil {
		return nil
	}

	q.mu.Lock()
	left := q.queue
	q.queue = nil
	if !q.flushed {
		q.flushed = true
		q.shutdownRoom = len(left) + q.running + q.calls
	}
	q.beginReporting()
	q.mu.Unlock()
	defer q.endReporting()

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

// Shutdown stops back-channel delivery, for no longer than ctx allows, and no report it starts holds it
// past that. A sign-in ending after it still ends, and its delivery is dropped and reported. It returns nil
// once what was queued has been delivered, every delivery's goroutine has ended and every report has been
// made, so nil means no goroutine of the provider's is left. When that is already so, it returns nil even if
// ctx is done.
//
// If ctx ends first, Shutdown returns its error, and cuts off what is running. What is still queued, and a
// delivery cut off with its token on the way, are reported as failed under the reason "shutdown". A read of
// the client or a signature it cut off told no one anything was coming, and is logged and not reported, as
// signingkey treats a store call it cuts off. A consumer's delivery ignoring its context, or a log handler or
// sink that does not return, cannot be stopped, and holds its goroutine until it returns. Their reports go on
// after Shutdown has returned, as they wait for a goroutine. A later Shutdown waits again under its own
// context, and returns nil once it has.
//
// Shutdown is terminal, and safe to call more than once and at the same time as anything else: the first
// context to end cuts off the rest for all of them. Never having started the provider changes nothing. A
// nil ctx is refused with an error matching ErrConfig, and changes nothing. Do not call it from inside a
// LogoutDelivery, or a log handler or sink a report runs, which would wait for itself until ctx ends.
func (p *Provider) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: Shutdown needs a non-nil context", ErrConfig)
	}

	return p.logouts.shutdown(ctx)
}
