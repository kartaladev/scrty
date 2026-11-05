package httpsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// This file is one stream's life: one body goroutine of timers, writes and cancellation, and
// beside it at most one goroutine reading the store, whose answer the body takes from a channel.
// So a body never waits for a store, and what a store does cannot stop a heartbeat.
//
// What a stream decides about time is in streamRules, as pure functions of what it holds and
// the time, and the loop only reads, writes and waits. The store decides whether a sign-in
// ended, so nothing here ends a stream on a message or on a deadline alone: session_ended follows
// streamRules.judge, on an answer the store just gave or, for a store that has not answered, at the
// absolute deadline alone. A stream that judge told to wait for a report ends on that same answer,
// at most streamReportGrace later (streamLoop.waitForReport), by streamLoop.onWake or onTimer and
// with no second judgement, as nothing but a read that answers alive takes the answer back.

const (
	// streamBeatJitter and streamAgeJitter spread heartbeats and maximum ages, ±10%, so that
	// streams opened together neither reload nor reconnect together. streamRetryJitter spreads
	// the reconnection delay, ±30%, because a replica's streams close together on a deploy.
	streamBeatJitter  = 0.10
	streamAgeJitter   = 0.10
	streamRetryJitter = 0.30

	// streamWakeGap is the least time between two reloads a wake asks for. It protects the store
	// from a message and not a consumer's policy, so it is a constant.
	streamWakeGap = time.Second

	// streamHoldAnswers is how many answered reads an end notice can hold a stream's queue across
	// while later notices keep arriving, one for a read older than the first and one for the read
	// that answers it. So a shared bus's holder who forges ends faster than a stream may read
	// cannot silence its queue. It protects a guarantee and not a consumer's policy, so it is a
	// constant.
	streamHoldAnswers = 2

	// streamReasonBeats is how many nominal heartbeats a reported reason stays good for, counted
	// from its local receipt, so that a report whose end never happened cannot name a later one.
	streamReasonBeats = 2

	// streamReportGrace is how long a stream whose read said gone, holding no report, waits for one
	// before it says ended. A session manager reports an end only after the store's write has
	// returned, so a read can land in between and take a logout for an end nobody reported. A report
	// from the same process follows in microseconds to a few milliseconds, and one over a healthy
	// broker in tens of them, so half a second holds both, a loaded machine's scheduling too. An end
	// no report will follow, as on another replica with the default bus, pays all of it, on top of a
	// heartbeat: so a longer wait would cover only a bus already in trouble, for a label, at the
	// price of every such end. It protects a label and not a consumer's policy, so it is a constant.
	streamReportGrace = 500 * time.Millisecond

	// streamFlow is the flow attribute of a stream's records, and what their sampling keys start
	// with.
	streamFlow = "session-signals"

	// panicPhaseStream and panicPhaseReload say where a stream's panic happened.
	panicPhaseStream = "stream"
	panicPhaseReload = "reload"

	// The deadline a session_expiring names.
	deadlineIdle     = "idle"
	deadlineAbsolute = "absolute"
)

// Why a stream closed: the reason attribute of its close record. None of them reaches a client.
const (
	closeClientLeft  = "client_left"
	closeClosing     = "closing"
	closeMaxAge      = "max_age"
	closeWriteFailed = "write_failed"
	closePanicked    = "panicked"
	closeEndedPrefix = "session_ended:"
)

// The records of a stream. None holds a token, a session identifier, a store's error text or a
// panic's value.
const (
	msgStreamOpened   = "httpsec: session signal stream opened"
	msgStreamClosed   = "httpsec: session signal stream closed"
	msgReloadFailed   = "httpsec: session signal stream: a reload failed"
	msgEventRefused   = "httpsec: session signal stream: an event was refused and skipped"
	msgStreamPanicked = "httpsec: session signal stream: a panic was recovered"
)

// errStreamReadPanicked is what a panic in a consumer's store or loader at the first read, or in
// SessionSignals.ReloadContext, becomes: a dependency failure, with the panic logged and its value
// nowhere.
var errStreamReadPanicked = errors.New("httpsec: the first read of a signal stream panicked")

// jittered is d spread by ±fraction, where roll is in [0, 1].
func jittered(d time.Duration, fraction, roll float64) time.Duration {
	return time.Duration(float64(d) * (1 - fraction + 2*fraction*roll))
}

// streamRules is what a stream's set and its chain's configuration decide about its time. A
// window of zero means the stream does not send that signal, by the chain's set or the client's
// narrowing.
type streamRules struct {
	warning, assurance time.Duration

	// reasonWindow is how long after its local receipt a report's reason can name an end.
	reasonWindow time.Duration
}

// heldSignIn is what a stream holds of its sign-in between reloads. It holds no identifier, and
// no upstream value: the state's upstream fields are always cleared.
type heldSignIn struct {
	state session.SignInState

	// warned is the deadline the current window was warned for, "" outside a window.
	warned string

	// lapsedFor is the authentication time assurance_lapsed was sent for, so that only a new
	// authentication lapses again.
	lapsedFor time.Time
}

// streamRead is what one reload found.
type streamRead struct {
	state               session.SignInState
	gone, userGone      bool
	sessionErr, userErr error

	// timedOut says ReloadTimeout passed with no answer, so that either store may be the one
	// holding it. sessionErr then says the read failed, and judge treats it as an outage.
	timedOut bool

	// panicked says a consumer's store or loader panicked, which ends the stream.
	panicked bool
}

// streamVerdict is what a reload decides.
type streamVerdict struct {
	// end is the reason session_ended names, and "" when the stream goes on.
	end string

	// alive says the session store holds the sign-in, so that its answer replaces what the
	// stream holds. failed says a store failed, which counts as a failed reload.
	alive, failed bool

	// unreported says end is what a gone sign-in gets when nothing named a reason, for which a
	// report may still be on its way (streamReportGrace).
	unreported bool
}

// streamEvent is one event a stream sends, its data ready for writeEvent.
type streamEvent struct {
	name string
	data any
}

// expiringData is the data of a session_expiring.
type expiringData struct {
	Deadline string `json:"deadline"`
	At       string `json:"at"`
}

// lapsedData is the data of an assurance_lapsed.
type lapsedData struct {
	AuthenticatedAt string `json:"authenticated_at"`
}

// endedData is the data of a session_ended.
type endedData struct {
	Reason string `json:"reason"`
}

// streamTime is how a stream states a time on the wire, as sessionEventData does.
func streamTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// earlierDeadline is the deadline a sign-in reaches first. Equal deadlines name absolute, so
// that a front end does not offer a "stay signed in" that cannot work.
func earlierDeadline(s session.SignInState) (string, time.Time) {
	if s.IdleDeadline.Before(s.AbsoluteDeadline) {
		return deadlineIdle, s.IdleDeadline
	}

	return deadlineAbsolute, s.AbsoluteDeadline
}

// judge decides what a reload found. Every session_ended follows a verdict of its: at once, or for
// one that says unreported, by streamLoop.onWake or onTimer once the wait for a report is over. It has
// an answer from the store on every path but one: a session store that cannot answer ends a stream only
// at the absolute deadline, because the idle deadline may have moved in a store it cannot read.
func (r streamRules) judge(h heldSignIn, read streamRead, reuse, notice *endNotice, now time.Time) streamVerdict {
	if read.sessionErr != nil {
		v := streamVerdict{failed: true}
		if !now.Before(h.state.AbsoluteDeadline) {
			v.end = reasonExpired
		}

		return v
	}

	switch {
	case read.userGone:
		return streamVerdict{end: reasonEnded}
	case read.gone:
		end, unreported := r.goneReason(h, reuse, notice, now)

		return streamVerdict{end: end, unreported: unreported}
	}

	// A user store that cannot answer leaves the session store's answer standing, deadlines
	// included, since that store did answer.
	return streamVerdict{alive: true, failed: read.userErr != nil}
}

// goneReason is why a sign-in the store says is gone ended, and whether that is only for want of a
// report. Otherwise expired is decided locally, from the deadlines held.
func (r streamRules) goneReason(h heldSignIn, reuse, notice *endNotice, now time.Time) (string, bool) {
	if why := r.reported(reuse, notice, now); why != "" {
		return why, false
	}

	if _, at := earlierDeadline(h.state); !now.Before(at) {
		return reasonExpired, false
	}

	return reasonEnded, true
}

// reported is the reason a report names now, "" for none. A report names one only inside its window,
// and reuse outranks a later report there, so a logout that finds its family just revoked for reuse
// does not relabel a theft.
func (r streamRules) reported(reuse, notice *endNotice, now time.Time) string {
	for _, n := range []*endNotice{reuse, notice} {
		if n != nil && now.Sub(n.at) <= r.reasonWindow {
			return n.reason
		}
	}

	return ""
}

// speak is what the state held says is due now, recording it as sent, or for a warning that is no
// longer due, forgetting it. It is called only with a state the store has just given, or the first
// read's, so a timer never speaks from a stale deadline.
func (r streamRules) speak(h *heldSignIn, now time.Time) []streamEvent {
	var events []streamEvent

	if r.warning > 0 {
		deadline, at := earlierDeadline(h.state)

		switch {
		case now.Before(at.Add(-r.warning)):
			h.warned = ""
		case h.warned != deadline:
			// A different deadline is a different warning: activity that caps the idle deadline
			// at the absolute one must say so, because staying active no longer helps.
			h.warned = deadline
			events = append(events, streamEvent{
				name: string(SignalSessionExpiring),
				data: expiringData{Deadline: deadline, At: streamTime(at)},
			})
		}
	}

	auth := h.state.AuthenticatedAt
	if r.assurance > 0 && !auth.IsZero() && !auth.Equal(h.lapsedFor) && !now.Before(auth.Add(r.assurance)) {
		h.lapsedFor = auth
		events = append(events, streamEvent{
			name: string(SignalAssuranceLapsed),
			data: lapsedData{AuthenticatedAt: streamTime(auth)},
		})
	}

	return events
}

// nextSpeech is when a timer should next reload, the zero time for never: the earliest of what has
// not been sent, strictly after now. What is already past is never armed, which is what keeps a
// timer from spinning at zero delay: it is the next heartbeat's to look at. The two deadlines
// are always candidates, because during an outage nothing else ends a stream at the absolute one.
func (r streamRules) nextSpeech(h heldSignIn, now time.Time) time.Time {
	var next time.Time

	consider := func(at time.Time) {
		if at.After(now) && (next.IsZero() || at.Before(next)) {
			next = at
		}
	}

	consider(h.state.IdleDeadline)
	consider(h.state.AbsoluteDeadline)

	if r.warning > 0 {
		if deadline, at := earlierDeadline(h.state); h.warned != deadline {
			consider(at.Add(-r.warning))
		}
	}

	if auth := h.state.AuthenticatedAt; r.assurance > 0 && !auth.IsZero() && !auth.Equal(h.lapsedFor) {
		consider(auth.Add(r.assurance))
	}

	return next
}

// streamReloadCounts is what a replica's streams counted of their reloads. They back
// Chain.SessionSignalStats, which takes no lock, so both are counters.
type streamReloadCounts struct {
	// failures is every reload that failed.
	failures atomic.Uint64

	// inRow is the failures in a row of the streams now open, added up: zero when every open
	// stream's last read succeeded. A single total reset by any success would hide one user's
	// unreadable session behind everyone else's streams, which is what it exists to show. Being a
	// sum, it scales with the number of streams, so an outage reads as streams times failures.
	inRow atomic.Uint64
}

// reloadCounts is every reload that failed, and the failures in a row of the streams now open.
func (e *sessionSignals) reloadCounts() (total, consecutive uint64) {
	return e.reloads.failures.Load(), e.reloads.inRow.Load()
}

// readStream reads the sign-in and its user on ctx, which carries the one ReloadTimeout both share,
// so that the first read and every reload are the same read. It presents nothing: SignInState
// records no presentation, judges nothing and revokes nothing, where Sessions.Load would sign the
// user out after a renewal.
//
// A session store that cannot answer stops it, because judge decides an outage by the absolute
// deadline alone, so the user's answer would change nothing. A user no longer active is then heard
// at the first read after the outage, however long that lasts. A sign-in that is gone still reads
// the user, because a user who is not active is "ended" whatever else was reported.
func (e *sessionSignals) readStream(ctx context.Context, user identity.UserID, family id.ID) streamRead {
	var read streamRead

	state, err := e.sessions.SignInState(ctx, user, family)

	switch {
	case errors.Is(err, session.ErrNotFound):
		read.gone = true
	case err != nil:
		read.sessionErr = err

		return read
	default:
		read.state = state
	}

	details, err := e.cfg.Users.LoadByUserID(ctx, user)

	switch {
	case errors.Is(err, identity.ErrUserNotFound):
		read.userGone = true
	case err != nil:
		read.userErr = err
	case details == nil || details.ID != user || !details.Active:
		read.userGone = true
	}

	return read
}

// readSignIn is the first read, the same read as a reload, so that a tenant-scoped store with no
// hook fails here, where it can be seen, and not as an open stream that never hears of an end.
//
// A sign-in the store does not hold, or a user who is not found or not active, is 401. Any other
// failure is a dependency failure, matching neither that nor anything a client is told by. A
// failed read of the user is answered as the authenticators answer one (classifyReload), behind
// fixed text with the cause reachable; the session read's error is already fixed text of
// Sessions.SignInState's. It is classified on reload, which carries none of the request's
// cancellation, so that a client's leaving is never what a failed read is taken for. It takes the user and the family and not the session, as a body must be able
// to. A panic in a consumer's store or loader is logged as a stream's is, without its value.
//
// It runs on the request's goroutine, as every read of a request's authentication does. So a store
// that ignores its context holds this request until it returns, even once its client has left. The
// request holds no stream's place while it waits, since a place is taken after this read.
func (e *sessionSignals) readSignIn(reload context.Context, user identity.UserID, family id.ID) (state session.SignInState, err error) {
	defer func() {
		if v := recover(); v != nil {
			e.logStreamPanic(reload, panicPhaseReload, family, v)

			err = errStreamReadPanicked
		}
	}()

	ctx, cancel := context.WithTimeout(reload, e.cfg.ReloadTimeout)
	defer cancel()

	read := e.readStream(ctx, user, family)

	switch {
	case read.sessionErr != nil:
		return session.SignInState{}, read.sessionErr
	case read.gone, read.userGone:
		return session.SignInState{}, ErrAuthenticationRequired
	case read.userErr != nil:
		return session.SignInState{}, classifyReload(reload, read.userErr)
	}

	return read.state, nil
}

// streamReading is the one read a stream has in flight.
type streamReading struct {
	// answer has room for the read's one answer, so that a read whose body has gone never waits
	// to give it.
	answer chan streamRead

	// timedOut ends when ReloadTimeout passes, and is nil once the body has acted on that.
	timedOut <-chan struct{}

	// cancel ends the read's context. The body calls it when the read ends or the stream does, and
	// the read's goroutine never does, or the timeout could not be told from an answer.
	cancel context.CancelFunc

	// notes is signalStream.notes when the read started: the end notices its answer can speak for,
	// since the store had already ended whatever they report.
	notes uint64

	// broad is the user-wide end notice held when the read started, nil for none: the one its
	// answer can take back (streamLoop.takeBackBroad).
	broad *endNotice

	// overdue says the read is past its timeout, already counted as a failure, so that any answer
	// it still gives is discarded.
	overdue bool
}

// streamLoop is one stream's body and what only it touches, and a read's goroutine touches none of
// it. A body holds what streamStart carries and nothing from the exchange.
//
// A store that ignores its context costs one goroutine per stream until it returns, because a
// goroutine cannot be stopped from outside. It holds neither the body nor the stream's place, so
// the heartbeat, MaxAge, closing and a client leaving all still act, and no second read starts.
type streamLoop struct {
	e     *sessionSignals
	w     EventWriter
	start streamStart
	rules streamRules
	held  heldSignIn

	// reading is the read in flight, nil for none. again says something wanted a read while it was
	// in flight, which it gets when that read returns. A wake needs no such note: it waits in its
	// channel, since the loop does not take one during a read.
	reading *streamReading
	again   bool

	// beat is the next heartbeat. timer is the stream's one timer, for the earliest of speakAt,
	// ageAt and wakeOpensAt. wake is the stream's wake channel, nil while the gap after a wake
	// runs, so that later wakes wait in the channel and are not lost.
	beat, timer <-chan time.Time
	wake        <-chan struct{}

	// answered is the end notices a read has answered, of signalStream.notes. heldAnswers is the
	// reads answered while a later notice stayed unanswered, and parked is a signal taken from the
	// queue before a notice was seen, which goes first when the hold ends. See holding.
	answered    uint64
	heldAnswers int
	parked      *queuedSignal

	// speakAt is the time the timer reloads at, the zero time for none. ageAt is when MaxAge
	// closes the stream, the zero time with NoMaxAge. wakeOpensAt is when the gap ends. graceAt is
	// when a stream a read said gone stops waiting for a report, the zero time when it is not.
	speakAt, ageAt, wakeOpensAt, graceAt time.Time

	// failuresInRow is this stream's share of streamReloadCounts.inRow.
	failuresInRow uint64
}

// runStream is one stream's life, from its first bytes until it closes. Its first deferred step
// recovers a panic in the stream's own code or a consumer's store or loader, on every adapter, so
// that it reaches the consumer's logger and, on net/http and gin, never the standard library's log
// of the panic value. A read's goroutine recovers its own, and has the body close. The caller then
// frees the place.
func (e *sessionSignals) runStream(ctx context.Context, w EventWriter, start streamStart) {
	l := &streamLoop{e: e, w: w, start: start, rules: e.streamRules(start.stream)}
	l.held.state = start.state

	reason := closePanicked

	defer func() {
		if v := recover(); v != nil {
			e.logStreamPanic(ctx, panicPhaseStream, start.stream.family, v)
		}

		l.closed(ctx, reason)
	}()

	l.logLifecycle(ctx, msgStreamOpened)

	reason = l.run(ctx)

	if reason == closeClosing {
		l.lastRetry()
	}
}

// lastRetry is a closing stream's last bytes: a fresh delay, so that a replica's clients do not all
// come back at one moment. It is a field and not an event, and a client gone by now hears nothing.
func (l *streamLoop) lastRetry() {
	if err := writeRetry(l.w, l.e.closingRetry()); err == nil {
		_ = l.w.Flush()
	}
}

// streamRules is what the chain's configuration and the client's narrowing leave for st.
func (e *sessionSignals) streamRules(st *signalStream) streamRules {
	rules := streamRules{reasonWindow: streamReasonBeats * e.cfg.Heartbeat}

	if st.wanted.wants(string(SignalSessionExpiring)) {
		rules.warning = e.cfg.ExpiryWarning
	}

	if st.wanted.wants(string(SignalAssuranceLapsed)) {
		rules.assurance = e.cfg.AssuranceWindow
	}

	return rules
}

// run is the stream's one select, and returns why the stream closed. Writes happen only here, so
// no event can interleave with another or with a heartbeat. Leaving it cancels a read in flight
// and does not wait for it, since a store that ignores its context could hold it for ever.
func (l *streamLoop) run(ctx context.Context) string {
	st := l.start.stream

	// A chain that refused after Stream leaves a body on an ended context, where what it writes
	// goes nowhere. A stream told to close between taking its place and getting here says nothing.
	if reason := l.told(ctx); reason != "" {
		return reason
	}

	defer func() {
		if l.reading != nil {
			l.reading.cancel()
		}
	}()

	if reason := l.open(ctx); reason != "" {
		return reason
	}

	for {
		// Both may be ready along with something else, and a stream that has been told to end
		// says nothing more.
		if reason := l.told(ctx); reason != "" {
			return reason
		}

		// A read in flight is waited for here, and a wake waits in its channel until it ends.
		var (
			answer   <-chan streamRead
			timedOut <-chan struct{}
		)

		wake := l.wake

		if l.reading != nil {
			answer, timedOut, wake = l.reading.answer, l.reading.timedOut, nil
		}

		// What a report wakes while one is waited for costs the store nothing, so no gap applies.
		if l.awaitingReport() {
			wake = st.wake
		}

		queue := (<-chan queuedSignal)(st.queue)

		switch {
		case l.queueHeld():
			queue = nil
		case l.parked != nil:
			sig := *l.parked
			l.parked = nil

			if reason := l.sendSignal(ctx, sig); reason != "" {
				return reason
			}

			continue
		}

		var reason string

		select {
		case <-ctx.Done():
			return closeClientLeft
		case <-st.closing:
			return closeClosing
		case <-l.beat:
			reason = l.onBeat(ctx)
		case <-l.timer:
			reason = l.onTimer(ctx)
		case <-wake:
			reason = l.onWake(ctx)
		case read := <-answer:
			reason = l.onAnswer(ctx, read)
		case <-timedOut:
			reason = l.onReadTimeout(ctx)
		case sig := <-queue:
			reason = l.onSignal(ctx, sig)
		}

		if reason != "" {
			return reason
		}
	}
}

// queueHeld says nothing is sent from the queue for now: a stream that end closes says session_ended
// instead of what was raised behind it.
func (l *streamLoop) queueHeld() bool {
	return l.awaitingReport() || l.holding()
}

// awaitingReport says a read has said gone with no report held, and the stream is waiting for one.
func (l *streamLoop) awaitingReport() bool {
	return !l.graceAt.IsZero()
}

// onWake is a wake. While a report is waited for it can be the one waited for, and the store has
// already said gone, so no read is needed to act on it. With a read in flight, what the wake asks is
// asked again after it, in case that read answers alive.
func (l *streamLoop) onWake(ctx context.Context) string {
	if l.awaitingReport() {
		st := l.start.stream

		if why := l.rules.reported(st.reuse.Load(), st.notice.Load(), l.e.clock.Now()); why != "" {
			return l.end(ctx, why)
		}

		if l.reading != nil {
			l.again = true
		}

		return ""
	}

	l.wake = nil
	l.wakeOpensAt = l.e.clock.Now().Add(streamWakeGap)
	l.startRead() //nolint:contextcheck // a read runs on what ReloadContext made, and not on the request's

	return ""
}

// holding says an end notice has had no answer from the store, so the stream sends nothing from its
// queue: a stream that end closes says session_ended instead of what was raised behind it. Nothing
// else waits on this, so a heartbeat, MaxAge, closing and a client leaving all still act.
//
// Every notice has a wake behind it, and a read has a timeout, so a hold ends with the read that
// answers it. That takes two ReloadTimeouts and a wake gap at most: a read older than the notice,
// which answers just inside its timeout, and the read the notice then gets, which hangs to its own.
// Whatever that read says short of gone lets the queue go: alive, because the notice was forged,
// rolled back or about another sign-in, and a failure or timeout, because the store cannot say and
// an outage must not silence a stream. Two things end a hold sooner. A read past its timeout cannot
// answer, however long it hangs, and no other read starts beside it. And notices that keep
// outrunning the reads (streamHoldAnswers) are not waited for, until a read answers all there are.
//
// Nothing is sent from the queue during a hold, and the queue holds streamQueueSize signals: one
// that fills while the hold lasts drops what is offered after, for this stream alone, as any full
// queue does.
//
// The bound has a limit, which is accepted: a notice that ended nothing (a session deleted from a
// family that stays live, a transaction rolled back, a forgery) can use up the answers the bound
// allows, so that a real end noted behind it is not held for, and a signal raised after that end
// can go out ahead of its session_ended. It takes notices that outrun the reads, and a forged flood
// must stay bounded, so that a holder of a shared bus cannot silence a stream by sending ends.
func (l *streamLoop) holding() bool {
	if l.answered == l.start.stream.notes.Load() || l.heldAnswers >= streamHoldAnswers {
		return false
	}

	return l.reading == nil || !l.reading.overdue
}

// settleHold is a read, which started with the given notes noted, answering. A signal raised from
// here on is no longer held for those.
func (l *streamLoop) settleHold(notes uint64) {
	l.answered = notes

	if notes == l.start.stream.notes.Load() {
		l.heldAnswers = 0

		return
	}

	// Counted past the bound too, which changes nothing: holding already lets the queue go at it.
	l.heldAnswers++
}

// onSignal is a signal from the queue. One taken with a notice already noted, which the select could
// not know of, waits for that notice's answer, and goes ahead of the rest of the queue then.
func (l *streamLoop) onSignal(ctx context.Context, sig queuedSignal) string {
	if l.queueHeld() {
		l.parked = &sig

		return ""
	}

	return l.sendSignal(ctx, sig)
}

// sendSignal sends a signal from the queue.
func (l *streamLoop) sendSignal(ctx context.Context, sig queuedSignal) string {
	return l.send(ctx, streamEvent{name: sig.name, data: sig.data})
}

// told is why the stream must close now that it has been told to end, "" when it has not.
func (l *streamLoop) told(ctx context.Context) string {
	select {
	case <-ctx.Done():
		return closeClientLeft
	case <-l.start.stream.closing:
		return closeClosing
	default:
		return ""
	}
}

// open sends the stream's first bytes, what is already due from the first read, and arms what the
// stream waits on. The reasons a stream never gets here are admission's.
func (l *streamLoop) open(ctx context.Context) string {
	cfg := l.e.cfg

	if err := writeRetry(l.w, jittered(cfg.ReconnectDelay, streamRetryJitter, rand.Float64())); err != nil { //nolint:gosec // jitter, not a secret
		return closeWriteFailed
	}

	if reason := l.send(ctx, streamEvent{name: "session", data: sessionEventData(l.held.state)}); reason != "" {
		return reason
	}

	now := l.e.clock.Now()

	if reason := l.speak(ctx, now); reason != "" {
		return reason
	}

	if cfg.MaxAge != NoMaxAge {
		l.ageAt = now.Add(jittered(cfg.MaxAge, streamAgeJitter, rand.Float64())) //nolint:gosec // jitter, not a secret
	}

	l.wake = l.start.stream.wake
	l.armBeat()
	l.armTimer(now)

	return ""
}

// armBeat draws the next heartbeat's jitter.
func (l *streamLoop) armBeat() {
	l.beat = l.e.clock.After(jittered(l.e.cfg.Heartbeat, streamBeatJitter, rand.Float64())) //nolint:gosec // jitter, not a secret
}

// armTimer arms the one timer for the earliest of what is left. A timer armed before is dropped,
// and the runtime collects it. What is left of the wake gap and of a wait for a report is cut back to
// its own length, so that a clock with no monotonic reading stepped back holds a pending wake for at most two gaps,
// and not until that clock catches up. clock.System's monotonic reading sees no such step.
func (l *streamLoop) armTimer(now time.Time) {
	if l.wake == nil {
		switch {
		case !now.Before(l.wakeOpensAt):
			l.wake = l.start.stream.wake
		case l.wakeOpensAt.Sub(now) > streamWakeGap:
			l.wakeOpensAt = now.Add(streamWakeGap)
		}
	}

	l.speakAt = l.rules.nextSpeech(l.held, now)

	// Cut back as the gap is, for the same clock.
	if l.awaitingReport() && l.graceAt.Sub(now) > streamReportGrace {
		l.graceAt = now.Add(streamReportGrace)
	}

	at := l.speakAt

	for _, other := range []time.Time{l.ageAt, l.graceAt} {
		if !other.IsZero() && (at.IsZero() || other.Before(at)) {
			at = other
		}
	}

	var gated time.Duration

	if l.wake == nil {
		gated = l.wakeOpensAt.Sub(now)
	}

	switch {
	case at.IsZero() && gated == 0:
		l.timer = nil
	case at.IsZero():
		l.timer = l.e.clock.After(gated)
	case gated == 0:
		l.timer = l.e.clock.After(at.Sub(now))
	default:
		l.timer = l.e.clock.After(min(at.Sub(now), gated))
	}
}

// onBeat is a heartbeat: its comment goes out at once, whatever the store is doing, and the store
// is asked. So the longest a stream goes without a byte is one jittered heartbeat and a write.
func (l *streamLoop) onBeat(ctx context.Context) string {
	// Armed before the write, so that a slow write does not stretch the beats apart.
	l.armBeat()

	if err := writeHeartbeat(l.w); err != nil {
		return closeWriteFailed
	}

	if err := l.w.Flush(); err != nil {
		return closeWriteFailed
	}

	return l.askStore(ctx, l.e.clock.Now())
}

// onTimer is the one timer firing. MaxAge closes with no event, and a gap that ended lets a pending
// wake through. Only what speakAt was armed for reads the store, so that neither of those can
// reload before the next heartbeat what the store has already said is alive.
func (l *streamLoop) onTimer(ctx context.Context) string {
	now := l.e.clock.Now()

	if !l.ageAt.IsZero() && !now.Before(l.ageAt) {
		return closeMaxAge
	}

	if l.awaitingReport() && !now.Before(l.graceAt) {
		st := l.start.stream
		why, _ := l.rules.goneReason(l.held, st.reuse.Load(), st.notice.Load(), now)

		return l.end(ctx, why)
	}

	if !l.speakAt.IsZero() && !now.Before(l.speakAt) {
		// A timer reloads before it speaks: what it held can be a heartbeat stale.
		if reason := l.askStore(ctx, now); reason != "" {
			return reason
		}
	}

	l.armTimer(now)

	return ""
}

// askStore starts a read, or with one in flight notes that another is wanted when it returns. A
// read already past its timeout is an outage until it returns, so the question is answered as for
// one: only the absolute deadline ends the stream. That counts no failure, for no read was tried.
func (l *streamLoop) askStore(ctx context.Context, now time.Time) string {
	if l.reading == nil {
		l.startRead() //nolint:contextcheck // a read runs on what ReloadContext made, and not on the request's

		return ""
	}

	l.again = true

	if !l.reading.overdue {
		return ""
	}

	verdict := l.rules.judge(l.held, streamRead{sessionErr: context.DeadlineExceeded}, nil, nil, now)
	if verdict.end != "" {
		return l.end(ctx, verdict.end)
	}

	return ""
}

// startRead starts the stream's one read, on what ReloadContext made: reload carries none of the
// request's cancellation, because on fiber the stream outlives the handlers. The goroutine takes
// only what it reads with, and its answer is the only thing it hands the body.
func (l *streamLoop) startRead() {
	timed, cancel := context.WithTimeout(l.start.reload, l.e.cfg.ReloadTimeout)

	e, st := l.e, l.start.stream

	answer := make(chan streamRead, 1)
	l.reading = &streamReading{answer: answer, timedOut: timed.Done(), cancel: cancel, notes: st.notes.Load()}

	if n := st.notice.Load(); n != nil && n.broad {
		l.reading.broad = n
	}

	user, family := st.user, st.family

	go func() {
		answer <- e.readInGoroutine(timed, user, family)
	}()
}

// readInGoroutine is one reload, away from its body. A panic in a consumer's store or loader is
// recovered here, where it would otherwise end the process, and logged whether or not the body is
// still there. What a stream holds of the upstream session is its digest, so the raw values a read
// answers with go at once.
func (e *sessionSignals) readInGoroutine(ctx context.Context, user identity.UserID, family id.ID) (read streamRead) {
	defer func() {
		if v := recover(); v != nil {
			e.logStreamPanic(ctx, panicPhaseReload, family, v)

			read = streamRead{panicked: true}
		}
	}()

	read = e.readStream(ctx, user, family)
	read.state.ExternalIssuer, read.state.ExternalSessionID = "", ""

	return read
}

// onAnswer is the read in flight returning. An overdue read's answer is discarded, because the
// body has already acted on its timeout, and an answer saying "gone" is not lost by that: the next
// read asks again. A panic closes the stream however late it came, as any panic in a stream does.
func (l *streamLoop) onAnswer(ctx context.Context, read streamRead) string {
	reading := l.reading
	reading.cancel()
	l.reading = nil

	if read.panicked {
		// An overdue read was counted when its timeout passed.
		if !reading.overdue {
			l.e.reloads.failures.Add(1)
		}

		return closePanicked
	}

	if !reading.overdue {
		l.settleHold(reading.notes)

		l.takeBackBroad(reading, read)

		if reason := l.answer(ctx, read); reason != "" {
			return reason
		}
	}

	if l.again {
		l.again = false
		l.startRead() //nolint:contextcheck // a read runs on what ReloadContext made, and not on the request's
	}

	return ""
}

// takeBackBroad drops the user-wide notice held when reading started, if the session store then answered
// that it holds the sign-in: that report was about another of the user's sign-ins, and must not name a
// later end of this one. A read begun before the notice says nothing of it, because a report may arrive
// before its write is visible, so such a notice waits for the read its wake starts. Compared by identity,
// so that a notice arriving during the read stays.
//
// A reuse is never taken back. Every reuse the session manager reports names its family, so one naming
// only a user comes from a bus's sender, who must not be able to erase a family's reuse with it.
func (l *streamLoop) takeBackBroad(reading *streamReading, read streamRead) {
	if reading.broad != nil && read.sessionErr == nil && !read.gone {
		l.start.stream.notice.CompareAndSwap(reading.broad, nil)
	}
}

// onReadTimeout is ReloadTimeout passing on the read in flight, which counts as a failure at once,
// whether or not its goroutine has returned. An answer that came with the timeout is an answer.
func (l *streamLoop) onReadTimeout(ctx context.Context) string {
	select {
	case read := <-l.reading.answer:
		return l.onAnswer(ctx, read)
	default:
	}

	l.settleHold(l.reading.notes)
	l.reading.timedOut, l.reading.overdue = nil, true

	return l.answer(ctx, streamRead{sessionErr: context.DeadlineExceeded, timedOut: true})
}

// answer acts on what a read found, and re-arms the timer whatever it found, so a clock step is
// corrected. A stream told to end since the read answered says nothing of it, and a read that was
// cut short by a client's leaving says nothing about the store.
func (l *streamLoop) answer(ctx context.Context, read streamRead) string {
	if reason := l.told(ctx); reason != "" {
		return reason
	}

	st := l.start.stream
	now := l.e.clock.Now()
	verdict := l.rules.judge(l.held, read, st.reuse.Load(), st.notice.Load(), now)

	l.count(ctx, read, verdict, now)

	if l.waitForReport(verdict, now) {
		l.armTimer(now)

		return ""
	}

	if verdict.end != "" {
		return l.end(ctx, verdict.end)
	}

	if verdict.alive {
		if signInMoved(l.held.state, read.state) {
			l.held.state = read.state

			if reason := l.send(ctx, streamEvent{name: "session", data: sessionEventData(read.state)}); reason != "" {
				return reason
			}
		}

		if reason := l.speak(ctx, now); reason != "" {
			return reason
		}
	}

	l.armTimer(now)

	return ""
}

// waitForReport says the stream should not act yet on verdict, which is a sign-in gone with no report
// held, and starts the one wait for one. A read that says gone again changes nothing of that wait, nor
// does one that fails, since the store has said what it said. Only a store that holds the sign-in again
// takes it back, which is an end rolled back. Nothing else is held up meanwhile: a heartbeat, MaxAge,
// closing, a client leaving, a read and its answer all go on, and only the queue waits.
func (l *streamLoop) waitForReport(verdict streamVerdict, now time.Time) bool {
	if verdict.alive {
		l.graceAt = time.Time{}
	}

	if !verdict.unreported {
		return false
	}

	if !l.awaitingReport() {
		l.graceAt = now.Add(streamReportGrace)
	}

	return now.Before(l.graceAt)
}

// end sends session_ended, and is why the stream closes. Every path here comes from a select that may
// have chosen it just as the stream was told to end, and a stream told to end says nothing more.
func (l *streamLoop) end(ctx context.Context, why string) string {
	if reason := l.told(ctx); reason != "" {
		return reason
	}

	if reason := l.send(ctx, streamEvent{name: string(SignalSessionEnded), data: endedData{Reason: why}}); reason != "" {
		return reason
	}

	return closeEndedPrefix + why
}

// signInMoved reports whether a reload found something a client needs told. The two states' upstream
// fields are always cleared by then, and they are not the client's.
func signInMoved(held, read session.SignInState) bool {
	return !held.IdleDeadline.Equal(read.IdleDeadline) ||
		!held.AbsoluteDeadline.Equal(read.AbsoluteDeadline) ||
		!held.AuthenticatedAt.Equal(read.AuthenticatedAt)
}

// count keeps the reload counts and logs a failure with sampling.
func (l *streamLoop) count(ctx context.Context, read streamRead, verdict streamVerdict, now time.Time) {
	counts := &l.e.reloads

	if !verdict.failed {
		counts.inRow.Add(-l.failuresInRow)
		l.failuresInRow = 0

		return
	}

	counts.failures.Add(1)
	counts.inRow.Add(1)
	l.failuresInRow++

	store, err := "session", read.sessionErr

	switch {
	case read.timedOut:
		store = "session_or_user"
	case err == nil:
		store, err = "user", read.userErr
	}

	logSampled(ctx, l.e.sampler, l.e.log, slog.LevelWarn, now,
		streamFlow+sampleKeySeparator+"reload-failed", msgReloadFailed,
		slog.String("flow", streamFlow),
		slog.String("store", store),
		slog.String("error_type", fmt.Sprintf("%T", err)),
		slog.Bool("timed_out", errors.Is(err, context.DeadlineExceeded)),
		slog.String("family", l.start.stream.family.String()),
	)
}

// speak sends what is due from what the stream holds. A stream told to end during one event's slow
// write says nothing more, as the loop would not.
func (l *streamLoop) speak(ctx context.Context, now time.Time) string {
	for _, event := range l.rules.speak(&l.held, now) {
		if reason := l.told(ctx); reason != "" {
			return reason
		}

		if reason := l.send(ctx, event); reason != "" {
			return reason
		}
	}

	return ""
}

// send writes one event and flushes it, and returns why the stream must close, "" when it need not.
// An event the writer refuses wrote nothing, so it is logged with sampling and skipped: it says
// nothing about the connection, and nothing after it needs it.
func (l *streamLoop) send(ctx context.Context, event streamEvent) string {
	w := &writeWatcher{w: l.w}

	if err := writeEvent(w, event.name, event.data); err != nil {
		if w.wrote {
			return closeWriteFailed
		}

		logSampled(ctx, l.e.sampler, l.e.log, slog.LevelWarn, l.e.clock.Now(),
			streamFlow+sampleKeySeparator+"event-refused", msgEventRefused, slog.String("flow", streamFlow))

		return ""
	}

	if err := l.w.Flush(); err != nil {
		return closeWriteFailed
	}

	return ""
}

// writeWatcher tells a write that failed from an event writeEvent refused, which it did not write.
type writeWatcher struct {
	w     io.Writer
	wrote bool
}

func (w *writeWatcher) Write(p []byte) (int, error) {
	w.wrote = true

	return w.w.Write(p)
}

// closed gives back this stream's share of the failures in a row, and logs its close. The share
// goes first, since it must go whatever a consumer's logger does.
func (l *streamLoop) closed(ctx context.Context, reason string) {
	l.e.reloads.inRow.Add(-l.failuresInRow)
	l.failuresInRow = 0

	defer func() { _ = recover() }()

	l.logLifecycle(ctx, msgStreamClosed, slog.String("reason", reason))
}

// logLifecycle writes a stream's open or close record, with its user, family, client address and
// origin. These are the operator's: a client address never reaches a stream.
func (l *streamLoop) logLifecycle(ctx context.Context, msg string, attrs ...slog.Attr) {
	st := l.start.stream

	l.e.log.LogAttrs(ctx, slog.LevelDebug, msg, append([]slog.Attr{
		slog.String("flow", streamFlow),
		slog.String("user", string(st.user)),
		slog.String("family", st.family.String()),
		slog.String("client_address", l.start.source),
		slog.String("origin", l.start.origin),
	}, attrs...)...)
}

// logStreamPanic logs a recovered panic through the chain's logger: where, the value's type, the
// family and the frames, and never the value, which can quote a secret from a consumer's store or
// loader. A logger that panics as well goes no further. It must be called from the deferred call
// that recovered, so that the frames still show where the panic happened.
func (e *sessionSignals) logStreamPanic(ctx context.Context, phase string, family id.ID, value any) {
	defer func() { _ = recover() }()

	e.log.LogAttrs(ctx, slog.LevelError, msgStreamPanicked,
		append(panicAttrs(phase, value), slog.String("family", family.String()))...)
}
