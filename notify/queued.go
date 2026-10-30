package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/nilcheck"
)

// QueuedSender hands each message to a pool of workers and returns as soon as
// it is queued.
//
// It exists so a flow's response time does not depend on a mail server. A
// magic-link request that waited for delivery would take measurably longer for
// an address that has an account than for one that does not, which is exactly
// what the flow is built not to reveal.
//
// Messages live only in memory. A crash, or a shutdown that skips Close, loses
// whatever is still queued. A consumer who needs delivery to survive that
// supplies a Sender backed by a durable queue instead.
type QueuedSender struct {
	inner   Sender
	queue   chan queued
	workers int
	size    int
	timeout time.Duration
	logger  *slog.Logger

	wg sync.WaitGroup

	// mu guards closed and the queue channel together: a send holds it for
	// reading while it writes to the channel, and Close holds it for writing
	// while it flips the flag and closes the channel, so no send can write to
	// a channel Close is closing. The flag is a plain bool because it is never
	// read outside that lock.
	mu     sync.RWMutex
	closed bool
}

// queued is one message and the detached context it travels with. The context
// lives here rather than on Message because Message is the consumer's API and
// a context has no business in it.
type queued struct {
	msg Message
	ctx context.Context //nolint:containedctx // the delivery outlives the call that queued it
}

// NewQueuedSender wraps inner and starts its workers.
//
// Defaults: 2 workers (WithQueueWorkers), a queue of 256 messages
// (WithQueueMaxMessages), a 30-second bound on each delivery (WithQueueSendTimeout)
// and slog's default logger (WithQueueLogger). Construction fails, wrapping
// ErrConfig, on an absent inner sender — a nil interface or one holding a nil
// pointer — or a worker count, queue size or send timeout of zero or less.
//
// The workers run until Close, which the consumer calls at shutdown.
func NewQueuedSender(inner Sender, opts ...QueuedOption) (*QueuedSender, error) {
	cfg := queuedConfig{
		workers: defaultQueueWorkers,
		size:    defaultQueueSize,
		timeout: defaultQueueSendTimeout,
		logger:  slog.Default(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	// A typed nil is the shape an unchecked constructor error hands over: the
	// interface is not nil, so `inner == nil` misses it, and the first
	// delivery panics inside a worker rather than here.
	if nilcheck.IsNil(inner) {
		return nil, fmt.Errorf("%w: queued sender requires a sender to wrap", ErrConfig)
	}

	if cfg.workers <= 0 {
		return nil, fmt.Errorf("%w: queued sender workers must be positive, got %d", ErrConfig, cfg.workers)
	}

	if cfg.size <= 0 {
		return nil, fmt.Errorf("%w: queued sender queue size must be positive, got %d", ErrConfig, cfg.size)
	}

	if cfg.timeout <= 0 {
		return nil, fmt.Errorf("%w: queued sender send timeout must be positive, got %s", ErrConfig, cfg.timeout)
	}

	s := &QueuedSender{
		inner:   inner,
		queue:   make(chan queued, cfg.size),
		workers: cfg.workers,
		size:    cfg.size,
		timeout: cfg.timeout,
		logger:  cfg.logger,
	}

	s.wg.Add(cfg.workers)

	for range cfg.workers {
		go s.work()
	}

	return s, nil
}

const (
	// defaultQueueWorkers is how many deliveries run at once with no sizing
	// configured. Two is enough to keep one slow server from stalling every
	// message behind it, and small enough that a library's own mail never
	// becomes the reason a process runs out of connections.
	defaultQueueWorkers = 2

	// defaultQueueSize is how many messages may wait for a worker. 256 absorbs
	// a burst without letting a mail outage grow the queue until the process
	// dies; past that, dropping and saying so beats failing later and larger.
	defaultQueueSize = 256

	// defaultQueueSendTimeout bounds one delivery. It matches the SMTP
	// sender's own default, so the wrapper adds no bound the wrapped sender
	// does not already keep.
	defaultQueueSendTimeout = 30 * time.Second
)

// queuedConfig collects what the options set, so construction can validate it
// before a QueuedSender exists and before any worker starts.
type queuedConfig struct {
	workers int
	size    int
	timeout time.Duration
	logger  *slog.Logger
}

// QueuedOption configures a QueuedSender. Every option names the default it
// replaces, and every default works with no configuration at all.
type QueuedOption func(*queuedConfig)

// WithQueueWorkers replaces how many deliveries run at once. The default is 2.
// Zero or less is a configuration error: a queue nothing drains accepts every
// message and delivers none.
func WithQueueWorkers(n int) QueuedOption { return func(c *queuedConfig) { c.workers = n } }

// WithQueueMaxMessages replaces how many messages may wait for a worker. The default
// is 256. Zero or less is a configuration error: it would drop every message
// that did not find an idle worker at that instant.
//
// The queue is memory, not storage. Sizing it larger buys tolerance of a
// longer outage and nothing else — a crash still loses whatever is in it.
func WithQueueMaxMessages(n int) QueuedOption { return func(c *queuedConfig) { c.size = n } }

// WithQueueSendTimeout replaces the bound on one delivery. The default is 30
// seconds. Zero or less is a configuration error.
//
// The bound works on a wrapped sender that honours its context, as SMTPSender
// does. One that ignores its context occupies a worker for as long as it
// likes; Go offers no way to stop a goroutine from outside, so this is stated
// rather than defended against.
func WithQueueSendTimeout(d time.Duration) QueuedOption {
	return func(c *queuedConfig) { c.timeout = d }
}

// WithQueueLogger replaces where the sender writes its logs. The default is
// slog.Default, captured when the sender is built, so a consumer who
// configures nothing still hears about mail that was never delivered.
//
// Records report a dropped message, a failed delivery and a panic in the
// wrapped sender. None of them carries the message body, the subject or the
// recipient; a failed delivery or a recovered panic carries a fixed reason and
// a Go type in place of the inner sender's own error text or panic value — a
// consumer who wants that detail logs it inside their own Sender.
//
// Each of those is a sign-in link that never arrives, and Send returned nil
// long before, so a record discarded here is a failure nobody learns of at
// either end. Silence is therefore chosen rather than inherited: a consumer
// who wants it passes a logger over a discarding handler, for example
// slog.New(slog.DiscardHandler), which puts the decision where the wiring is
// read instead of leaving it to a default.
func WithQueueLogger(l *slog.Logger) QueuedOption {
	return func(c *queuedConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// NonBlocking reports true: Send returns once the message is queued.
func (s *QueuedSender) NonBlocking() bool { return true }

// Workers reports how many deliveries can run at once. Default: 2.
func (s *QueuedSender) Workers() int { return s.workers }

// QueueMaxMessages reports how many messages can wait for a worker. Default: 256.
func (s *QueuedSender) QueueMaxMessages() int { return s.size }

// SendTimeout reports the bound on one delivery. Default: 30s.
func (s *QueuedSender) SendTimeout() time.Duration { return s.timeout }

// Send queues msg and returns.
//
// The caller's context is detached with context.WithoutCancel: its values go
// with the message, because a tenant or a trace belongs to the delivery, while
// its cancellation does not, because the request ending is not a reason to
// abandon a sign-in link. Each delivery is bounded by the send timeout
// instead.
//
// A full queue drops the message, logs at error and returns ErrQueueFull. It
// never waits for space: waiting would put delivery time back into the
// caller's response, and it would be longest exactly when the system is most
// loaded. A send after Close returns ErrSenderClosed.
func (s *QueuedSender) Send(ctx context.Context, msg Message) error {
	// The read lock is what stops a send from writing to a channel Close is
	// closing; Close takes the write lock to close it.
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrSenderClosed
	}

	select {
	case s.queue <- queued{msg: msg, ctx: context.WithoutCancel(ctx)}:
		return nil
	default:
		s.logger.LogAttrs(ctx, slog.LevelError, "notify: send queue is full, message dropped",
			slog.Int("queue_size", s.size))

		return ErrQueueFull
	}
}

// work is one worker's loop. It ends when the queue is closed and drained.
func (s *QueuedSender) work() {
	defer s.wg.Done()

	for q := range s.queue {
		s.deliver(q)
	}
}

// deliver sends one message, bounded by the send timeout, and never lets a
// failure or a panic take the worker with it. A panicking delivery is logged
// and the message is lost; it is not retried.
//
// Neither record carries the inner sender's own text: a failure is logged
// through [diag.Failure] (reason "send"), and a recovered panic is logged as
// reason "panic" with the recovered value's Go type, never the value itself —
// a custom sender's panic value can quote exactly what its error text can.
//
// The timeout bounds an inner sender that honours context cancellation
// mid-transfer. SMTPSender does. A custom sender that ignores its context can
// occupy a worker for as long as it likes, and this is documented rather than
// defended against: killing a goroutine is not something Go offers.
func (s *QueuedSender) deliver(q queued) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.LogAttrs(q.ctx, slog.LevelError,
				"notify: sender panicked while delivering",
				slog.String("reason", "panic"),
				slog.String("value_type", fmt.Sprintf("%T", r)))
		}
	}()

	ctx, cancel := context.WithTimeout(q.ctx, s.timeout)
	defer cancel()

	if err := s.inner.Send(ctx, q.msg); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError,
			"notify: delivery failed", diag.Failure("send", err)...)
	}
}

// Close stops intake and waits for what is already queued to be delivered,
// waiting no longer than ctx allows. It returns ctx's error if the drain has
// not finished by then; the workers carry on with what is left.
//
// Call it at shutdown, with a context that gives the drain a realistic amount
// of time — the caller's request context is the wrong one, since it is usually
// already over. Calling it twice is safe and the second call returns nil. A
// send after Close returns ErrSenderClosed, and messages still queued when the
// process ends are lost.
func (s *QueuedSender) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()

		return nil
	}

	s.closed = true

	close(s.queue)
	s.mu.Unlock()

	done := make(chan struct{})

	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
