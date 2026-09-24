package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

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
// (WithQueueSize), a 30-second bound on each delivery (WithQueueSendTimeout)
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

// NonBlocking reports true: Send returns once the message is queued.
func (s *QueuedSender) NonBlocking() bool { return true }

// Workers reports how many deliveries can run at once. Default: 2.
func (s *QueuedSender) Workers() int { return s.workers }

// QueueSize reports how many messages can wait for a worker. Default: 256.
func (s *QueuedSender) QueueSize() int { return s.size }

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
// The timeout bounds an inner sender that honours context cancellation
// mid-transfer. SMTPSender does. A custom sender that ignores its context can
// occupy a worker for as long as it likes, and this is documented rather than
// defended against: killing a goroutine is not something Go offers.
func (s *QueuedSender) deliver(q queued) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.LogAttrs(q.ctx, slog.LevelError,
				"notify: sender panicked while delivering",
				slog.Any("panic", r))
		}
	}()

	ctx, cancel := context.WithTimeout(q.ctx, s.timeout)
	defer cancel()

	if err := s.inner.Send(ctx, q.msg); err != nil {
		s.logger.LogAttrs(ctx, slog.LevelError,
			"notify: delivery failed", slog.Any("error", err))
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
