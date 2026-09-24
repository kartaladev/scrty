package notify

import (
	"log/slog"
	"time"
)

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

// WithQueueSize replaces how many messages may wait for a worker. The default
// is 256. Zero or less is a configuration error: it would drop every message
// that did not find an idle worker at that instant.
//
// The queue is memory, not storage. Sizing it larger buys tolerance of a
// longer outage and nothing else — a crash still loses whatever is in it.
func WithQueueSize(n int) QueuedOption { return func(c *queuedConfig) { c.size = n } }

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
// wrapped sender. None of them carries the message body or subject.
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
