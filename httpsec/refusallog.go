package httpsec

import (
	"context"
	"log/slog"
	"time"

	"github.com/kartaladev/scrty/pkg/logsample"
)

// msgRefusalsSuppressed is the record the default reporter writes for a key
// whose counts are about to be discarded.
const msgRefusalsSuppressed = "httpsec: refusal logs suppressed"

// logSampled writes at most one record per key per window, carrying the count
// it stood in for.
//
// A nil sampler, or one built with an interval of zero or less, writes every
// record: sampling is a defence against a flood filling a disk, and a consumer
// who would rather have every line says so through WithRefusalLogInterval.
func logSampled(
	ctx context.Context,
	s *logsample.Sampler,
	log *slog.Logger,
	level slog.Level,
	now time.Time,
	key, msg string,
	attrs ...slog.Attr,
) {
	write, suppressed := s.Allow(key, now)
	if !write {
		return
	}

	if suppressed > 0 {
		// Attached only when it says something. Padding every ordinary record
		// with suppressed=0 costs an operator a column that is almost always
		// noise, and hides the records where the count matters.
		attrs = append(attrs, slog.Int("suppressed", suppressed))
	}

	log.LogAttrs(ctx, level, msg, attrs...)
}

// refusalLogReporter is the reporter the chain's samplers report to: the
// consumer's (WithRefusalLogReporter), or else the default summary record
// through the chain's logger.
//
// It is resolved after every option has been applied, because which reporter
// and which logger that is is not settled until then. The source guards the
// chain builds report through it too, so a consumer's reporter receives their
// throttled-source counts like the chain's own.
func (c *config) refusalLogReporter() func(key string, suppressed int) {
	if c.refusalReporter != nil {
		return c.refusalReporter
	}

	return c.reportSuppressedRefusals
}

// reportSuppressedRefusals is the default reporter before the chain exists:
// the same summary record, through the logger the options settled on.
func (c *config) reportSuppressedRefusals(key string, suppressed int) {
	summariseRefusals(c.logger, key, suppressed)
}

// summariseRefusals writes the default summary record for key.
//
// It runs on whichever goroutine's refusal or flush evicted the key, and that
// goroutine's request context has nothing to do with the counts being reported,
// so the record is written without one.
func summariseRefusals(log *slog.Logger, key string, suppressed int) {
	log.LogAttrs(context.Background(), slog.LevelWarn, msgRefusalsSuppressed,
		slog.String("key", key),
		slog.Int("suppressed", suppressed))
}
