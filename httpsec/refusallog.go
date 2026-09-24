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

// reportSuppressedRefusals is the reporter a chain installs when the consumer
// supplies none: one record naming the key and how many records it stood for.
//
// There is always a reporter. Without one, the counts for a key that stops
// recurring before its window closes are simply discarded, and an operator
// reading the sampled records would under-count the flood that produced them.
//
// It runs on whichever goroutine's refusal or flush evicted the key, and that
// goroutine's request context has nothing to do with the counts being reported,
// so the record is written without one.
func (c *Chain) reportSuppressedRefusals(key string, suppressed int) {
	c.logger.LogAttrs(context.Background(), slog.LevelWarn, msgRefusalsSuppressed,
		slog.String("key", key),
		slog.Int("suppressed", suppressed))
}
