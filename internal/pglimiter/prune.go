package pglimiter

import (
	"context"
	"fmt"
	"time"

	"github.com/kartaladev/scrty/internal/diag"
	"github.com/kartaladev/scrty/internal/pgschema"
)

// DefaultPruneBatchSize is how many keys one prune batch deletes at most when
// no option sets it.
const DefaultPruneBatchSize = 1000

// Prune deletes idle keys in batches of cfg.PruneBatchSize, each its own
// statement and so its own transaction, and returns how many keys the batches
// that committed removed. The time is read once, before the first batch: the
// configured clock, or the database's. It stops on a short batch, on an ended
// ctx, or on the first failed batch; the count it returns with an error is a
// lower bound, every key of it removed. Its errors start with prefix, and none
// repeats the server's text.
func Prune(ctx context.Context, r Runner, prefix string, cfg Config) (int, error) {
	now := Now(cfg.Clock)
	if now == nil {
		var t time.Time
		if err := r.QueryRow(ctx, pgschema.LimiterClock).Scan(&t); err != nil {
			return 0, diag.Wrap(err, prefix+": rate-limit prune: the database clock could not be read")
		}
		now = t
	}

	total := 0
	for {
		res, err := r.Exec(ctx, pgschema.LimiterPrune, now, cfg.PruneBatchSize)
		if err != nil {
			return total, diag.Wrap(err, prefix+": rate-limit prune: a batch could not be deleted")
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, diag.Wrap(err, prefix+": rate-limit prune: a batch's row count could not be read")
		}
		total += int(n)
		if n < int64(cfg.PruneBatchSize) {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("%s: rate-limit prune: stopped after %d keys: %w", prefix, total, err)
		}
	}
}
