package pgxstore

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/pkg/id"
)

// recordingTx is a DBTX that keeps the statement it was last asked to run.
type recordingTx struct{ seen *string }

func (r recordingTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	*r.seen = sql
	return pgconn.CommandTag{}, nil
}

func (r recordingTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	*r.seen = sql
	return nil, nil
}

func (r recordingTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	*r.seen = sql
	return nil
}

// TestLineageSeam holds the binding of a session store to the lineage table: no option
// sets it, only the lineage constructor does, and it rewrites every kind of statement.
func TestLineageSeam(t *testing.T) {
	t.Parallel()

	pool := &pgxpool.Pool{}
	const statement = "SELECT 1 FROM sessions WHERE id_digest = $1"

	t.Run("no option binds a store to the lineage table", func(t *testing.T) {
		t.Parallel()

		c, err := newConfig(pool, []Option{
			WithTxResolver(func(context.Context) (pgx.Tx, bool) { return nil, false }),
			WithIDGenerator(id.NewV7Generator()),
			WithClock(clockwork.NewFakeClock()),
			WithResealOnRead(true),
		}, optIDGenerator, optClock, optResealOnRead)
		require.NoError(t, err)
		assert.False(t, c.lineage)

		var seen string
		_, err = c.boundTo(recordingTx{&seen}).Exec(t.Context(), statement)
		require.NoError(t, err)
		assert.Equal(t, statement, seen, "a session store's statements are left as they are")
	})

	t.Run("the lineage constructor binds every kind of statement", func(t *testing.T) {
		t.Parallel()

		c := &config{base: pool, lineage: true}
		const want = "SELECT 1 FROM op_refresh_tokens WHERE id_digest = $1"
		var seen string
		q := c.boundTo(recordingTx{&seen})

		_, err := q.Exec(t.Context(), statement)
		require.NoError(t, err)
		assert.Equal(t, want, seen)

		seen = ""
		_, err = q.Query(t.Context(), statement) //nolint:rowserrcheck // a recording double returns no rows
		require.NoError(t, err)
		assert.Equal(t, want, seen)

		seen = ""
		_ = q.QueryRow(t.Context(), statement)
		assert.Equal(t, want, seen)
	})
}
