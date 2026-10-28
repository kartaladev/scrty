package pgxstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/test"
	"github.com/kartaladev/scrty/test/internal/storefix"
	"github.com/kartaladev/scrty/test/storetest"
)

// isolationBrokenVar names the environment variable that selects the one
// broken variant TestBrokenIsolationStore runs.
const isolationBrokenVar = "PGXSTORE_ISOLATION_BROKEN"

// isolationBrokenVariants are stores that run their statements at the
// database default instead of READ COMMITTED, which the isolation suite must
// catch. The conforming stores passing it, in
// TestIsolation_RepeatableReadDefault, shows these fail for what they
// inherit and not for something else about the fixture.
var isolationBrokenVariants = []storefix.BrokenVariant{
	{
		Name: "streak-inherits-default",
		Run: func(t *testing.T) {
			f, pool := isolationFixture(t)
			f.Streaks = func(t *testing.T) policy.FailureStreakStore {
				s, err := pgxstore.NewAttemptStore(pool)
				require.NoError(t, err)
				return inheritingStreaks{AttemptStore: s, pool: pool}
			}
			t.Run("pgx", func(t *testing.T) { storetest.RunIsolationSuite(t, f) })
		},
		FailsCase: "concurrent failures of one username all count",
	},
	{
		Name: "codes-inherit-default",
		Run: func(t *testing.T) {
			f, pool := isolationFixture(t)
			f.RecoveryCodes = func(t *testing.T) recovery.CodeStore {
				s, err := pgxstore.NewRecoveryCodeStore(pool)
				require.NoError(t, err)
				return inheritingCodes{RecoveryCodeStore: s, pool: pool}
			}
			t.Run("pgx", func(t *testing.T) { storetest.RunIsolationSuite(t, f) })
		},
		FailsCase: "of two overlapping saved-code replacements, only the later set remains",
	},
}

// inheritingStreaks adds streak failures as the store did before it pinned
// READ COMMITTED: one autocommit statement on the pool, at the database
// default, or in the caller's transaction whatever its isolation.
type inheritingStreaks struct {
	*pgxstore.AttemptStore

	pool *pgxpool.Pool
}

func (s inheritingStreaks) AddStreakFailure(
	ctx context.Context, username string, at, since time.Time, limit int,
) (policy.FailureStreak, bool, error) {
	q := handle(ctx, s.pool)
	for range pgschema.StreakAddMaxRuns {
		rowID, err := id.NewV7Generator().NewID()
		if err != nil {
			return policy.FailureStreak{}, false, err
		}
		var (
			got     policy.FailureStreak
			heldAt  pgtype.Timestamptz
			setHold bool
		)
		err = q.QueryRow(ctx, pgschema.StreakAdd, uuidOf(rowID), username, at, since, limit).
			Scan(&got.Failures, &got.Newest, &heldAt, &setHold)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		return got, setHold, err
	}
	return policy.FailureStreak{}, false, errors.New("streak contended")
}

// inheritingCodes replaces saved-code sets as the store did before it pinned
// READ COMMITTED: in a transaction begun at the database default, or in the
// caller's transaction whatever its isolation.
type inheritingCodes struct {
	*pgxstore.RecoveryCodeStore

	pool *pgxpool.Pool
}

func (s inheritingCodes) ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	replace := func(q querier) error {
		if _, err := q.Exec(ctx, pgschema.RecoveryCodeLockUser, string(user)); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, pgschema.RecoveryCodeDeleteUser, string(user)); err != nil {
			return err
		}
		for _, h := range hashes {
			rowID, err := id.NewV7Generator().NewID()
			if err != nil {
				return err
			}
			if _, err := q.Exec(ctx, pgschema.RecoveryCodeInsert, uuidOf(rowID), string(user), h,
				storekit.Time(at)); err != nil {
				return err
			}
		}
		return nil
	}

	if tx, ok := ctx.Value(callerTxKey{}).(pgx.Tx); ok {
		return replace(tx)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := replace(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// querier is what the broken stores run statements on: the pool or a
// transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// handle is the caller's transaction the fixture attached to ctx, or pool.
func handle(ctx context.Context, pool *pgxpool.Pool) querier {
	if tx, ok := ctx.Value(callerTxKey{}).(pgx.Tx); ok {
		return tx
	}
	return pool
}

// uuidOf is an identifier as a PostgreSQL uuid.
func uuidOf(v id.ID) pgtype.UUID { return pgtype.UUID{Bytes: v, Valid: true} }

// TestBrokenIsolationStore runs the broken variant named by the environment,
// and is the child half of TestIsolationSuiteCatchesStoresInheritingDefault.
// Without a variant named it skips.
func TestBrokenIsolationStore(t *testing.T) {
	storefix.RunBrokenChild(t, isolationBrokenVar, "TestIsolationSuiteCatchesStoresInheritingDefault",
		isolationBrokenVariants)
}

// TestIsolationSuiteCatchesStoresInheritingDefault checks that the isolation
// suite fails a store that runs at the database default instead of READ
// COMMITTED, at the case guarding the guarantee it loses. Each variant runs
// in its own process, because a failing suite reports through its own
// *testing.T and would fail this test with it.
func TestIsolationSuiteCatchesStoresInheritingDefault(t *testing.T) {
	t.Parallel()

	// The children each want PostgreSQL: start the one server they will share.
	test.EnsureTestPostgresServer(t)
	storefix.CatchBrokenVariants(t, isolationBrokenVar, "TestBrokenIsolationStore", "pgx", isolationBrokenVariants)
}
