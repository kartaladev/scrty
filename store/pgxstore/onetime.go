package pgxstore

import (
	"context"
	"errors"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// OneTimeStore keeps one-time tokens in the one_time_tokens table the migrate
// package creates. It implements onetime.Store and onetime.Reaper, and is safe
// for concurrent use.
//
// Consume is one conditional update, so of several callers racing on a token,
// on this process or on another replica, exactly one succeeds; an unknown and
// an already-spent token are both onetime.ErrTokenNotFound, and the first
// consumption time is kept. A database failure is returned wrapped with the
// operation's name, never as that refusal.
type OneTimeStore struct{ c *config }

// NewOneTimeStore returns a durable one-time token store on pool.
//
// The reaper judges "expired" with the store's clock, at the moment it runs. It
// honours WithTxResolver and WithClock (default clock.System()), and refuses
// any other option.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// token whose purpose or subject holds either is refused with an error that
// names the field, never the value, and nothing is written; a count or purge
// by such a value matches nothing. Stored times are UTC, truncated to the
// microsecond.
func NewOneTimeStore(pool *pgxpool.Pool, opts ...Option) (*OneTimeStore, error) {
	c, err := newConfig(pool, opts, optClock)
	if err != nil {
		return nil, err
	}

	return &OneTimeStore{c: c}, nil
}

// Insert stores tok, refusing an identifier already stored.
func (s *OneTimeStore) Insert(ctx context.Context, tok onetime.Token) error {
	const op = "insert one-time token"

	if err := storekit.CheckStorable(
		storekit.Text("purpose", tok.Purpose), storekit.Text("subject", tok.Subject),
	); err != nil {
		return failed(op, err)
	}

	// An unbound token keeps its binding NULL, never an empty value: pgx sends
	// the nil slice as NULL.
	n, err := s.c.exec(ctx, op, pgschema.OneTimeInsert, uuidArg(tok.ID), tok.Purpose, tok.Subject,
		storekit.OrEmpty(tok.SecretHash), tok.BindingHash, storekit.Time(tok.IssuedAt), storekit.Time(tok.ExpiresAt),
		nullTs(tok.ConsumedAt))
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("pgxstore: insert one-time token: the identifier is already in use")
	}

	return nil
}

// FindByID returns the token with this identifier, spent or not, or
// onetime.ErrTokenNotFound.
func (s *OneTimeStore) FindByID(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
	const op = "find one-time token"

	tok := onetime.Token{ID: tokenID}

	var issued, expires time.Time
	var consumed pgtype.Timestamptz
	err := s.c.queryRow(ctx, op, pgschema.OneTimeSelect, []any{uuidArg(tokenID)},
		&tok.Purpose, &tok.Subject, &tok.SecretHash, &tok.BindingHash, &issued, &expires, &consumed)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return nil, onetime.ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}

	if tok.ConsumedAt, err = fromNull(consumed); err != nil {
		return nil, failed(op, err)
	}
	tok.IssuedAt, tok.ExpiresAt = issued.UTC(), expires.UTC()

	return &tok, nil
}

// Consume marks the token consumed at at, only while it is unspent.
func (s *OneTimeStore) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	const op = "consume one-time token"

	n, err := s.c.exec(ctx, op, pgschema.OneTimeConsume, uuidArg(tokenID), storekit.Time(at))
	if err != nil {
		return err
	}
	if n == 0 {
		return onetime.ErrTokenNotFound
	}

	return nil
}

// CountRecentBySubject counts purpose's tokens for subject issued at or after
// since, spent and expired ones included.
func (s *OneTimeStore) CountRecentBySubject(
	ctx context.Context, purpose, subject string, since time.Time,
) (int, error) {
	if !storekit.Storable(purpose, subject) {
		return 0, nil
	}

	return s.c.count(ctx, "count recent one-time tokens", pgschema.OneTimeCountRecent,
		purpose, subject, storekit.Time(since))
}

// InsertWithin stores tok only while fewer than limit of its purpose's tokens
// for its subject were issued at or after since, and reports whether it did. A
// refused insert writes nothing.
//
// The decision is taken under the transaction-scoped advisory lock of tok's
// purpose and subject: the lock, then the count, then the insert, in a READ
// COMMITTED transaction of the store's own, so a racer for the same subject,
// on this process or on another replica, counts only after this one's record
// is committed. Racers for different subjects do not wait for one another.
//
// Inside a caller's transaction the three statements join it, and the lock
// is held until the caller commits or rolls back. A caller's transaction
// stronger than READ COMMITTED is refused with ErrIsolationTooStrong and
// nothing is written: its snapshot would predate the lock, so the count could
// miss a racer's committed record.
func (s *OneTimeStore) InsertWithin(ctx context.Context, tok onetime.Token, since time.Time, limit int) (bool, error) {
	const op = "insert one-time token within a limit"

	if err := storekit.CheckStorable(
		storekit.Text("purpose", tok.Purpose), storekit.Text("subject", tok.Subject),
	); err != nil {
		return false, failed(op, err)
	}
	if limit < 1 {
		return false, nil
	}

	var stored bool
	decide := func(q DBTX) error {
		if _, err := q.Exec(ctx, pgschema.OneTimeLockSubject, tok.Purpose, tok.Subject); err != nil {
			return err
		}
		var n int
		if err := q.QueryRow(ctx, pgschema.OneTimeCountRecent,
			tok.Purpose, tok.Subject, storekit.Time(since)).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return nil
		}
		tag, err := q.Exec(ctx, pgschema.OneTimeInsert, uuidArg(tok.ID), tok.Purpose, tok.Subject,
			storekit.OrEmpty(tok.SecretHash), tok.BindingHash, storekit.Time(tok.IssuedAt),
			storekit.Time(tok.ExpiresAt), nullTs(tok.ConsumedAt))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return storekit.ErrIdentifierInUse
		}
		stored = true

		return nil
	}

	q, ambient, err := s.c.conn(ctx)
	if err != nil {
		return false, failed(op, err)
	}
	if ambient {
		if err = s.c.requireReadCommitted(ctx, q); err == nil {
			err = decide(q)
		}
	} else {
		err = s.c.readCommitted(ctx, func(tx pgxv5.Tx) error { return decide(tx) })
	}
	if err != nil {
		return false, failed(op, err)
	}

	return stored, nil
}

// DeleteExpiredBefore removes purpose's tokens expired by the store's clock
// and issued strictly before retainSince. A zero retainSince is refused with
// onetime.ErrRetainSinceRequired, and nothing is deleted.
func (s *OneTimeStore) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, onetime.ErrRetainSinceRequired
	}
	if !storekit.Storable(purpose) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "purge expired one-time tokens", pgschema.OneTimeDeleteExpiredBefore,
		purpose, storekit.Time(s.c.clock.Now()), storekit.Time(retainSince))

	return int(n), err
}

var (
	_ onetime.Store  = (*OneTimeStore)(nil)
	_ onetime.Reaper = (*OneTimeStore)(nil)
)
