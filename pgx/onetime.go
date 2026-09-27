package pgx

import (
	"context"
	"errors"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
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
// The reaper judges "expired" with the store's clock, at the moment it runs.
// It honours WithTxResolver and WithClock (default time.Now), and refuses any
// other option.
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
		return errors.New("pgx: insert one-time token: the identifier is already in use")
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
		purpose, storekit.Time(s.c.now()), storekit.Time(retainSince))

	return int(n), err
}

var (
	_ onetime.Store  = (*OneTimeStore)(nil)
	_ onetime.Reaper = (*OneTimeStore)(nil)
)
