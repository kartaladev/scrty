package gorm

import (
	"context"
	"errors"
	"time"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

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

// NewOneTimeStore returns a durable one-time token store on db.
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
func NewOneTimeStore(db *gormdb.DB, opts ...Option) (*OneTimeStore, error) {
	c, err := newConfig(db, opts, optClock)
	if err != nil {
		return nil, err
	}

	return &OneTimeStore{c: c}, nil
}

// Insert stores tok, refusing an identifier already stored: one INSERT … ON
// CONFLICT (id) DO NOTHING, whose zero rows affected is the refusal.
func (s *OneTimeStore) Insert(ctx context.Context, tok onetime.Token) error {
	const op = "insert one-time token"

	if err := storekit.CheckStorable(
		storekit.Text("purpose", tok.Purpose), storekit.Text("subject", tok.Subject),
	); err != nil {
		return failed(op, err)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	row := oneTimeTokenRow{
		ID:         tok.ID,
		Purpose:    tok.Purpose,
		Subject:    tok.Subject,
		SecretHash: storekit.OrEmpty(tok.SecretHash),
		// An unbound token keeps its binding NULL, never an empty value.
		BindingHash: tok.BindingHash,
		IssuedAt:    storekit.Time(tok.IssuedAt),
		ExpiresAt:   storekit.Time(tok.ExpiresAt),
		ConsumedAt:  nullTs(tok.ConsumedAt),
	}
	res := q.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoNothing: true}).Create(&row)
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		return errors.New("gorm: insert one-time token: the identifier is already in use")
	}

	return nil
}

// FindByID returns the token with this identifier, spent or not, or
// onetime.ErrTokenNotFound.
func (s *OneTimeStore) FindByID(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
	const op = "find one-time token"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	var row oneTimeTokenRow
	err = q.Where("id = ?", tokenID).Take(&row).Error
	if errors.Is(err, gormdb.ErrRecordNotFound) {
		return nil, onetime.ErrTokenNotFound
	}
	if err != nil {
		return nil, failed(op, err)
	}

	return &onetime.Token{
		ID:          row.ID,
		Purpose:     row.Purpose,
		Subject:     row.Subject,
		SecretHash:  row.SecretHash,
		BindingHash: row.BindingHash,
		IssuedAt:    row.IssuedAt.UTC(),
		ExpiresAt:   row.ExpiresAt.UTC(),
		ConsumedAt:  fromNull(row.ConsumedAt),
	}, nil
}

// Consume marks the token consumed at at, only while it is unspent: one
// UPDATE … WHERE id = ? AND consumed_at IS NULL, whose zero rows affected is
// onetime.ErrTokenNotFound.
func (s *OneTimeStore) Consume(ctx context.Context, tokenID id.ID, at time.Time) error {
	const op = "consume one-time token"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	res := q.Model(&oneTimeTokenRow{}).Where("id = ? AND consumed_at IS NULL", tokenID).
		Update("consumed_at", storekit.Time(at))
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		return onetime.ErrTokenNotFound
	}

	return nil
}

// CountRecentBySubject counts purpose's tokens for subject issued at or after
// since, spent and expired ones included.
func (s *OneTimeStore) CountRecentBySubject(
	ctx context.Context, purpose, subject string, since time.Time,
) (int, error) {
	const op = "count recent one-time tokens"

	if !storekit.Storable(purpose, subject) {
		return 0, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	var n int64
	err = q.Model(&oneTimeTokenRow{}).
		Where("purpose = ? AND subject = ? AND issued_at >= ?", purpose, subject, storekit.Time(since)).
		Count(&n).Error
	if err != nil {
		return 0, failed(op, err)
	}

	return int(n), nil
}

// DeleteExpiredBefore removes purpose's tokens expired by the store's clock
// and issued strictly before retainSince. A zero retainSince is refused with
// onetime.ErrRetainSinceRequired, and nothing is deleted.
func (s *OneTimeStore) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	const op = "purge expired one-time tokens"

	if retainSince.IsZero() {
		return 0, onetime.ErrRetainSinceRequired
	}
	if !storekit.Storable(purpose) {
		return 0, nil
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return 0, failed(op, err)
	}
	res := q.Where("purpose = ? AND expires_at <= ? AND issued_at < ?",
		purpose, storekit.Time(s.c.now()), storekit.Time(retainSince)).
		Delete(&oneTimeTokenRow{})
	if res.Error != nil {
		return 0, failed(op, res.Error)
	}

	return int(res.RowsAffected), nil
}

var (
	_ onetime.Store  = (*OneTimeStore)(nil)
	_ onetime.Reaper = (*OneTimeStore)(nil)
)
