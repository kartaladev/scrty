package gorm

import (
	"context"
	"time"

	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// HandoffStore keeps issued OIDC handoff codes in the oidc_handoffs table the
// migrate package creates. It implements oidc.HandoffStore, and is safe for
// concurrent use.
//
// Only the digest of a code's secret is stored. Consume is one conditional
// update, so of callers racing on a record, on this process or on another
// replica, exactly one succeeds; an unknown record, an already-consumed one
// and an empty token id are all oidc.ErrHandoffNotFound, and the first
// consumption time is kept.
type HandoffStore struct{ c *config }

// NewHandoffStore returns a durable handoff store on db.
//
// A record is stored under its own identifier, which must be unique and
// non-zero: the library's handoff manager mints one per code. It honours
// WithTxResolver and refuses any other option: expiry is judged against the
// cutoff a purge is given, never a clock of the store's.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// record whose token id, user reference, provider, issuer, session id, ID
// token or next location holds either is refused with an error that names
// the field, never the value, and nothing is written; a lookup or
// consumption by such a token id is oidc.ErrHandoffNotFound. The ID token is
// single-use and short-lived, and is not sealed. Stored times are UTC,
// truncated to the microsecond.
func NewHandoffStore(db *gormdb.DB, opts ...Option) (*HandoffStore, error) {
	c, err := newConfig(db, opts)
	if err != nil {
		return nil, err
	}

	return &HandoffStore{c: c}, nil
}

// Insert stores rec: one INSERT. A zero rec.ID is refused before any
// statement runs, since it is the row's primary key and the caller's to mint.
func (s *HandoffStore) Insert(ctx context.Context, rec oidc.HandoffRecord) error {
	const op = "insert handoff"

	if rec.ID.IsZero() {
		return errZeroID(op, "handoff")
	}
	if err := checkStorable(op,
		textField{"token id", rec.TokenID}, textField{"user reference", string(rec.UserID)},
		textField{"provider", rec.Provider}, textField{"issuer", rec.Issuer},
		textField{"session id", rec.SessionID}, textField{"ID token", rec.IDToken},
		textField{"next location", rec.Next},
	); err != nil {
		return err
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	err = q.Create(&handoffRow{
		ID:         rec.ID,
		TokenID:    rec.TokenID,
		SecretHash: orEmpty(rec.SecretHash),
		UserID:     string(rec.UserID),
		Provider:   rec.Provider,
		Issuer:     rec.Issuer,
		SessionID:  rec.SessionID,
		IDToken:    rec.IDToken,
		Next:       rec.Next,
		ExpiresAt:  ts(rec.ExpiresAt),
		CreatedAt:  ts(rec.CreatedAt),
		ConsumedAt: tsPtr(rec.ConsumedAt),
	}).Error
	if err != nil {
		return failed(op, err)
	}

	return nil
}

// FindByTokenID returns the record of tokenID, consumed or not, or
// oidc.ErrHandoffNotFound: one SELECT. An empty token id matches nothing.
func (s *HandoffStore) FindByTokenID(ctx context.Context, tokenID string) (*oidc.HandoffRecord, error) {
	const op = "find handoff"

	if !storable(tokenID) {
		return nil, oidc.ErrHandoffNotFound
	}

	row, found, err := takeWhere[handoffRow](ctx, s.c, op, "token_id = ? AND token_id <> ''", tokenID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, oidc.ErrHandoffNotFound
	}

	return &oidc.HandoffRecord{
		ID:         row.ID,
		TokenID:    row.TokenID,
		SecretHash: row.SecretHash,
		UserID:     identity.UserID(row.UserID),
		Provider:   row.Provider,
		Issuer:     row.Issuer,
		SessionID:  row.SessionID,
		IDToken:    row.IDToken,
		Next:       row.Next,
		ExpiresAt:  row.ExpiresAt.UTC(),
		CreatedAt:  row.CreatedAt.UTC(),
		ConsumedAt: utcPtr(row.ConsumedAt),
	}, nil
}

// Consume marks the record of tokenID consumed at at, only while it is
// unconsumed: one conditional UPDATE, whose zero rows affected is
// oidc.ErrHandoffNotFound. An empty token id matches nothing.
func (s *HandoffStore) Consume(ctx context.Context, tokenID string, at time.Time) error {
	if !storable(tokenID) {
		return oidc.ErrHandoffNotFound
	}

	return updateOrRefuse[handoffRow](ctx, s.c, "consume handoff", oidc.ErrHandoffNotFound,
		map[string]any{"consumed_at": ts(at)}, "token_id = ? AND token_id <> '' AND consumed_at IS NULL", tokenID)
}

// DeleteExpired removes records that expired strictly before before and
// reports how many it removed: one DELETE. A zero cutoff is refused with
// oidc.ErrRetainSinceRequired, and nothing is deleted.
func (s *HandoffStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, oidc.ErrRetainSinceRequired
	}

	return deleteWhere[handoffRow](ctx, s.c, "purge expired handoffs", "expires_at < ?", ts(before))
}

var _ oidc.HandoffStore = (*HandoffStore)(nil)
