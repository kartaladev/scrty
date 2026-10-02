package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
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
// A record is stored under its own identifier, which must be unique: the
// library's handoff manager mints one per code. It honours WithTxResolver and
// refuses any other option: expiry is judged against the cutoff a purge is
// given, never a clock of the store's.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// record whose token id, user reference, provider, issuer, session id, ID
// token, next location, amr value or acr holds either is refused with an
// error that names the field, never the value, and nothing is written; a
// lookup or consumption by such a token id is oidc.ErrHandoffNotFound. The ID
// token is single-use and short-lived, and is not sealed. Stored times are
// UTC, truncated to the microsecond.
func NewHandoffStore(db *sql.DB, opts ...Option) (*HandoffStore, error) {
	c, err := newConfig(db, opts)
	if err != nil {
		return nil, err
	}

	return &HandoffStore{c: c}, nil
}

// Insert stores rec. A zero rec.ID is refused before any statement runs,
// since it is the row's primary key and the caller's to mint.
func (s *HandoffStore) Insert(ctx context.Context, rec oidc.HandoffRecord) error {
	const op = "insert handoff"

	if err := storekit.CheckID(rec.ID, "handoff"); err != nil {
		return failed(op, err)
	}

	if err := storekit.CheckStorable(
		storekit.Text("token id", rec.TokenID), storekit.Text("user reference", string(rec.UserID)),
		storekit.Text("provider", rec.Provider), storekit.Text("issuer", rec.Issuer),
		storekit.Text("session id", rec.SessionID), storekit.Text("ID token", rec.IDToken),
		storekit.Text("next location", rec.Next),
	); err != nil {
		return failed(op, err)
	}
	if err := storekit.CheckAssurance("", rec.AMR, rec.ACR); err != nil {
		return failed(op, err)
	}
	amr, err := storekit.EncodeAMR(rec.AMR)
	if err != nil {
		return failed(op, err)
	}

	_, err = s.c.exec(ctx, op, pgschema.HandoffInsert, rec.ID, rec.TokenID, storekit.OrEmpty(rec.SecretHash),
		string(rec.UserID), rec.Provider, rec.Issuer, rec.SessionID, rec.IDToken, rec.Next,
		storekit.Time(rec.ExpiresAt), storekit.Time(rec.CreatedAt), nullTsPtr(rec.ConsumedAt),
		amr, rec.ACR)

	return err
}

// FindByTokenID returns the record of tokenID, consumed or not, or
// oidc.ErrHandoffNotFound.
func (s *HandoffStore) FindByTokenID(ctx context.Context, tokenID string) (*oidc.HandoffRecord, error) {
	if !storekit.Storable(tokenID) {
		return nil, oidc.ErrHandoffNotFound
	}

	rec := oidc.HandoffRecord{TokenID: tokenID}
	var (
		user             string
		expires, created time.Time
		consumed         sql.NullTime
		amr              []byte
	)
	err := s.c.queryRow(ctx, "find handoff", pgschema.HandoffSelect, []any{tokenID},
		&rec.ID, &rec.SecretHash, &user, &rec.Provider, &rec.Issuer, &rec.SessionID, &rec.IDToken, &rec.Next,
		&expires, &created, &consumed, &amr, &rec.ACR)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oidc.ErrHandoffNotFound
	}
	if err != nil {
		return nil, err
	}
	if rec.AMR, err = storekit.DecodeAMR(amr); err != nil {
		return nil, failed("find handoff", err)
	}
	rec.UserID, rec.ExpiresAt, rec.CreatedAt, rec.ConsumedAt = identity.UserID(user), expires.UTC(), created.UTC(),
		timePtr(consumed)

	return &rec, nil
}

// Consume marks the record of tokenID consumed at at, only while it is
// unconsumed.
func (s *HandoffStore) Consume(ctx context.Context, tokenID string, at time.Time) error {
	if !storekit.Storable(tokenID) {
		return oidc.ErrHandoffNotFound
	}

	return s.c.execOrRefuse(ctx, "consume handoff", oidc.ErrHandoffNotFound, pgschema.HandoffConsume,
		tokenID, storekit.Time(at))
}

// DeleteExpired removes records that expired strictly before before and
// reports how many it removed. A zero cutoff is refused with
// oidc.ErrRetainSinceRequired, and nothing is deleted.
func (s *HandoffStore) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, oidc.ErrRetainSinceRequired
	}

	n, err := s.c.exec(ctx, "purge expired handoffs", pgschema.HandoffDeleteExpired, storekit.Time(before))

	return int(n), err
}

var _ oidc.HandoffStore = (*HandoffStore)(nil)
