package gorm

import (
	"context"
	"fmt"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/seal"
	"github.com/kartaladev/scrty/signingkey"
)

// NewSigningKeyStore returns a durable signing-key store on db, keeping keys
// in the signing_keys table the migrate package creates.
//
// Each key's private material is sealed with c before it is written and
// opened when it is read, through seal.NewSigningKeyStore, bound to the key's
// id; there is no unsealed variant, and a nil c, typed nil included, is a
// configuration error. The public JWK is stored as given: it is published.
// LoadAll fails as a whole, returning no keys, when any stored key will not
// open.
//
// By default a load re-seals, under c's active key, every key that opened
// under a retired one, with one conditional update per key that replaces the
// stored value only while it still holds the value that was read. A load
// inside a caller's transaction re-seals nothing, since a failed write there
// would abort the caller's transaction. WithResealOnRead(false) turns
// re-sealing off.
//
// Store replaces the key already stored under the same kid, keeping its row,
// as the contract defines. It honours WithTxResolver, WithIDGenerator
// (default id.NewV7Generator, for the rows' primary keys) and
// WithResealOnRead (default on), and refuses any other option.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// key whose kid or algorithm holds either is refused with an error that names
// the field, never the value, and nothing is written. Stored times are UTC,
// truncated to the microsecond.
func NewSigningKeyStore(db *gormdb.DB, c seal.Cipher, opts ...Option) (signingkey.KeyStore, error) {
	cfg, err := newConfig(db, opts, optIDGenerator, optResealOnRead)
	if err != nil {
		return nil, err
	}
	if err := storekit.RequireCipher(c, ErrConfig); err != nil {
		return nil, err
	}

	inner := &signingKeyStore{c: cfg}
	s, err := seal.NewSigningKeyStore(inner, inner, c, seal.WithResealOnRead(cfg.resealOnRead))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return s, nil
}

// signingKeyStore is the unsealed store NewSigningKeyStore wraps, and the
// re-seal port the wrapper writes through. It stores Private as given, which
// is why it is not exported.
type signingKeyStore struct{ c *config }

// Store inserts rec, replacing any key stored under the same kid: one INSERT
// … ON CONFLICT (kid) DO UPDATE, which keeps the stored row's id.
func (s *signingKeyStore) Store(ctx context.Context, rec signingkey.Record) error {
	const op = "store signing key"

	if err := storekit.CheckStorable(
		storekit.Text("key id", rec.Kid), storekit.Text("algorithm", string(rec.Alg)),
	); err != nil {
		return failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	row := signingKeyRow{
		ID:         rowID,
		Kid:        rec.Kid,
		Alg:        string(rec.Alg),
		PrivateKey: storekit.OrEmpty(rec.Private),
		PublicJWK:  storekit.OrEmpty(rec.PublicJWK),
		CreatedAt:  storekit.Time(rec.CreatedAt),
	}
	err = q.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "kid"}},
		DoUpdates: clause.AssignmentColumns([]string{"alg", "private_key", "public_jwk", "created_at"}),
	}).Create(&row).Error
	if err != nil {
		return failed(op, err)
	}

	return nil
}

// LoadAll returns every stored key, oldest first, kid breaking ties: one
// SELECT.
func (s *signingKeyStore) LoadAll(ctx context.Context) ([]signingkey.Record, error) {
	const op = "load signing keys"

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	var rows []signingKeyRow
	if err := q.Order("created_at, kid").Find(&rows).Error; err != nil {
		return nil, failed(op, err)
	}

	var recs []signingkey.Record
	for _, row := range rows {
		recs = append(recs, signingkey.Record{
			Kid:       row.Kid,
			Alg:       signingkey.Alg(row.Alg),
			Private:   row.PrivateKey,
			PublicJWK: row.PublicJWK,
			CreatedAt: row.CreatedAt.UTC(),
		})
	}

	return recs, nil
}

// ResealSigningKey replaces kid's private material with resealed only while
// it still holds old: one conditional UPDATE. Inside a caller's transaction it
// writes nothing.
func (s *signingKeyStore) ResealSigningKey(ctx context.Context, kid string, old, resealed []byte) error {
	return resealWhere[signingKeyRow](ctx, s.c, "re-seal signing key",
		map[string]any{"private_key": resealed}, "kid = ? AND private_key = ?", kid, old)
}

var (
	_ signingkey.KeyStore     = (*signingKeyStore)(nil)
	_ seal.SigningKeyResealer = (*signingKeyStore)(nil)
)
