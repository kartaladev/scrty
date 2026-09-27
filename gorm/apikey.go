package gorm

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

// APIKeyStore keeps API keys in the api_keys table the migrate package
// creates. It implements apikey.Store, and is safe for concurrent use.
//
// A key is stored under its own identifier; only the secret's digest is
// kept. Revoke is one statement that keeps the first revocation time, so a
// later revocation never rewrites when the key stopped being accepted. Get
// and List judge no expiry or revocation: that is the manager's to decide.
type APIKeyStore struct{ c *config }

// NewAPIKeyStore returns a durable API key store on db.
//
// It honours WithTxResolver and refuses any other option: a key arrives with
// its own identifier and every instant comes from the caller.
//
// Limits, stated: PostgreSQL text and jsonb cannot hold a NUL byte or invalid
// UTF-8. A key whose principal, name or scopes hold either is refused with an
// error that names the field, never the value, and nothing is written; the
// value is never altered. Listing such a principal matches nothing. A key
// with no scopes, nil or empty, loads with an empty list. Stored times are
// UTC, truncated to the microsecond.
func NewAPIKeyStore(db *gormdb.DB, opts ...Option) (*APIKeyStore, error) {
	c, err := newConfig(db, opts)
	if err != nil {
		return nil, err
	}

	return &APIKeyStore{c: c}, nil
}

// Put stores rec: one INSERT. An identifier already stored is a failed
// statement, never an overwrite.
func (s *APIKeyStore) Put(ctx context.Context, rec apikey.Key) error {
	const op = "store API key"

	fields := []storekit.Field{storekit.Text("principal", string(rec.Principal)), storekit.Text("name", rec.Name)}
	for _, scope := range rec.Scopes {
		fields = append(fields, storekit.Text("scope", scope))
	}
	if err := storekit.CheckStorable(fields...); err != nil {
		return failed(op, err)
	}
	scopes, err := json.Marshal(storekit.OrNone(rec.Scopes))
	if err != nil {
		return failed(op, err)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	err = q.Create(&apiKeyRow{
		ID:           rec.ID,
		UserID:       string(rec.Principal),
		Name:         rec.Name,
		Scopes:       string(scopes),
		SecretDigest: storekit.OrEmpty(rec.SecretDigest),
		ExpiresAt:    tsPtr(rec.ExpiresAt),
		RevokedAt:    tsPtr(rec.RevokedAt),
		LastUsedAt:   tsPtr(rec.LastUsedAt),
		CreatedAt:    storekit.Time(rec.CreatedAt),
	}).Error
	if err != nil {
		return failed(op, err)
	}

	return nil
}

// Get returns the key with this identifier, revoked and expired ones
// included, or apikey.ErrKeyNotFound: one SELECT.
func (s *APIKeyStore) Get(ctx context.Context, keyID id.ID) (apikey.Key, error) {
	const op = "get API key"

	row, found, err := takeWhere[apiKeyRow](ctx, s.c, op, "id = ?", keyID)
	if err != nil {
		return apikey.Key{}, err
	}
	if !found {
		return apikey.Key{}, apikey.ErrKeyNotFound
	}

	k, err := row.key()
	if err != nil {
		return apikey.Key{}, failed(op, err)
	}

	return k, nil
}

// Revoke marks the key revoked at at, keeping an earlier revocation: one
// UPDATE … SET revoked_at = COALESCE(revoked_at, ?), whose zero rows affected
// is apikey.ErrKeyNotFound.
func (s *APIKeyStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) error {
	return updateOrRefuse[apiKeyRow](ctx, s.c, "revoke API key", apikey.ErrKeyNotFound,
		map[string]any{"revoked_at": gormdb.Expr("COALESCE(revoked_at, ?)", storekit.Time(at))}, "id = ?", keyID)
}

// TouchLastUsed records a successful verification of the key at at: one
// UPDATE, whose zero rows affected is apikey.ErrKeyNotFound.
func (s *APIKeyStore) TouchLastUsed(ctx context.Context, keyID id.ID, at time.Time) error {
	return updateOrRefuse[apiKeyRow](ctx, s.c, "record API key use", apikey.ErrKeyNotFound,
		map[string]any{"last_used_at": storekit.Time(at)}, "id = ?", keyID)
}

// List returns every key of principal, oldest first, the id breaking ties:
// one SELECT.
func (s *APIKeyStore) List(ctx context.Context, principal identity.UserID) ([]apikey.Key, error) {
	const op = "list API keys"

	if !storekit.Storable(string(principal)) {
		return []apikey.Key{}, nil
	}
	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	var rows []apiKeyRow
	if err := q.Where("user_id = ?", string(principal)).Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, failed(op, err)
	}

	keys := make([]apikey.Key, 0, len(rows))
	for _, row := range rows {
		k, err := row.key()
		if err != nil {
			return nil, failed(op, err)
		}
		keys = append(keys, k)
	}

	return keys, nil
}

// key is the key r holds.
func (r *apiKeyRow) key() (apikey.Key, error) {
	var scopes []string
	if err := json.Unmarshal([]byte(r.Scopes), &scopes); err != nil {
		return apikey.Key{}, errors.New("the stored scopes are not a JSON array of strings")
	}

	return apikey.Key{
		ID:           r.ID,
		Principal:    identity.UserID(r.UserID),
		Name:         r.Name,
		Scopes:       scopes,
		SecretDigest: r.SecretDigest,
		ExpiresAt:    utcPtr(r.ExpiresAt),
		RevokedAt:    utcPtr(r.RevokedAt),
		LastUsedAt:   utcPtr(r.LastUsedAt),
		CreatedAt:    r.CreatedAt.UTC(),
	}, nil
}

var _ apikey.Store = (*APIKeyStore)(nil)
