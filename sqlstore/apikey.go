package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
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
func NewAPIKeyStore(db *sql.DB, opts ...Option) (*APIKeyStore, error) {
	c, err := newConfig(db, opts)
	if err != nil {
		return nil, err
	}

	return &APIKeyStore{c: c}, nil
}

// Put stores rec.
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

	_, err = s.c.exec(ctx, op, pgschema.APIKeyInsert, rec.ID, string(rec.Principal), rec.Name, string(scopes),
		storekit.OrEmpty(rec.SecretDigest), nullTsPtr(rec.ExpiresAt), nullTsPtr(rec.RevokedAt),
		nullTsPtr(rec.LastUsedAt), storekit.Time(rec.CreatedAt))

	return err
}

// Get returns the key with this identifier, or apikey.ErrKeyNotFound.
func (s *APIKeyStore) Get(ctx context.Context, keyID id.ID) (apikey.Key, error) {
	const op = "get API key"

	var row apiKeyRow
	err := s.c.queryRow(ctx, op, pgschema.APIKeySelect, []any{keyID}, row.dest()...)
	if errors.Is(err, sql.ErrNoRows) {
		return apikey.Key{}, apikey.ErrKeyNotFound
	}
	if err != nil {
		return apikey.Key{}, err
	}

	k, err := row.key()
	if err != nil {
		return apikey.Key{}, failed(op, err)
	}

	return k, nil
}

// Revoke marks the key revoked at at, keeping an earlier revocation.
func (s *APIKeyStore) Revoke(ctx context.Context, keyID id.ID, at time.Time) error {
	return s.c.execOrRefuse(ctx, "revoke API key", apikey.ErrKeyNotFound, pgschema.APIKeyRevoke,
		keyID, storekit.Time(at))
}

// TouchLastUsed records a successful verification of the key at at.
func (s *APIKeyStore) TouchLastUsed(ctx context.Context, keyID id.ID, at time.Time) error {
	return s.c.execOrRefuse(ctx, "record API key use", apikey.ErrKeyNotFound, pgschema.APIKeyTouch,
		keyID, storekit.Time(at))
}

// List returns every key of principal, oldest first.
func (s *APIKeyStore) List(ctx context.Context, principal identity.UserID) ([]apikey.Key, error) {
	const op = "list API keys"

	if !storekit.Storable(string(principal)) {
		return []apikey.Key{}, nil
	}
	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	rows, err := q.QueryContext(ctx, pgschema.APIKeyList, string(principal))
	if err != nil {
		return nil, failed(op, err)
	}
	defer func() { _ = rows.Close() }()

	keys := []apikey.Key{}
	for rows.Next() {
		var row apiKeyRow
		if err := rows.Scan(row.dest()...); err != nil {
			return nil, failed(op, err)
		}
		k, err := row.key()
		if err != nil {
			return nil, failed(op, err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, failed(op, err)
	}

	return keys, nil
}

// apiKeyRow is one api_keys row as APIKeySelect and APIKeyList read it.
type apiKeyRow struct {
	k                      apikey.Key
	principal, scopes      string
	expires, revoked, used sql.NullTime
	created                time.Time
}

// dest is where a scan of the row's columns goes, in the statements' order.
func (r *apiKeyRow) dest() []any {
	return []any{&r.k.ID, &r.principal, &r.k.Name, &r.scopes, &r.k.SecretDigest, &r.expires, &r.revoked, &r.used,
		&r.created}
}

// key is the key the scanned row holds.
func (r *apiKeyRow) key() (apikey.Key, error) {
	k := r.k
	if err := json.Unmarshal([]byte(r.scopes), &k.Scopes); err != nil {
		return apikey.Key{}, errors.New("the stored scopes are not a JSON array of strings")
	}
	k.Principal = identity.UserID(r.principal)
	k.ExpiresAt, k.RevokedAt, k.LastUsedAt = timePtr(r.expires), timePtr(r.revoked), timePtr(r.used)
	k.CreatedAt = r.created.UTC()

	return k, nil
}

var _ apikey.Store = (*APIKeyStore)(nil)
