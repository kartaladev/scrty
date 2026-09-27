package pgx

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

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

// NewAPIKeyStore returns a durable API key store on pool.
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
func NewAPIKeyStore(pool *pgxpool.Pool, opts ...Option) (*APIKeyStore, error) {
	c, err := newConfig(pool, opts)
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

	// The marshalled scopes are sent as a string, which pgx passes to jsonb as
	// is rather than marshalling it again.
	_, err = s.c.exec(ctx, op, pgschema.APIKeyInsert, uuidArg(rec.ID), string(rec.Principal), rec.Name,
		string(scopes), storekit.OrEmpty(rec.SecretDigest), nullTsPtr(rec.ExpiresAt), nullTsPtr(rec.RevokedAt),
		nullTsPtr(rec.LastUsedAt), storekit.Time(rec.CreatedAt))

	return err
}

// Get returns the key with this identifier, or apikey.ErrKeyNotFound.
func (s *APIKeyStore) Get(ctx context.Context, keyID id.ID) (apikey.Key, error) {
	const op = "get API key"

	var row apiKeyRow
	err := s.c.queryRow(ctx, op, pgschema.APIKeySelect, []any{uuidArg(keyID)}, row.dest()...)
	if errors.Is(err, pgxv5.ErrNoRows) {
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
		uuidArg(keyID), storekit.Time(at))
}

// TouchLastUsed records a successful verification of the key at at.
func (s *APIKeyStore) TouchLastUsed(ctx context.Context, keyID id.ID, at time.Time) error {
	return s.c.execOrRefuse(ctx, "record API key use", apikey.ErrKeyNotFound, pgschema.APIKeyTouch,
		uuidArg(keyID), storekit.Time(at))
}

// List returns every key of principal, oldest first.
func (s *APIKeyStore) List(ctx context.Context, principal identity.UserID) ([]apikey.Key, error) {
	if !storekit.Storable(string(principal)) {
		return []apikey.Key{}, nil
	}

	keys := []apikey.Key{}
	err := s.c.query(ctx, "list API keys", pgschema.APIKeyList, []any{string(principal)}, func(rows pgxv5.Rows) error {
		var row apiKeyRow
		if err := rows.Scan(row.dest()...); err != nil {
			return err
		}
		k, err := row.key()
		if err != nil {
			return err
		}
		keys = append(keys, k)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// apiKeyRow is one api_keys row as APIKeySelect and APIKeyList read it.
type apiKeyRow struct {
	k                      apikey.Key
	keyID                  pgtype.UUID
	principal, scopes      string
	expires, revoked, used pgtype.Timestamptz
	created                time.Time
}

// dest is where a scan of the row's columns goes, in the statements' order.
func (r *apiKeyRow) dest() []any {
	return []any{&r.keyID, &r.principal, &r.k.Name, &r.scopes, &r.k.SecretDigest, &r.expires, &r.revoked, &r.used,
		&r.created}
}

// key is the key the scanned row holds.
func (r *apiKeyRow) key() (apikey.Key, error) {
	k := r.k
	var err error
	if k.ID, err = scanID(r.keyID); err != nil {
		return apikey.Key{}, err
	}
	if err := json.Unmarshal([]byte(r.scopes), &k.Scopes); err != nil {
		return apikey.Key{}, errors.New("the stored scopes are not a JSON array of strings")
	}
	if k.ExpiresAt, err = timePtr(r.expires); err != nil {
		return apikey.Key{}, err
	}
	if k.RevokedAt, err = timePtr(r.revoked); err != nil {
		return apikey.Key{}, err
	}
	if k.LastUsedAt, err = timePtr(r.used); err != nil {
		return apikey.Key{}, err
	}
	k.Principal = identity.UserID(r.principal)
	k.CreatedAt = r.created.UTC()

	return k, nil
}

var _ apikey.Store = (*APIKeyStore)(nil)
