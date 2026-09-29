package gorm

import (
	"bytes"
	"context"
	"errors"

	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

var (
	errUserReference = errors.New("the user reference is not a UUID in canonical lowercase text")
	errNegativeRead  = errors.New("the number of entries to read is negative")
	errNegativeKeep  = errors.New("the number of entries to keep is negative")
)

// RecentPasswords returns up to n of the user's retired password hashes,
// newest first by the order they were retired, byte for byte. A well-formed
// reference with no entries, and n == 0, return an empty slice and no error.
//
// A reference that is not the canonical lowercase UUID text this store hands
// out, a negative n, and a database failure are errors, and return no entries:
// never an empty history.
func (s *IdentityStore) RecentPasswords(ctx context.Context, ref identity.UserID, n int) ([][]byte, error) {
	const op = "read password history"

	uid, ok := parseUserID(ref)
	if !ok {
		return nil, failed(op, errUserReference)
	}
	if n < 0 {
		return nil, failed(op, errNegativeRead)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	if n == 0 {
		return [][]byte{}, nil
	}

	rows, err := q.Raw(pgschema.RecentHistory, uid, n).Rows()
	if err != nil {
		return nil, dbFailed(op, err)
	}
	defer func() { _ = rows.Close() }()

	out := [][]byte{}
	for rows.Next() {
		var hash []byte
		if err := rows.Scan(&hash); err != nil {
			return nil, scanFailed(op, err)
		}
		out = append(out, hash)
	}
	if err := rows.Err(); err != nil {
		return nil, dbFailed(op, err)
	}

	return out, nil
}

// RetirePassword records hash as the user's newest retired password hash,
// unless the newest entry already holds the same bytes, then removes every
// entry of the user beyond the newest keep. keep == 0 records nothing and
// removes every entry. The entry's identifier comes from the store's
// generator (WithIDGenerator) and its retired_at from its clock (WithClock).
//
// It is atomic: outside a caller's transaction it runs in one of its own, and
// inside one under a savepoint, so a failure undoes only its own writes and
// leaves the caller's transaction usable.
//
// A reference that is not canonical lowercase UUID text, and a negative keep,
// are refused before anything is written. Error text never carries the hash
// or the reference.
func (s *IdentityStore) RetirePassword(ctx context.Context, ref identity.UserID, hash []byte, keep int) error {
	const op = "retire password"

	uid, ok := parseUserID(ref)
	if !ok {
		return failed(op, errUserReference)
	}
	if keep < 0 {
		return failed(op, errNegativeKeep)
	}

	if keep == 0 {
		return s.atomically(ctx, op, func(q *gormdb.DB) error {
			return forgetHistory(q, op, uid)
		})
	}

	// The identifier is minted before the first statement, so a generator
	// failure writes nothing.
	entryID, err := s.c.ids.NewID()
	if err != nil {
		return failed(op, err)
	}
	now := storekit.Time(s.c.now())

	return s.atomically(ctx, op, func(q *gormdb.DB) error {
		var newest []byte
		found, err := queryRow(q, op, pgschema.NewestHistory, []any{uid}, &newest)
		if err != nil {
			return err
		}

		if !found || !bytes.Equal(newest, hash) {
			if err := q.Exec(pgschema.InsertHistory, entryID, uid, storekit.OrEmpty(hash), now).Error; err != nil {
				return dbFailed(op, err)
			}
		}

		if err := q.Exec(pgschema.PruneHistory, uid, keep).Error; err != nil {
			return dbFailed(op, err)
		}

		return nil
	})
}

// ForgetPasswords removes every retired password hash of the user. Because
// the identity tables declare no foreign keys, a consumer deleting a user
// calls it in the same transaction that deletes the user and their grants.
//
// A reference that is not canonical lowercase UUID text is refused with an
// error that does not carry it.
func (s *IdentityStore) ForgetPasswords(ctx context.Context, ref identity.UserID) error {
	const op = "forget password history"

	uid, ok := parseUserID(ref)
	if !ok {
		return failed(op, errUserReference)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	return forgetHistory(q, op, uid)
}

// forgetHistory removes every history entry of uid through q.
func forgetHistory(q *gormdb.DB, op string, uid id.ID) error {
	if err := q.Exec(pgschema.ForgetHistory, uid).Error; err != nil {
		return dbFailed(op, err)
	}

	return nil
}
