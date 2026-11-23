package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/pkg/id"
)

var (
	errUserReference = errors.New("the user reference is not a UUID in canonical lowercase text")
	errNegativeRead  = errors.New("the number of entries to read is negative")
	errNegativeKeep  = errors.New("the number of entries to keep is negative")

	// errHistoryOwnerDeleted refuses a retire for a soft-deleted user. It
	// matches identity.ErrUserNotFound, the identity ports' "no such user",
	// and admin.ErrNotFound, so the administration service's password
	// change reports a user deleted under it as not found.
	errHistoryOwnerDeleted = fmt.Errorf("%w: %w", identity.ErrUserNotFound, admin.ErrNotFound)
)

// RecentPasswords returns up to limit of the user's retired password hashes,
// newest first by the order they were retired, byte for byte. A well-formed
// reference with no entries, and limit == 0, return an empty slice and no error.
//
// A reference that is not the canonical lowercase UUID text this store hands
// out, a negative limit, and a database failure are errors, and return no entries:
// never an empty history.
func (s *IdentityStore) RecentPasswords(ctx context.Context, ref identity.UserID, limit int) ([][]byte, error) {
	const op = "read password history"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return nil, failed(op, errUserReference)
	}
	if limit < 0 {
		return nil, failed(op, errNegativeRead)
	}

	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return nil, failed(op, err)
	}
	if limit == 0 {
		return [][]byte{}, nil
	}

	rows, err := q.QueryContext(ctx, pgschema.RecentHistory, uid, limit)
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
// Before it records an entry it locks the user's row FOR UPDATE
// (pgschema.LockHistoryOwner), as every versioned user write does, so two
// password changes inside callers' transactions queue rather than deadlock.
// It is the user-row step of the store's lock order:
// after any role lock, before any advisory lock. A soft-deleted user is
// refused with an error matching identity.ErrUserNotFound and
// admin.ErrNotFound, and nothing is written: DeleteUser locks the row FOR
// UPDATE and removes the history in its transaction, so a retire racing a
// deletion either waits for it and is refused, or commits first and has its
// entry removed by it. A reference no user row has is recorded as before,
// since the history table declares no foreign key.
//
// A reference that is not canonical lowercase UUID text, and a negative keep,
// are refused before anything is written. Error text never carries the hash
// or the reference.
func (s *IdentityStore) RetirePassword(ctx context.Context, ref identity.UserID, hash []byte, keep int) error {
	const op = "retire password"

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return failed(op, errUserReference)
	}
	if keep < 0 {
		return failed(op, errNegativeKeep)
	}

	if keep == 0 {
		return s.atomically(ctx, op, func(q DBTX) error {
			return forgetHistory(ctx, q, op, uid)
		})
	}

	// The identifier is minted before the first statement, so a generator
	// failure writes nothing.
	entryID, err := idgen.New(s.c.ids)
	if err != nil {
		return failed(op, err)
	}
	now := storekit.Time(s.c.clock.Now())

	return s.atomically(ctx, op, func(q DBTX) error {
		if err := lockHistoryOwner(ctx, q, op, uid); err != nil {
			return err
		}

		var newest []byte
		err := q.QueryRowContext(ctx, pgschema.NewestHistory, uid).Scan(&newest)
		none := errors.Is(err, sql.ErrNoRows)
		if err != nil && !none {
			return scanFailed(op, err)
		}

		if none || !bytes.Equal(newest, hash) {
			if _, err := q.ExecContext(ctx, pgschema.InsertHistory, entryID, uid,
				storekit.OrEmpty(hash), now); err != nil {
				return dbFailed(op, err)
			}
		}

		if _, err := q.ExecContext(ctx, pgschema.PruneHistory, uid, keep); err != nil {
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

	uid, ok := storekit.ParseUserID(ref)
	if !ok {
		return failed(op, errUserReference)
	}

	q, _, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}

	return forgetHistory(ctx, q, op, uid)
}

// forgetHistory removes every history entry of uid through q.
func forgetHistory(ctx context.Context, q DBTX, op string, uid id.ID) error {
	if _, err := q.ExecContext(ctx, pgschema.ForgetHistory, uid); err != nil {
		return dbFailed(op, err)
	}

	return nil
}

// lockHistoryOwner locks the row of user uid FOR UPDATE through q, and
// refuses a soft-deleted user. No row is no refusal.
func lockHistoryOwner(ctx context.Context, q DBTX, op string, uid id.ID) error {
	var deleted bool
	err := q.QueryRowContext(ctx, pgschema.LockHistoryOwner, uid).Scan(&deleted)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return scanFailed(op, err)
	case deleted:
		return failed(op, errHistoryOwnerDeleted)
	}

	return nil
}
