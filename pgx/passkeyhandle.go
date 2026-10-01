package pgx

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/passkey"
)

// errPasskeyHandleHeld is the refusal of an offered handle another user
// holds. With 64 random bytes it does not happen by chance; it names no part
// of the handle.
var errPasskeyHandleHeld = errors.New("the offered user handle is held by another user")

// PasskeyHandleStore keeps each user's one WebAuthn user handle in the
// passkey_user_handles table the migrate package creates. It implements
// passkey.HandleStore, and is safe for concurrent use.
//
// Assign is an insert that stores the offer only when neither the user nor
// the handle is held, followed by a read of the handle the user holds. The
// table's unique indexes decide, so of concurrent assignments for one user,
// on this process or on another replica, every caller receives the same
// handle. Neither statement fails on a conflict, so an assignment never
// aborts a caller's transaction, and rows are never changed once written, so
// the two need no transaction of the store's own.
type PasskeyHandleStore struct {
	c *config
}

// NewPasskeyHandleStore returns a durable passkey user-handle store on pool.
//
// It honours WithTxResolver and WithIDGenerator (default id.NewV7Generator;
// the identifier of each passkey_user_handles row, which no caller sees), and
// refuses any other option. It judges no time, so WithClock does not apply.
//
// Limit, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. An
// assignment for a user reference holding either is refused with an error
// that names the field, never the value, and nothing is written.
func NewPasskeyHandleStore(pool *pgxpool.Pool, opts ...Option) (*PasskeyHandleStore, error) {
	c, err := newConfig(pool, opts, optIDGenerator)
	if err != nil {
		return nil, err
	}

	return &PasskeyHandleStore{c: c}, nil
}

// Assign stores offered as user's handle when user has none, and returns the
// handle user holds afterwards. An offer that is not passkey.HandleSize bytes
// is refused with an error wrapping passkey.ErrConfig, and an offer another
// user holds with an error naming no handle bytes.
func (s *PasskeyHandleStore) Assign(ctx context.Context, user identity.UserID, offered []byte) ([]byte, error) {
	const op = "assign passkey user handle"

	if len(offered) != passkey.HandleSize {
		return nil, failed(op, fmt.Errorf("%w: a user handle is %d bytes", passkey.ErrConfig, passkey.HandleSize))
	}
	if err := storekit.CheckStorable(storekit.Text("user", string(user))); err != nil {
		return nil, failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return nil, failed(op, err)
	}

	if _, err := s.c.exec(ctx, op, pgschema.PasskeyHandleInsert, uuidArg(rowID), string(user), bytes.Clone(offered)); err != nil {
		return nil, err
	}

	var held []byte
	err = s.c.queryRow(ctx, op, pgschema.PasskeyHandleOfUser, []any{string(user)}, &held)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return nil, failed(op, errPasskeyHandleHeld)
	}
	if err != nil {
		return nil, err
	}

	return held, nil
}

// UserFor returns the user holding handle, or false.
func (s *PasskeyHandleStore) UserFor(ctx context.Context, handle []byte) (identity.UserID, bool, error) {
	var user string
	err := s.c.queryRow(ctx, "find passkey user handle", pgschema.PasskeyHandleUser,
		[]any{storekit.OrEmpty(handle)}, &user)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}

	return identity.UserID(user), true, nil
}

var _ passkey.HandleStore = (*PasskeyHandleStore)(nil)
