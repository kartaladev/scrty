package pgx

import (
	"context"
	"errors"
	"fmt"
	"time"

	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidc"
)

// LinkStore keeps the links between external identities and users in the
// oidc_links table the migrate package creates. It implements
// oidc.LinkStore, and is safe for concurrent use.
//
// Insert is one statement that inserts only when the provider, issuer and
// subject are not linked yet, so of concurrent inserts of one external
// identity exactly one succeeds, on this process or on another replica, and
// the others are refused with oidc.ErrLinkExists. A refused insert, an
// identical re-insert included, never overwrites the stored link: the last
// writer would otherwise own the external identity.
type LinkStore struct{ c *config }

// NewLinkStore returns a durable link store on pool.
//
// A link is stored under its own identifier, which must be unique and
// non-zero: the library's broker mints one per link. It honours
// WithTxResolver and refuses any other option.
//
// Limits, stated: PostgreSQL text cannot hold a NUL byte or invalid UTF-8. A
// link whose provider, issuer, subject, user reference, username or email
// holds either is refused with an error that names the field, never the
// value, and nothing is written; a lookup or deletion by such a value matches
// nothing. Username and email are kept for operators and never used for a
// lookup. Stored times are UTC, truncated to the microsecond.
func NewLinkStore(pool *pgxpool.Pool, opts ...Option) (*LinkStore, error) {
	c, err := newConfig(pool, opts)
	if err != nil {
		return nil, err
	}

	return &LinkStore{c: c}, nil
}

// FindByExternal returns the link of the external identity, or
// oidc.ErrLinkNotFound.
func (s *LinkStore) FindByExternal(ctx context.Context, provider, issuer, subject string) (*oidc.Link, error) {
	const op = "find link"

	if !storable(provider, issuer, subject) {
		return nil, oidc.ErrLinkNotFound
	}

	l := oidc.Link{Provider: provider, Issuer: issuer, Subject: subject}
	var (
		linkID  pgtype.UUID
		user    string
		created time.Time
	)
	err := s.c.queryRow(ctx, op, pgschema.LinkSelect, []any{provider, issuer, subject},
		&linkID, &user, &l.Username, &l.Email, &created)
	if errors.Is(err, pgxv5.ErrNoRows) {
		return nil, oidc.ErrLinkNotFound
	}
	if err != nil {
		return nil, err
	}
	if l.ID, err = scanID(linkID); err != nil {
		return nil, failed(op, err)
	}
	l.UserID, l.CreatedAt = identity.UserID(user), created.UTC()

	return &l, nil
}

// Insert stores l, refusing with oidc.ErrLinkExists when its external
// identity is already linked. A zero l.ID is refused before any statement
// runs, since it is the row's primary key and the caller's to mint.
func (s *LinkStore) Insert(ctx context.Context, l oidc.Link) error {
	const op = "insert link"

	if l.ID.IsZero() {
		return fmt.Errorf("pgx: %s: the link id is zero", op)
	}

	if err := checkStorable(op,
		textField{"provider", l.Provider}, textField{"issuer", l.Issuer}, textField{"subject", l.Subject},
		textField{"user reference", string(l.UserID)}, textField{"username", l.Username}, textField{"email", l.Email},
	); err != nil {
		return err
	}

	return s.c.execOrRefuse(ctx, op, oidc.ErrLinkExists, pgschema.LinkInsert, uuidArg(l.ID), l.Provider, l.Issuer,
		l.Subject, string(l.UserID), l.Username, l.Email, ts(l.CreatedAt))
}

// DeleteByUser removes every link of user and reports how many it removed.
// An empty reference removes nothing.
func (s *LinkStore) DeleteByUser(ctx context.Context, user identity.UserID) (int, error) {
	if !storable(string(user)) {
		return 0, nil
	}

	n, err := s.c.exec(ctx, "delete links of user", pgschema.LinkDeleteByUser, string(user))

	return int(n), err
}

var _ oidc.LinkStore = (*LinkStore)(nil)
