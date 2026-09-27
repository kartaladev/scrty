package gorm

import (
	"context"

	gormdb "gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/storekit"
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

// NewLinkStore returns a durable link store on db.
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
func NewLinkStore(db *gormdb.DB, opts ...Option) (*LinkStore, error) {
	c, err := newConfig(db, opts)
	if err != nil {
		return nil, err
	}

	return &LinkStore{c: c}, nil
}

// FindByExternal returns the link of the external identity, or
// oidc.ErrLinkNotFound: one SELECT.
func (s *LinkStore) FindByExternal(ctx context.Context, provider, issuer, subject string) (*oidc.Link, error) {
	const op = "find link"

	if !storekit.Storable(provider, issuer, subject) {
		return nil, oidc.ErrLinkNotFound
	}

	row, found, err := takeWhere[linkRow](ctx, s.c, op,
		"provider = ? AND issuer = ? AND subject = ?", provider, issuer, subject)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, oidc.ErrLinkNotFound
	}

	return &oidc.Link{
		ID:        row.ID,
		Provider:  row.Provider,
		Issuer:    row.Issuer,
		Subject:   row.Subject,
		UserID:    identity.UserID(row.UserID),
		Username:  row.Username,
		Email:     row.Email,
		CreatedAt: row.CreatedAt.UTC(),
	}, nil
}

// Insert stores l, refusing with oidc.ErrLinkExists when its external
// identity is already linked: one INSERT … ON CONFLICT (provider, issuer,
// subject) DO NOTHING, whose zero rows affected is the refusal. A zero l.ID
// is refused before any statement runs, since it is the row's primary key and
// the caller's to mint.
func (s *LinkStore) Insert(ctx context.Context, l oidc.Link) error {
	const op = "insert link"

	if err := storekit.CheckID(l.ID, "link"); err != nil {
		return failed(op, err)
	}
	if err := storekit.CheckStorable(
		storekit.Text("provider", l.Provider), storekit.Text("issuer", l.Issuer),
		storekit.Text("subject", l.Subject),
		storekit.Text("user reference", string(l.UserID)), storekit.Text("username", l.Username),
		storekit.Text("email", l.Email),
	); err != nil {
		return failed(op, err)
	}

	q, _, err := s.c.conn(ctx)
	if err != nil {
		return failed(op, err)
	}
	res := q.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "provider"}, {Name: "issuer"}, {Name: "subject"}},
		DoNothing: true,
	}).Create(&linkRow{
		ID:        l.ID,
		Provider:  l.Provider,
		Issuer:    l.Issuer,
		Subject:   l.Subject,
		UserID:    string(l.UserID),
		Username:  l.Username,
		Email:     l.Email,
		CreatedAt: storekit.Time(l.CreatedAt),
	})
	if res.Error != nil {
		return failed(op, res.Error)
	}
	if res.RowsAffected == 0 {
		return oidc.ErrLinkExists
	}

	return nil
}

// DeleteByUser removes every link of user and reports how many it removed:
// one DELETE. An empty reference removes nothing.
func (s *LinkStore) DeleteByUser(ctx context.Context, user identity.UserID) (int, error) {
	if !storekit.Storable(string(user)) {
		return 0, nil
	}

	return deleteWhere[linkRow](ctx, s.c, "delete links of user", "user_id = ? AND user_id <> ''", string(user))
}

var _ oidc.LinkStore = (*LinkStore)(nil)
