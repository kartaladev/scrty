package sqlstore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/internal/storekit"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
)

// NewRefreshTokenStore returns the durable store of a provider's refresh-token lineages:
// the session store NewSessionStore builds, with everything that says about it, over the
// op_refresh_tokens table instead of the sessions table. No sign-in lookup reads that
// table, so a refresh token cannot be accepted as a sign-in.
//
// The table is fixed: no option names it, and the result is a type only scrty's own
// modules can build. A failure returns the zero value, which the provider refuses.
//
// A durable store outlives a restart, so oidcprovider.New refuses it unless it is given
// oidcprovider.WithRefreshSuccessorKey, the same on every replica, or
// oidcprovider.WithRefreshSuccessorWindow(0), which derives no successor.
//
// It honours WithTxResolver, WithClock (default clock.System()) and WithIDGenerator
// (default id.NewV7Generator), and refuses any other option. A nil cipher, typed nil
// included, is a configuration error, as there is no unsealed variant.
func NewRefreshTokenStore(db *sql.DB, cipher seal.Cipher, opts ...Option) (oidcprovider.RefreshTokenStore, error) {
	cfg, err := newConfig(db, opts, optIDGenerator, optClock)
	if err != nil {
		return oidcprovider.RefreshTokenStore{}, err
	}
	if err := storekit.RequireCipher(cipher, ErrConfig); err != nil {
		return oidcprovider.RefreshTokenStore{}, err
	}
	cfg.lineage = true

	s, err := session.NewEncryptedStore(&sessionStore{c: cfg}, seal.SessionCipher(cipher))
	if err != nil {
		return oidcprovider.RefreshTokenStore{}, fmt.Errorf("%w: %w", ErrConfig, err)
	}

	return oplineage.New(s), nil
}

// boundTo is q as this store's statements must run on it: for a lineage store, over the
// lineage table, and otherwise q itself.
func (c *config) boundTo(q DBTX) DBTX {
	if c.lineage {
		return lineageHandle{q}
	}

	return q
}

// lineageHandle runs a session statement over the lineage table.
type lineageHandle struct{ DBTX }

// ExecContext implements DBTX.
func (h lineageHandle) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return h.DBTX.ExecContext(ctx, pgschema.LineageStatement(query), args...)
}

// QueryContext implements DBTX.
func (h lineageHandle) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return h.DBTX.QueryContext(ctx, pgschema.LineageStatement(query), args...)
}

// QueryRowContext implements DBTX.
func (h lineageHandle) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return h.DBTX.QueryRowContext(ctx, pgschema.LineageStatement(query), args...)
}
