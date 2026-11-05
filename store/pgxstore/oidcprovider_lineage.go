package pgxstore

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

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
// (default id.NewV7Generator), and refuses any other option. A nil c, typed nil
// included, is a configuration error, as there is no unsealed variant.
func NewRefreshTokenStore(pool *pgxpool.Pool, c seal.Cipher, opts ...Option) (oidcprovider.RefreshTokenStore, error) {
	cfg, err := newConfig(pool, opts, optIDGenerator, optClock)
	if err != nil {
		return oidcprovider.RefreshTokenStore{}, err
	}
	if err := storekit.RequireCipher(c, ErrConfig); err != nil {
		return oidcprovider.RefreshTokenStore{}, err
	}
	cfg.lineage = true

	s, err := session.NewEncryptedStore(&sessionStore{c: cfg}, seal.SessionCipher(c))
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

// Exec implements DBTX.
func (h lineageHandle) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return h.DBTX.Exec(ctx, pgschema.LineageStatement(query), args...)
}

// Query implements DBTX.
func (h lineageHandle) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return h.DBTX.Query(ctx, pgschema.LineageStatement(query), args...)
}

// QueryRow implements DBTX.
func (h lineageHandle) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return h.DBTX.QueryRow(ctx, pgschema.LineageStatement(query), args...)
}
