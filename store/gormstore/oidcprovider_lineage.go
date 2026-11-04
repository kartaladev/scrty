package gormstore

import (
	"context"
	"database/sql"
	"fmt"

	"gorm.io/gorm"

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
// It honours WithTxResolver, WithClock (default clock.System()) and WithIDGenerator
// (default id.NewV7Generator), and refuses any other option. A nil c, typed nil
// included, is a configuration error, as there is no unsealed variant.
func NewRefreshTokenStore(db *gorm.DB, c seal.Cipher, opts ...Option) (oidcprovider.RefreshTokenStore, error) {
	cfg, err := newConfig(db, opts, optIDGenerator, optClock)
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

// boundTo is q as this store's statements must run on it: for a lineage store, on a
// connection that names the lineage table wherever a statement names the sessions table, and
// otherwise q itself. q is a session of one operation's own, so binding it changes no other.
//
// The binding is at the connection, not in the statements, because the session store's
// statements come in two kinds: pgschema's text, and what gorm builds from its session model,
// and a connection sees both as the text the server is sent.
func (c *config) boundTo(q *gorm.DB) *gorm.DB {
	if c.lineage {
		q.Statement.ConnPool = &lineagePool{q.Statement.ConnPool}
	}

	return q
}

// lineagePool runs a session statement over the lineage table. It is used by pointer, which
// gorm needs to commit through it. It wraps the connection a
// handle runs on, and a transaction begun from it is wrapped the same way.
type lineagePool struct{ gorm.ConnPool }

// PrepareContext implements gorm.ConnPool.
func (p lineagePool) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return p.ConnPool.PrepareContext(ctx, pgschema.LineageStatement(query))
}

// ExecContext implements gorm.ConnPool.
func (p lineagePool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return p.ConnPool.ExecContext(ctx, pgschema.LineageStatement(query), args...)
}

// QueryContext implements gorm.ConnPool.
func (p lineagePool) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return p.ConnPool.QueryContext(ctx, pgschema.LineageStatement(query), args...)
}

// QueryRowContext implements gorm.ConnPool.
func (p lineagePool) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return p.ConnPool.QueryRowContext(ctx, pgschema.LineageStatement(query), args...)
}

// BeginTx implements gorm.ConnPoolBeginner, so a transaction gorm begins on the handle is
// bound to the lineage table too.
func (p lineagePool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	switch b := p.ConnPool.(type) {
	case gorm.TxBeginner:
		tx, err := b.BeginTx(ctx, opts)
		if err != nil {
			return nil, err
		}

		return &lineagePool{tx}, nil
	case gorm.ConnPoolBeginner:
		tx, err := b.BeginTx(ctx, opts)
		if err != nil {
			return nil, err
		}

		return &lineagePool{tx}, nil
	}

	return nil, gorm.ErrInvalidTransaction
}

// Commit implements gorm.TxCommitter.
func (p lineagePool) Commit() error {
	if c, ok := p.ConnPool.(gorm.TxCommitter); ok {
		return c.Commit()
	}

	return gorm.ErrInvalidTransaction
}

// Rollback implements gorm.TxCommitter.
func (p lineagePool) Rollback() error {
	if c, ok := p.ConnPool.(gorm.TxCommitter); ok {
		return c.Rollback()
	}

	return gorm.ErrInvalidTransaction
}
