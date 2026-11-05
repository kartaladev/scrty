package gormstore

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/pgschema"
)

// recordingPool is a connection pool that keeps the text of each statement it is handed.
type recordingPool struct {
	gorm.ConnPool

	got string
}

func (p *recordingPool) PrepareContext(_ context.Context, query string) (*sql.Stmt, error) {
	p.got = query

	return nil, nil
}

func (p *recordingPool) ExecContext(_ context.Context, query string, _ ...any) (sql.Result, error) {
	p.got = query

	return nil, nil
}

func (p *recordingPool) QueryContext(_ context.Context, query string, _ ...any) (*sql.Rows, error) {
	p.got = query

	return nil, nil
}

func (p *recordingPool) QueryRowContext(_ context.Context, query string, _ ...any) *sql.Row {
	p.got = query

	return nil
}

// TestLineagePool_NamesTheLineageTable runs one statement naming the sessions table through
// each way a lineage store's connection takes a statement: every one must reach the pool
// naming the lineage table instead. Preparing is one of them, though gorm reaches it only
// through its own prepared-statement wrapper, so no suite on a handle sees it fail.
func TestLineagePool_NamesTheLineageTable(t *testing.T) {
	t.Parallel()

	const statement = "SELECT 1 FROM sessions WHERE id_digest = $1"

	type testCase struct {
		name   string
		run    func(ctx context.Context, p gorm.ConnPool) error
		assert func(t *testing.T, got string, err error)
	}

	named := func(t *testing.T, got string, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Contains(t, got, pgschema.RefreshTokenTable)
		assert.NotContains(t, got, "sessions")
		assert.Equal(t, pgschema.LineageStatement(statement), got)
	}

	cases := []testCase{
		{
			name: "prepare",
			run: func(ctx context.Context, p gorm.ConnPool) error {
				_, err := p.PrepareContext(ctx, statement)

				return err
			},
			assert: named,
		},
		{
			name: "exec",
			run: func(ctx context.Context, p gorm.ConnPool) error {
				_, err := p.ExecContext(ctx, statement)

				return err
			},
			assert: named,
		},
		{
			name: "query",
			run: func(ctx context.Context, p gorm.ConnPool) error {
				_, err := p.QueryContext(ctx, statement)

				return err
			},
			assert: named,
		},
		{
			name: "query row",
			run: func(ctx context.Context, p gorm.ConnPool) error {
				_ = p.QueryRowContext(ctx, statement)

				return nil
			},
			assert: named,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := &recordingPool{}
			err := tc.run(t.Context(), &lineagePool{inner})
			tc.assert(t, inner.got, err)
		})
	}
}
