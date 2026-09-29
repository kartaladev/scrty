package gormstore_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestIdentityStore_LogsNothing pins that no identity store operation reaches
// the consumer's gorm logger, whose default prints every statement with its
// bound values: here usernames, password hashes and user references. It
// covers the store's own transaction, a transaction the consumer attached or
// resolved, whose logger is the consumer's too, and failing statements, which
// gorm logs as errors.
func TestIdentityStore_LogsNothing(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)

	// operations runs every operation of the store, successful and refused,
	// on a store built with opts, with a context from ctx.
	operations := func(t *testing.T, ctx context.Context, db *gormdb.DB, opts ...gormstore.Option) {
		t.Helper()

		s := newIdentityStore(t, db, opts...)
		username := logCanary + "-" + storefix.NewID(t).String()
		hash := []byte(logCanary + "-hash")

		created, _ := s.Provision(ctx, username, identity.WithUserName(logCanary),
			identity.WithUserPassword(hash), identity.WithUserRoles(logCanary, logCanary+"-2"))
		_, _ = s.Provision(ctx, username, identity.WithUserPassword(hash))
		_, _ = s.Update(ctx, username, identity.WithUserPasswordChange(hash, time.Now()),
			identity.WithUserRoles(logCanary+"-3", logCanary))
		_, _ = s.Update(ctx, username+"-missing", identity.WithUserName(logCanary))
		_, _ = s.LoadByUsername(ctx, username)
		_, _ = s.LoadByUsername(ctx, username+"-missing")
		_, _ = s.LoadPrivileges(ctx, logCanary)

		user := identity.UserID(storefix.NewID(t).String())
		if created != nil {
			user = created.ID
		}
		_, _ = s.LoadByUserID(ctx, user)
		_, _ = s.Required(ctx, user)
		_ = s.RetirePassword(ctx, user, hash, 3)
		_ = s.RetirePassword(ctx, user, hash, 0)
		_, _ = s.RecentPasswords(ctx, user, 3)
		_ = s.ForgetPasswords(ctx, user)
	}

	type testCase struct {
		name string
		ctx  func(ctx context.Context) context.Context // nil means identity
		// run runs statements on db, a handle logging to the recorder.
		run    func(t *testing.T, ctx context.Context, db *gormdb.DB)
		assert func(t *testing.T, lines []string)
	}

	logsNothing := func(t *testing.T, lines []string) {
		t.Helper()
		assert.Empty(t, lines, "an identity store operation reached the consumer's logger")
	}

	cases := []testCase{
		{
			name: "a statement run on the consumer's handle itself is logged with its values",
			run: func(t *testing.T, ctx context.Context, db *gormdb.DB) {
				var got string
				require.NoError(t, db.WithContext(ctx).Raw("SELECT ?::text", logCanary).Scan(&got).Error)
			},
			assert: func(t *testing.T, lines []string) {
				require.Len(t, lines, 1, "the recorder does not see statements, so it proves nothing below")
				assert.Contains(t, lines[0], logCanary)
			},
		},
		{
			name: "operations on the store's own handle log nothing",
			run: func(t *testing.T, ctx context.Context, db *gormdb.DB) {
				operations(t, ctx, db)
			},
			assert: logsNothing,
		},
		{
			name: "operations inside a transaction the consumer attached log nothing",
			run: func(t *testing.T, ctx context.Context, db *gormdb.DB) {
				tx := db.WithContext(ctx).Begin()
				require.NoError(t, tx.Error)
				defer tx.Rollback()
				operations(t, gormstore.WithTx(ctx, tx), db)
			},
			assert: logsNothing,
		},
		{
			name: "operations inside a transaction the consumer's resolver reports log nothing",
			run: func(t *testing.T, ctx context.Context, db *gormdb.DB) {
				tx := db.WithContext(ctx).Begin()
				require.NoError(t, tx.Error)
				defer tx.Rollback()
				operations(t, ctx, db, gormstore.WithTxResolver(resolving(tx)))
			},
			assert: logsNothing,
		},
		{
			name: "failing operations log nothing",
			ctx:  storefix.Cancelled,
			run: func(t *testing.T, ctx context.Context, db *gormdb.DB) {
				operations(t, ctx, db)
			},
			assert: logsNothing,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &recordingLogger{}
			db, err := gormdb.Open(postgres.Open(d.conn.DSN), &gormdb.Config{Logger: rec, DisableAutomaticPing: true})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sqlDB.Close() })

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			tc.run(t, ctx, db)

			lines := rec.recorded()
			for i, line := range lines {
				lines[i] = strings.TrimSpace(line)
			}
			tc.assert(t, lines)
		})
	}
}
