package gormstore_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	gormdb "gorm.io/gorm"
	"gorm.io/gorm/logger"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// recordingLogger is a consumer's gorm logger at its most verbose: it records
// every message and every statement gorm traces, with its bound values.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (r *recordingLogger) record(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, line)
}

func (r *recordingLogger) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func (r *recordingLogger) LogMode(logger.LogLevel) logger.Interface { return r }

func (r *recordingLogger) Info(_ context.Context, msg string, args ...any) {
	r.record(fmt.Sprintf(msg, args...))
}

func (r *recordingLogger) Warn(_ context.Context, msg string, args ...any) {
	r.record(fmt.Sprintf(msg, args...))
}

func (r *recordingLogger) Error(_ context.Context, msg string, args ...any) {
	r.record(fmt.Sprintf(msg, args...))
}

func (r *recordingLogger) Trace(_ context.Context, _ time.Time, fc func() (string, int64), err error) {
	statement, _ := fc()
	r.record(fmt.Sprintf("%s (error: %v)", statement, err))
}

// logCanary is a value every store operation below carries, so a leaked
// statement shows it.
const logCanary = "LOG-CANARY"

// TestStores_LogNothing pins that no store operation reaches the consumer's
// gorm logger, whose default prints every statement with its bound values:
// here secrets, digests and user references. It covers the base handle, a
// transaction the consumer attached or resolved, whose logger is the
// consumer's too, and failing statements, which gorm logs as errors.
func TestStores_LogNothing(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)
	c := storefix.TestCipher(t)
	at := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

	// operations runs every operation of every store, successful and refused,
	// on stores built with opts and a context from ctx.
	operations := func(t *testing.T, ctx context.Context, db *gormdb.DB, opts ...gormstore.Option) {
		t.Helper()

		sessions := newSessionStore(t, db, c, append(opts, gormstore.WithClock(func() time.Time { return at }))...)
		tokens := newOneTimeStore(t, db, opts...)
		attempts := newAttemptStore(t, db, opts...)

		sid := logCanary + "-" + storefix.NewID(t).String()
		sess := storefix.DurableSession(sid, at)
		sess.UserID = logCanary
		_ = sessions.Create(ctx, sess)
		_ = sessions.Create(ctx, sess)
		_ = sessions.Save(ctx, sess)
		_, _ = sessions.Load(ctx, sid)
		_, _ = sessions.Load(ctx, logCanary+"-missing")
		_, _ = sessions.CountActiveByUser(ctx, logCanary)
		_, _ = sessions.DeleteByExternalSession(ctx, sess.ExternalIssuer, sess.ExternalSessionID)
		_, _ = sessions.DeleteByUserAndExternalIssuer(ctx, logCanary, sess.ExternalIssuer)
		_ = sessions.Delete(ctx, sid)
		_ = sessions.DeleteByUser(ctx, logCanary)
		_, _ = sessions.DeleteExpired(ctx)

		tok := storefix.RaceToken(0)
		tok.ID = storefix.NewID(t)
		tok.Subject = logCanary
		_ = tokens.Insert(ctx, tok)
		_ = tokens.Insert(ctx, tok)
		_, _ = tokens.FindByID(ctx, tok.ID)
		_, _ = tokens.FindByID(ctx, storefix.NewID(t))
		_ = tokens.Consume(ctx, tok.ID, at)
		_ = tokens.Consume(ctx, tok.ID, at)
		_, _ = tokens.CountRecentBySubject(ctx, tok.Purpose, logCanary, at)
		_, _ = tokens.DeleteExpiredBefore(ctx, tok.Purpose, at)

		_ = attempts.RecordFailure(ctx, logCanary, at)
		_, _ = attempts.FailureCount(ctx, logCanary, at.Add(-time.Hour))
		_ = attempts.Reset(ctx, logCanary)
		_, _ = attempts.DeleteAttemptsBefore(ctx, at)

		keys := newSigningKeyStore(t, db, c, opts...)
		kid := logCanary + "-" + storefix.NewID(t).String()
		_ = keys.Store(ctx, storefix.SigningKey(kid, []byte(logCanary)))
		_ = keys.Store(ctx, storefix.SigningKey(kid, []byte(logCanary)))
		_, _ = keys.LoadAll(ctx)

		enrolments := newEnrolmentStore(t, db, c, opts...)
		user := identity.UserID(logCanary + "-" + storefix.NewID(t).String())
		_ = enrolments.PutPending(ctx, storefix.Pending(user, logCanary))
		_, _, _ = enrolments.Get(ctx, user)
		_, _ = enrolments.Confirm(ctx, user, 1000, at)
		_, _ = enrolments.Confirm(ctx, user, 1000, at)
		_ = enrolments.PutPending(ctx, storefix.Pending(user, logCanary))
		_, _ = enrolments.AcceptStep(ctx, user, 1001)
		_, _ = enrolments.AcceptStep(ctx, user, 1001)
		_ = enrolments.Delete(ctx, user)

		apiKeys := newAPIKeyStore(t, db, opts...)
		key := storefix.APIKey(0, logCanary)
		key.ID, key.Name, key.Scopes = storefix.NewID(t), logCanary, []string{logCanary}
		_ = apiKeys.Put(ctx, key)
		_ = apiKeys.Put(ctx, key)
		_, _ = apiKeys.Get(ctx, key.ID)
		_ = apiKeys.Revoke(ctx, key.ID, at)
		_ = apiKeys.TouchLastUsed(ctx, key.ID, at)
		_ = apiKeys.Revoke(ctx, storefix.NewID(t), at)
		_, _ = apiKeys.List(ctx, logCanary)

		links := newLinkStore(t, db, opts...)
		l := storefix.Link(t, logCanary, logCanary, logCanary+"-"+storefix.NewID(t).String(), logCanary)
		_ = links.Insert(ctx, l)
		_ = links.Insert(ctx, l)
		_, _ = links.FindByExternal(ctx, l.Provider, l.Issuer, l.Subject)
		_, _ = links.DeleteByUser(ctx, logCanary)

		flows := newFlowStore(t, db, append(opts, gormstore.WithClock(func() time.Time { return storefix.OIDCStart }))...)
		f := storefix.Flow(logCanary, logCanary+"-"+storefix.NewID(t).String())
		h, _ := flows.Begin(ctx, f)
		_, _ = flows.Complete(ctx, h, logCanary, f.State)
		_, _ = flows.Complete(ctx, h, logCanary, f.State)
		_, _ = flows.DeleteExpired(ctx, storefix.OIDCStart)

		handoffs := newHandoffStore(t, db, opts...)
		rec := storefix.Handoff(t, logCanary+"-"+storefix.NewID(t).String())
		rec.UserID = logCanary
		_ = handoffs.Insert(ctx, rec)
		_ = handoffs.Insert(ctx, rec)
		_, _ = handoffs.FindByTokenID(ctx, rec.TokenID)
		_ = handoffs.Consume(ctx, rec.TokenID, at)
		_ = handoffs.Consume(ctx, rec.TokenID, at)
		_, _ = handoffs.DeleteExpired(ctx, storefix.OIDCStart)
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
		assert.Empty(t, lines, "a store operation reached the consumer's logger")
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
				operations(t, ctx, db, gormstore.WithTxResolver(func(context.Context) (*gormdb.DB, bool) {
					return tx, true
				}))
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
