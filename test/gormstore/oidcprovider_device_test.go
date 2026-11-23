package gormstore_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/store/gormstore"
)

// opDevice is an issued device authorization n of client c-1, its digests derived from n,
// issued at opTime and expiring ten minutes later.
func opDevice(n byte) *oidcprovider.DeviceAuthorization {
	return &oidcprovider.DeviceAuthorization{
		ID: opID(int(n)), DeviceCodeDigest: []byte{0xd0, n}, UserCodeDigest: []byte{0xe0, n},
		ClientID: "c-1", Scopes: []string{"openid"}, IssuedAt: opTime, ExpiresAt: opTime.Add(10 * time.Minute),
		Interval: 5 * time.Second,
	}
}

// deviceRows counts the device authorizations held.
func deviceRows(ctx context.Context, t *testing.T, db *sql.DB) int {
	t.Helper()

	var n int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM op_device_authorizations`).Scan(&n))

	return n
}

// second returns the error of a call's two results.
func second[T any](_ T, err error) error { return err }

// TestGormStore_DeviceGrantColumns pins what the device grant's migration added to the
// provider's existing tables, through the stores that read and write them.
func TestGormStore_DeviceGrantColumns(t *testing.T) {
	t.Parallel()

	signInFamily := opID(900)
	grant := func(family int, origin oidcprovider.GrantOrigin, offline, tied, survives bool) *oidcprovider.Grant {
		return &oidcprovider.Grant{
			Family: opID(family), User: "u-1", ClientID: "c-1", Scopes: []string{"openid"}, CodeID: opID(family + 50),
			SignInFamily: signInFamily, Offline: offline, EndsWithSignIn: tied, SurvivesSignInEnd: survives,
			Origin: origin, HoldsLineage: true, CreatedAt: opTime, ExpiresAt: opTime.Add(time.Hour),
		}
	}

	cases := []struct {
		name   string
		assert func(t *testing.T, ctx context.Context, g *gormdb.DB)
	}{
		{
			name: "a grant's origin and survival of its sign-in read back as written",
			assert: func(t *testing.T, ctx context.Context, g *gormdb.DB) {
				grants := newGrantStore(t, g)
				require.NoError(t, grants.Create(ctx, grant(1, oidcprovider.OriginDevice, false, false, true)))

				got, err := grants.Load(ctx, opID(1))
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.OriginDevice, got.Origin)
				assert.True(t, got.SurvivesSignInEnd)
			},
		},
		{
			name: "a sign-in's end revokes a grant tied to it, or holding neither offline_access nor survival",
			assert: func(t *testing.T, ctx context.Context, g *gormdb.DB) {
				grants := newGrantStore(t, g)
				require.NoError(t, grants.UseCodes(newCodeStore(t, g).(oidcprovider.UnspentCodes)))
				revoked := map[int]bool{
					1: true,  // a code grant without offline_access, as before
					2: false, // a code grant with offline_access, as before
					3: false, // a device grant that survives its sign-in
					4: true,  // a device grant that neither holds offline_access nor survives
					5: true,  // a device grant tied to its sign-in, which wins over both
				}
				for _, gr := range []*oidcprovider.Grant{
					grant(1, oidcprovider.OriginCode, false, false, false),
					grant(2, oidcprovider.OriginCode, true, false, false),
					grant(3, oidcprovider.OriginDevice, false, false, true),
					grant(4, oidcprovider.OriginDevice, false, false, false),
					grant(5, oidcprovider.OriginDevice, true, true, true),
				} {
					require.NoError(t, grants.Create(ctx, gr))
				}

				ended, err := grants.EndSignIns(ctx, oidcprovider.SignInSelector{Family: signInFamily}, opTime.Add(time.Minute))
				require.NoError(t, err)
				assert.Len(t, ended, len(revoked), "every grant of the sign-in is marked")

				for family, want := range revoked {
					got, err := grants.Load(ctx, opID(family))
					require.NoError(t, err)
					assert.Equal(t, want, got.Revoked, "grant %d", family)
					assert.False(t, got.SignInEndedAt.IsZero(), "grant %d is marked", family)
				}
			},
		},
		{
			name: "a pending request's device authorization and user code read back as written",
			assert: func(t *testing.T, ctx context.Context, g *gormdb.DB) {
				pending := newPendingStore(t, g)
				require.NoError(t, pending.Create(ctx, &oidcprovider.PendingRequest{
					ID: opID(1), HandleDigest: []byte{1}, FlowDigest: []byte{2}, ClientID: "c-1",
					ParkedAt: opTime, ExpiresAt: opTime.Add(time.Minute),
					DeviceAuthorizationID: opID(7), DeviceUserCode: "BCDF-GHJK",
				}))
				require.NoError(t, pending.Create(ctx, &oidcprovider.PendingRequest{
					ID: opID(2), HandleDigest: []byte{3}, FlowDigest: []byte{4}, ClientID: "c-1",
					ParkedAt: opTime, ExpiresAt: opTime.Add(time.Minute),
				}))

				got, err := pending.Load(ctx, []byte{1})
				require.NoError(t, err)
				assert.Equal(t, opID(7), got.DeviceAuthorizationID)
				assert.Equal(t, "BCDF-GHJK", got.DeviceUserCode)

				got, err = pending.Load(ctx, []byte{3})
				require.NoError(t, err)
				assert.True(t, got.DeviceAuthorizationID.IsZero(), "a code request names no device authorization")
				assert.Empty(t, got.DeviceUserCode)
			},
		},
		{
			name: "a client's device settings read back as written",
			assert: func(t *testing.T, ctx context.Context, g *gormdb.DB) {
				clients := newClientStore(t, g)
				require.NoError(t, clients.PutRegistered(ctx, oidcprovider.RegisteredClient{Client: oidcprovider.Client{
					ID: "cli", Type: oidcprovider.Public, ApplicationType: oidcprovider.Native,
					Scopes:            []string{"openid"},
					GrantTypes:        []oidcprovider.GrantType{oidcprovider.GrantDeviceCode},
					DeviceCompleteURI: true, DeviceGrantsOutliveSignIn: true,
				}}))

				got, err := clients.Client(ctx, "cli")
				require.NoError(t, err)
				assert.True(t, got.DeviceCompleteURI)
				assert.True(t, got.DeviceGrantsOutliveSignIn)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), migratedDB(t).db)
		})
	}
}

// TestGormStore_DeviceCreateUnit holds Create's release and insert to one unit: inside a
// caller's transaction under a savepoint, so a refusal leaves that transaction usable and
// a rollback takes both writes, and otherwise in a transaction of the store's own.
func TestGormStore_DeviceCreateUnit(t *testing.T) {
	t.Parallel()

	// expiredHolder is record 1, expired at opTime, holding the user code record 2 asks for.
	expiredHolder := func() *oidcprovider.DeviceAuthorization {
		r := opDevice(1)
		r.ExpiresAt = opTime
		return r
	}
	overHolder := func() *oidcprovider.DeviceAuthorization {
		r := opDevice(2)
		r.UserCodeDigest = expiredHolder().UserCodeDigest
		return r
	}

	cases := []struct {
		name   string
		assert func(t *testing.T, ctx context.Context, d database)
	}{
		{
			name: "a user code taken inside a caller's transaction stores nothing and leaves it usable",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newDeviceStore(t, d.db)
				require.NoError(t, s.Create(ctx, opDevice(1), opTime))
				tx := beginGorm(ctx, t, d.db)

				taken := opDevice(2)
				taken.UserCodeDigest = opDevice(1).UserCodeDigest
				err := s.Create(gormstore.WithTx(ctx, tx), taken, opTime)
				require.ErrorIs(t, err, oidcprovider.ErrUserCodeTaken)

				require.NoError(t, s.Create(gormstore.WithTx(ctx, tx), opDevice(3), opTime),
					"the caller's transaction is still usable")
				require.NoError(t, tx.Commit().Error)
				assert.Equal(t, 2, deviceRows(ctx, t, d.conn.DB), "the first record and the third, and nothing of the refused one")
			},
		},
		{
			name: "a caller's rollback takes the release and the insert together",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newDeviceStore(t, d.db)
				require.NoError(t, s.Create(ctx, expiredHolder(), opTime.Add(-time.Minute)))
				tx := beginGorm(ctx, t, d.db)

				require.NoError(t, s.Create(gormstore.WithTx(ctx, tx), overHolder(), opTime))
				require.NoError(t, tx.Rollback().Error)

				holder, err := s.LoadByDeviceCode(ctx, expiredHolder().DeviceCodeDigest)
				require.NoError(t, err)
				assert.Equal(t, expiredHolder().UserCodeDigest, holder.UserCodeDigest, "the release was rolled back")
				assert.Equal(t, 1, deviceRows(ctx, t, d.conn.DB))
			},
		},
		{
			name: "a create refused after the release leaves the holder's user code where it was",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newDeviceStore(t, d.db)
				require.NoError(t, s.Create(ctx, expiredHolder(), opTime.Add(-time.Minute)))

				// Its identifier is held, so the insert writes nothing after the release ran.
				refused := overHolder()
				refused.ID = opID(1)
				err := s.Create(ctx, refused, opTime)
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidcprovider.ErrUserCodeTaken, "a held identifier is not a taken user code")

				holder, err := s.LoadByDeviceCode(ctx, expiredHolder().DeviceCodeDigest)
				require.NoError(t, err)
				assert.Equal(t, expiredHolder().UserCodeDigest, holder.UserCodeDigest)
			},
		},
		{
			name: "a cancelled context stores and releases nothing",
			assert: func(t *testing.T, ctx context.Context, d database) {
				s := newDeviceStore(t, d.db)
				require.NoError(t, s.Create(ctx, expiredHolder(), opTime.Add(-time.Minute)))
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				err := s.Create(cancelled, overHolder(), opTime)
				require.ErrorIs(t, err, context.Canceled)

				holder, err := s.LoadByDeviceCode(ctx, expiredHolder().DeviceCodeDigest)
				require.NoError(t, err)
				assert.Equal(t, expiredHolder().UserCodeDigest, holder.UserCodeDigest)
				assert.Equal(t, 1, deviceRows(ctx, t, d.conn.DB))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), migratedDB(t))
		})
	}
}

// TestGormStore_DeviceRefusals holds the device store to refusing, with nothing written and
// no value repeated, what no row could hold or no compare could match, and to reporting a
// database it cannot reach as a failure, never as absence or a taken code.
func TestGormStore_DeviceRefusals(t *testing.T) {
	t.Parallel()

	d := migratedDB(t)

	cases := []struct {
		name   string
		call   func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "a client identifier PostgreSQL text cannot hold",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				r := opDevice(1)
				r.ClientID = "bad\x00"
				return s.Create(ctx, r, opTime)
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "bad")
			},
		},
		{
			name: "an approval naming no grant family",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				r := opDevice(2)
				r.State, r.Approval = oidcprovider.DeviceApproved, &oidcprovider.DeviceApproval{User: "u-1"}
				return s.Create(ctx, r, opTime)
			},
			assert: func(t *testing.T, err error) { require.Error(t, err) },
		},
		{
			name: "a negative poll count",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				r := opDevice(3)
				r.PollCount = -1
				return s.Create(ctx, r, opTime)
			},
			assert: func(t *testing.T, err error) { require.Error(t, err) },
		},
		{
			name: "a state past the last one this version knows",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				r := opDevice(7)
				r.State = oidcprovider.DeviceSpent + 1
				return s.Create(ctx, r, opTime)
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidcprovider.ErrUserCodeTaken)
			},
		},
		{
			name: "a negative interval",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				r := opDevice(8)
				r.Interval = -time.Second
				return s.Create(ctx, r, opTime)
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidcprovider.ErrUserCodeTaken)
			},
		},
		{
			name: "a nil record",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				return s.Create(ctx, nil, opTime)
			},
			assert: func(t *testing.T, err error) { require.Error(t, err) },
		},
		{
			name: "a claim with no flow digest",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				return s.Claim(ctx, opID(4), nil, opTime)
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidcprovider.ErrNotFound)
			},
		},
		{
			name: "a decision naming no grant family",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				return s.Decide(ctx, opID(4), &oidcprovider.DeviceApproval{User: "u-1"}, opTime)
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidcprovider.ErrNotFound, "a malformed approval is not a lost compare")
			},
		},
		{
			name: "a poll with a negative interval is refused, not reported as a lost compare",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				return s.RecordPoll(ctx, opID(6), 0, opTime, -time.Second)
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidcprovider.ErrNotFound, "a malformed interval is not a lost compare")
			},
		},
		{
			name: "a poll whose seen count no row can hold is a lost compare",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				return s.RecordPoll(ctx, opID(5), -1, opTime, time.Second)
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, oidcprovider.ErrNotFound) },
		},
		{
			name: "a transition of a record that is not there is not found",
			call: func(ctx context.Context, s oidcprovider.DeviceAuthorizationStore) error {
				return s.Spend(ctx, opID(40), opTime)
			},
			assert: func(t *testing.T, err error) { require.ErrorIs(t, err, oidcprovider.ErrNotFound) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, tc.call(t.Context(), newDeviceStore(t, d.db)))
		})
	}
	assert.Zero(t, deviceRows(t.Context(), t, d.conn.DB), "nothing refused was written")

	t.Run("an unreachable database is a failure, never absence or a taken code", func(t *testing.T) {
		s := newDeviceStore(t, unreachableDB(t))
		ctx := t.Context()

		for name, err := range map[string]error{
			"create":              s.Create(ctx, opDevice(1), opTime),
			"load by user code":   second(s.LoadByUserCode(ctx, []byte{1}, opTime)),
			"load by device code": second(s.LoadByDeviceCode(ctx, []byte{1})),
			"spend":               s.Spend(ctx, opID(1), opTime),
		} {
			require.Error(t, err, name)
			assert.NotErrorIs(t, err, oidcprovider.ErrNotFound, name)
			assert.NotErrorIs(t, err, oidcprovider.ErrUserCodeTaken, name)
		}
	})
}

// TestGormStore_DeviceReadRefusals holds the read side to what the write side holds to: a
// row no write could have made is a failure that names no value, never a record, and an
// approved record that holds no approval is no approval to list.
func TestGormStore_DeviceReadRefusals(t *testing.T) {
	t.Parallel()

	type store = oidcprovider.DeviceAuthorizationStore

	refused := func(t *testing.T, ctx context.Context, s store) {
		t.Helper()

		got, err := s.LoadByDeviceCode(ctx, opDevice(1).DeviceCodeDigest)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.NotErrorIs(t, err, oidcprovider.ErrNotFound, "a corrupt row is a failure, not absence")
	}
	absentFromBothLists := func(t *testing.T, ctx context.Context, s store) {
		t.Helper()

		unspent := s.(oidcprovider.UnspentCodes)
		got, err := unspent.UnspentByClient(ctx, "u-1", "c-1")
		require.NoError(t, err, "by client")
		assert.Empty(t, got, "by client")

		got, err = unspent.UnspentBySignIn(ctx, oidcprovider.SignInSelector{User: "u-1"}, true)
		require.NoError(t, err, "by sign-in")
		assert.Empty(t, got, "by sign-in")
	}

	cases := []struct {
		name  string
		state oidcprovider.DeviceState
		// corrupt is the SET list of an UPDATE of the one row, which no write makes.
		corrupt string
		assert  func(t *testing.T, ctx context.Context, s store)
	}{
		{
			name: "an approved record holding no approval is no approval to list", state: oidcprovider.DeviceApproved,
			corrupt: "user_ref = 'u-1'", assert: absentFromBothLists,
		},
		{
			name: "a spent record holding no approval is no approval to list", state: oidcprovider.DeviceSpent,
			corrupt: "user_ref = 'u-1'", assert: absentFromBothLists,
		},
		{name: "a state beyond the last one known", corrupt: "state = 9", assert: refused},
		{name: "a negative poll count", corrupt: "poll_count = -3", assert: refused},
		{name: "a negative interval", corrupt: "interval_ns = -5", assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, d := t.Context(), migratedDB(t)
			s := newDeviceStore(t, d.db)
			r := opDevice(1)
			r.State = tc.state
			require.NoError(t, s.Create(ctx, r, opTime))
			_, err := d.conn.DB.ExecContext(ctx, "UPDATE op_device_authorizations SET "+tc.corrupt) //nolint:gosec // tc.corrupt is a constant of this table
			require.NoError(t, err)

			tc.assert(t, ctx, s)
		})
	}
}

// TestGormStore_GrantOriginRefusals holds a grant's origin to the two it names, written
// and read.
func TestGormStore_GrantOriginRefusals(t *testing.T) {
	t.Parallel()

	grant := func(origin oidcprovider.GrantOrigin) *oidcprovider.Grant {
		return &oidcprovider.Grant{
			Family: opID(1), User: "u-1", ClientID: "c-1", Scopes: []string{"openid"}, CodeID: opID(51),
			Origin: origin, HoldsLineage: true, CreatedAt: opTime, ExpiresAt: opTime.Add(time.Hour),
		}
	}
	grantRows := func(ctx context.Context, t *testing.T, db *sql.DB) int {
		t.Helper()

		var n int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM op_grants`).Scan(&n))

		return n
	}

	cases := []struct {
		name   string
		assert func(t *testing.T, ctx context.Context, d database)
	}{
		{
			name: "an unknown origin is refused on write, and nothing is stored",
			assert: func(t *testing.T, ctx context.Context, d database) {
				err := newGrantStore(t, d.db).Create(ctx, grant(oidcprovider.OriginDevice+1))
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidcprovider.ErrNotFound)
				assert.Zero(t, grantRows(ctx, t, d.conn.DB))
			},
		},
		{
			name: "an unknown origin is refused on read",
			assert: func(t *testing.T, ctx context.Context, d database) {
				grants := newGrantStore(t, d.db)
				require.NoError(t, grants.Create(ctx, grant(oidcprovider.OriginCode)))
				_, err := d.conn.DB.ExecContext(ctx, `UPDATE op_grants SET origin = 7`)
				require.NoError(t, err)

				got, err := grants.Load(ctx, opID(1))
				require.Error(t, err)
				assert.Nil(t, got)
				assert.NotErrorIs(t, err, oidcprovider.ErrNotFound, "a corrupt row is a failure, not absence")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), migratedDB(t))
		})
	}
}

// vanishingInsertPool is a caller's connection on which the device insert writes nothing,
// as when it conflicted with a row that a sweep deleted before the store asked which.
type vanishingInsertPool struct{ gormdb.ConnPool }

func (v vanishingInsertPool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if strings.Contains(query, "INSERT INTO op_device_authorizations") {
		return noRows{}, nil
	}

	return v.ConnPool.ExecContext(ctx, query, args...)
}

type noRows struct{}

func (noRows) LastInsertId() (int64, error) { return 0, nil }
func (noRows) RowsAffected() (int64, error) { return 0, nil }

// TestGormStore_DeviceCreateConflictGone holds a create whose conflicting row was swept
// before the store asked which key it was to a taken user code, which the provider
// retries with a fresh code. Nothing was stored, so a fresh code is safe.
func TestGormStore_DeviceCreateConflictGone(t *testing.T) {
	t.Parallel()

	ctx, d := t.Context(), migratedDB(t)
	tx := beginGorm(ctx, t, d.db)
	h := overPool(ctx, tx, vanishingInsertPool{tx.Statement.ConnPool})

	s := must.Must(gormstore.NewDeviceAuthorizationStore(d.db, gormstore.WithTxResolver(
		func(context.Context) (*gormdb.DB, bool) { return h, true })))

	err := s.Create(ctx, opDevice(1), opTime)
	require.ErrorIs(t, err, oidcprovider.ErrUserCodeTaken)
	require.NoError(t, tx.Commit().Error)
	assert.Zero(t, deviceRows(ctx, t, d.conn.DB), "nothing was stored")
}
