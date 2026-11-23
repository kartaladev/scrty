package sqlstore_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/store/sqlstore"
)

func newDeviceStore(t *testing.T, db *sql.DB, opts ...sqlstore.Option) oidcprovider.DeviceAuthorizationStore {
	t.Helper()

	return must.Must(sqlstore.NewDeviceAuthorizationStore(db, opts...))
}

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

// TestSQLStore_DeviceGrantColumns pins what the device grant's migration added to the
// provider's existing tables, through the stores that read and write them: a grant's
// origin and survival of its sign-in, the one rule that ends a grant with its sign-in, a
// pending request's device authorization, and a client's two device settings.
func TestSQLStore_DeviceGrantColumns(t *testing.T) {
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
		assert func(t *testing.T, ctx context.Context, db *sql.DB)
	}{
		{
			name: "a grant's origin and survival of its sign-in read back as written",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				grants := newGrantStore(t, db)
				written := grant(1, oidcprovider.OriginDevice, false, false, true)
				require.NoError(t, grants.Create(ctx, written))

				got, err := grants.Load(ctx, opID(1))
				require.NoError(t, err)
				assert.Equal(t, oidcprovider.OriginDevice, got.Origin)
				assert.True(t, got.SurvivesSignInEnd)
			},
		},
		{
			name: "a sign-in's end revokes a grant tied to it, or holding neither offline_access nor survival",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				grants := newGrantStore(t, db)
				require.NoError(t, grants.UseCodes(newCodeStore(t, db).(oidcprovider.UnspentCodes)))
				revoked := map[int]bool{
					1: true,  // a code grant without offline_access, as before
					2: false, // a code grant with offline_access, as before
					3: false, // a device grant that survives its sign-in
					4: true,  // a device grant that neither holds offline_access nor survives
					5: true,  // a device grant tied to its sign-in, which wins over both
				}
				for _, g := range []*oidcprovider.Grant{
					grant(1, oidcprovider.OriginCode, false, false, false),
					grant(2, oidcprovider.OriginCode, true, false, false),
					grant(3, oidcprovider.OriginDevice, false, false, true),
					grant(4, oidcprovider.OriginDevice, false, false, false),
					grant(5, oidcprovider.OriginDevice, true, true, true),
				} {
					require.NoError(t, grants.Create(ctx, g))
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
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				pending := newPendingStore(t, db)
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
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				clients := newClientStore(t, db)
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

			tc.assert(t, t.Context(), migratedDB(t).DB)
		})
	}
}

// TestSQLStore_DeviceCreateUnit holds Create's release and insert to one unit: inside a
// caller's transaction under a savepoint, so a refusal leaves that transaction usable and
// a rollback takes both writes, and otherwise in a transaction of the store's own, so a
// failure leaves nothing written.
func TestSQLStore_DeviceCreateUnit(t *testing.T) {
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
		assert func(t *testing.T, ctx context.Context, db *sql.DB)
	}{
		{
			name: "a user code taken inside a caller's transaction stores nothing and leaves it usable",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				require.NoError(t, newDeviceStore(t, db).Create(ctx, opDevice(1), opTime))
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback() }()

				taken := opDevice(2)
				taken.UserCodeDigest = opDevice(1).UserCodeDigest
				err = newDeviceStore(t, db).Create(sqlstore.WithTx(ctx, tx), taken, opTime)
				require.ErrorIs(t, err, oidcprovider.ErrUserCodeTaken)

				require.NoError(t, newDeviceStore(t, db).Create(sqlstore.WithTx(ctx, tx), opDevice(3), opTime),
					"the caller's transaction is still usable")
				require.NoError(t, tx.Commit())
				assert.Equal(t, 2, deviceRows(ctx, t, db), "the first record and the third, and nothing of the refused one")
			},
		},
		{
			name: "a caller's rollback takes the release and the insert together",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				s := newDeviceStore(t, db)
				require.NoError(t, s.Create(ctx, expiredHolder(), opTime.Add(-time.Minute)))
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)

				require.NoError(t, s.Create(sqlstore.WithTx(ctx, tx), overHolder(), opTime))
				require.NoError(t, tx.Rollback())

				holder, err := s.LoadByDeviceCode(ctx, expiredHolder().DeviceCodeDigest)
				require.NoError(t, err)
				assert.Equal(t, expiredHolder().UserCodeDigest, holder.UserCodeDigest, "the release was rolled back")
				assert.Equal(t, 1, deviceRows(ctx, t, db))
			},
		},
		{
			name: "a create refused after the release leaves the holder's user code where it was",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				s := newDeviceStore(t, db)
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
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				s := newDeviceStore(t, db)
				require.NoError(t, s.Create(ctx, expiredHolder(), opTime.Add(-time.Minute)))
				cancelled, cancel := context.WithCancel(ctx)
				cancel()

				err := s.Create(cancelled, overHolder(), opTime)
				require.ErrorIs(t, err, context.Canceled)

				holder, err := s.LoadByDeviceCode(ctx, expiredHolder().DeviceCodeDigest)
				require.NoError(t, err)
				assert.Equal(t, expiredHolder().UserCodeDigest, holder.UserCodeDigest)
				assert.Equal(t, 1, deviceRows(ctx, t, db))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, t.Context(), migratedDB(t).DB)
		})
	}
}

// TestSQLStore_DeviceRefusals holds the device store to refusing, with nothing written and
// no value repeated, what no row could hold or no compare could match, and to reporting a
// database it cannot reach as a failure, never as absence or a taken code.
func TestSQLStore_DeviceRefusals(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB

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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.assert(t, tc.call(t.Context(), newDeviceStore(t, db)))
		})
	}
	assert.Zero(t, deviceRows(t.Context(), t, db), "nothing refused was written")

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

// second returns the error of a call's two results.
func second[T any](_ T, err error) error { return err }

// TestSQLStore_DeviceReadRefusals holds the read side to what the write side holds to: a
// row no write could have made is a failure that names no value, never a record, and an
// approved record that holds no approval is no approval to list.
func TestSQLStore_DeviceReadRefusals(t *testing.T) {
	t.Parallel()

	type store = oidcprovider.DeviceAuthorizationStore

	// refused is the assertion of a row the read must refuse.
	refused := func(t *testing.T, ctx context.Context, s store) {
		t.Helper()

		got, err := s.LoadByDeviceCode(ctx, opDevice(1).DeviceCodeDigest)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.NotErrorIs(t, err, oidcprovider.ErrNotFound, "a corrupt row is a failure, not absence")
	}
	// absentFromBothLists is the assertion of an approved or spent row with no approval, as
	// the user it names would otherwise match.
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

			ctx, db := t.Context(), migratedDB(t).DB
			s := newDeviceStore(t, db)
			r := opDevice(1)
			r.State = tc.state
			require.NoError(t, s.Create(ctx, r, opTime))
			_, err := db.ExecContext(ctx, "UPDATE op_device_authorizations SET "+tc.corrupt) //nolint:gosec // tc.corrupt is a constant of this table
			require.NoError(t, err)

			tc.assert(t, ctx, s)
		})
	}
}

// TestSQLStore_GrantOriginRefusals holds a grant's origin to the two it names, written
// and read: an unknown one is refused with nothing stored, and a stored one reads as a
// failure that repeats no value, never as a grant of an origin nothing knows.
func TestSQLStore_GrantOriginRefusals(t *testing.T) {
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
		assert func(t *testing.T, ctx context.Context, db *sql.DB)
	}{
		{
			name: "an unknown origin is refused on write, and nothing is stored",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				err := newGrantStore(t, db).Create(ctx, grant(oidcprovider.OriginDevice+1))
				require.Error(t, err)
				assert.NotErrorIs(t, err, oidcprovider.ErrNotFound)
				assert.Zero(t, grantRows(ctx, t, db))
			},
		},
		{
			name: "an unknown origin is refused on read",
			assert: func(t *testing.T, ctx context.Context, db *sql.DB) {
				grants := newGrantStore(t, db)
				require.NoError(t, grants.Create(ctx, grant(oidcprovider.OriginCode)))
				_, err := db.ExecContext(ctx, `UPDATE op_grants SET origin = 7`)
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

			tc.assert(t, t.Context(), migratedDB(t).DB)
		})
	}
}

// vanishingInsert is a caller's handle on which the device insert writes nothing, as
// when it conflicted with a row that a sweep deleted before the store asked which.
type vanishingInsert struct{ *sql.Tx }

func (v vanishingInsert) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if strings.Contains(query, "INSERT INTO op_device_authorizations") {
		return driverNoRows{}, nil
	}

	return v.Tx.ExecContext(ctx, query, args...)
}

type driverNoRows struct{}

func (driverNoRows) LastInsertId() (int64, error) { return 0, nil }
func (driverNoRows) RowsAffected() (int64, error) { return 0, nil }

// TestSQLStore_DeviceCreateConflictGone holds a create whose conflicting row was swept
// before the store asked which key it was to the answer the provider retries: a taken user
// code, so the provider draws a fresh one. Nothing was stored, so a fresh code is safe.
func TestSQLStore_DeviceCreateConflictGone(t *testing.T) {
	t.Parallel()

	ctx, db := t.Context(), migratedDB(t).DB
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	s := must.Must(sqlstore.NewDeviceAuthorizationStore(db, sqlstore.WithTxResolver(
		func(context.Context) (sqlstore.DBTX, bool) { return vanishingInsert{tx}, true })))

	err = s.Create(ctx, opDevice(1), opTime)
	require.ErrorIs(t, err, oidcprovider.ErrUserCodeTaken)
	require.NoError(t, tx.Commit())
	assert.Zero(t, deviceRows(ctx, t, db), "nothing was stored")
}
