package gormstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// A trigger whose constraint check is deferred refuses an update only when the transaction
// commits. A statement run outside a transaction commits at the end of its own execution, so
// the refusal arrives after the statement's rows were sent.
const refuseAtCommit = `
CREATE FUNCTION refuse_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'refused at commit' USING ERRCODE = '23514'; END $$`

// refuseUpdatesAtCommit makes every update of an MFA enrolment fail at commit.
func refuseUpdatesAtCommit(t *testing.T, d database) {
	t.Helper()

	ctx := t.Context()
	_, err := d.conn.DB.ExecContext(ctx, refuseAtCommit)
	require.NoError(t, err)
	_, err = d.conn.DB.ExecContext(ctx, `CREATE CONSTRAINT TRIGGER refuse_at_commit AFTER UPDATE ON mfa_enrolments
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_at_commit()`)
	require.NoError(t, err)
}

// TestGormStore_ChargeReportsACommitThatFailedAfterItsRow charges a verification attempt where
// the commit of the charge's own statement fails after the row was sent: the charge was rolled
// back, so the store must report the failure and not a charge.
func TestGormStore_ChargeReportsACommitThatFailedAfterItsRow(t *testing.T) {
	t.Parallel()

	for _, prepared := range []bool{false, true} {
		name := "plain"
		if prepared {
			name = "prepared"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			d := migratedDB(t)
			g := openGormWith(t, d.conn.DSN, &gormdb.Config{PrepareStmt: prepared})
			now := time.Now().UTC().Truncate(time.Microsecond)

			s := newEnrolmentStore(t, g, storefix.TestCipher(t))
			require.NoError(t, s.PutPending(ctx, storefix.Pending("u-charge", "TOTP")))
			_, err := s.Confirm(ctx, "u-charge", storefix.EnrolmentGen, 1000, now)
			require.NoError(t, err)
			refuseUpdatesAtCommit(t, d)

			_, charged, err := s.ChargeVerifyAttempt(ctx, "u-charge", now, 5, 15*time.Minute)

			var attempts int
			require.NoError(t, d.conn.DB.QueryRowContext(ctx,
				`SELECT verify_attempts FROM mfa_enrolments WHERE user_id = 'u-charge'`).Scan(&attempts))
			require.Zero(t, attempts, "the failed commit rolled the charge back")
			require.Error(t, err, "charged=%v while the row holds %d attempts", charged, attempts)
			assert.False(t, charged)
		})
	}
}

// TestGormStore_DryRunHandleRunsNoProviderStatement gives each provider store a gorm handle in
// DryRun mode. The stores send some statements to the connection pool directly, where gorm's
// own DryRun check is not reached: each call must report gorm.ErrDryRunModeUnsupported and
// change nothing.
func TestGormStore_DryRunHandleRunsNoProviderStatement(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// call runs the store call on dry, a DryRun handle; plain is a handle without it, for
		// building what the call would change.
		call   func(ctx context.Context, t *testing.T, dry, plain *gormdb.DB) error
		assert func(t *testing.T, d database, err error)
	}
	count := func(t *testing.T, d database, query string) int {
		t.Helper()
		var n int
		require.NoError(t, d.conn.DB.QueryRowContext(t.Context(), query).Scan(&n))

		return n
	}
	// refused asserts the refusal is the stores' own report of op, not gorm's bare sentinel.
	refused := func(op string) func(t *testing.T, d database, err error) {
		return func(t *testing.T, _ database, err error) {
			t.Helper()
			require.ErrorIs(t, err, gormdb.ErrDryRunModeUnsupported)
			assert.ErrorContains(t, err, "gormstore: "+op+": ")
		}
	}

	cases := []testCase{
		{
			name: "a write through the pool",
			call: func(ctx context.Context, t *testing.T, dry, _ *gormdb.DB) error {
				return newConsentStore(t, dry).Give(ctx, "u-dry", "c-1", []string{"openid"}, false, opTime)
			},
			assert: func(t *testing.T, d database, err error) {
				refused("give consent")(t, d, err)
				assert.Zero(t, count(t, d, `SELECT count(*) FROM op_consents`), "a row was written")
			},
		},
		{
			name: "a one-row read through the pool",
			call: func(ctx context.Context, t *testing.T, dry, _ *gormdb.DB) error {
				_, err := newPendingStore(t, dry).Load(ctx, []byte{1})

				return err
			},
			assert: refused("load pending request"),
		},
		{
			name: "a many-row read of identifiers",
			call: func(ctx context.Context, t *testing.T, dry, _ *gormdb.DB) error {
				_, err := newCodeStore(t, dry).UnspentByClient(ctx, identity.UserID("u-1"), "c-1")

				return err
			},
			assert: refused("list a client's outstanding codes"),
		},
		{
			name: "a many-row read of records",
			call: func(ctx context.Context, t *testing.T, dry, _ *gormdb.DB) error {
				_, err := newConsentStore(t, dry).ListByUser(ctx, identity.UserID("u-1"))

				return err
			},
			assert: refused("list user's consents"),
		},
		{
			name: "a many-grant call, which does not go through the pool helper",
			call: func(ctx context.Context, t *testing.T, dry, plain *gormdb.DB) error {
				require.NoError(t, newGrantStore(t, plain).Create(ctx,
					&oidcprovider.Grant{Family: opID(1), User: "u-1", CreatedAt: opTime}))
				s := newGrantStore(t, dry)
				require.NoError(t, s.UseCodes(must.Must(oidcprovider.NewMemoryCodeStore())))
				_, err := s.EndSignIns(ctx, oidcprovider.SignInSelector{User: "u-1"}, opTime)

				return err
			},
			assert: func(t *testing.T, d database, err error) {
				refused("end sign-ins")(t, d, err)
				assert.Zero(t, count(t, d, `SELECT count(*) FROM op_grants WHERE revoked`), "a grant was revoked")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := migratedDB(t)
			dry := openGormWith(t, d.conn.DSN, &gormdb.Config{DryRun: true})
			plain := openGormWith(t, d.conn.DSN, &gormdb.Config{})

			err := tc.call(t.Context(), t, dry, plain)
			tc.assert(t, d, err)
		})
	}
}
