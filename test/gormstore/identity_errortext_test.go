package gormstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gormdb "gorm.io/gorm"

	gormstore "github.com/kartaladev/scrty/gorm"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// driverErrSecret is a value a driver's primary message quotes, which the
// store's error text must never carry.
const driverErrSecret = "secret-xyz"

// erroringPool is a consumer's connection whose every statement fails with
// err instead of running, as a driver reporting err would.
type erroringPool struct {
	gormdb.ConnPool

	err error
}

func (p *erroringPool) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, p.err
}

func (p *erroringPool) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, p.err
}

// oddStateErr is a driver error whose SQLState method reports something
// other than a SQLSTATE.
type oddStateErr struct{ state string }

func (e oddStateErr) Error() string    { return "odd driver failure" }
func (e oddStateErr) SQLState() string { return e.state }

// TestIdentityStore_DatabaseErrorText pins the text of a database failure:
// fixed library text naming the operation, then the SQLSTATE when the
// driver's error reports one through a SQLState method, and nothing of the
// driver's own text, primary message included. The driver's error value is
// never reachable through the chain.
func TestIdentityStore_DatabaseErrorText(t *testing.T) {
	t.Parallel()

	d := migratedIdentityDB(t)
	user := identity.UserID(storefix.NewID(t).String())

	quoting := &pgconn.PgError{
		Severity: "ERROR",
		Code:     "22P02",
		Message:  `invalid input syntax for type uuid: "` + driverErrSecret + `"`,
	}

	// forget and read are the store calls a case makes, one running a
	// statement and one a query, against a store whose every statement
	// fails with the case's error.
	forget := func(ctx context.Context, s *gormstore.IdentityStore) error {
		return s.ForgetPasswords(ctx, user)
	}
	read := func(ctx context.Context, s *gormstore.IdentityStore) error {
		_, err := s.RecentPasswords(ctx, user, 3)
		return err
	}

	type testCase struct {
		name string
		// err is what every statement on the consumer's connection fails with.
		err    error
		call   func(ctx context.Context, s *gormstore.IdentityStore) error
		assert func(t *testing.T, err error)
	}

	// cutWithState asserts err is the fixed text of op with the SQLSTATE
	// 22P02, and the driver's error is out of its chain.
	cutWithState := func(op string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.Error(t, err)
			var pgErr *pgconn.PgError
			assert.False(t, errors.As(err, &pgErr), "the driver's error is reachable")
			assert.Equal(t, "gorm: "+op+": database failure (SQLSTATE 22P02)", err.Error())
			for _, text := range storefix.ErrorTexts(err) {
				assert.NotContains(t, text, driverErrSecret, "the driver's message reached the text")
			}
		}
	}

	cases := []testCase{
		{
			name:   "a statement's driver error keeps only its SQLSTATE",
			err:    quoting,
			call:   forget,
			assert: cutWithState("forget password history"),
		},
		{
			name:   "a query's driver error keeps only its SQLSTATE",
			err:    quoting,
			call:   read,
			assert: cutWithState("read password history"),
		},
		{
			name:   "a driver error wrapped by the consumer's connection keeps only its SQLSTATE",
			err:    fmt.Errorf("consumer pool saw %s: %w", driverErrSecret, quoting),
			call:   forget,
			assert: cutWithState("forget password history"),
		},
		{
			name: "an error reporting no SQLSTATE is fixed text alone",
			err:  errors.New("connection to " + driverErrSecret + " refused"),
			call: forget,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Equal(t, "gorm: forget password history: database failure", err.Error())
				for _, text := range storefix.ErrorTexts(err) {
					assert.NotContains(t, text, driverErrSecret)
				}
			},
		},
		{
			name: "a SQLState method reporting no SQLSTATE adds no text",
			err:  oddStateErr{state: driverErrSecret},
			call: forget,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Equal(t, "gorm: forget password history: database failure", err.Error())
			},
		},
		{
			name: "a cancellation stays matchable under fixed text",
			err:  fmt.Errorf("pool gave up on %s: %w", driverErrSecret, context.Canceled),
			call: forget,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, "gorm: forget password history: database failure", err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			pool := &erroringPool{ConnPool: d.db.Statement.ConnPool, err: tc.err}
			s := newIdentityStore(t, d.db, gormstore.WithTxResolver(
				func(context.Context) (*gormdb.DB, bool) { return overPool(ctx, d.db, pool), true }))

			tc.assert(t, tc.call(ctx, s))
		})
	}
}
