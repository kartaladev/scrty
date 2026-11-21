package pgxstore_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/idgen/idgentest"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/pgxstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestStores_GeneratorAnswers pins, per store that mints a row identifier, that
// a generator answering the nil identifier is refused like a failing one (same
// operation text), stores nothing under the nil id, and that a good identifier
// still stores the row.
func TestStores_GeneratorAnswers(t *testing.T) {
	t.Parallel()

	conn := migrated(t)
	cipher := storefix.TestCipher(t)
	errOutage := errors.New("generator outage")

	type testCase struct {
		name  string
		op    string
		table string
		write func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error
	}

	cases := []testCase{
		{"consent give", "pgxstore: give consent:", pgschema.ConsentTable,
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newConsentStore(t, pool, opt).Give(ctx, "u-1", "c-1", nil, false, opTime)
			}},
		{"assertion identifier record", "pgxstore: record assertion identifier:", pgschema.AssertionIDTable,
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				_, err := newAssertionStore(t, pool, opt).Record(ctx, "c-1", "jti", opTime)
				return err
			}},
		{"browser session put", "pgxstore: put browser session:", pgschema.BrowserSessionTable,
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newBrowserStore(t, pool, opt).Put(ctx, &oidcprovider.BrowserSession{
					Digest: []byte{1}, IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime})
			}},
		{"client put", "pgxstore: put client:", pgschema.ClientTable,
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newClientStore(t, pool, opt).Put(ctx, confidentialClient("c-1"))
			}},
		{"login flow begin", "pgxstore: begin login flow:", "oidc_flows",
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				_, err := newFlowStore(t, pool, opt).Begin(ctx, oidc.Flow{
					Provider: "p", State: "s", Nonce: "n", Verifier: "v", Next: "/", ExpiresAt: time.Now().Add(time.Hour)})
				return err
			}},
		{"enrolment put pending", "seal: the inner store could not store the pending MFA enrolment", "mfa_enrolments",
			func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opt pgxstore.Option) error {
				return newEnrolmentStore(t, pool, cipher, opt).PutPending(ctx, mfa.Enrolment{
					User: "u-1", Secret: []byte("secret"), CreatedAt: opTime})
			}},
	}

	nilGen := func(t *testing.T) pgxstore.Option {
		g := idgentest.NewMockGenerator(gomock.NewController(t))
		g.EXPECT().NewID().Return(id.Nil, nil).AnyTimes()

		return pgxstore.WithIDGenerator(g)
	}
	failGen := func(t *testing.T) pgxstore.Option {
		g := idgentest.NewMockGenerator(gomock.NewController(t))
		g.EXPECT().NewID().Return(id.Nil, errOutage).AnyTimes()

		return pgxstore.WithIDGenerator(g)
	}

	nilRows := func(ctx context.Context, t *testing.T, table string) int {
		t.Helper()

		var n int
		// table is one of this test's own constants.
		require.NoError(t, conn.Pool.QueryRow(ctx,
			"SELECT count(*) FROM "+table+" WHERE id = $1", id.Nil.String()).Scan(&n))

		return n
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			t.Run("good id stores the row", func(t *testing.T) {
				require.NoError(t, tc.write(t, ctx, conn.Pool, pgxstore.WithIDGenerator(id.NewV7Generator())))
			})
			t.Run("failing generator is refused", func(t *testing.T) {
				err := tc.write(t, ctx, conn.Pool, failGen(t))
				require.ErrorIs(t, err, errOutage)
				assert.Contains(t, err.Error(), tc.op)
			})
			t.Run("nil id is refused like a failing generator, nothing stored", func(t *testing.T) {
				err := tc.write(t, ctx, conn.Pool, nilGen(t))
				require.ErrorIs(t, err, idgen.ErrNil)
				assert.Contains(t, err.Error(), tc.op)
				assert.Zero(t, nilRows(ctx, t, tc.table), "a row was stored under the nil id")
			})
		})
	}
}
