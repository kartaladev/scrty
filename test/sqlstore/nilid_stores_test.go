package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/idgen/idgentest"
	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/store/sqlstore"
	"github.com/kartaladev/scrty/test/internal/storefix"
)

// TestSQLStore_NilIdentifierFromGenerator pins, against a real database, that a
// store whose generator answers the nil identifier fails like one whose
// generator fails: the same operation text, no row stored.
func TestSQLStore_NilIdentifierFromGenerator(t *testing.T) {
	t.Parallel()

	errGenerator := errors.New("generator exhausted")

	type site struct {
		name  string
		table string
		op    string
		write func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error
	}

	sites := []site{
		{"consents", pgschema.ConsentTable, "give consent",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newConsentStore(t, db, sqlstore.WithIDGenerator(g)).Give(ctx, "u-1", "c-1", nil, false, opTime)
			}},
		{"assertion identifiers", pgschema.AssertionIDTable, "record assertion identifier",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				_, err := newAssertionStore(t, db, sqlstore.WithIDGenerator(g)).Record(ctx, "c-1", "jti", opTime)
				return err
			}},
		{"browser sessions", pgschema.BrowserSessionTable, "put browser session",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newBrowserStore(t, db, sqlstore.WithIDGenerator(g)).Put(ctx, &oidcprovider.BrowserSession{
					Digest: []byte{1}, IdleExpiresAt: opTime, AbsoluteExpiresAt: opTime,
				})
			}},
		{"clients", pgschema.ClientTable, "put client",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newClientStore(t, db, sqlstore.WithIDGenerator(g)).Put(ctx, confidentialClient("c-1"))
			}},
		{"login flows", "oidc_flows", "begin login flow",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				_, err := newFlowStore(t, db, sqlstore.WithIDGenerator(g)).Begin(ctx, oidc.Flow{
					Provider: "p", State: "s", Nonce: "n", Verifier: "v", ExpiresAt: opTime,
				})
				return err
			}},
		{"MFA enrolments", "mfa_enrolments", "seal: the inner store could not store the pending MFA enrolment",
			func(t *testing.T, ctx context.Context, db *sql.DB, g id.Generator) error {
				return newEnrolmentStore(t, db, storefix.TestCipher(t), sqlstore.WithIDGenerator(g)).
					PutPending(ctx, storefix.Pending("nil-id-user", "TOTP"))
			}},
	}

	type testCase struct {
		name   string
		got    id.ID
		genErr error
		assert func(t *testing.T, s site, err error, rows int)
	}

	cases := []testCase{
		{
			name: "a good id stores the row",
			got:  storefix.NewID(t),
			assert: func(t *testing.T, _ site, err error, rows int) {
				require.NoError(t, err)
				assert.Equal(t, 1, rows)
			},
		},
		{
			name:   "a generator failure fails the write and stores nothing",
			genErr: errGenerator,
			assert: func(t *testing.T, s site, err error, rows int) {
				require.ErrorIs(t, err, errGenerator)
				assert.Contains(t, err.Error(), s.op)
				assert.Zero(t, rows)
			},
		},
		{
			name: "a generator answering the nil id fails like a generator failure and stores nothing",
			got:  id.Nil,
			assert: func(t *testing.T, s site, err error, rows int) {
				require.ErrorIs(t, err, idgen.ErrNil)
				assert.Contains(t, err.Error(), s.op)
				assert.Zero(t, rows)
			},
		},
	}

	for _, s := range sites {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					ctx := t.Context()
					db := migratedDB(t).DB
					g := idgentest.NewMockGenerator(gomock.NewController(t))
					g.EXPECT().NewID().Return(tc.got, tc.genErr).AnyTimes()

					err := s.write(t, ctx, db, g)

					var rows int
					// table is one of this test's own constants.
					require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM "+s.table).Scan(&rows))
					tc.assert(t, s, err, rows)
				})
			}
		})
	}
}
