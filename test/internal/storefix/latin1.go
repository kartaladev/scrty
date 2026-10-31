package storefix

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"sync/atomic"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver the handle opens
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/store/migrate"
)

// latin1Seq numbers the databases Latin1DSN creates, so two in one test
// process never share a name.
var latin1Seq atomic.Int64

// Latin1DSN creates a database whose server encoding is LATIN1 on the server
// admin is connected to, applies both migration sets to it, and returns a DSN
// for it. adminDSN is the DSN of the database admin is connected to, which
// supplies the server's address and credentials.
//
// The DSN asks the driver for the UTF-8 client encoding, as a driver that
// always sends UTF-8 does, so the server converts every string it receives to
// LATIN1 and refuses one that has no LATIN1 form (SQLSTATE 22P05). Without
// the request, pgx follows the database's encoding and refuses nothing.
//
// The database is dropped at cleanup, which ends any session still connected
// to it.
func Latin1DSN(t *testing.T, admin *sql.DB, adminDSN string) string {
	t.Helper()

	name := fmt.Sprintf("latin1_%d", latin1Seq.Add(1))
	_, err := admin.ExecContext(t.Context(),
		`CREATE DATABASE `+name+` ENCODING 'LATIN1' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
	})

	u, err := url.Parse(adminDSN)
	require.NoError(t, err)
	u.Path = "/" + name
	q := u.Query()
	q.Set("client_encoding", "UTF8")
	u.RawQuery = q.Encode()

	db, err := sql.Open("pgx", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	for _, set := range []migrate.Set{migrate.SecurityState(), migrate.Identity()} {
		fsys, err := fs.Sub(set.FS(), set.Dir)
		require.NoError(t, err)
		store, err := database.NewStore(database.DialectPostgres, set.VersionTable)
		require.NoError(t, err)
		p, err := goose.NewProvider(goose.DialectCustom, db, fsys, goose.WithStore(store))
		require.NoError(t, err)
		_, err = p.Up(t.Context())
		require.NoError(t, err)
	}

	return u.String()
}
