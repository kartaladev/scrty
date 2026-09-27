package test

import (
	"context"
	"database/sql"
	"io/fs"
	"log"
	"os"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"

	"github.com/kartaladev/scrty/migrate"
)

// ExampleSet applies an embedded migration set with goose, shown here with
// migrate.SecurityState(): a database.Store for the PostgreSQL dialect named
// after the set's version table, a goose.Provider over the set's files using
// that store, then Up to apply every migration and DownTo(ctx, 0) to roll the
// set back completely. migrate ships no helper that wraps these calls; a
// consumer uses goose, or any tool that reads goose's annotated format,
// directly.
//
// The example has no output comment, so it is compiled with the package's
// tests, keeping it correct against goose's API, but never run: it needs a
// PostgreSQL database to reach.
func ExampleSet() {
	ctx := context.Background()

	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	set := migrate.SecurityState()
	fsys, err := fs.Sub(set.FS(), set.Dir)
	if err != nil {
		log.Fatal(err)
	}

	store, err := database.NewStore(database.DialectPostgres, set.VersionTable)
	if err != nil {
		log.Fatal(err)
	}

	provider, err := goose.NewProvider(goose.DialectCustom, db, fsys, goose.WithStore(store))
	if err != nil {
		log.Fatal(err)
	}

	if _, err := provider.Up(ctx); err != nil {
		log.Fatal(err)
	}

	// Rolling back to version zero drops every table the set created.
	if _, err := provider.DownTo(ctx, 0); err != nil {
		log.Fatal(err)
	}
}
