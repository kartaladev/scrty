package test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5"
)

// postgresCloneSource is the database a call that names no migration set is
// cloned from: the one CREATE DATABASE copies by default, which is what a
// fresh server's own database starts as.
const postgresCloneSource = "template1"

// postgresTemplatePrefix starts the name of every template database, followed
// by the fingerprint of the migration sets it holds.
const postgresTemplatePrefix = "tpl_"

// postgresClonePrefix starts the name of every database clone creates, so a
// call's database is told apart from the server's own and from templates.
const postgresClonePrefix = "t_"

// clone creates a database of a new, generated name on s as a copy of
// template, and returns its name. An empty template means
// postgresCloneSource.
//
// The name is never caller-supplied, and both identifiers are quoted, so
// nothing a test passes reaches the statement's text.
func (s *postgresServer) clone(ctx context.Context, template string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate a database name: %w", err)
	}
	name := postgresClonePrefix + hex.EncodeToString(b[:])
	if template == "" {
		template = postgresCloneSource
	}
	_, err := s.admin.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+
		" TEMPLATE "+pgx.Identifier{template}.Sanitize())
	if err != nil {
		return "", fmt.Errorf("create database %s from %s on PostgreSQL %s: %w", name, template, s.image, err)
	}
	return name, nil
}

// drop removes database name from s, ending any session still connected to
// it. A database that is already gone is not an error.
func (s *postgresServer) drop(ctx context.Context, name string) error {
	_, err := s.admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	if err != nil {
		return fmt.Errorf("drop database %s on PostgreSQL %s: %w", name, s.image, err)
	}
	return nil
}

// dsnFor returns a DSN reaching database name on s: s's admin DSN with its
// database swapped, credentials and parameters unchanged.
func (s *postgresServer) dsnFor(name string) (string, error) {
	u, err := url.Parse(s.adminDSN)
	if err != nil {
		return "", fmt.Errorf("parse the PostgreSQL %s connection string: %w", s.image, err)
	}
	u.Path = "/" + name
	u.RawPath = ""
	return u.String(), nil
}

// postgresFingerprintLen is how many hex characters of the SHA-256 a
// fingerprint keeps: 64 bits, also the key of the template's advisory lock.
const postgresFingerprintLen = 16

// postgresFingerprint identifies an ordered list of migration sets by
// content: 16 hex characters of a SHA-256 over, for each set in order, its
// directory and version table, then the path and contents of every file
// under its directory. A changed file, another version table or another order
// gives another fingerprint; two file systems with the same directory but
// different files give different ones.
//
// A set that cannot be applied at all is refused here, before any database
// is touched.
func postgresFingerprint(migrations []postgresMigrations) (string, error) {
	h := sha256.New()
	// Every field is length-prefixed, so no two lists hash the same bytes.
	field := func(b []byte) {
		_, _ = fmt.Fprintf(h, "%d:", len(b))
		_, _ = h.Write(b)
	}
	for _, m := range migrations {
		if err := m.wiringError(); err != nil {
			return "", err
		}
		field([]byte("set"))
		field([]byte(m.dir))
		field([]byte(m.versionTable))
		err := fs.WalkDir(m.fsys, m.dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := fs.ReadFile(m.fsys, p)
			if err != nil {
				return err
			}
			field([]byte(p))
			field(b)
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("fingerprint migrations %s: %w", m.dir, err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:postgresFingerprintLen], nil
}

// template returns the name of the template database holding migrations on
// s, building it on first use, or "" when migrations is empty: such a call is
// cloned from postgresCloneSource.
//
// A template is built once per server. In this process, calls for the same
// template wait on one build lock while calls for other templates build in
// parallel. Across processes sharing the server, the build runs under a
// PostgreSQL advisory lock (see buildTemplate). A build that fails is not
// remembered: the next call for the same list builds again from empty.
func (s *postgresServer) template(ctx context.Context, migrations []postgresMigrations) (string, error) {
	if len(migrations) == 0 {
		return "", nil
	}
	fp, err := postgresFingerprint(migrations)
	if err != nil {
		return "", err
	}
	name := postgresTemplatePrefix + fp

	s.tmplMu.Lock()
	if s.tmplBuilt[name] {
		s.tmplMu.Unlock()
		return name, nil
	}
	if s.tmplLocks == nil {
		s.tmplLocks = map[string]*sync.Mutex{}
		s.tmplBuilt = map[string]bool{}
	}
	lock, ok := s.tmplLocks[name]
	if !ok {
		lock = &sync.Mutex{}
		s.tmplLocks[name] = lock
	}
	s.tmplMu.Unlock()

	lock.Lock()
	defer lock.Unlock()

	// Another call may have built it while this one waited.
	s.tmplMu.Lock()
	built := s.tmplBuilt[name]
	s.tmplMu.Unlock()
	if built {
		return name, nil
	}

	if err := s.buildTemplate(ctx, name, fp, migrations); err != nil {
		return "", err
	}
	s.tmplMu.Lock()
	s.tmplBuilt[name] = true
	s.tmplMu.Unlock()
	return name, nil
}

// buildTemplate makes database name on s a complete template of migrations,
// unless another process already has.
//
// It holds one admin connection for the whole build, and takes on it a
// session advisory lock keyed by fp, on the server's own database, so that
// processes sharing the server build one template at a time. Every
// administrative statement of the build runs on that same connection, and the
// migrations run through a handle of their own on the template: a build never
// needs a second admin connection while it holds one, so parallel builds of
// different templates cannot deadlock on the admin pool however many there
// are.
//
// Once it holds the lock, a database of that name already marked as a
// template is complete and used as it is. One that is not marked is a
// half-built leftover of a build that died, and is dropped and rebuilt.
// A build that fails drops what it created. A complete template refuses
// connections, so no session can ever hold it and make a clone of it fail.
func (s *postgresServer) buildTemplate(ctx context.Context, name, fp string, migrations []postgresMigrations) error {
	key, err := strconv.ParseUint(fp, 16, 64)
	if err != nil {
		return fmt.Errorf("lock key of template %s: %w", name, err)
	}
	conn, err := s.admin.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve a connection to build template %s on PostgreSQL %s: %w", name, s.image, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, int64(key)); err != nil { //nolint:gosec // a bit pattern, not a quantity: wrapping is intended
		return fmt.Errorf("lock template %s on PostgreSQL %s: %w", name, s.image, err)
	}
	defer s.unlockTemplate(ctx, conn, int64(key)) //nolint:gosec // as above

	ident := pgx.Identifier{name}.Sanitize()
	var isTemplate bool
	switch err := conn.QueryRowContext(ctx,
		`SELECT datistemplate FROM pg_database WHERE datname = $1`, name).Scan(&isTemplate); {
	case err == nil && isTemplate:
		return nil
	case err == nil:
		if _, err := conn.ExecContext(ctx, "DROP DATABASE "+ident+" WITH (FORCE)"); err != nil {
			return fmt.Errorf("drop half-built template %s on PostgreSQL %s: %w", name, s.image, err)
		}
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("look up template %s on PostgreSQL %s: %w", name, s.image, err)
	}

	if _, err := conn.ExecContext(ctx,
		"CREATE DATABASE "+ident+" TEMPLATE "+pgx.Identifier{postgresCloneSource}.Sanitize()); err != nil {
		return fmt.Errorf("create template %s on PostgreSQL %s: %w", name, s.image, err)
	}
	err = s.applyTo(ctx, name, migrations)
	if err == nil {
		// Every connection to it is closed by now: applyTo closes its handle.
		_, err = conn.ExecContext(ctx, "ALTER DATABASE "+ident+" WITH IS_TEMPLATE true ALLOW_CONNECTIONS false")
		if err != nil {
			err = fmt.Errorf("mark template %s on PostgreSQL %s: %w", name, s.image, err)
		}
	}
	if err != nil {
		// ctx may be what failed the build; the drop must still run.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postgresTeardownBudget)
		defer cancel()
		if _, derr := conn.ExecContext(dctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)"); derr != nil {
			return errors.Join(err, fmt.Errorf("drop half-built template %s on PostgreSQL %s: %w", name, s.image, derr))
		}
		return err
	}
	return nil
}

// unlockTemplate releases a template's advisory lock on conn. A connection
// whose lock could not be released is discarded rather than returned to the
// admin pool, where it would block every later build of that template.
func (s *postgresServer) unlockTemplate(ctx context.Context, conn *sql.Conn, key int64) {
	// ctx may be what ended the build; the unlock must still run.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postgresTeardownBudget)
	defer cancel()
	var released bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&released); err != nil || !released {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
}

// applyTo applies migrations to database name on s through a handle of its
// own, closed before it returns, so that no session is left on the database.
func (s *postgresServer) applyTo(ctx context.Context, name string, migrations []postgresMigrations) error {
	dsn, err := s.dsnFor(name)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open template %s on PostgreSQL %s: %w", name, s.image, err)
	}
	defer func() { _ = db.Close() }()

	s.applies.Add(int64(len(migrations)))
	return postgresApply(ctx, db, migrations)
}

// postgresApply applies migrations to db, in order. The error names the set
// that failed.
func postgresApply(ctx context.Context, db *sql.DB, migrations []postgresMigrations) error {
	for _, m := range migrations {
		p, err := m.provider(db)
		if err != nil {
			return err
		}
		if _, err := p.Up(ctx); err != nil {
			return fmt.Errorf("apply migrations %s: %w", m.dir, err)
		}
	}
	return nil
}
