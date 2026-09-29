package test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"io/fs"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // the "pgx" database/sql driver PostgresConn.DB uses
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mailpit"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/outbound"
)

// smtpImage is the SMTP test server every RunTestSMTP caller gets, pinned by
// digest so a remote tag move cannot change what the tests ran against.
const smtpImage = "axllent/mailpit@sha256:7eef0f38dbc85e4e264f2edf5d70fbb694826791e05cb2cae4fc9e3282f968f5"

// TestOption customises a helper in this package. Each helper documents the
// options it reads and the default each one replaces.
//
// The name stutters as test.TestOption and stays that way: RunTestX(t,
// ...TestOption) is this repository's convention for every container helper,
// and the prefix is what tells a caller these are not library options.
//
//nolint:revive // stuttering name kept deliberately, see above
type TestOption func(*testConfig)

type testConfig struct {
	image    string
	username string
	password string

	// Read by RunTestPostgres only.
	migrations         []postgresMigrations
	finalizers         []string
	leftoverTableCheck bool

	// Read by RunTestKeycloak only.
	backchannelPort   int
	backchannelPrefix string
}

// WithTestSMTPImage replaces the digest-pinned SMTP server image RunTestSMTP
// starts. Use it to reproduce a report against another version; the default
// is what CI runs.
func WithTestSMTPImage(ref string) TestOption {
	return func(c *testConfig) { c.image = ref }
}

// WithTestSMTPCredentials replaces the credentials the SMTP server requires.
// The default is a fixed pair; the server rejects a session that authenticates
// with anything else, so a test that expects a refusal sets its own.
func WithTestSMTPCredentials(username, password string) TestOption {
	return func(c *testConfig) {
		c.username = username
		c.password = password
	}
}

// SMTPConn is how a test reaches the SMTP server RunTestSMTP started.
//
// RootCAs trusts the certificate the server presents on STARTTLS, and is
// generated per test. A sender under test therefore keeps its certificate
// verification on: the test trusts this one server, not every server.
type SMTPConn struct {
	Host     string
	Port     int
	Username string
	Password string
	RootCAs  *x509.CertPool

	api string // the container's HTTP API, for reading received messages
}

// ReceivedMessage is one message the test server accepted, as it arrived on
// the wire. The subject is decoded from its encoded-word form so a caller
// compares readable text; every other field is left exactly as received.
type ReceivedMessage struct {
	DecodedSubject string
	Body           string
	Headers        map[string]string
}

// RunTestSMTP starts an SMTP server for one test and returns how to reach it.
//
// The server requires AUTH and requires STARTTLS, so a send that skips either
// is refused rather than quietly accepted — the point of testing against a
// real server is that it enforces what an in-process script only pretends to.
// The certificate is generated for this test alone and offered back through
// SMTPConn.RootCAs.
//
// The container is torn down with the test. Every test that needs SMTP calls
// this rather than starting its own: one helper means one place to change the
// image, the ports and the readiness rule.
//
// It skips the test when Docker is unavailable, because an unrunnable
// integration test is more useful skipped than failing for a reason that has
// nothing to do with the code.
func RunTestSMTP(t *testing.T, opts ...TestOption) SMTPConn {
	t.Helper()

	testcontainers.SkipIfProviderIsNotHealthy(t)

	cfg := &testConfig{
		image:    smtpImage,
		username: "mailbot",
		password: "s3cret",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	certPEM, keyPEM, pool := serverCertificate(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	ctx := t.Context()

	ctr, err := mailpit.Run(ctx, cfg.image,
		mailpit.WithSMTPAuth(cfg.username, cfg.password),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				HostFilePath:      certPath,
				ContainerFilePath: "/certs/cert.pem",
				FileMode:          0o644,
			},
			testcontainers.ContainerFile{
				HostFilePath:      keyPath,
				ContainerFilePath: "/certs/key.pem",
				FileMode:          0o644,
			},
		),
		testcontainers.WithEnv(map[string]string{
			"MP_SMTP_TLS_CERT": "/certs/cert.pem",
			"MP_SMTP_TLS_KEY":  "/certs/key.pem",
			// The credentials option above also permits AUTH in the clear,
			// which the server refuses to combine with required encryption.
			// Encryption wins: credentials only ever cross an upgraded
			// connection here.
			"MP_SMTP_AUTH_ALLOW_INSECURE": "false",
			"MP_SMTP_REQUIRE_STARTTLS":    "true",
		}),
	)
	require.NoError(t, err, "failed to start SMTP test container")

	t.Cleanup(func() {
		// Not t.Context(): it is already cancelled by the time cleanup runs,
		// and Terminate would fail before it removed anything.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Without an explicit StopTimeout, Terminate's own grace period
		// defaults to 10s too, leaving this context no margin over Docker's
		// stop deadline: under load the two race and the context loses. Mailpit
		// has nothing to flush on shutdown, so it is killed shortly after.
		if err := ctr.Terminate(cleanupCtx, testcontainers.StopTimeout(2*time.Second)); err != nil {
			t.Fatalf("failed to terminate SMTP container: %s", err)
		}
	})

	endpoint, err := ctr.SMTPEndpoint(ctx)
	require.NoError(t, err, "failed to read the SMTP endpoint")
	host, portText, err := net.SplitHostPort(endpoint)
	require.NoError(t, err, "unexpected SMTP endpoint %q", endpoint)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err, "unexpected SMTP port %q", portText)

	api, err := ctr.HTTPURL(ctx)
	require.NoError(t, err, "failed to read the message API URL")

	return SMTPConn{
		Host:     host,
		Port:     port,
		Username: cfg.username,
		Password: cfg.password,
		RootCAs:  pool,
		api:      strings.TrimSuffix(api, "/"),
	}
}

// Messages returns what the server has received, newest last.
func (c SMTPConn) Messages(t *testing.T) []ReceivedMessage {
	t.Helper()

	var list struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(c.get(t, c.api+"/api/v1/messages"), &list))

	// The API reports newest first.
	out := make([]ReceivedMessage, 0, len(list.Messages))
	for i := len(list.Messages) - 1; i >= 0; i-- {
		raw := c.get(t, c.api+"/api/v1/message/"+list.Messages[i].ID+"/raw")

		parsed, err := mail.ReadMessage(strings.NewReader(string(raw)))
		require.NoError(t, err, "received message is not parseable")

		body, err := io.ReadAll(parsed.Body)
		require.NoError(t, err, "failed to read the received body")

		// The subject crosses the wire in encoded-word form whenever it is not
		// plain ASCII. Decoding it here is what lets a caller assert the text
		// the recipient will read, rather than one particular encoding of it.
		subject, err := (&mime.WordDecoder{}).DecodeHeader(parsed.Header.Get("Subject"))
		require.NoError(t, err, "received subject is not decodable")

		headers := make(map[string]string, len(parsed.Header))
		for name, values := range parsed.Header {
			headers[name] = strings.Join(values, ", ")
		}

		out = append(out, ReceivedMessage{
			DecodedSubject: subject,
			Body:           string(body),
			Headers:        headers,
		})
	}

	return out
}

func (c SMTPConn) get(t *testing.T, url string) []byte {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "message API request to %s failed", url)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "message API %s answered %s", url, body)

	return body
}

// serverCertificate mints a certificate the test SMTP server presents on
// STARTTLS, valid for the loopback names a mapped container port is reached
// by, together with a pool that trusts exactly it.
func serverCertificate(t *testing.T) (certPEM, keyPEM []byte, pool *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	pool = x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))

	return certPEM, keyPEM, pool
}

// PostgresConn is how a test reaches the database RunTestPostgres started.
type PostgresConn struct {
	// DB is a database/sql handle over the pgx driver, closed at cleanup.
	DB *sql.DB

	// DSN opens further handles on the same database, for pgxpool.New or
	// gorm.Open.
	DSN string
}

// postgresImage is the PostgreSQL server every RunTestPostgres caller gets by
// default: the newest major CI runs, pinned to an exact minor so a remote tag
// move cannot change what the tests ran against.
const postgresImage = "postgres:18.6-alpine"

// PostgresImageEnv names the environment variable that, when set and not
// empty, replaces the default image RunTestPostgres starts. CI sets it to run
// the whole suite once per supported PostgreSQL major. WithTestPostgresImage
// still takes precedence over it.
const PostgresImageEnv = "SCRTY_TEST_POSTGRES_IMAGE"

// Credentials of the database RunTestPostgres creates. The server is reachable
// only from this host, for the length of one test.
const (
	postgresDatabase = "scrty"
	postgresUsername = "scrty"
	postgresPassword = "scrty"
)

// postgresMaxOpenConns bounds PostgresConn.DB's pool. It is wide enough for
// the race suites, which release several racers per record at once.
const postgresMaxOpenConns = 32

// WithTestPostgresImage replaces the PostgreSQL image RunTestPostgres starts.
// Use it to run against another major or minor. The default is the image
// named by PostgresImageEnv when that is set, and the pinned PostgreSQL 18
// image otherwise.
func WithTestPostgresImage(ref string) TestOption {
	return func(c *testConfig) { c.image = ref }
}

// WithTestPostgresLeftoverTableCheck registers a check RunTestPostgres runs at
// cleanup, after every migration set has rolled back and every finalize
// script has run: it fails naming every table left in the current schema,
// other than the version tables the registered migration sets use. Register
// it to prove a migration set's rollback drops everything its Up created.
//
// The exempt list is built from exactly the version tables
// WithTestPostgresMigrations registered for this call, passed as query
// parameters rather than matched by name pattern: a consumer's version table
// named, say, "auth_schema_versions" is exempted because it was registered,
// not because it happens to start with "goose", and a leftover table that
// merely looks like a goose version table is still named. The default runs
// no such check.
func WithTestPostgresLeftoverTableCheck() TestOption {
	return func(c *testConfig) { c.leftoverTableCheck = true }
}

// postgresLeftoverTables returns every table left in the current schema,
// other than exempt, sorted and joined into one readable line. An empty
// result means nothing is left behind. exempt is bound as query parameters,
// never concatenated into the statement.
func postgresLeftoverTables(ctx context.Context, db *sql.DB, exempt []string) (string, error) {
	query := `SELECT string_agg(tablename, ', ' ORDER BY tablename)
		FROM pg_tables
		WHERE schemaname = current_schema()`

	args := make([]any, len(exempt))
	if len(exempt) > 0 {
		placeholders := make([]string, len(exempt))
		for i, name := range exempt {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args[i] = name
		}
		query += " AND tablename NOT IN (" + strings.Join(placeholders, ", ") + ")"
	}

	var leftover sql.NullString
	if err := db.QueryRowContext(ctx, query, args...).Scan(&leftover); err != nil {
		return "", err
	}
	return leftover.String, nil
}

// WithTestPostgresMigrations applies the goose migration set in directory dir
// of fsys to the database RunTestPostgres returns, recording its versions in
// versionTable. Sets registered by several options are applied in the order
// the options are given. A nil fsys or an empty versionTable stops the test
// at set-up, before that set is used.
//
// At cleanup every set is rolled back to version zero, the last one first,
// and a rollback error fails the test. The default applies no migrations and
// leaves the database empty.
func WithTestPostgresMigrations(fsys fs.FS, dir, versionTable string) TestOption {
	return func(c *testConfig) {
		c.migrations = append(c.migrations, postgresMigrations{fsys: fsys, dir: dir, versionTable: versionTable})
	}
}

// WithTestPostgresFinalizeScripts registers SQL scripts RunTestPostgres runs at
// cleanup, after every migration set has been rolled back, in the order they
// are given (across options too). A script that fails fails the test, naming
// its position, and the next script still runs. Rollback, scripts and the
// leftover-table check share one 30-second budget. The default runs no scripts; WithTestPostgresLeftoverTableCheck
// is what most tests of a migration set want instead.
func WithTestPostgresFinalizeScripts(scripts ...string) TestOption {
	return func(c *testConfig) { c.finalizers = append(c.finalizers, scripts...) }
}

// RunTestPostgres starts a PostgreSQL server for one test and returns how to
// reach its database.
//
// Every call starts its own container, so two tests never see each other's
// rows. DB speaks database/sql through the pgx driver; DSN opens further
// handles on the same database for pgx or gorm.
//
// The container is torn down with the test. It skips the test when Docker is
// unavailable, and fails the test instead when the CI environment variable is
// set (see requireHealthyProvider). Every test that needs PostgreSQL calls
// this rather than starting its own.
func RunTestPostgres(t *testing.T, opts ...TestOption) PostgresConn {
	t.Helper()

	requireHealthyProvider(t)

	cfg := &testConfig{image: postgresImage}
	if ref := os.Getenv(PostgresImageEnv); ref != "" {
		cfg.image = ref
	}
	for _, opt := range opts {
		opt(cfg)
	}

	ctr := startTestPostgres(t, cfg.image)

	ctx := t.Context()

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to read the PostgreSQL connection string")

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err, "failed to open the PostgreSQL database")
	db.SetMaxOpenConns(postgresMaxOpenConns)
	// Registered after Terminate, so it runs before it.
	t.Cleanup(func() { _ = db.Close() })

	postgresSetUp(t, db, cfg)

	return PostgresConn{DB: db, DSN: dsn}
}

// postgresPort is the port the PostgreSQL server listens on inside its
// container.
const postgresPort = "5432/tcp"

// Timeouts of RunTestPostgres's readiness wait. The server's second ready
// line can take most of a minute on a busy Docker host. The host port is
// published when the container starts, so by then it is normally already
// there, and postgresPortTimeout only bounds how long a missing one is
// waited for before the container is given up on.
const (
	postgresReadyTimeout = 60 * time.Second
	postgresPortTimeout  = 10 * time.Second
)

// postgresStartAttempts bounds how many containers RunTestPostgres starts
// for one test when Docker brings a container up without publishing its port.
const postgresStartAttempts = 3

// startTestPostgres starts a PostgreSQL container for t and returns it only
// once the server accepts connections and its port is published on the host.
//
// Under load, Docker Desktop occasionally starts a container that runs and
// logs normally but has no host binding for its port, and never gets one.
// Such a container cannot be reached, so it is stopped and another started,
// up to postgresStartAttempts in all. Any other failure stops the test at
// once. Every container started is terminated with the test.
func startTestPostgres(t *testing.T, image string) *postgres.PostgresContainer {
	t.Helper()

	ctx := t.Context()

	for attempt := 1; ; attempt++ {
		ctr, err := postgres.Run(ctx, image,
			postgres.WithDatabase(postgresDatabase),
			postgres.WithUsername(postgresUsername),
			postgres.WithPassword(postgresPassword),
			// WithWaitStrategy would impose a 60-second deadline of its own
			// on the two waits together, so the deadline is given here as
			// their sum.
			testcontainers.WithWaitStrategyAndDeadline(postgresReadyTimeout+postgresPortTimeout,
				// The line appears once for the init server and once for the
				// real one; only the second means the database accepts
				// connections.
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(postgresReadyTimeout),
				// The log says nothing about the host side: without this,
				// the connection string is read from a container Docker may
				// not have published.
				wait.ForMappedPort(postgresPort).
					WithStartupTimeout(postgresPortTimeout),
			),
		)
		// Registered as soon as a container exists, before the error is
		// checked, so one that started but never became ready is removed too.
		if ctr != nil {
			t.Cleanup(func() {
				// Not t.Context(): it is already cancelled by the time cleanup
				// runs, and Terminate would fail before it removed anything.
				// The budget must exceed Docker's own stop grace period (10s),
				// or a container that needs all of it under load fails the
				// test here.
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				if err := ctr.Terminate(cleanupCtx); err != nil {
					t.Errorf("failed to terminate PostgreSQL container: %s", err)
				}
			})
		}
		if err == nil {
			return ctr
		}
		if attempt == postgresStartAttempts || !postgresPortUnpublished(ctx, ctr) {
			require.NoError(t, err, "failed to start PostgreSQL test container")
		}

		t.Logf("PostgreSQL container %s runs without a published port %s (attempt %d of %d: %v), starting another",
			ctr.GetContainerID(), postgresPort, attempt, postgresStartAttempts, err)
		// Stopped now so it does not load Docker for the rest of the test; the
		// cleanup above still removes it.
		stopTimeout := 2 * time.Second
		if err := ctr.Stop(ctx, &stopTimeout); err != nil {
			t.Logf("failed to stop the unreachable PostgreSQL container: %s", err)
		}
	}
}

// postgresPortUnpublished reports whether ctr is running with no host binding
// for postgresPort, the one failure startTestPostgres retries. A container that
// cannot be inspected, or that is not running, reports false.
func postgresPortUnpublished(ctx context.Context, ctr *postgres.PostgresContainer) bool {
	if ctr == nil {
		return false
	}
	inspect, err := ctr.Inspect(ctx)
	if err != nil || inspect.State == nil || !inspect.State.Running || inspect.NetworkSettings == nil {
		return false
	}
	for port, bindings := range inspect.NetworkSettings.Ports {
		if port.String() == postgresPort {
			return len(bindings) == 0
		}
	}
	return true
}

// ciEnv names the environment variable a CI runner sets, non-empty, to tell
// requireHealthyProvider to fail the test rather than skip it when Docker is
// unhealthy.
const ciEnv = "CI"

// postgresProviderHealth reports whether Docker's provider is usable, or the
// error that makes it not. It is a var, not a call, so this package's own
// tests can simulate an unhealthy provider without touching Docker.
var postgresProviderHealth = func() error {
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		return err
	}
	return provider.Health(context.Background())
}

// requireHealthyProviderTB is the part of testing.TB requireHealthyProvider
// uses, so its own behaviour can be observed by a recorder in this helper's
// tests.
type requireHealthyProviderTB interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// requireHealthyProvider stops the test when Docker is not usable. The
// default, when ciEnv is unset, skips: an unrunnable integration test is more
// useful skipped than failing for a reason that has nothing to do with the
// code. When ciEnv is set it fails the test instead, so a CI runner whose own
// Docker daemon is broken cannot pass the whole PostgreSQL lane without ever
// running it.
func requireHealthyProvider(t requireHealthyProviderTB) {
	t.Helper()

	err := postgresProviderHealth()
	if err == nil {
		return
	}
	if os.Getenv(ciEnv) != "" {
		t.Fatalf("Docker is not running, and CI is set: %s", err)
		return
	}
	t.Skipf("Docker is not running. Testcontainers can't perform its work without it: %s", err)
}

// postgresMigrations is one migration set WithTestPostgresMigrations
// registered.
type postgresMigrations struct {
	fsys         fs.FS
	dir          string
	versionTable string
}

// cleanupTB is the part of testing.TB postgresSetUp uses, so that what its
// teardown reports can be observed by a recorder in the helper's own tests.
type cleanupTB interface {
	Helper()
	Cleanup(f func())
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Context() context.Context
}

// postgresTeardownBudget bounds everything RunTestPostgres does at cleanup:
// rolling back every migration set and running every finalize script.
const postgresTeardownBudget = 30 * time.Second

// postgresSetUp applies cfg's migration sets to db, in the order they were
// registered, and registers the teardown that rolls them back and then runs
// cfg's finalize scripts.
//
// A set that fails to load or apply stops the test. At cleanup every set is
// rolled back to version zero, last registered first, and a rollback error
// fails the test: a Down that does not work is a defect of the set, and
// skipping it quietly would leave the next migration author to find it. The
// finalize scripts then run in declared order, each failure failing the test.
// When WithTestPostgresLeftoverTableCheck was given, the leftover-table check
// runs last, once every rollback and every finalize script has run, exempting
// exactly the version tables cfg's migration sets registered. The whole
// teardown shares one postgresTeardownBudget.
func postgresSetUp(tb cleanupTB, db *sql.DB, cfg *testConfig) {
	tb.Helper()

	type applied struct {
		dir      string
		provider *goose.Provider
	}

	var sets []applied
	// Registered before any set is applied, so a set that fails partway
	// through Up is still rolled back as far as it got.
	tb.Cleanup(func() {
		// Not tb.Context(): it is already cancelled by the time cleanup runs.
		ctx, cancel := context.WithTimeout(context.Background(), postgresTeardownBudget)
		defer cancel()

		for i := len(sets) - 1; i >= 0; i-- {
			if _, err := sets[i].provider.DownTo(ctx, 0); err != nil {
				tb.Errorf("roll back migrations %s: %v", sets[i].dir, err)
			}
		}
		for i, script := range cfg.finalizers {
			if _, err := db.ExecContext(ctx, script); err != nil {
				tb.Errorf("finalize script %d: %v", i, err)
			}
		}
		if cfg.leftoverTableCheck {
			exempt := make([]string, 0, len(cfg.migrations))
			for _, m := range cfg.migrations {
				exempt = append(exempt, m.versionTable)
			}
			switch leftover, err := postgresLeftoverTables(ctx, db, exempt); {
			case err != nil:
				tb.Errorf("leftover table check: %v", err)
			case leftover != "":
				tb.Errorf("tables left behind: %s", leftover)
			}
		}
	})

	for _, m := range cfg.migrations {
		if m.fsys == nil {
			tb.Fatalf("migrations %s: no file system", m.dir)
		}
		// goose would fall back to its own default table, which two sets
		// would then share.
		if m.versionTable == "" {
			tb.Fatalf("migrations %s: no version table", m.dir)
		}
		sub, err := fs.Sub(m.fsys, m.dir)
		if err != nil {
			tb.Fatalf("open migrations %s: %v", m.dir, err)
		}
		p, err := goose.NewProvider(goose.DialectPostgres, db, sub, goose.WithTableName(m.versionTable))
		if err != nil {
			tb.Fatalf("load migrations %s: %v", m.dir, err)
		}
		sets = append(sets, applied{dir: m.dir, provider: p})
		if _, err := p.Up(tb.Context()); err != nil {
			tb.Fatalf("apply migrations %s: %v", m.dir, err)
		}
	}
}

// keycloakImage is the OpenID provider every RunTestKeycloak caller gets,
// pinned by digest so a remote tag move cannot change what the tests ran
// against.
const keycloakImage = "quay.io/keycloak/keycloak:26.7.2@sha256:831330513f55695572286e521f94fcd3c7e285250ed5b848090265a33192f669"

// keycloakStartupTimeout is how long RunTestKeycloak waits for the realm's
// discovery document. Keycloak starts in about twenty seconds on an idle
// host, but well over a minute when other test packages share the Docker host.
const keycloakStartupTimeout = 3 * time.Minute

// The realm RunTestKeycloak imports, and the bootstrap administrator the
// container starts with. The administrator only ever drives the admin API
// from the test process; it is never handed to the code under test.
const (
	keycloakRealm         = "scrty"
	keycloakHTTPSPort     = "8443/tcp"
	keycloakAdminUsername = "admin"
	keycloakAdminPassword = "admin"
)

// keycloakRealmJSON is the realm RunTestKeycloak imports: two confidential
// clients, one per client authentication method, and two users. It is
// embedded so a caller in any package gets the same realm without depending
// on its own working directory.
//
//go:embed testdata/keycloak/realm.json
var keycloakRealmJSON []byte

// keycloakClientAuth is the client authentication method each realm client
// stands for. Keycloak accepts either method from a client-secret client, so
// the pairing is a convention of this fixture, not something Keycloak
// enforces: the method a test exercises is the one its oidc.Provider names.
var keycloakClientAuth = map[string]oidc.ClientAuthMethod{
	"scrty-post":  oidc.ClientSecretPost,
	"scrty-basic": oidc.ClientSecretBasic,
}

// WithTestKeycloakImage replaces the digest-pinned Keycloak image
// RunTestKeycloak starts. Use it to reproduce a report against another
// version; the default is what CI runs.
func WithTestKeycloakImage(ref string) TestOption {
	return func(c *testConfig) { c.image = ref }
}

// WithTestKeycloakBackchannelLogout registers a back-channel logout URL on
// every realm client, so Keycloak delivers a logout token to the test process
// when one of the client's sessions ends.
//
// hostPort is a port the test process is already listening on, on the host.
// Keycloak runs in a container, where the host's loopback is not reachable,
// so the port is exposed into the container through testcontainers' host
// port access, and the URL Keycloak posts to is
// http://host.testcontainers.internal:<hostPort><pathPrefix><client id>.
// The listener must therefore exist before RunTestKeycloak is called; an
// unstarted httptest.Server already holds its listener.
//
// The default registers no back-channel URL, and Keycloak then sends no
// logout token at all.
func WithTestKeycloakBackchannelLogout(hostPort int, pathPrefix string) TestOption {
	return func(c *testConfig) {
		c.backchannelPort = hostPort
		c.backchannelPrefix = pathPrefix
	}
}

// KeycloakClient is one confidential client of the test realm.
type KeycloakClient struct {
	ID          string
	Secret      string
	RedirectURL string                // the only redirect URI the realm accepts for it
	Auth        oidc.ClientAuthMethod // the method this client stands for
}

// KeycloakUser is one user of the test realm. Subject is Keycloak's user id,
// fixed by the realm import, and so the sub every token for the user carries.
type KeycloakUser struct {
	Subject  string
	Username string
	Password string
	Email    string
}

// KeycloakConn is how a test reaches the Keycloak realm RunTestKeycloak
// started.
type KeycloakConn struct {
	// Issuer is the https issuer URL of the test realm, as the test process
	// reaches it.
	Issuer string

	// Clients are the realm's clients, one per client authentication method.
	Clients []KeycloakClient

	// Users are the realm's users, with their passwords.
	Users []KeycloakUser

	// Outbound is a confined client that trusts the certificate Keycloak
	// presents, and nothing else beyond the defaults: https only.
	Outbound *outbound.Client

	// Login plays the user at Keycloak's login page, without a browser: given
	// the authorization redirect, it loads the login form, submits username
	// and password, and returns the redirect Keycloak answers with — the
	// client's callback URL carrying code and state. It fails the test when
	// Keycloak does not redirect back.
	Login func(t *testing.T, authorizeURL, username, password string) (callbackURL string)

	base string       // the Keycloak origin, for the admin API
	hc   *http.Client // trusts the container's certificate, follows no redirect
}

// RunTestKeycloak starts a Keycloak server for one test, with the realm in
// testdata/keycloak/realm.json imported, and returns how to reach it.
//
// Keycloak serves https only, with a certificate generated for this test and
// trusted by KeycloakConn.Outbound, so the code under test keeps its default
// https-only outbound policy and its certificate verification. The container
// is ready only once the realm's discovery document answers, because the port
// opens before the import has finished.
//
// The container is torn down with the test. It skips the test when Docker is
// unavailable. Every test that needs a real OpenID provider calls this rather
// than starting its own.
func RunTestKeycloak(t *testing.T, opts ...TestOption) KeycloakConn {
	t.Helper()

	testcontainers.SkipIfProviderIsNotHealthy(t)

	cfg := &testConfig{image: keycloakImage}
	for _, opt := range opts {
		opt(cfg)
	}

	realm, clients, users := keycloakRealmFixture(t, cfg)

	certPEM, keyPEM, pool := serverCertificate(t)
	keyPEM = pkcs8PEM(t, keyPEM)

	ctx := t.Context()

	customizers := []testcontainers.ContainerCustomizer{
		testcontainers.WithExposedPorts(keycloakHTTPSPort),
		testcontainers.WithCmd("start-dev", "--import-realm"),
		testcontainers.WithEnv(map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME":   keycloakAdminUsername,
			"KC_BOOTSTRAP_ADMIN_PASSWORD":   keycloakAdminPassword,
			"KC_HTTPS_CERTIFICATE_FILE":     "/opt/keycloak/conf/tls.crt",
			"KC_HTTPS_CERTIFICATE_KEY_FILE": "/opt/keycloak/conf/tls.key",
		}),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				Reader:            bytes.NewReader(certPEM),
				ContainerFilePath: "/opt/keycloak/conf/tls.crt",
				FileMode:          0o644,
			},
			testcontainers.ContainerFile{
				Reader:            bytes.NewReader(keyPEM),
				ContainerFilePath: "/opt/keycloak/conf/tls.key",
				FileMode:          0o644,
			},
			testcontainers.ContainerFile{
				Reader:            bytes.NewReader(realm),
				ContainerFilePath: "/opt/keycloak/data/import/realm.json",
				FileMode:          0o644,
			},
		),
		// WithWaitStrategy would wrap the strategy in wait.ForAll with a
		// 60-second deadline of its own, which cuts the startup timeout below
		// short: a JVM starting on a busy Docker host outlasts it. The
		// deadline is therefore given here, equal to the startup timeout.
		testcontainers.WithWaitStrategyAndDeadline(keycloakStartupTimeout,
			wait.ForHTTP("/realms/"+keycloakRealm+"/.well-known/openid-configuration").
				WithPort(keycloakHTTPSPort).
				// A config of its own: a transport mutates the config it is
				// given, so it is never shared with the clients below.
				WithTLS(true, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}).
				WithStatusCodeMatcher(func(status int) bool { return status == http.StatusOK }).
				WithStartupTimeout(keycloakStartupTimeout),
		),
	}
	if cfg.backchannelPort != 0 {
		customizers = append(customizers, testcontainers.WithHostPortAccess(cfg.backchannelPort))
	}

	ctr, err := testcontainers.Run(ctx, cfg.image, customizers...)
	// Registered as soon as a container exists, before the error is checked,
	// so one that started but never became ready is removed too.
	if ctr != nil {
		t.Cleanup(func() {
			// Not t.Context(): it is already cancelled by the time cleanup
			// runs, and Terminate would fail before it removed anything.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// The JVM is slow to honour SIGTERM; nothing in it needs a clean
			// shutdown, so it is killed shortly after.
			if err := ctr.Terminate(cleanupCtx, testcontainers.StopTimeout(2*time.Second)); err != nil {
				t.Fatalf("failed to terminate Keycloak container: %s", err)
			}
		})
	}
	require.NoError(t, err, "failed to start Keycloak test container")

	host, err := ctr.Host(ctx)
	require.NoError(t, err, "failed to read the Keycloak host")
	port, err := ctr.MappedPort(ctx, keycloakHTTPSPort)
	require.NoError(t, err, "failed to read the Keycloak port")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}

	out, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: transport}))
	require.NoError(t, err, "failed to build the outbound client")

	base := "https://" + net.JoinHostPort(host, port.Port())
	hc := &http.Client{
		Transport:     transport,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	return KeycloakConn{
		Issuer:   base + "/realms/" + keycloakRealm,
		Clients:  clients,
		Users:    users,
		Outbound: out,
		Login:    keycloakLogin(transport),
		base:     base,
		hc:       hc,
	}
}

// LogoutUser ends every Keycloak session of the user with this subject
// through the admin API, as an administrator would. Keycloak then delivers a
// back-channel logout token to every client of those sessions that registered
// a back-channel URL.
func (c KeycloakConn) LogoutUser(t *testing.T, subject string) {
	t.Helper()

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {keycloakAdminUsername},
		"password":   {keycloakAdminPassword},
	}
	tokReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		c.base+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.hc.Do(tokReq) //nolint:bodyclose // closed by readAll once the caller is done with it
	require.NoError(t, err, "admin token request failed")
	body := readAll(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "admin token request answered %s", body)

	var tok struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(body, &tok))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		c.base+"/admin/realms/"+keycloakRealm+"/users/"+url.PathEscape(subject)+"/logout", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	resp, err = c.hc.Do(req) //nolint:bodyclose // closed by readAll once the caller is done with it
	require.NoError(t, err, "admin logout request failed")
	body = readAll(t, resp)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "admin logout answered %s", body)
}

// keycloakLoginForm finds the login form's action in Keycloak's login page.
var keycloakLoginForm = regexp.MustCompile(`(?s)<form[^>]*\bid="kc-form-login"[^>]*>`)

// keycloakFormAction reads the action attribute out of a form tag.
var keycloakFormAction = regexp.MustCompile(`\baction="([^"]+)"`)

// keycloakLogin returns KeycloakConn.Login over transport. Each call keeps its
// own cookie jar, as a fresh browser would, so two logins never share a
// Keycloak session.
func keycloakLogin(transport http.RoundTripper) func(t *testing.T, authorizeURL, username, password string) string {
	return func(t *testing.T, authorizeURL, username, password string) string {
		t.Helper()

		jar, err := cookiejar.New(nil)
		require.NoError(t, err)

		hc := &http.Client{
			Transport:     transport,
			Jar:           jar,
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}

		authorizeReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authorizeURL, nil)
		require.NoError(t, err)
		resp, err := hc.Do(authorizeReq) //nolint:bodyclose // closed by readAll once the caller is done with it
		require.NoError(t, err, "loading Keycloak's login page failed")
		page := readAll(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode, "Keycloak's login page answered %s", page)

		form := keycloakLoginForm.Find(page)
		require.NotNil(t, form, "Keycloak's page has no login form: %s", page)
		action := keycloakFormAction.FindSubmatch(form)
		require.NotNil(t, action, "Keycloak's login form has no action: %s", form)

		loginForm := url.Values{
			"username":     {username},
			"password":     {password},
			"credentialId": {""},
		}
		loginReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			html.UnescapeString(string(action[1])), strings.NewReader(loginForm.Encode()))
		require.NoError(t, err)
		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = hc.Do(loginReq) //nolint:bodyclose // closed by readAll once the caller is done with it
		require.NoError(t, err, "submitting Keycloak's login form failed")
		answer := readAll(t, resp)
		require.Equal(t, http.StatusFound, resp.StatusCode,
			"Keycloak did not redirect back after login: %s", answer)

		callback := resp.Header.Get("Location")
		require.NotEmpty(t, callback, "Keycloak's redirect carried no Location")

		return callback
	}
}

// keycloakRealmFixture reads the embedded realm, registers the back-channel
// URL on every client when cfg asks for one, and returns the realm to import
// with the clients and users it defines.
func keycloakRealmFixture(t *testing.T, cfg *testConfig) (realm []byte, clients []KeycloakClient, users []KeycloakUser) {
	t.Helper()

	var doc map[string]any
	require.NoError(t, json.Unmarshal(keycloakRealmJSON, &doc), "the realm fixture is not JSON")

	var shape struct {
		Clients []struct {
			ClientID     string   `json:"clientId"`
			Secret       string   `json:"secret"`
			RedirectURIs []string `json:"redirectUris"`
		} `json:"clients"`
		Users []struct {
			ID          string `json:"id"`
			Username    string `json:"username"`
			Email       string `json:"email"`
			Credentials []struct {
				Value string `json:"value"`
			} `json:"credentials"`
		} `json:"users"`
	}
	require.NoError(t, json.Unmarshal(keycloakRealmJSON, &shape), "the realm fixture has an unexpected shape")

	for _, c := range shape.Clients {
		auth, ok := keycloakClientAuth[c.ClientID]
		require.True(t, ok, "the realm fixture's client %q stands for no client authentication method", c.ClientID)
		require.Len(t, c.RedirectURIs, 1, "the realm fixture's client %q needs exactly one redirect URI", c.ClientID)

		clients = append(clients, KeycloakClient{
			ID:          c.ClientID,
			Secret:      c.Secret,
			RedirectURL: c.RedirectURIs[0],
			Auth:        auth,
		})
	}

	for _, u := range shape.Users {
		require.Len(t, u.Credentials, 1, "the realm fixture's user %q needs exactly one password", u.Username)

		users = append(users, KeycloakUser{
			Subject:  u.ID,
			Username: u.Username,
			Password: u.Credentials[0].Value,
			Email:    u.Email,
		})
	}

	if cfg.backchannelPort != 0 {
		rawClients, ok := doc["clients"].([]any)
		require.True(t, ok, "the realm fixture has no clients list")

		for _, rc := range rawClients {
			client, ok := rc.(map[string]any)
			require.True(t, ok)

			attrs, ok := client["attributes"].(map[string]any)
			if !ok {
				attrs = map[string]any{}
				client["attributes"] = attrs
			}

			attrs["backchannel.logout.url"] = fmt.Sprintf("http://%s:%d%s%s",
				testcontainers.HostInternal, cfg.backchannelPort, cfg.backchannelPrefix, client["clientId"])
		}
	}

	realm, err := json.Marshal(doc)
	require.NoError(t, err)

	return realm, clients, users
}

// pkcs8PEM re-encodes an EC private key in PKCS #8, the encoding Keycloak's
// certificate loader reads.
func pkcs8PEM(t *testing.T, keyPEM []byte) []byte {
	t.Helper()

	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block, "the generated key is not PEM")

	key, err := x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// readAll reads and closes resp's body.
func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()

	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return b
}
