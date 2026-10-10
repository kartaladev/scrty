package test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// postgresServer is one running PostgreSQL server RunTestPostgres hands
// databases out of.
type postgresServer struct {
	image string

	// adminDSN reaches the server's own database, postgresDatabase, and is
	// used for administrative statements.
	adminDSN string
	admin    *sql.DB

	ctr *postgres.PostgresContainer

	// resolve is set on an own server, which Stop and Start may restart under
	// a new host port: its pools look the address up on every dial.
	resolve bool

	// applies counts the migration sets this server has applied to
	// templates, so this package's own tests can see a set applied once.
	applies atomic.Int64

	// tmplMu guards tmplLocks and tmplBuilt. tmplLocks holds one build lock
	// per template name, so one template is built at a time in this process
	// while different templates build in parallel; tmplBuilt records the
	// templates known to be complete.
	tmplMu    sync.Mutex
	tmplLocks map[string]*sync.Mutex
	tmplBuilt map[string]bool
}

// postgresAdminMaxOpenConns bounds a server's admin pool. Administrative
// statements are short and few, so a handful of connections is enough.
const postgresAdminMaxOpenConns = 8

// newPostgresServer wraps a started container: it reads the container's
// connection string and opens the admin pool on it.
func newPostgresServer(ctx context.Context, image string, ctr *postgres.PostgresContainer) (*postgresServer, error) {
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, fmt.Errorf("read the PostgreSQL %s connection string: %w", image, err)
	}
	return openPostgresServer(image, dsn, ctr)
}

// openPostgresServer opens the admin pool on dsn. ctr is nil for a server
// another process started.
func openPostgresServer(image, dsn string, ctr *postgres.PostgresContainer) (*postgresServer, error) {
	return openPostgresServerResolving(image, dsn, ctr, false)
}

// newOwnPostgresServer wraps the container of an own server: its pools
// resolve the address on every dial, so they survive a restart that moves the
// host port.
func newOwnPostgresServer(ctx context.Context, image string, ctr *postgres.PostgresContainer) (*postgresServer, error) {
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, fmt.Errorf("read the PostgreSQL %s connection string: %w", image, err)
	}
	return openPostgresServerResolving(image, dsn, ctr, true)
}

func openPostgresServerResolving(image, dsn string, ctr *postgres.PostgresContainer, resolve bool) (*postgresServer, error) {
	admin, err := openPostgresDB(dsn, ctr, resolve)
	if err != nil {
		return nil, fmt.Errorf("open the PostgreSQL %s admin pool: %w", image, err)
	}
	admin.SetMaxOpenConns(postgresAdminMaxOpenConns)
	return &postgresServer{image: image, adminDSN: dsn, admin: admin, ctr: ctr, resolve: resolve}, nil
}

// postgresDialTimeout bounds one dial of an own server's pool.
const postgresDialTimeout = 5 * time.Second

// openPostgresDB opens a database/sql handle on dsn. With resolve it asks ctr
// for the host port on every dial instead of trusting the one in dsn, because
// Docker maps a restarted container to a new host port.
func openPostgresDB(dsn string, ctr *postgres.PostgresContainer, resolve bool) (*sql.DB, error) {
	if !resolve {
		return sql.Open("pgx", dsn)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.DialFunc = func(ctx context.Context, network, _ string) (net.Conn, error) {
		current, err := ctr.PortEndpoint(ctx, postgresPort, "")
		if err != nil {
			return nil, fmt.Errorf("resolve the PostgreSQL endpoint: %w", err)
		}
		d := net.Dialer{Timeout: postgresDialTimeout}
		return d.DialContext(ctx, network, current)
	}
	return sql.OpenDB(stdlib.GetConnector(*cfg)), nil
}

// postgresEntry is one image's slot in a postgresRegistry: the server started
// for it, or the error its start failed with.
type postgresEntry struct {
	once sync.Once
	srv  *postgresServer
	err  error
}

// postgresRegistry maps a resolved image to the server started for it, so
// that every call in one test process that asks for the same image shares one
// server.
type postgresRegistry struct {
	// start starts a container running image. It is a field so this
	// package's own tests can count or fail starts.
	start func(ctx context.Context, image string) (*postgres.PostgresContainer, error)

	// shareEnv makes the registry read the servers its process inherited
	// from postgresServersEnv before it starts anything, and publish each
	// server it starts there. Only the registry RunTestPostgres uses sets
	// it; this package's own test registries stay out of the environment.
	shareEnv bool

	mu      sync.Mutex
	entries map[string]*postgresEntry
}

// postgresServersEnv names the process environment variable that carries a
// test process's PostgreSQL servers to its children: a JSON object mapping an
// image to the DSN of that server's maintenance database.
const postgresServersEnv = "SCRTY_TEST_POSTGRES_SERVERS"

// postgresServersEnvMu serializes reads and writes of postgresServersEnv, so
// two servers published at once do not drop each other.
var postgresServersEnvMu sync.Mutex

// inheritedPostgresServers reads postgresServersEnv. An unset or empty
// variable names no server; a variable that is not a JSON object of strings is
// an error, because a half-understood list could start a server the parent
// already runs.
func inheritedPostgresServers() (map[string]string, error) {
	postgresServersEnvMu.Lock()
	defer postgresServersEnvMu.Unlock()
	return readPostgresServersEnv()
}

func readPostgresServersEnv() (map[string]string, error) {
	raw := os.Getenv(postgresServersEnv)
	servers := map[string]string{}
	if raw == "" {
		return servers, nil
	}
	if err := json.Unmarshal([]byte(raw), &servers); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object from image to DSN: %w", postgresServersEnv, err)
	}
	return servers, nil
}

// publishPostgresServer records in postgresServersEnv that image is served at
// dsn, keeping the servers already recorded there.
func publishPostgresServer(image, dsn string) error {
	postgresServersEnvMu.Lock()
	defer postgresServersEnvMu.Unlock()

	servers, err := readPostgresServersEnv()
	if err != nil {
		return err
	}
	servers[image] = dsn
	raw, err := json.Marshal(servers)
	if err != nil {
		return fmt.Errorf("encode %s: %w", postgresServersEnv, err)
	}
	if err := os.Setenv(postgresServersEnv, string(raw)); err != nil {
		return fmt.Errorf("set %s: %w", postgresServersEnv, err)
	}
	return nil
}

// postgresInheritPingTimeout bounds the check that an inherited server answers.
const postgresInheritPingTimeout = 30 * time.Second

// inheritPostgresServer returns the server a parent process published for
// image, or nil when the variable names none. It starts nothing, and the
// server it returns has no container, so nothing in this process terminates it.
func inheritPostgresServer(ctx context.Context, image string) (*postgresServer, error) {
	servers, err := inheritedPostgresServers()
	if err != nil {
		return nil, err
	}
	dsn, ok := servers[image]
	if !ok {
		return nil, nil
	}
	srv, err := openPostgresServer(image, dsn, nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, postgresInheritPingTimeout)
	defer cancel()
	if err := srv.admin.PingContext(ctx); err != nil {
		_ = srv.admin.Close()
		return nil, fmt.Errorf("the PostgreSQL %s server named in %s does not answer: %w", image, postgresServersEnv, err)
	}
	return srv, nil
}

// defaultPostgresRegistry holds the servers RunTestPostgres shares within one
// test process.
var defaultPostgresRegistry = &postgresRegistry{start: startPostgresContainer, shareEnv: true}

// server returns the server running image, starting it on the first call for
// that image. Concurrent first calls wait on the one start.
//
// The start runs on a context no test owns: a server outlives the call that
// started it, and the test that made that call ending must not cancel it for
// everyone else. Nothing terminates a shared server; testcontainers' reaper
// removes it when the process exits.
//
// With shareEnv, a server a parent process published in postgresServersEnv is
// used instead of starting one, and a server this call starts is published
// there for the children of this process. An inherited server is never
// terminated by this process.
//
// A failed start is remembered: every later call for the image returns the
// same error at once, and no other start is attempted, so a broken Docker
// costs one start timeout per process rather than one per test.
func (r *postgresRegistry) server(image string) (*postgresServer, error) {
	r.mu.Lock()
	if r.entries == nil {
		r.entries = map[string]*postgresEntry{}
	}
	e, ok := r.entries[image]
	if !ok {
		e = &postgresEntry{}
		r.entries[image] = e
	}
	r.mu.Unlock()

	e.once.Do(func() {
		// Not a test's context: the server outlives the call that started it.
		ctx, cancel := context.WithTimeout(context.Background(),
			postgresStartAttempts*(postgresReadyTimeout+postgresPortTimeout))
		defer cancel()

		if r.shareEnv {
			srv, err := inheritPostgresServer(ctx, image)
			if err != nil {
				e.err = err
				return
			}
			if srv != nil {
				e.srv = srv
				return
			}
		}

		ctr, err := r.start(ctx, image)
		if err != nil {
			e.err = fmt.Errorf("start PostgreSQL %s: %w", image, err)
			return
		}
		e.srv, e.err = newPostgresServer(ctx, image, ctr)
		if e.err != nil {
			// No call will ever get this server, so nothing else removes it
			// before the reaper does at process exit.
			terminatePostgresContainer(ctx, ctr)
			return
		}
		if r.shareEnv {
			if err := publishPostgresServer(image, e.srv.adminDSN); err != nil {
				e.err = err
			}
		}
	})
	return e.srv, e.err
}

// postgresContainerStarts counts the containers startPostgresContainer has
// created in this process, including attempts it gave up on. This package's
// own tests read it to see whether a call started a container.
var postgresContainerStarts atomic.Int64

// postgresTerminateTimeout bounds terminating one container. It must exceed
// Docker's own stop grace period (10s), or a container that needs all of it
// under load fails to be removed.
const postgresTerminateTimeout = 60 * time.Second

// postgresMaxConnections is the server's max_connections. One server carries
// every call of a test process, each with a pool of up to 32 connections, so
// PostgreSQL's default of 100 is exhausted by a store package's parallel
// tests. The value is twice the larger of the peaks measured over a full local
// run of this module (301 connections, pgxstore, children included),
// rounded up to the next 100.
const postgresMaxConnections = 700

// postgresTuning returns the server arguments that make a test server fast.
// The durability settings risk losing data only if the operating system
// crashes, which the lifetime of a test container makes irrelevant, and none
// of them changes isolation, locking or error behaviour: a serializable
// conflict is still SQLSTATE 40001 (TestPostgresServerKeepsSerializableConflicts).
// fsync is off already in the module's own command; it is repeated so the
// tuning does not depend on that default.
func postgresTuning() []string {
	return []string{
		"-c", "fsync=off",
		"-c", "synchronous_commit=off",
		"-c", "full_page_writes=off",
		"-c", "max_connections=" + strconv.Itoa(postgresMaxConnections),
	}
}

// postgresDataDir is where every test server keeps its data. The official
// images disagree on the default (PostgreSQL 15 uses /var/lib/postgresql/data,
// PostgreSQL 18 uses /var/lib/postgresql/18/docker), so PGDATA is set to one
// path for all of them, and postgresTmpfs mounts memory over it.
const postgresDataDir = "/var/lib/postgresql/data"

// postgresTmpfs puts the data directory in memory. Docker backs the VOLUME an
// image declares with a disk volume unless that exact path is mounted, and the
// images declare different ones: /var/lib/postgresql/data up to 15,
// /var/lib/postgresql from 18. Mounting both leaves no disk volume behind
// whichever image runs. The size bounds a runaway test at a clear "no space
// left" failure instead of exhausting the Docker VM's memory.
var postgresTmpfs = map[string]string{
	"/var/lib/postgresql": "rw,size=" + postgresTmpfsSize,
	postgresDataDir:       "rw,size=" + postgresTmpfsSize,
}

// postgresTmpfsSize is the size limit of each tmpfs mount. A migrated clone is
// a few megabytes and is dropped when its call ends.
const postgresTmpfsSize = "2g"

// startPostgresContainer starts a PostgreSQL container running image and
// returns it only once the server accepts connections and its port is
// published on the host.
//
// Under load, Docker Desktop occasionally starts a container that runs and
// logs normally but has no host binding for its port, and never gets one.
// Such a container cannot be reached, so it is removed and another started,
// up to postgresStartAttempts in all. Any other failure is returned at once.
// Every container it gives up on is terminated before it returns, so a
// failure leaves nothing behind; the container it returns is the caller's to
// terminate.
func startPostgresContainer(ctx context.Context, image string) (*postgres.PostgresContainer, error) {
	return startPostgresContainerWith(ctx, image, true)
}

// startPostgresContainerWith is startPostgresContainer with a choice of where
// the data lives, and further customizers. An in-memory data directory
// (inMemory) is lost when the container stops, so an own server, which Stop
// and Start may restart, keeps its data on the container's disk instead.
func startPostgresContainerWith(ctx context.Context, image string, inMemory bool, extra ...testcontainers.ContainerCustomizer) (*postgres.PostgresContainer, error) {
	for attempt := 1; ; attempt++ {
		opts := []testcontainers.ContainerCustomizer{
			postgres.WithDatabase(postgresDatabase),
			postgres.WithUsername(postgresUsername),
			postgres.WithPassword(postgresPassword),
			// The module's own command is "postgres -c fsync=off", so these
			// are appended to it, never a replacement for it.
			testcontainers.WithCmdArgs(postgresTuning()...),
			testcontainers.WithEnv(map[string]string{"PGDATA": postgresDataDir}),
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
		}
		if inMemory {
			opts = append(opts, testcontainers.WithTmpfs(postgresTmpfs))
		}
		ctr, err := postgres.Run(ctx, image, append(opts, extra...)...)
		if ctr != nil {
			postgresContainerStarts.Add(1)
		}
		if err == nil {
			return ctr, nil
		}

		retry := attempt < postgresStartAttempts && postgresPortUnpublished(ctx, ctr)
		if retry {
			log.Printf("PostgreSQL container %s runs without a published port %s (attempt %d of %d: %v), starting another",
				ctr.GetContainerID(), postgresPort, attempt, postgresStartAttempts, err)
		}
		if ctr != nil {
			terminatePostgresContainer(ctx, ctr)
		}
		if !retry {
			return nil, err
		}
	}
}

// terminatePostgresContainer removes a container startPostgresContainer gave
// up on. It detaches from ctx's cancellation, because the start's context may
// be what expired, and a failure to remove the container is only logged: the
// start's error is the one that matters, and the reaper removes the container
// at process exit anyway.
func terminatePostgresContainer(ctx context.Context, ctr *postgres.PostgresContainer) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postgresTerminateTimeout)
	defer cancel()
	if err := ctr.Terminate(ctx, testcontainers.StopTimeout(2*time.Second)); err != nil {
		log.Printf("failed to terminate PostgreSQL container %s: %v", ctr.GetContainerID(), err)
	}
}
