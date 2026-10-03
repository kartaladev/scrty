package test

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

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
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open the PostgreSQL %s admin pool: %w", image, err)
	}
	admin.SetMaxOpenConns(postgresAdminMaxOpenConns)
	return &postgresServer{image: image, adminDSN: dsn, admin: admin, ctr: ctr}, nil
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

	mu      sync.Mutex
	entries map[string]*postgresEntry
}

// defaultPostgresRegistry holds the servers RunTestPostgres shares within one
// test process.
var defaultPostgresRegistry = &postgresRegistry{start: startPostgresContainer}

// server returns the server running image, starting it on the first call for
// that image. Concurrent first calls wait on the one start.
//
// The start runs on a context no test owns: a server outlives the call that
// started it, and the test that made that call ending must not cancel it for
// everyone else. Nothing terminates a shared server; testcontainers' reaper
// removes it when the process exits.
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
// tests. This value is provisional until the peak is measured.
const postgresMaxConnections = 1000

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
	for attempt := 1; ; attempt++ {
		ctr, err := postgres.Run(ctx, image,
			postgres.WithDatabase(postgresDatabase),
			postgres.WithUsername(postgresUsername),
			postgres.WithPassword(postgresPassword),
			testcontainers.WithCmdArgs("-c", "max_connections="+strconv.Itoa(postgresMaxConnections)),
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
