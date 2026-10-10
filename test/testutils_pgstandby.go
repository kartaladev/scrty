package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PostgresStandby is how a test reaches a primary and the hot standby that
// streams from it. Both are own servers, so Stop and Start work on each.
type PostgresStandby struct {
	// Primary is the read-write server. Migrations given to
	// RunTestPostgresStandby are applied to it.
	Primary PostgresConn

	// Standby is a read-only streaming replica of Primary. It reaches the
	// same database name as Primary, and sees Primary's writes once they
	// replicate.
	Standby PostgresConn
}

// Names inside the Docker network the primary and standby share.
const (
	postgresPrimaryAlias = "scrty-primary"

	// postgresStandbyReadyLine is logged once a standby accepts read-only
	// connections, the standby's counterpart of the primary's ready line.
	postgresStandbyReadyLine = "database system is ready to accept read-only connections"

	// postgresStandbyReadyTimeout is how long the base backup and the
	// standby's start are given.
	postgresStandbyReadyTimeout = 2 * time.Minute
)

// postgresReplicationHBA is the init script that lets the server's user stream
// WAL. The official images allow every user to connect to every database from
// the network, but not to replicate: the "replication" keyword matches no
// database name, so it needs a line of its own. The script runs once, while
// the data directory is initialised, before the real server starts.
const postgresReplicationHBA = `#!/bin/sh
set -e
echo "host replication all all scram-sha-256" >> "$PGDATA/pg_hba.conf"
`

// postgresStandbyScript is the standby's entrypoint. It copies the primary's
// data directory over the replication protocol (-R writes standby.signal and
// primary_conninfo, -X stream carries the WAL the copy needs, -c fast skips
// waiting for a spread checkpoint), then runs the server. The copy is skipped
// when the data directory already holds one, which is the case when Start
// restarts the container. The server must run
// with at least the primary's max_connections, so it takes the same tuning.
func postgresStandbyScript() string {
	args := make([]string, 0, len(postgresTuning()))
	for _, a := range postgresTuning() {
		args = append(args, "'"+a+"'")
	}
	return fmt.Sprintf(`set -e
export PGPASSWORD=%s
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  mkdir -p "$PGDATA"
  chmod 700 "$PGDATA"
  pg_basebackup -h %s -U %s -D "$PGDATA" -R -X stream -c fast
fi
exec postgres %s
`, postgresPassword, postgresPrimaryAlias, postgresUsername, strings.Join(args, " "))
}

// RunTestPostgresStandby starts an own primary and a hot standby streaming
// from it, and returns a connection to each.
//
// The primary is what RunTestPostgres(t, WithTestPostgresOwnServer(), opts...)
// returns, set up for streaming replication. The standby runs the same image
// (WithTestPostgresImage, else PostgresImageEnv, else the default): it copies
// the primary with pg_basebackup over a Docker network created for the call,
// then runs as a hot standby. WithTestPostgresMigrations and the other options
// act on the primary only; the standby receives their effect by replication,
// after the base backup, so the database the primary's migrations built is
// already there when this returns. Both containers and the network are removed
// at cleanup.
//
// Stop and Start work on both connections. A restarted standby resumes
// streaming; a restarted primary is where the standby streams from.
func RunTestPostgresStandby(t *testing.T, opts ...TestOption) PostgresStandby {
	t.Helper()

	cfg := &testConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if err := cfg.postgresConfigError(); err != nil {
		t.Fatalf("%v", err)
	}
	requireHealthyProvider(t)
	image := resolvePostgresImage(cfg)

	// Registered first, so it runs after both containers are gone.
	nw, err := network.New(t.Context())
	require.NoError(t, err, "failed to create the Docker network")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), postgresTerminateTimeout)
		defer cancel()
		if err := nw.Remove(ctx); err != nil {
			t.Errorf("failed to remove the Docker network: %s", err)
		}
	})

	// The primary: replication settings and an hba line for it. The replica
	// settings are the server defaults on current majors; they are given so
	// the helper does not depend on that.
	hba := testcontainers.ContainerFile{
		Reader:            bytes.NewReader([]byte(postgresReplicationHBA)),
		ContainerFilePath: "/docker-entrypoint-initdb.d/10-replication.sh",
		FileMode:          0o755,
	}
	srv := startTestPostgres(t, image,
		network.WithNetwork([]string{postgresPrimaryAlias}, nw),
		testcontainers.WithFiles(hba),
		testcontainers.WithCmdArgs("-c", "wal_level=replica", "-c", "max_wal_senders=4", "-c", "hot_standby=on"),
	)
	primary := postgresProvision(t, srv, cfg)

	// The standby copies the primary only after its migrations and clone
	// exist, so it carries them from the start.
	sbCtr, err := startPostgresStandbyContainer(t.Context(), image, nw)
	if sbCtr != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), postgresTerminateTimeout)
			defer cancel()
			if err := sbCtr.Terminate(ctx, testcontainers.StopTimeout(2*time.Second)); err != nil {
				t.Errorf("failed to terminate the PostgreSQL standby container: %s", err)
			}
		})
	}
	if err != nil && sbCtr != nil {
		// The script's own messages (a refused copy, a bad setting) are the
		// reason, and the container is about to be removed with them.
		if rc, lerr := sbCtr.Logs(context.WithoutCancel(t.Context())); lerr == nil {
			logs, _ := io.ReadAll(rc)
			_ = rc.Close()
			t.Logf("standby container output:\n%s", logs)
		}
	}
	require.NoError(t, err, "failed to start the PostgreSQL standby container")

	sbSrv, err := newOwnPostgresServer(t.Context(), image, sbCtr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sbSrv.admin.Close() })

	u, err := url.Parse(primary.DSN)
	require.NoError(t, err)
	dsn, err := sbSrv.dsnFor(strings.TrimPrefix(u.Path, "/"))
	require.NoError(t, err)
	db, err := openPostgresDB(dsn, sbCtr, true)
	require.NoError(t, err)
	db.SetMaxOpenConns(postgresMaxOpenConns)
	t.Cleanup(func() { _ = db.Close() })

	return PostgresStandby{
		Primary: primary,
		Standby: PostgresConn{DB: db, DSN: dsn, ctr: sbCtr},
	}
}

// startPostgresStandbyContainer starts a container of image that copies the
// primary on nw and then runs as its hot standby. It returns once the standby
// accepts read-only connections and its port is published. The container is
// returned alongside an error when it started but did not become ready, so
// the caller can remove it.
func startPostgresStandbyContainer(ctx context.Context, image string, nw *testcontainers.DockerNetwork) (*postgres.PostgresContainer, error) {
	return postgres.Run(ctx, image,
		// Only for ConnectionString: the entrypoint below replaces the
		// image's, so these set nothing in the standby itself.
		postgres.WithDatabase(postgresDatabase),
		postgres.WithUsername(postgresUsername),
		postgres.WithPassword(postgresPassword),
		testcontainers.WithEnv(map[string]string{"PGDATA": postgresDataDir}),
		// pg_basebackup and postgres refuse to run as root, and the image's
		// own entrypoint, which would drop privileges, is the one replaced.
		testcontainers.CustomizeRequestOption(func(req *testcontainers.GenericContainerRequest) error {
			// The deprecated field is the one that needs no import of the
			// Docker API types, which this module does not require directly.
			req.User = "postgres" //nolint:staticcheck
			return nil
		}),
		testcontainers.WithEntrypoint("sh", "-c", postgresStandbyScript()),
		testcontainers.WithCmd(),
		network.WithNetwork(nil, nw),
		testcontainers.WithWaitStrategyAndDeadline(postgresStandbyReadyTimeout+postgresPortTimeout,
			wait.ForLog(postgresStandbyReadyLine).WithStartupTimeout(postgresStandbyReadyTimeout),
			wait.ForMappedPort(postgresPort).WithStartupTimeout(postgresPortTimeout),
		),
	)
}
