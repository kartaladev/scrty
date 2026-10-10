package pglimiter

import (
	"fmt"

	"github.com/kartaladev/scrty/internal/pgschema"
	"github.com/kartaladev/scrty/ratelimit"
)

// Facts is what Verify reads about the server, in one query
// (pgschema.LimiterServerFacts).
type Facts struct {
	// InRecovery is whether the server is a standby.
	InRecovery bool
	// Version is the server's server_version_num.
	Version int
	// TableExists is whether the bucket table resolves through the
	// connection's search_path.
	TableExists bool
	// Logged is whether that table is logged.
	Logged bool
}

// Check refuses the facts of a server the limiter cannot hold its limits on,
// in this order: a standby, a server older than PostgreSQL 15, a bucket table
// that does not resolve through search_path, and an unlogged one. Every
// refusal wraps ratelimit.ErrConfig.
func (f Facts) Check() error {
	switch {
	case f.InRecovery:
		return fmt.Errorf("%w: the server is a standby (in recovery); the limiter must run on the primary, "+
			"because a standby lags, so it undercounts, and refuses writes", ratelimit.ErrConfig)
	case f.Version < pgschema.LimiterMinServerVersion:
		return fmt.Errorf("%w: the server's server_version_num is %d, older than PostgreSQL 15 (%d), the oldest the limiter supports",
			ratelimit.ErrConfig, f.Version, pgschema.LimiterMinServerVersion)
	case !f.TableExists:
		return fmt.Errorf("%w: the table %s does not resolve through the connection's search_path; "+
			"apply the security-state migration set (migrate.SecurityState) to this database",
			ratelimit.ErrConfig, pgschema.LimiterTable)
	case !f.Logged:
		return fmt.Errorf("%w: the table %s is unlogged, so a crash or a failover would reset every limit to zero; "+
			"make it logged again with ALTER TABLE %s SET LOGGED",
			ratelimit.ErrConfig, pgschema.LimiterTable, pgschema.LimiterTable)
	}
	return nil
}
