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
	// Encoding is the database's server_encoding.
	Encoding string
	// Persistence is the relpersistence of the bucket table that resolves
	// through the connection's search_path: "p" permanent, "u" unlogged, "t"
	// temporary, or "" when no such table resolves.
	Persistence string
}

// Check refuses the facts of a server the limiter cannot hold its limits on,
// in this order: a standby, a server older than PostgreSQL 15, a database whose
// encoding is not UTF8, a bucket table that does not resolve through
// search_path, a temporary one and an unlogged one. Every
// refusal wraps ratelimit.ErrConfig.
func (f Facts) Check() error {
	switch {
	case f.InRecovery:
		return fmt.Errorf("%w: the server is a standby (in recovery); the limiter must run on the primary, "+
			"because a standby lags, so it undercounts, and refuses writes", ratelimit.ErrConfig)
	case f.Version < pgschema.LimiterMinServerVersion:
		return fmt.Errorf("%w: the server's server_version_num is %d, older than PostgreSQL 15 (%d), the oldest the limiter supports",
			ratelimit.ErrConfig, f.Version, pgschema.LimiterMinServerVersion)
	case f.Encoding != "UTF8":
		return fmt.Errorf("%w: the database's server encoding is %s; the limiter needs UTF8, "+
			"the encoding every key and namespace is stored in", ratelimit.ErrConfig, f.Encoding)
	case f.Persistence == "":
		return fmt.Errorf("%w: the table %s does not resolve through the connection's search_path; "+
			"apply the security-state migration set (migrate.SecurityState) to this database",
			ratelimit.ErrConfig, pgschema.LimiterTable)
	case f.Persistence == "t":
		return fmt.Errorf("%w: the table %s resolves to a temporary table, which shadows the migration's "+
			"and lasts only for its session; drop it", ratelimit.ErrConfig, pgschema.LimiterTable)
	case f.Persistence == "u":
		return fmt.Errorf("%w: the table %s is unlogged, so a crash or a failover would reset every limit to zero; "+
			"make it logged again with ALTER TABLE %s SET LOGGED",
			ratelimit.ErrConfig, pgschema.LimiterTable, pgschema.LimiterTable)
	}
	return nil
}
