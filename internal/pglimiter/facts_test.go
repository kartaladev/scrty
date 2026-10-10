package pglimiter_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pglimiter"
)

// TestFactsCheck pins the order Verify refuses a server's facts in, their
// messages, and the version floor, which no supported server can be made to
// fail.
func TestFactsCheck(t *testing.T) {
	t.Parallel()

	healthy := pglimiter.Facts{InRecovery: false, Version: 150000, TableExists: true, Logged: true}

	const (
		standby = "the server is a standby (in recovery); the limiter must run on the primary, " +
			"because a standby lags, so it undercounts, and refuses writes"
		missing = "the table rate_limit_buckets does not resolve through the connection's search_path; " +
			"apply the security-state migration set (migrate.SecurityState) to this database"
		unlogged = "the table rate_limit_buckets is unlogged, so a crash or a failover would reset every limit to zero; " +
			"make it logged again with ALTER TABLE rate_limit_buckets SET LOGGED"
	)

	type testCase struct {
		name   string
		facts  func(f pglimiter.Facts) pglimiter.Facts
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "PostgreSQL 15 primary",
			facts:  func(f pglimiter.Facts) pglimiter.Facts { return f },
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:   "PostgreSQL 18 primary",
			facts:  func(f pglimiter.Facts) pglimiter.Facts { f.Version = 180006; return f },
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
		{
			name:  "PostgreSQL 14",
			facts: func(f pglimiter.Facts) pglimiter.Facts { f.Version = 140013; return f },
			assert: refusedWith("the server's server_version_num is 140013, older than PostgreSQL 15 (150000), " +
				"the oldest the limiter supports"),
		},
		{
			name: "standby before everything else",
			facts: func(pglimiter.Facts) pglimiter.Facts {
				return pglimiter.Facts{InRecovery: true, Version: 140000}
			},
			assert: refusedWith(standby),
		},
		{
			name: "version before the table",
			facts: func(pglimiter.Facts) pglimiter.Facts {
				return pglimiter.Facts{Version: 140000}
			},
			assert: refusedWith("the server's server_version_num is 140000, older than PostgreSQL 15 (150000), " +
				"the oldest the limiter supports"),
		},
		{
			name: "missing table",
			facts: func(f pglimiter.Facts) pglimiter.Facts {
				f.TableExists, f.Logged = false, false
				return f
			},
			assert: refusedWith(missing),
		},
		{
			name:   "unlogged table",
			facts:  func(f pglimiter.Facts) pglimiter.Facts { f.Logged = false; return f },
			assert: refusedWith(unlogged),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.facts(healthy).Check())
		})
	}
}
