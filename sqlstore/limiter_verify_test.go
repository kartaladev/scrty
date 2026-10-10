package sqlstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/ratelimit"
)

// TestLimiterServerFacts_Check pins the order Verify refuses a server's facts
// in, and the version floor, which no supported server can be made to fail.
func TestLimiterServerFacts_Check(t *testing.T) {
	t.Parallel()

	refused := func(want string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			require.ErrorIs(t, err, ratelimit.ErrConfig)
			assert.Contains(t, err.Error(), want)
		}
	}
	healthy := limiterServerFacts{inRecovery: false, version: 150000, tableExists: true, logged: true}

	type testCase struct {
		name   string
		facts  func(f limiterServerFacts) limiterServerFacts
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{name: "PostgreSQL 15 primary", facts: func(f limiterServerFacts) limiterServerFacts { return f },
			assert: func(t *testing.T, err error) { require.NoError(t, err) }},
		{name: "PostgreSQL 18 primary", facts: func(f limiterServerFacts) limiterServerFacts { f.version = 180006; return f },
			assert: func(t *testing.T, err error) { require.NoError(t, err) }},
		{name: "PostgreSQL 14", facts: func(f limiterServerFacts) limiterServerFacts { f.version = 140013; return f },
			assert: refused("140013")},
		{name: "standby before everything else", facts: func(limiterServerFacts) limiterServerFacts {
			return limiterServerFacts{inRecovery: true, version: 140000}
		}, assert: refused("standby")},
		{name: "version before the table", facts: func(limiterServerFacts) limiterServerFacts {
			return limiterServerFacts{version: 140000}
		}, assert: refused("PostgreSQL 15")},
		{name: "missing table", facts: func(f limiterServerFacts) limiterServerFacts {
			f.tableExists, f.logged = false, false
			return f
		}, assert: refused("security-state migration set")},
		{name: "unlogged table", facts: func(f limiterServerFacts) limiterServerFacts { f.logged = false; return f },
			assert: refused("unlogged")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, tc.facts(healthy).check())
		})
	}
}
