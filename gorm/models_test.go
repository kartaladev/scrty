package gorm

import (
	"bufio"
	"io/fs"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"

	"github.com/kartaladev/scrty/migrate"
)

// migratedColumns reads the migration set and returns, for every table it
// creates, each column's type as the migration declares it. Table-level
// constraint lines (UNIQUE, PRIMARY KEY) declare no column and are skipped.
func migratedColumns(t *testing.T, set migrate.Set) map[string]map[string]string {
	t.Helper()

	files, err := fs.Glob(set.FS(), set.Dir+"/*.sql")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	tables := map[string]map[string]string{}
	for _, name := range files {
		data, err := fs.ReadFile(set.FS(), name)
		require.NoError(t, err)

		var table string
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			switch {
			case strings.HasPrefix(line, "CREATE TABLE "):
				table = strings.Fields(line)[2]
				tables[table] = map[string]string{}
			case table == "":
			case strings.HasPrefix(line, ");"):
				table = ""
			case line == "", strings.HasPrefix(line, "--"), strings.HasPrefix(line, "UNIQUE"),
				strings.HasPrefix(line, "PRIMARY"):
			default:
				f := strings.Fields(line)
				require.GreaterOrEqual(t, len(f), 2, "cannot read column line %q", line)
				tables[table][f[0]] = strings.TrimSuffix(f[1], ",")
			}
		}
		require.NoError(t, scanner.Err())
	}

	return tables
}

// TestModels pins each model to the table the migration creates: the table
// name, every column and its type, whatever naming strategy the consumer's
// *gorm.DB carries. No AutoMigrate runs anywhere, so a model that drifted from
// the migration would only show at run time.
//
// It also pins that no column carries a default or an automatic time: gorm
// leaves a zero value out of an insert for a column with a default, and fills
// an automatic time itself, and either would store something other than the
// record the store was given.
func TestModels(t *testing.T) {
	t.Parallel()

	migrated := migratedColumns(t, migrate.SecurityState())

	// A consumer's naming strategy: models must not depend on gorm's default.
	namers := map[string]schema.Namer{
		"gorm's default naming":          schema.NamingStrategy{},
		"a consumer's prefixed singular": schema.NamingStrategy{TablePrefix: "app_", SingularTable: true, NoLowerCase: true},
	}

	type testCase struct {
		name  string
		model any
		table string
	}

	cases := []testCase{
		{name: "sessions", model: &sessionRow{}, table: "sessions"},
		{name: "one-time tokens", model: &oneTimeTokenRow{}, table: "one_time_tokens"},
		{name: "login attempts", model: &loginAttemptRow{}, table: "login_attempts"},
		{name: "signing keys", model: &signingKeyRow{}, table: "signing_keys"},
		{name: "MFA enrolments", model: &enrolmentRow{}, table: "mfa_enrolments"},
		{name: "API keys", model: &apiKeyRow{}, table: "api_keys"},
		{name: "OIDC links", model: &linkRow{}, table: "oidc_links"},
		{name: "OIDC flows", model: &flowRow{}, table: "oidc_flows"},
		{name: "OIDC handoffs", model: &handoffRow{}, table: "oidc_handoffs"},
	}

	for _, tc := range cases {
		for namerName, namer := range namers {
			t.Run(tc.name+" under "+namerName, func(t *testing.T) {
				t.Parallel()

				s, err := schema.Parse(tc.model, &sync.Map{}, namer)
				require.NoError(t, err)
				assert.Equal(t, tc.table, s.Table)

				want, ok := migrated[tc.table]
				require.True(t, ok, "the migration creates no table %s", tc.table)

				got := map[string]string{}
				for _, f := range s.Fields {
					if f.DBName == "" {
						continue
					}
					got[f.DBName] = f.TagSettings["TYPE"]
					assert.False(t, f.HasDefaultValue, "column %s has a default", f.DBName)
					assert.Zero(t, f.AutoCreateTime, "column %s is filled on create", f.DBName)
					assert.Zero(t, f.AutoUpdateTime, "column %s is filled on update", f.DBName)
				}
				assert.Equal(t, want, got)

				require.Len(t, s.PrimaryFields, 1)
				assert.Equal(t, "id", s.PrimaryFields[0].DBName)
			})
		}
	}
}
