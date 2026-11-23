package gormstore

import (
	"bufio"
	"io/fs"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"

	"github.com/kartaladev/scrty/store/migrate"
)

// migratedColumns reads the migration set and returns, for every table it
// creates, each column's type as the migration declares it. Table-level
// constraint lines (UNIQUE, PRIMARY KEY, CONSTRAINT) declare no column and are
// skipped.
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
	lines:
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			switch {
			case strings.HasPrefix(line, "-- +goose Down"):
				// What the down migration drops is not the schema the
				// models run against.
				break lines
			case strings.HasPrefix(line, "ALTER TABLE ") && strings.Contains(line, " ADD COLUMN "):
				// ALTER TABLE <table> ADD COLUMN <column> <type> ...;
				f := strings.Fields(line)
				require.GreaterOrEqual(t, len(f), 7, "cannot read column line %q", line)
				require.Contains(t, tables, f[2], "column added to table %s, which no migration creates", f[2])
				tables[f[2]][f[5]] = strings.TrimSuffix(f[6], ";")
			case strings.HasPrefix(line, "ALTER TABLE ") && strings.Contains(line, " RENAME TO "):
				// ALTER TABLE <old> RENAME TO <new>;
				f := strings.Fields(line)
				require.Len(t, f, 6, "cannot read rename line %q", line)
				require.Contains(t, tables, f[2], "rename of table %s, which no migration creates", f[2])
				tables[strings.TrimSuffix(f[5], ";")] = tables[f[2]]
				delete(tables, f[2])
			case strings.HasPrefix(line, "CREATE TABLE "):
				table = strings.Fields(line)[2]
				tables[table] = map[string]string{}
			case table == "":
			case strings.HasPrefix(line, ");"):
				table = ""
			case line == "", strings.HasPrefix(line, "--"), strings.HasPrefix(line, "UNIQUE"),
				strings.HasPrefix(line, "PRIMARY"), strings.HasPrefix(line, "CONSTRAINT"):
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

// TestModels pins each model, of the security state and of the identity, to
// the table its migration creates: the table name, every column and its type,
// whatever naming strategy the consumer's *gorm.DB carries. No AutoMigrate
// runs anywhere, so a model that drifted from the migration would only show
// at run time.
//
// It also pins that no column carries a default or an automatic time: gorm
// leaves a zero value out of an insert for a column with a default, and fills
// an automatic time itself, and either would store something other than the
// record the store was given. An automatic created_at or updated_at in
// particular would let gorm stamp its own clock where the store's clock
// (WithClock) must.
func TestModels(t *testing.T) {
	t.Parallel()

	securityState := migratedColumns(t, migrate.SecurityState())
	identity := migratedColumns(t, migrate.Identity())

	// A consumer's naming strategy: models must not depend on gorm's default.
	namers := map[string]schema.Namer{
		"gorm's default naming":          schema.NamingStrategy{},
		"a consumer's prefixed singular": schema.NamingStrategy{TablePrefix: "app_", SingularTable: true, NoLowerCase: true},
	}

	type testCase struct {
		name     string
		model    any
		table    string
		migrated map[string]map[string]string // the columns of the tables the model's migration creates
	}

	cases := []testCase{
		{name: "sessions", model: &sessionRow{}, table: "scrty_sessions", migrated: securityState},
		{name: "one-time tokens", model: &oneTimeTokenRow{}, table: "scrty_one_time_tokens", migrated: securityState},
		{name: "login attempts", model: &loginAttemptRow{}, table: "scrty_login_attempts", migrated: securityState},
		{name: "signing keys", model: &signingKeyRow{}, table: "scrty_signing_keys", migrated: securityState},
		{name: "MFA enrolments", model: &enrolmentRow{}, table: "scrty_mfa_enrolments", migrated: securityState},
		{name: "API keys", model: &apiKeyRow{}, table: "scrty_api_keys", migrated: securityState},
		{name: "OIDC links", model: &linkRow{}, table: "scrty_oidc_links", migrated: securityState},
		{name: "OIDC flows", model: &flowRow{}, table: "scrty_oidc_flows", migrated: securityState},
		{name: "OIDC handoffs", model: &handoffRow{}, table: "scrty_oidc_handoffs", migrated: securityState},
		{name: "recovery codes", model: &recoveryCodeRow{}, table: "scrty_recovery_codes", migrated: securityState},
		{name: "account recoveries", model: &accountRecoveryRow{}, table: "scrty_account_recoveries", migrated: securityState},
		{name: "passkey credentials", model: &passkeyCredentialRow{}, table: "scrty_passkey_credentials", migrated: securityState},
		{name: "passkey user handles", model: &passkeyHandleRow{}, table: "scrty_passkey_user_handles", migrated: securityState},
		{name: "users", model: &userRow{}, table: "scrty_users", migrated: identity},
		{name: "role grants", model: &assignedRoleRow{}, table: "scrty_assigned_roles", migrated: identity},
	}

	for _, tc := range cases {
		for namerName, namer := range namers {
			t.Run(tc.name+" under "+namerName, func(t *testing.T) {
				t.Parallel()

				migrated := tc.migrated
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

// TestModels_AdministrationColumnsAreInert pins that the model fields for the
// columns later changes wire (the user's email, its verification time, the
// deletion time and the version; the session's selected role) are read-only:
// gorm neither inserts nor updates them from a struct, so a store write can
// never put a zero value (a version of 0, an empty email, a zero time) over
// what the migration gave the column, and the columns stay at their NULL or
// default. A later change that wires one of them removes it from this list.
func TestModels_AdministrationColumnsAreInert(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		model   any
		columns []string
	}

	cases := []testCase{
		{
			name:    "users",
			model:   &userRow{},
			columns: []string{"email", "email_verified_at", "deleted_at", "version"},
		},
		{name: "sessions", model: &sessionRow{}, columns: []string{"selected_role"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, err := schema.Parse(tc.model, &sync.Map{}, schema.NamingStrategy{})
			require.NoError(t, err)

			for _, column := range tc.columns {
				f := s.LookUpField(column)
				require.NotNil(t, f, "the model has no field for column %s", column)
				assert.False(t, f.Creatable, "column %s is written by an insert", column)
				assert.False(t, f.Updatable, "column %s is written by an update", column)
				assert.True(t, f.Readable, "column %s is not read", column)
			}
		})
	}
}
