package gorm

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"

	"github.com/kartaladev/scrty/migrate"
)

// TestIdentityModels pins each identity model to the table the identity
// migration creates, as TestModels does for the security-state models: the
// table name, every column and its type, whatever naming strategy the
// consumer's *gorm.DB carries, and no column with a default or an automatic
// time. An automatic created_at or updated_at in particular would let gorm
// stamp its own clock where the store's clock (WithClock) must.
func TestIdentityModels(t *testing.T) {
	t.Parallel()

	migrated := migratedColumns(t, migrate.Identity())

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
		{name: "users", model: &userRow{}, table: "users"},
		{name: "role grants", model: &assignedRoleRow{}, table: "assigned_roles"},
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
