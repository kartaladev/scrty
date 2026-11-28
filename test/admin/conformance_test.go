//go:build admin_stub

package admintest_test

import (
	"context"
	"testing"
	"time"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	admintest "github.com/kartaladev/scrty/test/admin"
)

// TestStubConformance runs the suite against a fixture whose every port call
// answers admin.ErrNotFound (or identity.ErrUserNotFound) and whose hooks do
// nothing. It is the suite's red step: every case must fail on an assertion,
// none on a compile error or a panic. It sits behind the admin_stub build tag
// so the default run does not carry a test that is meant to fail:
//
//	go test -race -count=1 -tags admin_stub ./admin/...
func TestStubConformance(t *testing.T) {
	t.Parallel()

	admintest.RunConformanceSuite(t, func(t *testing.T) admintest.Fixture {
		t.Helper()

		return stubFixture{}
	})
}

type stubFixture struct{}

var (
	_ admintest.Fixture       = stubFixture{}
	_ admintest.HistorySeeder = stubFixture{}
)

func (stubFixture) Users() admin.UserStore                { return stubStore{} }
func (stubFixture) Importer() admin.ImportStore           { return stubStore{} }
func (stubFixture) Roles() admin.RoleStore                { return stubStore{} }
func (stubFixture) Grants() admin.GrantStore              { return stubStore{} }
func (stubFixture) Assignments() admin.AssignmentStore    { return stubStore{} }
func (stubFixture) Loader() identity.UserLoader           { return stubStore{} }
func (stubFixture) Provisioner() identity.UserProvisioner { return stubStore{} }

func (stubFixture) UserResidue(context.Context, identity.UserID) (admintest.Residue, error) {
	return admintest.Residue{}, nil
}

func (stubFixture) SeedOrganization(context.Context, *identity.Organization) error { return nil }

func (stubFixture) SeedPasswordHistory(context.Context, identity.UserID, []byte) error { return nil }

func (stubFixture) FailGrantWrite(context.Context, string, string, string) error { return nil }

func (stubFixture) StallGrantWrite(context.Context, string, string, string) (<-chan struct{}, error) {
	ch := make(chan struct{})
	close(ch)

	return ch, nil
}

// stubStore answers every call as if nothing were stored.
type stubStore struct{}

func (stubStore) ListUsers(context.Context, admin.UserQuery) ([]admin.User, error) {
	return nil, admin.ErrNotFound
}

func (stubStore) GetUser(context.Context, identity.UserID) (admin.User, error) {
	return admin.User{}, admin.ErrNotFound
}

func (stubStore) CreateUser(context.Context, admin.NewUser) (admin.User, error) {
	return admin.User{}, admin.ErrNotFound
}

func (stubStore) UpdateUser(context.Context, identity.UserID, int64, admin.UserChange) (admin.User, bool, error) {
	return admin.User{}, false, admin.ErrNotFound
}

func (stubStore) SetActive(context.Context, identity.UserID, int64, bool) (admin.User, bool, error) {
	return admin.User{}, false, admin.ErrNotFound
}

func (stubStore) DeleteUser(context.Context, identity.UserID, int64) error { return admin.ErrNotFound }

func (stubStore) CurrentPasswordHash(context.Context, identity.UserID) ([]byte, error) {
	return nil, admin.ErrNotFound
}

func (stubStore) SetPassword(context.Context, identity.UserID, int64, []byte, time.Time) (admin.User, error) {
	return admin.User{}, admin.ErrNotFound
}

func (stubStore) ImportUser(context.Context, admin.ImportedUser) (admin.ImportOutcome, error) {
	return 0, admin.ErrNotFound
}

func (stubStore) ListRoles(context.Context, string) ([]admin.Role, error) {
	return nil, admin.ErrNotFound
}

func (stubStore) GetRole(context.Context, string) (admin.Role, error) {
	return admin.Role{}, admin.ErrNotFound
}

func (stubStore) CreateRole(context.Context, admin.Role) (admin.Role, error) {
	return admin.Role{}, admin.ErrNotFound
}

func (stubStore) UpdateRole(context.Context, string, int64, admin.RoleChange) (admin.Role, error) {
	return admin.Role{}, admin.ErrNotFound
}

func (stubStore) DeleteRole(context.Context, string, int64, bool) error { return admin.ErrNotFound }

func (stubStore) GetGrants(context.Context, string) ([]admin.Grant, int64, error) {
	return nil, 0, admin.ErrNotFound
}

func (stubStore) ReplaceGrants(context.Context, string, int64, []admin.ResourceGrants) (int64, error) {
	return 0, admin.ErrNotFound
}

func (stubStore) ListAssignments(context.Context, identity.UserID) ([]*identity.AssignedRole, int64, error) {
	return nil, 0, admin.ErrNotFound
}

func (stubStore) AddAssignment(context.Context, identity.UserID, int64, admin.Assignment) (int64, error) {
	return 0, admin.ErrNotFound
}

func (stubStore) RemoveAssignment(context.Context, identity.UserID, int64, string) (int64, error) {
	return 0, admin.ErrNotFound
}

func (stubStore) SetPrimary(context.Context, identity.UserID, int64, string) (int64, error) {
	return 0, admin.ErrNotFound
}

func (stubStore) LoadByUsername(context.Context, string) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

func (stubStore) LoadByUserID(context.Context, identity.UserID) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

func (stubStore) Provision(context.Context, string, ...identity.UserOption) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

func (stubStore) Update(context.Context, string, ...identity.UserOption) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}
