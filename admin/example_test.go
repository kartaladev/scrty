package admin_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/identity"
)

// The stores below are the smallest in-memory ports the examples need. An
// application uses scrty's identity stores, or its own store behind the same
// ports.

// exampleUserStore holds users in a map; it implements only what
// ExampleUsers and ExampleWithSessionRevocation call in full, renames
// included, and offset listing and counts
// (admin.UserPager). It applies no filter, only the order and the page.
type exampleUserStore struct {
	users map[identity.UserID]admin.User
}

func (s *exampleUserStore) ListUsers(context.Context, admin.UserQuery) ([]admin.User, error) {
	return slices.Collect(maps.Values(s.users)), nil
}

// ListUsersFrom lists in username order, skipping offset users.
func (s *exampleUserStore) ListUsersFrom(_ context.Context, q admin.UserQuery, offset int) ([]admin.User, error) {
	all := slices.SortedFunc(maps.Values(s.users), func(a, b admin.User) int {
		return strings.Compare(a.Username, b.Username)
	})

	if offset >= len(all) {
		return nil, nil
	}

	all = all[offset:]

	return all[:min(q.Limit, len(all))], nil
}

func (s *exampleUserStore) CountUsers(context.Context, admin.UserQuery) (int64, error) {
	return int64(len(s.users)), nil
}

func (s *exampleUserStore) GetUser(_ context.Context, id identity.UserID) (admin.User, error) {
	u, ok := s.users[id]
	if !ok {
		return admin.User{}, admin.ErrNotFound
	}

	return u, nil
}

func (s *exampleUserStore) CreateUser(_ context.Context, nu admin.NewUser) (admin.User, error) {
	u := admin.User{ID: nu.ID, Username: nu.Username, Name: nu.Name, Email: nu.Email, Active: true, Version: 1}
	s.users[nu.ID] = u

	return u, nil
}

// UpdateUser applies the name and the username. A real store also refuses a
// username another user holds, under the row lock.
func (s *exampleUserStore) UpdateUser(_ context.Context, id identity.UserID, version int64, c admin.UserChange) (admin.User, bool, error) {
	u, ok := s.users[id]
	if !ok {
		return admin.User{}, false, admin.ErrNotFound
	}

	if u.Version != version {
		return admin.User{}, false, admin.ErrStaleUpdate
	}

	renamed := c.Username != nil && *c.Username != u.Username
	if c.Username != nil {
		u.Username = *c.Username
	}

	if c.Name != nil {
		u.Name = *c.Name
	}

	u.Version++
	s.users[id] = u

	return u, renamed, nil
}

func (s *exampleUserStore) SetActive(_ context.Context, id identity.UserID, version int64, active bool) (admin.User, bool, error) {
	u, ok := s.users[id]
	if !ok {
		return admin.User{}, false, admin.ErrNotFound
	}

	if u.Version != version {
		return admin.User{}, false, admin.ErrStaleUpdate
	}

	if u.Active == active {
		return u, false, nil
	}

	u.Active = active
	u.Version++
	s.users[id] = u

	return u, true, nil
}

func (s *exampleUserStore) DeleteUser(_ context.Context, id identity.UserID, _ int64) error {
	delete(s.users, id)

	return nil
}

func (s *exampleUserStore) CurrentPasswordHash(context.Context, identity.UserID) ([]byte, error) {
	return nil, nil
}

func (s *exampleUserStore) SetPassword(_ context.Context, id identity.UserID, _ int64, _ []byte, _ time.Time) (admin.User, error) {
	return s.users[id], nil
}

// printEvent is an event sink that prints what an administration event
// carries.
func printEvent(_ context.Context, e event.Event) {
	fmt.Printf("event %s actor=%s changed=%v\n", e.Name, e.Actor, e.Changed)
}

// ExampleUsers creates a user from a job, renames and deactivates it, and
// deactivates it again, which changes nothing and reports nothing.
func ExampleUsers() {
	users, err := admin.NewUsers(&exampleUserStore{users: map[identity.UserID]admin.User{}},
		admin.WithEventSink(printEvent))
	if err != nil {
		panic(err)
	}

	ctx := admin.WithSystemActor(context.Background(), "onboarding")

	ada, err := users.Create(ctx, admin.NewUser{Username: "ada", Name: "Ada", Email: "ada@example.com"})
	if err != nil {
		panic(err)
	}

	name := "Ada Lovelace"

	ada, err = users.Update(ctx, ada.ID, ada.Version, admin.UserChange{Name: &name})
	if err != nil {
		panic(err)
	}

	ada, err = users.Deactivate(ctx, ada.ID, ada.Version)
	if err != nil {
		panic(err)
	}

	ada, err = users.Deactivate(ctx, ada.ID, ada.Version)
	fmt.Println(ada.Name, "active:", ada.Active, "version:", ada.Version, "error:", err)

	_, err = users.Deactivate(context.Background(), ada.ID, ada.Version)
	fmt.Println(errors.Is(err, admin.ErrNoActor))

	// Output:
	// event user_created actor=system:onboarding changed=[]
	// event user_updated actor=system:onboarding changed=[name]
	// event user_archived actor=system:onboarding changed=[active]
	// Ada Lovelace active: false version: 3 error: <nil>
	// true
}

// exampleImportStore holds imported users by identifier and writes only what
// differs.
type exampleImportStore struct {
	users map[identity.UserID]admin.ImportedUser
}

func (s *exampleImportStore) ImportUser(_ context.Context, u admin.ImportedUser) (admin.ImportOutcome, error) {
	old, ok := s.users[u.ID]
	s.users[u.ID] = u

	switch {
	case !ok:
		return admin.ImportCreated, nil
	case reflect.DeepEqual(old, u):
		return admin.ImportUnchanged, nil
	default:
		return admin.ImportUpdated, nil
	}
}

// ExampleImporter imports a user with a bcrypt hash from another system, twice:
// the second run finds every value equal and reports nothing. A hash the
// recogniser does not recognise is refused before the store is called.
func ExampleImporter() {
	bcrypt, err := password.NewBcryptEncoder()
	if err != nil {
		panic(err)
	}

	hash, err := bcrypt.Encode("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	importer, err := admin.NewImporter(&exampleImportStore{users: map[identity.UserID]admin.ImportedUser{}},
		bcrypt, admin.WithEventSink(printEvent))
	if err != nil {
		panic(err)
	}

	ctx := admin.WithSystemActor(context.Background(), "sync")
	ada := admin.ImportedUser{
		ID: "0192f1e2-3c4d-7e5f-8a9b-0c1d2e3f4a5b", Username: "ada", Email: "ada@example.com",
		PasswordHash: hash, Active: true,
		CreatedAt: time.Date(2021, 3, 4, 0, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2021, 3, 4, 0, 0, 0, 0, time.UTC),
	}

	for range 2 {
		out, err := importer.Import(ctx, ada)
		fmt.Println(out, err)
	}

	ada.PasswordHash = []byte("plain-text-is-not-a-hash")
	_, err = importer.Import(ctx, ada)
	fmt.Println(errors.Is(err, admin.ErrInvalidInput))

	// Output:
	// event scrty_user_imported actor=system:sync changed=[]
	// created <nil>
	// unchanged <nil>
	// true
}

// exampleRoleStore holds roles in a map.
type exampleRoleStore struct{ roles map[string]admin.Role }

func (s *exampleRoleStore) ListRoles(_ context.Context, label string) ([]admin.Role, error) {
	var out []admin.Role

	for _, name := range slices.Sorted(maps.Keys(s.roles)) {
		if r := s.roles[name]; label == "" || slices.Contains(r.Labels, label) {
			out = append(out, r)
		}
	}

	return out, nil
}

func (s *exampleRoleStore) GetRole(_ context.Context, name string) (admin.Role, error) {
	r, ok := s.roles[name]
	if !ok {
		return admin.Role{}, admin.ErrNotFound
	}

	return r, nil
}

func (s *exampleRoleStore) CreateRole(_ context.Context, r admin.Role) (admin.Role, error) {
	if _, ok := s.roles[r.Name]; ok {
		return admin.Role{}, admin.AlreadyExistsError{Field: admin.FieldRole}
	}

	r.Version = 1
	s.roles[r.Name] = r

	return r, nil
}

func (s *exampleRoleStore) UpdateRole(_ context.Context, name string, version int64, c admin.RoleChange) (admin.Role, error) {
	r, ok := s.roles[name]
	if !ok {
		return admin.Role{}, admin.ErrNotFound
	}

	if r.Version != version {
		return admin.Role{}, admin.ErrStaleUpdate
	}

	if c.DisplayName != nil {
		r.DisplayName = *c.DisplayName
	}

	r.Version++
	s.roles[name] = r

	return r, nil
}

func (s *exampleRoleStore) DeleteRole(_ context.Context, name string, _ int64, _ bool) error {
	delete(s.roles, name)

	return nil
}

// ExampleRoles creates a role and "renames" it: the display name changes, the
// name that grants and assignments use does not. A second role of the same
// name is refused.
func ExampleRoles() {
	roles, err := admin.NewRoles(&exampleRoleStore{roles: map[string]admin.Role{}}, admin.WithEventSink(printEvent))
	if err != nil {
		panic(err)
	}

	ctx := admin.WithSystemActor(context.Background(), "setup")

	sales, err := roles.Create(ctx, admin.Role{Name: "sales", DisplayName: "Sales", Labels: []string{"Partner"}})
	if err != nil {
		panic(err)
	}

	display := "Sales (Partner)"
	if _, err := roles.Update(ctx, sales.Name, sales.Version, admin.RoleChange{DisplayName: &display}); err != nil {
		panic(err)
	}

	_, err = roles.Create(ctx, admin.Role{Name: "sales"})
	fmt.Println(errors.Is(err, admin.ErrAlreadyExists))

	listed, err := roles.List(ctx, "Partner")
	if err != nil {
		panic(err)
	}

	for _, r := range listed {
		fmt.Println(r.Name, "-", r.DisplayName)
	}

	// Output:
	// event authz_admin actor=system:setup changed=[name display_name labels]
	// event authz_admin actor=system:setup changed=[display_name]
	// true
	// sales - Sales (Partner)
}

// exampleGrantStore holds one role's grants per resource.
type exampleGrantStore struct {
	version int64
	byKey   map[string][]admin.Grant
}

func (s *exampleGrantStore) GetGrants(context.Context, string) ([]admin.Grant, int64, error) {
	var out []admin.Grant
	for _, k := range slices.Sorted(maps.Keys(s.byKey)) {
		out = append(out, s.byKey[k]...)
	}

	return out, s.version, nil
}

func (s *exampleGrantStore) ReplaceGrants(_ context.Context, _ string, version int64, rgs []admin.ResourceGrants) (int64, error) {
	if version != s.version {
		return 0, admin.ErrStaleUpdate
	}

	for _, rg := range rgs {
		s.byKey[rg.Group+"/"+rg.Resource] = rg.Grants
	}

	s.version++

	return s.version, nil
}

// ExampleGrants declares the application's catalogue and replaces a role's
// grants on one resource. A privilege the catalogue does not list, and a scope
// a privilege may not be granted with, are refused before anything is written.
func ExampleGrants() {
	catalogue, err := authorize.NewCatalogue(authorize.CatalogueResource{
		Group: "crm", Name: "lead",
		Privileges: []authorize.CataloguePrivilege{
			{Name: "view"},
			{Name: "update"},
			{Name: "create", Scopes: []identity.Scope{identity.ScopeAll}},
		},
	})
	if err != nil {
		panic(err)
	}

	grants, err := admin.NewGrants(&exampleGrantStore{version: 1, byKey: map[string][]admin.Grant{}}, catalogue,
		admin.WithEventSink(printEvent))
	if err != nil {
		panic(err)
	}

	ctx := admin.WithSystemActor(context.Background(), "setup")
	lead := func(gs ...admin.Grant) admin.ResourceGrants {
		return admin.ResourceGrants{Group: "crm", Resource: "lead", Grants: gs}
	}

	version, err := grants.Replace(ctx, "sales", 1, lead(
		admin.Grant{Privilege: "view", Granted: true, Scope: identity.ScopeAll},
		admin.Grant{Privilege: "update", Granted: true, Scope: identity.ScopeOwn},
	))
	fmt.Println(version, err)

	_, err = grants.Replace(ctx, "sales", version, lead(admin.Grant{Privilege: "purge", Granted: true}))
	fmt.Println(errors.Is(err, admin.ErrUnknownPrivilege))

	_, err = grants.Replace(ctx, "sales", version, lead(admin.Grant{Privilege: "create", Granted: true, Scope: identity.ScopeOwn}))
	fmt.Println(errors.Is(err, admin.ErrUnknownPrivilege))

	held, _, err := grants.Get(ctx, "sales")
	if err != nil {
		panic(err)
	}

	for _, g := range held {
		fmt.Printf("%s/%s %s %s\n", g.Group, g.Resource, g.Privilege, g.Scope)
	}

	// Output:
	// event privilege_permissions_changed actor=system:setup changed=[crm/lead]
	// 2 <nil>
	// true
	// true
	// crm/lead view all
	// crm/lead update own
}

// exampleAssignmentStore holds one user's role grants.
type exampleAssignmentStore struct {
	version int64
	roles   []*identity.AssignedRole
}

func (s *exampleAssignmentStore) ListAssignments(context.Context, identity.UserID) ([]*identity.AssignedRole, int64, error) {
	return s.roles, s.version, nil
}

func (s *exampleAssignmentStore) AddAssignment(_ context.Context, _ identity.UserID, version int64, a admin.Assignment) (int64, error) {
	if version != s.version {
		return 0, admin.ErrStaleUpdate
	}

	if a.Primary {
		for _, r := range s.roles {
			r.Primary = false
		}
	}

	s.roles = append(s.roles, &identity.AssignedRole{
		ID: fmt.Sprintf("g-%d", len(s.roles)+1), Name: a.Role, Primary: a.Primary,
		StartDate: a.Start, ValidUntil: a.End,
	})
	s.version++

	return s.version, nil
}

func (s *exampleAssignmentStore) RemoveAssignment(context.Context, identity.UserID, int64, string) (int64, error) {
	return s.version, nil
}

func (s *exampleAssignmentStore) SetPrimary(_ context.Context, _ identity.UserID, version int64, grantID string) (int64, error) {
	if version != s.version {
		return 0, admin.ErrStaleUpdate
	}

	for _, r := range s.roles {
		r.Primary = r.ID == grantID
	}

	s.version++

	return s.version, nil
}

// ExampleAssignments grants a user a primary role with no dates and a second
// one that ends, then makes the second primary. An end that is not after the
// start is refused.
func ExampleAssignments() {
	store := &exampleAssignmentStore{version: 1}

	assignments, err := admin.NewAssignments(store, admin.WithEventSink(printEvent))
	if err != nil {
		panic(err)
	}

	ctx := admin.WithSystemActor(context.Background(), "setup")
	ada := identity.UserID("0192f1e2-3c4d-7e5f-8a9b-0c1d2e3f4a5b")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	v, err := assignments.Add(ctx, ada, 1, admin.Assignment{Role: "sales", Primary: true})
	if err != nil {
		panic(err)
	}

	_, err = assignments.Add(ctx, ada, v, admin.Assignment{Role: "audit", Start: start, End: start})
	fmt.Println(errors.Is(err, admin.ErrInvalidInput))

	v, err = assignments.Add(ctx, ada, v, admin.Assignment{Role: "audit", Start: start, End: start.AddDate(1, 0, 0)})
	if err != nil {
		panic(err)
	}

	if _, err := assignments.SetPrimary(ctx, ada, v, "g-2"); err != nil {
		panic(err)
	}

	roles, _, err := assignments.List(ctx, ada)
	if err != nil {
		panic(err)
	}

	for _, r := range roles {
		until := "unbounded"
		if !r.ValidUntil.IsZero() {
			until = r.ValidUntil.Format(time.DateOnly)
		}

		fmt.Println(r.Name, "primary:", r.Primary, "until:", until)
	}

	// Output:
	// event authz_change actor=system:setup changed=[roles]
	// true
	// event authz_change actor=system:setup changed=[roles]
	// event authz_change actor=system:setup changed=[primary]
	// sales primary: false until: unbounded
	// audit primary: true until: 2027-01-01
}
