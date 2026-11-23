package authorize_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// ExampleNewCatalogue declares what an application may grant. A privilege
// listed without scopes allows all and own; one listed with scopes allows only
// those. Anything not declared is refused.
func ExampleNewCatalogue() {
	catalogue, err := authorize.NewCatalogue(authorize.CatalogueResource{
		Group: "crm", Name: "lead",
		Privileges: []authorize.CataloguePrivilege{
			{Name: "view"},
			{Name: "create", Scopes: []identity.Scope{identity.ScopeAll}},
		},
	})
	if err != nil {
		fmt.Println(err)

		return
	}

	fmt.Println(catalogue.Allows("crm", "lead", "view", identity.ScopeOwn))
	fmt.Println(catalogue.Allows("crm", "lead", "create", identity.ScopeOwn))
	fmt.Println(catalogue.Allows("crm", "lead", "purge", identity.ScopeAll))

	// Output:
	// true
	// false
	// false
}

// ExampleHasPrivilegeFor guards one lead. A sales clerk holds update with own
// only, so the check passes for their own lead and is denied, with ErrNotOwner,
// for another's. HasPrivilege, which accepts all only, denies them both.
func ExampleHasPrivilegeFor() {
	authorizer, err := authorize.NewPrivilegeAuthorizer(salesRoles())
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := signedIn(context.Background(), authorizer)
	leads := map[string]identity.UserID{"L-1": "u-1", "L-2": "u-2"}

	check := func(id string) error {
		owned := authorize.OwnershipAttributes{
			Group: "crm", Resource: "lead",
			ResolveID: func(context.Context) (string, error) { return id, nil },
			OwnedBy: func(_ context.Context, subject *identity.Principal, id string) (bool, error) {
				return leads[id] == subject.ID, nil
			},
		}

		return authorize.HasPrivilegeFor("crm", "lead", owned, "update")(ctx)
	}

	fmt.Println("own lead:", check("L-1"))
	fmt.Println("other's lead not owner:", errors.Is(check("L-2"), authorize.ErrNotOwner))
	fmt.Println("plain check denied:", errors.Is(authorize.HasPrivilege("crm", "lead", "update")(ctx), authorize.ErrAccessDenied))

	// Output:
	// own lead: <nil>
	// other's lead not owner: true
	// plain check denied: true
}
