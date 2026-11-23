package authorize_test

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// roleTable stands in for the consumer's role loader, one of the identity
// stores in a real application. It counts its loads so the examples can show
// the memo at work.
type roleTable struct {
	roles map[string][]*identity.ResourcePrivileges
	loads int
}

func (r *roleTable) LoadPrivileges(_ context.Context, role string) ([]*identity.ResourcePrivileges, error) {
	r.loads++

	privileges, ok := r.roles[role]
	if !ok {
		return nil, identity.ErrPrivilegesNotFound
	}

	return privileges, nil
}

// salesRoles grants a sales clerk view on every lead and update and delete on
// their own leads only.
func salesRoles() *roleTable {
	return &roleTable{roles: map[string][]*identity.ResourcePrivileges{
		"sales-clerk": {{
			Group:    "crm",
			Resource: "lead",
			Privileges: []identity.Privilege{
				{Name: "view", Granted: true, Scope: identity.ScopeAll},
				{Name: "update", Granted: true, Scope: identity.ScopeOwn},
			},
		}},
	}}
}

// signedIn returns ctx as the chain leaves it for a request by a sales clerk:
// the principal, the authorizer and a fresh privilege memo.
func signedIn(ctx context.Context, authorizer authorize.Authorizer) context.Context {
	role := &identity.AssignedRole{ID: "r-1", Name: "sales-clerk", Primary: true}
	ctx = identity.WithPrincipal(ctx, &identity.Principal{
		ID:         "u-1",
		Username:   "ada",
		Roles:      []*identity.AssignedRole{role},
		ActiveRole: role,
	})

	return authorize.WithRequestMemo(authorize.WithAuthorizer(ctx, authorizer))
}

// ExampleHeldPrivileges lists the actions a caller may take on a lead, the
// "allowed actions" a response carries beside the record, with one load of
// the caller's role.
func ExampleHeldPrivileges() {
	roles := salesRoles()

	authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := signedIn(context.Background(), authorizer)

	holdings, err := authorize.HeldPrivileges(ctx, "crm", "lead", "view", "update", "delete")
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, holding := range holdings {
		if holding.Held {
			fmt.Printf("%s: %s\n", holding.Privilege, holding.Scope)
		} else {
			fmt.Printf("%s: not held\n", holding.Privilege)
		}
	}

	// Lookup finds one answer by the name it was asked with.
	if update, ok := holdings.Lookup("update"); ok {
		fmt.Println("edit form limited to own leads:", update.Scope == identity.ScopeOwn)
	}

	// A later check in the same request reads the memo, not the store.
	err = authorizer.Authorize(ctx, authorize.PrivilegeAttributes{
		Group: "crm", Resource: "lead", Required: []string{"view"},
	})
	fmt.Println("route check allowed:", err == nil)
	fmt.Println("loads:", roles.loads)

	// Output:
	// view: all
	// update: own
	// delete: not held
	// edit form limited to own leads: true
	// route check allowed: true
	// loads: 1
}

// salesLead is a record of the consumer's own.
type salesLead struct {
	ID    string
	Owner identity.UserID
}

// ExampleCheckAnyScope filters a list endpoint's result: a caller who holds
// update with all sees every lead, and one who holds it only with own sees
// only their own.
func ExampleCheckAnyScope() {
	authorizer, err := authorize.NewPrivilegeAuthorizer(salesRoles())
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := signedIn(context.Background(), authorizer)

	leads := []salesLead{{ID: "L-1", Owner: "u-1"}, {ID: "L-2", Owner: "u-2"}, {ID: "L-3", Owner: "u-1"}}

	scope, err := authorize.CheckAnyScope(ctx, "crm", "lead", "update")
	if err != nil {
		fmt.Println("denied:", err)

		return
	}

	caller := identity.MustPrincipalFromContext(ctx)

	visible := leads
	if scope == identity.ScopeOwn {
		visible = nil

		for _, l := range leads {
			if l.Owner == caller.ID {
				visible = append(visible, l)
			}
		}
	}

	fmt.Println("scope:", scope)

	for _, l := range visible {
		fmt.Println(l.ID)
	}

	// Output:
	// scope: own
	// L-1
	// L-3
}
