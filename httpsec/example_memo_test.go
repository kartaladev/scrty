package httpsec_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// memoExampleRoles stands in for the consumer's role loader and counts its loads.
type memoExampleRoles struct{ loads int }

func (r *memoExampleRoles) LoadPrivileges(context.Context, string) ([]*identity.ResourcePrivileges, error) {
	r.loads++

	return []*identity.ResourcePrivileges{{
		Group: "crm", Resource: "lead",
		Privileges: []identity.Privilege{{Name: "view", Granted: true, Scope: identity.ScopeAll}},
	}}, nil
}

// ExampleWithoutPrivilegeMemo counts the loads of a role's privileges for two
// checks in one request. The chain attaches a per-request memo by default, so
// they cost one load; WithoutPrivilegeMemo gives each check its own.
func ExampleWithoutPrivilegeMemo() {
	run := func(opts ...httpsec.Option) int {
		roles := &memoExampleRoles{}

		authorizer, err := authorize.NewPrivilegeAuthorizer(roles)
		if err != nil {
			panic(err)
		}

		chain, err := httpsec.New(opts...)
		if err != nil {
			panic(err)
		}

		app := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			role := &identity.AssignedRole{ID: "r-1", Name: "sales-clerk", Primary: true}
			ctx := identity.WithPrincipal(r.Context(), &identity.Principal{
				ID: "u-1", Username: "ada", Roles: []*identity.AssignedRole{role}, ActiveRole: role,
			})
			ctx = authorize.WithAuthorizer(ctx, authorizer)

			for range 2 {
				if _, err := authorize.HeldPrivileges(ctx, "crm", "lead", "view"); err != nil {
					panic(err)
				}
			}
		})

		chain.Middleware()(app).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

		return roles.loads
	}

	fmt.Println("default:", run())
	fmt.Println("without memo:", run(httpsec.WithoutPrivilegeMemo()))

	// Output:
	// default: 1
	// without memo: 2
}
