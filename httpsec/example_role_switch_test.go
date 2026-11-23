package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// grantedUsers stands in for the consumer's user store: ada holds sales, her
// primary role, and audit.
type grantedUsers struct{}

func (grantedUsers) LoadByUsername(context.Context, string) (*identity.Details, error) {
	return nil, identity.ErrUserNotFound
}

func (grantedUsers) LoadByUserID(_ context.Context, id identity.UserID) (*identity.Details, error) {
	if id != "u-ada" {
		return nil, identity.ErrUserNotFound
	}

	return &identity.Details{
		ID: "u-ada", Username: "ada", Active: true,
		Roles: []*identity.AssignedRole{
			{ID: "r-sales", Name: "sales", Primary: true},
			{ID: "r-audit", Name: "audit"},
		},
	}, nil
}

// ExampleWithSwitchableRoles lets a signed-in user act under another role
// she holds. Switching is off by default; WithSwitchableRoles turns it on,
// and Chain.SwitchActiveRole records the choice on her session, so her next
// request is active as that role for as long as she still holds it.
func ExampleWithSwitchableRoles() {
	store, err := session.NewMemoryStore()
	if err != nil {
		panic(err)
	}

	sessions, err := session.New(session.WithStore(store))
	if err != nil {
		panic(err)
	}

	build := func(opts ...httpsec.Option) http.Handler {
		chain, err := httpsec.New(append([]httpsec.Option{
			httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: grantedUsers{}}),
		}, opts...)...)
		if err != nil {
			panic(err)
		}

		app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if role, ok := r.URL.Query()["switch"]; ok {
				if err := chain.SwitchActiveRole(r.Context(), role[0]); err != nil {
					fmt.Println("switch refused:", errors.Is(err, httpsec.ErrRoleSwitchingDisabled))
					w.WriteHeader(http.StatusForbidden)

					return
				}
			}

			caller, _ := identity.PrincipalFromContext(r.Context())
			fmt.Println("active role:", caller.ActiveRole.Name)
		})

		return chain.Middleware()(app)
	}

	s, err := sessions.Create(context.Background(), "u-ada", session.WithFirstFactor(factor.Password))
	if err != nil {
		panic(err)
	}

	call := func(h http.Handler, target string) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target, nil)
		req.Header.Set("Authorization", "Bearer "+s.ID)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	switching := build(httpsec.WithSwitchableRoles())
	call(switching, "/role?switch=audit") // this request keeps the role it was authenticated with
	call(switching, "/me")                // the next one acts as audit

	plain := build() // switching is off by default
	call(plain, "/role?switch=sales")

	// Output:
	// active role: sales
	// active role: audit
	// switch refused: true
}
