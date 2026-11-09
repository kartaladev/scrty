package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// projectDeleters stands in for the consumer's authorizer: only "ada" may
// delete projects.
type projectDeleters struct{}

func (projectDeleters) Authorize(ctx context.Context, _ authorize.Attributes) error {
	if principal, ok := identity.PrincipalFromContext(ctx); ok && principal.Username == "ada" {
		return nil
	}

	return authorize.ErrAccessDenied
}

// ExampleGuards_RequireRecentAuthentication guards a destructive route with a
// privilege guard and, inside it, a recency guard: the caller must hold the
// privilege, and must have proved their identity within the last 15 minutes
// (DefaultRecentAuthenticationWindow).
//
// Behind a session-backed chain the guard reads the authentication time from
// the request's session, and nothing more is wired. This example runs without
// a chain, so WithAuthenticationTime supplies the time, and a controlled clock
// stands in for the one a consumer passes to both httpsec.WithClock and
// WithGuardClock.
func ExampleGuards_RequireRecentAuthentication() {
	signedIn := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	clock := clockwork.NewFakeClockAt(signedIn)

	guards, err := httpsec.NewGuards(projectDeleters{},
		httpsec.WithGuardClock(clock),
		httpsec.WithAuthenticationTime(func(context.Context) (time.Time, bool) {
			return signedIn, true
		}),
		httpsec.WithGuardErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
			var stale *httpsec.ReauthenticationRequiredError
			if errors.As(err, &stale) {
				fmt.Printf("re-authenticate within %s\n", stale.Window)
			} else {
				fmt.Println(err)
			}

			w.WriteHeader(httpsec.StatusForError(err))
		}),
	)
	if err != nil {
		panic(err)
	}

	privileged := guards.ResourcePrivileges("projects", "project").RequireAny("delete")
	recent := guards.RequireRecentAuthentication()

	deleteProject := privileged(recent(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))

	call := func(username string) {
		ctx := identity.WithPrincipal(context.Background(),
			&identity.Principal{ID: identity.UserID(username), Username: username})
		rec := httptest.NewRecorder()

		deleteProject.ServeHTTP(rec,
			httptest.NewRequestWithContext(ctx, http.MethodDelete, "/projects/p-1", nil))
		fmt.Println(username, rec.Code)
	}

	clock.Advance(10 * time.Minute)
	call("ada")

	clock.Advance(10 * time.Minute)
	call("ada")
	call("grace")

	// Output:
	// ada 204
	// re-authenticate within 15m0s
	// ada 403
	// authorize: access denied
	// grace 403
}
