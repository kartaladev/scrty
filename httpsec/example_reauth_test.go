package httpsec_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/jonboulle/clockwork"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// ExampleEnableReauthentication wires the second factor, form login and
// re-authentication onto a chain, and guards a route with the recency guard.
//
// The user signs in with their password, and twenty minutes later the guarded
// route refuses the stale session. The user holds no second factor, so the
// method listing offers the password, and a password re-proof answers with the
// credential of the rotated, freshly authenticated session, which the route
// then accepts; the credential the user signed in with no longer works.
//
// A controlled clock stands in for time, given to the session manager, the
// chain (httpsec.WithClock) and the guards (httpsec.WithGuardClock) alike. The
// chain answers bearer session references (httpsec.EnableSessionBearer), so no
// token generator is wired.
func ExampleEnableReauthentication() {
	clock := clockwork.NewFakeClockAt(time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC))

	// Cheap hashing parameters keep the example quick; use the defaults.
	enc, err := password.NewArgon2idEncoder(password.WithArgon2idMemory(19456),
		password.WithArgon2idIterations(2), password.WithArgon2idThreads(1))
	if err != nil {
		panic(err)
	}

	hash, err := enc.Encode("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	users := exampleUserLoader{details: &identity.Details{
		ID: "u-1", Username: "ada", Password: hash, Active: true,
	}}

	authn, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(enc))
	if err != nil {
		panic(err)
	}

	sessions, err := session.New(session.WithClock(clock))
	if err != nil {
		panic(err)
	}

	totp, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Co")
	if err != nil {
		panic(err)
	}

	lockoutPolicy, err := lockout.New()
	if err != nil {
		panic(err)
	}

	chain, err := httpsec.New(
		httpsec.WithClock(clock),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn, Sessions: sessions, Attempts: lockoutPolicy.Attempts(),
		}),
		httpsec.EnableMFA([]mfa.Method{totp}),
		httpsec.EnableReauthentication(),
	)
	if err != nil {
		panic(err)
	}

	guards, err := httpsec.NewGuards(projectDeleters{}, httpsec.WithGuardClock(clock))
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("DELETE /projects/{id}", guards.RequireRecentAuthentication()(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))

	app := chain.Middleware()(mux)

	send := func(method, path, credential string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}

		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)

		return rec
	}

	credentialOf := func(rec *httptest.ResponseRecorder) string {
		var doc struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			panic(err)
		}

		return doc.AccessToken
	}

	signedIn := send(http.MethodPost, httpsec.DefaultLoginPath, "", url.Values{
		"username": {"ada"}, "password": {"correct horse battery staple"},
	})
	fmt.Println("sign-in:", signedIn.Code)

	first := credentialOf(signedIn)

	clock.Advance(20 * time.Minute)
	fmt.Println("delete, 20 minutes on:", send(http.MethodDelete, "/projects/p-1", first, nil).Code)

	methods := send(http.MethodGet, httpsec.DefaultReauthenticationPrefix+"/methods", first, nil)
	fmt.Println("methods:", strings.TrimSpace(methods.Body.String()))

	reproved := send(http.MethodPost, httpsec.DefaultReauthenticationPrefix+"/password", first, url.Values{
		"password": {"correct horse battery staple"},
	})
	fmt.Println("re-proof:", reproved.Code, reproved.Header().Get("Cache-Control"))

	fresh := credentialOf(reproved)
	fmt.Println("delete with the new credential:", send(http.MethodDelete, "/projects/p-1", fresh, nil).Code)
	fmt.Println("delete with the old credential:", send(http.MethodDelete, "/projects/p-1", first, nil).Code)

	// Output:
	// sign-in: 200
	// delete, 20 minutes on: 403
	// methods: {"methods":[],"password":true}
	// re-proof: 200 no-store
	// delete with the new credential: 204
	// delete with the old credential: 401
}
