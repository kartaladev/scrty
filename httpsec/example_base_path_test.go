package httpsec_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
)

// ExampleWithBasePath answers password sign-in under "/auth". The endpoint's own
// path, "/sign-in/password" by default, is relative to the base path, so sign-in
// answers at "/auth/sign-in/password" and the unprefixed path passes through to
// the application, which here answers 404.
func ExampleWithBasePath() {
	encoder, err := password.NewArgon2idEncoder()
	if err != nil {
		panic(err)
	}

	hash, err := encoder.Encode("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	users := exampleUserLoader{details: &identity.Details{
		ID: "u-1", Username: "grace@example.com", Password: hash, Active: true,
	}}

	authn, err := authenticate.NewUsernamePasswordAuthenticator(users, authenticate.WithPasswordEncoder(encoder))
	if err != nil {
		panic(err)
	}

	sessions, err := session.New()
	if err != nil {
		panic(err)
	}

	attempts, err := lockout.NewMemoryAttemptStore()
	if err != nil {
		panic(err)
	}

	chain, err := httpsec.New(
		httpsec.WithBasePath("/auth"),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn,
			Sessions:      sessions,
			Tokens:        exampleTokens{},
			Attempts:      attempts,
		}),
	)
	if err != nil {
		panic(err)
	}

	app := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	handler := chain.Middleware()(app)

	signIn := func(path string) int {
		form := url.Values{"username": {"grace@example.com"}, "password": {"correct horse battery staple"}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec.Code
	}

	fmt.Println("POST /auth/sign-in/password:", signIn("/auth/sign-in/password"))
	fmt.Println("POST /sign-in/password:", signIn("/sign-in/password"))

	for _, e := range chain.Endpoints() {
		fmt.Println(e.OperationID, e.Path)
	}

	// Output:
	// POST /auth/sign-in/password: 200
	// POST /sign-in/password: 404
	// scrty.sign-in.password /auth/sign-in/password
}
