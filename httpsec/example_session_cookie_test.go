package httpsec_test

import (
	"context"
	"encoding/json"
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

// ExampleEnableSessionCookie_twoChains serves browsers and native clients from
// one mux. A chain delivers either cookies or tokens, so there are two: the
// cookie chain at the default paths, and the token chain under "/api". Both
// read one session manager, so a sign-in is one session whichever client
// holds it.
func ExampleEnableSessionCookie_twoChains() {
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

	// Browsers: the session cookie, which needs CSRF protection beside it.
	browsers, err := httpsec.New(
		httpsec.EnableCSRFProtection(),
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
	)
	if err != nil {
		panic(err)
	}

	// Native clients: signed tokens, under their own base path.
	natives, err := httpsec.New(
		httpsec.WithBasePath("/api"),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn, Sessions: sessions, Tokens: exampleTokens{}, Attempts: attempts,
		}),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: exampleTokens{}, Sessions: sessions, Users: users,
		}),
	)
	if err != nil {
		panic(err)
	}

	whoami := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := authenticate.AuthenticationFromContext(r.Context())
		if !ok {
			http.Error(w, "anonymous", http.StatusUnauthorized)

			return
		}

		_, _ = fmt.Fprint(w, auth.Principal.ID)
	})

	mux := http.NewServeMux()
	mux.Handle("/api/", natives.Middleware()(whoami))
	mux.Handle("/", browsers.Middleware()(whoami))

	do := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		return rec
	}

	ctx := context.Background()

	// A browser holding the cookie of a sign-in.
	signIn, err := sessions.Create(ctx, "u-1")
	if err != nil {
		panic(err)
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://app.example.com/orders", nil)
	req.AddCookie(&http.Cookie{Name: httpsec.DefaultSessionCookieName, Value: signIn.ID}) //nolint:gosec // G124: a request cookie; attributes belong to Set-Cookie
	rec := do(req)
	fmt.Println("browser:", rec.Code, rec.Body.String())

	// A browser holding a cookie no session answers to: refused, and its
	// cookie expired.
	req = httptest.NewRequestWithContext(ctx, http.MethodGet, "https://app.example.com/orders", nil)
	req.AddCookie(&http.Cookie{Name: httpsec.DefaultSessionCookieName, Value: "stale"}) //nolint:gosec // G124: a request cookie; attributes belong to Set-Cookie
	rec = do(req)
	fmt.Println("stale browser:", rec.Code, rec.Header().Get("Set-Cookie"))

	// A native client signs in under /api and presents its token.
	form := url.Values{"username": {"grace@example.com"}, "password": {"correct horse battery staple"}}
	req = httptest.NewRequestWithContext(ctx, http.MethodPost, "https://app.example.com/api/sign-in/password",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = do(req)

	var issued struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		panic(err)
	}

	req = httptest.NewRequestWithContext(ctx, http.MethodGet, "https://app.example.com/api/orders", nil)
	req.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	rec = do(req)
	fmt.Println("native:", rec.Code, rec.Body.String())

	// Output:
	// browser: 200 u-1
	// stale browser: 401 __Host-scrty-session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
	// native: 200 u-1
}
