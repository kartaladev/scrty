package prblmsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"

	"github.com/kartaladev/prblm"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/prblmsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
)

// show prints what a client of rec sees: the status, the media type, any of the
// named headers the response carries, and every member of the problem document
// except the fixed title and detail, one per line in name order. The title and
// detail are fixed library text and are left out so the output pins the
// contract a client acts on: the type, the status and the extension members.
func show(rec *httptest.ResponseRecorder, headers ...string) {
	fmt.Println(rec.Code, rec.Header().Get("Content-Type"))

	for _, name := range headers {
		fmt.Printf("%s: %s\n", name, rec.Header().Get(name))
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		panic(err)
	}

	delete(doc, "title")
	delete(doc, "detail")
	delete(doc, "instance")

	names := make([]string, 0, len(doc))
	for name := range doc {
		names = append(names, name)
	}

	slices.Sort(names)

	for _, name := range names {
		fmt.Printf("%s: %s\n", name, doc[name])
	}
}

// problem writes err through h for a POST to /login and returns the response.
func problem(h *prblm.Handler, err error) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login", nil)
	rec := httptest.NewRecorder()
	h.Write(rec, req, err)

	return rec
}

// mfaChallenge is the error a password login that owes a second factor is
// refused with: the chain's own, built here so the example needs no stores.
func mfaChallenge() error {
	return &httpsec.ChallengeError{
		Kind: policy.ChallengeMFA,
		Methods: []httpsec.MFAMethod{
			{Name: "totp", Channel: factor.AuthenticatorApp, Begins: false},
			{Name: "passkey", Channel: factor.PublicKey, Begins: true},
		},
		Token:     "tok-123",
		TokenType: httpsec.TokenTypeBearer,
	}
}

// refuseAll is a Basic authenticator that judges every credential wrong.
type refuseAll struct{}

func (refuseAll) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	return nil, authenticate.ErrAuthenticationFailed
}

// Example_netHTTP wires the integration on net/http: a namespace, the
// integration's option, and the chain's and the guards' error handlers set to
// the prblm handler's Write, so a refusal at the chain and one at a guard are
// answered alike. An unauthenticated request to a protected path is answered
// with the authentication-required problem.
func Example_netHTTP() {
	p, err := prblmsec.New()
	if err != nil {
		panic(err)
	}

	h := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option())

	attempts, err := lockout.NewMemoryAttemptStore()
	if err != nil {
		panic(err)
	}

	chain, err := httpsec.New(
		httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: refuseAll{}, Attempts: attempts}),
		httpsec.EnableAuthorization(allowAll{},
			authorize.Rule[httpsec.Request]{
				Match:   func(httpsec.Request) bool { return true },
				Require: authorize.Authenticated(),
			}),
		httpsec.WithErrorHandler(h.Write),
	)
	if err != nil {
		panic(err)
	}

	guards, err := httpsec.NewGuards(allowAll{}, httpsec.WithGuardErrorHandler(h.Write))
	if err != nil {
		panic(err)
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	mux := http.NewServeMux()
	mux.Handle("GET /records/{id}", guards.ResourcePrivileges("records", "r-1").RequireOne("read")(ok))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/records/r-1", nil)
	rec := httptest.NewRecorder()
	chain.Middleware()(mux).ServeHTTP(rec, req)

	show(rec)

	// Output:
	// 401 application/problem+json
	// status: 401
	// type: "/probs/security/authentication-required"
}

// allowAll is an authorizer that permits every request it is asked about.
type allowAll struct{}

func (allowAll) Authorize(context.Context, authorize.Attributes) error { return nil }

// Example_challengedLogin shows the problem a password login that owes a second
// factor is answered with: the mfa-required type, the usable methods, the
// access token to continue with and its type, and Cache-Control: no-store so no
// cache keeps the credential.
func Example_challengedLogin() {
	p, err := prblmsec.New()
	if err != nil {
		panic(err)
	}

	h := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option())

	show(problem(h, mfaChallenge()), "Cache-Control")

	// Output:
	// 401 application/problem+json
	// Cache-Control: no-store
	// access_token: "tok-123"
	// challenge: "mfa"
	// methods: [{"name":"totp","channel":"authenticator-app","begins":false},{"name":"passkey","channel":"public-key","begins":true}]
	// status: 401
	// token_type: "Bearer"
	// type: "/probs/security/mfa-required"
}

// ExampleWithTypePrefix replaces the default prefix, "security", under which
// every type is defined. With the prefix "auth" and the namespace "/probs", an
// access-denied refusal has the type "/probs/auth/access-denied".
func ExampleWithTypePrefix() {
	p, err := prblmsec.New(prblmsec.WithTypePrefix("auth"))
	if err != nil {
		panic(err)
	}

	h := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option())

	show(problem(h, authorize.ErrAccessDenied))

	// Output:
	// 403 application/problem+json
	// status: 403
	// type: "/probs/auth/access-denied"
}

// ExampleWithoutChallengeToken withholds the challenge's access token, for a
// deployment that delivers it another way or whose prblm hooks log problem
// members. The same challenge as Example_challengedLogin is answered without
// access_token and token_type; the rest of the problem is unchanged.
func ExampleWithoutChallengeToken() {
	p, err := prblmsec.New(prblmsec.WithoutChallengeToken())
	if err != nil {
		panic(err)
	}

	h := prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option())

	show(problem(h, mfaChallenge()))

	// Output:
	// 401 application/problem+json
	// challenge: "mfa"
	// methods: [{"name":"totp","channel":"authenticator-app","begins":false},{"name":"passkey","channel":"public-key","begins":true}]
	// status: 401
	// type: "/probs/security/mfa-required"
}

// errVesselNotFound is the application's own error, which the integration does
// not recognise.
var errVesselNotFound = errors.New("vessel not found")

// ExampleProblems_Mapper registers the integration by hand, which a consumer
// who builds the handler from separate pieces does: the type definitions with
// prblm.WithTypes and the mapper with prblm.WithMappers, the integration's
// mapper first. Its refusals get its problems; the application's own error,
// which it does not recognise, is left to the application's mapper.
func ExampleProblems_Mapper() {
	p, err := prblmsec.New()
	if err != nil {
		panic(err)
	}

	appMapper := prblm.Is(errVesselNotFound, func(error) *prblm.Problem {
		return prblm.New(http.StatusNotFound, prblm.WithType("app/vessel-not-found"))
	})

	h := prblm.NewHandler(
		prblm.WithNamespace("/probs"),
		prblm.WithTypes(p.Types()...),
		prblm.WithMappers(p.Mapper(), appMapper),
	)

	show(problem(h, authorize.ErrAccessDenied))
	show(problem(h, errVesselNotFound))

	// Output:
	// 403 application/problem+json
	// status: 403
	// type: "/probs/security/access-denied"
	// 404 application/problem+json
	// status: 404
	// type: "/probs/app/vessel-not-found"
}

// Example_override replaces one problem on purpose: a consumer mapper for a
// disclosed account lock, registered ahead of the integration, answers 429 with
// Retry-After: 900. Every other refusal keeps the integration's problem, so a
// wrong password is still authentication-failed.
func Example_override() {
	p, err := prblmsec.New()
	if err != nil {
		panic(err)
	}

	lockPage := prblm.Is(lockout.ErrAccountLocked, func(error) *prblm.Problem {
		return prblm.New(http.StatusTooManyRequests,
			prblm.WithType("app/locked"),
			prblm.WithHeader("Retry-After", "900"))
	})

	h := prblm.NewHandler(
		prblm.WithNamespace("/probs"),
		prblm.WithMappers(lockPage),
		p.Option(),
	)

	show(problem(h, lockout.ErrAccountLocked), "Retry-After")
	show(problem(h, authenticate.ErrAuthenticationFailed))

	// Output:
	// 429 application/problem+json
	// Retry-After: 900
	// status: 429
	// type: "/probs/app/locked"
	// 401 application/problem+json
	// status: 401
	// type: "/probs/security/authentication-failed"
}
