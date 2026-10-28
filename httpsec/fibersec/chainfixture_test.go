package fibersec_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The test doubles these tests drive the chain with. Every one stands in for a
// port the core declares, so the directives name the core's own packages: the
// mocks are consumed here and are generated into this module's tests only.
//
//go:generate mockgen -destination=verifier_mock_test.go -package=fibersec_test -typed github.com/kartaladev/scrty/token Verifier
//go:generate mockgen -destination=userloader_mock_test.go -package=fibersec_test -typed github.com/kartaladev/scrty/identity UserLoader
//go:generate mockgen -destination=authorizer_mock_test.go -package=fibersec_test -typed github.com/kartaladev/scrty/authorize Authorizer

// presentedToken is the credential the bearer fixture's verifier accepts. It is
// not a real token: the verifier is a double, and what it returns is the only
// thing the chain reads.
const presentedToken = "presented-bearer-token" //nolint:gosec // a fixture string, not a credential

// traceKey is what fiber middleware outside the chain put on the request
// context before the chain ever saw it.
type traceKey struct{}

// testPrincipal is the caller the fixtures authenticate.
func testPrincipal() *identity.Principal {
	return &identity.Principal{ID: "u-1", Username: "ada", Name: "Ada"}
}

// newChain builds a chain from opts and fails the test if it does not build.
func newChain(t *testing.T, opts ...httpsec.Option) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(opts...)
	require.NoError(t, err)

	return c
}

// publishing is an interceptor that resolves a request the way an
// authenticating one would, so a test can pin what a guard or a route behind
// the chain reads without standing up a whole first factor.
func publishing(p *identity.Principal) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if p != nil {
			// Only when nothing has authenticated the request already, so this
			// stands in for a first factor rather than replacing one.
			if ex.Authentication == nil {
				ex.Authentication = &authenticate.Authentication{Principal: p}
			}

			ex.SetContext(identity.WithPrincipal(ex.Context(), p))
		}

		return next(ex)
	})
}

// refusing is an interceptor that refuses every request with err, after running
// act so a test can have it commit a status or a body first.
func refusing(err error, act func(ex *httpsec.Exchange)) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
		if act != nil {
			act(ex)
		}

		return err
	})
}

// inspecting is an interceptor that hands a test the request the chain was
// given, which is the one thing the adapter decides about every accessor.
func inspecting(fn func(r httpsec.Request)) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		fn(ex.Request)

		return next(ex)
	})
}

// authenticated wires bearer authentication over a live session, so a request
// carrying presentedToken reaches the chain's later slots with a principal, an
// authentication result and a session the chain itself resolved.
//
// It returns the options and the session, because a test that asserts on the
// session needs the same pointer the store holds.
func authenticated(t *testing.T) ([]httpsec.Option, *session.Session) {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.NewManager()
	require.NoError(t, err)

	live, err := sessions.Create(t.Context(), "u-1")
	require.NoError(t, err)

	verifier := NewMockVerifier(ctrl)
	verifier.EXPECT().
		Verify(gomock.Any(), presentedToken).
		Return(token.NewClaims("ada", live.ID), nil).
		AnyTimes()

	users := NewMockUserLoader(ctrl)
	users.EXPECT().
		LoadByUsername(gomock.Any(), "ada").
		Return(&identity.Details{
			ID: "u-1", Username: "ada", Name: "Ada", Active: true,
			PasswordChangedAt: time.Now().Add(-time.Hour),
		}, nil).
		AnyTimes()

	return []httpsec.Option{
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: verifier,
			Sessions: sessions,
			Users:    users,
		}),
	}, live
}

// bearerRequest is a request carrying the credential the bearer fixture
// accepts.
func bearerRequest(ctx context.Context, method, path string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, method, path, nil)
	req.Header.Set("Authorization", "Bearer "+presentedToken)

	return req
}

// response is what serving one request through a fiber app produced, read out
// in full so a case asserts on values rather than on an open body.
type response struct {
	status int
	header http.Header
	body   string
}

// serve runs req through app over fiber's in-memory transport.
//
// The timeout is disabled: a case that deadlocks is better reported by the
// test framework's own timeout, with every goroutine's stack, than by fiber
// returning a timeout error that hides where the request stopped.
func serve(t *testing.T, app *fiber.App, req *http.Request) response {
	t.Helper()

	res, err := app.Test(req, fiber.TestConfig{Timeout: 0, FailOnTimeout: false})
	require.NoError(t, err)

	defer func() { require.NoError(t, res.Body.Close()) }()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	return response{status: res.StatusCode, header: res.Header, body: string(body)}
}
