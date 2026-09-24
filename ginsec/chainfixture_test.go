package ginsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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
//go:generate mockgen -destination=verifier_mock_test.go -package=ginsec_test -typed github.com/kartaladev/scrty/token Verifier
//go:generate mockgen -destination=userloader_mock_test.go -package=ginsec_test -typed github.com/kartaladev/scrty/identity UserLoader
//go:generate mockgen -destination=authorizer_mock_test.go -package=ginsec_test -typed github.com/kartaladev/scrty/authorize Authorizer
//go:generate mockgen -destination=keysetprovider_mock_test.go -package=ginsec_test -typed github.com/kartaladev/scrty/httpsec KeySetProvider

// TestMain puts gin in test mode, so a test's output is the test's and not
// gin's start-up banner.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	os.Exit(m.Run())
}

// presentedToken is the credential the bearer fixture's verifier accepts. It is
// not a real token: the verifier is a double, and what it returns is the only
// thing the chain reads.
const presentedToken = "presented-bearer-token" //nolint:gosec // a fixture string, not a credential

// traceKey is what gin middleware outside the chain put on the request before
// the chain ever saw it.
type traceKey struct{}

// served is what serving one request through a gin engine produced.
type served struct {
	rec *httptest.ResponseRecorder

	// routeRan reports whether the gin route behind the chain was reached, and
	// routeCtx is the context it read through c.Request.Context().
	routeRan bool
	routeCtx context.Context //nolint:containedctx // captured for assertions, never used to call anything

	// noRouteRan reports whether a consumer's no-route handler was reached.
	noRouteRan bool

	// ginErrors is what a consumer's error middleware found on gin's error
	// channel after the chain returned.
	ginErrors []error

	// sessionID is the identifier of the session the fixture opened, so a case
	// can assert the route read that one and not another.
	sessionID string

	// clientAddr is the address the chain saw through Request.ClientIP().
	clientAddr string
}

// route is a gin handler that records it was reached, and nothing else.
func (s *served) route() gin.HandlerFunc {
	return func(gc *gin.Context) {
		s.routeRan = true
		s.routeCtx = gc.Request.Context()
	}
}

// writingRoute is a gin route that answers with its own status and body, so a
// test can tell a route that ran from one the adapter stopped.
func (s *served) writingRoute(status int, body string) gin.HandlerFunc {
	return func(gc *gin.Context) {
		s.routeRan = true
		s.routeCtx = gc.Request.Context()
		gc.Data(status, "text/plain; charset=utf-8", []byte(body))
	}
}

// collecting is consumer error middleware that reads gin's error channel after
// the chain returned and writes nothing, so the adapter's own answer stands.
func (s *served) collecting() gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Next()

		for _, e := range gc.Errors {
			s.ginErrors = append(s.ginErrors, e.Err)
		}
	}
}

// rendering is consumer error middleware that reads gin's error channel after
// the chain returned and renders a refusal its own way.
//
// It is the whole point of the lazily-set status: it runs outside the chain,
// after the adapter has refused, and it must still be able to choose the
// status, the content type and the body.
func rendering(status int, contentType, body string) gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Next()

		if len(gc.Errors) == 0 {
			return
		}

		gc.Data(status, contentType, []byte(body))
	}
}

// tracing is gin middleware outside the chain that puts a value on the request
// context before the chain ever sees it.
func tracing(id string) gin.HandlerFunc {
	return func(gc *gin.Context) {
		gc.Request = gc.Request.WithContext(context.WithValue(gc.Request.Context(), traceKey{}, id))
		gc.Next()
	}
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

// answering is an interceptor that answers the request itself and returns no
// error, which is what login, logout and the key set endpoint do.
func answering(status int, body string) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
		ex.Writer.SetHeader("Content-Type", "application/json")
		ex.Writer.WriteHeader(status)
		_, err := ex.Writer.Write([]byte(body))

		return err
	})
}

// observing is an interceptor that records the address the chain was given for
// this request, which is the one thing the adapter decides about attribution.
func observing(out *served) httpsec.Interceptor {
	return httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		out.clientAddr = ex.Request.ClientIP()

		return next(ex)
	})
}

// newChain builds a chain from opts and fails the test if it does not build.
func newChain(t *testing.T, opts ...httpsec.Option) *httpsec.Chain {
	t.Helper()

	c, err := httpsec.New(opts...)
	require.NoError(t, err)

	return c
}

// testPrincipal is the caller the fixtures authenticate.
func testPrincipal() *identity.Principal {
	return &identity.Principal{ID: "u-1", Username: "ada", Name: "Ada"}
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
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}),
	}, live
}

// bearerRequest is a request carrying the credential the bearer fixture
// accepts.
func bearerRequest(ctx context.Context, method, path string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, method, path, nil)
	req.Header.Set("Authorization", "Bearer "+presentedToken)
	req.RemoteAddr = "198.51.100.7:51234"

	return req
}

// serve runs req through eng and returns the recorded response.
func serve(eng *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)

	return rec
}
