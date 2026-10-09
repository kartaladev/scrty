package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// The errors a guard's collaborators fail with, each distinct so a test can say
// which one the refusal came from and whether it arrived unchanged.
var (
	errNoRecordID      = errors.New("guards_test: the path names no record")
	errAuthorizerRoles = errors.New("guards_test: the role store is unreachable")
)

// guardRun is what putting one request through a guard produced.
type guardRun struct {
	rec      *httptest.ResponseRecorder
	routeRan bool

	// refusal is what the guard handed its error handler, and nil when the
	// guard let the request through.
	refusal error
}

// guardRequest builds the request a guard judges: a GET of one record, carrying
// the principal and the authorizer the caller wants published on it.
func guardRequest(t *testing.T, p *identity.Principal, az authorize.Authorizer) *http.Request {
	t.Helper()

	ctx := t.Context()
	if p != nil {
		ctx = identity.WithPrincipal(ctx, p)
	}
	if az != nil {
		ctx = authorize.WithAuthorizer(ctx, az)
	}

	return httptest.NewRequestWithContext(ctx, http.MethodGet, "/records/r-1", nil)
}

// runGuard puts req through mw onto a route that records that it was reached.
func runGuard(t *testing.T, mw func(http.Handler) http.Handler, req *http.Request) guardRun {
	t.Helper()

	out := guardRun{rec: httptest.NewRecorder()}
	route := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { out.routeRan = true })

	mw(route).ServeHTTP(out.rec, req)

	return out
}

// capturing records what a guard refused with, so a test names the refusal
// rather than reading it back out of a status code.
func capturing(run *guardRun) httpsec.GuardOption {
	return httpsec.WithGuardErrorHandler(func(_ http.ResponseWriter, _ *http.Request, err error) {
		run.refusal = err
	})
}

// permittingAuthorizer judges every attempt allowed.
func permittingAuthorizer(t *testing.T) *MockAuthorizer {
	t.Helper()

	az := NewMockAuthorizer(gomock.NewController(t))
	az.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return az
}

// refusingAuthorizer refuses every attempt with err.
func refusingAuthorizer(t *testing.T, err error) *MockAuthorizer {
	t.Helper()

	az := NewMockAuthorizer(gomock.NewController(t))
	az.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(err).AnyTimes()

	return az
}

// recordOwner is the ownership check a test guards a record with. It never
// runs in the fail-closed rows, which is part of what they assert.
func recordOwner(owned bool, err error) httpsec.OwnershipChecker[string] {
	return func(context.Context, *identity.Principal, string) (bool, error) {
		return owned, err
	}
}

// recordID extracts the identifier an ownership guard judges, or fails.
func recordID(err error) func(httpsec.Request) (string, error) {
	return func(r httpsec.Request) (string, error) {
		if err != nil {
			return "", err
		}

		return r.Path(), nil
	}
}

// TestGuardsFailClosed pins the four refusals a guard answers without reaching
// the route, and that a guard which found everything it needs does reach it.
func TestGuardsFailClosed(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, run *guardRun) (func(http.Handler) http.Handler, *http.Request)
		assert func(t *testing.T, run guardRun)
	}

	cases := []testCase{
		{
			name: "no principal",
			build: func(t *testing.T, run *guardRun) (func(http.Handler) http.Handler, *http.Request) {
				g := httpsec.NewGuards(permittingAuthorizer(t), capturing(run))

				return g.RequireAuthenticated(), guardRequest(t, nil, nil)
			},
			assert: func(t *testing.T, run guardRun) {
				require.ErrorIs(t, run.refusal, httpsec.ErrAuthenticationRequired)
				assert.False(t, run.routeRan)
			},
		},
		{
			name: "no authorizer in the context and none at construction",
			build: func(t *testing.T, run *guardRun) (func(http.Handler) http.Handler, *http.Request) {
				g := httpsec.NewGuards(nil, capturing(run))

				return g.ResourcePrivileges("admin", "user").RequireOne("read"),
					guardRequest(t, testPrincipal(), nil)
			},
			assert: func(t *testing.T, run guardRun) {
				require.ErrorIs(t, run.refusal, authorize.ErrAccessDenied,
					"a guard that found no judge has not been told the request is allowed")
				assert.False(t, run.routeRan)
			},
		},
		{
			name: "the identifier extractor fails",
			build: func(t *testing.T, run *guardRun) (func(http.Handler) http.Handler, *http.Request) {
				g := httpsec.NewGuards(permittingAuthorizer(t), capturing(run))
				owned := httpsec.ResourceOwnerships(g, "admin", "user",
					recordOwner(true, nil))

				return owned.ForResource(recordID(errNoRecordID)),
					guardRequest(t, testPrincipal(), nil)
			},
			assert: func(t *testing.T, run guardRun) {
				require.ErrorIs(t, run.refusal, errNoRecordID)
				assert.Equal(t, errNoRecordID, run.refusal,
					"the extractor's own error is the refusal, unchanged")
				assert.False(t, run.routeRan)
			},
		},
		{
			name: "the authorizer refuses",
			build: func(t *testing.T, run *guardRun) (func(http.Handler) http.Handler, *http.Request) {
				g := httpsec.NewGuards(refusingAuthorizer(t, errAuthorizerRoles), capturing(run))

				return g.ResourcePrivileges("admin", "user").RequireOne("read"),
					guardRequest(t, testPrincipal(), nil)
			},
			assert: func(t *testing.T, run guardRun) {
				require.ErrorIs(t, run.refusal, errAuthorizerRoles)
				assert.Equal(t, errAuthorizerRoles, run.refusal,
					"the authorizer's error is the refusal, unchanged")
				assert.False(t, run.routeRan)
			},
		},
		{
			name: "the ownership check refuses",
			build: func(t *testing.T, run *guardRun) (func(http.Handler) http.Handler, *http.Request) {
				g := httpsec.NewGuards(authorize.NewOwnershipAuthorizer(), capturing(run))
				owned := httpsec.ResourceOwnerships(g, "admin", "user",
					recordOwner(false, nil))

				return owned.ForResource(recordID(nil)), guardRequest(t, testPrincipal(), nil)
			},
			assert: func(t *testing.T, run guardRun) {
				require.ErrorIs(t, run.refusal, authorize.ErrAccessDenied)
				assert.False(t, run.routeRan)
			},
		},
		{
			name: "everything the guard needed is there",
			build: func(t *testing.T, run *guardRun) (func(http.Handler) http.Handler, *http.Request) {
				g := httpsec.NewGuards(permittingAuthorizer(t), capturing(run))

				return g.ResourcePrivileges("admin", "user").RequireOne("read"),
					guardRequest(t, testPrincipal(), nil)
			},
			assert: func(t *testing.T, run guardRun) {
				require.NoError(t, run.refusal)
				assert.True(t, run.routeRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var run guardRun

			mw, req := tc.build(t, &run)

			out := runGuard(t, mw, req)
			run.rec, run.routeRan = out.rec, out.routeRan

			tc.assert(t, run)
		})
	}
}

// TestGuardsAuthorizerSource pins where a guard finds its judge: the chain's
// authorizer first, the one it was built with as the fallback.
func TestGuardsAuthorizerSource(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		built  func(t *testing.T) authorize.Authorizer // nil means none at construction
		inCtx  func(t *testing.T) authorize.Authorizer // nil means the chain published none
		assert func(t *testing.T, run guardRun)
	}

	cases := []testCase{
		{
			name:  "the context's authorizer is preferred over the construction one",
			built: func(t *testing.T) authorize.Authorizer { return refusingAuthorizer(t, errAuthorizerRoles) },
			inCtx: func(t *testing.T) authorize.Authorizer { return permittingAuthorizer(t) },
			assert: func(t *testing.T, run guardRun) {
				require.NoError(t, run.refusal,
					"one chain publishes one authorizer, and a guard must not keep judging by a stale one")
				assert.True(t, run.routeRan)
			},
		},
		{
			name:  "the construction authorizer is the fallback when the chain published none",
			built: func(t *testing.T) authorize.Authorizer { return permittingAuthorizer(t) },
			inCtx: nil,
			assert: func(t *testing.T, run guardRun) {
				require.NoError(t, run.refusal)
				assert.True(t, run.routeRan)
			},
		},
		{
			name:  "the context's authorizer decides even when it refuses",
			built: func(t *testing.T) authorize.Authorizer { return permittingAuthorizer(t) },
			inCtx: func(t *testing.T) authorize.Authorizer { return refusingAuthorizer(t, errAuthorizerRoles) },
			assert: func(t *testing.T, run guardRun) {
				require.ErrorIs(t, run.refusal, errAuthorizerRoles)
				assert.False(t, run.routeRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var run guardRun

			var built, published authorize.Authorizer
			if tc.built != nil {
				built = tc.built(t)
			}
			if tc.inCtx != nil {
				published = tc.inCtx(t)
			}

			g := httpsec.NewGuards(built, capturing(&run))
			mw := g.ResourcePrivileges("admin", "user").RequireOne("read")

			out := runGuard(t, mw, guardRequest(t, testPrincipal(), published))
			run.rec, run.routeRan = out.rec, out.routeRan

			tc.assert(t, run)
		})
	}
}

// TestGuardsAttributes pins what each guard builder asks the authorizer, so a
// route guarded by "all of" cannot quietly be judged as "any of".
func TestGuardsAttributes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(g *httpsec.Guards) func(http.Handler) http.Handler
		assert func(t *testing.T, attrs authorize.Attributes)
	}

	cases := []testCase{
		{
			name: "one privilege",
			build: func(g *httpsec.Guards) func(http.Handler) http.Handler {
				return g.ResourcePrivileges("admin", "user").RequireOne("read")
			},
			assert: func(t *testing.T, attrs authorize.Attributes) {
				p, ok := attrs.(authorize.PrivilegeAttributes)
				require.True(t, ok, "got %T", attrs)
				assert.Equal(t, "admin", p.Group)
				assert.Equal(t, "user", p.Resource)
				assert.Equal(t, []string{"read"}, p.Required)
			},
		},
		{
			name: "all of several privileges",
			build: func(g *httpsec.Guards) func(http.Handler) http.Handler {
				return g.ResourcePrivileges("admin", "user").RequireAll("read", "write")
			},
			assert: func(t *testing.T, attrs authorize.Attributes) {
				p, ok := attrs.(authorize.PrivilegeAttributes)
				require.True(t, ok, "got %T", attrs)
				assert.Equal(t, []string{"read", "write"}, p.Required)
				assert.Equal(t, authorize.MatchAllOf, p.Mode)
			},
		},
		{
			name: "any of several privileges",
			build: func(g *httpsec.Guards) func(http.Handler) http.Handler {
				return g.ResourcePrivileges("admin", "user").RequireAny("read", "write")
			},
			assert: func(t *testing.T, attrs authorize.Attributes) {
				p, ok := attrs.(authorize.PrivilegeAttributes)
				require.True(t, ok, "got %T", attrs)
				assert.Equal(t, []string{"read", "write"}, p.Required)
				assert.Equal(t, authorize.MatchAnyOf, p.Mode)
			},
		},
		{
			name: "ownership of the extracted record",
			build: func(g *httpsec.Guards) func(http.Handler) http.Handler {
				owned := httpsec.ResourceOwnerships(g, "admin", "user", recordOwner(true, nil))

				return owned.ForResource(recordID(nil))
			},
			assert: func(t *testing.T, attrs authorize.Attributes) {
				o, ok := attrs.(authorize.OwnershipAttributes)
				require.True(t, ok, "got %T", attrs)
				assert.Equal(t, "admin", o.Group)
				assert.Equal(t, "user", o.Resource)
				require.NotNil(t, o.ResolveID)
				require.NotNil(t, o.OwnedBy)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var seen authorize.Attributes

			az := NewMockAuthorizer(gomock.NewController(t))
			az.EXPECT().Authorize(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, attrs authorize.Attributes) error {
					seen = attrs

					return nil
				})

			run := runGuard(t, tc.build(httpsec.NewGuards(az)),
				guardRequest(t, testPrincipal(), nil))
			require.True(t, run.routeRan)

			tc.assert(t, seen)
		})
	}
}

// TestGuardOwnershipCheck pins that the consumer's own check is asked about the
// record the extractor named and the caller the request carries.
//
// It stands on its own rather than joining the tables above because its setup
// is the consumer's two functions rather than one authorizer's answer.
func TestGuardOwnershipCheck(t *testing.T) {
	t.Parallel()

	var (
		gotID      string
		gotSubject *identity.Principal
	)

	g := httpsec.NewGuards(authorize.NewOwnershipAuthorizer())
	owned := httpsec.ResourceOwnerships(g, "admin", "user",
		func(_ context.Context, subject *identity.Principal, id string) (bool, error) {
			gotID, gotSubject = id, subject

			return true, nil
		})

	p := testPrincipal()
	run := runGuard(t, owned.ForResource(recordID(nil)), guardRequest(t, p, nil))

	require.True(t, run.routeRan)
	assert.Equal(t, "/records/r-1", gotID, "the identifier arrives as the extractor produced it")
	assert.Same(t, p, gotSubject)
}

// TestGuardOnTopOfPermissiveRule pins that a guard is enforced in addition to
// the centralized rules: the rule set permits the request and the guard still
// refuses it.
//
// It stands on its own rather than joining TestGuardsFailClosed because its
// setup is a whole chain in front of the guard rather than a guard alone.
func TestGuardOnTopOfPermissiveRule(t *testing.T) {
	t.Parallel()

	permitAll := authorize.Rule[httpsec.Request]{
		Match:   func(httpsec.Request) bool { return true },
		Require: authorize.PermitAll(),
	}

	var run guardRun

	// The chain judges by an authorizer that refuses, so the guard behind it
	// refuses too although the rule set permitted the request centrally.
	az := refusingAuthorizer(t, errAuthorizerRoles)

	chain, err := httpsec.New(httpsec.EnableAuthorization(az, permitAll))
	require.NoError(t, err)

	guards := httpsec.NewGuards(nil, capturing(&run))
	mw := guards.ResourcePrivileges("admin", "user").RequireOne("read")

	route := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { run.routeRan = true })

	run.rec = httptest.NewRecorder()
	ctx := identity.WithPrincipal(t.Context(), testPrincipal())
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/records/r-1", nil)

	// The terminal stands in for the framework's own routing: the chain resolved
	// the request, and the guarded route runs behind it with what it published.
	handlerRan := false
	runChain := chain.Assemble(func(ex *httpsec.Exchange) error {
		handlerRan = true
		mw(route).ServeHTTP(run.rec, req.WithContext(ex.Context()))

		return nil
	})

	chainErr := runChain(httpsec.NewExchange(ctx,
		httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(run.rec)))

	require.NoError(t, chainErr, "the centralized rule permitted the request")
	require.True(t, handlerRan)
	require.ErrorIs(t, run.refusal, errAuthorizerRoles)
	assert.False(t, run.routeRan, "the route behind the guard is not called")
}

// answering records what a guard refused with and still writes the status the
// public table gives, so a row names both the refusal and what a client would
// have been answered with.
func answering(run *guardRun) httpsec.GuardOption {
	return httpsec.WithGuardErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
		run.refusal = err

		w.WriteHeader(httpsec.StatusForError(err))
	})
}

// TestGuardBehindAuthentication pins that a guard behind a chain which has
// already authenticated the caller lets them through, whichever first factor
// did the authenticating.
//
// A guard asks who the caller is, so a first factor that publishes only its
// authentication result leaves every guard refusing a caller the chain itself
// accepted — and that refusal is indistinguishable from a missing credential.
// The last row is the other half of the contract: the fix must not open the
// guard to a request nothing authenticated.
func TestGuardBehindAuthentication(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		build   func(t *testing.T, h *authHarness, published *context.Context) *httpsec.Chain
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, run guardRun)
	}

	letThrough := func(t *testing.T, run guardRun) {
		require.NoError(t, run.refusal,
			"the chain authenticated this caller, so its own guard must not refuse them")
		assert.True(t, run.routeRan, "the guarded route runs for an authenticated caller")
		assert.Equal(t, http.StatusOK, run.rec.Code)
	}

	cases := []testCase{
		{
			name: "behind form login",
			build: func(t *testing.T, h *authHarness, published *context.Context) *httpsec.Chain {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("tok-1")

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(h.formLoginDeps(),
						httpsec.WithLoginResponder(
							func(ex *httpsec.Exchange, _ httpsec.LoginResult) error {
								// Form login answers its own endpoint, so what
								// it published is read here rather than at a
								// handler behind the chain.
								*published = ex.Context()

								return nil
							})),
				)
				require.NoError(t, err)

				return chain
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: letThrough,
		},
		{
			name: "behind Basic authentication",
			build: func(t *testing.T, h *authHarness, _ *context.Context) *httpsec.Chain {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBasicAuth(h.basicAuthDeps()))
				require.NoError(t, err)

				return chain
			},
			request: func(ctx context.Context) *http.Request {
				return basicRequest(ctx, "ada", "s3cret")
			},
			assert: letThrough,
		},
		{
			name: "behind bearer authentication",
			build: func(t *testing.T, h *authHarness, _ *context.Context) *httpsec.Chain {
				h.expectVerified()
				h.expectLiveSessionAndUser(liveSession())

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()))
				require.NoError(t, err)

				return chain
			},
			request: func(ctx context.Context) *http.Request {
				return bearerRequest(ctx, "Bearer abc.def.ghi")
			},
			assert: letThrough,
		},
		{
			name: "the same guard still refuses a caller nothing authenticated",
			build: func(t *testing.T, h *authHarness, _ *context.Context) *httpsec.Chain {
				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBasicAuth(h.basicAuthDeps()))
				require.NoError(t, err)

				return chain
			},
			request: func(ctx context.Context) *http.Request { return rawBasicRequest(ctx, "") },
			assert: func(t *testing.T, run guardRun) {
				require.ErrorIs(t, run.refusal, httpsec.ErrAuthenticationRequired)
				assert.False(t, run.routeRan)
				assert.Equal(t, http.StatusUnauthorized, run.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)

			var published context.Context

			chain := tc.build(t, h, &published)

			s := serve(t, chain, tc.request(t.Context()))
			require.NoError(t, s.err, "the chain accepted this request")

			if published == nil {
				require.NotNil(t, s.handled, "the request reached what runs behind the chain")
				published = s.handled.Context()
			}

			var run guardRun

			g := httpsec.NewGuards(permittingAuthorizer(t), answering(&run))
			out := runGuard(t, g.RequireAuthenticated(),
				httptest.NewRequestWithContext(published, http.MethodGet, "/records/r-1", nil))
			run.rec, run.routeRan = out.rec, out.routeRan

			tc.assert(t, run)
		})
	}
}

// TestConsumerFirstFactorPublishesCaller pins that an interceptor a consumer
// registers can publish its caller exactly as a built-in first factor does.
//
// The obvious exported API is authenticate.WithAuthentication, which publishes
// only the event. A guard asks who the caller is, so a consumer's first factor
// that publishes the event alone leaves every guard behind it refusing 401 — a
// refusal indistinguishable from a missing credential. The second row is the
// other half of the contract: the helper must not open the guard to a request
// nothing authenticated.
func TestConsumerFirstFactorPublishesCaller(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// publish is the consumer's own first factor, given the exchange it is
		// judging. A row that publishes nothing stands for a request that
		// authenticated nothing.
		publish func(ex *httpsec.Exchange)

		assert func(t *testing.T, run guardRun, caller *identity.Principal, known bool)
	}

	cases := []testCase{
		{
			name: "a consumer interceptor using the exported helper",
			publish: func(ex *httpsec.Exchange) {
				ex.SetContext(httpsec.WithCaller(ex.Context(), &authenticate.Authentication{
					Principal: testPrincipal(),
					Time:      time.Now(),
				}))
			},
			assert: func(t *testing.T, run guardRun, caller *identity.Principal, known bool) {
				require.NoError(t, run.refusal,
					"the consumer's first factor authenticated this caller, "+
						"so a guard behind it must not refuse them")
				assert.True(t, run.routeRan, "the guarded route runs for an authenticated caller")
				assert.Equal(t, http.StatusOK, run.rec.Code)

				require.True(t, known, "the handler reads the principal the chain resolved")
				assert.Equal(t, testPrincipal().ID, caller.ID)
			},
		},
		{
			name:    "the same guard still refuses a caller nothing authenticated",
			publish: func(*httpsec.Exchange) {},
			assert: func(t *testing.T, run guardRun, _ *identity.Principal, known bool) {
				require.ErrorIs(t, run.refusal, httpsec.ErrAuthenticationRequired)
				assert.False(t, run.routeRan, "the route behind the guard is not called")
				assert.Equal(t, http.StatusUnauthorized, run.rec.Code)
				assert.False(t, known, "nothing authenticated this request")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			first := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				tc.publish(ex)

				return next(ex)
			})

			chain, err := httpsec.New(
				httpsec.RegisterInterceptor(first, httpsec.After(httpsec.OrderBearerToken)))
			require.NoError(t, err)

			s := serve(t, chain, httptest.NewRequestWithContext(
				t.Context(), http.MethodGet, "/records/r-1", nil))
			require.NoError(t, s.err, "the chain accepted this request")
			require.NotNil(t, s.handled, "the request reached what runs behind the chain")

			published := s.handled.Context()
			caller, known := identity.PrincipalFromContext(published)

			var run guardRun

			g := httpsec.NewGuards(permittingAuthorizer(t), answering(&run))
			out := runGuard(t, g.RequireAuthenticated(),
				httptest.NewRequestWithContext(published, http.MethodGet, "/records/r-1", nil))
			run.rec, run.routeRan = out.rec, out.routeRan

			tc.assert(t, run, caller, known)
		})
	}
}
