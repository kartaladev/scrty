package fibersec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	recoverer "github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
)

// The errors a guard's collaborators fail with, each distinct so a row can say
// which one the refusal came from and whether it arrived unchanged.
var (
	errNoRecordID      = errors.New("guards_test: the path names no record")
	errAuthorizerRoles = errors.New("guards_test: the role store is unreachable")
)

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

// recordID extracts the identifier an ownership guard judges, or fails.
func recordID(err error) func(httpsec.Request) (string, error) {
	return func(r httpsec.Request) (string, error) {
		if err != nil {
			return "", err
		}

		return r.Path(), nil
	}
}

// mustGuards builds fiber guards a test needs to exist, failing the test when
// the wiring it was handed is refused.
func mustGuards(t *testing.T, az authorize.Authorizer, opts ...fibersec.GuardOption) *fibersec.Guards {
	t.Helper()

	g, err := fibersec.NewGuards(az, opts...)
	require.NoError(t, err)

	return g
}

// TestFiber_NewGuards_Authorizer pins that fiber guards follow the core guards'
// construction rule: an authorizer, a declared reliance on the chain's, or
// both, and a refusal at construction for neither. A refusal is still rendered
// by fiber's error handler, which the consumer owns.
func TestFiber_NewGuards_Authorizer(t *testing.T) {
	t.Parallel()

	var typedNil *MockAuthorizer

	// guarded serves one request through a fiber chain that publishes the test
	// principal, with opts added to the chain, onto a route behind g's guard.
	// The error handler records the refusal and then answers as the library's
	// default does. fiber's recover middleware turns a panic into an error, so
	// a nil-method call shows as a wrong refusal rather than a crashed binary.
	guarded := func(t *testing.T, g *fibersec.Guards, opts ...httpsec.Option) (response, bool, error) {
		t.Helper()

		var (
			refusal  error
			routeRan bool
		)

		app := fiber.New(fiber.Config{ErrorHandler: func(fc fiber.Ctx, err error) error {
			refusal = err

			return fibersec.ErrorHandler(fc, err)
		}})
		app.Use(recoverer.New())
		app.Use(fibersec.Middleware(newChain(t, append([]httpsec.Option{
			httpsec.RegisterInterceptor(publishing(testPrincipal()), httpsec.OrderBearerToken),
		}, opts...)...)))
		app.Get("/records/:id", g.ResourcePrivileges("admin", "user").RequireOne("read"),
			func(fc fiber.Ctx) error {
				routeRan = true

				return fc.SendStatus(http.StatusNoContent)
			})

		res := serve(t, app,
			httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records/r-1", nil))

		return res, routeRan, refusal
	}

	type testCase struct {
		name   string
		az     func(t *testing.T) authorize.Authorizer
		opts   []fibersec.GuardOption
		assert func(t *testing.T, g *fibersec.Guards, err error)
	}

	cases := []testCase{
		{
			name: "fiber guards built with no authorizer",
			az:   func(*testing.T) authorize.Authorizer { return nil },
			assert: func(t *testing.T, g *fibersec.Guards, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, g)
			},
		},
		{
			name: "typed-nil authorizer",
			az:   func(*testing.T) authorize.Authorizer { return typedNil },
			assert: func(t *testing.T, g *fibersec.Guards, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig,
					"an interface holding a nil value is no authorizer")
				assert.Nil(t, g)
			},
		},
		{
			name: "chain authorizer declared",
			az:   func(*testing.T) authorize.Authorizer { return nil },
			opts: []fibersec.GuardOption{fibersec.WithChainAuthorizer()},
			assert: func(t *testing.T, g *fibersec.Guards, err error) {
				require.NoError(t, err)

				chainAz := NewMockAuthorizer(gomock.NewController(t))
				chainAz.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(nil).Times(1)

				res, routeRan, refusal := guarded(t, g, httpsec.EnableAuthorization(chainAz))

				require.NoError(t, refusal)
				assert.True(t, routeRan, "the guard judged with the chain's authorizer")
				assert.Equal(t, http.StatusNoContent, res.status)
			},
		},
		{
			name: "typed nil beside declared reliance",
			az:   func(*testing.T) authorize.Authorizer { return typedNil },
			opts: []fibersec.GuardOption{fibersec.WithChainAuthorizer()},
			assert: func(t *testing.T, g *fibersec.Guards, err error) {
				require.NoError(t, err)

				res, routeRan, refusal := guarded(t, g)

				require.ErrorIs(t, refusal, authorize.ErrAccessDenied,
					"a typed nil is no fallback, so no method is called on it")
				assert.False(t, routeRan)
				assert.Equal(t, http.StatusForbidden, res.status)
			},
		},
		{
			name: "declared reliance, no chain authorizer",
			az:   func(*testing.T) authorize.Authorizer { return nil },
			opts: []fibersec.GuardOption{fibersec.WithChainAuthorizer()},
			assert: func(t *testing.T, g *fibersec.Guards, err error) {
				require.NoError(t, err)

				_, routeRan, refusal := guarded(t, g)

				require.ErrorIs(t, refusal, authorize.ErrAccessDenied)
				assert.False(t, routeRan)
			},
		},
		{
			name: "both given",
			az:   func(t *testing.T) authorize.Authorizer { return refusingAuthorizer(t, errAuthorizerRoles) },
			opts: []fibersec.GuardOption{fibersec.WithChainAuthorizer()},
			assert: func(t *testing.T, g *fibersec.Guards, err error) {
				require.NoError(t, err)

				_, routeRan, refusal := guarded(t, g, httpsec.EnableAuthorization(permittingAuthorizer(t)))
				require.NoError(t, refusal)
				assert.True(t, routeRan, "the request's authorizer is preferred over the one built in")

				_, routeRan, refusal = guarded(t, g)
				require.ErrorIs(t, refusal, errAuthorizerRoles,
					"the one built in is the fallback when the request carries none")
				assert.False(t, routeRan)
			},
		},
		{
			name: "fiber guard refusal reaches the consumer's error handler",
			az: func(t *testing.T) authorize.Authorizer {
				return refusingAuthorizer(t, authorize.ErrAccessDenied)
			},
			assert: func(t *testing.T, g *fibersec.Guards, err error) {
				require.NoError(t, err)

				var refusal error

				app := fiber.New(fiber.Config{ErrorHandler: func(fc fiber.Ctx, err error) error {
					refusal = err

					return fc.Status(http.StatusTeapot).SendString("custom")
				}})
				app.Use(fibersec.Middleware(newChain(t,
					httpsec.RegisterInterceptor(publishing(testPrincipal()), httpsec.OrderBearerToken))))
				app.Get("/records/:id", g.ResourcePrivileges("admin", "user").RequireOne("read"),
					func(fiber.Ctx) error {
						t.Error("the route behind a refusing guard ran")

						return nil
					})

				res := serve(t, app,
					httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records/r-1", nil))

				require.ErrorIs(t, refusal, authorize.ErrAccessDenied)
				assert.Equal(t, http.StatusTeapot, res.status)
				assert.Equal(t, "custom", res.body, "the consumer's error handler rendered the refusal")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g, err := fibersec.NewGuards(tc.az(t), tc.opts...)
			tc.assert(t, g, err)
		})
	}
}

// TestFiberGuards pins the fail-closed contract at a fiber route: a guard that
// cannot establish the caller may proceed returns its refusal the way the chain
// does, and the route never runs.
func TestFiberGuards(t *testing.T) {
	t.Parallel()

	type guarded struct {
		routeRan bool
		refusal  error
	}

	type testCase struct {
		name string

		// caller is the principal the chain publishes, and nil means the chain
		// authenticated nobody.
		caller *identity.Principal

		build  func(t *testing.T) fiber.Handler
		assert func(t *testing.T, res response, out guarded)
	}

	cases := []testCase{
		{
			name:   "a guard behind an authenticating chain reaches the route",
			caller: testPrincipal(),
			build: func(t *testing.T) fiber.Handler {
				t.Helper()

				return mustGuards(t, permittingAuthorizer(t)).
					ResourcePrivileges("admin", "user").RequireOne("read")
			},
			assert: func(t *testing.T, res response, out guarded) {
				require.NoError(t, out.refusal)
				assert.True(t, out.routeRan)
				assert.Equal(t, http.StatusNoContent, res.status)
			},
		},
		{
			name:   "a request nothing authenticated is told to authenticate",
			caller: nil,
			build: func(t *testing.T) fiber.Handler {
				t.Helper()

				return mustGuards(t, permittingAuthorizer(t)).RequireAuthenticated()
			},
			assert: func(t *testing.T, res response, out guarded) {
				require.ErrorIs(t, out.refusal, httpsec.ErrAuthenticationRequired)
				assert.ErrorIs(t, out.refusal, authorize.ErrAuthenticationRequired,
					"either identity reaches a consumer matching on one of them")
				assert.False(t, out.routeRan)
				assert.Equal(t, http.StatusUnauthorized, res.status)
				assert.Empty(t, res.body)
			},
		},
		{
			name:   "a guard that found no judge refuses",
			caller: testPrincipal(),
			build: func(t *testing.T) fiber.Handler {
				t.Helper()

				return mustGuards(t, nil, fibersec.WithChainAuthorizer()).
					ResourcePrivileges("admin", "user").RequireOne("read")
			},
			assert: func(t *testing.T, res response, out guarded) {
				require.ErrorIs(t, out.refusal, authorize.ErrAccessDenied,
					"a guard that found no judge has not been told the request is allowed")
				assert.False(t, out.routeRan)
				assert.Equal(t, http.StatusForbidden, res.status)
			},
		},
		{
			name:   "the authorizer's refusal is returned unchanged",
			caller: testPrincipal(),
			build: func(t *testing.T) fiber.Handler {
				t.Helper()

				return mustGuards(t, refusingAuthorizer(t, errAuthorizerRoles)).
					ResourcePrivileges("admin", "user").RequireAll("read", "write")
			},
			assert: func(t *testing.T, res response, out guarded) {
				require.ErrorIs(t, out.refusal, errAuthorizerRoles,
					"rewriting it here would cost the consumer the reason")
				assert.False(t, out.routeRan)
				assert.Equal(t, http.StatusInternalServerError, res.status,
					"a judge that could not answer is a fault, not a judgement")
			},
		},
		{
			name:   "an extractor that cannot name the record refuses before any lookup",
			caller: testPrincipal(),
			build: func(t *testing.T) fiber.Handler {
				t.Helper()

				g := mustGuards(t, authorize.NewOwnershipAuthorizer())
				owned := fibersec.ResourceOwnerships(g, "admin", "user",
					func(context.Context, *identity.Principal, string) (bool, error) {
						t.Error("the ownership check ran although the record was never named")

						return true, nil
					})

				return owned.ForResource(recordID(errNoRecordID))
			},
			assert: func(t *testing.T, _ response, out guarded) {
				require.ErrorIs(t, out.refusal, errNoRecordID)
				assert.False(t, out.routeRan)
			},
		},
		{
			name:   "an ownership guard reaches the route for the record's owner",
			caller: testPrincipal(),
			build: func(t *testing.T) fiber.Handler {
				t.Helper()

				g := mustGuards(t, authorize.NewOwnershipAuthorizer())
				owned := fibersec.ResourceOwnerships(g, "admin", "user",
					func(_ context.Context, subject *identity.Principal, id string) (bool, error) {
						return subject.ID == "u-1" && id == "/records/r-1", nil
					})

				return owned.ForResource(recordID(nil))
			},
			assert: func(t *testing.T, res response, out guarded) {
				require.NoError(t, out.refusal)
				assert.True(t, out.routeRan)
				assert.Equal(t, http.StatusNoContent, res.status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out guarded

			app := fiber.New(fiber.Config{ErrorHandler: func(fc fiber.Ctx, err error) error {
				out.refusal = err

				return fibersec.ErrorHandler(fc, err)
			}})

			app.Use(fibersec.Middleware(newChain(t,
				httpsec.RegisterInterceptor(publishing(tc.caller), httpsec.OrderBearerToken))))
			app.Get("/records/:id", tc.build(t), func(fc fiber.Ctx) error {
				out.routeRan = true

				return fc.SendStatus(http.StatusNoContent)
			})

			res := serve(t, app,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records/r-1", nil))

			tc.assert(t, res, out)
		})
	}
}

// TestFiberGuardsAttributes pins what each guard builder asks the authorizer, so
// a route guarded by "all of" cannot quietly be judged as "any of".
//
// It stands apart from TestFiberGuards: each case lets the request through and
// records what the authorizer was asked.
func TestFiberGuardsAttributes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(g *fibersec.Guards) fiber.Handler
		assert func(t *testing.T, attrs authorize.Attributes)
	}

	cases := []testCase{
		{
			name: "one privilege",
			build: func(g *fibersec.Guards) fiber.Handler {
				return g.ResourcePrivileges("admin", "user").RequireOne("read")
			},
			assert: func(t *testing.T, attrs authorize.Attributes) {
				p, ok := attrs.(authorize.PrivilegeAttributes)
				require.True(t, ok, "got %T", attrs)
				assert.Equal(t, "admin", p.Group)
				assert.Equal(t, "user", p.Resource)
				assert.Equal(t, []string{"read"}, p.Required)
				assert.Equal(t, authorize.MatchAllOf, p.Mode)
			},
		},
		{
			name: "all of several privileges",
			build: func(g *fibersec.Guards) fiber.Handler {
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
			build: func(g *fibersec.Guards) fiber.Handler {
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
			build: func(g *fibersec.Guards) fiber.Handler {
				owned := fibersec.ResourceOwnerships(g, "admin", "user",
					func(context.Context, *identity.Principal, string) (bool, error) {
						return true, nil
					})

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

			var (
				seen     authorize.Attributes
				routeRan bool
			)

			az := NewMockAuthorizer(gomock.NewController(t))
			az.EXPECT().Authorize(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, attrs authorize.Attributes) error {
					seen = attrs

					return nil
				}).AnyTimes()

			app := fiber.New()
			app.Use(fibersec.Middleware(newChain(t,
				httpsec.RegisterInterceptor(publishing(testPrincipal()), httpsec.OrderBearerToken))))
			app.Get("/records/:id", tc.build(mustGuards(t, az)), func(fc fiber.Ctx) error {
				routeRan = true

				return fc.SendStatus(http.StatusNoContent)
			})

			res := serve(t, app,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records/r-1", nil))
			require.Equal(t, http.StatusNoContent, res.status)
			require.True(t, routeRan)
			require.NotNil(t, seen, "the guard asked the authorizer something")

			tc.assert(t, seen)
		})
	}
}

// ownedByAnyone is a checker that is never reached: the wiring cases fail first.
func ownedByAnyone(context.Context, *identity.Principal, string) (bool, error) { return true, nil }

// TestFiber_OwnershipGuardFailsAtWiring pins that a guard built without what
// it cannot work without panics when it is wired, naming the missing
// dependency, instead of refusing every request once traffic arrives.
func TestFiber_OwnershipGuardFailsAtWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "with nil checker",
			assert: func(t *testing.T) {
				assert.PanicsWithValue(t, "fibersec: ResourceOwnerships needs a non-nil checker", func() {
					fibersec.ResourceOwnerships[string](mustGuards(t, nil, fibersec.WithChainAuthorizer()), "orders", "order", nil)
				})
			},
		},
		{
			name: "with nil extractor",
			assert: func(t *testing.T) {
				owned := fibersec.ResourceOwnerships[string](mustGuards(t, nil, fibersec.WithChainAuthorizer()), "orders", "order", ownedByAnyone)

				assert.PanicsWithValue(t, "fibersec: ForResource needs a non-nil extractor", func() {
					owned.ForResource(nil)
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}

// TestFiber_GuardsBuildersWithNilGuardsFailAtWiring stands apart from
// TestFiber_OwnershipGuardFailsAtWiring: its cases are named after the builder
// called on nil Guards, and folding them would need a nested group.
func TestFiber_GuardsBuildersWithNilGuardsFailAtWiring(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func()
		panics string
	}

	cases := []testCase{
		{
			name:   "RequireAuthenticated",
			build:  func() { (*fibersec.Guards)(nil).RequireAuthenticated() },
			panics: "fibersec: RequireAuthenticated needs non-nil Guards",
		},
		{
			name:   "ResourcePrivileges",
			build:  func() { (*fibersec.Guards)(nil).ResourcePrivileges("orders", "order") },
			panics: "fibersec: ResourcePrivileges needs non-nil Guards",
		},
		{
			name: "ResourceOwnerships",
			build: func() {
				fibersec.ResourceOwnerships[string](nil, "orders", "order", ownedByAnyone)
			},
			panics: "fibersec: ResourceOwnerships needs non-nil Guards",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.PanicsWithValue(t, tc.panics, tc.build)
		})
	}
}
