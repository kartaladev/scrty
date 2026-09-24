package fibersec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/fibersec"
	"github.com/kartaladev/scrty/httpsec"
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

				return fibersec.NewGuards(permittingAuthorizer(t)).
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

				return fibersec.NewGuards(permittingAuthorizer(t)).RequireAuthenticated()
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

				return fibersec.NewGuards(nil).
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

				return fibersec.NewGuards(refusingAuthorizer(t, errAuthorizerRoles)).
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

				g := fibersec.NewGuards(authorize.NewOwnershipAuthorizer())
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

				g := fibersec.NewGuards(authorize.NewOwnershipAuthorizer())
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
			app.Get("/records/:id", tc.build(fibersec.NewGuards(az)), func(fc fiber.Ctx) error {
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
