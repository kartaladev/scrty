package httpsec

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// declaring is a built-in stand-in that declares what it is given.
type declaring struct {
	declared []Endpoint
}

func (d declaring) Intercept(ex *Exchange, next Next) error { return next(ex) }

func (d declaring) endpoints() []Endpoint { return d.declared }

// declaredAt is one complete entry at path, with identifier id.
func declaredAt(id, path string) Endpoint {
	return declare("EnableTest", "WithTestPath", id, path, MatchExact, PassThrough, RequiresNothing, http.MethodPost)
}

// TestChainEndpoints_Collect pins how New gathers the declarations: in slot
// order and then registration order, skipping interceptors that declare
// nothing, and refusing a declaration that does not describe its operation.
func TestChainEndpoints_Collect(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		register func(c *config)
		assert   func(t *testing.T, eps []Endpoint, err error)
	}

	broken := func(change func(e *Endpoint)) func(c *config) {
		return func(c *config) {
			e := declaredAt("scrty.test", "/test")
			change(&e)
			c.register(declaring{declared: []Endpoint{e}}, OrderFormLogin)
		}
	}

	refused := func(field string) func(t *testing.T, eps []Endpoint, err error) {
		return func(t *testing.T, eps []Endpoint, err error) {
			require.Error(t, err)
			assert.Contains(t, err.Error(), field)
			assert.Nil(t, eps)
		}
	}

	cases := []testCase{
		{
			name: "slot order, then registration order",
			register: func(c *config) {
				c.register(declaring{declared: []Endpoint{declaredAt("scrty.late", "/late")}}, OrderLogout)
				c.register(declaring{declared: []Endpoint{
					declaredAt("scrty.first.a", "/a"), declaredAt("scrty.first.b", "/b"),
				}}, OrderJWKS)
				c.register(InterceptorFunc(func(ex *Exchange, next Next) error { return next(ex) }), OrderJWKS)
				c.register(declaring{declared: []Endpoint{declaredAt("scrty.second", "/second")}}, OrderJWKS)
			},
			assert: func(t *testing.T, eps []Endpoint, err error) {
				require.NoError(t, err)

				ids := make([]string, 0, len(eps))
				for _, e := range eps {
					ids = append(ids, e.OperationID)
				}

				assert.Equal(t, []string{"scrty.first.a", "scrty.first.b", "scrty.second", "scrty.late"}, ids)
			},
		},
		{
			name:     "nothing declared is an empty list",
			register: func(*config) {},
			assert: func(t *testing.T, eps []Endpoint, err error) {
				require.NoError(t, err)
				assert.NotNil(t, eps)
				assert.Empty(t, eps)
			},
		},
		{
			name:     "an identifier outside the scrty namespace is refused",
			register: broken(func(e *Endpoint) { e.OperationID = "sign-in" }),
			assert:   refused("operation identifier"),
		},
		{
			name:     "no methods is refused",
			register: broken(func(e *Endpoint) { e.Methods = nil }),
			assert:   refused("methods"),
		},
		{
			name:     "an empty method is refused",
			register: broken(func(e *Endpoint) { e.Methods = []string{""} }),
			assert:   refused("methods"),
		},
		{
			name:     "an empty path, an endpoint nobody placed, is refused",
			register: broken(func(e *Endpoint) { e.Path = "" }),
			assert:   refused("a path"),
		},
		{
			name:     "no match kind is refused",
			register: broken(func(e *Endpoint) { e.Match = 0 }),
			assert:   refused("match kind"),
		},
		{
			name:     "no other-method policy is refused",
			register: broken(func(e *Endpoint) { e.OtherMethods = 0 }),
			assert:   refused("other-method policy"),
		},
		{
			name:     "no requirement is refused",
			register: broken(func(e *Endpoint) { e.Requires = 0 }),
			assert:   refused("requirement"),
		},
		{
			name:     "no placing setting is refused",
			register: broken(func(e *Endpoint) { e.PlacedBy = "" }),
			assert:   refused("setting and feature"),
		},
		{
			name:     "no feature is refused",
			register: broken(func(e *Endpoint) { e.feature = "" }),
			assert:   refused("setting and feature"),
		},
		{
			name: "an identifier listed twice is refused, naming it and both settings",
			register: func(c *config) {
				first := declaredAt("scrty.test", "/one")
				first.PlacedBy = "WithFirstPath"
				second := declaredAt("scrty.test", "/two")
				second.PlacedBy = "WithSecondPath"
				c.register(declaring{declared: []Endpoint{first}}, OrderJWKS)
				c.register(declaring{declared: []Endpoint{second}}, OrderLogout)
			},
			assert: func(t *testing.T, eps []Endpoint, err error) {
				require.ErrorIs(t, err, ErrConfig)
				assert.Contains(t, err.Error(), "scrty.test")
				assert.Contains(t, err.Error(), "WithFirstPath")
				assert.Contains(t, err.Error(), "WithSecondPath")
				assert.Nil(t, eps)
			},
		},
		func() testCase {
			shared := []string{http.MethodGet}

			return testCase{
				name: "the collected methods are not the declaration's",
				register: func(c *config) {
					e := declaredAt("scrty.test", "/test")
					e.Methods = shared
					c.register(declaring{declared: []Endpoint{e}}, OrderJWKS)
				},
				assert: func(t *testing.T, eps []Endpoint, err error) {
					require.NoError(t, err)
					require.Len(t, eps, 1)

					shared[0] = http.MethodDelete

					assert.Equal(t, []string{http.MethodGet}, eps[0].Methods,
						"a later change to the declared slice does not reach the inventory")
				},
			}
		}(),
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &config{}
			tc.register(c)

			eps, err := collectEndpoints(c.ordered())
			tc.assert(t, eps, err)
		})
	}
}

// TestChainEndpoints_NilChain pins that a nil chain lists nothing rather than
// panicking.
func TestChainEndpoints_NilChain(t *testing.T) {
	t.Parallel()

	var c *Chain

	eps := c.Endpoints()
	assert.NotNil(t, eps)
	assert.Empty(t, eps)
}

// TestEndpointEnums_String pins the names the enumerations print, an unnamed
// value included.
func TestEndpointEnums_String(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		value  interface{ String() string }
		assert func(t *testing.T, s string)
	}

	is := func(want string) func(t *testing.T, s string) {
		return func(t *testing.T, s string) {
			t.Helper()
			assert.Equal(t, want, s)
		}
	}

	cases := []testCase{
		{"exact", MatchExact, is("MatchExact")},
		{"segment", MatchSegment, is("MatchSegment")},
		{"subtree", MatchSubtree, is("MatchSubtree")},
		{"no match kind", PathMatch(0), is("PathMatch(0)")},
		{"pass through", PassThrough, is("PassThrough")},
		{"refused", Refused, is("Refused")},
		{"no policy", MethodPolicy(9), is("MethodPolicy(9)")},
		{"nothing", RequiresNothing, is("RequiresNothing")},
		{"authentication", RequiresAuthentication, is("RequiresAuthentication")},
		{"pending second factor", RequiresPendingSecondFactor, is("RequiresPendingSecondFactor")},
		{"pending enrolment", RequiresPendingEnrolment, is("RequiresPendingEnrolment")},
		{"session", RequiresSession, is("RequiresSession")},
		{"bearer", RequiresBearer, is("RequiresBearer")},
		{"client authentication", RequiresClientAuthentication, is("RequiresClientAuthentication")},
		{"no requirement", Requirement(0), is("Requirement(0)")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.value.String())
		})
	}
}
