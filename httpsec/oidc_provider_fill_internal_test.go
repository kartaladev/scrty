package httpsec

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// routeGroup is a group that answers fixed routes, so a test can place two on
// one path, which no consumer option can do once the chain has resolved.
type routeGroup struct {
	oidcGroupBase

	list []oidcRoute
}

func (g *routeGroup) routes() []oidcRoute { return g.list }

func (*routeGroup) flushRefusalLogs() error { return nil }

func TestOIDCProviderFillRouters_DuplicateIsInvariant(t *testing.T) {
	t.Parallel()

	handler := func(*Exchange, Next) error { return nil }

	type testCase struct {
		name   string
		groups [][]oidcRoute
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "two groups on one outer path are a broken invariant",
			groups: [][]oidcRoute{{{path: "/p/x", handle: handler}}, {{path: "/p/x", handle: handler}}},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, ErrConfig)
				assert.Contains(t, err.Error(), "internal")
				assert.Contains(t, err.Error(), `"/p/x"`)
			},
		},
		{
			name:   "an outer and an inner route on one path are a broken invariant",
			groups: [][]oidcRoute{{{path: "/p/y", handle: handler}, {path: "/p/y", inner: true, handle: handler}}},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.False(t, errors.Is(err, ErrConfig))
				assert.Contains(t, err.Error(), `"/p/y"`)
			},
		},
		{
			name:   "distinct paths fill without error",
			groups: [][]oidcRoute{{{path: "/p/a", handle: handler}}, {{path: "/p/b", inner: true, handle: handler}}},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			op := &oidcEndpoints{outer: &oidcOuterRouter{}, inner: &oidcInnerRouter{}}
			for _, list := range tc.groups {
				op.groups = append(op.groups, &routeGroup{list: list})
			}

			tc.assert(t, op.fillRouters())
		})
	}
}
