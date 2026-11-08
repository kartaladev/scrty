package httpsec

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shared is e declared to share path with the operations of its feature that
// declare the same one.
func shared(e Endpoint, feature, path string) Endpoint {
	e.feature = feature
	e.SharesPath = path

	return e
}

// op is an operation of feature "EnableA" at path.
func op(id, path string, match PathMatch, other MethodPolicy, methods ...string) Endpoint {
	return declare("EnableA", "WithAPath", id, path, match, other, RequiresNothing, methods...)
}

// TestCheckCollisions_Pairs pins the pair predicate: which two operations
// collide, and the one exemption, which only operations of one feature that
// declare the same shared path get.
func TestCheckCollisions_Pairs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		a, b   Endpoint
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConfig)
	}
	allowed := func(t *testing.T, err error) {
		t.Helper()

		assert.NoError(t, err)
	}

	const path = "/shared"

	sharedOf := func(feature string, e Endpoint) Endpoint { return shared(e, feature, path) }

	exact := func(id string, methods ...string) Endpoint {
		return op(id, path, MatchExact, PassThrough, methods...)
	}
	segment := func(id string, methods ...string) Endpoint {
		return op(id, path+"/{name}", MatchSegment, PassThrough, methods...)
	}

	cases := []testCase{
		{
			name:   "one feature sharing a path, answering different methods",
			a:      sharedOf("EnableA", exact("scrty.a", http.MethodGet)),
			b:      sharedOf("EnableA", exact("scrty.b", http.MethodPost)),
			assert: allowed,
		},
		{
			name:   "one feature sharing a path, answering the same method on the same exact path",
			a:      sharedOf("EnableA", exact("scrty.a", http.MethodPost)),
			b:      sharedOf("EnableA", exact("scrty.b", http.MethodPost)),
			assert: refused,
		},
		{
			name:   "one feature sharing a path, an exact path beside one segment, the same method",
			a:      sharedOf("EnableA", exact("scrty.a", http.MethodPost)),
			b:      sharedOf("EnableA", segment("scrty.b", http.MethodPost)),
			assert: allowed,
		},
		{
			name:   "one feature sharing a path, one segment beside an exact path, the same method",
			a:      sharedOf("EnableA", segment("scrty.a", http.MethodPost)),
			b:      sharedOf("EnableA", exact("scrty.b", http.MethodPost)),
			assert: allowed,
		},
		{
			name: "one feature sharing a path, a subtree over an exact path, the same method",
			a:    sharedOf("EnableA", exact("scrty.a", http.MethodPost)),
			b: sharedOf("EnableA", op("scrty.b", path+"/{rest...}", MatchSubtree, PassThrough,
				http.MethodPost)),
			assert: refused,
		},
		{
			name:   "one feature sharing a path, two segments, the same method",
			a:      sharedOf("EnableA", segment("scrty.a", http.MethodPost)),
			b:      sharedOf("EnableA", segment("scrty.b", http.MethodPost)),
			assert: refused,
		},
		{
			name:   "two features declaring the same shared path, answering different methods",
			a:      sharedOf("EnableA", exact("scrty.a", http.MethodGet)),
			b:      sharedOf("EnableB", exact("scrty.b", http.MethodPost)),
			assert: refused,
		},
		{
			name:   "two features declaring the same shared path, an exact path beside one segment",
			a:      sharedOf("EnableA", exact("scrty.a", http.MethodPost)),
			b:      sharedOf("EnableB", segment("scrty.b", http.MethodPost)),
			assert: refused,
		},
		{
			name:   "one feature, only one side declaring the shared path",
			a:      sharedOf("EnableA", exact("scrty.a", http.MethodGet)),
			b:      exact("scrty.b", http.MethodPost),
			assert: refused,
		},
		{
			name:   "one feature declaring two different shared paths",
			a:      shared(exact("scrty.a", http.MethodGet), "EnableA", "one"),
			b:      shared(exact("scrty.b", http.MethodPost), "EnableA", "two"),
			assert: refused,
		},
		{
			name:   "one feature, no declared sharing, different methods on one path",
			a:      exact("scrty.a", http.MethodGet),
			b:      exact("scrty.b", http.MethodPost),
			assert: refused,
		},
		{
			name:   "different paths and methods",
			a:      exact("scrty.a", http.MethodGet),
			b:      op("scrty.b", "/elsewhere", MatchExact, PassThrough, http.MethodGet),
			assert: allowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, checkCollisions([]Endpoint{tc.a, tc.b}))
		})
	}
}

// TestClaimsMeet pins which request paths two claims share, for each pair of
// match kinds, in either order.
func TestClaimsMeet(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		a, b pathClaim
		want bool
	}

	exact := func(base string) pathClaim { return pathClaim{match: MatchExact, base: base} }
	segment := func(base string) pathClaim { return pathClaim{match: MatchSegment, base: base} }
	subtree := func(base string) pathClaim { return pathClaim{match: MatchSubtree, base: base} }

	cases := []testCase{
		{"equal exact paths", exact("/a"), exact("/a"), true},
		{"different exact paths", exact("/a"), exact("/b"), false},
		{"an exact path one segment below a segment prefix", exact("/a/x"), segment("/a"), true},
		{"an exact path two segments below a segment prefix", exact("/a/x/y"), segment("/a"), false},
		{"an exact path equal to a segment prefix", exact("/a"), segment("/a"), false},
		{"an exact path under a subtree", exact("/a/x/y"), subtree("/a"), true},
		{"an exact path beside a subtree", exact("/ab"), subtree("/a"), false},
		{"two segments on one prefix", segment("/a"), segment("/a"), true},
		{"two segments on different prefixes", segment("/a"), segment("/a/b"), false},
		{"a segment under a subtree", segment("/a/b"), subtree("/a"), true},
		{"a subtree rooted one segment below a segment prefix", segment("/a"), subtree("/a/x"), true},
		{"a subtree rooted two segments below a segment prefix", segment("/a"), subtree("/a/x/y"), false},
		{"a subtree rooted beside a segment prefix", segment("/a"), subtree("/b"), false},
		{"nested subtrees", subtree("/a"), subtree("/a/b"), true},
		{"separate subtrees", subtree("/a"), subtree("/ab"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, claimsMeet(tc.a, tc.b), "in the order given")
			assert.Equal(t, tc.want, claimsMeet(tc.b, tc.a), "in the other order")
		})
	}
}
