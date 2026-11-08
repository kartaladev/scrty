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
		return op(id, path, MatchExact, OtherMethodsPassThrough, methods...)
	}
	segment := func(id string, methods ...string) Endpoint {
		return op(id, path+"/{name}", MatchSegment, OtherMethodsPassThrough, methods...)
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
			b: sharedOf("EnableA", op("scrty.b", path+"/{rest...}", MatchSubtree, OtherMethodsPassThrough,
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
			b:      op("scrty.b", "/elsewhere", MatchExact, OtherMethodsPassThrough, http.MethodGet),
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
		name   string
		a, b   pathClaim
		assert func(t *testing.T, met bool)
	}

	exact := func(base string) pathClaim { return pathClaim{match: MatchExact, base: base} }
	segment := func(base string) pathClaim { return pathClaim{match: MatchSegment, base: base} }
	subtree := func(base string) pathClaim { return pathClaim{match: MatchSubtree, base: base} }

	cases := []testCase{
		{"equal exact paths", exact("/a"), exact("/a"), func(t *testing.T, met bool) { assert.True(t, met, "equal exact paths") }},
		{"different exact paths", exact("/a"), exact("/b"), func(t *testing.T, met bool) { assert.False(t, met, "different exact paths") }},
		{"an exact path one segment below a segment prefix", exact("/a/x"), segment("/a"), func(t *testing.T, met bool) { assert.True(t, met, "an exact path one segment below a segment prefix") }},
		{"an exact path two segments below a segment prefix", exact("/a/x/y"), segment("/a"), func(t *testing.T, met bool) {
			assert.False(t, met, "an exact path two segments below a segment prefix")
		}},
		{"an exact path equal to a segment prefix", exact("/a"), segment("/a"), func(t *testing.T, met bool) { assert.False(t, met, "an exact path equal to a segment prefix") }},
		{"an exact path under a subtree", exact("/a/x/y"), subtree("/a"), func(t *testing.T, met bool) { assert.True(t, met, "an exact path under a subtree") }},
		{"an exact path beside a subtree", exact("/ab"), subtree("/a"), func(t *testing.T, met bool) { assert.False(t, met, "an exact path beside a subtree") }},
		{"two segments on one prefix", segment("/a"), segment("/a"), func(t *testing.T, met bool) { assert.True(t, met, "two segments on one prefix") }},
		{"two segments on different prefixes", segment("/a"), segment("/a/b"), func(t *testing.T, met bool) { assert.False(t, met, "two segments on different prefixes") }},
		{"a segment under a subtree", segment("/a/b"), subtree("/a"), func(t *testing.T, met bool) { assert.True(t, met, "a segment under a subtree") }},
		{"a subtree rooted one segment below a segment prefix", segment("/a"), subtree("/a/x"), func(t *testing.T, met bool) {
			assert.True(t, met, "a subtree rooted one segment below a segment prefix")
		}},
		{"a subtree rooted two segments below a segment prefix", segment("/a"), subtree("/a/x/y"), func(t *testing.T, met bool) {
			assert.False(t, met, "a subtree rooted two segments below a segment prefix")
		}},
		{"a subtree rooted beside a segment prefix", segment("/a"), subtree("/b"), func(t *testing.T, met bool) { assert.False(t, met, "a subtree rooted beside a segment prefix") }},
		{"nested subtrees", subtree("/a"), subtree("/a/b"), func(t *testing.T, met bool) { assert.True(t, met, "nested subtrees") }},
		{"separate subtrees", subtree("/a"), subtree("/ab"), func(t *testing.T, met bool) { assert.False(t, met, "separate subtrees") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, claimsMeet(tc.a, tc.b))
			tc.assert(t, claimsMeet(tc.b, tc.a))
		})
	}
}

// TestOneSegmentBelow pins the one-segment match every segment endpoint, the
// collision check and the stale-route check share: the prefix followed by
// exactly one non-empty segment, compared case-sensitively.
func TestOneSegmentBelow(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		path   string
		assert func(t *testing.T, segment string, ok bool)
	}

	refused := func(t *testing.T, segment string, ok bool) {
		t.Helper()
		assert.False(t, ok, "not one segment below the prefix")
		assert.Empty(t, segment)
	}

	cases := []testCase{
		{name: "the bare prefix", path: "/sessions", assert: refused},
		{name: "the prefix with a trailing slash", path: "/sessions/", assert: refused},
		{name: "an empty segment before another", path: "/sessions//x", assert: refused},
		{name: "a deeper path", path: "/sessions/a/b", assert: refused},
		{name: "one segment and a trailing slash", path: "/sessions/a/", assert: refused},
		{name: "a near-miss prefix", path: "/sessionsX/a", assert: refused},
		{name: "the prefix in another case", path: "/Sessions/a", assert: refused},
		{name: "an unrelated path", path: "/other/a", assert: refused},
		{name: "one segment", path: "/sessions/a", assert: func(t *testing.T, segment string, ok bool) {
			require.True(t, ok, "one segment below the prefix")
			assert.Equal(t, "a", segment)
		}},
		{name: "one segment keeps its case", path: "/sessions/A", assert: func(t *testing.T, segment string, ok bool) {
			require.True(t, ok, "one segment below the prefix")
			assert.Equal(t, "A", segment)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			segment, ok := oneSegmentBelow(tc.path, "/sessions")
			tc.assert(t, segment, ok)
		})
	}
}
