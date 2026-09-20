package authorize_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
)

// consumerRequest stands in for the request type a consumer instantiates the
// rule set with. It is deliberately not an HTTP request: the rule set must work
// for a type it knows nothing about, and matching on a path is something the
// consumer's own matcher does, not something the library understands.
type consumerRequest struct {
	path   string
	method string
}

// underPath is the kind of matcher a consumer writes. The rule set never sees
// what it looks at.
func underPath(prefix string) func(consumerRequest) bool {
	return func(r consumerRequest) bool { return strings.HasPrefix(r.path, prefix) }
}

// anyRequest matches everything, which is what a deliberate trailing rule does.
func anyRequest() func(consumerRequest) bool {
	return func(consumerRequest) bool { return true }
}

func TestNewRules(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		rules  []authorize.Rule[consumerRequest]
		assert func(t *testing.T, rules *authorize.Rules[consumerRequest], err error)
	}

	configError := func(t *testing.T, rules *authorize.Rules[consumerRequest], err error) {
		require.ErrorIs(t, err, authorize.ErrConfig)
		assert.Nil(t, rules, "a refused configuration still produced a rule set")
	}

	cases := []testCase{
		{
			name: "a complete rule is accepted",
			rules: []authorize.Rule[consumerRequest]{
				{Match: underPath("/admin/"), Require: authorize.Authenticated()},
			},
			assert: func(t *testing.T, rules *authorize.Rules[consumerRequest], err error) {
				require.NoError(t, err)
				assert.NotNil(t, rules)
			},
		},
		{
			// An empty set is a configuration, not a mistake: it says no
			// decision is made centrally.
			name: "no rules at all is accepted",
			assert: func(t *testing.T, rules *authorize.Rules[consumerRequest], err error) {
				require.NoError(t, err)
				assert.NotNil(t, rules)
			},
		},
		{
			name: "a rule with no matcher is a configuration error",
			rules: []authorize.Rule[consumerRequest]{
				{Require: authorize.DenyAll()},
			},
			assert: configError,
		},
		{
			name: "a rule with no requirement is a configuration error",
			rules: []authorize.Rule[consumerRequest]{
				{Match: underPath("/admin/")},
			},
			assert: configError,
		},
		{
			name: "a later half-built rule is refused too",
			rules: []authorize.Rule[consumerRequest]{
				{Match: underPath("/admin/"), Require: authorize.DenyAll()},
				{Match: anyRequest()},
			},
			assert: configError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rules, err := authorize.NewRules(tc.rules...)
			tc.assert(t, rules, err)
		})
	}
}

func TestRulesEvaluate(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		rules   func(t *testing.T) []authorize.Rule[consumerRequest]
		request consumerRequest
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, err error)
	}

	fixed := func(rules ...authorize.Rule[consumerRequest]) func(*testing.T) []authorize.Rule[consumerRequest] {
		return func(*testing.T) []authorize.Rule[consumerRequest] { return rules }
	}

	denied := func(t *testing.T, err error) { require.ErrorIs(t, err, authorize.ErrAccessDenied) }
	allowed := func(t *testing.T, err error) { require.NoError(t, err) }

	// laterMatcherCalls counts matchers consulted after a rule has matched.
	// Only the first-match case touches it.
	laterMatcherCalls := 0

	cases := []testCase{
		{
			name: "the first matching rule decides, later matches are not consulted",
			rules: func(*testing.T) []authorize.Rule[consumerRequest] {
				return []authorize.Rule[consumerRequest]{
					{Match: underPath("/admin/"), Require: authorize.HasAnyRole("admin")},
					{
						Match: func(consumerRequest) bool {
							laterMatcherCalls++

							return true
						},
						Require: authorize.PermitAll(),
					},
				}
			},
			request: consumerRequest{path: "/admin/users", method: "GET"},
			ctx: func(ctx context.Context) context.Context {
				return withRole(ctx, "viewer")
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied)
				assert.Zero(t, laterMatcherCalls,
					"a permissive rule behind the deciding one was consulted anyway")
			},
		},
		{
			name: "a rule that does not match is passed over",
			rules: fixed(
				authorize.Rule[consumerRequest]{Match: underPath("/admin/"), Require: authorize.DenyAll()},
				authorize.Rule[consumerRequest]{Match: underPath("/health"), Require: authorize.PermitAll()},
			),
			request: consumerRequest{path: "/health"},
			assert:  allowed,
		},
		{
			name: "a non-empty set with no match denies",
			rules: fixed(
				authorize.Rule[consumerRequest]{Match: underPath("/api/"), Require: authorize.PermitAll()},
			),
			request: consumerRequest{path: "/health"},
			assert:  denied,
		},
		{
			name:    "an empty set makes no central decision",
			rules:   fixed(),
			request: consumerRequest{path: "/health"},
			assert: func(t *testing.T, err error) {
				require.NoError(t, err, "an empty set must leave the decision to per-endpoint guards")
			},
		},
		{
			name: "a trailing permit-all rule is the documented override for the deny default",
			rules: fixed(
				authorize.Rule[consumerRequest]{Match: underPath("/admin/"), Require: authorize.HasAnyRole("admin")},
				authorize.Rule[consumerRequest]{Match: anyRequest(), Require: authorize.PermitAll()},
			),
			request: consumerRequest{path: "/health"},
			assert:  allowed,
		},
		{
			name: "a matcher may read anything the consumer's request carries",
			rules: fixed(
				authorize.Rule[consumerRequest]{
					Match:   func(r consumerRequest) bool { return r.method == "DELETE" },
					Require: authorize.DenyAll(),
				},
				authorize.Rule[consumerRequest]{Match: anyRequest(), Require: authorize.PermitAll()},
			),
			request: consumerRequest{path: "/api/orders/1", method: "DELETE"},
			assert:  denied,
		},
		{
			name: "the anonymous sentinel from the deciding rule survives",
			rules: fixed(
				authorize.Rule[consumerRequest]{Match: underPath("/admin/"), Require: authorize.Authenticated()},
			),
			request: consumerRequest{path: "/admin/users"},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAuthenticationRequired)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
					"an anonymous caller was refused outright by the rule set")
			},
		},
		{
			name: "a requirement's own error is returned unchanged",
			rules: fixed(
				authorize.Rule[consumerRequest]{
					Match:   anyRequest(),
					Require: func(context.Context) error { return errBackendDown },
				},
			),
			request: consumerRequest{path: "/api/orders"},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errBackendDown)
				assert.NotErrorIs(t, err, authorize.ErrAccessDenied,
					"an outage inside a requirement was rewritten as a denial")
			},
		},
		{
			name: "the deciding requirement is given the caller's context",
			rules: fixed(
				authorize.Rule[consumerRequest]{
					Match:   anyRequest(),
					Require: func(ctx context.Context) error { return ctx.Err() },
				},
			),
			request: consumerRequest{path: "/api/orders"},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, context.Canceled,
					"the rule set substituted a context of its own")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rules, err := authorize.NewRules(tc.rules(t)...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			tc.assert(t, rules.Evaluate(ctx, tc.request))
		})
	}
}

func TestRulesHoldTheirOwnSlice(t *testing.T) {
	t.Parallel()

	rules := []authorize.Rule[consumerRequest]{
		{Match: anyRequest(), Require: authorize.DenyAll()},
	}

	set, err := authorize.NewRules(rules...)
	require.NoError(t, err)

	// A caller reusing its slice must not be able to replace a rule that was
	// already checked at construction, which is how a half-built rule would
	// reach evaluation after having been refused there.
	rules[0] = authorize.Rule[consumerRequest]{}

	require.ErrorIs(t, set.Evaluate(t.Context(), consumerRequest{path: "/health"}),
		authorize.ErrAccessDenied)
}

func TestRulesInstantiateOverAnyRequestType(t *testing.T) {
	t.Parallel()

	// The request type carries no method, no field and no shape this package
	// knows: whatever a consumer's transport hands them is what the rule set
	// matches over.
	paths, err := authorize.NewRules(
		authorize.Rule[string]{
			Match:   func(path string) bool { return path == "/health" },
			Require: authorize.PermitAll(),
		},
	)
	require.NoError(t, err)
	require.NoError(t, paths.Evaluate(t.Context(), "/health"))
	require.ErrorIs(t, paths.Evaluate(t.Context(), "/admin"), authorize.ErrAccessDenied)

	type command struct {
		verb    string
		subject identity.UserID
	}

	commands, err := authorize.NewRules(
		authorize.Rule[command]{
			Match:   func(c command) bool { return c.verb == "delete" },
			Require: authorize.DenyAll(),
		},
	)
	require.NoError(t, err)
	require.ErrorIs(t, commands.Evaluate(t.Context(), command{verb: "delete", subject: "u-1"}),
		authorize.ErrAccessDenied)
}
