package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// memoRig is one session-bearer chain, built once, and the guard it puts on
// its route. Every request a test serves goes through the same chain, so a
// memo kept on the chain instead of on the request would show.
type memoRig struct {
	chain  *httpsec.Chain
	guards *httpsec.Guards
	f      resolveFixture

	// inner, when set, is a request the route's handler serves through the
	// same chain again, from the request's own context, as a request forwarded
	// in-process to another path would be: the chain passes a request it is
	// already running on straight on, and runs a forward in full.
	inner bool
}

func newMemoRig(t *testing.T, roles *countingRoles, f resolveFixture, users identity.UserLoader, opts ...httpsec.Option) *memoRig {
	t.Helper()

	az, err := authorize.NewPrivilegeAuthorizer(roles)
	require.NoError(t, err)

	permitAll := authorize.Rule[httpsec.Request]{
		Match:   func(httpsec.Request) bool { return true },
		Require: authorize.PermitAll(),
	}

	all := append([]httpsec.Option{
		httpsec.WithClock(f.clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: f.sessions, Users: users}),
		httpsec.EnableAuthorization(az, permitAll),
	}, opts...)

	chain, err := httpsec.New(all...)
	require.NoError(t, err)

	guards, err := httpsec.NewGuards(nil, httpsec.WithChainAuthorizer())
	require.NoError(t, err)

	return &memoRig{chain: chain, guards: guards, f: f}
}

// serve puts one authenticated request through the rig's chain onto a route
// guarded by a privilege guard, whose handler makes nine more checks on the
// same resource (and, for a rig with inner set, serves one more request the
// same way), and returns what the chain answered.
func (g *memoRig) serve(ctx context.Context, t *testing.T, path string) (*httptest.ResponseRecorder, error) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+g.f.session.ID)

	route := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 9 {
			if _, err := authorize.HeldPrivileges(r.Context(), "crm", "lead", "read"); err != nil {
				w.WriteHeader(http.StatusInternalServerError)

				return
			}
		}
	})

	guarded := g.guards.ResourcePrivileges("crm", "lead").RequireOne("read")

	//nolint:contextcheck // the forwarded request takes the context of the request it is forwarded from, which the handler holds as r.
	run := g.chain.Assemble(func(ex *httpsec.Exchange) error {
		inner := route

		if g.inner {
			inner = func(w http.ResponseWriter, r *http.Request) {
				route(w, r)

				g.inner = false
				innerRec, err := g.serve(r.Context(), t, "/forwarded")
				g.inner = true

				if err != nil || innerRec.Code != http.StatusOK {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
		}

		guarded(inner).ServeHTTP(rec, req.WithContext(ex.Context()))

		return nil
	})

	err := run(httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(rec)))

	return rec, err
}

// TestChain_PrivilegeMemoPerRequest pins that the chain attaches a new
// privilege memo to every request it authenticates, that one request's memo is
// never another's, and that a consumer can turn the memo off.
func TestChain_PrivilegeMemoPerRequest(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		opts     []httpsec.Option
		requests int
		nested   bool
		assert   func(t *testing.T, loads int64)
	}

	cases := []testCase{
		{
			name:     "one request loads once",
			requests: 1,
			assert:   func(t *testing.T, loads int64) { assert.EqualValues(t, 1, loads) },
		},
		{
			name:     "a second request through the same chain loads once more and not from the first's memo",
			requests: 2,
			assert:   func(t *testing.T, loads int64) { assert.EqualValues(t, 2, loads) },
		},
		{
			name:     "a request served from inside another through the same chain gets a memo of its own",
			requests: 1,
			nested:   true,
			assert:   func(t *testing.T, loads int64) { assert.EqualValues(t, 2, loads) },
		},
		{
			name:     "with the memo turned off every check loads",
			opts:     []httpsec.Option{httpsec.WithoutPrivilegeMemo()},
			requests: 1,
			assert:   func(t *testing.T, loads int64) { assert.EqualValues(t, 10, loads) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)
			roles := &countingRoles{grant: []*identity.ResourcePrivileges{readOn("crm", "lead")}}

			users := NewMockUserLoader(gomock.NewController(t))
			details := storedUser()
			details.Roles = []*identity.AssignedRole{{ID: "r-sales", Name: "sales", Primary: true}}
			users.EXPECT().LoadByUserID(gomock.Any(), testUserID).Return(details, nil).AnyTimes()

			rig := newMemoRig(t, roles, f, users, tc.opts...)
			rig.inner = tc.nested

			for range tc.requests {
				rec, err := rig.serve(t.Context(), t, "/orders")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			}

			tc.assert(t, roles.calls.Load())
		})
	}
}
