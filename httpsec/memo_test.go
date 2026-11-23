package httpsec_test

import (
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

// memoRequest puts one authenticated request through a session-bearer chain
// onto a route guarded by a privilege guard, whose handler makes nine more
// checks on the same resource, and returns what the chain answered.
func memoRequest(t *testing.T, roles *countingRoles, f resolveFixture, users identity.UserLoader, opts ...httpsec.Option) (*httptest.ResponseRecorder, error) {
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

	rec := httptest.NewRecorder()
	req := bearerRequest(t.Context(), "Bearer "+f.session.ID)

	route := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 9 {
			if _, err := authorize.HeldPrivileges(r.Context(), "crm", "lead", "read"); err != nil {
				w.WriteHeader(http.StatusInternalServerError)

				return
			}
		}
	})

	guarded := guards.ResourcePrivileges("crm", "lead").RequireOne("read")(route)

	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		guarded.ServeHTTP(rec, req.WithContext(ex.Context()))

		return nil
	})

	err = run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(rec)))

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
		assert   func(t *testing.T, loads int64)
	}

	cases := []testCase{
		{
			name:     "one request loads once",
			requests: 1,
			assert:   func(t *testing.T, loads int64) { assert.EqualValues(t, 1, loads) },
		},
		{
			name:     "a second request loads once more and not from the first's memo",
			requests: 2,
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

			for range tc.requests {
				rec, err := memoRequest(t, roles, f, users, tc.opts...)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
			}

			tc.assert(t, roles.calls.Load())
		})
	}
}
