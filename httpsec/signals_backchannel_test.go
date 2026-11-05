package httpsec_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// TestSessionSignals_Backchannel is a provider's logout through the real logout-token endpoint, and the
// reason the wire then carries. Scope-all ends password sign-ins too, so it says all_ended; a logout
// that names one upstream session, and the default scope, say provider_logout.
func TestSessionSignals_Backchannel(t *testing.T) {
	t.Parallel()

	const upstream = "abc"

	type testCase struct {
		name     string
		scopeAll bool
		sid      string

		// password opens the stream on a sign-in with no upstream session, in place of the federated one.
		password bool
		assert   func(t *testing.T, data string)
	}

	says := func(reason string) func(*testing.T, string) {
		return func(t *testing.T, data string) {
			t.Helper()

			assert.JSONEq(t, `{"reason":"`+reason+`"}`, data)
		}
	}

	cases := []testCase{
		{name: "the default scope, subject only", assert: says("provider_logout")},
		{name: "the default scope, naming a sid", sid: upstream, assert: says("provider_logout")},
		{name: "scope-all, subject only", scopeAll: true, assert: says("all_ended")},
		{name: "scope-all ends a password sign-in too", scopeAll: true, password: true, assert: says("all_ended")},
		{name: "scope-all, naming a sid", scopeAll: true, sid: upstream, assert: says("provider_logout")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newBackchannelHarness(t)

			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(
				&identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil)

			h.chainOpts = append(h.chainOpts,
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: users}),
				httpsec.EnableSessionSignals(httpsec.SessionSignals{Users: users}))

			opts := []httpsec.OIDCOption{httpsec.WithOIDCSessions(h.sessions)}
			if tc.scopeAll {
				opts = append(opts, httpsec.WithOIDCBackchannelLogoutScope(httpsec.BackchannelLogoutScopeAll))
			}

			h.chain = h.build(t, h.handoffs, opts...)

			h.federated(t, "fed", testOIDCProvider, h.issuer(), upstream)

			credential := h.ids["fed"]

			if tc.password {
				s, err := h.sessions.Create(t.Context(), oidcTestUserID, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				credential = s.ID
			}

			srv := httptest.NewServer(h.chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTeapot)
			})))
			t.Cleanup(srv.Close)

			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			t.Cleanup(cancel)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+httpsec.DefaultSessionSignalsPath, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+credential)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })
			require.Equal(t, http.StatusOK, resp.StatusCode)

			lines := bufio.NewScanner(resp.Body)

			for lines.Scan() && lines.Text() != "event: session" { //nolint:revive // reading up to the opening event is the whole loop
			}

			out := h.post(t, h.provider.logoutToken(t, oidcTestSubject, tc.sid))
			require.NoError(t, out.err)

			for lines.Scan() {
				if lines.Text() == "event: session_ended" {
					require.True(t, lines.Scan())
					tc.assert(t, strings.TrimPrefix(lines.Text(), "data: "))

					return
				}
			}

			require.FailNow(t, "no session_ended", "%v", lines.Err())
		})
	}
}

// TestSessionSignals_Construction_ChainLogoutSaysLogout is the chain's own logout on the wire: a tab
// other than the one that logged out still hears logout, whatever a deleted session now says.
func TestSessionSignals_Construction_ChainLogoutSaysLogout(t *testing.T) {
	t.Parallel()

	f := newSignalsFixture(t, signalsSetup{opts: func(f *signalsFixture) []httpsec.Option {
		return []httpsec.Option{httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions})}
	}})

	s := f.signIn(t, "u-1")

	resp, _ := f.openStream(t, s.ID)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	lines := bufio.NewScanner(resp.Body)

	for lines.Scan() && lines.Text() != "event: session" { //nolint:revive // reading up to the opening event is the whole loop
	}

	logout := f.send(t.Context(), t, http.MethodPost, httpsec.DefaultLogoutPath, s.ID)
	require.Equal(t, http.StatusOK, logout.StatusCode)

	for lines.Scan() {
		if lines.Text() == "event: session_ended" {
			require.True(t, lines.Scan())
			assert.JSONEq(t, `{"reason":"logout"}`, strings.TrimPrefix(lines.Text(), "data: "))

			return
		}
	}

	require.FailNow(t, "no session_ended", "%v", lines.Err())
}
