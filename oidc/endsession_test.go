package oidc_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/session"
)

func TestEndSessionURL(t *testing.T) {
	t.Parallel()

	const (
		hint     = "eyJhbGciOiJSUzI1NiJ9.hint-payload.hint-signature"
		redirect = "https://app.example/bye"
		pinned   = "https://idp.example/end-session?tenant=a"

		// staleRedirect, staleIDTokenHint and staleState each pin an endpoint
		// that already carries, in its own query, the same parameter
		// EndSessionURL would otherwise add. Since none is configured for
		// these cases, the endpoint's own stale value must be removed, not
		// merely left unset.
		staleRedirect    = "https://idp.example/end?post_logout_redirect_uri=https%3A%2F%2Fother.example%2F"
		staleIDTokenHint = "https://idp.example/end?id_token_hint=stale-hint-value" //nolint:gosec // G101: a URL fixture proving a stale query value is removed, not a credential
		staleState       = "https://idp.example/end?state=stale-state-value"
	)

	// env holds two providers: p discovers an end-session endpoint (and backs
	// the "pinned" registration, which pins its own), q discovers none.
	type env struct {
		p, q *testProvider
	}

	type testCase struct {
		name   string
		opts   []oidc.ManagerOption
		setup  func(e env)
		act    func(ctx context.Context, m *oidc.Manager) (string, error)
		assert func(t *testing.T, e env, got string, err error)
	}

	direct := func(provider, idToken, state string) func(context.Context, *oidc.Manager) (string, error) {
		return func(ctx context.Context, m *oidc.Manager) (string, error) {
			return m.EndSessionURL(ctx, provider, idToken, state)
		}
	}
	viaSession := func(s *session.Session, state string) func(context.Context, *oidc.Manager) (string, error) {
		return func(ctx context.Context, m *oidc.Manager) (string, error) {
			return m.EndSessionBuilder().EndSessionURL(ctx, s, state)
		}
	}
	// targets requires got to address endpoint with exactly the given query.
	targets := func(endpoint func(e env) string, query url.Values) func(*testing.T, env, string, error) {
		return func(t *testing.T, e env, got string, err error) {
			t.Helper()
			require.NoError(t, err)
			u, err := url.Parse(got)
			require.NoError(t, err)
			want, err := url.Parse(endpoint(e))
			require.NoError(t, err)
			assert.Equal(t, want.Scheme, u.Scheme)
			assert.Equal(t, want.Host, u.Host)
			assert.Equal(t, want.Path, u.Path)
			assert.Equal(t, query, u.Query())
		}
	}
	discovered := func(e env) string { return e.p.Issuer() + "/logout" }
	noURL := func(t *testing.T, _ env, got string, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Empty(t, got)
	}

	cases := []testCase{
		{name: "with an endpoint and a redirect",
			opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect(redirect)},
			act:  direct("corp", hint, "xyz"),
			assert: targets(discovered, url.Values{
				"client_id":                {"client-corp"},
				"id_token_hint":            {hint},
				"post_logout_redirect_uri": {redirect},
				"state":                    {"xyz"},
			})},
		{name: "no redirect configured omits the parameter",
			act: direct("corp", hint, "xyz"),
			assert: targets(discovered, url.Values{
				"client_id": {"client-corp"}, "id_token_hint": {hint}, "state": {"xyz"},
			})},
		{name: "an empty state is omitted",
			opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect(redirect)},
			act:  direct("corp", hint, ""),
			assert: targets(discovered, url.Values{
				"client_id": {"client-corp"}, "id_token_hint": {hint}, "post_logout_redirect_uri": {redirect},
			})},
		{name: "an empty ID token hint is omitted",
			act:    direct("corp", "", ""),
			assert: targets(discovered, url.Values{"client_id": {"client-corp"}})},
		{name: "an endpoint's own post_logout_redirect_uri is not sent when none is configured",
			act: direct("stale-redirect", hint, ""),
			assert: targets(func(env) string { return "https://idp.example/end" }, url.Values{
				"client_id": {"client-stale-redirect"}, "id_token_hint": {hint},
			})},
		{name: "an endpoint's own id_token_hint is not sent when none is configured",
			act: direct("stale-id-token-hint", "", ""),
			assert: targets(func(env) string { return "https://idp.example/end" }, url.Values{
				"client_id": {"client-stale-id-token-hint"},
			})},
		{name: "an endpoint's own state is not sent when none is configured",
			act: direct("stale-state", hint, ""),
			assert: targets(func(env) string { return "https://idp.example/end" }, url.Values{
				"client_id": {"client-stale-state"}, "id_token_hint": {hint},
			})},
		{name: "a pinned endpoint wins without discovery and keeps its own query",
			act: direct("pinned", hint, ""),
			assert: func(t *testing.T, e env, got string, err error) {
				targets(func(env) string { return pinned }, url.Values{
					"tenant": {"a"}, "client_id": {"client-pinned"}, "id_token_hint": {hint},
				})(t, e, got, err)
				assert.Zero(t, e.p.discoveryCalls.Load(), "a pinned end-session endpoint needs no discovery")
			}},
		{name: "no end-session endpoint yields no URL and no error",
			act:    direct("bare", hint, "xyz"),
			assert: noURL},
		{name: "an unknown provider yields no URL and no error",
			act:    direct("removed", hint, "xyz"),
			assert: noURL},
		{name: "a discovery failure is a provider failure that never repeats the ID token",
			setup: func(e env) { e.p.failDiscovery.Store(true) },
			act:   direct("corp", hint, "xyz"),
			assert: func(t *testing.T, _ env, got string, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.NotContains(t, err.Error(), "hint-payload")
				assert.Empty(t, got)
			}},
		{name: "the session adapter reads the session's provider and token",
			opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect(redirect)},
			act:  viaSession(&session.Session{ExternalProvider: "corp", ExternalIDToken: hint}, "xyz"),
			assert: targets(discovered, url.Values{
				"client_id":                {"client-corp"},
				"id_token_hint":            {hint},
				"post_logout_redirect_uri": {redirect},
				"state":                    {"xyz"},
			})},
		{name: "the session adapter gives no URL for a session that records no provider",
			act:    viaSession(&session.Session{ID: "local"}, "xyz"),
			assert: noURL},
		{name: "the session adapter gives no URL for a provider since removed",
			act:    viaSession(&session.Session{ExternalProvider: "removed", ExternalIDToken: hint}, "xyz"),
			assert: noURL},
		{name: "the session adapter gives no URL for a nil session",
			act:    viaSession(nil, "xyz"),
			assert: noURL},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := env{p: newTestProvider(t), q: newTestProvider(t)}
			e.q.discoveryBody.Store(`{"issuer":"` + e.q.Issuer() + `",` +
				`"authorization_endpoint":"` + e.q.Issuer() + `/authorize",` +
				`"token_endpoint":"` + e.q.Issuer() + `/token",` +
				`"jwks_uri":"` + e.q.Issuer() + `/jwks"}`)
			if tc.setup != nil {
				tc.setup(e)
			}
			pin := e.p.Provider("pinned")
			pin.EndSessionEndpoint = pinned
			staleRedirectProvider := e.p.Provider("stale-redirect")
			staleRedirectProvider.EndSessionEndpoint = staleRedirect
			staleIDTokenHintProvider := e.p.Provider("stale-id-token-hint")
			staleIDTokenHintProvider.EndSessionEndpoint = staleIDTokenHint
			staleStateProvider := e.p.Provider("stale-state")
			staleStateProvider.EndSessionEndpoint = staleState
			reg, err := oidc.NewRegistry(e.p.Provider("corp"), pin, e.q.Provider("bare"),
				staleRedirectProvider, staleIDTokenHintProvider, staleStateProvider)
			require.NoError(t, err)

			opts := append([]oidc.ManagerOption{
				oidc.WithOutboundClient(inMemoryOutbound(t, e.p, e.q)),
			}, tc.opts...)
			m, err := oidc.NewManager(reg, stubBroker{}, opts...)
			require.NoError(t, err)

			got, err := tc.act(t.Context(), m)
			tc.assert(t, e, got, err)
		})
	}

	t.Run("construction", func(t *testing.T) {
		t.Parallel()

		p := newTestProvider(t)
		reg, err := oidc.NewRegistry(p.Provider("corp"))
		require.NoError(t, err)
		allowHTTP, err := outbound.New(outbound.WithAllowedSchemes("http"))
		require.NoError(t, err)

		type constructionCase struct {
			name   string
			opts   []oidc.ManagerOption
			assert func(t *testing.T, m *oidc.Manager, err error)
		}
		refused := func(t *testing.T, m *oidc.Manager, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Contains(t, err.Error(), "WithPostLogoutRedirect")
			assert.NotContains(t, err.Error(), "s3cr3t", "user information is never repeated")
			assert.Nil(t, m)
		}
		built := func(t *testing.T, m *oidc.Manager, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.NotNil(t, m)
		}

		cases := []constructionCase{
			{name: "an absolute https redirect is accepted",
				opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect(redirect)}, assert: built},
			{name: "an http redirect is refused with the default client",
				opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect("http://app.example/bye")}, assert: refused},
			{name: "an http redirect is accepted with a client allowing http",
				opts: []oidc.ManagerOption{
					oidc.WithPostLogoutRedirect("http://localhost:3000/bye"), oidc.WithOutboundClient(allowHTTP),
				},
				assert: built},
			{name: "a redirect with user information is refused",
				opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect("https://user:s3cr3t@app.example/")}, assert: refused},
			{name: "a redirect with a user name only is refused",
				opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect("https://user@app.example/")}, assert: refused},
			{name: "a relative redirect is refused",
				opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect("/bye")}, assert: refused},
			{name: "a redirect with no host is refused",
				opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect("https:///bye")}, assert: refused},
			{name: "an empty redirect is refused",
				opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect("")}, assert: refused},
			{name: "an unparsable redirect is refused",
				opts: []oidc.ManagerOption{oidc.WithPostLogoutRedirect("https://app.example/%zz")}, assert: refused},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				m, err := oidc.NewManager(reg, stubBroker{}, tc.opts...)
				tc.assert(t, m, err)
			})
		}
	})
}
