package oidc_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/outbound"
	"github.com/kartaladev/scrty/session"
)

// backchannelEvent is the member of events that names a back-channel logout.
const backchannelEvent = oidc.BackchannelLogoutEvent

func TestVerifyLogoutToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	// valid returns the claims of a logout token corp would accept at now,
	// naming both a subject and a provider session.
	valid := func(p *testProvider) map[string]any {
		return map[string]any{
			"iss":    p.Issuer(),
			"aud":    "client-corp",
			"iat":    now.Unix(),
			"jti":    "logout-jti-1",
			"sub":    "subject-1",
			"sid":    "provider-session",
			"events": map[string]any{backchannelEvent: map[string]any{}},
		}
	}
	with := func(claims map[string]any, kv ...any) map[string]any {
		for i := 0; i < len(kv); i += 2 {
			k := kv[i].(string)
			if kv[i+1] == nil {
				delete(claims, k)
				continue
			}
			claims[k] = kv[i+1]
		}
		return claims
	}
	signed := func(edit func(p *testProvider, c map[string]any) map[string]any, opts ...signOption) func(*testing.T, *testProvider) string {
		return func(t *testing.T, p *testProvider) string {
			c := valid(p)
			if edit != nil {
				c = edit(p, c)
			}
			return p.Sign(t, c, opts...)
		}
	}
	claimsEdit := func(kv ...any) func(*testProvider, map[string]any) map[string]any {
		return func(_ *testProvider, c map[string]any) map[string]any { return with(c, kv...) }
	}

	type testCase struct {
		name     string
		provider string
		opts     []oidc.Option
		setup    func(p *testProvider)
		before   func(t *testing.T, m *oidc.RelyingParty, raw string)
		token    func(t *testing.T, p *testProvider) string
		ctx      func(ctx context.Context) context.Context
		assert   func(t *testing.T, p *testProvider, got oidc.LogoutClaims, err error)
	}

	invalid := func(t *testing.T, got oidc.LogoutClaims, err error) {
		t.Helper()
		require.ErrorIs(t, err, oidc.ErrInvalidLogoutToken)
		assert.NotErrorIs(t, err, oidc.ErrDiscoveryFailed)
		assert.NotErrorIs(t, err, oidc.ErrInvalidIDToken)
		assert.Equal(t, oidc.LogoutClaims{}, got)
	}
	// refusedFor is invalid, and also requires the cause to name rule and to
	// repeat none of the given claim values.
	refusedFor := func(rule string, values ...string) func(*testing.T, *testProvider, oidc.LogoutClaims, error) {
		return func(t *testing.T, _ *testProvider, got oidc.LogoutClaims, err error) {
			t.Helper()
			invalid(t, got, err)
			assert.Contains(t, err.Error(), rule)
			for _, v := range values {
				assert.NotContains(t, err.Error(), v)
			}
		}
	}
	accepted := func(sub, sid string) func(*testing.T, *testProvider, oidc.LogoutClaims, error) {
		return func(t *testing.T, p *testProvider, got oidc.LogoutClaims, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.Equal(t, oidc.LogoutClaims{
				Issuer: p.Issuer(), Subject: sub, SessionID: sid, JTI: "logout-jti-1",
			}, got)
		}
	}

	cases := []testCase{
		{name: "a token with a session id only is accepted",
			token:  signed(claimsEdit("sub", nil)),
			assert: accepted("", "provider-session")},
		{name: "a token with a subject only is accepted",
			token:  signed(claimsEdit("sid", nil)),
			assert: accepted("subject-1", "")},
		{name: "a token with both a subject and a session id is accepted",
			token:  signed(nil),
			assert: accepted("subject-1", "provider-session")},
		{name: "extra members in the event object are ignored",
			token: signed(claimsEdit("events", map[string]any{
				backchannelEvent:  map[string]any{"reason": "admin", "nested": map[string]any{"x": 1}},
				"urn:other:event": true,
			}, "custom", "ignored")),
			assert: accepted("subject-1", "provider-session")},
		{name: "a consumer max age of 10 minutes accepts a 5-minute-old token",
			opts:   []oidc.Option{oidc.WithLogoutTokenMaxAge(10 * time.Minute)},
			token:  signed(claimsEdit("iat", now.Add(-5*time.Minute).Unix())),
			assert: accepted("subject-1", "provider-session")},
		{name: "an unexpired exp is accepted",
			token:  signed(claimsEdit("exp", now.Add(time.Minute).Unix())),
			assert: accepted("subject-1", "provider-session")},
		{name: "an iat at the max age plus leeway is accepted",
			token:  signed(claimsEdit("iat", now.Add(-oidc.DefaultLogoutTokenMaxAge-oidc.DefaultClockSkew).Unix())),
			assert: accepted("subject-1", "provider-session")},
		{name: "an iat inside the leeway ahead of the clock is accepted",
			token:  signed(claimsEdit("iat", now.Add(oidc.DefaultClockSkew).Unix())),
			assert: accepted("subject-1", "provider-session")},
		{name: "the same token is accepted again inside the window, since no jti is recorded",
			before: func(t *testing.T, m *oidc.RelyingParty, raw string) {
				_, err := m.VerifyLogoutToken(t.Context(), "corp", raw)
				require.NoError(t, err)
			},
			token:  signed(claimsEdit("sid", nil)),
			assert: accepted("subject-1", "")},

		{name: "an ID token presented as a logout token is refused",
			token:  signed(claimsEdit("events", nil, "nonce", "flow-nonce", "exp", now.Add(5*time.Minute).Unix())),
			assert: refusedFor("", "flow-nonce")},
		{name: "a nonce is refused even beside the back-channel event",
			token:  signed(claimsEdit("nonce", "flow-nonce")),
			assert: refusedFor("carries a nonce", "flow-nonce")},
		{name: "a token issued 5 minutes ago is stale with the default max age",
			token:  signed(claimsEdit("iat", now.Add(-5*time.Minute).Unix())),
			assert: refusedFor("issued too long ago")},
		{name: "a replay after the max age plus leeway is refused",
			token:  signed(claimsEdit("iat", now.Add(-oidc.DefaultLogoutTokenMaxAge-oidc.DefaultClockSkew-time.Second).Unix())),
			assert: refusedFor("issued too long ago")},
		{name: "missing iat and exp is refused",
			token:  signed(claimsEdit("iat", nil)),
			assert: refusedFor("no issued-at")},
		{name: "missing iat is refused even with an unexpired exp",
			token:  signed(claimsEdit("iat", nil, "exp", now.Add(time.Minute).Unix())),
			assert: refusedFor("no issued-at")},
		{name: "an iat 5 minutes in the future is refused",
			token:  signed(claimsEdit("iat", now.Add(5*time.Minute).Unix())),
			assert: refusedFor("issued in the future")},
		{name: "an iat just past the leeway ahead of the clock is refused",
			token:  signed(claimsEdit("iat", now.Add(oidc.DefaultClockSkew+time.Second).Unix())),
			assert: refusedFor("issued in the future")},
		{name: "an expired exp is refused",
			token:  signed(claimsEdit("exp", now.Add(-2*time.Minute).Unix())),
			assert: refusedFor("the token has expired")},
		{name: "a missing jti is refused",
			token:  signed(claimsEdit("jti", nil)),
			assert: refusedFor("no jti")},
		{name: "an empty jti is refused",
			token:  signed(claimsEdit("jti", "")),
			assert: refusedFor("no jti")},
		{name: "a jti that is not a string is refused",
			token:  signed(claimsEdit("jti", 12345)),
			assert: refusedFor("", "12345")},
		{name: "a missing events claim is refused",
			token:  signed(claimsEdit("events", nil)),
			assert: refusedFor("no back-channel logout event")},
		{name: "events without the back-channel member is refused",
			token:  signed(claimsEdit("events", map[string]any{"urn:other:event": map[string]any{}})),
			assert: refusedFor("no back-channel logout event")},
		{name: "a back-channel member that is not an object is refused",
			token:  signed(claimsEdit("events", map[string]any{backchannelEvent: true})),
			assert: refusedFor("no back-channel logout event")},
		{name: "a null back-channel member is refused",
			token:  signed(claimsEdit("events", map[string]any{backchannelEvent: nil})),
			assert: refusedFor("no back-channel logout event")},
		{name: "an events claim that is not an object is refused",
			token:  signed(claimsEdit("events", []any{backchannelEvent})),
			assert: refusedFor("no back-channel logout event")},
		{name: "neither sub nor sid is refused",
			token:  signed(claimsEdit("sub", nil, "sid", nil)),
			assert: refusedFor("neither a subject nor a session id")},
		{name: "empty sub and sid are refused",
			token:  signed(claimsEdit("sub", "", "sid", "")),
			assert: refusedFor("neither a subject nor a session id")},
		{name: "a sub that is not a string is refused",
			token:  signed(claimsEdit("sub", 123456)),
			assert: refusedFor("", "123456")},
		{name: "a sid that is not a string is refused",
			token:  signed(claimsEdit("sub", nil, "sid", 987654)),
			assert: refusedFor("", "987654")},
		{name: "a wrong audience is refused",
			token:  signed(claimsEdit("aud", "other-client")),
			assert: refusedFor("audience does not name the client", "other-client")},
		{name: "a wrong issuer is refused",
			token:  signed(claimsEdit("iss", "https://evil.example")),
			assert: refusedFor("issuer is not the provider", "evil.example")},
		{name: "a signature by a key the provider does not hold is refused",
			token:  signed(nil, withKey(newRSAKey(t, "k1"))),
			assert: refusedFor("")},
		{name: "an unknown provider is refused as unknown",
			provider: "nobody",
			token:    signed(nil),
			assert: func(t *testing.T, _ *testProvider, got oidc.LogoutClaims, err error) {
				require.ErrorIs(t, err, oidc.ErrUnknownProvider)
				assert.NotErrorIs(t, err, oidc.ErrInvalidLogoutToken)
				assert.Equal(t, oidc.LogoutClaims{}, got)
			}},
		{name: "an unreachable key set is a provider failure",
			setup: func(p *testProvider) { p.failJWKS.Store(true) },
			token: signed(nil),
			assert: func(t *testing.T, _ *testProvider, got oidc.LogoutClaims, err error) {
				require.ErrorIs(t, err, oidc.ErrDiscoveryFailed)
				assert.NotErrorIs(t, err, oidc.ErrInvalidLogoutToken)
				assert.Equal(t, oidc.LogoutClaims{}, got)
			}},
		{name: "a canceled context is returned as itself",
			ctx: func(ctx context.Context) context.Context {
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				return ctx
			},
			token: signed(nil),
			assert: func(t *testing.T, _ *testProvider, got oidc.LogoutClaims, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, oidc.ErrInvalidLogoutToken)
				assert.Equal(t, oidc.LogoutClaims{}, got)
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTestProvider(t)
			if tc.setup != nil {
				tc.setup(p)
			}
			reg, err := oidc.NewRegistry(p.Provider("corp"))
			require.NoError(t, err)
			opts := append([]oidc.Option{
				oidc.WithOutboundClient(p.Outbound(t)),
				oidc.WithClock(clockwork.NewFakeClockAt(now)),
			}, tc.opts...)
			m, err := oidc.NewRelyingParty(reg, stubBroker{}, opts...)
			require.NoError(t, err)

			provider := tc.provider
			if provider == "" {
				provider = "corp"
			}
			raw := tc.token(t, p)
			if tc.before != nil {
				tc.before(t, m, raw)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			got, err := m.VerifyLogoutToken(ctx, provider, raw)
			tc.assert(t, p, got, err)
		})
	}
}

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
		opts   []oidc.Option
		setup  func(e env)
		act    func(ctx context.Context, m *oidc.RelyingParty) (string, error)
		assert func(t *testing.T, e env, got string, err error)
	}

	direct := func(provider, idToken, state string) func(context.Context, *oidc.RelyingParty) (string, error) {
		return func(ctx context.Context, m *oidc.RelyingParty) (string, error) {
			return m.EndSessionURL(ctx, provider, idToken, state)
		}
	}
	viaSession := func(s *session.Session, state string) func(context.Context, *oidc.RelyingParty) (string, error) {
		return func(ctx context.Context, m *oidc.RelyingParty) (string, error) {
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
			opts: []oidc.Option{oidc.WithPostLogoutRedirect(redirect)},
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
			opts: []oidc.Option{oidc.WithPostLogoutRedirect(redirect)},
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
			opts: []oidc.Option{oidc.WithPostLogoutRedirect(redirect)},
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

			opts := append([]oidc.Option{
				oidc.WithOutboundClient(inMemoryOutbound(t, e.p, e.q)),
			}, tc.opts...)
			m, err := oidc.NewRelyingParty(reg, stubBroker{}, opts...)
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
			opts   []oidc.Option
			assert func(t *testing.T, m *oidc.RelyingParty, err error)
		}
		refused := func(t *testing.T, m *oidc.RelyingParty, err error) {
			t.Helper()
			require.ErrorIs(t, err, oidc.ErrConfig)
			assert.Contains(t, err.Error(), "WithPostLogoutRedirect")
			assert.NotContains(t, err.Error(), "s3cr3t", "user information is never repeated")
			assert.Nil(t, m)
		}
		built := func(t *testing.T, m *oidc.RelyingParty, err error) {
			t.Helper()
			require.NoError(t, err)
			assert.NotNil(t, m)
		}

		cases := []constructionCase{
			{name: "an absolute https redirect is accepted",
				opts: []oidc.Option{oidc.WithPostLogoutRedirect(redirect)}, assert: built},
			{name: "an http redirect is refused with the default client",
				opts: []oidc.Option{oidc.WithPostLogoutRedirect("http://app.example/bye")}, assert: refused},
			{name: "an http redirect is accepted with a client allowing http",
				opts: []oidc.Option{
					oidc.WithPostLogoutRedirect("http://localhost:3000/bye"), oidc.WithOutboundClient(allowHTTP),
				},
				assert: built},
			{name: "a redirect with user information is refused",
				opts: []oidc.Option{oidc.WithPostLogoutRedirect("https://user:s3cr3t@app.example/")}, assert: refused},
			{name: "a redirect with a user name only is refused",
				opts: []oidc.Option{oidc.WithPostLogoutRedirect("https://user@app.example/")}, assert: refused},
			{name: "a relative redirect is refused",
				opts: []oidc.Option{oidc.WithPostLogoutRedirect("/bye")}, assert: refused},
			{name: "a redirect with no host is refused",
				opts: []oidc.Option{oidc.WithPostLogoutRedirect("https:///bye")}, assert: refused},
			{name: "an empty redirect is refused",
				opts: []oidc.Option{oidc.WithPostLogoutRedirect("")}, assert: refused},
			{name: "an unparsable redirect is refused",
				opts: []oidc.Option{oidc.WithPostLogoutRedirect("https://app.example/%zz")}, assert: refused},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				m, err := oidc.NewRelyingParty(reg, stubBroker{}, tc.opts...)
				tc.assert(t, m, err)
			})
		}
	})
}
