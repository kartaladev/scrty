package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidc"
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
		opts     []oidc.ManagerOption
		setup    func(p *testProvider)
		before   func(t *testing.T, m *oidc.Manager, raw string)
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
			opts:   []oidc.ManagerOption{oidc.WithLogoutTokenMaxAge(10 * time.Minute)},
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
			before: func(t *testing.T, m *oidc.Manager, raw string) {
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
			opts := append([]oidc.ManagerOption{
				oidc.WithOutboundClient(p.Outbound(t)),
				oidc.WithClock(clockwork.NewFakeClockAt(now)),
			}, tc.opts...)
			m, err := oidc.NewManager(reg, stubBroker{}, opts...)
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
