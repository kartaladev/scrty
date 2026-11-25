package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/ratelimit"
)

// TestResourceServer_SecurityEvents pins what a resource server reports: a refused token as the
// access-token refusal event naming the resource server and the source and carrying no token; a
// throttled address as excess_rate_limit_exceeded; binding refusals under their own events; a
// dependency failure and a server-nonce challenge as nothing, and never counted; and a caller naming
// no local user without a user reference.
func TestResourceServer_SecurityEvents(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name string
		// src is the source's stub; rs adds resource-server options; opts adds chain options.
		src  func() *httpsec.StubSource
		rs   []httpsec.ResourceServerOption
		opts func(t *testing.T) []httpsec.Option
		// requests are served in order through one chain.
		requests []func(t *testing.T) *http.Request
		assert   func(t *testing.T, rec *eventRecorder, out []served)
	}

	bearer := func(t *testing.T) *http.Request {
		return rsRequest(t, "http://example.com/api/orders", "Bearer "+rsToken)
	}
	nonceless := func(t *testing.T) *http.Request {
		proof := key.validProof("j-nonce").with(map[string]any{"ath": tokenHash(rsToken)}).sign(t)
		req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", proof)
		req.Header.Set("Authorization", "DPoP "+rsToken)

		return req
	}
	limitedTo := func(n int) []httpsec.ResourceServerOption {
		return []httpsec.ResourceServerOption{httpsec.WithRefusalLimiter(must.Must(ratelimit.NewMemoryLimiter(n, time.Hour)))}
	}
	scopeRule := func(t *testing.T) []httpsec.Option {
		az := NewMockAuthorizer(gomock.NewController(t))

		return []httpsec.Option{httpsec.EnableAuthorization(az, authorize.Rule[httpsec.Request]{
			Match:   func(httpsec.Request) bool { return true },
			Require: authorize.HasAllScopes("orders:write"),
		})}
	}
	noTokenIn := func(t *testing.T, events []event.Event) {
		t.Helper()

		for _, e := range events {
			for _, field := range []string{string(e.User), e.Session, e.Cause, e.Target, e.Actor, e.Client} {
				assert.NotContains(t, field, rsToken, "an event carries no token")
			}
		}
	}

	cases := []testCase{
		{
			name: "a refused token is the access-token refusal event, naming the resource server and the source",
			src: func() *httpsec.StubSource {
				return &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true, Verify: rsExpired}
			},
			requests: []func(t *testing.T) *http.Request{bearer},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, httpsec.ErrInvalidToken)
				got := rec.named(event.AccessTokenRefused)
				require.Len(t, got, 1)
				assert.Equal(t, event.OutcomeFailure, got[0].Outcome)
				assert.Equal(t, "urn:orders", got[0].Target)
				assert.Equal(t, "provider", got[0].Cause)
				assert.Empty(t, got[0].User)
				noTokenIn(t, rec.all())
			},
		},
		{
			name: "a throttled address is excess_rate_limit_exceeded, and not a second refusal event",
			src: func() *httpsec.StubSource {
				return &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true, Verify: rsExpired}
			},
			rs:       limitedTo(1),
			requests: []func(t *testing.T) *http.Request{bearer, bearer},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[1].err, httpsec.ErrInvalidToken)
				assert.Len(t, rec.named(event.AccessTokenRefused), 1, "only the verified refusal")
				got := rec.named(event.ExcessRateLimitExceeded)
				require.Len(t, got, 1)
				assert.Empty(t, got[0].User)
				noTokenIn(t, rec.all())
			},
		},
		{
			name: "a dependency failure reports nothing and is not counted",
			src: func() *httpsec.StubSource {
				return &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true,
					Verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
						return nil, nil, errors.New("store down")
					}}
			},
			rs:       limitedTo(1),
			requests: []func(t *testing.T) *http.Request{bearer, bearer, bearer},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				for _, o := range out {
					assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(o.err))
				}
				assert.Empty(t, rec.all())
			},
		},
		{
			name: "server-nonce challenges report nothing and are never counted",
			src: func() *httpsec.StubSource {
				return &httpsec.StubSource{Name: "provider", Provider: true, Verify: rsBoundTo(map[string]string{"jkt": key.jkt})}
			},
			rs: limitedTo(1),
			opts: func(t *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableDPoP(*nonceDPoP(t, []byte("0123456789abcdef0123456789abcdef")))}
			},
			requests: []func(t *testing.T) *http.Request{nonceless, nonceless, nonceless},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				for _, o := range out {
					askedForNonce(t, o)
				}
				assert.Empty(t, rec.named(event.AccessTokenRefused))
				assert.Empty(t, rec.named(event.ExcessRateLimitExceeded))
			},
		},
		{
			name: "a DPoP refusal keeps its own event",
			src: func() *httpsec.StubSource {
				return &httpsec.StubSource{Name: "provider", Provider: true, Verify: rsBoundTo(map[string]string{"jkt": "another"})}
			},
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL})}
			},
			requests: []func(t *testing.T) *http.Request{nonceless},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, httpsec.ErrInvalidDPoPProof)
				assert.Len(t, rec.named(event.DPoPRefused), 1)
				assert.Empty(t, rec.named(event.AccessTokenRefused))
			},
		},
		{
			name: "a claims-only caller refused at a scope rule is authz_fail with no user reference",
			src: func() *httpsec.StubSource {
				return &httpsec.StubSource{Name: "issuer", Provider: true, Unbound: true, External: true,
					TokenScopes: []string{"orders:read"},
					Verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
						return &identity.Principal{ID: "https://sso.example#42", Kind: identity.KindUser}, nil, nil
					}}
			},
			opts:     scopeRule,
			requests: []func(t *testing.T) *http.Request{bearer},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, authorize.ErrAccessDenied)
				got := rec.named(event.AuthzFail)
				require.Len(t, got, 1)
				assert.Empty(t, got[0].User, "the external subject never stands in for a user")
			},
		},
		{
			name: "a local caller refused at a scope rule is authz_fail naming the user",
			src: func() *httpsec.StubSource {
				return &httpsec.StubSource{Name: "provider", Provider: true, Unbound: true,
					TokenScopes: []string{"orders:read"}, Verify: rsBoundTo(nil)}
			},
			opts:     scopeRule,
			requests: []func(t *testing.T) *http.Request{bearer},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, authorize.ErrAccessDenied)
				got := rec.named(event.AuthzFail)
				require.Len(t, got, 1)
				assert.Equal(t, identity.UserID("u-1"), got[0].User)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &eventRecorder{}

			opts := []httpsec.Option{
				httpsec.WithClock(clockwork.NewFakeClockAt(dpopNow)),
				httpsec.WithLogger(slog.New(slog.DiscardHandler)),
				httpsec.EnableSecurityEvents(rec.sink),
			}
			if tc.opts != nil {
				opts = append(opts, tc.opts(t)...)
			}

			rsOpts := append([]httpsec.ResourceServerOption{httpsec.WithPathPrefix("/api/"),
				httpsec.WithStubSource(tc.src())}, tc.rs...)
			opts = append(opts, httpsec.EnableResourceServer("urn:orders", rsOpts...))

			c, err := httpsec.New(opts...)
			require.NoError(t, err)

			out := make([]served, 0, len(tc.requests))
			for _, r := range tc.requests {
				out = append(out, serve(t, c, r(t)))
			}

			tc.assert(t, rec, out)
		})
	}
}
