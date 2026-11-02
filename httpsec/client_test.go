package httpsec_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
)

// seenClient is what the first interceptor of a chain read from the request.
type seenClient struct {
	ip     string
	host   string
	secure bool
}

// resolvedThroughChain builds a chain from opts with an interceptor at the outermost
// built-in slot recording what it reads from the request, runs req through it
// and returns what was recorded. A chain that does not build returns the
// error and runs nothing.
func resolvedThroughChain(t *testing.T, req *http.Request, opts ...httpsec.Option) (seenClient, error) {
	t.Helper()

	var seen seenClient

	recorder := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		seen = seenClient{ip: ex.Request.ClientIP(), host: ex.Request.Host(), secure: ex.Request.Secure()}

		return next(ex)
	})

	chain, err := httpsec.New(append(opts, httpsec.RegisterInterceptor(recorder, httpsec.OrderJWKS))...)
	if err != nil {
		return seenClient{}, err
	}

	run := chain.Assemble(func(*httpsec.Exchange) error { return nil }) //nolint:contextcheck // the exchange carries the request context, and begin reads it through ex.Context()
	ex := httpsec.NewExchange(req.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
	require.NoError(t, run(ex))

	return seen, nil
}

// plainRequest is a plain-HTTP request for app.example.com from peer.
func plainRequest(t *testing.T, peer string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = peer

	return req
}

func TestHTTPSDeployment(t *testing.T) {
	t.Parallel()

	proxies := httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Headers:  httpsec.XForwarded(httpsec.ForwardedFor),
	})

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, seen seenClient, err error)
	}

	cases := []testCase{
		{
			name: "default: a plain request is not secure",
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "198.51.100.7", host: "app.example.com"}, seen)
			},
		},
		{
			name: "declared HTTPS: a plain request is secure, host and client from the transport",
			opts: []httpsec.Option{httpsec.WithHTTPSDeployment()},
			assert: func(t *testing.T, seen seenClient, err error) {
				require.NoError(t, err)
				assert.Equal(t, seenClient{ip: "198.51.100.7", host: "app.example.com", secure: true}, seen)
			},
		},
		{
			name: "declared HTTPS beside trusted proxies fails naming both",
			opts: []httpsec.Option{httpsec.WithHTTPSDeployment(), proxies},
			assert: func(t *testing.T, _ seenClient, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "EnableTrustedProxies")
				assert.ErrorContains(t, err, "WithHTTPSDeployment")
			},
		},
		{
			name: "trusted proxies before the HTTPS declaration fails the same way",
			opts: []httpsec.Option{proxies, httpsec.WithHTTPSDeployment()},
			assert: func(t *testing.T, _ seenClient, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "EnableTrustedProxies")
				assert.ErrorContains(t, err, "WithHTTPSDeployment")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := plainRequest(t, "198.51.100.7:51234")
			req.Header.Set("X-Forwarded-Proto", "http")

			seen, err := resolvedThroughChain(t, req, tc.opts...)
			tc.assert(t, seen, err)
		})
	}
}

func TestClientFromContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		peer   string
		lines  []header
		assert func(t *testing.T, c httpsec.Client, ok bool)
	}

	cases := []testCase{
		{
			name: "a proxied request carries the forwarded client, marked as via a proxy",
			opts: []httpsec.Option{httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
				Prefixes: proxyNet,
				Headers:  httpsec.XForwarded(httpsec.ForwardedFor, httpsec.ForwardedProto),
			})},
			peer:  "10.20.0.2:41000",
			lines: []header{{"X-Forwarded-For", "203.0.113.7"}, {"X-Forwarded-Proto", "https"}},
			assert: func(t *testing.T, c httpsec.Client, ok bool) {
				require.True(t, ok)
				assert.Equal(t, httpsec.Client{IP: "203.0.113.7", Secure: true, Host: "app.example.com", ViaProxy: true}, c)
			},
		},
		{
			name:  "without trusted proxies it carries the transport peer, not via a proxy",
			peer:  "198.51.100.7:41000",
			lines: []header{{"X-Forwarded-For", "203.0.113.9"}},
			assert: func(t *testing.T, c httpsec.Client, ok bool) {
				require.True(t, ok)
				assert.Equal(t, httpsec.Client{IP: "198.51.100.7", Host: "app.example.com"}, c)
			},
		},
		{
			name: "a declared HTTPS deployment is secure, not via a proxy",
			opts: []httpsec.Option{httpsec.WithHTTPSDeployment()},
			peer: "198.51.100.7:41000",
			assert: func(t *testing.T, c httpsec.Client, ok bool) {
				require.True(t, ok)
				assert.Equal(t, httpsec.Client{IP: "198.51.100.7", Secure: true, Host: "app.example.com"}, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.opts...)
			require.NoError(t, err)

			var (
				got httpsec.Client
				ok  bool
				ran bool
			)

			chain.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				ran = true
				got, ok = httpsec.ClientFromContext(r.Context())
			})).ServeHTTP(httptest.NewRecorder(), forwardedRequest(t, tc.peer, tc.lines...))

			require.True(t, ran, "the handler ran")
			tc.assert(t, got, ok)
		})
	}

	t.Run("outside the chain there is none", func(t *testing.T) {
		t.Parallel()

		_, ok := httpsec.ClientFromContext(t.Context())
		assert.False(t, ok)
	})
}

// TestSourceGuard_UsesResolvedClient pins that rate limiting keys on the
// resolved client: behind a trusted proxy two clients are two sources, and
// without trusted proxies the proxy itself is the one source.
func TestSourceGuard_UsesResolvedClient(t *testing.T) {
	t.Parallel()

	const proxy = "10.20.0.2"

	proxies := httpsec.EnableTrustedProxies(httpsec.TrustedProxies{
		Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedFor),
	})

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, second served)
	}

	cases := []testCase{
		{
			name: "behind a trusted proxy the second client is not throttled",
			opts: []httpsec.Option{proxies},
			assert: func(t *testing.T, second served) {
				require.ErrorIs(t, second.err, authenticate.ErrAuthenticationFailed)
				assert.NotErrorIs(t, second.err, ratelimit.ErrThrottled)
			},
		},
		{
			name: "without trusted proxies both clients are the proxy, and the second is throttled",
			assert: func(t *testing.T, second served) {
				requireThrottled(t, second)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newLoginGuardHarness(t)
			c := h.chain(t, []httpsec.LoginOption{httpsec.WithLoginLimiter(memLimiter(t, 3, time.Hour))}, nil, tc.opts...)

			login := func(client, username string) served {
				req := fromSource(formRequest(t.Context(), httpsec.DefaultLoginPath,
					"username="+username+"&password=wrong"), proxy)
				req.Header.Set("X-Forwarded-For", client)

				return serve(t, c, req)
			}

			for i := range 3 {
				out := login("203.0.113.7", fmt.Sprintf("user%d", i))
				require.NotErrorIs(t, out.err, ratelimit.ErrThrottled, "attempt %d is within the allowance", i+1)
			}

			requireThrottled(t, login("203.0.113.7", "user4"))
			tc.assert(t, login("203.0.113.8", "user5"))
		})
	}
}

// keyRecordingLimiter wraps a limiter and records every key it is asked about,
// so a test can say which addresses a throttled flow reached the limiter with.
type keyRecordingLimiter struct {
	ratelimit.Limiter

	mu   sync.Mutex
	keys []string
}

func (l *keyRecordingLimiter) note(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.keys = append(l.keys, key)
}

func (l *keyRecordingLimiter) Exceeded(ctx context.Context, key string) (bool, error) {
	l.note(key)

	return l.Limiter.Exceeded(ctx, key)
}

func (l *keyRecordingLimiter) RecordFailure(ctx context.Context, key string) error {
	l.note(key)

	return l.Limiter.RecordFailure(ctx, key)
}

func (l *keyRecordingLimiter) Charge(ctx context.Context, key string) (ratelimit.Receipt, bool, error) {
	l.note(key)

	return l.Limiter.Charge(ctx, key)
}

// TestSourceGuard_ObfuscatedClientIsNotChargedToProxy pins that a trusted
// proxy forwarding an obfuscated client leaves the request unattributable, and
// that a throttled flow refuses it rather than charging the proxy's address.
func TestSourceGuard_ObfuscatedClientIsNotChargedToProxy(t *testing.T) {
	t.Parallel()

	const proxy = "10.20.0.2"

	type testCase struct {
		name   string
		tp     httpsec.TrustedProxies
		lines  []header
		assert func(t *testing.T, out served, keys []string)
	}

	refusedUnattributed := func(t *testing.T, out served, keys []string) {
		require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		assert.Empty(t, keys, "the limiter saw no key, so the proxy's address bucket was not charged")
	}

	cases := []testCase{
		{
			name: "Forwarded for=unknown",
			tp: httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.Forwarded(httpsec.ForwardedFor),
			},
			lines:  []header{{"Forwarded", "for=unknown"}},
			assert: refusedUnattributed,
		},
		{
			name: "Forwarded for with an obfuscated identifier",
			tp: httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.Forwarded(httpsec.ForwardedFor),
			},
			lines:  []header{{"Forwarded", "for=_hidden"}},
			assert: refusedUnattributed,
		},
		{
			name: "X-Forwarded-For with garbage where the client should be",
			tp: httpsec.TrustedProxies{
				Prefixes: proxyNet, Headers: httpsec.XForwarded(httpsec.ForwardedFor),
			},
			lines:  []header{{"X-Forwarded-For", "203.0.113.7, not-an-ip"}},
			assert: refusedUnattributed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limiter := &keyRecordingLimiter{Limiter: memLimiter(t, 3, time.Hour)}

			h := newLoginGuardHarness(t)
			c := h.chain(t, []httpsec.LoginOption{httpsec.WithLoginLimiter(limiter)}, nil,
				httpsec.EnableTrustedProxies(tc.tp))

			req := fromSource(formRequest(t.Context(), httpsec.DefaultLoginPath,
				"username=ada&password=wrong"), proxy)
			for _, l := range tc.lines {
				req.Header.Add(l.name, l.value)
			}

			out := serve(t, c, req)

			limiter.mu.Lock()
			defer limiter.mu.Unlock()

			tc.assert(t, out, limiter.keys)
		})
	}
}
