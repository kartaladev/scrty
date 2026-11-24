package keyset_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/keyset"
	"github.com/kartaladev/scrty/outbound"
)

// idp is a TLS server that answers per path, and counts what it was asked.
type idp struct {
	srv *httptest.Server

	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	hits     map[string]int
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	p := &idp{handlers: map[string]http.HandlerFunc{}, hits: map[string]int{}}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.hits[r.URL.Path]++
		h := p.handlers[r.URL.Path]
		p.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) handle(path string, h http.HandlerFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers[path] = h
}

func (p *idp) count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hits[path]
}

func (p *idp) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.hits {
		n += c
	}
	return n
}

// serveDiscovery publishes OpenID metadata naming issuer and jwksURI.
func (p *idp) serveDiscovery(path, issuer, jwksURI string) {
	p.handle(path, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": jwksURI}) //nolint:errcheck // test server
	})
}

// serveKeys publishes a key set holding the public halves of keys.
func (p *idp) serveKeys(t *testing.T, path string, keys ...jwk.Key) {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		require.NoError(t, set.AddKey(k))
	}
	body, err := json.Marshal(set)
	require.NoError(t, err)
	p.handle(path, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body) //nolint:errcheck // test server
	})
}

func (p *idp) fail(path string, status int) {
	p.handle(path, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
}

const (
	discoveryPath = "/.well-known/openid-configuration"
	jwksPath      = "/jwks"
)

// signingKey returns a public EC signing key with the given id and use.
func signingKey(t *testing.T, kid, use string) jwk.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	k, err := jwk.Import[jwk.Key](&priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, kid))
	if use != "" {
		require.NoError(t, k.Set(jwk.KeyUsageKey, use))
	}
	return k
}

// opsKey returns a public EC key with the given id and key_ops, and no use.
func opsKey(t *testing.T, kid string, ops ...jwk.KeyOperation) jwk.Key {
	t.Helper()
	k := signingKey(t, kid, "")
	require.NoError(t, k.Set(jwk.KeyOpsKey, jwk.KeyOperationList(ops)))
	return k
}

func client(t *testing.T, p *idp) *outbound.Client {
	t.Helper()
	c, err := outbound.New(outbound.WithHTTPClient(p.srv.Client()))
	require.NoError(t, err)
	return c
}

// standard returns a server publishing discovery and one key "k1", and a
// source for it on a fake clock.
func standard(t *testing.T, opts ...keyset.Option) (*idp, *keyset.Source, *clockwork.FakeClock) {
	t.Helper()
	p := newIDP(t)
	p.serveDiscovery(discoveryPath, p.srv.URL, p.srv.URL+jwksPath)
	p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
	clk := clockwork.NewFakeClock()
	all := append([]keyset.Option{keyset.WithIssuer(p.srv.URL), keyset.WithClock(clk)}, opts...)
	s, err := keyset.New("test", client(t, p), all...)
	require.NoError(t, err)
	return p, s, clk
}

func TestSource_TTL(t *testing.T) {
	t.Parallel()
	p, s, clk := standard(t, keyset.WithTTL(time.Minute))

	for range 3 {
		k, err := s.Key(t.Context(), "k1")
		require.NoError(t, err)
		require.NotNil(t, k)
	}
	assert.Equal(t, 1, p.count(discoveryPath), "metadata is fetched once inside the TTL")
	assert.Equal(t, 1, p.count(jwksPath), "the key set is fetched once inside the TTL")

	clk.Advance(time.Minute)
	_, err := s.Key(t.Context(), "k1")
	require.NoError(t, err)
	assert.Equal(t, 2, p.count(jwksPath), "an expired key set is refetched")
	assert.Equal(t, 2, p.count(discoveryPath), "expired metadata is refetched")
}

func TestSource_Backoff(t *testing.T) {
	t.Parallel()
	p, s, clk := standard(t, keyset.WithBackoff(time.Second, 4*time.Second))
	p.fail(jwksPath, http.StatusServiceUnavailable)

	_, err := s.Key(t.Context(), "k1")
	require.ErrorIs(t, err, keyset.ErrUnavailable)
	require.Equal(t, 1, p.count(jwksPath))

	_, err = s.Key(t.Context(), "k1")
	require.ErrorIs(t, err, keyset.ErrUnavailable, "inside the window the failure is answered")
	assert.Equal(t, 1, p.count(jwksPath), "no request inside the backoff window")

	clk.Advance(time.Second)
	_, err = s.Key(t.Context(), "k1")
	require.ErrorIs(t, err, keyset.ErrUnavailable)
	assert.Equal(t, 2, p.count(jwksPath), "the window ended: one refetch")

	clk.Advance(time.Second)
	_, err = s.Key(t.Context(), "k1")
	require.ErrorIs(t, err, keyset.ErrUnavailable)
	assert.Equal(t, 2, p.count(jwksPath), "the second window is twice the first")

	p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
	clk.Advance(time.Second)
	_, err = s.Key(t.Context(), "k1")
	require.NoError(t, err, "a success after the window clears the failure")
	assert.Equal(t, 3, p.count(jwksPath))
}

func TestSource_UnknownKeyCooldown(t *testing.T) {
	t.Parallel()
	p, s, clk := standard(t, keyset.WithRefetchCooldown(10*time.Second))

	_, err := s.Key(t.Context(), "k1")
	require.NoError(t, err)
	require.Equal(t, 1, p.count(jwksPath))

	_, err = s.Key(t.Context(), "forged-1")
	require.ErrorIs(t, err, keyset.ErrUnknownKey)
	assert.Equal(t, 2, p.count(jwksPath), "an unknown key id refetches once")

	_, err = s.Key(t.Context(), "forged-2")
	require.ErrorIs(t, err, keyset.ErrUnknownKey)
	assert.Equal(t, 2, p.count(jwksPath), "inside the cooldown no refetch is sent")

	p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"), signingKey(t, "k2", "sig"))
	clk.Advance(10 * time.Second)
	k, err := s.Key(t.Context(), "k2")
	require.NoError(t, err, "after the cooldown a rotated key is found")
	assert.Equal(t, "k2", keyID(t, k))
	assert.Equal(t, 3, p.count(jwksPath))
}

func TestSource_Singleflight(t *testing.T) {
	t.Parallel()
	p := newIDP(t)
	p.serveDiscovery(discoveryPath, p.srv.URL, p.srv.URL+jwksPath)
	release := make(chan struct{})
	var arrived atomic.Int32
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(signingKey(t, "k1", "sig")))
	body, err := json.Marshal(set)
	require.NoError(t, err)
	p.handle(jwksPath, func(w http.ResponseWriter, _ *http.Request) {
		arrived.Add(1)
		<-release
		_, _ = w.Write(body) //nolint:errcheck // test server
	})
	s, err := keyset.New("test", client(t, p), keyset.WithIssuer(p.srv.URL))
	require.NoError(t, err)

	const callers = 16
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Go(func() {
			_, err := s.Key(t.Context(), "k1")
			errs <- err
		})
	}
	require.Eventually(t, func() bool { return arrived.Load() == 1 }, 5*time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond) // let every caller join the flight
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, 1, p.count(jwksPath), "concurrent callers share one fetch")
}

func TestSource_CancelledCaller(t *testing.T) {
	t.Parallel()
	p, s, _ := standard(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := s.Key(ctx, "k1")
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, p.total(), "a cancelled caller sends nothing")
}

func TestSource_Key(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		keys   func(t *testing.T) []jwk.Key
		kid    string
		assert func(t *testing.T, k jwk.Key, err error)
	}
	cases := []testCase{
		{
			name: "named key is returned",
			keys: func(t *testing.T) []jwk.Key { return []jwk.Key{signingKey(t, "a", "sig"), signingKey(t, "b", "")} },
			kid:  "b",
			assert: func(t *testing.T, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "b", keyID(t, k))
			},
		},
		{
			name: "no key id with exactly one signing key returns it",
			keys: func(t *testing.T) []jwk.Key { return []jwk.Key{signingKey(t, "a", "sig"), signingKey(t, "e", "enc")} },
			assert: func(t *testing.T, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "a", keyID(t, k))
			},
		},
		{
			name: "no key id with two signing keys is refused",
			keys: func(t *testing.T) []jwk.Key { return []jwk.Key{signingKey(t, "a", "sig"), signingKey(t, "b", "sig")} },
			assert: func(t *testing.T, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnknownKey)
			},
		},
		{
			name: "an encryption key is never returned",
			keys: func(t *testing.T) []jwk.Key { return []jwk.Key{signingKey(t, "a", "sig"), signingKey(t, "e", "enc")} },
			kid:  "e",
			assert: func(t *testing.T, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnknownKey)
			},
		},
		{
			name: "a key whose key_ops lack verify is never returned",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{signingKey(t, "a", "sig"), opsKey(t, "s", jwk.KeyOpSign)}
			},
			kid: "s",
			assert: func(t *testing.T, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnknownKey)
			},
		},
		{
			name: "a key whose key_ops is empty is never returned",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{signingKey(t, "a", "sig"), opsKey(t, "s")}
			},
			kid: "s",
			assert: func(t *testing.T, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnknownKey)
			},
		},
		{
			name: "a key whose key_ops include verify is returned",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{opsKey(t, "v", jwk.KeyOpSign, jwk.KeyOpVerify)}
			},
			kid: "v",
			assert: func(t *testing.T, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "v", keyID(t, k))
			},
		},
		{
			name: "a set with no signing key is a dependency failure",
			keys: func(t *testing.T) []jwk.Key { return []jwk.Key{signingKey(t, "e", "enc")} },
			kid:  "e",
			assert: func(t *testing.T, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newIDP(t)
			p.serveDiscovery(discoveryPath, p.srv.URL, p.srv.URL+jwksPath)
			p.serveKeys(t, jwksPath, tc.keys(t)...)
			s, err := keyset.New("test", client(t, p), keyset.WithIssuer(p.srv.URL))
			require.NoError(t, err)
			k, err := s.Key(t.Context(), tc.kid)
			tc.assert(t, k, err)
		})
	}
}

func TestSource_Discovery(t *testing.T) {
	t.Parallel()

	type env struct {
		p, other *idp
		issuer   string
		out      *outbound.Client
	}
	type testCase struct {
		name   string
		setup  func(t *testing.T, e *env) []keyset.Option
		assert func(t *testing.T, e *env, k jwk.Key, err error)
	}
	cases := []testCase{
		{
			name: "OpenID discovery 404 falls back to RFC 8414 with the path after the well-known segment",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.issuer = e.p.srv.URL + "/tenant"
				e.p.serveDiscovery("/.well-known/oauth-authorization-server/tenant", e.issuer, e.p.srv.URL+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				return nil
			},
			assert: func(t *testing.T, e *env, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID(t, k))
				assert.Equal(t, 1, e.p.count("/tenant"+discoveryPath), "OpenID discovery tried first")
				assert.Equal(t, 1, e.p.count("/.well-known/oauth-authorization-server/tenant"))
			},
		},
		{
			name: "an issuer with a trailing slash is discovered without a doubled slash and matched exactly",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.issuer = e.p.srv.URL + "/"
				e.p.serveDiscovery(discoveryPath, e.issuer, e.p.srv.URL+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				return nil
			},
			assert: func(t *testing.T, e *env, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID(t, k))
				assert.Equal(t, 1, e.p.count(discoveryPath))
			},
		},
		{
			name: "metadata dropping the issuer's trailing slash is refused",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.issuer = e.p.srv.URL + "/"
				e.p.serveDiscovery(discoveryPath, e.p.srv.URL, e.p.srv.URL+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				return nil
			},
			assert: func(t *testing.T, e *env, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
				assert.Equal(t, 0, e.p.count(jwksPath))
			},
		},
		{
			name: "RFC 8414 fallback drops the root issuer's trailing slash",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.issuer = e.p.srv.URL + "/"
				e.p.serveDiscovery("/.well-known/oauth-authorization-server", e.issuer, e.p.srv.URL+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				return nil
			},
			assert: func(t *testing.T, e *env, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID(t, k))
				assert.Equal(t, 1, e.p.count("/.well-known/oauth-authorization-server"))
			},
		},
		{
			name: "RFC 8414 fallback drops a path issuer's trailing slash",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.issuer = e.p.srv.URL + "/tenant/"
				e.p.serveDiscovery("/.well-known/oauth-authorization-server/tenant", e.issuer, e.p.srv.URL+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				return nil
			},
			assert: func(t *testing.T, e *env, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID(t, k))
				assert.Equal(t, 1, e.p.count("/.well-known/oauth-authorization-server/tenant"))
			},
		},
		{
			name: "a discovered key-set URL with the explicit default port is accepted",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.issuer = "https://example.com"
				e.p.serveDiscovery(discoveryPath, e.issuer, "https://example.com:443"+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				tr, ok := e.p.srv.Client().Transport.(*http.Transport)
				require.True(t, ok)
				tr = tr.Clone()
				addr := e.p.srv.Listener.Addr().String()
				tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
				out, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: tr}))
				require.NoError(t, err)
				e.out = out
				return nil
			},
			assert: func(t *testing.T, e *env, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID(t, k))
				assert.Equal(t, 1, e.p.count(jwksPath))
			},
		},
		{
			name: "an http key-set URL under an https issuer is refused",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.p.serveDiscovery(discoveryPath, e.issuer, "http://"+strings.TrimPrefix(e.p.srv.URL, "https://")+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				rt := &countingTransport{next: e.p.srv.Client().Transport}
				out, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: rt}))
				require.NoError(t, err)
				e.out = out
				t.Cleanup(func() {
					assert.Equal(t, int32(1), rt.n.Load(), "only the metadata request was sent")
				})
				return nil
			},
			assert: func(t *testing.T, e *env, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
				assert.Equal(t, 0, e.p.count(jwksPath))
			},
		},
		{
			name: "OpenID discovery failing with another status does not fall back",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.p.fail(discoveryPath, http.StatusInternalServerError)
				e.p.serveDiscovery("/.well-known/oauth-authorization-server", e.issuer, e.p.srv.URL+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				return nil
			},
			assert: func(t *testing.T, e *env, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
				assert.Equal(t, 0, e.p.count("/.well-known/oauth-authorization-server"), "no fallback on a 500")
				assert.Equal(t, 0, e.p.count(jwksPath))
			},
		},
		{
			name: "metadata naming another issuer is refused",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.p.serveDiscovery(discoveryPath, "https://evil.example", e.p.srv.URL+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				return nil
			},
			assert: func(t *testing.T, e *env, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
				assert.NotContains(t, err.Error(), "evil.example", "no part of the answer is quoted")
				assert.Equal(t, 0, e.p.count(jwksPath), "no key set is fetched")
			},
		},
		{
			name: "a discovered key-set URL on another origin is refused",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.p.serveDiscovery(discoveryPath, e.issuer, e.other.srv.URL+jwksPath)
				e.other.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				return nil
			},
			assert: func(t *testing.T, e *env, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
				assert.Equal(t, 0, e.other.total(), "nothing is fetched from the other origin")
			},
		},
		{
			name: "metadata with no key-set URL is refused",
			setup: func(_ *testing.T, e *env) []keyset.Option {
				e.p.serveDiscovery(discoveryPath, e.issuer, "")
				return nil
			},
			assert: func(t *testing.T, _ *env, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
			},
		},
		{
			name: "metadata that is not JSON is refused",
			setup: func(_ *testing.T, e *env) []keyset.Option {
				e.p.handle(discoveryPath, func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("<html>")) //nolint:errcheck // test server
				})
				return nil
			},
			assert: func(t *testing.T, _ *env, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
			},
		},
		{
			name: "a key set that is not a JWK set is refused",
			setup: func(_ *testing.T, e *env) []keyset.Option {
				e.p.serveDiscovery(discoveryPath, e.issuer, e.p.srv.URL+jwksPath)
				e.p.handle(jwksPath, func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte(`{"keys":"no"}`)) //nolint:errcheck // test server
				})
				return nil
			},
			assert: func(t *testing.T, _ *env, _ jwk.Key, err error) {
				require.ErrorIs(t, err, keyset.ErrUnavailable)
			},
		},
		{
			name: "a pinned key-set URL on another origin is used with no metadata read",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.other.serveKeys(t, "/certs", signingKey(t, "k1", "sig"))
				return []keyset.Option{keyset.WithJWKSURL(e.other.srv.URL + "/certs")}
			},
			assert: func(t *testing.T, e *env, k jwk.Key, err error) {
				require.NoError(t, err)
				assert.Equal(t, "k1", keyID(t, k))
				assert.Equal(t, 0, e.p.total(), "no metadata is read")
				assert.Equal(t, 1, e.other.count("/certs"))
			},
		},
		{
			name: "a replaced outbound client carries every fetch",
			setup: func(t *testing.T, e *env) []keyset.Option {
				e.p.serveDiscovery(discoveryPath, e.issuer, e.p.srv.URL+jwksPath)
				e.p.serveKeys(t, jwksPath, signingKey(t, "k1", "sig"))
				rt := &countingTransport{next: e.p.srv.Client().Transport}
				hc := &http.Client{Transport: rt}
				out, err := outbound.New(outbound.WithHTTPClient(hc))
				require.NoError(t, err)
				e.out = out
				t.Cleanup(func() {
					assert.Equal(t, int32(2), rt.n.Load(), "metadata and key set both went through the consumer's client")
				})
				return nil
			},
			assert: func(t *testing.T, _ *env, _ jwk.Key, err error) {
				require.NoError(t, err)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := &env{p: newIDP(t), other: newIDP(t)}
			e.issuer = e.p.srv.URL
			e.out = client(t, e.p)
			opts := tc.setup(t, e)
			s, err := keyset.New("test", e.out, append([]keyset.Option{keyset.WithIssuer(e.issuer)}, opts...)...)
			require.NoError(t, err)
			k, err := s.Key(t.Context(), "k1")
			tc.assert(t, e, k, err)
		})
	}
}

type countingTransport struct {
	next http.RoundTripper
	n    atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return c.next.RoundTrip(r)
}

func TestNew_Config(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		srcNm  string
		opts   []keyset.Option
		assert func(t *testing.T, s *keyset.Source, err error)
	}
	refused := func(t *testing.T, s *keyset.Source, err error) {
		require.ErrorIs(t, err, keyset.ErrConfig)
		assert.Nil(t, s)
	}
	cases := []testCase{
		{name: "issuer only", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example")},
			assert: func(t *testing.T, s *keyset.Source, err error) {
				require.NoError(t, err)
				assert.NotNil(t, s)
			}},
		{name: "pinned URL only", srcNm: "a", opts: []keyset.Option{keyset.WithJWKSURL("https://keys.example/certs")},
			assert: func(t *testing.T, s *keyset.Source, err error) {
				require.NoError(t, err)
				assert.NotNil(t, s)
			}},
		{name: "empty name", srcNm: "", opts: []keyset.Option{keyset.WithIssuer("https://idp.example")}, assert: refused},
		{name: "neither issuer nor URL", srcNm: "a", assert: refused},
		{name: "http pinned URL", srcNm: "a", opts: []keyset.Option{keyset.WithJWKSURL("http://keys.example/certs")}, assert: refused},
		{name: "relative issuer", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("/idp")}, assert: refused},
		{name: "http issuer", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("http://idp.example")}, assert: refused},
		{name: "issuer with a query", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example?x=1")}, assert: refused},
		{name: "issuer with a fragment", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example#x")}, assert: refused},
		{name: "issuer with userinfo", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://user:pw@idp.example")}, assert: refused},
		{name: "issuer with a username only", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://user@idp.example")}, assert: refused},
		{name: "nil logger", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example"), keyset.WithLogger(nil)}, assert: refused},
		{name: "negative backoff base", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example"), keyset.WithBackoff(-time.Second, time.Second)}, assert: refused},
		{name: "zero TTL", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example"), keyset.WithTTL(0)}, assert: refused},
		{name: "zero cooldown", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example"), keyset.WithRefetchCooldown(0)}, assert: refused},
		{name: "backoff max below base", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example"), keyset.WithBackoff(time.Second, time.Millisecond)}, assert: refused},
		{name: "nil clock", srcNm: "a", opts: []keyset.Option{keyset.WithIssuer("https://idp.example"), keyset.WithClock(nil)}, assert: refused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := keyset.New(tc.srcNm, nil, tc.opts...)
			tc.assert(t, s, err)
		})
	}
}

func keyID(t *testing.T, k jwk.Key) string {
	t.Helper()
	require.NotNil(t, k)
	kid, ok := k.KeyID()
	require.True(t, ok)
	return strings.TrimSpace(kid)
}
