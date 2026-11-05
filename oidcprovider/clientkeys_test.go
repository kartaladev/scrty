package oidcprovider_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/outbound"
)

const secondKeyClient = "second-key-client"

// keysFixture is a client publishing its key set over TLS, reached through an outbound
// client trusting that server, on a clock the row controls.
type keysFixture struct {
	t        *testing.T
	srv      *httptest.Server
	clk      *clockwork.FakeClock
	registry *oidcprovider.MemoryRegistry
	provider *oidcprovider.Provider

	hits    atomic.Int64
	body    atomic.Pointer[[]byte]
	status  atomic.Int64
	handler atomic.Pointer[http.HandlerFunc]
	release chan struct{}
}

type keysOptions struct {
	outbound func(f *keysFixture) []outbound.Option
	provider []oidcprovider.Option
}

func newKeysFixture(t *testing.T, o keysOptions) *keysFixture {
	t.Helper()

	f := &keysFixture{t: t, clk: clockwork.NewFakeClockAt(authNow), release: make(chan struct{})}
	f.status.Store(http.StatusOK)
	f.publish(publicKey{raw: testECKey().Public(), kid: esKid})

	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if h := f.handler.Load(); h != nil {
			(*h)(w, r)

			return
		}
		f.serve(w)
	}))
	var once sync.Once
	t.Cleanup(func() {
		f.releaseHandlers(&once)
		f.srv.Close()
	})

	outOpts := []outbound.Option{outbound.WithHTTPClient(f.srv.Client())}
	if o.outbound != nil {
		outOpts = append(outOpts, o.outbound(f)...)
	}
	out, err := outbound.New(outOpts...)
	require.NoError(t, err)

	uriClient := func(id string) oidcprovider.Client {
		c := keyClient(id, nil)
		c.JWKSURI = f.srv.URL + "/jwks"

		return c
	}
	f.registry, err = oidcprovider.NewMemoryRegistry([]oidcprovider.Client{uriClient(keyClientID), uriClient(secondKeyClient)})
	require.NoError(t, err)

	d := validDeps(t)
	d.Clients = nil
	d.Registry = f.registry
	f.provider, err = oidcprovider.New(d, append([]oidcprovider.Option{
		oidcprovider.WithOutbound(out),
		oidcprovider.WithClock(f.clk),
	}, o.provider...)...)
	require.NoError(t, err)

	return f
}

func (f *keysFixture) releaseHandlers(once *sync.Once) { once.Do(func() { close(f.release) }) }

func (f *keysFixture) serve(w http.ResponseWriter) {
	w.WriteHeader(int(f.status.Load()))
	_, _ = w.Write(*f.body.Load())
}

func (f *keysFixture) setHandler(h http.HandlerFunc) { f.handler.Store(&h) }

func (f *keysFixture) publish(keys ...publicKey) {
	body := publicSet(f.t, keys...)
	f.body.Store(&body)
}

func (f *keysFixture) publishRaw(body string) {
	raw := []byte(body)
	f.body.Store(&raw)
}

// claims pass every check at the fixture's current time.
func (f *keysFixture) claims(client string) map[string]any {
	claims := claimsFor(client)
	claims["exp"] = f.clk.Now().Add(time.Minute).Unix()

	return claims
}

// authenticate presents a fresh ES256 assertion from the client's own key, naming kid.
func (f *keysFixture) authenticate(ctx context.Context, client, kid string) (*oidcprovider.RegisteredClient, error) {
	f.t.Helper()

	tok := signed(f.t, "ES256", testECKey(), map[string]any{"kid": kid}, f.claims(client))

	return f.provider.AuthenticateClient(ctx, presenting(tok))
}

func (f *keysFixture) mustAuthenticate(client, kid string) {
	f.t.Helper()

	rc, err := f.authenticate(f.t.Context(), client, kid)
	require.NoError(f.t, err)
	assert.Equal(f.t, client, rc.ID)
}

func (f *keysFixture) mustRefuse(client, kid string) {
	f.t.Helper()

	rc, err := f.authenticate(f.t.Context(), client, kid)
	refusedAs(f.t, oidcprovider.CodeInvalidClient, rc, err)
}

// mustFailDependency asserts the failure is an outage, and no verdict on the client.
func (f *keysFixture) mustFailDependency(client, kid string) {
	f.t.Helper()

	rc, err := f.authenticate(f.t.Context(), client, kid)
	assert.Nil(f.t, rc)
	require.ErrorIs(f.t, err, oidcprovider.ErrDependency)
	var refusal *oidcprovider.Error
	assert.False(f.t, errors.As(err, &refusal), "a fetch failure must not be a refusal of the client")
}

func TestAuthenticateClient_PrivateKeyJWT_KeySet(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   keysOptions
		assert func(t *testing.T, f *keysFixture)
	}

	cases := []testCase{
		// Fetched and cached.
		{
			name: "the set is fetched through the outbound client, and cached",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				f.mustAuthenticate(keyClientID, esKid)
				assert.EqualValues(t, 1, f.hits.Load())
			},
		},
		{
			name: "an assertion with no kid uses the set, and asks for no refetch",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				tok := func() string {
					return signed(t, "ES256", testECKey(), nil, f.claims(keyClientID))
				}
				_, err := f.provider.AuthenticateClient(t.Context(), presenting(tok()))
				require.NoError(t, err)

				forged := signed(t, "ES256", strangerECKey(), nil, f.claims(keyClientID))
				rc, err := f.provider.AuthenticateClient(t.Context(), presenting(forged))
				refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)
				assert.EqualValues(t, 1, f.hits.Load())
			},
		},
		{
			name: "each client has its own entry",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				f.mustAuthenticate(secondKeyClient, esKid)
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "a client moved to another URI uses the new one",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.setHandler(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/moved" {
						f.serve(w)

						return
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(publicSet(t, publicKey{raw: strangerECKey().Public(), kid: esKid}))
				})

				// The old URI publishes other keys under the same kid.
				f.mustRefuse(keyClientID, esKid)

				moved := keyClient(keyClientID, nil)
				moved.JWKSURI = f.srv.URL + "/moved"
				require.NoError(t, f.registry.Put(t.Context(), moved))
				f.mustAuthenticate(keyClientID, esKid)
			},
		},

		// A rotation, and the cooldown.
		{
			name: "a new kid refetches and authenticates, with no wait after the first fetch",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)

				f.publish(publicKey{raw: testECKey().Public(), kid: "es-2"})
				f.mustAuthenticate(keyClientID, "es-2")
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "many unknown kids within the cooldown fetch once, and are refused",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)

				for range 10 {
					f.mustRefuse(keyClientID, "unknown")
					f.clk.Advance(time.Second)
				}
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "a refetch that found its kid still starts the cooldown",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)

				f.publish(publicKey{raw: testECKey().Public(), kid: "es-2"})
				f.mustAuthenticate(keyClientID, "es-2")
				require.EqualValues(t, 2, f.hits.Load())

				f.mustRefuse(keyClientID, "unknown")
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "different unknown kids share one cooldown",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)

				for _, kid := range []string{"a", "b", "c", "d"} {
					f.mustRefuse(keyClientID, kid)
				}
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "an unknown kid on a cold cache fetches once, not twice",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				for range 5 {
					f.mustRefuse(keyClientID, "unknown")
				}
				assert.EqualValues(t, 1, f.hits.Load())
			},
		},
		{
			name: "a known kid is still served during the cooldown",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				f.mustRefuse(keyClientID, "unknown")
				f.mustAuthenticate(keyClientID, esKid)
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "a refetch is allowed again once the cooldown ends",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				f.mustRefuse(keyClientID, "es-2")
				require.EqualValues(t, 2, f.hits.Load())

				f.publish(publicKey{raw: testECKey().Public(), kid: "es-2"})
				f.clk.Advance(30*time.Second - time.Nanosecond)
				f.mustRefuse(keyClientID, "es-2")
				require.EqualValues(t, 2, f.hits.Load(), "still inside the cooldown")

				f.clk.Advance(time.Nanosecond)
				f.mustAuthenticate(keyClientID, "es-2")
				assert.EqualValues(t, 3, f.hits.Load())
			},
		},
		{
			name: "a consumer's cooldown replaces the default",
			opts: keysOptions{provider: []oidcprovider.Option{oidcprovider.WithClientKeysRefetchCooldown(time.Minute)}},
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				f.mustRefuse(keyClientID, "unknown")

				f.clk.Advance(59 * time.Second)
				f.mustRefuse(keyClientID, "unknown")
				require.EqualValues(t, 2, f.hits.Load())

				f.clk.Advance(time.Second)
				f.mustRefuse(keyClientID, "unknown")
				assert.EqualValues(t, 3, f.hits.Load())
			},
		},
		{
			name: "one client's cooldown holds back no other",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				f.mustAuthenticate(secondKeyClient, esKid)
				f.mustRefuse(keyClientID, "unknown")
				f.mustRefuse(secondKeyClient, "unknown")
				assert.EqualValues(t, 4, f.hits.Load())
			},
		},

		// The set's lifetime.
		{
			name: "the set is refetched past its lifetime, so a withdrawn key stops working",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				f.publish(publicKey{raw: strangerECKey().Public(), kid: esKid})

				f.clk.Advance(15*time.Minute - time.Second)
				f.mustAuthenticate(keyClientID, esKid)
				require.EqualValues(t, 1, f.hits.Load())

				f.clk.Advance(time.Second)
				f.mustRefuse(keyClientID, esKid)
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "a consumer's lifetime replaces the default",
			opts: keysOptions{provider: []oidcprovider.Option{oidcprovider.WithClientKeysTTL(time.Minute)}},
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				f.clk.Advance(time.Minute)
				f.mustAuthenticate(keyClientID, esKid)
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "an expired set is not served in place of a failed refetch",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)

				f.status.Store(http.StatusInternalServerError)
				f.clk.Advance(15 * time.Minute)
				f.mustFailDependency(keyClientID, esKid)
			},
		},

		// What is kept from a document.
		{
			name: "a symmetric key in a fetched set is never used",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				secret := []byte("shared-secret-0123456789abcdef-0123")
				f.publish(publicKey{raw: []byte(secret), kid: "oct-1"}, publicKey{raw: testECKey().Public(), kid: esKid})

				tok := unsigned(t, map[string]any{"alg": "HS256", "kid": "oct-1"}, f.claims(keyClientID), hs256(secret))
				rc, err := f.provider.AuthenticateClient(t.Context(), presenting(tok))
				refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)

				f.mustAuthenticate(keyClientID, esKid)
			},
		},
		{
			name: "a private key in a fetched set is dropped",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.publish(publicKey{raw: strangerECKey(), kid: "leaked"}, publicKey{raw: testECKey().Public(), kid: esKid})

				tok := signed(t, "ES256", strangerECKey(), map[string]any{"kid": "leaked"}, f.claims(keyClientID))
				rc, err := f.provider.AuthenticateClient(t.Context(), presenting(tok))
				refusedAs(t, oidcprovider.CodeInvalidClient, rc, err)

				f.mustAuthenticate(keyClientID, esKid)
			},
		},
		{
			name: "a key marked for encryption is dropped",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				body := string(publicSet(t, publicKey{raw: testECKey().Public(), kid: esKid}))
				f.publishRaw(strings.Replace(body, `"kty"`, `"use":"enc","kty"`, 1))

				f.mustFailDependency(keyClientID, esKid)
			},
		},

		// A fetch failure is the dependency's, not the client's.
		{
			name: "a 500",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.status.Store(http.StatusInternalServerError)
				f.publishRaw("upstream-detail")

				rc, err := f.authenticate(t.Context(), keyClientID, esKid)
				assert.Nil(t, rc)
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.NotContains(t, err.Error(), "upstream-detail")
				assert.NotContains(t, err.Error(), f.srv.URL)
			},
		},
		{
			name: "a document that is no key set",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.publishRaw("<html>upstream-detail</html>")

				rc, err := f.authenticate(t.Context(), keyClientID, esKid)
				assert.Nil(t, rc)
				require.ErrorIs(t, err, oidcprovider.ErrDependency)
				assert.NotContains(t, err.Error(), "upstream-detail")
			},
		},
		{
			name: "an empty key set",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.publishRaw(`{"keys":[]}`)
				f.mustFailDependency(keyClientID, esKid)
			},
		},
		{
			name: "a set holding nothing that can verify",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.publish(publicKey{raw: []byte("shared-secret-0123456789abcdef-0123"), kid: esKid})
				f.mustFailDependency(keyClientID, esKid)
			},
		},
		{
			name: "a server that cannot be reached",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.srv.Close()
				f.mustFailDependency(keyClientID, esKid)
			},
		},
		{
			name: "a failed fetch is tried again at most once per cooldown",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.status.Store(http.StatusInternalServerError)
				for range 5 {
					f.mustFailDependency(keyClientID, esKid)
				}
				require.EqualValues(t, 1, f.hits.Load())

				f.clk.Advance(30 * time.Second)
				f.status.Store(http.StatusOK)
				f.mustAuthenticate(keyClientID, esKid)
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "a failed refetch for an unknown kid is an outage, and known kids still work",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)

				f.status.Store(http.StatusServiceUnavailable)
				f.mustFailDependency(keyClientID, "es-2")
				require.EqualValues(t, 2, f.hits.Load())

				// The window remembers the outage, so a rotated client is not told its
				// credential is wrong while the set cannot be read.
				f.mustFailDependency(keyClientID, "es-2")
				require.EqualValues(t, 2, f.hits.Load())

				f.mustAuthenticate(keyClientID, esKid)
			},
		},
		{
			name: "a recovered server clears the failure",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.status.Store(http.StatusInternalServerError)
				f.mustFailDependency(keyClientID, esKid)

				f.status.Store(http.StatusOK)
				f.clk.Advance(30 * time.Second)
				f.mustAuthenticate(keyClientID, esKid)
				f.mustRefuse(keyClientID, "unknown")
				f.mustRefuse(keyClientID, "unknown")
			},
		},
		{
			name: "a panicking transport is a dependency failure, and no crash",
			opts: keysOptions{outbound: func(*keysFixture) []outbound.Option {
				return []outbound.Option{outbound.WithHTTPClient(&http.Client{Transport: panickingTransport{}})}
			}},
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustFailDependency(keyClientID, esKid)
			},
		},

		// The outbound client's confinement.
		{
			name: "a redirect to another origin is not followed",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				var reached atomic.Int64
				other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached.Add(1)
					_, _ = w.Write(publicSet(t, publicKey{raw: strangerECKey().Public(), kid: esKid}))
				}))
				t.Cleanup(other.Close)

				f.setHandler(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, other.URL+"/jwks", http.StatusFound)
				})

				f.mustFailDependency(keyClientID, esKid)
				assert.Zero(t, reached.Load(), "the request must not leave for the other origin")
			},
		},
		{
			name: "a redirect on the same origin is followed",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.setHandler(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/jwks" {
						http.Redirect(w, r, "/moved", http.StatusFound)

						return
					}
					f.serve(w)
				})

				f.mustAuthenticate(keyClientID, esKid)
			},
		},
		{
			name: "an origin the client is not allowed is refused before anything is sent",
			opts: keysOptions{outbound: func(*keysFixture) []outbound.Option {
				return []outbound.Option{outbound.WithAllowedOrigins("https://elsewhere.example.com")}
			}},
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustFailDependency(keyClientID, esKid)
				assert.Zero(t, f.hits.Load())
			},
		},
		{
			name: "a document past the size bound",
			opts: keysOptions{outbound: func(*keysFixture) []outbound.Option {
				return []outbound.Option{outbound.WithMaxResponseBytes(16)}
			}},
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustFailDependency(keyClientID, esKid)
			},
		},
		{
			name: "a server that never answers is bounded by the outbound timeout",
			opts: keysOptions{outbound: func(*keysFixture) []outbound.Option {
				return []outbound.Option{outbound.WithTimeout(50 * time.Millisecond)}
			}},
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.setHandler(func(_ http.ResponseWriter, r *http.Request) {
					<-r.Context().Done()
				})

				f.mustFailDependency(keyClientID, esKid)
			},
		},

		// A caller who leaves.
		{
			name: "a caller who left matches its own context, and records no failure",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				started := make(chan struct{})
				proceed := make(chan struct{})
				var once sync.Once
				f.setHandler(func(w http.ResponseWriter, _ *http.Request) {
					once.Do(func() { close(started) })
					select {
					case <-proceed:
					case <-f.release:
					}
					f.serve(w)
				})

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				tok := signed(t, "ES256", testECKey(), map[string]any{"kid": esKid}, f.claims(keyClientID))
				go func() {
					_, err := f.provider.AuthenticateClient(ctx, presenting(tok))
					done <- err
				}()

				select {
				case <-started:
				case err := <-done:
					require.Fail(t, "answered without fetching", "%v", err)
				}
				cancel()
				err := <-done
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorIs(t, err, oidcprovider.ErrDependency)

				close(proceed)
				f.mustAuthenticate(keyClientID, esKid)
				assert.EqualValues(t, 1, f.hits.Load(), "the fetch that outlived its caller fills the cache")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newKeysFixture(t, tc.opts))
		})
	}
}

// panickingTransport stands in for a consumer's transport with a bug.
type panickingTransport struct{}

func (panickingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("consumer transport bug")
}

// Concurrent callers share one fetch, and the cooldown holds whatever order they
// arrive in.
func TestAuthenticateClient_PrivateKeyJWT_KeySetConcurrent(t *testing.T) {
	t.Parallel()

	const callers = 32

	type outcome struct {
		successes, refusals, dependencies, others atomic.Int64
	}

	// race runs callers at once and sorts what they got.
	race := func(t *testing.T, f *keysFixture, kid func(i int) string) *outcome {
		t.Helper()

		toks := make([]string, callers)
		for i := range toks {
			toks[i] = signed(t, "ES256", testECKey(), map[string]any{"kid": kid(i)}, f.claims(keyClientID))
		}

		var (
			got   outcome
			start = make(chan struct{})
			wg    sync.WaitGroup
		)
		for i := range callers {
			wg.Go(func() {
				<-start
				_, err := f.provider.AuthenticateClient(t.Context(), presenting(toks[i]))

				var refusal *oidcprovider.Error
				switch {
				case err == nil:
					got.successes.Add(1)
				case errors.As(err, &refusal) && refusal.Code == oidcprovider.CodeInvalidClient:
					got.refusals.Add(1)
				case errors.Is(err, oidcprovider.ErrDependency):
					got.dependencies.Add(1)
				default:
					got.others.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()

		return &got
	}

	// held makes every fetch wait a moment, so callers pile up behind the first.
	held := func(f *keysFixture) {
		f.setHandler(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(20 * time.Millisecond)
			f.serve(w)
		})
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, f *keysFixture)
	}

	cases := []testCase{
		{
			name: "a cold cache fetches once for everyone",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				held(f)

				got := race(t, f, func(int) string { return esKid })

				assert.EqualValues(t, callers, got.successes.Load())
				assert.EqualValues(t, 1, f.hits.Load())
			},
		},
		{
			// With no wait in the fetch, a caller can look just before a flight finishes
			// and start the next one just after, which must then find the set it missed.
			name: "a set expiring under load fetches once per expiry",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				const rounds = 150

				for round := 1; round <= rounds; round++ {
					got := race(t, f, func(int) string { return esKid })
					require.Zero(t, got.others.Load())
					require.EqualValues(t, round, f.hits.Load(), "round %d", round)

					f.clk.Advance(15 * time.Minute)
				}
			},
		},
		{
			name: "one unknown kid refetches once, and everyone is refused",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				held(f)

				got := race(t, f, func(int) string { return "unknown" })

				assert.EqualValues(t, callers, got.refusals.Load())
				assert.EqualValues(t, 2, f.hits.Load(), "the cooldown must hold under concurrency")
			},
		},
		{
			name: "many unknown kids refetch once between them",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)

				kids := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
				got := race(t, f, func(i int) string { return kids[i%len(kids)] })

				assert.EqualValues(t, callers, got.refusals.Load())
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "known and unknown kids together: the known never wait on the outcome of the unknown",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.mustAuthenticate(keyClientID, esKid)
				held(f)

				got := race(t, f, func(i int) string {
					if i%2 == 0 {
						return esKid
					}

					return "unknown"
				})

				assert.EqualValues(t, callers/2, got.successes.Load())
				assert.EqualValues(t, callers/2, got.refusals.Load())
				assert.EqualValues(t, 2, f.hits.Load())
			},
		},
		{
			name: "a failing server is asked once, and everyone gets the outage",
			assert: func(t *testing.T, f *keysFixture) {
				t.Helper()
				f.status.Store(http.StatusInternalServerError)
				held(f)

				got := race(t, f, func(int) string { return esKid })

				assert.EqualValues(t, callers, got.dependencies.Load())
				assert.EqualValues(t, 1, f.hits.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newKeysFixture(t, keysOptions{}))
		})
	}
}
