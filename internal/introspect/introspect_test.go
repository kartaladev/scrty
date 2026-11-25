package introspect_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/introspect"
	"github.com/kartaladev/scrty/outbound"
)

const (
	issuer   = "https://as.example.com"
	resource = "https://api.example.com"
	clientID = "rs:client"
	secret   = "s3cr3t-introspection-secret"   //nolint:gosec // G101: test fixture, not a credential
	token    = "opaque-token-value-0123456789" //nolint:gosec // G101: test fixture, not a credential
)

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

// server is a TLS introspection endpoint recording every request it is sent.
type server struct {
	srv    *httptest.Server
	out    *outbound.Client
	calls  atomic.Int64
	mu     sync.Mutex
	last   *http.Request
	form   url.Values
	answer func(w http.ResponseWriter, r *http.Request)
}

func newServer(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) *server {
	t.Helper()
	s := &server{answer: answer}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		_ = r.ParseForm()
		s.mu.Lock()
		s.last, s.form = r, r.PostForm
		s.mu.Unlock()
		s.answer(w, r)
	}))
	t.Cleanup(s.srv.Close)
	out, err := outbound.New(outbound.WithHTTPClient(s.srv.Client()))
	require.NoError(t, err)
	s.out = out
	return s
}

func jsonAnswer(body map[string]any) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

func activeBody(exp time.Time) map[string]any {
	return map[string]any{
		"active": true, "token_type": "access_token", "iss": issuer, "sub": "user-1",
		"aud": resource, "client_id": "app", "scope": "read write", "exp": exp.Unix(),
		"auth_time": t0.Add(-time.Minute).Unix(), "acr": "urn:mfa", "amr": []string{"pwd", "otp"},
		"cnf": map[string]any{"jkt": "thumb"}, "custom": "x",
	}
}

func (s *server) config(mutate func(*introspect.Config)) introspect.Config {
	cfg := introspect.Config{
		Issuer: issuer, Endpoint: s.srv.URL + "/introspect", ClientID: clientID, Secret: secret,
		Clock: clockwork.NewFakeClockAt(t0),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return cfg
}

func TestClient_Introspect(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	type testCase struct {
		name   string
		answer func(w http.ResponseWriter, r *http.Request)
		cfg    func(*introspect.Config)
		assert func(t *testing.T, s *server, res *introspect.Result, err error)
	}

	cases := []testCase{
		{
			name:   "active access token is read and accepted",
			answer: jsonAnswer(activeBody(t0.Add(time.Hour))),
			assert: func(t *testing.T, s *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.Active)
				assert.Equal(t, "user-1", res.Subject)
				assert.Equal(t, issuer, res.Issuer)
				assert.Equal(t, []string{resource}, res.Audience)
				assert.Equal(t, []string{"read", "write"}, res.Scopes)
				assert.Equal(t, "app", res.ClientID)
				assert.Equal(t, "urn:mfa", res.ACR)
				assert.Equal(t, []string{"pwd", "otp"}, res.AMR)
				assert.Equal(t, map[string]string{"jkt": "thumb"}, res.Confirmation)
				assert.True(t, res.ExpiresAt.Equal(t0.Add(time.Hour)))
				assert.True(t, res.AuthTime.Equal(t0.Add(-time.Minute)))
				assert.Equal(t, "x", res.Claims["custom"])
				assert.True(t, res.Accepts(resource, t0))
				assert.False(t, res.Accepts("https://other.example.com", t0))
				assert.Equal(t, token, s.form.Get("token"))
				assert.Equal(t, "access_token", s.form.Get("token_type_hint"))
			},
		},
		{
			name:   "inactive token is not accepted",
			answer: jsonAnswer(map[string]any{"active": false}),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Active)
				assert.False(t, res.Accepts(resource, t0))
			},
		},
		{
			name: "refresh token reported active is refused",
			answer: func() func(http.ResponseWriter, *http.Request) {
				b := activeBody(t0.Add(time.Hour))
				b["token_type"] = "refresh_token"
				return jsonAnswer(b)
			}(),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Accepts(resource, t0))
			},
		},
		{
			name: "DPoP token type is accepted",
			answer: func() func(http.ResponseWriter, *http.Request) {
				b := activeBody(t0.Add(time.Hour))
				b["token_type"] = "DPoP"
				return jsonAnswer(b)
			}(),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.True(t, res.Accepts(resource, t0))
			},
		},
		{
			name: "another issuer is refused",
			answer: func() func(http.ResponseWriter, *http.Request) {
				b := activeBody(t0.Add(time.Hour))
				b["iss"] = "https://evil.example.com"
				return jsonAnswer(b)
			}(),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Active)
				assert.False(t, res.Accepts(resource, t0))
			},
		},
		{
			name: "no audience is refused",
			answer: func() func(http.ResponseWriter, *http.Request) {
				b := activeBody(t0.Add(time.Hour))
				delete(b, "aud")
				return jsonAnswer(b)
			}(),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Accepts(resource, t0))
			},
		},
		{
			name: "no subject is refused",
			answer: func() func(http.ResponseWriter, *http.Request) {
				b := activeBody(t0.Add(time.Hour))
				delete(b, "sub")
				return jsonAnswer(b)
			}(),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Accepts(resource, t0))
			},
		},
		{
			name: "no expiry is refused",
			answer: func() func(http.ResponseWriter, *http.Request) {
				b := activeBody(t0)
				delete(b, "exp")
				return jsonAnswer(b)
			}(),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Accepts(resource, t0))
			},
		},
		{
			name:   "expiry in the past is refused, and expiry exactly now too",
			answer: jsonAnswer(activeBody(t0)),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.NoError(t, err)
				assert.False(t, res.Accepts(resource, t0))
				assert.False(t, res.Accepts(resource, t0.Add(time.Second)))
				assert.True(t, res.Accepts(resource, t0.Add(-time.Second)))
			},
		},
		{
			name: "503 is a dependency error, not an inactive answer",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "down "+token, http.StatusServiceUnavailable)
			},
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.ErrorIs(t, err, introspect.ErrUnavailable)
				assert.Nil(t, res)
			},
		},
		{
			name: "malformed body is a dependency error",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"active": tru` + token))
			},
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.ErrorIs(t, err, introspect.ErrUnavailable)
				assert.Nil(t, res)
			},
		},
		{
			name:   "active not a boolean is a dependency error",
			answer: jsonAnswer(map[string]any{"active": "true"}),
			assert: func(t *testing.T, _ *server, res *introspect.Result, err error) {
				require.ErrorIs(t, err, introspect.ErrUnavailable)
				assert.Nil(t, res)
			},
		},
		{
			name:   "client_secret_basic sends form-encoded credentials in the header only",
			answer: jsonAnswer(map[string]any{"active": false}),
			assert: func(t *testing.T, s *server, _ *introspect.Result, err error) {
				require.NoError(t, err)
				want := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientID) + ":" + url.QueryEscape(secret)))
				assert.Equal(t, "Basic "+want, s.last.Header.Get("Authorization"))
				assert.Empty(t, s.form.Get("client_secret"))
				assert.Empty(t, s.form.Get("client_assertion"))
			},
		},
		{
			name:   "private_key_jwt sends a signed assertion for the issuer",
			answer: jsonAnswer(map[string]any{"active": false}),
			cfg: func(c *introspect.Config) {
				c.Secret = ""
				c.Key = &introspect.Key{Signer: key, Algorithm: "ES256", KeyID: "k1"}
			},
			assert: func(t *testing.T, s *server, _ *introspect.Result, err error) {
				require.NoError(t, err)
				assert.Empty(t, s.last.Header.Get("Authorization"))
				assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", s.form.Get("client_assertion_type"))
				assert.Equal(t, clientID, s.form.Get("client_id"))
				parsed, err := jwt.Parse([]byte(s.form.Get("client_assertion")),
					jwt.WithKey(jwa.ES256(), &key.PublicKey), jwt.WithValidate(false))
				require.NoError(t, err)
				iss, _ := parsed.Issuer()
				sub, _ := parsed.Subject()
				aud, _ := parsed.Audience()
				jti, _ := parsed.JwtID()
				exp, _ := parsed.Expiration()
				assert.Equal(t, clientID, iss)
				assert.Equal(t, clientID, sub)
				assert.Equal(t, []string{issuer}, aud)
				assert.NotEmpty(t, jti)
				assert.True(t, exp.After(t0) && !exp.After(t0.Add(5*time.Minute)))
			},
		},
		{
			name: "log capture carries no token or secret on any failure",
			answer: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, token+" "+secret, http.StatusInternalServerError)
			},
			assert: func(t *testing.T, _ *server, _ *introspect.Result, err error) {
				require.ErrorIs(t, err, introspect.ErrUnavailable)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, tc.answer)
			var logs bytes.Buffer
			cfg := s.config(func(c *introspect.Config) {
				c.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				if tc.cfg != nil {
					tc.cfg(c)
				}
			})
			c, err := introspect.New(cfg, s.out)
			require.NoError(t, err)

			res, err := c.Introspect(t.Context(), token)
			tc.assert(t, s, res, err)

			for _, leak := range []string{token, secret} {
				assert.NotContains(t, logs.String(), leak)
				if err != nil {
					assert.NotContains(t, err.Error(), leak)
				}
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	s := newServer(t, jsonAnswer(map[string]any{"active": false}))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	type testCase struct {
		name    string
		cfg     func(*introspect.Config)
		fetcher func() *outbound.Client
		assert  func(t *testing.T, c *introspect.Client, err error)
	}
	refused := func(t *testing.T, c *introspect.Client, err error) {
		require.ErrorIs(t, err, introspect.ErrConfig)
		assert.Nil(t, c)
		assert.NotContains(t, err.Error(), secret)
	}

	cases := []testCase{
		{name: "default secret config builds", assert: func(t *testing.T, c *introspect.Client, err error) {
			require.NoError(t, err)
			assert.NotNil(t, c)
		}},
		{name: "http endpoint is refused", cfg: func(c *introspect.Config) { c.Endpoint = "http://as.example.com/introspect" }, assert: refused},
		{name: "http endpoint refused even when the fetcher allows http", cfg: func(c *introspect.Config) { c.Endpoint = "http://127.0.0.1/introspect" },
			fetcher: func() *outbound.Client {
				o, err := outbound.New(outbound.WithAllowedSchemes("http"))
				require.NoError(t, err)
				return o
			}, assert: refused},
		{name: "malformed endpoint is refused", cfg: func(c *introspect.Config) { c.Endpoint = "://nope" }, assert: refused},
		{name: "endpoint with fragment is refused", cfg: func(c *introspect.Config) { c.Endpoint = s.srv.URL + "/i#x" }, assert: refused},
		{name: "missing issuer is refused", cfg: func(c *introspect.Config) { c.Issuer = "" }, assert: refused},
		{name: "missing client id is refused", cfg: func(c *introspect.Config) { c.ClientID = "" }, assert: refused},
		{name: "no credential is refused", cfg: func(c *introspect.Config) { c.Secret = "" }, assert: refused},
		{name: "secret and key together are refused", cfg: func(c *introspect.Config) {
			c.Key = &introspect.Key{Signer: key, Algorithm: "ES256"}
		}, assert: refused},
		{name: "key without signer is refused", cfg: func(c *introspect.Config) {
			c.Secret = ""
			c.Key = &introspect.Key{Algorithm: "ES256"}
		}, assert: refused},
		{name: "key with unknown or symmetric algorithm is refused", cfg: func(c *introspect.Config) {
			c.Secret = ""
			c.Key = &introspect.Key{Signer: key, Algorithm: "HS256"}
		}, assert: refused},
		{name: "cache with age but no entries is refused", cfg: func(c *introspect.Config) {
			c.Cache = introspect.Cache{MaxAge: time.Minute}
		}, assert: refused},
		{name: "cache with negative bound is refused", cfg: func(c *introspect.Config) {
			c.Cache = introspect.Cache{MaxAge: -time.Minute, MaxEntries: 10}
		}, assert: refused},
		{name: "nil fetcher is refused", fetcher: func() *outbound.Client { return nil }, assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fetcher := s.out
			if tc.fetcher != nil {
				fetcher = tc.fetcher()
			}
			c, err := introspect.New(s.config(tc.cfg), fetcher)
			tc.assert(t, c, err)
		})
	}
}

func TestClient_Cache(t *testing.T) {
	t.Parallel()

	type step struct {
		token   string
		advance time.Duration
	}
	type testCase struct {
		name   string
		cache  introspect.Cache
		body   map[string]any
		steps  []step
		assert func(t *testing.T, calls int64)
	}

	cases := []testCase{
		{
			name: "reused within the age bound, refetched after it", cache: introspect.Cache{MaxAge: time.Minute, MaxEntries: 10},
			body:   activeBody(t0.Add(time.Hour)),
			steps:  []step{{token: "a"}, {token: "a", advance: 59 * time.Second}, {token: "a", advance: 2 * time.Second}},
			assert: func(t *testing.T, calls int64) { assert.EqualValues(t, 2, calls) },
		},
		{
			name: "never reused past the token's expiry", cache: introspect.Cache{MaxAge: time.Minute, MaxEntries: 10},
			body:   activeBody(t0.Add(10 * time.Second)),
			steps:  []step{{token: "a"}, {token: "a", advance: 9 * time.Second}, {token: "a", advance: time.Second}},
			assert: func(t *testing.T, calls int64) { assert.EqualValues(t, 2, calls) },
		},
		{
			name: "an answer with no expiry is not cached", cache: introspect.Cache{MaxAge: time.Minute, MaxEntries: 10},
			body: func() map[string]any {
				b := activeBody(t0)
				delete(b, "exp")
				return b
			}(),
			steps:  []step{{token: "a"}, {token: "a"}},
			assert: func(t *testing.T, calls int64) { assert.EqualValues(t, 2, calls) },
		},
		{
			name: "an inactive answer is not cached", cache: introspect.Cache{MaxAge: time.Minute, MaxEntries: 10},
			body:   map[string]any{"active": false, "exp": t0.Add(time.Hour).Unix()},
			steps:  []step{{token: "a"}, {token: "a"}},
			assert: func(t *testing.T, calls int64) { assert.EqualValues(t, 2, calls) },
		},
		{
			name: "the entry bound evicts the oldest", cache: introspect.Cache{MaxAge: time.Minute, MaxEntries: 2},
			body:   activeBody(t0.Add(time.Hour)),
			steps:  []step{{token: "a"}, {token: "b"}, {token: "c"}, {token: "c"}, {token: "b"}, {token: "a"}},
			assert: func(t *testing.T, calls int64) { assert.EqualValues(t, 4, calls) },
		},
		{
			name: "off by default", body: activeBody(t0.Add(time.Hour)),
			steps:  []step{{token: "a"}, {token: "a"}},
			assert: func(t *testing.T, calls int64) { assert.EqualValues(t, 2, calls) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t, jsonAnswer(tc.body))
			clk := clockwork.NewFakeClockAt(t0)
			c, err := introspect.New(s.config(func(cfg *introspect.Config) {
				cfg.Cache, cfg.Clock = tc.cache, clk
			}), s.out)
			require.NoError(t, err)
			for _, st := range tc.steps {
				clk.Advance(st.advance)
				_, err := c.Introspect(t.Context(), st.token)
				require.NoError(t, err)
			}
			tc.assert(t, s.calls.Load())
		})
	}
}

func TestClient_CachedResultIsACopy(t *testing.T) {
	t.Parallel()
	s := newServer(t, jsonAnswer(activeBody(t0.Add(time.Hour))))
	c, err := introspect.New(s.config(func(cfg *introspect.Config) {
		cfg.Cache = introspect.Cache{MaxAge: time.Minute, MaxEntries: 10}
	}), s.out)
	require.NoError(t, err)

	first, err := c.Introspect(t.Context(), token)
	require.NoError(t, err)
	first.Audience[0] = "tampered"
	first.Claims["sub"] = "tampered"

	second, err := c.Introspect(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, []string{resource}, second.Audience)
	assert.Equal(t, "user-1", second.Claims["sub"])
	assert.EqualValues(t, 1, s.calls.Load())
}

func TestClient_ConcurrentRequestsShareOneCall(t *testing.T) {
	t.Parallel()

	const n = 10
	release := make(chan struct{})
	s := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		jsonAnswer(activeBody(t0.Add(time.Hour)))(w, r)
	})
	c, err := introspect.New(s.config(nil), s.out)
	require.NoError(t, err)

	// The answer is held until every caller has joined the shared call.
	var joined atomic.Int32
	var once sync.Once
	introspect.SetJoinHook(c, func() {
		if joined.Add(1) == n {
			once.Do(func() { close(release) })
		}
	})

	var done sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		done.Go(func() {
			res, err := c.Introspect(t.Context(), token)
			if err == nil && !res.Active {
				err = assert.AnError
			}
			errs <- err
		})
	}
	done.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.EqualValues(t, 1, s.calls.Load())
}

func TestClient_CancelledContextMakesNoCall(t *testing.T) {
	t.Parallel()

	s := newServer(t, jsonAnswer(activeBody(t0.Add(time.Hour))))
	c, err := introspect.New(s.config(nil), s.out)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	res, err := c.Introspect(ctx, token)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, res)
	// The detached call, had it started, would reach the server shortly.
	time.Sleep(200 * time.Millisecond)
	assert.EqualValues(t, 0, s.calls.Load())
}

func TestClient_Introspect_TransportErrorTextStaysOutOfRecordsAndErrors(t *testing.T) {
	t.Parallel()

	hostile := errors.New("dial failed carrying " + token + " " + secret)
	s := newServer(t, jsonAnswer(map[string]any{"active": false}))
	out, err := outbound.New(outbound.WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, hostile }),
	}))
	require.NoError(t, err)

	var logs bytes.Buffer
	cfg := s.config(func(c *introspect.Config) {
		c.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	c, err := introspect.New(cfg, out)
	require.NoError(t, err)

	_, err = c.Introspect(t.Context(), token)

	require.ErrorIs(t, err, introspect.ErrUnavailable)
	for _, leak := range []string{token, secret} {
		assert.NotContains(t, logs.String(), leak)
		assert.NotContains(t, err.Error(), leak)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
