package outbound_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/outbound"
)

// countingServer starts a server that counts every request reaching it, so a
// test asserts that nothing was sent rather than assuming it.
func countingServer(t *testing.T, secure bool, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var seen atomic.Int64
	counted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		h(w, r)
	})

	srv := httptest.NewServer(counted)
	if secure {
		srv = httptest.NewTLSServer(counted)
	}
	t.Cleanup(srv.Close)

	return srv, &seen
}

// trusting returns a client that trusts the given test servers' certificates
// and nothing else.
func trusting(t *testing.T, servers ...*httptest.Server) *http.Client {
	t.Helper()

	return &http.Client{Transport: trustingTransport(t, servers...)}
}

func trustingTransport(t *testing.T, servers ...*httptest.Server) *http.Transport {
	t.Helper()

	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
}

// dialingOnly returns a client that trusts srv and sends every connection to
// it, whatever host the URL names. It is how a test uses a real host name — and
// so a real origin comparison — without depending on name resolution.
func dialingOnly(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()

	tr := trustingTransport(t, srv)
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer

		return d.DialContext(ctx, network, srv.Listener.Addr().String())
	}

	return &http.Client{Transport: tr}
}

func ok(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"keys":[]}`))
}

func TestOutboundTargets(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) (target string, opts []outbound.Option, sent *atomic.Int64)
		assert func(t *testing.T, res *outbound.Response, err error, sent *atomic.Int64)
	}

	refusedUnsent := func(t *testing.T, res *outbound.Response, err error, sent *atomic.Int64) {
		require.ErrorIs(t, err, outbound.ErrRefused)
		assert.Nil(t, res)
		assert.Zero(t, sent.Load(), "the request must fail before anything is sent")
	}

	cases := []testCase{
		{
			name: "plain http is refused by default, before a connection is opened",
			setup: func(t *testing.T) (string, []outbound.Option, *atomic.Int64) {
				srv, seen := countingServer(t, false, ok)

				return srv.URL + "/jwks", nil, seen
			},
			assert: refusedUnsent,
		},
		{
			name: "the consumer allows http for a local provider",
			setup: func(t *testing.T) (string, []outbound.Option, *atomic.Int64) {
				srv, seen := countingServer(t, false, ok)

				return srv.URL + "/jwks", []outbound.Option{outbound.WithAllowedSchemes("http")}, seen
			},
			assert: func(t *testing.T, res *outbound.Response, err error, sent *atomic.Int64) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, http.StatusOK, res.Status)
				assert.JSONEq(t, `{"keys":[]}`, string(res.Body))
				assert.Equal(t, int64(1), sent.Load())
			},
		},
		{
			name: "an origin that is not on the allowlist",
			setup: func(t *testing.T) (string, []outbound.Option, *atomic.Int64) {
				idp, _ := countingServer(t, true, ok)
				evil, evilSeen := countingServer(t, true, ok)

				return evil.URL + "/token", []outbound.Option{
					outbound.WithAllowedOrigins(idp.URL),
					outbound.WithHTTPClient(trusting(t, idp, evil)),
				}, evilSeen
			},
			assert: refusedUnsent,
		},
		{
			name: "a declared origin matches case and the scheme's default port",
			setup: func(t *testing.T) (string, []outbound.Option, *atomic.Int64) {
				idp, seen := countingServer(t, true, ok)

				return "https://EXAMPLE.com/token", []outbound.Option{
					outbound.WithAllowedOrigins("https://example.com:443"),
					outbound.WithHTTPClient(dialingOnly(t, idp)),
				}, seen
			},
			assert: func(t *testing.T, res *outbound.Response, err error, sent *atomic.Int64) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, http.StatusOK, res.Status)
				assert.Equal(t, int64(1), sent.Load())
			},
		},
		{
			name: "an empty URL",
			setup: func(t *testing.T) (string, []outbound.Option, *atomic.Int64) {
				_, seen := countingServer(t, true, ok)

				return "", nil, seen
			},
			assert: refusedUnsent,
		},
		{
			name: "a URL that cannot be parsed",
			setup: func(t *testing.T) (string, []outbound.Option, *atomic.Int64) {
				_, seen := countingServer(t, true, ok)

				return "https://exa mple.com/\x7f", nil, seen
			},
			assert: refusedUnsent,
		},
		{
			name: "a URL with no host",
			setup: func(t *testing.T) (string, []outbound.Option, *atomic.Int64) {
				_, seen := countingServer(t, true, ok)

				return "https:///jwks", nil, seen
			},
			assert: refusedUnsent,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target, opts, sent := tc.setup(t)

			c, err := outbound.New(opts...)
			require.NoError(t, err)

			res, err := c.Get(t.Context(), target, nil)
			tc.assert(t, res, err, sent)
		})
	}
}

// counters names each server a redirect row watches, so a row asserts which
// origins were reached and which never were.
type counters map[string]*atomic.Int64

func TestOutboundRedirects(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) (target string, opts []outbound.Option, seen counters)
		assert func(t *testing.T, res *outbound.Response, err error, seen counters)
	}

	// redirectTo answers every request with a redirect to raw.
	redirectTo := func(raw string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, raw, http.StatusFound)
		}
	}

	cases := []testCase{
		{
			name: "a redirect off the starting origin is not followed",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				cdn, cdnSeen := countingServer(t, true, ok)
				idp, _ := countingServer(t, true, redirectTo(cdn.URL+"/jwks"))

				return idp.URL + "/jwks", []outbound.Option{
					outbound.WithHTTPClient(trusting(t, idp, cdn)),
				}, counters{"cdn": cdnSeen}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, seen counters) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Nil(t, res)
				assert.Zero(t, seen["cdn"].Load(), "no request may be sent to the redirect target")
			},
		},
		{
			name: "a redirect down to cleartext is not followed",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				plain, plainSeen := countingServer(t, false, ok)
				idp, _ := countingServer(t, true, redirectTo(plain.URL+"/jwks"))

				return idp.URL + "/jwks", []outbound.Option{
					outbound.WithHTTPClient(trusting(t, idp)),
				}, counters{"plain": plainSeen}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, seen counters) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Nil(t, res)
				assert.Zero(t, seen["plain"].Load())
			},
		},
		{
			name: "a redirect to another path on the starting origin is followed",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				var idp *httptest.Server
				idp, idpSeen := countingServer(t, true, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/jwks" {
						http.Redirect(w, r, "/keys", http.StatusFound)

						return
					}
					ok(w, r)
				})

				return idp.URL + "/jwks", []outbound.Option{
					outbound.WithHTTPClient(trusting(t, idp)),
				}, counters{"idp": idpSeen}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, seen counters) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.JSONEq(t, `{"keys":[]}`, string(res.Body))
				assert.Equal(t, int64(2), seen["idp"].Load())
			},
		},
		{
			name: "an endless same-origin loop stops at the default cap",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				idp, idpSeen := countingServer(t, true, loopingHandler)

				return idp.URL + "/hop/0", []outbound.Option{
					outbound.WithHTTPClient(trusting(t, idp)),
				}, counters{"idp": idpSeen}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, seen counters) {
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, int64(11), seen["idp"].Load(),
					"the original request and ten hops, never the fifty the server would have served")
			},
		},
		{
			name: "the consumer lowers the cap",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				idp, idpSeen := countingServer(t, true, loopingHandler)

				return idp.URL + "/hop/0", []outbound.Option{
					outbound.WithMaxRedirects(2),
					outbound.WithHTTPClient(trusting(t, idp)),
				}, counters{"idp": idpSeen}
			},
			assert: func(t *testing.T, _ *outbound.Response, err error, seen counters) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Equal(t, int64(3), seen["idp"].Load())
			},
		},
		{
			name: "a cap of zero never follows a redirect",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				idp, idpSeen := countingServer(t, true, loopingHandler)

				return idp.URL + "/hop/0", []outbound.Option{
					outbound.WithMaxRedirects(0),
					outbound.WithHTTPClient(trusting(t, idp)),
				}, counters{"idp": idpSeen}
			},
			assert: func(t *testing.T, _ *outbound.Response, err error, seen counters) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Equal(t, int64(1), seen["idp"].Load())
			},
		},
		{
			name: "the consumer's own redirect check still runs",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				idp, idpSeen := countingServer(t, true, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/jwks" {
						http.Redirect(w, r, "/keys", http.StatusFound)

						return
					}
					ok(w, r)
				})

				hc := trusting(t, idp)
				hc.CheckRedirect = func(*http.Request, []*http.Request) error {
					return errors.New("this application follows no redirect")
				}

				return idp.URL + "/jwks", []outbound.Option{outbound.WithHTTPClient(hc)}, counters{"idp": idpSeen}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, seen counters) {
				require.Error(t, err)
				assert.ErrorContains(t, err, "this application follows no redirect")
				assert.Nil(t, res)
				assert.Equal(t, int64(1), seen["idp"].Load())
			},
		},
		{
			name: "the library refuses before the consumer's check is consulted",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				var consulted atomic.Int64

				cdn, cdnSeen := countingServer(t, true, ok)
				idp, _ := countingServer(t, true, redirectTo(cdn.URL+"/jwks"))

				hc := trusting(t, idp, cdn)
				hc.CheckRedirect = func(*http.Request, []*http.Request) error {
					consulted.Add(1)

					return nil
				}

				return idp.URL + "/jwks", []outbound.Option{outbound.WithHTTPClient(hc)},
					counters{"cdn": cdnSeen, "consulted": &consulted}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, seen counters) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Nil(t, res)
				assert.Zero(t, seen["cdn"].Load())
				assert.Zero(t, seen["consulted"].Load(),
					"a consumer check that allows everything must not be able to undo the library's refusal")
			},
		},
		{
			name: "a hop to another declared origin is still off the starting origin",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				third, thirdSeen := countingServer(t, true, ok)
				second, secondSeen := countingServer(t, true, redirectTo(third.URL+"/jwks"))
				first, _ := countingServer(t, true, redirectTo(second.URL+"/jwks"))

				return first.URL + "/jwks", []outbound.Option{
					outbound.WithAllowedOrigins(first.URL, second.URL, third.URL),
					outbound.WithHTTPClient(trusting(t, first, second, third)),
				}, counters{"second": secondSeen, "third": thirdSeen}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, seen counters) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Nil(t, res)
				assert.Zero(t, seen["second"].Load(), "declaring an origin does not make it a redirect target")
				assert.Zero(t, seen["third"].Load(), "and a chain cannot walk to a third origin one hop at a time")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target, opts, seen := tc.setup(t)

			c, err := outbound.New(opts...)
			require.NoError(t, err)

			res, err := c.Get(t.Context(), target, nil)
			tc.assert(t, res, err, seen)
		})
	}
}

// loopingHandler redirects to the next path on its own origin, and answers
// normally only after fifty hops. The end exists so that a client with no cap
// fails the test that asserts the cap, instead of hanging it.
func loopingHandler(w http.ResponseWriter, r *http.Request) {
	hop := 0
	_, _ = fmt.Sscanf(r.URL.Path, "/hop/%d", &hop)

	if hop >= 50 {
		ok(w, r)

		return
	}

	http.Redirect(w, r, fmt.Sprintf("/hop/%d", hop+1), http.StatusFound)
}

// TestOutboundNoBodyReplay proves a 307 cannot resend a client secret to
// another origin.
//
// The check that stops it runs before the redirected request is sent. The
// final-URL check is not what protects this: by the time a response has come
// back, the secret has already been transmitted and cannot be unsent. This is
// the whole reason WithHTTPClient takes an *http.Client, whose redirect policy
// can be replaced, and not an interface with a Do method, whose redirect
// handling is out of reach.
func TestOutboundNoBodyReplay(t *testing.T) {
	t.Parallel()

	var secretsReceived atomic.Int64

	evil, _ := countingServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "client_secret") || r.Header.Get("Authorization") != "" {
			secretsReceived.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	})

	idp, _ := countingServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/token", http.StatusTemporaryRedirect)
	})

	c, err := outbound.New(outbound.WithHTTPClient(trusting(t, idp, evil)))
	require.NoError(t, err)

	res, err := c.PostForm(t.Context(), idp.URL+"/token", url.Values{
		"client_secret": {"the-secret"},
		"code":          {"the-code"},
	}, http.Header{"Authorization": {"Basic c2VjcmV0"}})

	assert.Zero(t, secretsReceived.Load(), "no client secret may reach another origin")
	require.ErrorIs(t, err, outbound.ErrRefused)
	assert.Nil(t, res)
}

// followingTransport answers a redirect by fetching the target itself, without
// consulting the client's redirect policy. It is what a consumer transport that
// handles redirects on its own looks like from this package's side.
type followingTransport struct{ inner http.RoundTripper }

func (t followingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusFound {
		return res, nil
	}

	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	//nolint:gosec // G704: following the location without a check is exactly what this stand-in models
	next, err := http.NewRequestWithContext(
		req.Context(), req.Method, req.URL.ResolveReference(location).String(), nil)
	if err != nil {
		return nil, err
	}

	return t.inner.RoundTrip(next)
}

func TestOutboundFinalURL(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T) (target string, opts []outbound.Option, seen counters)
		assert func(t *testing.T, res *outbound.Response, err error, seen counters)
	}

	cases := []testCase{
		{
			name: "a response the consumer's transport fetched from another origin",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				evil, evilSeen := countingServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"access_token":"attacker-issued"}`))
				})
				idp, _ := countingServer(t, true, func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, evil.URL+"/token", http.StatusFound)
				})

				hc := trusting(t, idp, evil)
				hc.Transport = followingTransport{inner: hc.Transport}

				return idp.URL + "/token", []outbound.Option{outbound.WithHTTPClient(hc)},
					counters{"evil": evilSeen}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, seen counters) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Nil(t, res, "no content from an unexpected origin is returned")
				assert.Equal(t, int64(1), seen["evil"].Load(),
					"the request did go out: a transport of the consumer's own bypasses the pre-send check, "+
						"which is the documented limit this check backstops")
			},
		},
		{
			name: "a response the consumer's transport fetched from the starting origin",
			setup: func(t *testing.T) (string, []outbound.Option, counters) {
				var idp *httptest.Server
				idp, idpSeen := countingServer(t, true, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/jwks" {
						http.Redirect(w, r, "/keys", http.StatusFound)

						return
					}
					ok(w, r)
				})

				hc := trusting(t, idp)
				hc.Transport = followingTransport{inner: hc.Transport}

				return idp.URL + "/jwks", []outbound.Option{outbound.WithHTTPClient(hc)},
					counters{"idp": idpSeen}
			},
			assert: func(t *testing.T, res *outbound.Response, err error, _ counters) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.JSONEq(t, `{"keys":[]}`, string(res.Body))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			target, opts, seen := tc.setup(t)

			c, err := outbound.New(opts...)
			require.NoError(t, err)

			res, err := c.Get(t.Context(), target, nil)
			tc.assert(t, res, err, seen)
		})
	}
}

func TestOutboundTimeout(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []outbound.Option
		ctx    func(ctx context.Context) context.Context // nil means identity
		assert func(t *testing.T, err error, elapsed time.Duration, sent *atomic.Int64)
	}

	cases := []testCase{
		{
			name: "the bound ends a call the consumer's client would have left running for ever",
			opts: []outbound.Option{outbound.WithTimeout(200 * time.Millisecond)},
			assert: func(t *testing.T, err error, elapsed time.Duration, sent *atomic.Int64) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Less(t, elapsed, 5*time.Second, "the bound, not the default, ended the call")
				assert.Equal(t, int64(1), sent.Load())
			},
		},
		{
			name: "the consumer lowers the bound",
			opts: []outbound.Option{outbound.WithTimeout(100 * time.Millisecond)},
			assert: func(t *testing.T, err error, elapsed time.Duration, _ *atomic.Int64) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Less(t, elapsed, 5*time.Second)
			},
		},
		{
			name: "an earlier deadline on the caller's context wins over the default bound",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
				t.Cleanup(cancel)

				return cctx
			},
			assert: func(t *testing.T, err error, elapsed time.Duration, _ *atomic.Int64) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Less(t, elapsed, 5*time.Second,
					"the caller gave up first, so the ten-second default never applied")
			},
		},
		{
			name: "a caller who has already given up",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: func(t *testing.T, err error, _ time.Duration, sent *atomic.Int64) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Zero(t, sent.Load(), "a request is not sent for a caller that has gone")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A provider that accepts the connection and never answers.
			silent, sent := countingServer(t, true, func(_ http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			})

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			// A client with no timeout of its own: the bound must come from here.
			opts := append([]outbound.Option{outbound.WithHTTPClient(trusting(t, silent))}, tc.opts...)

			c, err := outbound.New(opts...)
			require.NoError(t, err)

			started := time.Now()
			_, err = c.Get(ctx, silent.URL+"/jwks", nil)
			tc.assert(t, err, time.Since(started), sent)
		})
	}
}

func TestOutboundBodyLimit(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		size   int
		opts   []outbound.Option
		assert func(t *testing.T, res *outbound.Response, err error)
	}

	cases := []testCase{
		{
			name: "a five mebibyte key set under the default bound",
			size: 5 << 20,
			assert: func(t *testing.T, res *outbound.Response, err error) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Nil(t, res, "nothing is returned, so nothing can be parsed in part")
			},
		},
		{
			name: "the consumer raises the bound for a larger discovery document",
			size: 2 << 20,
			opts: []outbound.Option{outbound.WithMaxResponseBytes(4 << 20)},
			assert: func(t *testing.T, res *outbound.Response, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Len(t, res.Body, 2<<20)
			},
		},
		{
			name: "a body exactly at the bound",
			size: 1024,
			opts: []outbound.Option{outbound.WithMaxResponseBytes(1024)},
			assert: func(t *testing.T, res *outbound.Response, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Len(t, res.Body, 1024)
			},
		},
		{
			name: "one byte over the bound",
			size: 1025,
			opts: []outbound.Option{outbound.WithMaxResponseBytes(1024)},
			assert: func(t *testing.T, res *outbound.Response, err error) {
				require.ErrorIs(t, err, outbound.ErrRefused)
				assert.Nil(t, res)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, _ := countingServer(t, true, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(bytes.Repeat([]byte("k"), tc.size))
			})

			opts := append([]outbound.Option{outbound.WithHTTPClient(trusting(t, srv))}, tc.opts...)

			c, err := outbound.New(opts...)
			require.NoError(t, err)

			res, err := c.Get(t.Context(), srv.URL+"/jwks", nil)
			tc.assert(t, res, err)
		})
	}
}

// TestOutboundPostForm pins that what the caller gave is what the provider
// receives: the form always, and the caller's header exactly as given, or
// nothing beyond the form content type when there is none.
//
// TestOutboundNoBodyReplay calls PostForm too, but for what happens to the
// body and the header on a redirect, with a second server and a different
// setup entirely, which is why that case stays a separate test rather than a
// row here.
func TestOutboundPostForm(t *testing.T) {
	t.Parallel()

	type received struct {
		contentType, authorization string
		form                       url.Values
	}

	type testCase struct {
		name   string
		header http.Header
		assert func(t *testing.T, got received, err error)
	}

	cases := []testCase{
		{
			name:   "no header sends only the form and its content type",
			header: nil,
			assert: func(t *testing.T, got received, err error) {
				require.NoError(t, err)
				assert.Equal(t, "application/x-www-form-urlencoded", got.contentType)
				assert.Empty(t, got.authorization)
				assert.Equal(t, "authorization_code", got.form.Get("grant_type"))
				assert.Equal(t, "the code", got.form.Get("code"))
			},
		},
		{
			name:   "a caller header is sent exactly as given",
			header: http.Header{"Authorization": {"Basic Y2xpZW50OnNlY3JldA=="}},
			assert: func(t *testing.T, got received, err error) {
				require.NoError(t, err)
				assert.Equal(t, "Basic Y2xpZW50OnNlY3JldA==", got.authorization)
				assert.Equal(t, "the code", got.form.Get("code"),
					"the header travels beside the form, not instead of it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got received
			idp, _ := countingServer(t, true, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				got.contentType = r.Header.Get("Content-Type")
				got.authorization = r.Header.Get("Authorization")
				got.form, _ = url.ParseQuery(string(body))
				w.WriteHeader(http.StatusOK)
			})

			c, err := outbound.New(outbound.WithHTTPClient(trusting(t, idp)))
			require.NoError(t, err)

			_, err = c.PostForm(t.Context(), idp.URL+"/token", url.Values{
				"grant_type": {"authorization_code"},
				"code":       {"the code"},
			}, tc.header)
			tc.assert(t, got, err)
		})
	}
}

func TestOutboundAllowsScheme(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []outbound.Option
		assert func(t *testing.T, c *outbound.Client)
	}

	cases := []testCase{
		{
			name: "the default client allows https only",
			assert: func(t *testing.T, c *outbound.Client) {
				assert.True(t, c.AllowsScheme("https"))
				assert.True(t, c.AllowsScheme("HTTPS"), "schemes compare case-insensitively")
				assert.False(t, c.AllowsScheme("http"))
				assert.False(t, c.AllowsScheme(""))
				assert.False(t, c.AllowsScheme("ftp"))
			},
		},
		{
			name: "a client allowing http reports it, case-insensitively",
			opts: []outbound.Option{outbound.WithAllowedSchemes("http")},
			assert: func(t *testing.T, c *outbound.Client) {
				assert.True(t, c.AllowsScheme("HTTP"))
				assert.True(t, c.AllowsScheme("http"))
				assert.True(t, c.AllowsScheme("https"))
			},
		},
		{
			name: "case folding stays inside ASCII",
			assert: func(t *testing.T, c *outbound.Client) {
				// U+017F LATIN SMALL LETTER LONG S folds to "s" under Unicode
				// case folding; a request to such a URL would not parse as
				// https, so the answer here must not either.
				assert.False(t, c.AllowsScheme("httpſ"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := outbound.New(tc.opts...)
			require.NoError(t, err)
			tc.assert(t, c)
		})
	}
}
