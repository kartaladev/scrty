// These tests are white-box, in package oidcprovider: which clock read panics
// (the caller's, the flight's first, the one after the fetch) is not observable
// through the public path, and the row has to aim at each one.
package oidcprovider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/outbound"
)

// flightClock is a consumer clock that panics on the calls numbered from..to
// (1-based) while armed.
type flightClock struct {
	mu       sync.Mutex
	now      time.Time
	calls    int
	from, to int
}

func (c *flightClock) Now() time.Time {
	c.mu.Lock()
	c.calls++
	n, now := c.calls, c.now
	c.mu.Unlock()
	if n >= c.from && n <= c.to {
		panic("clock down")
	}

	return now
}

func (c *flightClock) disarm() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.from, c.to = 0, -1
}

func (c *flightClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// flightBuffer is a buffer safe for a logger's concurrent writes.
type flightBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *flightBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *flightBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// flightPanickingTransport panics on every round trip while armed.
type flightPanickingTransport struct {
	mu    sync.Mutex
	armed bool
	next  http.RoundTripper
}

func (p *flightPanickingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	armed := p.armed
	p.mu.Unlock()
	if armed {
		panic("consumer transport bug")
	}

	return p.next.RoundTrip(r)
}

func (p *flightPanickingTransport) disarm() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.armed = false
}

// TestClientKeySets_ClockPanicOnFlight pins that consumer code panicking on the
// fetch flight's goroutine (the clock, the transport) does not end the process:
// the waiting caller gets a dependency failure, as for a failing fetch, the
// failure window opens, the mutex is not left held and the flight is not stuck,
// so a later call returns and, past the window, fetches again.
func TestClientKeySets_ClockPanicOnFlight(t *testing.T) {
	t.Parallel()

	const (
		kid      = "flight-key"
		cooldown = time.Minute
		bound    = 5 * time.Second
	)

	type testCase struct {
		name           string
		from, to       int // the clock calls that panic; get makes call 1
		transportPanic bool
		assert         func(t *testing.T, hits int, log string)
	}

	cases := []testCase{
		{
			name: "the flight's first clock read panics",
			from: 2, to: 2,
			assert: func(t *testing.T, hits int, _ string) {
				t.Helper()
				assert.Equal(t, 1, hits, "only the fetch past the window reached the network")
			},
		},
		{
			name: "the clock read after a successful fetch panics",
			from: 3, to: 3,
			assert: func(t *testing.T, hits int, _ string) {
				t.Helper()
				assert.Equal(t, 2, hits)
			},
		},
		{
			name: "every clock read on the flight panics, so the window is timed by the caller's read",
			from: 2, to: 1 << 30,
			assert: func(t *testing.T, hits int, _ string) {
				t.Helper()
				assert.Equal(t, 1, hits)
			},
		},
		{
			name:           "the consumer's transport panics",
			transportPanic: true,
			assert: func(t *testing.T, hits int, _ string) {
				t.Helper()
				assert.Equal(t, 1, hits, "the panicking round trip never reached the server")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := flightKeySet(t, kid)
			var (
				hitsMu sync.Mutex
				hits   int
			)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hitsMu.Lock()
				hits++
				hitsMu.Unlock()
				_, _ = w.Write(body)
			}))
			t.Cleanup(srv.Close)

			transport := &flightPanickingTransport{armed: tc.transportPanic, next: srv.Client().Transport}
			out, err := outbound.New(outbound.WithHTTPClient(&http.Client{Transport: transport}))
			require.NoError(t, err)

			clk := &flightClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), from: tc.from, to: tc.to}
			if tc.from == 0 {
				clk.disarm()
			}
			log := &flightBuffer{}
			c := &clientKeySets{
				out:      out,
				logger:   slog.New(slog.NewJSONHandler(log, nil)),
				clock:    clk,
				ttl:      time.Hour,
				cooldown: cooldown,
			}
			uri := srv.URL + "/jwks"

			get := func() (jwk.Set, error) {
				t.Helper()
				type result struct {
					set jwk.Set
					err error
				}
				done := make(chan result, 1)
				go func() {
					set, err := c.get(t.Context(), "client", uri, kid)
					done <- result{set, err}
				}()
				select {
				case r := <-done:
					return r.set, r.err
				case <-time.After(bound):
					require.FailNow(t, "get did not return: the mutex is held or the flight is stuck")

					return nil, nil
				}
			}

			_, err = get()
			require.ErrorIs(t, err, ErrDependency, "a panic on the flight is a dependency failure")
			assert.NotContains(t, err.Error(), "clock down", "the panic value is not in the error")
			assert.NotContains(t, err.Error(), "consumer transport bug")
			assert.Contains(t, log.String(), "consumer code panicked", "the panic is recorded on the provider's logger")
			assert.NotContains(t, log.String(), "clock down", "the record does not carry the panic value")

			clk.disarm()
			transport.disarm()

			_, err = get()
			require.ErrorIs(t, err, ErrDependency, "inside the window the failure is answered without a fetch")

			clk.advance(cooldown + time.Second)
			set, err := get()
			require.NoError(t, err, "past the window the flight fetches again")
			_, ok := set.LookupKeyID(kid)
			assert.True(t, ok)

			hitsMu.Lock()
			n := hits
			hitsMu.Unlock()
			tc.assert(t, n, log.String())
			assert.False(t, strings.Contains(log.String(), "clock down"))
		})
	}
}

// flightKeySet is a published set holding one EC verification key named kid.
func flightKeySet(t *testing.T, kid string) []byte {
	t.Helper()

	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](raw.Public())
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	encoded, err := json.Marshal(key)
	require.NoError(t, err)
	body, err := json.Marshal(map[string][]json.RawMessage{"keys": {encoded}})
	require.NoError(t, err)

	return body
}
