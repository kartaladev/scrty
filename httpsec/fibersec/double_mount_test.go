package fibersec_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/httpsec/fibersec"
	"github.com/kartaladev/scrty/identity"
)

// The two tests here mount one chain twice around different interceptors, Basic
// authentication and a stream, with different outcomes to read, so they do not
// share a table. Both run on a real listener: fiber's in-memory transport
// reports the unspecified client address, which Basic authentication refuses
// before its authenticator is called.

// countingAttempts counts what Basic authentication records and clears, and
// otherwise answers as an empty store.
type countingAttempts struct{ fails, resets atomic.Int32 }

func (c *countingAttempts) RecordFailure(context.Context, string, time.Time) error {
	c.fails.Add(1)
	return nil
}

func (c *countingAttempts) Reset(context.Context, string) error {
	c.resets.Add(1)
	return nil
}

func (*countingAttempts) FailureCount(context.Context, string, time.Time) (int, error) {
	return 0, nil
}

// countingAuthenticator counts its calls, and answers with err or, when err is
// nil, with one principal.
type countingAuthenticator struct {
	calls atomic.Int32
	err   error
}

func (a *countingAuthenticator) Authenticate(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
	a.calls.Add(1)

	if a.err != nil {
		return nil, a.err
	}

	return &authenticate.Authentication{Principal: &identity.Principal{ID: "u-1", Username: "ada"}}, nil
}

// TestRepro_DoubleMount pins that one chain used by a fiber app and by one of
// its groups runs once on a request to that group: the credentials are
// verified once and the attempt counters are touched once.
func TestRepro_DoubleMount(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		authErr error
		assert  func(t *testing.T, a *countingAuthenticator, at *countingAttempts, status int)
	}

	cases := []testCase{
		{
			name:    "a refused Basic login is charged once",
			authErr: authenticate.ErrAuthenticationFailed,
			assert: func(t *testing.T, a *countingAuthenticator, at *countingAttempts, status int) {
				assert.Equal(t, http.StatusUnauthorized, status)
				assert.EqualValues(t, 1, a.calls.Load(), "authenticator calls")
				assert.EqualValues(t, 1, at.fails.Load(), "failures recorded")
			},
		},
		{
			name: "a successful Basic login authenticates once",
			assert: func(t *testing.T, a *countingAuthenticator, at *countingAttempts, status int) {
				assert.Equal(t, http.StatusOK, status)
				assert.EqualValues(t, 1, a.calls.Load(), "authenticator calls")
				assert.EqualValues(t, 1, at.resets.Load(), "resets")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			a := &countingAuthenticator{err: tc.authErr}
			at := &countingAttempts{}
			chain := newChain(t, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: a, Attempts: at}))

			app := fiber.New(fiber.Config{ErrorHandler: fibersec.ErrorHandler})
			app.Use(fibersec.Middleware(chain))
			g := app.Group("/api")
			g.Use(fibersec.Middleware(chain))
			g.Get("/x", func(fc fiber.Ctx) error { return fc.SendStatus(http.StatusOK) })

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				"http://"+serveFiber(t, app)+"/api/x", http.NoBody)
			require.NoError(t, err)
			req.SetBasicAuth("ada", "pw")

			client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

			res, err := client.Do(req)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())

			tc.assert(t, a, at, res.StatusCode)
		})
	}
}

// TestDoubleMount_StreamOpensOnce pins that a stream served by a chain mounted
// at a fiber app and at one of its groups is opened once, and ends cleanly.
func TestDoubleMount_StreamOpensOnce(t *testing.T) {
	t.Parallel()

	var opened atomic.Int32

	returned := make(chan struct{})

	chain := newChain(t, streaming(func(ex *httpsec.Exchange) error {
		opened.Add(1)

		return ex.Writer.Stream(ex.Context(), "text/event-stream",
			func(_ context.Context, w httpsec.EventWriter) error {
				defer close(returned)

				return writeAndFlush(w)
			})
	}))

	app := fiber.New(fiber.Config{WriteTimeout: streamWriteTimeout, ErrorHandler: fibersec.ErrorHandler})
	app.Use(fibersec.Middleware(chain))
	g := app.Group("/s")
	g.Use(fibersec.Middleware(chain))
	g.Get("/stream", func(fiber.Ctx) error { return nil })

	resp := openStream(t.Context(), t, "http://"+serveFiber(t, app)+"/s/stream")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	events, err := countEvents(resp.Body)
	require.NoError(t, err)
	waitFor(t, returned, "the stream's body to return")

	assert.Equal(t, 1, events, "events read")
	assert.EqualValues(t, 1, opened.Load(), "streams opened")
}
