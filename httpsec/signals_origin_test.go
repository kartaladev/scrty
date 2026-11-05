package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// originLimit is what a stream keeps of an Origin at most.
const originLimit = 256

// openFromOrigin is rig.open of a request naming origin, which Sec-Fetch-Site: none lets through
// whatever it says.
func (r *streamRig) openFromOrigin(t *testing.T, sid, origin string) *riggedStream {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, httpsec.DefaultSessionSignalsPath, nil)
	req.RemoteAddr = streamClient + ":4242"
	req.Header.Set("Authorization", "Bearer "+sid)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Origin", origin)

	s := &riggedStream{w: &streamWriter{header: http.Header{}}, cancel: cancel, done: make(chan struct{})}

	before, reusesBefore, endsBefore := r.counted.loads.Load(), r.reuses.Load(), r.ends.Load()

	go func() {
		defer close(s.done)

		r.handler.ServeHTTP(s.w, req)
	}()

	synctest.Wait()

	r.loadsByTest.Add(r.counted.loads.Load() - before)
	r.reusesByTest.Add(r.reuses.Load() - reusesBefore)
	r.endsByTest.Add(r.ends.Load() - endsBefore)

	t.Cleanup(func() {
		cancel()
		synctest.Wait()
	})

	return s
}

// TestSessionSignals_Caps_Origin is an Origin of the client's own choosing: what a stream holds of it
// for its whole life, and what its open and close records quote.
func TestSessionSignals_Caps_Origin(t *testing.T) {
	t.Parallel()

	origin := func(size int) string { return "http://" + strings.Repeat("a", size-len("http://")) }

	type testCase struct {
		name   string
		origin string
		want   string
	}

	cases := []testCase{
		{name: "a real origin is held whole", origin: "http://example.com", want: "http://example.com"},
		{name: "one at the limit is held whole", origin: origin(originLimit), want: origin(originLimit)},
		{name: "one over the limit is cut to it", origin: origin(originLimit + 1), want: origin(originLimit)},
		{name: "a mebibyte is cut to it", origin: origin(1 << 20), want: origin(originLimit)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, streamSetup{})
				s := r.openFromOrigin(t, r.signIn(t).ID, tc.origin)

				require.Equal(t, http.StatusOK, s.status())

				s.cancel()
				synctest.Wait()

				for _, msg := range []string{"stream opened", "stream closed"} {
					assert.Equal(t, tc.want, streamLogRecord(t, r.logs.String(), msg)["origin"], msg)
				}

				assert.NotContains(t, r.logs.String(), tc.want+"a", "a record quotes more than the limit")
			})
		})
	}

	t.Run("what a body starts from holds only the cut", func(t *testing.T) {
		t.Parallel()

		ex := httpsec.NewExchange(t.Context(), stubRequest{
			method: http.MethodGet, path: httpsec.DefaultSessionSignalsPath, clientIP: "198.51.100.7",
			headers: map[string]string{"Origin": origin(1 << 20)},
		}, &stubWriter{})

		start := httpsec.StreamStartFor(t.Context(), ex, newSignalsFixture(t, signalsSetup{}).signIn(t, "u-1"), session.SignInState{})

		assert.Contains(t, start.Everything, origin(originLimit))
		assert.NotContains(t, start.Everything, origin(originLimit)+"a")
	})
}
