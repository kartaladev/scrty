package httpsec_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// These tests are the stream's rows of what a replica does at its limits: a request it cannot
// serve now, and how it closes. The registry's and the hub's own rows are in their own files.

// The range BusyDelay's default stays in, ±30%.
const (
	busyLeast = 21 * time.Second
	busyMost  = 39 * time.Second
)

// storeDownText is what a failing store says, which no log may quote.
const storeDownText = "db-primary:5432 is down"

// requireOnlyRetry asserts s was answered 200 with the stream's headers, a body of one retry within
// its bounds, and nothing else, that its response has ended, and returns the delay stated.
func requireOnlyRetry(t *testing.T, s *riggedStream, least, most time.Duration) time.Duration {
	t.Helper()

	require.True(t, s.closed(), "the response did not end")
	assert.Equal(t, http.StatusOK, s.status())
	assert.Equal(t, "text/event-stream", s.w.header.Get("Content-Type"))
	assert.Equal(t, "no-store, no-transform", s.w.header.Get("Cache-Control"))
	assert.Equal(t, "no", s.w.header.Get("X-Accel-Buffering"))

	frames := s.frames()
	require.Len(t, frames, 1, "the body holds only a retry: %v", frames)
	require.Equal(t, "retry", frames[0].Kind, "the body holds only a retry: %v", frames)
	assert.Zero(t, s.unflushed(), "what was written was not flushed")

	ms, err := strconv.Atoi(frames[0].Data)
	require.NoError(t, err)

	delay := time.Duration(ms) * time.Millisecond
	assert.GreaterOrEqual(t, delay, least)
	assert.LessOrEqual(t, delay, most)

	return delay
}

// onlyRetryBody matches a body of one retry line.
var onlyRetryBody = regexp.MustCompile(`^retry: ([0-9]+)\n\n$`)

// requireOnlyRetryResponse is requireOnlyRetry for a response over a real connection, whose body
// it reads to its end, which is what shows the response ended.
func requireOnlyRetryResponse(t *testing.T, resp *http.Response, least, most time.Duration) {
	t.Helper()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store, no-transform", resp.Header.Get("Cache-Control"))

	var body []byte

	requireReturns(t, func() {
		var err error

		body, err = io.ReadAll(resp.Body)
		assert.NoError(t, err)
	})

	match := onlyRetryBody.FindSubmatch(body)
	require.NotNil(t, match, "the body holds only a retry: %q", body)

	ms, err := strconv.Atoi(string(match[1]))
	require.NoError(t, err)

	delay := time.Duration(ms) * time.Millisecond
	assert.GreaterOrEqual(t, delay, least)
	assert.LessOrEqual(t, delay, most)
}

// refusedCount is what the registry counted as refused by a cap.
func refusedCount(r *streamRig) uint64 {
	_, refused := httpsec.SignalHubProbeOf(r.chain).Registry().Stats()

	return refused
}

// signInOf stores a sign-in of user, who may not be the rig's u-1.
func (r *streamRig) signInOf(t *testing.T, user identity.UserID) *session.Session {
	t.Helper()

	var s *session.Session

	r.act(func() {
		var err error

		s, err = r.sessions.Create(t.Context(), user, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)
	})

	return s
}

// openN opens n streams of the sign-in, requiring each to have opened.
func (r *streamRig) openN(t *testing.T, s *session.Session, n int) []*riggedStream {
	t.Helper()

	streams := make([]*riggedStream, 0, n)

	for range n {
		stream := r.open(t, s.ID)
		require.Equal(t, []string{"session"}, stream.sent(), "a stream did not open")

		streams = append(streams, stream)
	}

	return streams
}

// TestSessionSignals_Caps_Stream is a cap reached by a real request: it answers 200 with only a
// longer retry, charges nothing and closes nothing.
func TestSessionSignals_Caps_Stream(t *testing.T) {
	t.Parallel()

	runStreamCases(t, []streamCase{
		{
			name: "a fifth stream of a sign-in gets only a retry, and the four stay open",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				open := r.openN(t, s, 4)

				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)

				assert.Equal(t, 4, r.openStreams())
				assert.EqualValues(t, 1, refusedCount(r))

				beats := len(open[0].comments())
				advance(20 * time.Second)

				for _, stream := range open {
					assert.False(t, stream.closed(), "a refusal closed a stream")
				}

				assert.Greater(t, len(open[0].comments()), beats, "a stream that was kept stopped")
			},
		},
		{
			name: "a seventeenth stream of a user, on a sign-in with fewer than four",
			assert: func(t *testing.T, r *streamRig) {
				for range 4 {
					r.openN(t, r.signIn(t), 4)
				}

				requireOnlyRetry(t, r.open(t, r.signIn(t).ID), busyLeast, busyMost)

				assert.Equal(t, 16, r.openStreams())
				assert.EqualValues(t, 1, refusedCount(r))
			},
		},
		{
			name: "one over the total, from a user who has none open",
			setup: streamSetup{signals: httpsec.SessionSignals{
				MaxStreams: 2, MaxPerUser: 2, MaxPerSignIn: 2,
			}},
			assert: func(t *testing.T, r *streamRig) {
				r.openN(t, r.signIn(t), 2)

				requireOnlyRetry(t, r.open(t, r.signInOf(t, "u-2").ID), busyLeast, busyMost)

				assert.Equal(t, 2, r.openStreams())
			},
		},
		{
			name:  "a consumer's cap is used",
			setup: streamSetup{signals: httpsec.SessionSignals{MaxPerSignIn: 1}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				r.openN(t, s, 1)

				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
			},
		},
		{
			name: "MaxPerSource is off by default, so one address holds more than a sign-in's four",
			assert: func(t *testing.T, r *streamRig) {
				r.openN(t, r.signIn(t), 4)
				r.openN(t, r.signIn(t), 4)

				assert.Equal(t, 8, r.openStreams())
			},
		},
		{
			name:  "MaxPerSource is used when set",
			setup: streamSetup{signals: httpsec.SessionSignals{MaxPerSource: 1}},
			assert: func(t *testing.T, r *streamRig) {
				r.openN(t, r.signIn(t), 1)

				requireOnlyRetry(t, r.open(t, r.signInOf(t, "u-2").ID), busyLeast, busyMost)

				assert.Equal(t, 1, r.openStreams())
			},
		},
		{
			name:  "a consumer's BusyDelay is used, and each refusal draws its own",
			setup: streamSetup{signals: httpsec.SessionSignals{BusyDelay: 10 * time.Second, MaxPerSignIn: 1}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				r.openN(t, s, 1)

				seen := map[time.Duration]bool{}

				for range 16 {
					seen[requireOnlyRetry(t, r.open(t, s.ID), 7*time.Second, 13*time.Second)] = true
				}

				assert.Greater(t, len(seen), 1, "every refusal stated the same delay")
			},
		},
		{
			name:  "a flood of refusals writes one record and charges nothing",
			setup: streamSetup{signals: httpsec.SessionSignals{MaxPerSignIn: 1}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				first := r.openN(t, s, 1)[0]

				for range 32 {
					requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
				}

				record := streamLogRecord(t, r.logs.String(), "a cap is reached")
				assert.Equal(t, "WARN", record["level"])
				assert.Equal(t, 1, strings.Count(r.logs.String(), "a cap is reached"), "the record is not sampled")
				assert.EqualValues(t, 32, refusedCount(r))

				// Thirty-two refusals cost the sign-in nothing: when the place frees, it opens.
				first.cancel()
				synctest.Wait()

				assert.Equal(t, []string{"session"}, r.open(t, s.ID).sent(), "a refused request was charged")
			},
		},
	})
}

// failLoad makes every authenticator's read of a session fail with a store's error.
func (r *streamRig) failLoad() {
	hook := func(context.Context) error { return errors.New(storeDownText) }
	r.loadHook.Store(&hook)
}

// TestSessionSignals_Caps_DependencyFailure is a store that cannot answer a request for the stream,
// at each place one is read. An EventSource gives up for good on a 5xx, and a retry could fix this,
// so each answers 200 with only a longer retry. The first rows are what the endpoint's own slot
// cannot see, because the authenticators read the store first.
func TestSessionSignals_Caps_DependencyFailure(t *testing.T) {
	t.Parallel()

	failing := func(t *testing.T, r *streamRig, trip func(), settle ...func()) *riggedStream {
		t.Helper()

		s := r.signIn(t)

		trip()

		stream := r.open(t, s.ID)

		for _, fn := range settle {
			fn()
		}

		return stream
	}

	// answeredRetry is what every row shares: the answer, no place taken, one failure counted, and
	// nothing of the store's text in a log.
	answeredRetry := func(t *testing.T, r *streamRig, stream *riggedStream) {
		t.Helper()

		requireOnlyRetry(t, stream, busyLeast, busyMost)

		assert.Zero(t, r.openStreams(), "a place was taken")
		assert.Zero(t, refusedCount(r), "a dependency failure is no cap's refusal")

		failures, inRow := httpsec.SignalReloadCounts(r.chain)
		assert.EqualValues(t, 1, failures, "an operator could not see it")
		assert.Zero(t, inRow, "no open stream failed")

		record := streamLogRecord(t, r.logs.String(), "a dependency failed")
		assert.Equal(t, "WARN", record["level"])
		assert.NotEmpty(t, record["error_type"])
		assert.NotContains(t, r.logs.String(), storeDownText, "a log quotes the store's error")
	}

	// secondUserReadFails lets the authenticator's read of the user through, and fails the next.
	secondUserReadFails := func(r *streamRig, fail func() (*identity.Details, error)) {
		var reads atomic.Int64

		r.userAnswers(func(context.Context) (*identity.Details, error) {
			if reads.Add(1) == 1 {
				return storedUser(), nil
			}

			return fail()
		})
	}

	runStreamCases(t, []streamCase{
		{
			name: "the session store fails at the authenticator's read",
			assert: func(t *testing.T, r *streamRig) {
				answeredRetry(t, r, failing(t, r, r.failLoad))
			},
		},
		{
			name: "the user store fails at the authenticator's read",
			assert: func(t *testing.T, r *streamRig) {
				answeredRetry(t, r, failing(t, r, func() {
					r.userAnswers(func(context.Context) (*identity.Details, error) {
						return nil, errors.New(storeDownText)
					})
				}))
			},
		},
		{
			name: "the session store fails at the stream's first read",
			assert: func(t *testing.T, r *streamRig) {
				answeredRetry(t, r, failing(t, r, func() {
					hook := func(context.Context) error { return errors.New(storeDownText) }
					r.listHook.Store(&hook)
				}))
			},
		},
		{
			name: "the user store fails at the stream's first read",
			assert: func(t *testing.T, r *streamRig) {
				answeredRetry(t, r, failing(t, r, func() {
					secondUserReadFails(r, func() (*identity.Details, error) { return nil, errors.New(storeDownText) })
				}))
			},
		},
		{
			name:  "a store that hangs at the first read, past ReloadTimeout",
			setup: streamSetup{signals: httpsec.SessionSignals{ReloadTimeout: 3 * time.Second}},
			assert: func(t *testing.T, r *streamRig) {
				answeredRetry(t, r, failing(t, r, r.honouringStore, func() { advance(3 * time.Second) }))
			},
		},
		{
			name: "a loader that panics at the first read, its value in no log",
			assert: func(t *testing.T, r *streamRig) {
				answeredRetry(t, r, failing(t, r, func() {
					secondUserReadFails(r, func() (*identity.Details, error) { panic(errors.New(streamSecret)) })
				}))

				assert.NotContains(t, r.logs.String(), streamSecret)
				assert.Equal(t, "reload", streamLogRecord(t, r.logs.String(), "panic")["phase"])
			},
		},
		{
			name: "a ReloadContext that returns nothing",
			setup: streamSetup{signals: httpsec.SessionSignals{ReloadContext: func(context.Context) context.Context {
				return nil
			}}},
			assert: func(t *testing.T, r *streamRig) {
				lists := r.lists.Load()

				answeredRetry(t, r, failing(t, r, func() {}))
				assert.Equal(t, lists, r.lists.Load(), "reads ran with no tenant")
			},
		},
		{
			name: "a cross-origin EventSource gets CORS's headers on it, or it could not read it and would give up",
			setup: streamSetup{opts: func(*streamRig) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableCORS(httpsec.CORSPolicy{
					AllowedOrigins: []string{"http://example.com"}, AllowCredentials: true,
				})}
			}},
			assert: func(t *testing.T, r *streamRig) {
				stream := failing(t, r, r.failLoad)

				answeredRetry(t, r, stream)
				assert.Equal(t, "http://example.com", stream.w.header.Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "true", stream.w.header.Get("Access-Control-Allow-Credentials"))
				assert.Contains(t, stream.w.header.Values("Vary"), "Origin")
			},
		},
		{
			name: "a flood of failures writes one record",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				r.failLoad()

				for range 8 {
					requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
				}

				assert.Equal(t, 1, strings.Count(r.logs.String(), "a dependency failed"), "the record is not sampled")

				failures, _ := httpsec.SignalReloadCounts(r.chain)
				assert.EqualValues(t, 8, failures)
			},
		},
	})
}

// failingLoadStore is a session store whose authenticator's read fails while fail is set.
type failingLoadStore struct {
	session.Store

	fail atomic.Bool
}

func (s *failingLoadStore) Load(ctx context.Context, sid string) (*session.Session, error) {
	if s.fail.Load() {
		return nil, errors.New(storeDownText)
	}

	return s.Store.Load(ctx, sid)
}

// TestSessionSignals_Caps_OtherAnswersStand is what the answer above must not reach: any other path,
// a chain with no stream, any answer a retry would not change, what a consumer answers, and a
// response already begun.
func TestSessionSignals_Caps_OtherAnswersStand(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  signalsSetup
		assert func(t *testing.T, f *signalsFixture, store *failingLoadStore)
	}

	// downAt asks method on target with a credential while the store is down.
	downAt := func(t *testing.T, f *signalsFixture, store *failingLoadStore, method, target string) *http.Response {
		t.Helper()

		sid := f.signIn(t, "u-1").ID

		store.fail.Store(true)

		return f.send(t, t.Context(), method, target, sid)
	}

	refuser := func(fn func(*httpsec.Exchange) error, at httpsec.Order) func(*signalsFixture) []httpsec.Option {
		return func(*signalsFixture) []httpsec.Option {
			return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
				func(ex *httpsec.Exchange, next httpsec.Next) error {
					if ex.Request.Path() != httpsec.DefaultSessionSignalsPath {
						return next(ex)
					}

					return fn(ex)
				}), at)}
		}
	}

	cases := []testCase{
		{
			name: "any other path keeps its 500",
			assert: func(t *testing.T, f *signalsFixture, store *failingLoadStore) {
				requireNoStream(t, downAt(t, f, store, http.MethodGet, "/orders"), http.StatusInternalServerError)
			},
		},
		{
			name: "a path that only starts with the stream's keeps its 500",
			assert: func(t *testing.T, f *signalsFixture, store *failingLoadStore) {
				requireNoStream(t, downAt(t, f, store, http.MethodGet, httpsec.DefaultSessionSignalsPath+"/x"),
					http.StatusInternalServerError)
			},
		},
		{
			name:  "a chain with no stream keeps its 500 on that path",
			setup: signalsSetup{withoutSignals: true},
			assert: func(t *testing.T, f *signalsFixture, store *failingLoadStore) {
				requireNoStream(t, downAt(t, f, store, http.MethodGet, httpsec.DefaultSessionSignalsPath),
					http.StatusInternalServerError)
			},
		},
		{
			name: "a POST is no EventSource, and keeps its 500",
			assert: func(t *testing.T, f *signalsFixture, store *failingLoadStore) {
				requireNoStream(t, downAt(t, f, store, http.MethodPost, httpsec.DefaultSessionSignalsPath),
					http.StatusInternalServerError)
			},
		},
		{
			name: "a writer that cannot stream is still 501, since no retry would change that",
			setup: signalsSetup{wrapHandler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(unflushableWriter{w}, r)
				})
			}},
			assert: func(t *testing.T, f *signalsFixture, store *failingLoadStore) {
				resp := downAt(t, f, store, http.MethodGet, httpsec.DefaultSessionSignalsPath)
				assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
			},
		},
		{
			name: "a store that answers an ended sign-in is still 401",
			assert: func(t *testing.T, f *signalsFixture, _ *failingLoadStore) {
				s := f.signIn(t, "u-1")
				require.NoError(t, f.sessions.Delete(t.Context(), s.ID))

				resp, _ := f.openStream(t, s.ID)
				requireNoStream(t, resp, http.StatusUnauthorized)
			},
		},
		{
			name: "a consumer's own rate limit, by error, stays its 429",
			setup: signalsSetup{opts: refuser(func(*httpsec.Exchange) error {
				return policy.ErrTooManySessions
			}, httpsec.After(httpsec.OrderBearerToken))},
			assert: func(t *testing.T, f *signalsFixture, _ *failingLoadStore) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
				requireNoStream(t, resp, http.StatusTooManyRequests)
			},
		},
		{
			name: "a response a consumer began is not written over, whatever it then returns",
			setup: signalsSetup{opts: refuser(func(ex *httpsec.Exchange) error {
				ex.Writer.SetHeader("Content-Type", "text/plain")
				ex.Writer.WriteHeader(http.StatusServiceUnavailable)

				if _, err := ex.Writer.Write([]byte("maintenance")); err != nil {
					return err
				}

				return errors.New(storeDownText)
			}, httpsec.After(httpsec.OrderBearerToken))},
			assert: func(t *testing.T, f *signalsFixture, _ *failingLoadStore) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)
				requireNoStream(t, resp, http.StatusServiceUnavailable)

				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, "maintenance", string(body))

				failures, _ := httpsec.SignalReloadCounts(f.chain)
				assert.Zero(t, failures, "what was not answered as a failure was counted as one")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &failingLoadStore{}
			setup := tc.setup
			setup.wrap = func(s session.Store) session.Store {
				store.Store = s

				return store
			}

			tc.assert(t, newSignalsFixture(t, setup), store)
		})
	}
}

// closing closes the chain's streams in the background, and hands back the result.
func (r *streamRig) closing(ctx context.Context) <-chan error {
	result := make(chan error, 1)

	go func() { result <- r.chain.CloseSessionSignals(ctx) }()

	synctest.Wait()

	return result
}

// lastRetry requires the last thing s sent to be a retry, and returns its delay.
func lastRetry(t *testing.T, s *riggedStream) time.Duration {
	t.Helper()

	frames := s.frames()
	require.NotEmpty(t, frames)

	last := frames[len(frames)-1]
	require.Equal(t, "retry", last.Kind, "a closing stream's last bytes: %v", frames)
	assert.Zero(t, s.unflushed(), "what was written was not flushed")

	ms, err := strconv.Atoi(last.Data)
	require.NoError(t, err)

	return time.Duration(ms) * time.Millisecond
}

// TestSessionSignals_Close_Streams is CloseSessionSignals on open streams.
func TestSessionSignals_Close_Streams(t *testing.T) {
	t.Parallel()

	withSignal := httpsec.SessionSignals{
		Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
	}

	changed := httpsec.SignalEnvelope{User: "u-1", Name: "credential_changed", Data: []byte(`{"kind":"passkey"}`)}

	runStreamCases(t, []streamCase{
		{
			name: "each stream closes with no event, its last bytes a retry, and frees its place",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				streams := r.openN(t, s, 2)

				require.NoError(t, <-r.closing(t.Context()))

				for _, stream := range streams {
					assert.True(t, stream.closed())
					assert.Equal(t, []string{"session"}, stream.sent(), "closing sent an event")

					delay := lastRetry(t, stream)
					assert.GreaterOrEqual(t, delay, time.Second)
					assert.LessOrEqual(t, delay, 15*time.Second)
				}

				assert.Zero(t, r.openStreams())
				assert.Equal(t, httpsec.RegistryKeys{}, httpsec.SignalHubProbeOf(r.chain).Registry().Keys(), "a key remains")
			},
		},
		{
			name: "a request after a close with its store down is still told what a closing replica tells",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				require.NoError(t, <-r.closing(t.Context()))
				r.failLoad()

				late := r.open(t, s.ID)

				assert.Equal(t, "close", late.w.header.Get("Connection"), "a keep-alive connection comes back here")
				requireOnlyRetry(t, late, time.Second, 15*time.Second)
				assert.Zero(t, r.chain.SessionSignalStats().ReloadFailures, "closing is no failure to report")
			},
		},
		{
			name: "each stream draws its own closing retry",
			assert: func(t *testing.T, r *streamRig) {
				var streams []*riggedStream
				for range 4 {
					streams = append(streams, r.openN(t, r.signIn(t), 4)...)
				}

				require.NoError(t, <-r.closing(t.Context()))

				seen := map[time.Duration]bool{}
				for _, stream := range streams {
					seen[lastRetry(t, stream)] = true
				}

				assert.Greater(t, len(seen), 1, "every stream would come back at one moment")
			},
		},
		{
			name:  "a consumer's ReconnectDelay sets the top of the range",
			setup: streamSetup{signals: httpsec.SessionSignals{ReconnectDelay: 2 * time.Second}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				streams := r.openN(t, s, 4)

				require.NoError(t, <-r.closing(t.Context()))

				for _, stream := range streams {
					delay := lastRetry(t, stream)
					assert.GreaterOrEqual(t, delay, time.Second)
					assert.LessOrEqual(t, delay, 6*time.Second)
				}
			},
		},
		{
			name:  "a ReconnectDelay so short that the range is empty closes at its floor",
			setup: streamSetup{signals: httpsec.SessionSignals{ReconnectDelay: 100 * time.Millisecond}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				require.NoError(t, <-r.closing(t.Context()))
				assert.Equal(t, time.Second, lastRetry(t, stream))
			},
		},
		{
			name:  "a stream that left for another reason says nothing of closing",
			setup: streamSetup{signals: httpsec.SessionSignals{Heartbeat: 5 * time.Second, MaxAge: 10 * time.Second}},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				retries := func() (n int) {
					for _, f := range stream.frames() {
						if f.Kind == "retry" {
							n++
						}
					}

					return n
				}

				advanceUntil(t, time.Minute, "MaxAge", stream.closed)
				assert.Equal(t, 1, retries(), "only closing states a second retry")
			},
		},
		{
			name: "a request afterwards gets only a retry, is not registered, and its connection closes",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)

				require.NoError(t, <-r.closing(t.Context()))

				late := r.open(t, s.ID)
				requireOnlyRetry(t, late, time.Second, 15*time.Second)

				assert.Equal(t, "close", late.w.header.Get("Connection"), "a keep-alive connection would come back here")
				assert.Zero(t, r.openStreams())
				assert.Zero(t, refusedCount(r), "closing is no cap's refusal")
				assert.NotContains(t, r.logs.String(), "refused", "a closing replica is not a problem to report")

				failures, _ := httpsec.SignalReloadCounts(r.chain)
				assert.Zero(t, failures)
			},
		},
		{
			name: "a second call ends nothing new, and waits on its own context",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				writing := stream.w.holdWrites()

				defer func() {
					select {
					case <-writing:
					default:
						close(writing)
					}
				}()

				first, cancelFirst := context.WithTimeout(t.Context(), time.Second)
				defer cancelFirst()

				// The body is held in its closing retry, the first write after the close.
				require.ErrorIs(t, r.chain.CloseSessionSignals(first), context.DeadlineExceeded)
				assert.Equal(t, 1, r.openStreams(), "the place is held until the body has returned")

				second, cancelSecond := context.WithTimeout(t.Context(), time.Second)
				defer cancelSecond()

				require.ErrorIs(t, r.chain.CloseSessionSignals(second), context.DeadlineExceeded,
					"it returned though a stream the first timed out on is still closing")

				result := r.closing(t.Context())
				assert.Empty(t, result, "it returned before the stream had")

				close(writing)
				synctest.Wait()

				require.Len(t, result, 1)
				require.NoError(t, <-result)
				assert.True(t, stream.closed())
				assert.Zero(t, r.openStreams())
			},
		},
		{
			name:  "a body blocked in a write does not stop it returning when its context ends",
			setup: streamSetup{signals: withSignal},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				writing := stream.w.holdWrites()

				defer close(writing)

				httpsec.SignalHubProbeOf(r.chain).Deliver(changed)
				synctest.Wait()

				ctx, cancel := context.WithCancel(t.Context())
				result := r.closing(ctx)

				assert.Empty(t, result, "the body has not returned")

				cancel()
				synctest.Wait()

				require.Len(t, result, 1)
				require.ErrorIs(t, <-result, context.Canceled)
				assert.False(t, stream.closed(), "a write nothing can stop")
			},
		},
		{
			name: "with nothing open it returns at once, and a stream afterwards still does not open",
			assert: func(t *testing.T, r *streamRig) {
				ended, cancel := context.WithCancel(t.Context())
				cancel()

				require.NoError(t, r.chain.CloseSessionSignals(ended))
				requireOnlyRetry(t, r.open(t, r.signIn(t).ID), time.Second, 15*time.Second)
			},
		},
	})
}

// TestSessionSignals_Close_NoSecondEventOfAnAnswer pins that one read's answer of two events stops
// between them when closing arrives during the first one's slow write.
func TestSessionSignals_Close_NoSecondEventOfAnAnswer(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newStreamRig(t, streamSetup{
			idle:     10 * time.Minute,
			absolute: 11 * time.Minute,
			signals: httpsec.SessionSignals{
				MaxAge:  httpsec.NoMaxAge,
				Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalSessionExpiring},
			},
		})

		s := r.signIn(t)
		stream := r.open(t, s.ID)

		advance(9*time.Minute + 30*time.Second)
		require.Len(t, stream.events("session_expiring"), 1, "the idle warning")

		held := r.holdListings(t)
		held.waitForRead(t)

		// So the idle deadline moves to the absolute one: a session event, and a new warning.
		r.touch(t, s.ID)

		writing := stream.w.holdWrites()

		held.letGo()
		synctest.Wait()

		closed := make(chan error, 1)

		go func() {
			closed <- r.chain.CloseSessionSignals(context.WithoutCancel(t.Context()))
		}()

		synctest.Wait()
		close(writing)
		synctest.Wait()

		assert.NoError(t, <-closed)
		assert.Len(t, stream.events("session_expiring"), 1, "an event started after closing: %v", stream.sent())
	})
}

// TestSessionSignals_Close_ServerShutdown runs a real server on the real clock, since what it pins is
// that http.Server.Shutdown, which waits for handlers and cancels nothing, comes back.
func TestSessionSignals_Close_ServerShutdown(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		register bool
		bound    time.Duration
		assert   func(t *testing.T, err error, lines <-chan string)
	}

	cases := []testCase{
		{
			name:     "registered with RegisterOnShutdown, it returns before its deadline, and the client hears a retry",
			register: true,
			bound:    signalsTestBound,
			assert: func(t *testing.T, err error, lines <-chan string) {
				require.NoError(t, err)

				var sent []string

				for {
					line, ok := nextStreamLine(t, lines)
					if !ok {
						break
					}

					sent = append(sent, line)
				}

				require.GreaterOrEqual(t, len(sent), 2)
				assert.Contains(t, sent[len(sent)-2], "retry: ", "the last bytes: %q", sent)
			},
		},
		{
			name:  "with no call registered, it waits out its deadline, so the row above shows the call's doing",
			bound: 100 * time.Millisecond,
			assert: func(t *testing.T, err error, _ <-chan string) {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := newRealStreams(t)
			_, lines, _ := r.open(t)

			closed := make(chan error, 1)

			if tc.register {
				r.srv.Config.RegisterOnShutdown(func() {
					ctx, cancel := context.WithTimeout(t.Context(), tc.bound)
					defer cancel()

					closed <- r.chain.CloseSessionSignals(ctx)
				})
			} else {
				closed <- nil
			}

			// The client's first lines mean the handler is running, which is what Shutdown waits for.
			line, ok := nextStreamLine(t, lines)
			require.True(t, ok)
			require.Contains(t, line, "retry: ")

			ctx, cancel := context.WithTimeout(t.Context(), tc.bound)
			defer cancel()

			tc.assert(t, r.srv.Config.Shutdown(ctx), lines)
			require.NoError(t, <-closed)

			// A row that did not close them leaves it to the server's Close, which waits.
			require.NoError(t, r.chain.CloseSessionSignals(t.Context()))
		})
	}
}

// TestSessionSignals_Close_OnAChain is what the call does to the rest of the feature.
func TestSessionSignals_Close_OnAChain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "a chain with no stream says so, and its stats are the zero value",
			assert: func(t *testing.T) {
				f := newSignalsFixture(t, signalsSetup{withoutSignals: true})

				require.ErrorIs(t, f.chain.CloseSessionSignals(t.Context()), httpsec.ErrSessionSignalsDisabled)
				assert.Equal(t, httpsec.SessionSignalStats{}, f.chain.SessionSignalStats())
			},
		},
		{
			name: "it ends a consumer's bus, and nothing is raised afterwards",
			assert: func(t *testing.T) {
				subscribed, ended := make(chan struct{}), make(chan struct{})

				bus := NewMockSignalBus(gomock.NewController(t))
				bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ctx context.Context, _ func(httpsec.SignalEnvelope)) error {
						close(subscribed)
						<-ctx.Done()
						close(ended)

						return ctx.Err()
					})

				f := newSignalsFixture(t, signalsSetup{signals: httpsec.SessionSignals{Bus: bus}})

				resp, cancel := f.openStream(t, f.signIn(t, "u-1").ID)
				requireStreamHead(t, resp)
				<-subscribed

				defer cancel()

				require.NoError(t, f.chain.CloseSessionSignals(t.Context()))

				select {
				case <-ended:
				case <-time.After(signalsTestBound):
					require.FailNow(t, "the bus's subscription was left running")
				}

				require.ErrorIs(t, httpsec.SignalHubProbeOf(f.chain).Raise(httpsec.SignalEnvelope{User: "u-1", Name: "app.x"}),
					httpsec.ErrSignalsBusy)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t)
		})
	}
}

// TestSessionSignals_Caps_Stats is what an operator reads, each from a real stream.
func TestSessionSignals_Caps_Stats(t *testing.T) {
	t.Parallel()

	withSignal := httpsec.SessionSignals{
		Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
	}

	changed := httpsec.SignalEnvelope{User: "u-1", Name: "credential_changed", Data: []byte(`{"kind":"passkey"}`)}

	runStreamCases(t, []streamCase{
		{
			name:  "open streams and cap refusals",
			setup: streamSetup{signals: httpsec.SessionSignals{MaxPerSignIn: 2}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				r.openN(t, s, 2)
				r.open(t, s.ID)
				r.open(t, s.ID)

				stats := r.chain.SessionSignalStats()
				assert.Equal(t, 2, stats.Open)
				assert.EqualValues(t, 2, stats.RefusedByCap)
				assert.False(t, stats.BusSubscribed, "the default bus has no subscription")
			},
		},
		{
			name: "a read that panics on an open stream counts, as one at admission does",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				r.userAnswers(func(context.Context) (*identity.Details, error) { panic(errors.New(streamSecret)) })
				advanceUntil(t, 20*time.Second, "the panic", stream.closed)

				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name: "a read that panics after its timeout has already counted, and counts once",
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)

				let := make(chan struct{})
				r.userAnswers(func(context.Context) (*identity.Details, error) {
					<-let

					panic(errors.New(streamSecret))
				})

				advanceUntil(t, 30*time.Second, "the timeout", func() bool {
					return r.chain.SessionSignalStats().ReloadFailures > 0
				})

				close(let)
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name: "reload failures, and those in a row, which a success gives back",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				r.openN(t, s, 2)

				r.failListing(true)
				advance(20 * time.Second)

				stats := r.chain.SessionSignalStats()
				assert.EqualValues(t, 2, stats.ReloadFailures, "one per stream's beat")
				assert.EqualValues(t, 2, stats.ConsecutiveReloadFailures, "it scales with the open streams")

				r.failListing(false)
				advance(20 * time.Second)

				stats = r.chain.SessionSignalStats()
				assert.EqualValues(t, 2, stats.ReloadFailures)
				assert.Zero(t, stats.ConsecutiveReloadFailures)
			},
		},
		{
			name: "a dependency failure at admission counts as a reload failure, and never as one in a row",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)

				r.failLoad()
				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)

				stats := r.chain.SessionSignalStats()
				assert.EqualValues(t, 1, stats.ReloadFailures)
				assert.Zero(t, stats.ConsecutiveReloadFailures)
			},
		},
		{
			name:  "a stream's own drops, apart from the bus's",
			setup: streamSetup{signals: withSignal},
			assert: func(t *testing.T, r *streamRig) {
				stream := r.open(t, r.signIn(t).ID)
				writing := stream.w.holdWrites()

				defer close(writing)

				hub := httpsec.SignalHubProbeOf(r.chain)

				hub.Deliver(changed)
				synctest.Wait()

				for range httpsec.StreamQueueSize + 1 {
					hub.Deliver(changed)
				}

				stats := r.chain.SessionSignalStats()
				assert.EqualValues(t, 1, stats.StreamDropped)
				assert.Zero(t, stats.BusDropped)
			},
		},
	})

	t.Run("a client that left during its authenticator's read is no failure of a store", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			var leave context.CancelFunc

			r := newStreamRig(t, streamSetup{requestCtx: func(ctx context.Context) context.Context {
				ctx, leave = context.WithCancel(ctx)

				return ctx
			}})
			s := r.signIn(t)

			hook := func(ctx context.Context) error {
				leave()

				return ctx.Err()
			}
			r.loadHook.Store(&hook)

			stream := r.open(t, s.ID)

			assert.Empty(t, stream.frames())
			assert.Zero(t, r.chain.SessionSignalStats().ReloadFailures)
			assert.NotContains(t, r.logs.String(), "a dependency failed")
		})
	})

	t.Run("a consumer's bus: its subscription, its drops and its failures", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) {
			var publishes atomic.Int64

			bus := NewMockSignalBus(gomock.NewController(t))
			bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, _ func(httpsec.SignalEnvelope)) error {
					<-ctx.Done()

					return ctx.Err()
				})
			bus.EXPECT().Publish(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
				func(ctx context.Context, _ httpsec.SignalEnvelope) error {
					if publishes.Add(1) == 1 {
						return errors.New("the bus refused")
					}

					<-ctx.Done()

					return ctx.Err()
				})

			r := newStreamRig(t, streamSetup{signals: httpsec.SessionSignals{Bus: bus, BusQueue: 1}})
			r.open(t, r.signIn(t).ID)

			assert.True(t, r.chain.SessionSignalStats().BusSubscribed)

			hub := httpsec.SignalHubProbeOf(r.chain)
			envelope := httpsec.SignalEnvelope{User: "u-1", Name: "app.x", Data: []byte(`{}`)}

			require.NoError(t, hub.Raise(envelope))
			synctest.Wait()
			assert.EqualValues(t, 1, r.chain.SessionSignalStats().BusPublishFailures)

			// One held in Publish, one queued, and the rest over the queue.
			require.NoError(t, hub.Raise(envelope))
			synctest.Wait()
			require.NoError(t, hub.Raise(envelope))
			require.ErrorIs(t, hub.Raise(envelope), httpsec.ErrSignalsBusy)

			assert.EqualValues(t, 1, r.chain.SessionSignalStats().BusDropped)

			require.NoError(t, r.chain.CloseSessionSignals(t.Context()))
			synctest.Wait()

			assert.False(t, r.chain.SessionSignalStats().BusSubscribed)
		})
	})
}

// TestSessionSignals_Heartbeat_AnswerWithTheTimeout pins that a read's answer landing with its
// timeout is an answer. Held in a write, the body finds both ready, and its select picks at random,
// so a stream that took the timeout without looking would wait another beat in half of these rounds.
func TestSessionSignals_Heartbeat_AnswerWithTheTimeout(t *testing.T) {
	t.Parallel()

	setup := streamSetup{idle: 3 * time.Hour, signals: httpsec.SessionSignals{
		MaxAge:  httpsec.NoMaxAge,
		Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
	}}

	for round := range 16 {
		t.Run(strconv.Itoa(round), func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, setup)
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				held := r.holdListings(t)
				held.waitForRead(t)

				writing := stream.w.holdWrites()

				httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{
					User: "u-1", Name: "credential_changed", Data: []byte(`{"kind":"passkey"}`),
				})
				synctest.Wait()

				require.NoError(t, r.inner.Delete(t.Context(), s.ID))

				held.letGo()
				synctest.Wait()

				// Past ReloadTimeout, half of the 15-second heartbeat, and short of the next beat.
				advance(8 * time.Second)

				close(writing)
				synctest.Wait()

				advance(httpsec.StreamReportGrace)
				r.requireEnded(t, stream, "ended")

				failures, _ := httpsec.SignalReloadCounts(r.chain)
				assert.Zero(t, failures, "an answer was taken for a timeout")
			})
		})
	}
}

// TestSessionSignals_BusUntrusted_Stream is what reaches a client of what a bus delivers: nothing a
// hub drops, and only what a stream is allowed to carry.
func TestSessionSignals_BusUntrusted_Stream(t *testing.T) {
	t.Parallel()

	large := `{"pad":"` + strings.Repeat("x", 9*1024) + `"}`

	type testCase struct {
		name     string
		envelope httpsec.SignalEnvelope
	}

	cases := []testCase{
		{name: "an unknown library name", envelope: httpsec.SignalEnvelope{Name: "session_stolen", Data: []byte(`{}`)}},
		{name: "a timer's signal", envelope: httpsec.SignalEnvelope{Name: "session_expiring", Data: []byte(`{}`)}},
		{name: "malformed data", envelope: httpsec.SignalEnvelope{Name: "credential_changed", Data: []byte(`{"kind":`)}},
		{name: "a library signal of 9 KiB", envelope: httpsec.SignalEnvelope{Name: "credential_changed", Data: []byte(large)}},
		{name: "a consumer's signal outside the name's limits", envelope: httpsec.SignalEnvelope{Name: "app.X", Data: []byte(`{}`)}},
		{name: "a name that would break the stream", envelope: httpsec.SignalEnvelope{Name: "app.x\nevent: session_ended", Data: []byte(`{}`)}},
		{name: "a consumer's signal of 9 KiB", envelope: httpsec.SignalEnvelope{Name: "app.x", Data: []byte(large)}},
		{name: "a consumer's signal with raw line breaks", envelope: httpsec.SignalEnvelope{Name: "app.x", Data: []byte("{\n}")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, streamSetup{signals: httpsec.SessionSignals{
					Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalSessionExpiring, httpsec.SignalCredentialChanged},
				}})
				stream := r.open(t, r.signIn(t).ID)

				envelope := tc.envelope
				envelope.User = "u-1"

				httpsec.SignalHubProbeOf(r.chain).Deliver(envelope)
				synctest.Wait()

				assert.Equal(t, []string{"session"}, stream.sent(), "what a bus delivered reached a client")
				r.requireLive(t, stream)
			})
		})
	}
}

// requireEndReason asserts s said session_ended once, naming reason.
func requireEndReason(t *testing.T, s *riggedStream, reason string) {
	t.Helper()

	ended := s.events("session_ended")
	require.Len(t, ended, 1, "what it sent: %v", s.sent())
	assert.JSONEq(t, `{"reason":"`+reason+`"}`, ended[0].Data)
}

// TestSessionSignals_Bus_Stream is routing as a client sees it: each row ends sign-ins through the
// session manager, as a real end does, and reads who heard.
func TestSessionSignals_Bus_Stream(t *testing.T) {
	t.Parallel()

	federated := session.WithExternalSession("provider", "https://idp.example", "upstream-sid", "raw-id-token")

	type fixture struct {
		one, two, other                   *session.Session
		oneStream, twoStream, otherStream *riggedStream

		// lists is how many listings had run before the end.
		lists int64
	}

	type testCase struct {
		name   string
		create []session.CreateOption
		end    func(t *testing.T, r *streamRig, f *fixture)
		assert func(t *testing.T, r *streamRig, f *fixture)
	}

	cases := []testCase{
		{
			name: "ending one sign-in leaves the user's other sign-in's stream open, and any other user's",
			end: func(t *testing.T, r *streamRig, f *fixture) {
				_, err := r.sessions.Logout(t.Context(), f.one.UserID, f.one.FamilyID)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, r *streamRig, f *fixture) {
				assert.Equal(t, []string{"session", "session_ended"}, f.oneStream.sent())
				assert.Equal(t, []string{"session"}, f.twoStream.sent())
				assert.Equal(t, []string{"session"}, f.otherStream.sent())
				assert.False(t, f.twoStream.closed())
				assert.False(t, f.otherStream.closed())
			},
		},
		{
			name: "a family-only report reaches its family",
			end: func(t *testing.T, r *streamRig, f *fixture) {
				_, err := r.sessions.RevokeFamily(t.Context(), f.one.FamilyID)
				require.NoError(t, err)
			},
			assert: func(t *testing.T, r *streamRig, f *fixture) {
				assert.Equal(t, []string{"session", "session_ended"}, f.oneStream.sent())
				assert.False(t, f.twoStream.closed())
			},
		},
		{
			name: "a user-wide report that spared a sign-in spares its streams",
			end: func(t *testing.T, r *streamRig, f *fixture) {
				_, err := r.sessions.EndOtherSignIns(t.Context(), f.two.UserID, r.stored(t, f.two.ID))
				require.NoError(t, err)
			},
			assert: func(t *testing.T, r *streamRig, f *fixture) {
				requireEndReason(t, f.oneStream, "all_ended")
				assert.Equal(t, []string{"session"}, f.twoStream.sent(), "the kept sign-in heard of it")
				assert.EqualValues(t, 1, r.lists.Load()-f.lists, "the kept sign-in's stream was woken to read")
				assert.False(t, f.twoStream.closed())
				assert.Equal(t, []string{"session"}, f.otherStream.sent())
			},
		},
		{
			name: "a user-wide report that spared nothing wakes all of them",
			end: func(t *testing.T, r *streamRig, f *fixture) {
				require.NoError(t, r.sessions.DeleteByUser(t.Context(), f.one.UserID))
			},
			assert: func(t *testing.T, r *streamRig, f *fixture) {
				requireEndReason(t, f.oneStream, "all_ended")
				requireEndReason(t, f.twoStream, "all_ended")
				assert.Equal(t, []string{"session"}, f.otherStream.sent())
			},
		},
		{
			name:   "an upstream session's report reaches the streams holding its digest, and the raw value stays out",
			create: []session.CreateOption{federated},
			end: func(t *testing.T, r *streamRig, _ *fixture) {
				_, err := r.sessions.DeleteByExternalSession(t.Context(), "https://idp.example", "upstream-sid")
				require.NoError(t, err)
			},
			assert: func(t *testing.T, r *streamRig, f *fixture) {
				requireEndReason(t, f.oneStream, "provider_logout")
				assert.False(t, f.twoStream.closed())
				assert.NotContains(t, r.logs.String(), "upstream-sid")
			},
		},
		{
			name: "once every stream has left, no registry key remains",
			end: func(t *testing.T, r *streamRig, f *fixture) {
				f.oneStream.cancel()
				f.twoStream.cancel()
				f.otherStream.cancel()
			},
			assert: func(t *testing.T, r *streamRig, _ *fixture) {
				assert.Equal(t, httpsec.RegistryKeys{}, httpsec.SignalHubProbeOf(r.chain).Registry().Keys())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, streamSetup{})

				f := &fixture{one: r.signIn(t, tc.create...), two: r.signIn(t), other: r.signInOf(t, "u-2")}
				f.oneStream = r.open(t, f.one.ID)
				f.twoStream = r.open(t, f.two.ID)
				f.otherStream = r.open(t, f.other.ID)
				f.lists = r.lists.Load()

				r.act(func() { tc.end(t, r, f) })

				tc.assert(t, r, f)
			})
		})
	}
}

// TestSessionSignals_BusOutage_Stream is what a client sees of a bus that is down: the store still
// decides, so the heartbeat still ends its stream.
func TestSessionSignals_BusOutage_Stream(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		bus  func(t *testing.T) httpsec.SignalBus
	}

	cases := []testCase{
		{
			name: "a Subscribe that always fails, and a Publish that hangs",
			bus: func(t *testing.T) httpsec.SignalBus {
				t.Helper()

				bus := NewMockSignalBus(gomock.NewController(t))
				bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).AnyTimes().Return(errors.New("the bus is down"))
				bus.EXPECT().Publish(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
					func(ctx context.Context, _ httpsec.SignalEnvelope) error {
						<-ctx.Done()

						return ctx.Err()
					})

				return bus
			},
		},
		{
			name: "a Subscribe and a Publish that both panic",
			bus: func(t *testing.T) httpsec.SignalBus {
				t.Helper()

				bus := NewMockSignalBus(gomock.NewController(t))
				bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
					func(context.Context, func(httpsec.SignalEnvelope)) error { panic(errors.New(streamSecret)) })
				bus.EXPECT().Publish(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
					func(context.Context, httpsec.SignalEnvelope) error { panic(errors.New(streamSecret)) })

				return bus
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, streamSetup{signals: httpsec.SessionSignals{Bus: tc.bus(t)}})
				t.Cleanup(func() { assert.NoError(t, r.chain.CloseSessionSignals(context.WithoutCancel(t.Context()))) })

				s := r.signIn(t)
				stream := r.open(t, s.ID)

				began := time.Now()

				r.act(func() {
					_, err := r.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
					require.NoError(t, err)
				})

				assert.Zero(t, time.Since(began), "a bus that is down held the logout up")

				advanceUntil(t, 20*time.Second, "the heartbeat", stream.closed)

				r.requireEnded(t, stream, "ended")
				assert.NotContains(t, r.logs.String(), streamSecret)
			})
		})
	}
}

// TestSessionSignals_SlowStream_Streams is a stream that has stopped reading, beside one that has
// not. What raises the signals is the hub's own path, Raise, which is what the session manager and
// the chain's endpoints call: Chain.PublishSignal comes later, and will call it too.
func TestSessionSignals_SlowStream_Streams(t *testing.T) {
	t.Parallel()

	setup := streamSetup{signals: httpsec.SessionSignals{
		Signals: []httpsec.Signal{httpsec.SignalSessionEnded, httpsec.SignalCredentialChanged},
	}}

	envelope := func(n int) httpsec.SignalEnvelope {
		return httpsec.SignalEnvelope{User: "u-1", Name: "app.ping", Data: []byte(`{"n":` + strconv.Itoa(n) + `}`)}
	}

	type testCase struct {
		name   string
		assert func(t *testing.T, r *streamRig, s *session.Session, slow, fast *riggedStream, writing chan struct{})
	}

	cases := []testCase{
		{
			name: "it drops its own, the other gets all, and the publisher waits for neither",
			assert: func(t *testing.T, r *streamRig, _ *session.Session, slow, fast *riggedStream, writing chan struct{}) {
				defer close(writing)

				assert.Len(t, fast.events("app.ping"), 100, "the other stream lost one")

				for n, event := range fast.events("app.ping") {
					assert.JSONEq(t, `{"n":`+strconv.Itoa(n)+`}`, event.Data, "in order")
				}

				assert.Empty(t, slow.events("app.ping"), "the stalled stream's write was let through")
				assert.EqualValues(t, 100-1-httpsec.StreamQueueSize, r.chain.SessionSignalStats().StreamDropped,
					"one in its write, its queue full, and the rest its own to lose")
			},
		},
		{
			name: "its sign-in ending still reaches it, once it can write",
			assert: func(t *testing.T, r *streamRig, s *session.Session, slow, fast *riggedStream, writing chan struct{}) {
				r.act(func() {
					_, err := r.sessions.Logout(t.Context(), s.UserID, s.FamilyID)
					require.NoError(t, err)
				})

				assert.Len(t, fast.events("session_ended"), 1)
				assert.False(t, slow.closed(), "it is still in its write")

				close(writing)
				advanceUntil(t, 20*time.Second, "the end", slow.closed)

				assert.Len(t, slow.events("session_ended"), 1, "session_ended was dropped: %v", slow.sent())

				last := slow.frames()[len(slow.frames())-1]
				assert.Equal(t, "session_ended", last.Name)
				assert.JSONEq(t, `{"reason":"logout"}`, last.Data)
				assert.Zero(t, r.openStreams())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, setup)
				s := r.signIn(t)

				slow, fast := r.open(t, s.ID, "signals=session_ended,app.ping"), r.open(t, s.ID, "signals=session_ended,app.ping")
				writing := slow.w.holdWrites()
				hub := httpsec.SignalHubProbeOf(r.chain)

				began := time.Now()

				for n := range 100 {
					require.NoError(t, hub.Raise(envelope(n)))
					synctest.Wait()
				}

				assert.Zero(t, time.Since(began), "a stream that does not read held the publisher up")

				tc.assert(t, r, s, slow, fast, writing)
			})
		})
	}
}

// TestSessionSignals_Caps_Places is a place being held and freed by what a real stream does.
func TestSessionSignals_Caps_Places(t *testing.T) {
	t.Parallel()

	// refuseAfter is a consumer's interceptor outside the endpoint, refusing once the endpoint has
	// returned, which on net/http is once its stream has ended.
	refuseAfter := func(*streamRig) []httpsec.Option {
		return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
			func(ex *httpsec.Exchange, next httpsec.Next) error {
				if err := next(ex); err != nil {
					return err
				}

				return httpsec.ErrAuthenticationRequired
			}), httpsec.After(httpsec.OrderBearerToken))}
	}

	// requireExactlyFreed shows the place was freed once and not twice: with one more freed than was
	// taken, a fifth stream would fit, and with none freed, the fourth would not.
	requireExactlyFreed := func(t *testing.T, r *streamRig, s *session.Session) {
		t.Helper()

		assert.Zero(t, r.openStreams(), "the place was not freed")

		r.openN(t, s, 4)
		requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
		assert.Equal(t, 4, r.openStreams())
	}

	runStreamCases(t, []streamCase{
		{
			name: "a client that leaves frees its place, for a new stream of that sign-in",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				open := r.openN(t, s, 4)

				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)

				open[0].cancel()
				synctest.Wait()

				assert.Equal(t, 3, r.openStreams())
				assert.Equal(t, []string{"session"}, r.open(t, s.ID).sent())
			},
		},
		{
			name:  "a chain refusing after Stream, on net/http, frees it once",
			setup: streamSetup{opts: refuseAfter},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				stream.cancel()
				synctest.Wait()

				require.True(t, stream.closed())
				requireExactlyFreed(t, r, s)
			},
		},
		{
			name: "a body that panics frees it once, and the process runs on",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.userAnswers(func(context.Context) (*identity.Details, error) { panic(errors.New(streamSecret)) })

				advanceUntil(t, 20*time.Second, "the panic", stream.closed)
				assert.Equal(t, []string{"session"}, stream.sent())
				assert.NotContains(t, r.logs.String(), streamSecret)
				assert.Equal(t, "reload", streamLogRecord(t, r.logs.String(), "panic")["phase"])

				r.userHook.Store(nil)
				requireExactlyFreed(t, r, s)
			},
		},
		{
			name: "a stream's own code that panics frees it once",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.clock.armed.Store(true)
				httpsec.SignalHubProbeOf(r.chain).Registry().DeliverEndToFamily(s.FamilyID, "", time.Time{})
				synctest.Wait()
				r.clock.armed.Store(false)

				require.True(t, stream.closed())
				assert.Equal(t, "stream", streamLogRecord(t, r.logs.String(), "panic")["phase"])

				requireExactlyFreed(t, r, s)
			},
		},
		{
			name:  "a body that cannot write frees it once",
			setup: streamSetup{signals: httpsec.SessionSignals{Heartbeat: 5 * time.Second}},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				stream := r.open(t, s.ID)

				stream.w.failWrite.Store(true)
				advanceUntil(t, 10*time.Second, "the failed write", stream.closed)

				requireExactlyFreed(t, r, s)
			},
		},
	})

	// Two for the last place, held together at the read that comes just before it.
	for round := range 8 {
		t.Run("two racing for the last place: one opens, the other gets only a retry, "+strconv.Itoa(round), func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				r := newStreamRig(t, streamSetup{})
				s := r.signIn(t)
				r.openN(t, s, 3)

				held := r.holdListings(t)
				racers := []*riggedStream{r.open(t, s.ID), r.open(t, s.ID)}

				require.EqualValues(t, 2, held.entered.Load(), "both reach the barrier")

				held.letGo()
				synctest.Wait()

				var opened, refused int

				// Both are 200, so it is the first event that tells them apart.
				for _, racer := range racers {
					assert.Equal(t, http.StatusOK, racer.status())

					if events := racer.sent(); len(events) > 0 {
						assert.Equal(t, []string{"session"}, events)

						opened++

						continue
					}

					requireOnlyRetry(t, racer, busyLeast, busyMost)

					refused++
				}

				assert.Equal(t, 1, opened)
				assert.Equal(t, 1, refused)
				assert.Equal(t, 4, r.openStreams())
				assert.EqualValues(t, 1, refusedCount(r))
			})
		})
	}

	t.Run("a chain refusing after Stream, where the body runs after it, frees it once and writes nothing", func(t *testing.T) {
		t.Parallel()

		f := newSignalsFixture(t, signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
			return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
				func(ex *httpsec.Exchange, next httpsec.Next) error {
					if err := next(ex); err != nil {
						return err
					}

					return httpsec.ErrAuthenticationRequired
				}), httpsec.After(httpsec.OrderBearerToken))}
		}})

		w := &endedContextWriter{stubWriter: &stubWriter{}}
		s := f.signIn(t, "u-1")

		err := f.chain.Assemble(func(*httpsec.Exchange) error { return nil })(httpsec.NewExchange(t.Context(), stubRequest{
			method:   http.MethodGet,
			path:     httpsec.DefaultSessionSignalsPath,
			clientIP: streamClient,
			headers:  map[string]string{"Authorization": "Bearer " + s.ID},
		}, w))

		require.ErrorIs(t, err, httpsec.ErrAuthenticationRequired)
		assert.Empty(t, w.wrote.String())
		assert.Zero(t, f.chain.SessionSignalStats().Open)
	})

	t.Run("a cross-site refusal leaves the sign-in's count unchanged, however many", func(t *testing.T) {
		t.Parallel()

		chain := crossSiteChain{cors: corsNamedWithCredentials}
		f := newSignalsFixture(t, chain.setup())

		s := f.signIn(t, "u-1")

		for range 3 {
			resp, _ := f.openStream(t, s.ID)
			requireStreamHead(t, resp)
		}

		for range 8 {
			resp, _ := f.openStream(t, s.ID, fetchHeaders("cross-site", crossSiteForeign))
			requireNoStream(t, resp, http.StatusForbidden)
		}

		stats := f.chain.SessionSignalStats()
		assert.Equal(t, 3, stats.Open, "a foreign page holds the victim's places")
		assert.Zero(t, stats.RefusedByCap)

		resp, _ := f.openStream(t, s.ID)
		requireStreamHead(t, resp)
	})
}

// TestSessionSignals_Caps_RequestContextEnded is a request whose context ended and whose client is
// still there, which a request for the stream answers as any other: a retry written whatever ended it.
// Only a client's own leaving is no failure.
func TestSessionSignals_Caps_RequestContextEnded(t *testing.T) {
	t.Parallel()

	// withDeferredCancel is a consumer's interceptor with the ordinary deferred cancel, inside the step.
	withDeferredCancel := func(*streamRig) []httpsec.Option {
		return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
			func(ex *httpsec.Exchange, next httpsec.Next) error {
				ctx, cancel := context.WithTimeout(ex.Context(), time.Minute)
				defer cancel()

				ex.SetContext(ctx)

				return next(ex)
			}), httpsec.After(httpsec.OrderCSRF))}
	}

	// serverDeadline is a request deadline a server sets, with its client still there. The parent's
	// cancel, which every stream of the rig has, ends its timer.
	serverDeadline := func(ctx context.Context) context.Context {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		context.AfterFunc(ctx, cancel)

		return ctx
	}

	loadWaitsForItsContext := func(r *streamRig) {
		hook := func(ctx context.Context) error {
			<-ctx.Done()

			return ctx.Err()
		}
		r.loadHook.Store(&hook)
	}

	runStreamCases(t, []streamCase{
		{
			name:  "an interceptor's deferred cancel leaves a cap's retry",
			setup: streamSetup{signals: httpsec.SessionSignals{MaxPerSignIn: 1}, opts: withDeferredCancel},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				r.openN(t, s, 1)
				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
			},
		},
		{
			name:  "an interceptor's deferred cancel leaves a dependency failure's retry",
			setup: streamSetup{opts: withDeferredCancel},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				r.failLoad()
				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
			},
		},
		{
			name:  "an interceptor's deferred cancel leaves a closing replica's retry",
			setup: streamSetup{opts: withDeferredCancel},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				require.NoError(t, <-r.closing(t.Context()))
				requireOnlyRetry(t, r.open(t, s.ID), time.Second, 15*time.Second)
			},
		},
		{
			name:  "a server's request deadline is a dependency failure, and its client gets a retry",
			setup: streamSetup{requestCtx: serverDeadline},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				loadWaitsForItsContext(r)

				stream := r.open(t, s.ID)
				advance(3 * time.Second)

				require.Equal(t, http.StatusOK, stream.status(), "a live client's EventSource stops for good on this")
				requireOnlyRetry(t, stream, busyLeast, busyMost)
				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name:  "a server's deadline with an interceptor's deferred cancel is the same failure",
			setup: streamSetup{requestCtx: serverDeadline, opts: withDeferredCancel},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				loadWaitsForItsContext(r)

				stream := r.open(t, s.ID)
				advance(3 * time.Second)

				requireOnlyRetry(t, stream, busyLeast, busyMost)
				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name: "a client that leaves is told nothing, and is no failure",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				loadWaitsForItsContext(r)

				stream := r.open(t, s.ID)
				stream.cancel()
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Empty(t, stream.frames(), "a retry for a client that has gone")
				assert.Zero(t, r.chain.SessionSignalStats().ReloadFailures, "a hang-up says nothing about a store")
			},
		},
	})
}

// errGeoBlocked is a consumer's own refusal, which StatusForError does not know and maps to 500.
var errGeoBlocked = errors.New("consumer: refused by geography")

// TestSessionSignals_Caps_RetryableError is a failure a consumer knows is no outage. By default every
// 5xx-mapped failure on the stream's path is retried; RetryableError lets one through to the chain's
// error mapping.
func TestSessionSignals_Caps_RetryableError(t *testing.T) {
	t.Parallel()

	// watched is what a row sees of the consumer's side.
	type watched struct {
		handled atomic.Pointer[error]
		asked   atomic.Int64
		logs    lockedBuffer
	}

	type testCase struct {
		name      string
		signals   httpsec.SessionSignals
		refuse    error
		wrap      func(http.Handler) http.Handler
		retryable func(error) bool
		assert    func(t *testing.T, f *signalsFixture, w *watched)
	}

	never := func(error) bool { return false }
	always := func(error) bool { return true }

	notHandled := func(t *testing.T, w *watched) {
		t.Helper()

		assert.Nil(t, w.handled.Load(), "the error handler was called")
	}

	cases := []testCase{
		{
			name:   "by default a consumer's own refusal is retried",
			refuse: errGeoBlocked,
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
				notHandled(t, w)
				assert.EqualValues(t, 1, f.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name:      "RetryableError returning false reaches the error handler, and counts no failure",
			refuse:    errGeoBlocked,
			retryable: never,
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

				requireNoStream(t, resp, http.StatusForbidden)
				require.NotNil(t, w.handled.Load(), "the consumer's error handler never heard of its own refusal")
				assert.ErrorIs(t, *w.handled.Load(), errGeoBlocked)
				assert.EqualValues(t, 1, w.asked.Load())
				assert.Zero(t, f.chain.SessionSignalStats().ReloadFailures, "a refusal was counted as a store's failure")
				assert.NotContains(t, w.logs.String(), "a dependency failed")
			},
		},
		{
			name:      "RetryableError returning true is retried, and is told the error",
			refuse:    errGeoBlocked,
			retryable: func(err error) bool { return errors.Is(err, errGeoBlocked) },
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
				notHandled(t, w)
				assert.EqualValues(t, 1, f.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name:   "a RetryableError that panics is logged without its value, and the failure retried",
			refuse: errGeoBlocked,
			retryable: func(error) bool {
				panic(errors.New(streamSecret))
			},
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
				notHandled(t, w)
				assert.NotContains(t, w.logs.String(), streamSecret)
				assert.Contains(t, w.logs.String(), "a panic was recovered")
			},
		},
		{
			name:      "it is not asked about what a cap answers",
			signals:   httpsec.SessionSignals{MaxPerSignIn: 1},
			retryable: never,
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				s := f.signIn(t, "u-1")

				first, _ := f.openStream(t, s.ID)
				require.Equal(t, http.StatusOK, first.StatusCode)

				line := make([]byte, 16)
				_, err := first.Body.Read(line)
				require.NoError(t, err)

				second, _ := f.openStream(t, s.ID)
				requireOnlyRetryResponse(t, second, busyLeast, busyMost)
				assert.Zero(t, w.asked.Load())
			},
		},
		{
			name:      "it is not asked about what maps below a 5xx",
			refuse:    policy.ErrTooManySessions,
			retryable: always,
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

				requireNoStream(t, resp, http.StatusForbidden)
				assert.Zero(t, w.asked.Load())
				assert.ErrorIs(t, *w.handled.Load(), policy.ErrTooManySessions)
			},
		},
		{
			name: "it is not asked about a writer that cannot stream",
			wrap: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(unflushableWriter{w}, r)
				})
			},
			retryable: always,
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

				assert.Equal(t, http.StatusForbidden, resp.StatusCode)
				assert.Zero(t, w.asked.Load())
				assert.ErrorIs(t, *w.handled.Load(), httpsec.ErrStreamingUnsupported)
			},
		},
		{
			name:      "it is not asked on any other path",
			refuse:    errGeoBlocked,
			retryable: always,
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				resp := f.send(t, t.Context(), http.MethodGet, "/orders", f.signIn(t, "u-1").ID)

				requireNoStream(t, resp, http.StatusForbidden)
				assert.Zero(t, w.asked.Load())
			},
		},
		{
			name:      "after a close, a refusal it lets through stays a refusal",
			refuse:    errGeoBlocked,
			retryable: never,
			assert: func(t *testing.T, f *signalsFixture, w *watched) {
				s := f.signIn(t, "u-1")
				require.NoError(t, f.chain.CloseSessionSignals(t.Context()))

				resp, _ := f.openStream(t, s.ID)

				requireNoStream(t, resp, http.StatusForbidden)
				assert.ErrorIs(t, *w.handled.Load(), errGeoBlocked)
			},
		},
		{
			name:      "after a close, what it retries is told what a closing replica tells",
			refuse:    errGeoBlocked,
			retryable: always,
			assert: func(t *testing.T, f *signalsFixture, _ *watched) {
				s := f.signIn(t, "u-1")
				require.NoError(t, f.chain.CloseSessionSignals(t.Context()))

				resp, _ := f.openStream(t, s.ID)

				assert.True(t, resp.Close, "a keep-alive connection comes back here")
				requireOnlyRetryResponse(t, resp, time.Second, 15*time.Second)
				assert.Zero(t, f.chain.SessionSignalStats().ReloadFailures)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := &watched{}

			signals := tc.signals
			if tc.retryable != nil {
				signals.RetryableError = func(err error) bool {
					w.asked.Add(1)

					return tc.retryable(err)
				}
			}

			f := newSignalsFixture(t, signalsSetup{
				signals:     signals,
				wrapHandler: tc.wrap,
				opts: func(*signalsFixture) []httpsec.Option {
					opts := []httpsec.Option{
						httpsec.WithLogger(slog.New(slog.NewJSONHandler(&w.logs, nil))),
						httpsec.WithErrorHandler(func(rw http.ResponseWriter, _ *http.Request, err error) {
							w.handled.Store(&err)
							rw.WriteHeader(http.StatusForbidden)
						}),
					}

					if tc.refuse == nil {
						return opts
					}

					return append(opts, httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
						func(*httpsec.Exchange, httpsec.Next) error { return tc.refuse },
					), httpsec.After(httpsec.OrderBearerToken)))
				},
			})

			tc.assert(t, f, w)
		})
	}
}

// TestSessionSignals_Caps_AtTheStream is what shares the call to the stream with no store failing: the
// slot the answer's step takes, and a place taken for a stream that never ran.
func TestSessionSignals_Caps_AtTheStream(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  signalsSetup
		assert func(t *testing.T, f *signalsFixture, resp *http.Response)
	}

	cases := []testCase{
		{
			name: "a stream that never ran frees its place",
			setup: signalsSetup{wrapHandler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(unflushableWriter{w}, r)
				})
			}},
			assert: func(t *testing.T, f *signalsFixture, resp *http.Response) {
				assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
				assert.Zero(t, f.chain.SessionSignalStats().Open, "a stream that never ran kept its place")
			},
		},
		{
			name: "a failure just inside CSRF is answered with a retry",
			setup: signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
					func(*httpsec.Exchange, httpsec.Next) error { return errors.New(storeDownText) },
				), httpsec.After(httpsec.OrderCSRF))}
			}},
			assert: func(t *testing.T, _ *signalsFixture, resp *http.Response) {
				requireOnlyRetryResponse(t, resp, busyLeast, busyMost)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, tc.setup)
			resp, _ := f.openStream(t, f.signIn(t, "u-1").ID)

			tc.assert(t, f, resp)
		})
	}
}

// closeAtHead is a writer that starts a close while the head is going out, which is after the place
// was taken and before the body ran. The close has done all it can when the wait returns: it waits on
// the body.
type closeAtHead struct {
	*streamWriter

	chain *httpsec.Chain
}

func (w closeAtHead) WriteHeader(status int) {
	go func() { _ = w.chain.CloseSessionSignals(context.Background()) }() //nolint:gosec // it returns when the body it waits on has

	synctest.Wait()

	w.streamWriter.WriteHeader(status)
}

// TestSessionSignals_Close_AStreamAdmittedBeforeItSendsNoEvent is a stream that has a place when a close
// comes, and has sent nothing yet: it closes without an event as every other does.
func TestSessionSignals_Close_AStreamAdmittedBeforeItSendsNoEvent(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		r := newStreamRig(t, streamSetup{})
		s := r.signIn(t)

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultSessionSignalsPath, nil)
		req.RemoteAddr = streamClient + ":4242"
		req.Header.Set("Authorization", "Bearer "+s.ID)

		w := &streamWriter{header: http.Header{}}
		done := make(chan struct{})
		before := r.counted.loads.Load()

		go func() {
			defer close(done)

			r.handler.ServeHTTP(closeAtHead{streamWriter: w, chain: r.chain}, req)
		}()

		<-done
		r.loadsByTest.Add(r.counted.loads.Load() - before)

		stream := &riggedStream{w: w, cancel: func() {}, done: done}

		assert.Empty(t, stream.sent(), "a stream told to close before its first byte sent an event")
		lastRetry(t, stream)
		synctest.Wait()
		assert.Zero(t, r.openStreams())
	})
}

// closedOverAServer is a closed chain behind a real server of either protocol, and a credential.
func closedOverAServer(t *testing.T, h2 bool, downstream http.Handler) (*httptest.Server, *httpsec.Chain, string) {
	t.Helper()

	sessions := must.Must(session.New(
		session.WithStore(must.Must(session.NewMemoryStore())),
		session.WithIdleTimeout(30*time.Minute),
		session.WithAbsoluteTimeout(12*time.Hour),
	))

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(storedUser(), nil)

	chain := must.Must(httpsec.New(
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
	))

	srv := httptest.NewUnstartedServer(chain.Middleware()(downstream))

	if h2 {
		srv.EnableHTTP2 = true
		srv.StartTLS()
		srv.Client().Transport.(*http.Transport).TLSClientConfig = &tls.Config{ //nolint:gosec // the test's own server
			InsecureSkipVerify: true, NextProtos: []string{"h2"},
		}
	} else {
		srv.Start()
	}

	t.Cleanup(srv.Close)

	s := must.Must(sessions.Create(t.Context(), identity.UserID("u-1"), session.WithFirstFactor(factor.Password)))

	return srv, chain, s.ID
}

// TestSessionSignals_Close_ConnectionOnTheWire is what Connection: close does to a closing replica's
// connection, on each protocol. Go's HTTP/2 server takes it as a graceful end of the whole connection: a
// GOAWAY, so a client's next request of any kind goes on a new connection, which a load balancer can send
// elsewhere.
func TestSessionSignals_Close_ConnectionOnTheWire(t *testing.T) {
	t.Parallel()

	type asked struct {
		resp   *http.Response
		reused bool
	}

	type testCase struct {
		name   string
		h2     bool
		assert func(t *testing.T, stream asked, next func() asked)
	}

	cases := []testCase{
		{
			name: "HTTP/1.1: the connection closes with the response",
			assert: func(t *testing.T, stream asked, next func() asked) {
				assert.Equal(t, "HTTP/1.1", stream.resp.Proto)
				assert.True(t, stream.resp.Close, "Connection: close")
				assert.False(t, next().reused, "the connection came back")
			},
		},
		{
			name: "HTTP/2: the header is not sent, and a GOAWAY gives up the connection",
			h2:   true,
			assert: func(t *testing.T, stream asked, next func() asked) {
				assert.Equal(t, "HTTP/2.0", stream.resp.Proto)
				assert.Empty(t, stream.resp.Header.Get("Connection"), "forbidden on HTTP/2")
				assert.True(t, stream.reused, "the stream's own request did not share the connection, so this row shows nothing")

				// The client hears a GOAWAY when it hears it, so ask until a request has a new connection.
				deadline := time.Now().Add(streamBound)

				for next().reused {
					require.True(t, time.Now().Before(deadline), "the connection was never given up")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, chain, sid := closedOverAServer(t, tc.h2, http.NotFoundHandler())

			ask := func(target string) asked {
				var reused bool

				ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
					GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
				})

				req := must.Must(http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+target, nil))
				req.Header.Set("Authorization", "Bearer "+sid)

				resp, err := srv.Client().Do(req)
				require.NoError(t, err)

				defer func() { _ = resp.Body.Close() }()

				_, err = io.ReadAll(resp.Body)
				require.NoError(t, err)

				return asked{resp: resp, reused: reused}
			}

			// A connection already there, which the close's answer then goes out on.
			ask("/orders")
			require.NoError(t, chain.CloseSessionSignals(t.Context()))

			tc.assert(t, ask(httpsec.DefaultSessionSignalsPath), func() asked { return ask("/orders") })
		})
	}
}

// TestSessionSignals_Close_HTTP2GoAwaySparesARequestInFlight is what that GOAWAY does to another
// request on the connection: nothing, however long it then takes.
func TestSessionSignals_Close_HTTP2GoAwaySparesARequestInFlight(t *testing.T) {
	t.Parallel()

	// A wait and not an order of events: Go's server allows a closing connection a second before it
	// would cut what is left, so the row has to outlast that.
	const pastGoAwayTimeout = 1500 * time.Millisecond

	entered, release := make(chan struct{}), make(chan struct{})

	srv, chain, sid := closedOverAServer(t, true, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release

		_, _ = w.Write([]byte("done"))
	}))

	require.NoError(t, chain.CloseSessionSignals(t.Context()))

	slow := make(chan string, 1)

	go func() {
		req := must.Must(http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/orders", nil))
		req.Header.Set("Authorization", "Bearer "+sid)

		resp, err := srv.Client().Do(req)
		if err != nil {
			slow <- err.Error()

			return
		}

		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		slow <- string(body)
	}()

	<-entered

	req := must.Must(http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+httpsec.DefaultSessionSignalsPath, nil))
	req.Header.Set("Authorization", "Bearer "+sid)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	assert.Equal(t, "HTTP/2.0", resp.Proto)

	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	time.Sleep(pastGoAwayTimeout)
	close(release)

	assert.Equal(t, "done", <-slow)
}

// TestSessionSignals_Caps_StatsBusSubscribedAfterClose is BusSubscribed's godoc for a bus that ignores
// its context, which the port's godoc allows for: its Subscribe has not returned, and what a close
// ended is not up.
func TestSessionSignals_Caps_StatsBusSubscribedAfterClose(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		stuck := make(chan struct{})
		defer close(stuck)

		bus := NewMockSignalBus(gomock.NewController(t))
		bus.EXPECT().Subscribe(gomock.Any(), gomock.Any()).DoAndReturn(
			func(context.Context, func(httpsec.SignalEnvelope)) error {
				<-stuck

				return nil
			})

		r := newStreamRig(t, streamSetup{signals: httpsec.SessionSignals{Bus: bus}})
		r.open(t, r.signIn(t).ID)
		require.True(t, r.chain.SessionSignalStats().BusSubscribed)

		require.NoError(t, r.chain.CloseSessionSignals(t.Context()))
		synctest.Wait()

		assert.False(t, r.chain.SessionSignalStats().BusSubscribed)
	})
}
