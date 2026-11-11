package httpsec_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/session"
)

// TestSessionSignals_Caps_ContextEndedOnTheWayOut is a live client, a failing store, and a consumer's
// interceptor that ends the context it made on its way out. Nobody left, whatever the context says by
// the time the answer is decided, so each is told to come back.
func TestSessionSignals_Caps_ContextEndedOnTheWayOut(t *testing.T) {
	t.Parallel()

	storeErr := errors.New("the store is down")
	poolCancelled := fmt.Errorf("pool: acquire: %w", context.Canceled)

	// withCause ends the context with the error going out as its cause, which is what makes the
	// failure look like the context's own.
	withCause := func(*streamRig) []httpsec.Option {
		return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
			func(ex *httpsec.Exchange, next httpsec.Next) (err error) {
				ctx, cancel := context.WithCancelCause(ex.Context())
				defer func() { cancel(err) }()

				ex.SetContext(ctx)

				return next(ex)
			}), httpsec.After(httpsec.OrderCSRF))}
	}
	withPlainCancel := func(*streamRig) []httpsec.Option {
		return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
			func(ex *httpsec.Exchange, next httpsec.Next) error {
				ctx, cancel := context.WithCancel(ex.Context())
				defer cancel()

				ex.SetContext(ctx)

				return next(ex)
			}), httpsec.After(httpsec.OrderCSRF))}
	}

	failWith := func(r *streamRig, err error) {
		hook := func(context.Context) error { return err }
		r.loadHook.Store(&hook)
	}

	runStreamCases(t, []streamCase{
		{
			name: "with no consumer's cancel, a store's own Canceled is a failure",
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				failWith(r, poolCancelled)
				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
			},
		},
		{
			name:  "a consumer's cancel on the way out, with the store's error as its cause",
			setup: streamSetup{opts: withCause},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				failWith(r, storeErr)
				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
			},
		},
		{
			name:  "a consumer's plain deferred cancel, with a store's own Canceled",
			setup: streamSetup{opts: withPlainCancel},
			assert: func(t *testing.T, r *streamRig) {
				s := r.signIn(t)
				failWith(r, poolCancelled)
				requireOnlyRetry(t, r.open(t, s.ID), busyLeast, busyMost)
				assert.EqualValues(t, 1, r.chain.SessionSignalStats().ReloadFailures)
			},
		},
	})
}

// closeOnNow is the chain's clock, which starts a close the first time it is read once armed. A
// stream's onTimer and onWake read it after the select chose them and before they say anything, so
// this is CloseSessionSignals landing in that gap.
type closeOnNow struct {
	armed atomic.Bool
	skip  atomic.Int64 // reads to let past once armed: a Deliver stamps its notice from this clock
	chain atomic.Pointer[httpsec.Chain]
	inner clock.Timed
}

func (c *closeOnNow) Now() time.Time {
	if c.armed.Load() && c.skip.Add(-1) < 0 && c.armed.CompareAndSwap(true, false) {
		go func() { _ = c.chain.Load().CloseSessionSignals(context.Background()) }()

		time.Sleep(time.Millisecond) // the bubble's time: the close has run by now
	}

	return c.inner.Now()
}

func (c *closeOnNow) After(d time.Duration) <-chan time.Time { return c.inner.After(d) }

// TestSessionSignals_Close_NoEventAfterTheSelect is a close that lands after the select chose one of
// the two paths to session_ended that take no read's answer. A closing replica ends a stream with no
// event, on these as on a read's.
func TestSessionSignals_Close_NoEventAfterTheSelect(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		act  func(c *closeOnNow, report func())
	}

	cases := []testCase{
		{
			name: "the wait for a report ending",
			act: func(c *closeOnNow, _ func()) {
				c.armed.Store(true)
				advance(httpsec.StreamReportGrace + 10*time.Millisecond)
			},
		},
		{
			name: "a report during the wait",
			act: func(c *closeOnNow, report func()) {
				advance(httpsec.StreamReportGrace / 2)
				c.skip.Store(1)
				c.armed.Store(true)
				report()
				advance(10 * time.Millisecond)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				c := &closeOnNow{}

				r := newStreamRig(t, streamSetup{
					signals:  httpsec.SessionSignals{Heartbeat: 5 * time.Second, Signals: endedOnly},
					ownClock: true,
					opts: func(r *streamRig) []httpsec.Option {
						c.inner = r.clock

						return []httpsec.Option{httpsec.WithClock(c)}
					},
				})
				c.chain.Store(r.chain)

				s := r.signIn(t)
				stream := r.open(t, s.ID)

				r.listsNothing.Store(true)
				r.untilRead(t)

				tc.act(c, func() {
					httpsec.SignalHubProbeOf(r.chain).Deliver(httpsec.SignalEnvelope{
						User: s.UserID, Family: s.FamilyID, Name: string(httpsec.SignalSessionEnded), Reason: "logout",
					})
				})
				synctest.Wait()

				assert.True(t, stream.closed())
				assert.Equal(t, []string{"session"}, stream.sent(), "a stream told to close sent an event")
				lastRetry(t, stream)
			})
		})
	}
}

// TestSessionSignals_Heartbeat_ReportAtTheWaitsEnd is the wait's end finding a report no wake acted on,
// as when both are ready for one select. A real stream chooses at random, so this calls the wait's end
// directly.
func TestSessionSignals_Heartbeat_ReportAtTheWaitsEnd(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		report string
		assert func(t *testing.T, reason string)
	}

	cases := []testCase{
		{
			name:   "a report held by then names the end",
			report: "logout",
			assert: func(t *testing.T, reason string) {
				t.Helper()

				assert.Equal(t, "session_ended:logout", reason)
			},
		},
		{
			name: "with none it says ended",
			assert: func(t *testing.T, reason string) {
				t.Helper()

				assert.Equal(t, "session_ended:ended", reason)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, signalsSetup{})

			var written bytes.Buffer

			tc.assert(t, httpsec.StreamWaitEnds(t.Context(), f.chain, &bufferEventWriter{&written}, tc.report))
		})
	}
}

// TestSessionSignals_Caps_RefusalOfAWriterThatCannotStream is what a refusal's answer is labelled when
// the stream's own type never went on: as any other refusal's, with no empty header line.
func TestSessionSignals_Caps_RefusalOfAWriterThatCannotStream(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request, err error)
		assert  func(t *testing.T, resp *http.Response, body []byte)
	}

	cases := []testCase{
		{
			name: "an error handler that writes and names no type gets net/http's detected one",
			handler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				w.WriteHeader(http.StatusNotImplemented)
				_, _ = w.Write([]byte("refused"))
			},
			assert: func(t *testing.T, resp *http.Response, body []byte) {
				t.Helper()

				assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
				assert.Equal(t, "refused", string(body))
				assert.Equal(t, []string{"text/plain; charset=utf-8"}, resp.Header["Content-Type"])
			},
		},
		{
			name: "an error handler that names a type keeps it",
			handler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(http.StatusNotImplemented)
			},
			assert: func(t *testing.T, resp *http.Response, _ []byte) {
				t.Helper()

				assert.Equal(t, []string{"application/problem+json"}, resp.Header["Content-Type"])
			},
		},
		{
			name: "the default answer has no body and no type at all",
			assert: func(t *testing.T, resp *http.Response, body []byte) {
				t.Helper()

				assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
				assert.Empty(t, body)
				assert.NotContains(t, resp.Header, "Content-Type", "an empty header line")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions := must.Must(session.New(session.WithStore(must.Must(session.NewMemoryStore()))))
			users := NewMockUserLoader(gomock.NewController(t))
			users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().Return(storedUser(), nil)

			opts := []httpsec.Option{
				httpsec.EnableSessionSignals(httpsec.SessionSignals{}),
				httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
				httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
					return errors.New(storeDownText)
				}), httpsec.After(httpsec.OrderCSRF)),
			}

			if tc.handler != nil {
				opts = append(opts, httpsec.WithErrorHandler(tc.handler))
			}

			inner := must.Must(httpsec.New(opts...)).Middleware()(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				inner.ServeHTTP(unflushableWriter{w}, r)
			}))
			t.Cleanup(srv.Close)

			req := must.Must(http.NewRequestWithContext(
				t.Context(), http.MethodGet, srv.URL+httpsec.DefaultSessionSignalsPath, http.NoBody))

			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)

			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			tc.assert(t, resp, body)
		})
	}
}

// TestSessionSignals_EndpointGivesAnAdapterTheType is a consumer's own writer that cannot stream, on both
// the stream's path and a retry's: it is told the type by Stream and through no header, so its refusal
// has nothing to take back.
func TestSessionSignals_EndpointGivesAnAdapterTheType(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		setup signalsSetup
	}

	cases := []testCase{
		{name: "the stream itself"},
		{
			name: "a retry after a dependency failed",
			setup: signalsSetup{opts: func(*signalsFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
					return errors.New(storeDownText)
				}), httpsec.After(httpsec.OrderCSRF))}
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newSignalsFixture(t, tc.setup)
			s := f.signIn(t, "u-1")
			w := &stubWriter{}

			run := f.chain.Assemble(func(*httpsec.Exchange) error { return nil })

			require.ErrorIs(t, run(httpsec.NewExchange(t.Context(), stubRequest{
				method:   http.MethodGet,
				path:     httpsec.DefaultSessionSignalsPath,
				clientIP: "198.51.100.7",
				headers:  map[string]string{"Authorization": "Bearer " + s.ID},
			}, w)), httpsec.ErrStreamingUnsupported)

			assert.Equal(t, "text/event-stream", w.streamType)
			assert.NotContains(t, w.header, "Content-Type", "not even a blank one")
			assert.Contains(t, w.header.Get("Cache-Control"), "no-store", "a refusal is never cached")
		})
	}
}

// firstReadSecret is text a dependency's error carries that no returned error may.
const firstReadSecret = "dial tcp 10.0.0.9: password=hunter2" //nolint:gosec // G101: a fixture standing in for text that must not leak, not a credential

// stubUsers is a UserLoader that answers every read with load.
type stubUsers struct {
	load func(ctx context.Context) (*identity.Details, error)
}

func (s stubUsers) LoadByUsername(ctx context.Context, _ string) (*identity.Details, error) {
	return s.load(ctx)
}

func (s stubUsers) LoadByUserID(ctx context.Context, _ identity.UserID) (*identity.Details, error) {
	return s.load(ctx)
}

// listFailingStore is a session store whose listing, the stream's own read, fails once armed.
type listFailingStore struct {
	session.Store

	armed atomic.Bool
}

func (s *listFailingStore) ListByUser(ctx context.Context, user identity.UserID, now time.Time) ([]*session.Session, error) {
	if s.armed.Load() {
		return nil, errors.New(firstReadSecret)
	}

	return s.Store.ListByUser(ctx, user, now)
}

// TestSessionSignals_Caps_FirstReadReturnsNoDependencyText is each way the stream's first read of the
// sign-in and its user can fail, with the chain's error handler made to see the error. A dependency's
// text is in no error the request returns, as at the authenticators' own reads, and the cause stays
// reachable where there is one.
func TestSessionSignals_Caps_FirstReadReturnsNoDependencyText(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		signals httpsec.SessionSignals
		store   *listFailingStore

		// hangUp has the client leave while the user read is in flight, and the read then fail.
		hangUp bool

		assert func(t *testing.T, err error)
	}

	var never = func(error) bool { return false }

	noText := func(t *testing.T, err error) {
		t.Helper()

		require.NotNil(t, err, "the error handler never heard of the failure")
		assert.NotContains(t, err.Error(), firstReadSecret)
	}

	failing := func(context.Context) (*identity.Details, error) { return nil, errors.New(firstReadSecret) }

	cases := []testCase{
		{
			name:    "the user store fails",
			signals: httpsec.SessionSignals{RetryableError: never, Users: stubUsers{load: failing}},
			assert:  noText,
		},
		{
			name:    "the session store fails",
			signals: httpsec.SessionSignals{RetryableError: never},
			store:   &listFailingStore{},
			assert:  noText,
		},
		{
			name: "the user store meets the read's own deadline",
			signals: httpsec.SessionSignals{RetryableError: never, ReloadTimeout: 20 * time.Millisecond, Users: stubUsers{
				load: func(ctx context.Context) (*identity.Details, error) {
					<-ctx.Done()

					return nil, fmt.Errorf("%s: %w", firstReadSecret, ctx.Err())
				},
			}},
			assert: func(t *testing.T, err error) {
				noText(t, err)
				assert.ErrorIs(t, err, context.DeadlineExceeded, "the cause was lost")
			},
		},
		{
			name: "the user loader panics",
			signals: httpsec.SessionSignals{RetryableError: never, Users: stubUsers{
				load: func(context.Context) (*identity.Details, error) { panic(errors.New(firstReadSecret)) },
			}},
			assert: noText,
		},
		{
			name: "ReloadContext panics",
			signals: httpsec.SessionSignals{RetryableError: never, ReloadContext: func(context.Context) context.Context {
				panic(errors.New(firstReadSecret))
			}},
			assert: noText,
		},
		{
			name:   "the client hangs up while the user store is read, and the store then fails",
			hangUp: true,
			assert: noText,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var handled atomic.Pointer[error]

			signals := tc.signals

			entered, release := make(chan struct{}), make(chan struct{})

			if tc.hangUp {
				signals.RetryableError = never
				signals.Users = stubUsers{load: func(context.Context) (*identity.Details, error) {
					close(entered)
					<-release

					return nil, errors.New(firstReadSecret)
				}}
			}

			setup := signalsSetup{
				signals: signals,
				opts: func(*signalsFixture) []httpsec.Option {
					return []httpsec.Option{httpsec.WithErrorHandler(func(rw http.ResponseWriter, _ *http.Request, err error) {
						handled.Store(&err)
						rw.WriteHeader(http.StatusInternalServerError)
					})}
				},
			}

			if tc.store != nil {
				setup.wrap = func(inner session.Store) session.Store {
					tc.store.Store = inner

					return tc.store
				}
			}

			f := newSignalsFixture(t, setup)
			s := f.signIn(t, "u-1")

			if tc.store != nil {
				tc.store.armed.Store(true)
			}

			if !tc.hangUp {
				resp, _ := f.openStream(t, s.ID)
				require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
			} else {
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)

				go func() {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.server.URL+httpsec.DefaultSessionSignalsPath, nil)
					if err != nil {
						return
					}

					req.Header.Set("Authorization", "Bearer "+s.ID)

					if resp, err := f.server.Client().Do(req); err == nil {
						_ = resp.Body.Close()
					}
				}()

				<-entered
				cancel()
				close(release)
				f.waitDone(t)
			}

			var err error
			if p := handled.Load(); p != nil {
				err = *p
			}

			tc.assert(t, err)
		})
	}
}
