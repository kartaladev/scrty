package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/ratelimit"
)

// flowCancelPath is the cancel endpoint's default path.
const flowCancelPath = "/oauth2/authorize/cancel"

// errCancelOutage is a store failing in a cancel row.
var errCancelOutage = errors.New("store outage")

// cancel sends body to the cancel endpoint at path by method, declared as contentType, as a login
// page's fetch would.
func (w *opFlow) cancel(
	ctx context.Context, t *testing.T, method, path, contentType, body string, change ...flowChange,
) flowAnswer {
	t.Helper()

	r := httptest.NewRequestWithContext(ctx, method, w.issuer+path, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)

	return w.serve(t, r, change)
}

// flowSpent is the check that the request behind handle can no longer be resumed or ended.
func flowSpent(t *testing.T, w *opFlow, handle, flow string) {
	t.Helper()

	_, err := w.p.PendingRequest(t.Context(), handle, flow)
	require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle, "the request is spent")
}

// failingAdvancePending is a pending-request store over a memory store whose stage moves fail.
func failingAdvancePending(t *testing.T) *MockPendingRequestStore {
	t.Helper()

	mem := must.Must(oidcprovider.NewMemoryPendingRequestStore())
	store := NewMockPendingRequestStore(gomock.NewController(t))
	store.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(mem.Create).AnyTimes()
	store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(mem.Load).AnyTimes()
	store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(mem.DeleteExpired).AnyTimes()
	store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(errCancelOutage).AnyTimes()

	return store
}

// TestCancel pins the cancel endpoint through a whole chain: a live handle with its flow cookie
// ends the login stage with access_denied and answers the client's redirect URI in a document,
// with no sign-in; everything else is refused as the resume endpoint refuses it, spending
// nothing, and only an unknown handle is charged to the source.
func TestCancel(t *testing.T) {
	t.Parallel()

	// cancelCall is what a row sends, and the request it parked first, if any.
	type cancelCall struct {
		method, path, contentType, body string
		change                          []flowChange
		handle, flow                    string
	}

	// cancelRun is what a row's assert inspects.
	type cancelRun struct {
		w       *opFlow
		call    cancelCall
		a       flowAnswer
		charged int64
		loads   int64 // what reached the fixture's pending store during the call
	}

	type testCase struct {
		name string
		// setup is the row's provider and chain; the resume limiter is added, and is a
		// counter of charges unless limiter replaces it.
		setup   func(t *testing.T) flowSetup
		limiter func(t *testing.T) ratelimit.Limiter
		ctx     func(ctx context.Context) context.Context
		arrange func(t *testing.T, w *opFlow) cancelCall
		assert  func(t *testing.T, r cancelRun)
	}

	// live parks a request and cancels it, with its flow cookie, at path.
	live := func(path string, change ...flowChange) func(t *testing.T, w *opFlow) cancelCall {
		return func(t *testing.T, w *opFlow) cancelCall {
			t.Helper()

			handle, flow := w.park(t, flowWeb)

			return cancelCall{
				method: http.MethodPost, path: path, contentType: "application/json", body: flowLoginBody(handle),
				change: append([]flowChange{flowCookieOf(flowCookie, flow)}, change...),
				handle: handle, flow: flow,
			}
		}
	}

	// refused is a refusal that answered err with status, an empty body and no-store, charging
	// charged, and leaving the request at its login stage.
	refused := func(err error, status int, charged int64) func(t *testing.T, r cancelRun) {
		return func(t *testing.T, r cancelRun) {
			t.Helper()

			require.ErrorIs(t, r.a.err, err)
			assert.Equal(t, status, r.a.status)
			assert.Empty(t, r.a.body)
			assert.Empty(t, r.a.header.Get("Location"), "a refusal is never a redirect")
			assert.Equal(t, "no-store", r.a.header.Get("Cache-Control"), "a refusal is not cached either")
			assert.Equal(t, charged, r.charged, "charges to the source")
			assert.False(t, r.a.passedOn)
			flowUnspent(t, r.w, r.call.handle, r.call.flow)
		}
	}

	// endedAt is an answer at path ending the request with access_denied.
	endedAt := func(path string) func(t *testing.T, r cancelRun) {
		return func(t *testing.T, r cancelRun) {
			t.Helper()

			require.Equal(t, http.StatusOK, r.a.status, r.a.body)
			assert.Equal(t, "no-store", r.a.header.Get("Cache-Control"))
			assert.Empty(t, r.a.header.Get("Location"), "the answer is a document, never a redirect")
			assert.False(t, r.a.passedOn)
			assert.Zero(t, r.charged, "an ended request charges no one")

			to := r.a.redirectTo(t)
			assert.Equal(t, rpCallback, to.Scheme+"://"+to.Host+to.Path)
			assert.Equal(t, url.Values{"error": {"access_denied"}, "state": {"xyz"}, "iss": {r.w.issuer}}, to.Query(),
				"the error, state and iss, and no code or error_description")
			flowSpent(t, r.w, r.call.handle, r.call.flow)

			var listed []httpsec.Endpoint

			for _, e := range r.w.chain.Endpoints() {
				if e.OperationID == httpsec.OperationOAuth2AuthorizeCancel {
					listed = append(listed, e)
				}
			}

			require.Len(t, listed, 1, "the inventory lists the cancel once")
			assert.Equal(t, path, listed[0].Path, "at the path it is served on")
			assert.Equal(t, []string{http.MethodPost}, listed[0].Methods)
			assert.Equal(t, httpsec.RequiresNothing, listed[0].Requires, "a user who gives up has not signed in")
		}
	}

	cases := []testCase{
		{
			name:    "a live handle with its flow cookie is ended with access_denied, with no sign-in",
			arrange: live(flowCancelPath),
			assert:  endedAt(flowCancelPath),
		},
		{
			name: "an unknown handle is refused and charged",
			arrange: func(t *testing.T, w *opFlow) cancelCall {
				t.Helper()

				handle, flow := w.park(t, flowWeb)

				return cancelCall{
					method: http.MethodPost, path: flowCancelPath, contentType: "application/json", body: flowLoginBody("rh.unknown"),
					change: []flowChange{flowCookieOf(flowCookie, flow)}, handle: handle, flow: flow,
				}
			},
			assert: refused(httpsec.ErrOIDCUnknownHandle, http.StatusBadRequest, 1),
		},
		{
			name: "another request's flow cookie is an unknown handle, charged, and the request stays parked",
			arrange: func(t *testing.T, w *opFlow) cancelCall {
				t.Helper()

				handle, flow := w.park(t, flowWeb)
				_, otherFlow := w.park(t, flowWeb)

				return cancelCall{
					method: http.MethodPost, path: flowCancelPath, contentType: "application/json", body: flowLoginBody(handle),
					change: []flowChange{flowCookieOf(flowCookie, otherFlow)}, handle: handle, flow: flow,
				}
			},
			assert: refused(httpsec.ErrOIDCUnknownHandle, http.StatusBadRequest, 1),
		},
		{
			name: "a live handle without its flow cookie is an unknown handle, charged",
			arrange: func(t *testing.T, w *opFlow) cancelCall {
				t.Helper()

				call := live(flowCancelPath)(t, w)
				call.change = nil

				return call
			},
			assert: refused(httpsec.ErrOIDCUnknownHandle, http.StatusBadRequest, 1),
		},
		{
			name: "a request at its consent stage is an unknown handle, charged, and stays there",
			arrange: func(t *testing.T, w *opFlow) cancelCall {
				t.Helper()

				handle, flow, _ := w.atConsent(t, w.session(t))

				return cancelCall{
					method: http.MethodPost, path: flowCancelPath, contentType: "application/json", body: flowLoginBody(handle),
					change: []flowChange{flowCookieOf(flowCookie, flow)}, handle: handle, flow: flow,
				}
			},
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				require.ErrorIs(t, r.a.err, httpsec.ErrOIDCUnknownHandle)
				assert.Equal(t, http.StatusBadRequest, r.a.status)
				assert.Equal(t, int64(1), r.charged)
				assert.Equal(t, oidcprovider.StageConsent, r.w.stage(t, r.call.handle, r.call.flow))
			},
		},
		{
			name: "a throttled source is refused before the handle is looked up",
			limiter: func(t *testing.T) ratelimit.Limiter {
				t.Helper()

				// RecordFailure is not expected: a refused source is not charged again.
				l := NewMockLimiter(gomock.NewController(t))
				l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				return l
			},
			arrange: live(flowCancelPath),
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				refused(httpsec.ErrOIDCThrottled, http.StatusTooManyRequests, 0)(t, r)
				assert.Zero(t, r.loads, "the provider never read the request")
			},
		},
		{
			name: "a limiter that cannot answer is refused, failing closed",
			limiter: func(*testing.T) ratelimit.Limiter {
				return flowDownLimiter{}
			},
			arrange: live(flowCancelPath),
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				require.ErrorIs(t, r.a.err, httpsec.ErrOIDCThrottled)
				assert.Equal(t, http.StatusTooManyRequests, r.a.status)
				assert.Zero(t, r.loads, "the provider never read the request")
				flowUnspent(t, r.w, r.call.handle, r.call.flow)
			},
		},
		{
			name:    "a cancel not made over TLS is refused as at resume, uncharged",
			arrange: live(flowCancelPath, flowPlainHTTP),
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				refused(httpsec.ErrOIDCUnknownHandle, http.StatusBadRequest, 0)(t, r)
				assert.Zero(t, r.loads, "the provider never read the request")
			},
		},
		{
			name: "a cross-site POST is refused by CSRF protection",
			arrange: live(flowCancelPath, func(r *http.Request) {
				r.Header.Set("Sec-Fetch-Site", "cross-site")
				r.Header.Set("Origin", "https://evil.example.com")
			}),
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				require.ErrorIs(t, r.a.err, httpsec.ErrCrossSiteRequest)
				assert.Equal(t, http.StatusForbidden, r.a.status)
				assert.Zero(t, r.charged)
				assert.Zero(t, r.loads, "the provider never read the request")
				flowUnspent(t, r.w, r.call.handle, r.call.flow)
			},
		},
		{
			name: "a body over the limit is too large",
			arrange: func(t *testing.T, w *opFlow) cancelCall {
				t.Helper()

				call := live(flowCancelPath)(t, w)
				call.body = `{"req":"` + call.handle + `","pad":"` + strings.Repeat("a", int(httpsec.DefaultLoginBodyLimit)) + `"}`

				return call
			},
			assert: refused(httpsec.ErrRequestTooLarge, http.StatusRequestEntityTooLarge, 0),
		},
		{
			name: "the resume's body limit bounds the cancel too",
			setup: func(*testing.T) flowSetup {
				return flowSetup{endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCResumeBodyLimit(4)}}
			},
			arrange: live(flowCancelPath),
			assert:  refused(httpsec.ErrRequestTooLarge, http.StatusRequestEntityTooLarge, 0),
		},
		{
			name: "a body not declared as JSON is refused as at resume, uncharged",
			arrange: func(t *testing.T, w *opFlow) cancelCall {
				t.Helper()

				call := live(flowCancelPath)(t, w)
				call.contentType = "text/plain"

				return call
			},
			assert: refused(httpsec.ErrOIDCUnknownHandle, http.StatusBadRequest, 0),
		},
		{
			name: "a body that is not JSON names no handle, uncharged",
			arrange: func(t *testing.T, w *opFlow) cancelCall {
				t.Helper()

				call := live(flowCancelPath)(t, w)
				call.body = "{"

				return call
			},
			assert: refused(httpsec.ErrOIDCUnknownHandle, http.StatusBadRequest, 0),
		},
		{
			name: "a store failing to spend the request is answered as a dependency failure, nothing spent",
			setup: func(t *testing.T) flowSetup {
				t.Helper()

				return flowSetup{provider: []oidcprovider.Option{oidcprovider.WithPendingRequestStore(failingAdvancePending(t))}}
			},
			arrange: live(flowCancelPath),
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				require.ErrorIs(t, r.a.err, oidcprovider.ErrDependency)
				assert.Equal(t, http.StatusInternalServerError, r.a.status)
				assert.Empty(t, r.a.body, "no redirect_to")
				assert.Zero(t, r.charged, "a failure is no verdict on the source")
				assert.NotContains(t, r.a.err.Error(), r.call.handle, "the error carries no handle")
				assert.NotContains(t, r.a.err.Error(), r.call.flow, "the error carries no flow secret")
				flowUnspent(t, r.w, r.call.handle, r.call.flow)
			},
		},
		{
			name: "a caller that left is answered no redirect, and nothing is spent or charged",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			arrange: live(flowCancelPath),
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				// The chain answers a caller who left as it answers any: nobody hears it.
				assert.NotEqual(t, http.StatusOK, r.a.status)
				assert.Empty(t, r.a.body, "no redirect_to")
				assert.Zero(t, r.charged)
				flowUnspent(t, r.w, r.call.handle, r.call.flow)
			},
		},
		{
			name: "a GET is refused with Allow: POST, uncharged",
			arrange: func(t *testing.T, w *opFlow) cancelCall {
				t.Helper()

				call := live(flowCancelPath)(t, w)
				call.method = http.MethodGet

				return call
			},
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				assert.Equal(t, http.StatusMethodNotAllowed, r.a.status)
				assert.Equal(t, http.MethodPost, r.a.header.Get("Allow"))
				assert.Equal(t, "no-store", r.a.header.Get("Cache-Control"))
				assert.Zero(t, r.charged)
				assert.Zero(t, r.loads)
				flowUnspent(t, r.w, r.call.handle, r.call.flow)
			},
		},
		{
			name: "a moved cancel is served at its new path",
			setup: func(*testing.T) flowSetup {
				return flowSetup{endpoint: []httpsec.OIDCProviderOption{
					httpsec.WithOIDCProviderPath(httpsec.OIDCCancel, "/login/give-up"),
				}}
			},
			arrange: live("/login/give-up"),
			assert:  endedAt("/login/give-up"),
		},
		{
			name: "a moved cancel is not served at the default path",
			setup: func(*testing.T) flowSetup {
				return flowSetup{endpoint: []httpsec.OIDCProviderOption{
					httpsec.WithOIDCProviderPath(httpsec.OIDCCancel, "/login/give-up"),
				}}
			},
			arrange: live(flowCancelPath),
			assert: func(t *testing.T, r cancelRun) {
				t.Helper()

				assert.True(t, r.a.passedOn, "the default path is the application's")
				assert.Zero(t, r.loads)
				flowUnspent(t, r.w, r.call.handle, r.call.flow)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var charged atomic.Int64

			var limiter ratelimit.Limiter = resumeChargeCounter(t, &charged)
			if tc.limiter != nil {
				limiter = tc.limiter(t)
			}

			var setup flowSetup
			if tc.setup != nil {
				setup = tc.setup(t)
			}

			setup.endpoint = append([]httpsec.OIDCProviderOption{httpsec.WithOIDCResumeLimiter(limiter)}, setup.endpoint...)

			w := newOPFlow(t, setup)
			call := tc.arrange(t, w)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			loads := w.pending.loads.Load()
			a := w.cancel(ctx, t, call.method, call.path, call.contentType, call.body, call.change...)

			tc.assert(t, cancelRun{
				w: w, call: call, a: a, charged: charged.Load(), loads: w.pending.loads.Load() - loads,
			})
		})
	}
}

// TestCancel_SharesTheResumeBudget pins that the resume and the cancel count unknown handles in
// one budget per source: a source that spent it at the resume is refused at the cancel, with
// 429, before any lookup.
func TestCancel_SharesTheResumeBudget(t *testing.T) {
	t.Parallel()

	const budget = 2

	var spent atomic.Int64

	limiter := NewMockLimiter(gomock.NewController(t))
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) (bool, error) { return spent.Load() >= budget, nil })
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) error {
			spent.Add(1)

			return nil
		})

	w := newOPFlow(t, flowSetup{endpoint: []httpsec.OIDCProviderOption{httpsec.WithOIDCResumeLimiter(limiter)}})
	handle, flow := w.park(t, flowWeb)

	for range budget {
		a := w.resume(t, flowLoginBody("rh.unknown"), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, flow))
		require.ErrorIs(t, a.err, httpsec.ErrOIDCUnknownHandle)
	}

	loads := w.pending.loads.Load()
	a := w.cancel(t.Context(), t, http.MethodPost, flowCancelPath, "application/json", flowLoginBody(handle),
		flowCookieOf(flowCookie, flow))

	require.ErrorIs(t, a.err, httpsec.ErrOIDCThrottled)
	assert.Equal(t, http.StatusTooManyRequests, a.status)
	assert.Equal(t, loads, w.pending.loads.Load(), "the provider never read the request")
	assert.Equal(t, int64(budget), spent.Load(), "a refused source is not charged again")
	flowUnspent(t, w, handle, flow)
}

// TestCancel_SecondCancelIsUnknownHandle pins a login page that posts its cancel twice, in turn
// (a double click) or at once: one post is answered with the client's redirect, and the other is
// an unknown handle, never a second answer. A resume after the cancel is an unknown handle too.
func TestCancel_SecondCancelIsUnknownHandle(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		post func(t *testing.T, w *opFlow, handle, flow string) [2]flowAnswer
	}

	send := func(t *testing.T, w *opFlow, handle, flow string) flowAnswer {
		t.Helper()

		return w.cancel(t.Context(), t, http.MethodPost, flowCancelPath, "application/json", flowLoginBody(handle),
			flowCookieOf(flowCookie, flow))
	}

	cases := []testCase{
		{
			name: "in turn",
			post: func(t *testing.T, w *opFlow, handle, flow string) [2]flowAnswer {
				t.Helper()

				return [2]flowAnswer{send(t, w, handle, flow), send(t, w, handle, flow)}
			},
		},
		{
			name: "at once",
			post: func(t *testing.T, w *opFlow, handle, flow string) [2]flowAnswer {
				t.Helper()

				var (
					got   [2]flowAnswer
					wg    sync.WaitGroup
					start = make(chan struct{})
				)

				for i := range got {
					wg.Go(func() {
						<-start

						got[i] = send(t, w, handle, flow)
					})
				}

				close(start)
				wg.Wait()

				return got
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var charged atomic.Int64

			w := newOPFlow(t, flowSetup{endpoint: []httpsec.OIDCProviderOption{
				httpsec.WithOIDCResumeLimiter(resumeChargeCounter(t, &charged)),
			}})
			handle, flow := w.park(t, flowWeb)

			got := tc.post(t, w, handle, flow)

			// Invariant: exactly one answer carries the client's redirect, and the other is an
			// unknown handle, charged once.
			var answered, unknown int

			for _, a := range got {
				switch a.status {
				case http.StatusOK:
					answered++

					assert.Equal(t, "access_denied", a.redirectTo(t).Query().Get("error"))
				case http.StatusBadRequest:
					unknown++

					assert.Empty(t, a.body)
				default:
					t.Errorf("unexpected status %d: %s", a.status, a.body)
				}
			}

			assert.Equal(t, 1, answered, "one redirect")
			assert.Equal(t, 1, unknown, "one unknown handle")
			assert.Equal(t, int64(1), charged.Load(), "the unknown handle is charged")
			flowSpent(t, w, handle, flow)

			resumed := w.resume(t, flowLoginBody(handle), flowBearer(w.session(t).ID), flowCookieOf(flowCookie, flow))
			require.ErrorIs(t, resumed.err, httpsec.ErrOIDCUnknownHandle, "a resume after the cancel finds nothing")
		})
	}
}
