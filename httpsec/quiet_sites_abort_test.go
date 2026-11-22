package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
)

// errRefusedPlain is what a quiet site's interceptor refuses with once the site
// has classified the hostile error: a plain error, so nothing on the way out
// walks the hostile one again and only the site's record is counted.
var errRefusedPlain = errors.New("refused")

// teapotHandler is a consumer's error handler that answers without classifying.
func teapotHandler(w http.ResponseWriter, _ *http.Request, _ error) {
	w.WriteHeader(http.StatusTeapot)
}

// atQuietSites is an interceptor that runs each site with hostile, then refuses
// with errRefusedPlain.
func atQuietSites(hostile error, sites ...httpsec.QuietSite) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
		for _, site := range sites {
			site(ex, hostile)
		}

		return errRefusedPlain
	}), httpsec.Order(100))
}

// throttledCycle matches ratelimit.ErrThrottled through the standard library,
// which finds it first, and still aborts the library's walk on the cycle behind
// it.
func throttledCycle() error { return errors.Join(ratelimit.ErrThrottled, &cycleOne{}) }

// TestQuietSites_ReportUnderConsumerHandler pins that every quiet site reports
// an aborted classification when a consumer's WithErrorHandler leaves the
// chain's dispatch classifying nothing: through the chain's logger and sampler,
// never to the process default. Each row fails if its site stops reporting.
func TestQuietSites_ReportUnderConsumerHandler(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type got struct {
		status               int
		chainLogs, otherLogs []slog.Record
	}

	type testCase struct {
		name string
		// opts are the chain's options beyond its logger and the consumer's
		// error handler.
		opts    func(t *testing.T) []httpsec.Option
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, g got)
	}

	plainRequest := func(ctx context.Context) *http.Request {
		return httptest.NewRequestWithContext(ctx, http.MethodGet, "/records", nil)
	}

	oneChainRecord := func(t *testing.T, g got) {
		t.Helper()
		assert.Equal(t, http.StatusTeapot, g.status)
		require.Len(t, g.chainLogs, 1, "the quiet site reports the abort through the chain's logger")
		assertAbortRecord(t, g.chainLogs[0], "budget")
		assert.Empty(t, g.otherLogs, "nothing goes to the process default")
	}

	at := func(hostile error, sites ...httpsec.QuietSite) func(*testing.T) []httpsec.Option {
		return func(*testing.T) []httpsec.Option { return []httpsec.Option{atQuietSites(hostile, sites...)} }
	}

	cases := []testCase{
		{
			// The authenticator's refusal is a fan-out the standard library
			// walks in a few thousand steps and the library's walk refuses past
			// its budget, so only the challenge-header check reports it.
			name: "the Basic challenge header",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				h := newAuthHarness(t)
				h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).Return(nil, fanOut(11)).Times(1)
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).Return(nil).AnyTimes()

				return []httpsec.Option{httpsec.EnableBasicAuth(h.basicAuthDeps())}
			},
			request: func(ctx context.Context) *http.Request { return basicRequest(ctx, "ada", "s3cret") },
			assert:  oneChainRecord,
		},
		{
			name:    "the OIDC sign-in challenge",
			opts:    at(&cycleOne{}, httpsec.QuietSiteOIDCConsent),
			request: plainRequest,
			assert:  oneChainRecord,
		},
		{
			name:    "the signal stream's per-request throttle mark",
			opts:    at(throttledCycle(), httpsec.QuietSitePerRequestThrottle),
			request: plainRequest,
			assert:  oneChainRecord,
		},
		{
			name:    "the signal stream's throttled sign-in check",
			opts:    at(&cycleOne{}, httpsec.QuietSiteThrottledSignIn),
			request: plainRequest,
			assert:  oneChainRecord,
		},
		{
			name:    "the signal stream's dependency failure check",
			opts:    at(&cycleOne{}, httpsec.QuietSiteDependencyFailure),
			request: plainRequest,
			assert:  oneChainRecord,
		},
		{
			// Two sites on one request share the per-reason sampling key, so
			// the window holds one record.
			name:    "two quiet sites on one request, sampled: one record",
			opts:    at(&cycleOne{}, httpsec.QuietSiteOIDCConsent, httpsec.QuietSiteDependencyFailure),
			request: plainRequest,
			assert:  oneChainRecord,
		},
		{
			// Accepted over-reporting (design decision 11): with sampling off
			// nothing collapses the sites' records, so each site writes its own.
			name: "two quiet sites on one request, sampling off: one record each",
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithRefusalLogInterval(0),
					atQuietSites(&cycleOne{}, httpsec.QuietSiteOIDCConsent, httpsec.QuietSiteDependencyFailure),
				}
			},
			request: plainRequest,
			assert: func(t *testing.T, g got) {
				t.Helper()
				assert.Equal(t, http.StatusTeapot, g.status)
				require.Len(t, g.chainLogs, 2, "each site writes a record when nothing samples them")
				assertAbortRecord(t, g.chainLogs[0], "budget")
				assertAbortRecord(t, g.chainLogs[1], "budget")
				assert.Empty(t, g.otherLogs)
			},
		},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			chainLogs := &capturingHandler{}

			opts := append([]httpsec.Option{
				httpsec.WithLogger(slog.New(chainLogs)),
				httpsec.WithErrorHandler(teapotHandler),
			}, tc.opts(t)...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			rec := httptest.NewRecorder()
			chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("the handler ran behind a refusal")
			})).ServeHTTP(rec, tc.request(t.Context()))

			tc.assert(t, got{
				status:    rec.Code,
				chainLogs: abortRecords(chainLogs.records()),
				otherLogs: abortRecords(defaultLogs.records()),
			})
		})
	}
}

// TestChain_AbortReportedByAnsweringChain pins which chain a quiet site reports
// through when one chain is assembled inside another on one exchange: the
// chain that answers the error, the one at the bottom of the run stack whose
// middleware created the exchange, not the inner one that raised the refusal.
func TestChain_AbortReportedByAnsweringChain(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type got struct {
		status                         int
		outerLogs, innerLogs, defaults []slog.Record
	}

	type testCase struct {
		name string
		// outer and inner are each chain's options beyond its logger; the
		// outer chain mounts the inner one around the rest of its run, and the
		// inner one refuses with a cyclic error.
		outer, inner []httpsec.Option
		assert       func(t *testing.T, g got)
	}

	events := httpsec.EnableSecurityEvents(func(context.Context, event.Event) {})

	cases := []testCase{
		{
			// The outer chain answers through the consumer's handler, so its
			// dispatch classifies nothing; the inner chain's refusal event is
			// the only classification, and reports through the outer chain.
			name:  "outer with a consumer handler, inner with events and no handler: one record, on the outer logger",
			outer: []httpsec.Option{httpsec.WithErrorHandler(teapotHandler)},
			inner: []httpsec.Option{events},
			assert: func(t *testing.T, g got) {
				t.Helper()
				assert.Equal(t, http.StatusTeapot, g.status)
				require.Len(t, g.outerLogs, 1, "an aborted classification nobody can see")
				assertAbortRecord(t, g.outerLogs[0], "budget")
				assert.Empty(t, g.innerLogs)
				assert.Empty(t, g.defaults)
			},
		},
		{
			// The inner chain's handler answers nothing under Assemble: the
			// outer chain's dispatch answers and reports the abort itself, so
			// the inner refusal event stays quiet.
			name:  "inner with a consumer handler and events, outer with none: one record, the outer dispatch's",
			outer: nil,
			inner: []httpsec.Option{events, httpsec.WithErrorHandler(teapotHandler)},
			assert: func(t *testing.T, g got) {
				t.Helper()
				assert.Equal(t, http.StatusInternalServerError, g.status)
				require.Len(t, g.outerLogs, 1, "the outer dispatch reports")
				assertAbortRecord(t, g.outerLogs[0], "budget")
				assert.Empty(t, g.innerLogs, "the inner chain answers nothing, so it reports nothing")
				assert.Empty(t, g.defaults)
			},
		},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			outerLogs, innerLogs := &capturingHandler{}, &capturingHandler{}

			refuse := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
				return &cycleOne{}
			}), httpsec.Order(100))

			inner, err := httpsec.New(append([]httpsec.Option{httpsec.WithLogger(slog.New(innerLogs)), refuse}, tc.inner...)...)
			require.NoError(t, err)

			mount := httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				return inner.Assemble(next)(ex)
			}), httpsec.Order(100))

			outer, err := httpsec.New(append([]httpsec.Option{httpsec.WithLogger(slog.New(outerLogs)), mount}, tc.outer...)...)
			require.NoError(t, err)

			rec := httptest.NewRecorder()
			outer.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("the handler ran behind a refusal")
			})).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records", nil))

			tc.assert(t, got{
				status:    rec.Code,
				outerLogs: abortRecords(outerLogs.records()),
				innerLogs: abortRecords(innerLogs.records()),
				defaults:  abortRecords(defaultLogs.records()),
			})
		})
	}
}
