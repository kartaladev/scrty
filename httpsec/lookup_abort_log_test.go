package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// msgClassificationAborted is the record an aborted classification writes.
const msgClassificationAborted = "httpsec: error classification aborted"

// isPanicMessage is what isPanics panics with: a record must not quote it.
const isPanicMessage = "the link's Is panicked"

// swapDefaultLogger points slog.Default() at a capturing handler until the test
// ends. The caller must not be parallel.
func swapDefaultLogger(t *testing.T) *capturingHandler {
	t.Helper()

	prev := slog.Default()
	logs := &capturingHandler{}
	slog.SetDefault(slog.New(logs))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return logs
}

// abortRecords returns the aborted-classification records among recs.
func abortRecords(recs []slog.Record) []slog.Record {
	var out []slog.Record

	for _, r := range recs {
		if r.Message == msgClassificationAborted {
			out = append(out, r)
		}
	}

	return out
}

// assertAbortRecord checks one aborted-classification record: Error level,
// the reason, and no text of the error or of a recovered panic anywhere in it.
func assertAbortRecord(t *testing.T, r slog.Record, reason string) {
	t.Helper()

	assert.Equal(t, slog.LevelError, r.Level)

	got, ok := attrValue(r, "reason")
	require.True(t, ok, "the record names its reason")
	assert.Equal(t, reason, got.String())

	_, hasType := attrValue(r, "panic_type")
	assert.Equal(t, reason == "panic", hasType, "a panic, and only a panic, names the panic's type")

	assert.NotContains(t, r.Message, hostileSecret)
	r.Attrs(func(a slog.Attr) bool {
		v := a.Value.String()
		assert.NotContains(t, v, hostileSecret, "attribute %q quotes the error's text", a.Key)
		assert.NotContains(t, v, isPanicMessage, "attribute %q quotes the panic's value", a.Key)

		return true
	})
}

// assertFramesFromPanic checks a panic record's frames attribute: it names
// method, the fixture's panicking method, and its first frame is not the
// classification or the dispatch that wrote the record.
func assertFramesFromPanic(t *testing.T, r slog.Record, method string) {
	t.Helper()

	frames, ok := attrValue(r, "frames")
	require.True(t, ok, "a panic record names its frames")

	all := strings.Split(frames.String(), "; ")
	require.NotEmpty(t, all)
	assert.Contains(t, frames.String(), method, "the frames reach the panicking method")

	for _, writer := range []string{"httpsec.lookup", "httpsec.LookupStatus", "handleError", "classificationAbortedAttrs"} {
		assert.NotContains(t, all[0], writer, "the frames start where it panicked, not at %s", writer)
	}
}

func TestLookupStatus_AbortIsLogged(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, records []slog.Record)
	}

	oneRecord := func(reason string) func(t *testing.T, records []slog.Record) {
		return func(t *testing.T, records []slog.Record) {
			t.Helper()
			require.Len(t, records, 1, "one record per aborted classification")
			assertAbortRecord(t, records[0], reason)
		}
	}
	noRecord := func(t *testing.T, records []slog.Record) {
		t.Helper()
		assert.Empty(t, records)
	}

	cases := []testCase{
		{name: "a cyclic chain", err: &cycleOne{}, assert: oneRecord("budget")},
		{name: "a fan-out of joins", err: fanOut(25), assert: oneRecord("budget")},
		{name: "a link whose Is panics", err: errors.Join(isPanics{}, authorize.ErrAccessDenied), assert: oneRecord("panic")},
		{name: "a link whose As panics", err: asPanics{}, assert: oneRecord("panic")},
		{
			// The frames are captured where the walk recovered, so they name
			// the link's panicking method, not the code writing the record.
			name: "a link whose Is panics: the frames name where it panicked",
			err:  errors.Join(isPanics{}, authorize.ErrAccessDenied),
			assert: func(t *testing.T, records []slog.Record) {
				t.Helper()
				require.Len(t, records, 1)
				assertAbortRecord(t, records[0], "panic")
				assertFramesFromPanic(t, records[0], "httpsec_test.isPanics.Is")
			},
		},
		{
			name: "a link whose As panics: the frames name where it panicked",
			err:  asPanics{},
			assert: func(t *testing.T, records []slog.Record) {
				t.Helper()
				require.Len(t, records, 1)
				assertFramesFromPanic(t, records[0], "httpsec_test.asPanics.As")
			},
		},
		{name: "a recognised refusal", err: authorize.ErrAccessDenied, assert: noRecord},
		{name: "an unrecognised error that walks", err: errors.New(hostileSecret), assert: noRecord},
		{name: "nil", err: nil, assert: noRecord},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			logs := swapDefaultLogger(t)

			_, _ = httpsec.LookupStatus(tc.err)
			tc.assert(t, abortRecords(logs.records()))
		})
	}
}

func TestChain_AbortLogsToChainLogger(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type requests struct {
		statuses             []int
		chainLogs, otherLogs []slog.Record
	}

	type testCase struct {
		name string
		// refusal is what the interceptor returns on every request, unless
		// sequence is set: then request i is refused with sequence[i], and as
		// many requests are sent as sequence holds.
		refusal  error
		sequence []error
		// opts are the chain's options beyond the interceptor; chainLog is the
		// logger WithLogger receives, when a case gives it.
		opts   func(chainLog *slog.Logger) []httpsec.Option
		assert func(t *testing.T, got requests)
	}

	withLogger := func(chainLog *slog.Logger) []httpsec.Option {
		return []httpsec.Option{httpsec.WithLogger(chainLog)}
	}

	// teapot is a consumer's error handler that answers without classifying.
	teapot := func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusTeapot) }

	cases := []testCase{
		{
			// The spec's "Consumer chooses the logger", and one record per
			// sampling window, not one per request.
			name:    "the consumer's logger receives one sampled record",
			refusal: &cycleOne{},
			opts:    withLogger,
			assert: func(t *testing.T, got requests) {
				t.Helper()
				assert.Equal(t, []int{http.StatusInternalServerError, http.StatusInternalServerError}, got.statuses)
				require.Len(t, got.chainLogs, 1, "a second abort inside the sampling window adds no record")
				assertAbortRecord(t, got.chainLogs[0], "budget")
				assert.Empty(t, got.otherLogs, "nothing goes to the process default")
			},
		},
		{
			name:    "a panicking Is is reported with its reason",
			refusal: errors.Join(isPanics{}, authorize.ErrAccessDenied),
			opts:    withLogger,
			assert: func(t *testing.T, got requests) {
				t.Helper()
				assert.Equal(t, []int{http.StatusInternalServerError, http.StatusInternalServerError}, got.statuses)
				require.Len(t, got.chainLogs, 1)
				assertAbortRecord(t, got.chainLogs[0], "panic")
				assert.Empty(t, got.otherLogs)
			},
		},
		{
			// The events path classifies the same refusal on the same
			// request: it must not write a record of its own.
			name:    "security events on: still one record",
			refusal: &cycleOne{},
			opts: func(chainLog *slog.Logger) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(chainLog),
					httpsec.EnableSecurityEvents(func(context.Context, event.Event) {}),
				}
			},
			assert: func(t *testing.T, got requests) {
				t.Helper()
				assert.Equal(t, []int{http.StatusInternalServerError, http.StatusInternalServerError}, got.statuses)
				require.Len(t, got.chainLogs, 1)
				assertAbortRecord(t, got.chainLogs[0], "budget")
				assert.Empty(t, got.otherLogs)
			},
		},
		{
			// Without WithLogger the chain's logger is the process default.
			name:    "no consumer logger: the process default",
			refusal: &cycleOne{},
			opts:    func(*slog.Logger) []httpsec.Option { return nil },
			assert: func(t *testing.T, got requests) {
				t.Helper()
				assert.Equal(t, []int{http.StatusInternalServerError, http.StatusInternalServerError}, got.statuses)
				assert.Empty(t, got.chainLogs)
				require.Len(t, got.otherLogs, 1, "sampled through the chain, as with a consumer's logger")
				assertAbortRecord(t, got.otherLogs[0], "budget")
			},
		},
		{
			// The sampling key is per reason, so a budget abort does not hide
			// a panic abort that follows it inside the window.
			name:     "a budget abort then a panic abort in one window: one record each",
			sequence: []error{&cycleOne{}, errors.Join(isPanics{}, authorize.ErrAccessDenied)},
			opts:     withLogger,
			assert: func(t *testing.T, got requests) {
				t.Helper()
				assert.Equal(t, []int{http.StatusInternalServerError, http.StatusInternalServerError}, got.statuses)
				require.Len(t, got.chainLogs, 2, "a panic abort is not sampled away by an earlier budget abort")
				assertAbortRecord(t, got.chainLogs[0], "budget")
				assertAbortRecord(t, got.chainLogs[1], "panic")
				assert.Empty(t, got.otherLogs)
			},
		},
		{
			// Under a consumer's error handler the chain's dispatch classifies
			// nothing, so the refusal event's own classification reports the
			// abort, through the chain's logger and sampler: one record for
			// the two requests, none to the process default.
			name:    "a consumer error handler that does not classify, events on: the quiet site reports",
			refusal: &cycleOne{},
			opts: func(chainLog *slog.Logger) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(chainLog),
					httpsec.EnableSecurityEvents(func(context.Context, event.Event) {}),
					httpsec.WithErrorHandler(teapot),
				}
			},
			assert: func(t *testing.T, got requests) {
				t.Helper()
				assert.Equal(t, []int{http.StatusTeapot, http.StatusTeapot}, got.statuses)
				require.Len(t, got.chainLogs, 1, "one sampled record from the quiet site")
				assertAbortRecord(t, got.chainLogs[0], "budget")
				assert.Empty(t, got.otherLogs)
			},
		},
		{
			// Accepted over-reporting: the quiet site reports to the chain's
			// logger, sampled, and the consumer's own StatusForError reports
			// again, to the process default, once per call. Never silence.
			name:    "a consumer error handler classifying with StatusForError, events on: both report",
			refusal: &cycleOne{},
			opts: func(chainLog *slog.Logger) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(chainLog),
					httpsec.EnableSecurityEvents(func(context.Context, event.Event) {}),
					httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
						w.WriteHeader(httpsec.StatusForError(err))
					}),
				}
			},
			assert: func(t *testing.T, got requests) {
				t.Helper()
				assert.Equal(t, []int{http.StatusInternalServerError, http.StatusInternalServerError}, got.statuses)
				require.Len(t, got.chainLogs, 1, "the quiet site's record, sampled")
				assertAbortRecord(t, got.chainLogs[0], "budget")
				require.Len(t, got.otherLogs, 2, "the free function reports every call")
				assertAbortRecord(t, got.otherLogs[0], "budget")
			},
		},
		{
			// A consumer's error handler owns the response, so the chain's
			// dispatch classifies nothing; the handler's own StatusForError
			// reports, to the process default, once per call. Re-derived after
			// the quiet sites learned to report under a consumer handler:
			// without security events no quiet site classifies this refusal,
			// so the chain's logger still gets nothing.
			name:    "a consumer error handler classifying with StatusForError",
			refusal: &cycleOne{},
			opts: func(chainLog *slog.Logger) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithLogger(chainLog),
					httpsec.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, err error) {
						w.WriteHeader(httpsec.StatusForError(err))
					}),
				}
			},
			assert: func(t *testing.T, got requests) {
				t.Helper()
				assert.Equal(t, []int{http.StatusInternalServerError, http.StatusInternalServerError}, got.statuses)
				assert.Empty(t, got.chainLogs, "the chain did not classify")
				require.Len(t, got.otherLogs, 2, "the free function reports every call")
				assertAbortRecord(t, got.otherLogs[0], "budget")
			},
		},
	}

	for _, tc := range cases { //nolint:paralleltest // it replaces slog.Default()
		t.Run(tc.name, func(t *testing.T) {
			defaultLogs := swapDefaultLogger(t)
			chainLogs := &capturingHandler{}

			sent := 0
			refusing := httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
				if tc.sequence != nil {
					return tc.sequence[sent]
				}

				return tc.refusal
			})
			opts := append(tc.opts(slog.New(chainLogs)), httpsec.RegisterInterceptor(refusing, httpsec.Order(100)))

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			handler := chain.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("the handler ran behind a refusal")
			}))

			var got requests

			requestCount := 2
			if tc.sequence != nil {
				requestCount = len(tc.sequence)
			}

			for ; sent < requestCount; sent++ {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/records", nil))
				got.statuses = append(got.statuses, rec.Code)
			}

			got.chainLogs = abortRecords(chainLogs.records())
			got.otherLogs = abortRecords(defaultLogs.records())
			tc.assert(t, got)
		})
	}
}

// TestGuards_AbortLogsToDefault pins that a guard, which has no chain logger,
// reports an aborted classification of its refusal to the process default,
// once, and answers it 500.
func TestGuards_AbortLogsToDefault(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	defaultLogs := swapDefaultLogger(t)

	az := NewMockAuthorizer(gomock.NewController(t))
	az.EXPECT().Authorize(gomock.Any(), gomock.Any()).Return(&cycleOne{}).Times(1)

	g := mustGuards(t, az)
	mw := g.ResourcePrivileges("records", "record").RequireOne("read")

	rec := httptest.NewRecorder()
	ctx := identity.WithPrincipal(t.Context(), testPrincipal())
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the route ran behind a refusal")
	})).ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/records/r-1", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	records := abortRecords(defaultLogs.records())
	require.Len(t, records, 1)
	assertAbortRecord(t, records[0], "budget")
}
