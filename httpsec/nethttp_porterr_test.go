package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
)

// streamPortErrRowEnv names the row a child process of
// TestPortErrors_StreamWriter runs. It is empty in the parent.
const streamPortErrRowEnv = "SCRTY_HTTPSEC_STREAM_PORTERR_ROW"

// streamPortErrRan is what a child prints, as a line of its own followed by
// the row's name, once it has run its row to the end.
const streamPortErrRan = "stream-porterr-row-ran:"

// flushFailingBottom is a consumer middleware's writer with a FlushError and
// no Unwrap: the bottom of the chain the adapter looks down, whose FlushError
// the stream asks before naming a status.
type flushFailingBottom struct {
	http.ResponseWriter

	err error
}

func (w flushFailingBottom) FlushError() error { return w.err }

// flushFailingAbove is a consumer middleware's writer with a FlushError and an
// Unwrap: http.ResponseController's flush stops at its FlushError.
type flushFailingAbove struct {
	http.ResponseWriter

	err error
}

func (w flushFailingAbove) FlushError() error { return w.err }

func (w flushFailingAbove) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// deadlineFailingAbove is a consumer middleware's writer whose
// SetWriteDeadline fails, with an Unwrap below it: http.ResponseController's
// deadline stops at it.
type deadlineFailingAbove struct {
	http.ResponseWriter

	err error
}

func (w deadlineFailingAbove) SetWriteDeadline(time.Time) error { return w.err }

func (w deadlineFailingAbove) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// notSupportedClaim is a cycle through Unwrap() error whose own Is claims to be
// http.ErrNotSupported: the stdlib asks Is first and takes the stream for one
// that cannot flush, without ever reaching the cycle.
type notSupportedClaim struct{}

func (*notSupportedClaim) Error() string { return hostileSecret }

func (c *notSupportedClaim) Unwrap() error { return c }

func (*notSupportedClaim) Is(target error) bool { return target == http.ErrNotSupported } //nolint:errorlint // identity of a sentinel

// streamWriterSite is one place the net/http adapter reads an error from a
// consumer's writer while it starts a stream.
type streamWriterSite struct {
	name string
	wrap func(w http.ResponseWriter, err error) http.ResponseWriter
}

// streamAnswer is what the client of a stream saw, and the chain's records.
type streamAnswer struct {
	status int
	header http.Header
	body   string
	logs   []slog.Record
}

// streamThrough opens the chain's session-signals stream through a consumer
// middleware whose writer fails with portErr where site says, and reads the
// whole answer, failing the test when it does not end within five seconds.
func streamThrough(t *testing.T, site streamWriterSite, portErr error) streamAnswer {
	t.Helper()

	logs := &capturingHandler{}

	f := newSignalsFixture(t, signalsSetup{
		opts: func(*signalsFixture) []httpsec.Option {
			return []httpsec.Option{httpsec.WithLogger(slog.New(logs))}
		},
		wrapHandler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(site.wrap(w, portErr), r)
			})
		},
	})

	s := f.signIn(t, "u-1")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.server.URL+httpsec.DefaultSessionSignalsPath, http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+s.ID)

	resp, err := f.server.Client().Do(req)
	require.NoError(t, err, "a hostile writer error hung the stream's head")

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "a hostile writer error hung the stream")

	f.waitDone(t)

	header := resp.Header.Clone()
	header.Del("Date")

	return streamAnswer{status: resp.StatusCode, header: header, body: string(body), logs: logs.records()}
}

// TestPortErrors_StreamWriter pins that a hostile error from a consumer
// middleware's writer, read by the net/http adapter as it starts a stream
// (the bottom writer's FlushError, a wrapper's FlushError through the flush,
// a wrapper's SetWriteDeadline), is answered exactly as a plain failure of
// that writer is: the same answer on the wire, one abort record on the chain's
// logger, none on slog.Default(). A cycle claiming http.ErrNotSupported is
// never taken for a writer that cannot stream.
func TestPortErrors_StreamWriter(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(streamPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	plainOutage := errors.New("connection reset by peer")

	sites := []streamWriterSite{
		{
			name: "the bottom writer's FlushError",
			wrap: func(w http.ResponseWriter, err error) http.ResponseWriter { return flushFailingBottom{w, err} },
		},
		{
			name: "a wrapper's FlushError, through the flush",
			wrap: func(w http.ResponseWriter, err error) http.ResponseWriter { return flushFailingAbove{w, err} },
		},
		{
			name: "a wrapper's SetWriteDeadline",
			wrap: func(w http.ResponseWriter, err error) http.ResponseWriter { return deadlineFailingAbove{w, err} },
		},
	}

	kinds := []stepUpPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		{name: "cycle claiming ErrNotSupported through Is", err: &notSupportedClaim{}, reason: "budget"},
		{name: "cycle wrapping ErrNotSupported", err: &throttleCycleWrapping{sentinel: http.ErrNotSupported}, reason: "budget"},
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}

	for _, site := range sites {
		for _, kind := range kinds {
			row := site.name + "/" + kind.name
			if childRow != "" && childRow != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if kind.child && childRow == "" {
					limiterPortErrInChild(t, streamPortErrRowEnv, streamPortErrRan, row)

					return
				}

				defaults := swapDefaultLogger(t)

				plain := streamThrough(t, site, plainOutage)
				require.Empty(t, abortRecords(plain.logs), "the plain failure writes no abort record")

				got := streamThrough(t, site, kind.err)

				assert.Equal(t, plain.status, got.status, "status")
				assert.Equal(t, comparableHeader(plain.header), comparableHeader(got.header), "headers")
				assert.Equal(t, plain.body, got.body, "body")
				assert.NotContains(t, got.body, hostileSecret, "the answer quotes the error")
				assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")

				aborts := abortRecords(got.logs)
				if kind.reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, aborts, 1, "one abort record, on the chain's logger")
					assertAbortRecord(t, aborts[0], kind.reason)
				}

				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

				if childRow != "" && !t.Failed() {
					fmt.Fprintln(os.Stdout, streamPortErrRan+row)
				}
			})
		}
	}
}
