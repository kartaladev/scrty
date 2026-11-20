package outbound_test

// TestOutboundPortErrors replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/outbound"
)

const (
	poSecret    = "po-secret-marker-7731"
	poRowEnv    = "SCRTY_OUTBOUND_PORTERR_ROW"
	poRanMarker = "SCRTY_OUTBOUND_PORTERR_RAN: "
)

type poCycleOne struct{}

func (*poCycleOne) Error() string   { return poSecret }
func (c *poCycleOne) Unwrap() error { return c }

type poCycleMany struct{}

func (*poCycleMany) Error() string     { return poSecret }
func (c *poCycleMany) Unwrap() []error { return []error{c} }

type poPanicUnwrap struct{}

func (poPanicUnwrap) Error() string { return poSecret }
func (poPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + poSecret) }

type poPanicNilUnwrap struct{}

func (poPanicNilUnwrap) Error() string { return poSecret }
func (poPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type poTypedNil struct{}

func (*poTypedNil) Error() string { return poSecret }

func poFanOut(depth int) error {
	err := errors.New(poSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// poBuffer is a buffer safe for the concurrent writes of a logger.
type poBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *poBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *poBuffer) records(t *testing.T) []map[string]any {
	t.Helper()

	b.mu.Lock()
	out := b.buf.String()
	b.mu.Unlock()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}

		rec := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}

	return records
}

// poTransport fails the exchange with err, either as the RoundTrip error or as
// the error of the response body's read.
type poTransport struct {
	err  error
	body bool
}

func (tr poTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !tr.body {
		return nil, tr.err
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(poFailingBody{err: tr.err}),
		Request:    req,
	}, nil
}

type poFailingBody struct{ err error }

func (b poFailingBody) Read([]byte) (int, error) { return 0, b.err }

type poOutcome struct {
	err    error
	text   string
	refuse bool
	unwalk bool
	aborts []map[string]any
}

// poRun sends one request through a client whose transport fails with portErr
// and reports the outcome. It fails the test when the call hangs or panics.
func poRun(t *testing.T, ctx context.Context, body, status bool, portErr error) poOutcome {
	t.Helper()

	defaults := &poBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(defaults, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	c, err := outbound.New(
		outbound.WithHTTPClient(&http.Client{Transport: poTransport{err: portErr, body: body}}),
		outbound.WithAllowedSchemes("https"),
	)
	require.NoError(t, err)

	type result struct {
		out      poOutcome
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				done <- result{panicked: true, value: recover()}
			}
		}()

		var err error
		if status {
			_, err = c.PostFormStatus(ctx, "https://idp.example/x", url.Values{}, nil)
		} else {
			_, err = c.Get(ctx, "https://idp.example/x", nil)
		}

		o := poOutcome{err: err}
		if err != nil {
			o.text = err.Error()
			o.refuse = errors.Is(err, outbound.ErrRefused)
			o.unwalk = errors.Is(err, porterr.ErrUnwalkable)
		}

		returned = true
		done <- result{out: o}
	}()

	var out poOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a port error escaped as a panic: %v", r.value)

		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile transport error hung the call, or its classification")
	}

	for _, rec := range defaults.records(t) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

type poRow struct {
	name   string
	err    error
	reason string // the abort record's reason; empty when the walk completes
	child  bool   // overflows the stack unsanitized: run in a child process
	cancel bool
}

func poRows() []poRow {
	return []poRow{
		{name: "a cycle through Unwrap() error", err: &poCycleOne{}, reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: &poCycleMany{}, reason: "budget", child: true},
		{name: "a fan-out join", err: poFanOut(40), reason: "budget"},
		{name: "a link whose Unwrap panics", err: poPanicUnwrap{}, reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: poPanicNilUnwrap{}, reason: "panic"},
		{name: "a typed nil root", err: (*poTypedNil)(nil)},
		{name: "a cycle on a context the caller cancelled", err: &poCycleOne{}, reason: "budget", cancel: true},
	}
}

func TestOutboundPortErrors(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(poRowEnv)

	paths := []struct {
		name         string
		body, status bool
	}{
		{name: "the transport's error"},
		{name: "the body read's error", body: true},
		{name: "the transport's error on PostFormStatus", status: true},
	}

	for _, p := range paths {
		for _, row := range poRows() {
			name := p.name + "/" + row.name

			if only != "" && only != name {
				continue
			}

			t.Run(name, func(t *testing.T) {
				if row.child && only == "" {
					poInChild(t, name)

					return
				}

				ctx := t.Context()
				if row.cancel {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}

				base := poRun(t, t.Context(), p.body, p.status, errors.New("boom"))
				require.Error(t, base.err)
				assert.False(t, base.unwalk)
				assert.Empty(t, base.aborts)

				got := poRun(t, ctx, p.body, p.status, row.err)

				require.Error(t, got.err)
				assert.Equal(t, base.refuse, got.refuse, "the same error class as a plain transport error")

				if row.reason == "" {
					// A walk that completes passes the error through, text and all.
					assert.False(t, got.unwalk)
					assert.Empty(t, got.aborts)
				} else {
					assert.NotContains(t, got.text, poSecret, "the consumer's text must not travel")
					assert.True(t, got.unwalk, "a walkable fault stands in for the hostile error")
					require.Len(t, got.aborts, 1, "exactly one abort record")
					assert.Equal(t, row.reason, got.aborts[0]["reason"])
					assert.NotContains(t, fmt.Sprint(got.aborts[0]), poSecret)
				}

				if only != "" {
					fmt.Println(poRanMarker + name)
				}
			})
		}
	}
}

// poInChild re-runs the top-level test in a child process limited to row, and
// fails unless the child exits 0 within a minute and prints a line equal to the
// row's marker.
func poInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOutboundPortErrors$", "-test.count=1")
	cmd.Env = append(os.Environ(), poRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	want := poRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
