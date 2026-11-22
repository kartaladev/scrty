package recovered_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/recovered"
)

// secret stands for text a consumer's panic value holds. No record may carry it.
const secret = "s3cr3t-token-value"

const (
	// childRowEnv names the TestCall row a child test binary runs.
	childRowEnv = "RECOVERED_TEST_CHILD_ROW"
	// childMarker is the line a child prints, only when its row passed.
	childMarker = "recovered-child-row-ok"
)

// recorder is a slog handler the test owns: it keeps every record it is given.
type recorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *recorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *recorder) WithGroup(string) slog.Handler            { return r }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec.Clone())
	return nil
}

func (r *recorder) all() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]slog.Record(nil), r.records...)
}

// attrs flattens a record's attributes by key.
func attrs(rec slog.Record) map[string]string {
	out := map[string]string{}
	rec.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.String()
		return true
	})
	return out
}

// panickingHandler is a consumer's slog handler that panics on every record.
type panickingHandler struct{}

func (panickingHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (panickingHandler) WithAttrs([]slog.Attr) slog.Handler        { return panickingHandler{} }
func (panickingHandler) WithGroup(string) slog.Handler             { return panickingHandler{} }
func (panickingHandler) Handle(context.Context, slog.Record) error { panic("sink down") }

// hostile is a panic value whose text methods panic or hold a secret.
type hostile struct{}

func (hostile) Error() string  { panic("Error method: " + secret) }
func (hostile) String() string { return secret }

func TestCall(t *testing.T) { // not parallel: rows swap slog's default logger
	type testCase struct {
		name   string
		f      func() error
		nilLog bool
		nilCtx bool
		// badSink gives a logger whose handler panics when it writes.
		badSink bool
		// legacy runs the row in a child test binary under GODEBUG=panicnil=1.
		legacy bool
		// assert receives the records written to the given logger and to the default logger.
		assert func(t *testing.T, err error, given, def []slog.Record)
	}

	sentinel := errors.New("consumer failure")

	// panicked asserts the one record every recovered panic writes.
	panicked := func(wantType string) func(t *testing.T, err error, given, def []slog.Record) {
		return func(t *testing.T, err error, given, def []slog.Record) {
			require.ErrorIs(t, err, recovered.ErrPanicked)
			assert.Empty(t, def, "a given logger leaves the default logger alone")
			require.Len(t, given, 1)
			rec := given[0]
			assert.Equal(t, slog.LevelError, rec.Level)
			assert.Equal(t, "consumer code panicked", rec.Message)
			got := attrs(rec)
			assert.Equal(t, "refresh", got["what"])
			if wantType != "" {
				assert.Equal(t, wantType, got["panic_type"])
			} else {
				assert.NotEmpty(t, got["panic_type"])
			}
			assert.Contains(t, got["frames"], "recovered_test.TestCall", "frames name where the consumer's code panicked")
			for k, v := range got {
				assert.NotContains(t, v, secret, "attribute %q carries the panic value's text", k)
			}
		}
	}

	cases := []testCase{
		{
			name: "no panic, nil",
			f:    func() error { return nil },
			assert: func(t *testing.T, err error, given, def []slog.Record) {
				require.NoError(t, err)
				assert.Empty(t, given)
				assert.Empty(t, def)
			},
		},
		{
			name: "no panic, error",
			f:    func() error { return sentinel },
			assert: func(t *testing.T, err error, given, def []slog.Record) {
				require.Same(t, sentinel, err, "the error comes back unchanged")
				assert.Empty(t, given)
				assert.Empty(t, def)
			},
		},
		{
			name:   "panic with a string",
			f:      func() error { panic("boom " + secret) },
			assert: panicked("string"),
		},
		{
			name:   "panic with an error",
			f:      func() error { panic(fmt.Errorf("wrapped: %w", errors.New(secret))) },
			assert: panicked("*fmt.wrapError"),
		},
		{
			name: "runtime error (nil map write)",
			f: func() error {
				var m map[string]int
				m["k"] = 1 //nolint:staticcheck // SA5000: the panic is the point: a runtime error inside the consumer's f
				return nil
			},
			assert: panicked(""),
		},
		{
			name:   "panic(nil), default mode",
			f:      func() error { panic(nil) },
			assert: panicked("*runtime.PanicNilError"),
		},
		{
			// recover() returns nil here, so only the returned flag tells.
			name:   "legacy_panicnil_mode_child",
			f:      func() error { panic(nil) },
			legacy: true,
			assert: panicked(""),
		},
		{
			name:   "value with a hostile Error method",
			f:      func() error { panic(hostile{}) },
			assert: panicked("recovered_test.hostile"),
		},
		{
			name:   "nil context still records",
			f:      func() error { panic("boom") },
			nilCtx: true,
			assert: panicked("string"),
		},
		{
			name:   "nil logger writes to the default logger",
			f:      func() error { panic("boom") },
			nilLog: true,
			assert: func(t *testing.T, err error, given, def []slog.Record) {
				require.ErrorIs(t, err, recovered.ErrPanicked)
				assert.Empty(t, given)
				require.Len(t, def, 1)
				assert.Equal(t, "consumer code panicked", def[0].Message)
				assert.Equal(t, "refresh", attrs(def[0])["what"])
			},
		},
		{
			name:    "logger whose handler panics",
			f:       func() error { panic("boom") },
			badSink: true,
			assert: func(t *testing.T, err error, _, def []slog.Record) {
				require.ErrorIs(t, err, recovered.ErrPanicked)
				assert.Empty(t, def)
			},
		},
		{
			name:   "nil logger, no panic, writes nothing",
			f:      func() error { return sentinel },
			nilLog: true,
			assert: func(t *testing.T, err error, given, def []slog.Record) {
				require.ErrorIs(t, err, sentinel)
				assert.Empty(t, given)
				assert.Empty(t, def)
			},
		},
		{
			name: "nil function is refused, not run",
			f:    nil,
			assert: func(t *testing.T, err error, given, def []slog.Record) {
				require.Error(t, err)
				assert.NotErrorIs(t, err, recovered.ErrPanicked)
				assert.Empty(t, given)
				assert.Empty(t, def)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.legacy {
				if os.Getenv(childRowEnv) != tc.name {
					runLegacyChild(t, tc.name)
					return
				}
				requireLegacyPanicNil(t)
			}
			def := &recorder{}
			prev := slog.Default()
			slog.SetDefault(slog.New(def))
			t.Cleanup(func() { slog.SetDefault(prev) })

			given := &recorder{}
			log := slog.New(given)
			if tc.nilLog {
				log = nil
			}
			if tc.badSink {
				log = slog.New(panickingHandler{})
			}
			ctx := t.Context()
			if tc.nilCtx {
				ctx = nil //nolint:staticcheck // the nil context is the row's point
			}

			var err error
			require.NotPanics(t, func() { err = recovered.Call(ctx, log, "refresh", tc.f) }, "Call never panics")
			tc.assert(t, err, given.all(), def.all())
			if tc.legacy && !t.Failed() {
				fmt.Println(childMarker)
			}
		})
	}
}

// runLegacyChild re-runs one TestCall row in a child of this test binary with
// GODEBUG=panicnil=1, which a running process cannot switch on for itself. The
// child prints childMarker only when the row passed; the parent needs a zero
// exit and one output line equal to the marker.
func runLegacyChild(t *testing.T, row string) {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.count=1", "-test.run", "^TestCall$/^"+regexp.QuoteMeta(row)+"$") //nolint:gosec // G204: this test binary re-executed with fixed arguments
	cmd.Env = append(os.Environ(), "GODEBUG=panicnil=1", childRowEnv+"="+row)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child output:\n%s", out)
	found := false
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == childMarker {
			found = true
		}
	}
	assert.True(t, found, "no output line equals the marker; child output:\n%s", out)
}

// requireLegacyPanicNil fails unless this process runs under panicnil=1, where
// recover() returns nil for panic(nil). It keeps a mis-set child from passing.
func requireLegacyPanicNil(t *testing.T) {
	t.Helper()
	var got any = "unset"
	func() {
		defer func() { got = recover() }()
		panic(nil)
	}()
	require.Nil(t, got, "the child must run under GODEBUG=panicnil=1")
}

// Standalone: it needs a goroutine of its own, which no TestCall row has.
func TestCall_GoexitInFWritesOneRecord(t *testing.T) {
	t.Parallel()
	given := &recorder{}
	var after atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = recovered.Call(t.Context(), slog.New(given), "refresh", func() error {
			runtime.Goexit()
			return nil
		})
		after.Store(true) // Goexit ends the goroutine: Call returns nothing to its caller
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the goroutine did not finish after runtime.Goexit")
	}
	assert.False(t, after.Load(), "Call must not return to its caller on Goexit")
	recs := given.all()
	require.Len(t, recs, 1)
	assert.Equal(t, slog.LevelError, recs[0].Level)
	assert.Equal(t, "consumer code panicked", recs[0].Message)
	assert.Equal(t, "refresh", attrs(recs[0])["what"])
}

func TestCall_ErrorTextHoldsNothingFromTheValue(t *testing.T) {
	t.Parallel()
	err := recovered.Call(t.Context(), slog.New(&recorder{}), "x", func() error { panic(hostile{}) })
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), secret))
}
