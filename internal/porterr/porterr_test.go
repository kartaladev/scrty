//go:debug panicnil=1

package porterr_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/internal/guardauth"
	"github.com/kartaladev/scrty/internal/porterr"
)

// secret is what a consumer's error text and panic values quote. It must
// never reach the fault's text or the record.
const secret = "alice@example.com"

// errUnavailable stands for a port's unavailable sentinel.
var errUnavailable = errors.New("scrty: the store is unavailable")

// errRefusal stands for a library refusal sentinel a call site's flow tests
// for, which a fault built with ErrUnwalkable must not match.
var errRefusal = errors.New("scrty: the request is refused")

// plainError is a consumer's ordinary error.
type plainError struct{}

func (*plainError) Error() string { return "store: " + secret }

// cycleOne contains itself through Unwrap() error.
type cycleOne struct{}

func (*cycleOne) Error() string   { return "cycle one: " + secret }
func (c *cycleOne) Unwrap() error { return c }

// cycleMany contains itself through Unwrap() []error.
type cycleMany struct{}

func (*cycleMany) Error() string     { return "cycle many: " + secret }
func (c *cycleMany) Unwrap() []error { return []error{c} }

// panicUnwrap is a link whose Unwrap panics with a value quoting the secret.
type panicUnwrap struct{}

func (panicUnwrap) Error() string { return "panic unwrap: " + secret }
func (panicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + secret) }

// panicNilUnwrap is a link whose Unwrap panics with nil, which recover
// reports as nil under GODEBUG=panicnil=1, set for this test binary above.
type panicNilUnwrap struct{}

func (panicNilUnwrap) Error() string { return "panic nil unwrap: " + secret }
func (panicNilUnwrap) Unwrap() error { panic(nil) }

// manyNils is a link whose Unwrap() []error is huge: a million nil entries.
type manyNils struct{ kids []error }

func (*manyNils) Error() string     { return "many nils: " + secret }
func (m *manyNils) Unwrap() []error { return m.kids }

// selectiveIs panics when its own Is method is asked about panicsOn, and
// matches nothing else.
type selectiveIs struct{ panicsOn error }

func (selectiveIs) Error() string { return "selective: " + secret }

func (e selectiveIs) Is(target error) bool {
	if target == e.panicsOn { //nolint:errorlint // the identity of the target asked about
		panic("test: Is panicked for " + secret)
	}

	return false
}

// fanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func fanOut(depth int) error {
	err := error(&plainError{})
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// recorder keeps every record it is handed.
type recorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (*recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.records = append(r.records, rec.Clone())

	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

func (r *recorder) all() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]slog.Record(nil), r.records...)
}

// recording makes slog.Default() write to a new recorder until the test ends.
// The default logger is process-wide, so a test that uses it is not parallel.
func recording(t *testing.T) *recorder {
	t.Helper()

	rec := new(recorder)
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return rec
}

// attrsOf returns a record's attributes by key, rendered as strings.
func attrsOf(rec slog.Record) map[string]string {
	attrs := make(map[string]string, rec.NumAttrs())
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()

		return true
	})

	return attrs
}

// rendered is rec as the JSON handler writes it.
func rendered(t *testing.T, rec slog.Record) string {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, slog.NewJSONHandler(&buf, nil).Handle(t.Context(), rec))

	return buf.String()
}

// sanitized is what one call of Sanitize did.
type sanitized struct {
	got      error
	panicked bool
	value    any
	records  []slog.Record
}

// TestSanitize pins the boundary sanitizer: an error the bounded walk reads to
// the end passes through as the same value, with no record; one it cannot read
// is replaced by a fixed *Fault that matches the port's unavailable sentinel,
// carries the abort and nothing of the consumer's, and writes exactly one
// record. A nil unavailable sentinel is a wiring mistake, refused on every
// call.
//
// It is not parallel: the record goes to slog.Default(), which is
// process-wide, and testing.AllocsPerRun counts every allocation in the
// process.
//
//nolint:paralleltest // see above
func TestSanitize(t *testing.T) {
	type testCase struct {
		name          string
		err           func() error
		noUnavailable bool
		unavailable   error // nil means errUnavailable
		assert        func(t *testing.T, in error, out sanitized)
	}

	unchanged := func(t *testing.T, in error, out sanitized) {
		t.Helper()
		require.False(t, out.panicked, "Sanitize panicked: %v", out.value)
		assert.True(t, in == out.got, "got %T, want the error itself", out.got) //nolint:errorlint // identity
		assert.Empty(t, out.records, "a walkable error wrote a record")
	}

	replacedFor := func(unavailable error, reason string, frame string) func(t *testing.T, in error, out sanitized) {
		return func(t *testing.T, _ error, out sanitized) {
			t.Helper()
			require.False(t, out.panicked, "Sanitize panicked: %v", out.value)

			// A type assertion first: stdlib must not inspect the error
			// before it is known to be the library's own.
			fault, ok := out.got.(*porterr.Fault) //nolint:errorlint // the exact value Sanitize returned
			require.True(t, ok, "got %T, want *porterr.Fault", out.got)

			assert.ErrorIs(t, out.got, unavailable)
			assert.ErrorIs(t, out.got, porterr.ErrUnwalkable, "every fault matches ErrUnwalkable")
			assert.Equal(t, reason, errwalk.Reason(fault.Abort()))

			chain, abort := errwalk.Flatten(out.got)
			require.NoError(t, abort, "the fault's own chain cannot be walked")
			assert.Equal(t, []error{fault, unavailable}, []error(chain), "the fault wraps something besides the sentinel")

			for _, text := range []string{out.got.Error(), fmt.Sprintf("%v", out.got), fmt.Sprintf("%+v", out.got), fmt.Sprintf("%#v", out.got)} {
				assert.NotEmpty(t, text)
				assert.NotContains(t, text, secret)
			}

			require.Len(t, out.records, 1, "an aborted walk must write exactly one record")
			rec := out.records[0]
			assert.Equal(t, slog.LevelError, rec.Level)
			assert.Equal(t, porterr.MsgClassificationAborted, rec.Message)
			assert.Equal(t, guardauth.MsgClassificationAborted, rec.Message, "one search finds every abort record")
			assert.NotContains(t, rendered(t, rec), secret)

			attrs := attrsOf(rec)
			assert.Equal(t, reason, attrs["reason"])

			if reason == "panic" {
				assert.Contains(t, attrs, "panic_type")
				assert.Contains(t, attrs["frames"], frame, "the frames do not name where the panic happened")
			} else {
				assert.NotContains(t, attrs, "panic_type")
				assert.NotContains(t, attrs, "frames")
			}
		}
	}

	replaced := func(reason string, frame string) func(t *testing.T, in error, out sanitized) {
		return replacedFor(errUnavailable, reason, frame)
	}

	cases := []testCase{
		{
			name: "a nil error is nil, with no record",
			err:  func() error { return nil },
			assert: func(t *testing.T, _ error, out sanitized) {
				require.False(t, out.panicked, "Sanitize panicked: %v", out.value)
				assert.NoError(t, out.got)
				assert.Empty(t, out.records)
			},
		},
		{name: "a plain error is the same value", err: func() error { return &plainError{} }, assert: unchanged},
		{
			name: "a walkable error does not match ErrUnwalkable",
			err:  func() error { return fmt.Errorf("store: %w", errUnavailable) },
			assert: func(t *testing.T, in error, out sanitized) {
				unchanged(t, in, out)
				assert.NotErrorIs(t, out.got, porterr.ErrUnwalkable)
			},
		},
		{
			name: "a wrapped unavailable sentinel is the same value",
			err:  func() error { return fmt.Errorf("store: %w", errUnavailable) },
			assert: func(t *testing.T, in error, out sanitized) {
				unchanged(t, in, out)
				assert.ErrorIs(t, out.got, errUnavailable)
			},
		},
		{
			name:   "a typed-nil pointer root is the same value, since the walk does not abort",
			err:    func() error { return (*plainError)(nil) },
			assert: unchanged,
		},
		{
			name:   "an error whose Is panics only for one sentinel passes, since the walk calls no Is (accepted)",
			err:    func() error { return fmt.Errorf("store: %w", selectiveIs{panicsOn: errUnavailable}) },
			assert: unchanged,
		},
		{
			name: "a fault sanitized again is the same fault, with no second record",
			err: func() error {
				// Built under a throwaway logger, so only the second call's
				// records are counted.
				prev := slog.Default()
				slog.SetDefault(slog.New(slog.DiscardHandler))
				defer slog.SetDefault(prev)

				return porterr.Sanitize(&cycleOne{}, errUnavailable)
			},
			assert: func(t *testing.T, in error, out sanitized) {
				unchanged(t, in, out)
				assert.ErrorIs(t, out.got, errUnavailable)
				assert.ErrorIs(t, out.got, porterr.ErrUnwalkable)
			},
		},
		{name: "a cycle through Unwrap() error", err: func() error { return &cycleOne{} }, assert: replaced("budget", "")},
		{name: "a cycle through Unwrap() []error", err: func() error { return &cycleMany{} }, assert: replaced("budget", "")},
		{
			name:        "a port with no unavailable sentinel: the fault matches ErrUnwalkable once and no refusal",
			err:         func() error { return &cycleOne{} },
			unavailable: porterr.ErrUnwalkable,
			assert: func(t *testing.T, in error, out sanitized) {
				replacedFor(porterr.ErrUnwalkable, "budget", "")(t, in, out)
				assert.NotErrorIs(t, out.got, errRefusal)
				assert.NotErrorIs(t, out.got, errUnavailable)
			},
		},
		{
			name:        "a panicking link with ErrUnwalkable as the sentinel",
			err:         func() error { return fmt.Errorf("store: %w", panicUnwrap{}) },
			unavailable: porterr.ErrUnwalkable,
			assert:      replacedFor(porterr.ErrUnwalkable, "panic", "porterr_test.panicUnwrap.Unwrap"),
		},
		{name: "a join that fans out", err: func() error { return fanOut(25) }, assert: replaced("budget", "")},
		{
			name:   "a link whose Unwrap() []error holds a million nils",
			err:    func() error { return &manyNils{kids: make([]error, 1_000_000)} },
			assert: replaced("budget", ""),
		},
		{
			name:   "a link whose Unwrap panics",
			err:    func() error { return fmt.Errorf("store: %w", panicUnwrap{}) },
			assert: replaced("panic", "porterr_test.panicUnwrap.Unwrap"),
		},
		{
			name:   "a link whose Unwrap panics with nil",
			err:    func() error { return fmt.Errorf("store: %w", panicNilUnwrap{}) },
			assert: replaced("panic", "porterr_test.panicNilUnwrap.Unwrap"),
		},
		{
			name: "a walkable short chain allocates nothing",
			err:  func() error { return fmt.Errorf("a: %w", fmt.Errorf("b: %w", &plainError{})) },
			assert: func(t *testing.T, in error, out sanitized) {
				unchanged(t, in, out)

				allocs := testing.AllocsPerRun(1000, func() {
					_ = porterr.Sanitize(in, errUnavailable)
				})
				assert.Zero(t, allocs, "Sanitize allocated for a chain that fits its buffer")
			},
		},
		{
			name:          "a nil unavailable sentinel is a wiring mistake, refused even for a nil error",
			err:           func() error { return nil },
			noUnavailable: true,
			assert: func(t *testing.T, _ error, out sanitized) {
				require.True(t, out.panicked, "Sanitize accepted a nil unavailable sentinel")
				assert.Contains(t, fmt.Sprint(out.value), "porterr")
				assert.Empty(t, out.records)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.err()
			rec := recording(t)

			unavailable := errUnavailable
			if tc.unavailable != nil {
				unavailable = tc.unavailable
			}

			if tc.noUnavailable {
				unavailable = nil
			}

			var out sanitized

			func() {
				defer func() {
					if out.panicked {
						out.value = recover()
					}
				}()

				out.panicked = true
				out.got = porterr.Sanitize(in, unavailable)
				out.panicked = false
			}()

			out.records = rec.all()
			tc.assert(t, in, out)
		})
	}
}

// TestSanitize_Concurrent pins that Sanitize keeps no state between calls:
// calls from many goroutines at once each get their own answer, and each
// aborted walk writes exactly one record. Run it with -race.
//
// It is not parallel: the record goes to slog.Default(), which is
// process-wide.
//
//nolint:paralleltest // see above
func TestSanitize_Concurrent(t *testing.T) {
	const (
		workers = 8
		calls   = 50
	)

	rec := recording(t)
	plain := &plainError{}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		faults int
		wrong  []string
	)

	for w := range workers {
		wg.Go(func() {
			for i := range calls {
				var in error = plain
				if (w+i)%2 == 0 {
					in = &cycleOne{}
				}

				got := porterr.Sanitize(in, errUnavailable)

				mu.Lock()
				if _, ok := got.(*porterr.Fault); ok { //nolint:errorlint // the exact value Sanitize returned
					faults++
				} else if got != in { //nolint:errorlint // identity
					wrong = append(wrong, fmt.Sprintf("%T", got))
				}
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	assert.Empty(t, wrong, "a walkable error came back as something else")
	assert.Equal(t, workers*calls/2, faults)
	assert.Len(t, rec.all(), faults, "each aborted walk must write exactly one record")

	for _, r := range rec.all() {
		assert.False(t, strings.Contains(rendered(t, r), secret))
	}
}
