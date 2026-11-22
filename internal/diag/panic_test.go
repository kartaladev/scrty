package diag_test

import (
	"bytes"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/diag"
)

// agreedFrameLimit is written out here, and not read from the package, because this is the
// number the two records agreed on: changing it is a decision, not an edit.
const agreedFrameLimit = 32

// secretText is what a panic's value quotes in these rows.
const secretText = "session-token-abc123"

// recordPanic stands where a caller's helper does: it is the frame PanicAttrs leaves out.
//
//go:noinline
func recordPanic(value any) []slog.Attr { return diag.PanicAttrs(value) }

// panicAt panics with value below depth frames of itself, and returns what recovering it records.
func panicAt(depth int, value any) (attrs []slog.Attr) {
	defer func() { attrs = recordPanic(recover()) }()

	descendAndPanic(depth, value)

	return nil
}

//go:noinline
func descendAndPanic(depth int, value any) {
	if depth > 0 {
		descendAndPanic(depth-1, value)

		return
	}

	panic(value)
}

// renderPanic is what a handler writes for attrs: the whole record, as an operator reads it.
func renderPanic(t *testing.T, attrs []slog.Attr) string {
	t.Helper()

	var buf bytes.Buffer

	slog.New(slog.NewJSONHandler(&buf, nil)).LogAttrs(t.Context(), slog.LevelError, "panicked", attrs...)

	return buf.String()
}

func TestPanicAttrs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		depth  int
		value  any
		assert func(t *testing.T, panicType string, frames []string, rendered string)
	}

	cases := []testCase{
		{
			name:  "a panic deeper than the limit names exactly the agreed frames",
			depth: 4 * agreedFrameLimit,
			value: "deep",
			assert: func(t *testing.T, _ string, frames []string, _ string) {
				assert.Len(t, frames, agreedFrameLimit)
				assert.Contains(t, frames[0], "panicAt", "the frames start above the caller of PanicAttrs")
			},
		},
		{
			name:  "a shallow panic names only the frames it has, each with a function",
			depth: 1,
			value: "shallow",
			assert: func(t *testing.T, _ string, frames []string, _ string) {
				assert.Less(t, len(frames), agreedFrameLimit)

				for _, frame := range frames {
					assert.Regexp(t, `^\S+ \S+:\d+$`, frame, "function file:line")
				}
			},
		},
		{
			name:  "the frames reach where it panicked and leave out the caller of PanicAttrs",
			depth: 1,
			value: "where",
			assert: func(t *testing.T, _ string, frames []string, _ string) {
				joined := strings.Join(frames, "\n")

				assert.Contains(t, joined, "descendAndPanic")
				assert.NotContains(t, joined, "recordPanic")
			},
		},
		{
			name:  "a string value is not logged, only its type",
			depth: 1,
			value: secretText,
			assert: func(t *testing.T, panicType string, _ []string, rendered string) {
				assert.Equal(t, "string", panicType)
				assert.NotContains(t, rendered, secretText)
			},
		},
		{
			name:  "an error value's text is not logged, only its type",
			depth: 1,
			value: errors.New(secretText),
			assert: func(t *testing.T, panicType string, _ []string, rendered string) {
				assert.Equal(t, "*errors.errorString", panicType)
				assert.NotContains(t, rendered, secretText)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			attrs := panicAt(tc.depth, tc.value)

			require.Len(t, attrs, 2, "a panic's record holds its type and its frames")
			require.Equal(t, "panic_type", attrs[0].Key)
			require.Equal(t, "frames", attrs[1].Key)

			tc.assert(t, attrs[0].Value.String(), strings.Split(attrs[1].Value.String(), "; "), renderPanic(t, attrs))
		})
	}
}

// capturedPCLimit is more than the agreed limit, so a deep capture hands
// PanicAttrsFrom more frames than it may name.
const capturedPCLimit = 4 * agreedFrameLimit

// capturePCs is the stack above its caller, as a recovering helper captures it.
//
//go:noinline
func capturePCs() []uintptr {
	pcs := make([]uintptr, capturedPCLimit)

	return pcs[:runtime.Callers(2, pcs)]
}

// panicAtCapturing panics with value below depth frames of itself, and returns
// what PanicAttrs records on recovering it and the stack captured beside it.
// Both are taken on one line of one function, so their frames are the same.
func panicAtCapturing(depth int, value any) (attrs []slog.Attr, pcs []uintptr) {
	defer func() { attrs, pcs = recordPanic(recover()), capturePCs() }()

	descendAndPanic(depth, value)

	return nil, nil
}

func TestPanicAttrsFrom(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		depth int
		value any
		// pcs changes the captured stack before it is formatted; nil keeps it.
		pcs    func(captured []uintptr) []uintptr
		assert func(t *testing.T, from, viaPanicAttrs []slog.Attr, rendered string)
	}

	sameAsPanicAttrs := func(t *testing.T, from, viaPanicAttrs []slog.Attr, _ string) {
		t.Helper()
		assert.Equal(t, viaPanicAttrs, from, "the same frames give the same record")
	}

	cases := []testCase{
		{name: "a shallow panic gives what PanicAttrs gives", depth: 1, value: "shallow", assert: sameAsPanicAttrs},
		{
			name:  "a stack deeper than the limit names exactly the agreed frames, as PanicAttrs does",
			depth: 2 * capturedPCLimit,
			value: "deep",
			assert: func(t *testing.T, from, viaPanicAttrs []slog.Attr, rendered string) {
				t.Helper()
				sameAsPanicAttrs(t, from, viaPanicAttrs, rendered)
				assert.Len(t, strings.Split(from[1].Value.String(), "; "), agreedFrameLimit)
			},
		},
		{
			name:  "a string value is not logged, only its type",
			depth: 1,
			value: secretText,
			assert: func(t *testing.T, from, viaPanicAttrs []slog.Attr, rendered string) {
				t.Helper()
				sameAsPanicAttrs(t, from, viaPanicAttrs, rendered)
				assert.Equal(t, "string", from[0].Value.String())
				assert.NotContains(t, rendered, secretText)
			},
		},
		{
			name:  "an error value's text is not logged, only its type",
			depth: 1,
			value: errors.New(secretText),
			assert: func(t *testing.T, from, viaPanicAttrs []slog.Attr, rendered string) {
				t.Helper()
				sameAsPanicAttrs(t, from, viaPanicAttrs, rendered)
				assert.Equal(t, "*errors.errorString", from[0].Value.String())
				assert.NotContains(t, rendered, secretText)
			},
		},
		{
			name:  "no captured frames still gives both keys, with no frames",
			depth: 1,
			value: "none",
			pcs:   func([]uintptr) []uintptr { return nil },
			assert: func(t *testing.T, from, _ []slog.Attr, _ string) {
				t.Helper()
				assert.Equal(t, "string", from[0].Value.String())
				assert.Empty(t, from[1].Value.String())
			},
		},
		{
			name:  "frames the runtime cannot name are left out",
			depth: 1,
			value: "unnamed",
			pcs:   func([]uintptr) []uintptr { return []uintptr{0, 1} },
			assert: func(t *testing.T, from, _ []slog.Attr, _ string) {
				t.Helper()
				assert.Empty(t, from[1].Value.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			viaPanicAttrs, pcs := panicAtCapturing(tc.depth, tc.value)
			if tc.pcs != nil {
				pcs = tc.pcs(pcs)
			}

			from := diag.PanicAttrsFrom(tc.value, pcs)

			require.Len(t, from, 2, "a panic's record holds its type and its frames")
			require.Equal(t, "panic_type", from[0].Key)
			require.Equal(t, "frames", from[1].Key)

			tc.assert(t, from, viaPanicAttrs, renderPanic(t, from))
		})
	}
}
