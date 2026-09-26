package diag_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/diag"
)

// causeText is what a consumer's store might write: it quotes an address and a
// user reference the library must not repeat.
const causeText = "store: Key (username)=(alice@example.com) for user u-123"

// leaked are the values of causeText that must never reach a record or a
// returned error's text.
var leaked = []string{"alice@example.com", "u-123", "Key (username)"}

// errNotFound and errUnavailable stand for library sentinels.
var (
	errNotFound    = errors.New("scrty: the session was not found")
	errUnavailable = errors.New("scrty: the store is unavailable")
)

// storeError is a typed dependency error, like a database driver's.
type storeError struct{ detail string }

func (e *storeError) Error() string { return e.detail }

// valueError is a dependency error with a value receiver, so a value of it
// carries its detail inline rather than behind a pointer.
type valueError struct{ detail string }

func (e valueError) Error() string { return e.detail }

// sliceError is a value-receiver error with a slice field: two values of it
// cannot be compared with ==.
type sliceError struct{ parts []string }

func (e sliceError) Error() string { return fmt.Sprint(e.parts) }

// boxError is a comparable type whose value is not comparable when its field
// holds a sliceError.
type boxError struct{ inner error }

func (e boxError) Error() string { return e.inner.Error() }

// attrValues indexes attrs by key, failing on a repeated key.
func attrValues(t *testing.T, attrs []slog.Attr) map[string]slog.Value {
	t.Helper()

	values := make(map[string]slog.Value, len(attrs))
	for _, a := range attrs {
		_, dup := values[a.Key]
		require.Falsef(t, dup, "attribute %q repeated", a.Key)
		values[a.Key] = a.Value
	}

	return values
}

func assertNoCauseText(t *testing.T, rendered string) {
	t.Helper()

	for _, v := range leaked {
		assert.NotContains(t, rendered, v)
	}
}

func TestFailure(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, attrs []slog.Attr)
	}

	cases := []testCase{
		{
			name: "a plain dependency error is recorded by reason and type only",
			err:  errors.New(causeText),
			assert: func(t *testing.T, attrs []slog.Attr) {
				assertNoCauseText(t, fmt.Sprint(attrs))

				values := attrValues(t, attrs)
				assert.Len(t, values, 2)
				assert.Equal(t, "attempt-store", values["reason"].String())
				assert.Equal(t, "*errors.errorString", values["error_type"].String())
			},
		},
		{
			name: "a typed dependency error is recorded by its type",
			err:  &storeError{detail: causeText},
			assert: func(t *testing.T, attrs []slog.Attr) {
				assertNoCauseText(t, fmt.Sprint(attrs))
				assert.Equal(t, "*diag_test.storeError", attrValues(t, attrs)["error_type"].String())
			},
		},
		{
			name: "an error wrapped twice is recorded by its outermost type, without text",
			err:  fmt.Errorf("x: %w", fmt.Errorf("y: %w", &storeError{detail: causeText})),
			assert: func(t *testing.T, attrs []slog.Attr) {
				assertNoCauseText(t, fmt.Sprint(attrs))
				assert.NotContains(t, fmt.Sprint(attrs), "x: ")

				values := attrValues(t, attrs)
				assert.Equal(t, "*fmt.wrapError", values["error_type"].String())
				assert.NotContains(t, values, "cancelled")
			},
		},
		{
			name: "a wrapped cancellation is flagged",
			err:  fmt.Errorf("store: %w", context.Canceled),
			assert: func(t *testing.T, attrs []slog.Attr) {
				values := attrValues(t, attrs)
				require.Contains(t, values, "cancelled")
				assert.True(t, values["cancelled"].Bool())
				assert.Equal(t, "attempt-store", values["reason"].String())
			},
		},
		{
			name: "a wrapped deadline is flagged",
			err:  fmt.Errorf("store: %w", context.DeadlineExceeded),
			assert: func(t *testing.T, attrs []slog.Attr) {
				values := attrValues(t, attrs)
				require.Contains(t, values, "cancelled")
				assert.True(t, values["cancelled"].Bool())
			},
		},
		{
			name: "a record rendered by the text and JSON handlers carries reason and type, not the cause",
			err:  valueError{detail: causeText},
			assert: func(t *testing.T, attrs []slog.Attr) {
				var text, js bytes.Buffer
				slog.New(slog.NewTextHandler(&text, nil)).LogAttrs(t.Context(), slog.LevelError, "store failed", attrs...)
				slog.New(slog.NewJSONHandler(&js, nil)).LogAttrs(t.Context(), slog.LevelError, "store failed", attrs...)

				assertNoCauseText(t, text.String())
				assert.Contains(t, text.String(), "reason=attempt-store")
				assert.Contains(t, text.String(), "error_type=diag_test.valueError")

				assertNoCauseText(t, js.String())
				var record map[string]any
				require.NoError(t, json.Unmarshal(js.Bytes(), &record))
				assert.Equal(t, "attempt-store", record["reason"])
				assert.Equal(t, "diag_test.valueError", record["error_type"])
			},
		},
		{
			name: "a fault is recorded by its cause's type, without text",
			err:  diag.Wrap(&storeError{detail: causeText}, "scrty: the session could not be saved"),
			assert: func(t *testing.T, attrs []slog.Attr) {
				assertNoCauseText(t, fmt.Sprint(attrs))
				assert.NotContains(t, fmt.Sprint(attrs), "could not be saved")

				values := attrValues(t, attrs)
				assert.Equal(t, "*diag_test.storeError", values["error_type"].String())
				assert.NotContains(t, values, "cancelled")
			},
		},
		{
			name: "a fault around a fault is recorded by the innermost cause's type",
			err: diag.Wrap(
				diag.Wrap(valueError{detail: causeText}, "scrty: inner", errNotFound),
				"scrty: outer", errUnavailable),
			assert: func(t *testing.T, attrs []slog.Attr) {
				assertNoCauseText(t, fmt.Sprint(attrs))
				assert.Equal(t, "diag_test.valueError", attrValues(t, attrs)["error_type"].String())
			},
		},
		{
			name: "a fault wrapped by fmt.Errorf is looked through to its cause's type",
			err:  fmt.Errorf("x: %w", diag.Wrap(&storeError{detail: causeText}, "scrty: inner")),
			assert: func(t *testing.T, attrs []slog.Attr) {
				assertNoCauseText(t, fmt.Sprint(attrs))
				assert.NotContains(t, fmt.Sprint(attrs), "x: ")
				assert.Equal(t, "*diag_test.storeError", attrValues(t, attrs)["error_type"].String())
			},
		},
		{
			name: "a cancellation inside a fault is flagged, and typed by the cause",
			err:  diag.Wrap(fmt.Errorf("store: %w", context.Canceled), "scrty: inner", errUnavailable),
			assert: func(t *testing.T, attrs []slog.Attr) {
				values := attrValues(t, attrs)
				require.Contains(t, values, "cancelled")
				assert.True(t, values["cancelled"].Bool())
				assert.Equal(t, "*fmt.wrapError", values["error_type"].String())
			},
		},
		{
			name: "a nil error still records the reason",
			err:  nil,
			assert: func(t *testing.T, attrs []slog.Attr) {
				values := attrValues(t, attrs)
				assert.Equal(t, "attempt-store", values["reason"].String())
				assert.Equal(t, "<nil>", values["error_type"].String())
				assert.NotContains(t, values, "cancelled")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, diag.Failure("attempt-store", tc.err))
		})
	}
}

func TestWrap(t *testing.T) {
	t.Parallel()

	const text = "scrty: the session could not be saved"

	// callerKinds is the caller's own slice, changed after Wrap returns.
	callerKinds := []error{errNotFound, errUnavailable}

	type testCase struct {
		name   string
		err    error
		kinds  []error
		assert func(t *testing.T, cause, got error)
	}

	cases := []testCase{
		{
			name:  "a dependency error gets the fixed text and stays reachable",
			err:   errors.New(causeText),
			kinds: []error{errNotFound},
			assert: func(t *testing.T, cause, got error) {
				require.Error(t, got)
				require.EqualError(t, got, text)
				assert.Equal(t, text, fmt.Sprintf("%+v", got))
				assertNoCauseText(t, fmt.Sprintf("%v %s %q", got, got, got))
				assert.ErrorIs(t, got, cause)
				assert.ErrorIs(t, got, errNotFound)
				assert.NotErrorIs(t, got, errUnavailable)
			},
		},
		{
			name:  "every kind is reachable, and a typed cause is found by type",
			err:   &storeError{detail: causeText},
			kinds: []error{errNotFound, errUnavailable},
			assert: func(t *testing.T, cause, got error) {
				require.EqualError(t, got, text)
				assert.ErrorIs(t, got, errNotFound)
				assert.ErrorIs(t, got, errUnavailable)

				var typed *storeError
				require.ErrorAs(t, got, &typed)
				assert.Same(t, cause, typed)
			},
		},
		{
			name: "a cause wrapped twice is reachable and its text is not repeated",
			err: fmt.Errorf("x: %w",
				fmt.Errorf("y: %w", &storeError{detail: causeText})),
			kinds: []error{errUnavailable},
			assert: func(t *testing.T, cause, got error) {
				require.EqualError(t, got, text)
				assert.ErrorIs(t, got, cause)
				assert.ErrorIs(t, got, errUnavailable)

				var typed *storeError
				assert.ErrorAs(t, got, &typed)
			},
		},
		{
			name:  "no kinds still hides the text and keeps the cause",
			err:   errors.New(causeText),
			kinds: nil,
			assert: func(t *testing.T, cause, got error) {
				require.EqualError(t, got, text)
				assert.ErrorIs(t, got, cause)

				var fault *diag.Fault
				require.ErrorAs(t, got, &fault)
				assert.Equal(t, []error{cause}, fault.Unwrap())
			},
		},
		{
			name:  "unwrap lists the kinds, then the cause, in a slice of its own",
			err:   errors.New(causeText),
			kinds: []error{errNotFound, errUnavailable},
			assert: func(t *testing.T, cause, got error) {
				var fault *diag.Fault
				require.ErrorAs(t, got, &fault)

				first := fault.Unwrap()
				require.Equal(t, []error{errNotFound, errUnavailable, cause}, first)

				first[0], first[2] = nil, nil
				assert.Equal(t, []error{errNotFound, errUnavailable, cause}, fault.Unwrap())
			},
		},
		{
			name:  "no fmt verb reveals a value-typed cause",
			err:   valueError{detail: causeText},
			kinds: []error{errNotFound},
			assert: func(t *testing.T, cause, got error) {
				require.EqualError(t, got, text)
				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
					assertNoCauseText(t, fmt.Sprintf(verb, got))
				}
				assert.Equal(t, text, fmt.Sprintf("%v", got))
				assert.Equal(t, text, fmt.Sprintf("%+v", got))
				assert.Equal(t, text, fmt.Sprintf("%s", got))
				assert.Equal(t, fmt.Sprintf("%q", text), fmt.Sprintf("%q", got))

				var typed valueError
				require.ErrorAs(t, got, &typed)
				assert.Equal(t, cause, typed)
			},
		},
		{
			name:  "a non-comparable cause of a kind's own type is not compared, and gets the fixed text",
			err:   sliceError{parts: []string{"alice@example.com", "u-123"}},
			kinds: []error{sliceError{parts: []string{"x"}}, errNotFound},
			assert: func(t *testing.T, cause, got error) {
				require.EqualError(t, got, text)
				assert.ErrorIs(t, got, errNotFound)

				var fault *diag.Fault
				require.ErrorAs(t, got, &fault)
				unwrapped := fault.Unwrap()
				require.Len(t, unwrapped, 3)
				assert.Equal(t, cause, unwrapped[2])
			},
		},
		{
			name:  "a comparable type holding a non-comparable value is not compared, and gets the fixed text",
			err:   boxError{inner: sliceError{parts: []string{"u-123"}}},
			kinds: []error{boxError{inner: sliceError{parts: []string{"x"}}}},
			assert: func(t *testing.T, _, got error) {
				require.EqualError(t, got, text)

				var fault *diag.Fault
				assert.ErrorAs(t, got, &fault)
			},
		},
		{
			name:  "a comparable value sentinel that is the error passes through as itself",
			err:   boxError{inner: errNotFound},
			kinds: []error{errUnavailable, boxError{inner: errNotFound}},
			assert: func(t *testing.T, cause, got error) {
				assert.Equal(t, cause, got)

				var fault *diag.Fault
				assert.NotErrorAs(t, got, &fault)
			},
		},
		{
			name:  "the caller changing its kinds slice after Wrap does not change the fault",
			err:   errors.New(causeText),
			kinds: callerKinds,
			assert: func(t *testing.T, cause, got error) {
				callerKinds[0], callerKinds[1] = nil, nil

				var fault *diag.Fault
				require.ErrorAs(t, got, &fault)
				assert.Equal(t, []error{errNotFound, errUnavailable, cause}, fault.Unwrap())
				assert.ErrorIs(t, got, errNotFound)
			},
		},
		{
			name:  "a bare sentinel passes through as itself",
			err:   errNotFound,
			kinds: []error{errUnavailable, errNotFound},
			assert: func(t *testing.T, cause, got error) {
				require.NotNil(t, got)
				assert.Same(t, cause, got)
			},
		},
		{
			name:  "a sentinel that is wrapped is not bare, and gets the fixed text",
			err:   fmt.Errorf("store: u-123: %w", errNotFound),
			kinds: []error{errNotFound},
			assert: func(t *testing.T, cause, got error) {
				require.EqualError(t, got, text)
				assert.ErrorIs(t, got, errNotFound)
				assert.ErrorIs(t, got, cause)
			},
		},
		{
			name:  "a wrapped cancellation stays a cancellation",
			err:   fmt.Errorf("store: %w", context.Canceled),
			kinds: []error{errUnavailable},
			assert: func(t *testing.T, _, got error) {
				require.EqualError(t, got, text)
				assert.ErrorIs(t, got, context.Canceled)
			},
		},
		{
			name:  "nil is nil",
			err:   nil,
			kinds: []error{errNotFound},
			assert: func(t *testing.T, _, got error) {
				assert.NoError(t, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.err, diag.Wrap(tc.err, text, tc.kinds...))
		})
	}
}
