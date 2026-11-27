package httpsec

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/porterr"
)

// TestCSRFAnswer pins csrfAnswer against error trees a consumer's CSRF token
// source can return: whatever methods of the tree panic, loop or answer
// differently when asked again, a refusal stays a refusal, the request is
// never panicked, and a walk that aborts is recorded.
func TestCSRFAnswer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    func() error
		assert func(t *testing.T, got error, panicked any, logs []slog.Record)
	}

	errOutage := errors.New("token store down")

	// crossSite asserts the answer is the cross-site refusal, reached without a
	// panic, and that it records exactly the abort named by reason ("" for
	// none).
	crossSite := func(reason string) func(*testing.T, error, any, []slog.Record) {
		return func(t *testing.T, got error, panicked any, logs []slog.Record) {
			t.Helper()
			require.Nil(t, panicked, "csrfAnswer must not panic")
			require.ErrorIs(t, got, ErrCrossSiteRequest)
			assert.NotErrorIs(t, got, ErrAuthenticationRequired)

			aborts := csrfAnswerAborts(logs)
			if reason == "" {
				assert.Empty(t, aborts, "nothing aborted, so nothing is reported")

				return
			}

			require.Len(t, aborts, 1, "the abort is reported once")
			gotReason, ok := csrfAnswerAttr(aborts[0], "reason")
			require.True(t, ok)
			assert.Equal(t, reason, gotReason)
		}
	}

	cases := []testCase{
		{
			name:   "the sentinel alone is the cross-site refusal",
			err:    func() error { return ErrAuthenticationRequired },
			assert: crossSite(""),
		},
		{
			name: "an outage joined to the sentinel is the outage alone",
			err:  func() error { return errors.Join(ErrAuthenticationRequired, errOutage) },
			assert: func(t *testing.T, got error, panicked any, logs []slog.Record) {
				t.Helper()
				require.Nil(t, panicked)
				require.ErrorIs(t, got, errOutage)
				assert.NotErrorIs(t, got, ErrAuthenticationRequired)
				assert.NotErrorIs(t, got, ErrCrossSiteRequest)
				assert.Empty(t, csrfAnswerAborts(logs))
			},
		},
		{
			name: "an error not matching the sentinel is returned as it is",
			err:  func() error { return errOutage },
			assert: func(t *testing.T, got error, panicked any, logs []slog.Record) {
				t.Helper()
				require.Nil(t, panicked)
				assert.Same(t, errOutage, got) //nolint:testifylint // the very value, unchanged
				assert.Empty(t, csrfAnswerAborts(logs))
			},
		},
		{
			name:   "a cause matching the sentinel by its own Is method is the cross-site refusal",
			err:    func() error { return errors.Join(ErrAuthenticationRequired, csrfAnsIsAuth{}) },
			assert: crossSite(""),
		},
		{
			name:   "a panicking Is method after the sentinel is the cross-site refusal, reported",
			err:    func() error { return errors.Join(ErrAuthenticationRequired, csrfAnsPanickyIs{}) },
			assert: crossSite("panic"),
		},
		{
			name:   "a panicking Is method before the sentinel is the cross-site refusal, reported",
			err:    func() error { return errors.Join(csrfAnsPanickyIs{}, ErrAuthenticationRequired) },
			assert: crossSite("panic"),
		},
		{
			name: "a panicking Unwrap() []error is the cross-site refusal, reported",
			err: func() error {
				return errors.Join(ErrAuthenticationRequired, csrfAnsPanickyJoin{})
			},
			assert: crossSite("panic"),
		},
		{
			name: "an Unwrap that panics when asked a second time is asked once",
			err: func() error {
				return &csrfAnsOnceJoin{first: []error{ErrAuthenticationRequired, errOutage}}
			},
			assert: func(t *testing.T, got error, panicked any, logs []slog.Record) {
				t.Helper()
				require.Nil(t, panicked, "csrfAnswer must not unwrap a node twice")
				require.ErrorIs(t, got, errOutage)
				assert.NotErrorIs(t, got, ErrAuthenticationRequired)
				assert.Empty(t, csrfAnswerAborts(logs))
			},
		},
		{
			name: "a cycle through Unwrap() error is the cross-site refusal, reported",
			err: func() error {
				loop := &csrfAnsLoop{}
				loop.next = loop

				return errors.Join(ErrAuthenticationRequired, loop)
			},
			assert: crossSite("budget"),
		},
		{
			name: "a wrapper wrapping nothing beside the sentinel is no cause: the cross-site refusal",
			err: func() error {
				return errors.Join(ErrAuthenticationRequired, &csrfAnsLoop{})
			},
			assert: crossSite(""),
		},
		{
			name: "an outage under a wrapper beside the sentinel is the outage alone",
			err: func() error {
				return errors.Join(ErrAuthenticationRequired, &csrfAnsLoop{next: errOutage})
			},
			assert: func(t *testing.T, got error, panicked any, logs []slog.Record) {
				t.Helper()
				require.Nil(t, panicked)
				require.ErrorIs(t, got, errOutage)
				assert.NotErrorIs(t, got, ErrAuthenticationRequired)
				assert.Empty(t, csrfAnswerAborts(logs))
			},
		},
		{
			name:   "a wrapper over nothing whose own Is matches the sentinel is the cross-site refusal",
			err:    func() error { return &csrfAnsIsWrap{} },
			assert: crossSite(""),
		},
		{
			name: "a wrapper over an outage whose own Is matches the sentinel is the outage alone",
			err:  func() error { return &csrfAnsIsWrap{next: errOutage} },
			assert: func(t *testing.T, got error, panicked any, logs []slog.Record) {
				t.Helper()
				require.Nil(t, panicked)
				require.ErrorIs(t, got, errOutage)
				assert.NotErrorIs(t, got, ErrAuthenticationRequired)
				assert.NotErrorIs(t, got, ErrCrossSiteRequest)
				assert.Empty(t, csrfAnswerAborts(logs))
			},
		},
		{
			name: "a tree larger than the cause budget is the cross-site refusal, reported",
			err: func() error {
				errs := []error{ErrAuthenticationRequired}
				for i := range csrfCauseBudget {
					errs = append(errs, errors.New("cause "+strconv.Itoa(i)))
				}

				return errors.Join(errs...)
			},
			assert: crossSite("budget"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &csrfAnswerLogs{}
			ctx := ctxlog.With(t.Context(), slog.New(logs))
			err := tc.err()

			var (
				got      error
				panicked any
			)

			func() {
				defer func() { panicked = recover() }()

				got = csrfAnswer(ctx, err)
			}()

			tc.assert(t, got, panicked, logs.records())
		})
	}
}

// csrfAnsIsAuth is a leaf that matches ErrAuthenticationRequired by its own Is.
type csrfAnsIsAuth struct{}

func (csrfAnsIsAuth) Error() string        { return "claims authentication required" }
func (csrfAnsIsAuth) Is(target error) bool { return target == ErrAuthenticationRequired } //nolint:errorlint // the sentinel itself

// csrfAnsPanickyIs is a leaf whose Is method panics.
type csrfAnsPanickyIs struct{}

func (csrfAnsPanickyIs) Error() string { return "panicky is" }
func (csrfAnsPanickyIs) Is(error) bool { panic("csrfAnsPanickyIs.Is") }

// csrfAnsPanickyJoin is a join whose Unwrap panics.
type csrfAnsPanickyJoin struct{}

func (csrfAnsPanickyJoin) Error() string   { return "panicky join" }
func (csrfAnsPanickyJoin) Unwrap() []error { panic("csrfAnsPanickyJoin.Unwrap") }

// csrfAnsOnceJoin is a join that answers first on its first Unwrap and panics
// on every later one.
type csrfAnsOnceJoin struct {
	first []error
	calls atomic.Int32
}

func (*csrfAnsOnceJoin) Error() string { return "once join" }

func (e *csrfAnsOnceJoin) Unwrap() []error {
	if e.calls.Add(1) > 1 {
		panic("csrfAnsOnceJoin.Unwrap asked again")
	}

	return e.first
}

// csrfAnsIsWrap is a wrapper whose own Is matches ErrAuthenticationRequired.
type csrfAnsIsWrap struct{ next error }

func (*csrfAnsIsWrap) Error() string   { return "wrapper claiming authentication required" }
func (e *csrfAnsIsWrap) Unwrap() error { return e.next }
func (*csrfAnsIsWrap) Is(target error) bool {
	return target == ErrAuthenticationRequired //nolint:errorlint // the sentinel itself
}

// csrfAnsLoop wraps next, which may be itself.
type csrfAnsLoop struct{ next error }

func (*csrfAnsLoop) Error() string   { return "loop" }
func (e *csrfAnsLoop) Unwrap() error { return e.next }

// csrfAnswerLogs captures the records csrfAnswer writes.
type csrfAnswerLogs struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (*csrfAnswerLogs) Enabled(context.Context, slog.Level) bool { return true }

func (h *csrfAnswerLogs) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.recs = append(h.recs, r.Clone())

	return nil
}

func (h *csrfAnswerLogs) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *csrfAnswerLogs) WithGroup(string) slog.Handler      { return h }

func (h *csrfAnswerLogs) records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]slog.Record(nil), h.recs...)
}

// csrfAnswerAborts returns the aborted-classification records among recs.
func csrfAnswerAborts(recs []slog.Record) []slog.Record {
	var out []slog.Record

	for _, r := range recs {
		if r.Message == porterr.MsgClassificationAborted {
			out = append(out, r)
		}
	}

	return out
}

// csrfAnswerAttr returns the string value of r's attribute key.
func csrfAnswerAttr(r slog.Record, key string) (string, bool) {
	var (
		val   string
		found bool
	)

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val, found = a.Value.String(), true

			return false
		}

		return true
	})

	return val, found
}
