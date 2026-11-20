package depfault_test

// TestPortErrors_Store replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

//go:generate mockgen -source=../../token/onetime/store.go -package=depfault_test -destination=onetime_store_mock_test.go -typed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/depfault"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// spSecret is text no record may quote.
const spSecret = "sp-secret: ana@example.com"

// spErrDown is the plain outage the parity runs fail with.
var spErrDown = errors.New("sp: connection refused, " + spSecret)

// spPanicNilUnwrap is an error whose Unwrap panics with nil.
type spPanicNilUnwrap struct{}

func (spPanicNilUnwrap) Error() string { return spSecret }
func (spPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// spTypedNil is returned as a nil pointer inside a non-nil error.
type spTypedNil struct{}

func (*spTypedNil) Error() string { return spSecret }

// spCycleAround holds sentinel first and then itself: a stdlib errors.Is for
// sentinel answers yes at once, and one for anything else overflows the
// stack. Its rows run in a child process.
type spCycleAround struct{ sentinel error }

func (*spCycleAround) Error() string     { return spSecret }
func (c *spCycleAround) Unwrap() []error { return []error{c.sentinel, c} }

// spFanOver is errors.Join(n, n) nested 25 times over leaf.
func spFanOver(leaf error) error {
	err := leaf
	for range 25 {
		err = errors.Join(err, err)
	}

	return err
}

// spBuffer is a buffer safe for a logger's concurrent writes.
type spBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *spBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *spBuffer) aborts(t *testing.T) []map[string]any {
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

		if rec["msg"] == porterr.MsgClassificationAborted {
			records = append(records, rec)
		}
	}

	return records
}

// spMethod names the decorated store method a row fails.
type spMethod string

const (
	spFind         spMethod = "FindByID"
	spConsume      spMethod = "Consume"
	spInsert       spMethod = "Insert"
	spInsertWithin spMethod = "InsertWithin"
	spCount        spMethod = "CountRecentBySubject"
	spDelete       spMethod = "DeleteExpiredBefore"
)

// spWatched reports whether the decorator notes method's failures on a Watch.
func spWatched(method spMethod) bool { return method == spFind || method == spConsume }

// spOutcome is what one call through the decorator returned, and what its
// Watch holds. Every classification is made inside the bound.
type spOutcome struct {
	same       bool // the store's own error value came back
	failed     bool
	unwalkable bool
	notFound   bool
	canceled   bool
	n          int  // the count, or the number removed
	stored     bool // InsertWithin's answer

	watchFailed bool
	watchSame   bool // the Watch holds the very error the call returned

	// aborts are the records on the logger the store was given, and defaults
	// the ones on slog.Default().
	aborts   []map[string]any
	defaults []map[string]any
}

// spRun calls method through depfault.Store on ctx, with a Watch, while the
// consumer's store fails it with portErr and answers 3 (and true) beside it.
func spRun(t *testing.T, ctx context.Context, method spMethod, portErr error) spOutcome {
	t.Helper()

	defaults := &spBuffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(defaults, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logs := &spBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctrl := gomock.NewController(t)
	inner := NewMockStore(ctrl)
	reaper := NewMockReaper(ctrl)

	switch method {
	case spFind:
		inner.EXPECT().FindByID(gomock.Any(), gomock.Any()).Return(nil, portErr)
	case spConsume:
		inner.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).Return(portErr)
	case spInsert:
		inner.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(portErr)
	case spInsertWithin:
		inner.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, portErr)
	case spCount:
		inner.EXPECT().CountRecentBySubject(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(3, portErr)
	case spDelete:
		reaper.EXPECT().DeleteExpiredBefore(gomock.Any(), gomock.Any(), gomock.Any()).Return(3, portErr)
	}

	s := depfault.Store(struct {
		*MockStore
		*MockReaper
	}{inner, reaper}, logger)

	ctx, w := depfault.Watching(ctx)

	out := within(t, func() spOutcome {
		var (
			o   spOutcome
			err error
		)

		switch method {
		case spFind:
			_, err = s.FindByID(ctx, id.Nil)
		case spConsume:
			err = s.Consume(ctx, id.Nil, time.Time{})
		case spInsert:
			err = s.Insert(ctx, onetime.Token{})
		case spInsertWithin:
			o.stored, err = s.InsertWithin(ctx, onetime.Token{}, time.Time{}, 1)
		case spCount:
			o.n, err = s.CountRecentBySubject(ctx, "p", "s", time.Time{})
		case spDelete:
			o.n, err = s.(onetime.Reaper).DeleteExpiredBefore(ctx, "p", time.Time{})
		}

		o.same = err == portErr //nolint:errorlint // identity
		if err != nil {
			o.failed = true
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
			o.notFound = errors.Is(err, onetime.ErrTokenNotFound)
			o.canceled = errors.Is(err, context.Canceled)
		}

		if failure := w.Failure(); failure != nil {
			o.watchFailed = true
			o.watchSame = failure == err //nolint:errorlint // identity
		}

		return o
	})

	out.aborts = logs.aborts(t)
	out.defaults = defaults.aborts(t)

	return out
}

// TestPortErrors_Store pins that the decorator sanitizes every call it
// forwards to the consumer's store before the error reaches the manager or
// the Watch: an error whose chain cannot be walked comes back, and is noted,
// as the sanitizer's fault, with one abort record on the logger the store was given, and is
// answered as a plain outage is. A walkable error is the same value as before.
func TestPortErrors_Store(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := childRow()

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name   string
		method spMethod
		err    error
		child  bool
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, plain, got spOutcome)
	}

	sameAsPlain := func(t *testing.T, method spMethod, plain, got spOutcome) {
		t.Helper()

		require.True(t, plain.failed, "precondition: a plain outage fails")
		require.Equal(t, spWatched(method), plain.watchFailed, "precondition: a plain outage is noted where watched")

		assert.True(t, got.failed, "never answered success")
		assert.False(t, got.notFound, "an outage never reads as a token the store does not hold")
		assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
		assert.Equal(t, plain.n, got.n, "the store's count passes through")
		assert.Equal(t, plain.stored, got.stored, "the store's answer passes through")
		assert.Equal(t, plain.watchFailed, got.watchFailed, "noted, or not, as a plain outage")
	}

	asFault := func(method spMethod, reason string) func(t *testing.T, plain, got spOutcome) {
		return func(t *testing.T, plain, got spOutcome) {
			t.Helper()

			sameAsPlain(t, method, plain, got)
			assert.False(t, got.same, "the store's error is not passed on")
			assert.True(t, got.unwalkable, "the call answers the sanitizer's fault")
			if spWatched(method) {
				assert.True(t, got.watchSame, "the Watch holds the fault the call answered")
			}

			require.Len(t, got.aborts, 1, "one abort record, on the logger the store was given")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
			assert.Empty(t, got.defaults, "no abort record on slog.Default()")

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), spSecret, "the record quotes the error")
		}
	}

	unchanged := func(method spMethod) func(t *testing.T, plain, got spOutcome) {
		return func(t *testing.T, plain, got spOutcome) {
			t.Helper()

			sameAsPlain(t, method, plain, got)
			assert.True(t, got.same, "a walkable error is the same value")
			assert.False(t, got.unwalkable)
			if spWatched(method) {
				assert.True(t, got.watchSame, "the Watch holds the store's own error")
			}
			assert.Empty(t, got.aborts, "a walk that completes writes no record")
			assert.Empty(t, got.defaults, "a walk that completes writes no record")
		}
	}

	var cases []testCase

	for _, method := range []spMethod{spFind, spConsume, spInsert, spInsertWithin, spCount, spDelete} {
		prefix := string(method) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", method: method, err: &cycleOne{}, assert: asFault(method, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", method: method, err: &cycleMany{}, child: true, assert: asFault(method, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", method: method, err: panicUnwrap{}, assert: asFault(method, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", method: method, err: spPanicNilUnwrap{}, assert: asFault(method, "panic")},
			testCase{name: prefix + "a join that fans out", method: method, err: fanOut(25), assert: asFault(method, "budget")},
			testCase{
				name:   prefix + "a join that fans out over ErrTokenNotFound",
				method: method, err: spFanOver(onetime.ErrTokenNotFound), assert: asFault(method, "budget"),
			},
			testCase{
				name:   prefix + "a cycle around ErrTokenNotFound",
				method: method, err: &spCycleAround{sentinel: onetime.ErrTokenNotFound}, child: true, assert: asFault(method, "budget"),
			},
			testCase{
				name:   prefix + "a join that fans out over context.Canceled on a context the caller cancelled",
				method: method, err: spFanOver(context.Canceled), ctx: cancelled, assert: asFault(method, "budget"),
			},
			testCase{
				name:   prefix + "a typed-nil root is the same value",
				method: method, err: (*spTypedNil)(nil), assert: unchanged(method),
			},
			testCase{name: prefix + "a plain outage, against itself", method: method, err: spErrDown, assert: unchanged(method)},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				inChild(t, tc.name)

				return
			}

			announceRan(t, only, tc.name)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := spRun(t, ctx, tc.method, spErrDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.Empty(t, plain.defaults, "a plain outage writes no abort record")

			tc.assert(t, plain, spRun(t, ctx, tc.method, tc.err))
		})
	}
}
