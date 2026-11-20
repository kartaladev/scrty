package onetime_test

// TestPortErrors_TokensMint replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found. It shares the
// hostile error types and the child-process helper of tokens_porterr_test.go.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/idgen"
	"github.com/kartaladev/scrty/internal/idgen/idgentest"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// ptFailingReader answers every Read with err.
type ptFailingReader struct{ err error }

func (r ptFailingReader) Read([]byte) (int, error) { return 0, r.err }

// ptMintOutcome is what one failing issue produced and the state it left.
type ptMintOutcome struct {
	ok           bool
	text         string
	limitReached bool
	unwalkable   bool
	stored       int
	aborts       []map[string]any
	defaults     []map[string]any
}

// ptMintSource names the consumer port a mint run fails.
type ptMintSource string

const (
	ptGenerator ptMintSource = "the id generator"
	ptReader    ptMintSource = "the random reader"
)

// ptMintRun issues a token, through Issue or IssueWithin, by a manager whose
// source fails with portErr (nil makes the generator answer the nil
// identifier), and reports what came back. It fails the test when the call
// hangs or lets a panic escape.
func ptMintRun(t *testing.T, source ptMintSource, within bool, portErr error) ptMintOutcome {
	t.Helper()

	defaults := &ptBuffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(defaults, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logs := &ptBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mem, err := onetime.NewMemoryStore()
	require.NoError(t, err)

	opts := []onetime.Option{onetime.WithStore(mem), onetime.WithLogger(logger)}

	switch source {
	case ptGenerator:
		gen := idgentest.NewMockGenerator(gomock.NewController(t))
		gen.EXPECT().NewID().Return(id.Nil, portErr).AnyTimes()

		opts = append(opts, onetime.WithIDGenerator(gen))
	case ptReader:
		opts = append(opts, onetime.WithRandom(ptFailingReader{err: portErr}))
	}

	m, err := onetime.New("pt-purpose", opts...)
	require.NoError(t, err)

	type result struct {
		out      ptMintOutcome
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
		if within {
			_, _, err = m.IssueWithin(t.Context(), "s-1", 5)
		} else {
			_, _, err = m.Issue(t.Context(), "s-1")
		}

		// Every classification a caller makes runs inside the bound.
		o := ptMintOutcome{ok: err == nil}
		if err != nil {
			o.text = err.Error()
			o.limitReached = errors.Is(err, onetime.ErrIssueLimitReached)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}

		returned = true
		done <- result{out: o}
	}()

	var out ptMintOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a port error escaped as a panic: %v", r.value)

		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the operation, or its classification")
	}

	out.stored = mem.Len()

	for _, rec := range logs.records(t) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	for _, rec := range defaults.records(t) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.defaults = append(out.defaults, rec)
		}
	}

	return out
}

// TestPortErrors_TokensMint pins that an error a consumer's id generator or
// random reader returns whose chain cannot be walked is answered as a plain
// error from the same port is: a failed issue that stored nothing and is not
// the issue limit, with one abort record on the manager's logger, none on
// slog.Default(), and no hang or panic. The library's own nil-identifier
// error is left as it was.
func TestPortErrors_TokensMint(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(ptRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	type testCase struct {
		name   string
		source ptMintSource
		within bool
		err    error
		child  bool

		assert func(t *testing.T, plain, got ptMintOutcome)
	}

	asOutage := func(reason string) func(t *testing.T, plain, got ptMintOutcome) {
		return func(t *testing.T, plain, got ptMintOutcome) {
			t.Helper()

			require.False(t, plain.ok, "precondition: a plain error is no success")
			require.False(t, plain.limitReached, "precondition: a plain error is no limit reached")

			assert.False(t, got.ok, "never answered success")
			assert.False(t, got.limitReached, "a port error never reads as the issue limit reached")
			assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")
			assert.Equal(t, plain.stored, got.stored, "nothing is stored, as for a plain error")
			assert.NotContains(t, got.text, ptSecret, "the error quotes the consumer's")

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
			assert.Empty(t, got.defaults, "no abort record on slog.Default()")

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), ptSecret, "the record quotes the error")
		}
	}

	walked := func(t *testing.T, plain, got ptMintOutcome) {
		t.Helper()

		assert.False(t, got.ok, "never answered success")
		assert.False(t, got.limitReached)
		assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
		assert.Equal(t, plain.stored, got.stored)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
		assert.Empty(t, got.defaults, "a walk that completes writes no abort record")
	}

	var cases []testCase

	for _, source := range []ptMintSource{ptGenerator, ptReader} {
		for _, within := range []bool{false, true} {
			prefix := string(source) + " through Issue: "
			if within {
				prefix = string(source) + " through IssueWithin: "
			}

			for _, row := range ptRows(onetime.ErrIssueLimitReached) {
				if row.cancel {
					continue // the mint reads no context-dependent port
				}

				cases = append(cases, testCase{
					name: prefix + row.name, source: source, within: within, err: row.err,
					child: row.child, assert: asOutage(row.reason),
				})
			}

			cases = append(cases,
				testCase{
					name:   prefix + "a typed-nil root walks to the end and is answered as an error",
					source: source, within: within, err: (*ptTypedNil)(nil), assert: walked,
				},
				testCase{
					name:   prefix + "a plain error, against itself",
					source: source, within: within, err: ptErrDown, assert: walked,
				},
			)
		}
	}

	cases = append(cases, testCase{
		name:   "the generator answering the nil identifier keeps the library's own error",
		source: ptGenerator, err: nil,
		assert: func(t *testing.T, _, got ptMintOutcome) {
			t.Helper()

			assert.False(t, got.ok)
			assert.Contains(t, got.text, idgen.ErrNil.Error())
			assert.Empty(t, got.aborts)
			assert.Empty(t, got.defaults)
		},
	})

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				ptInChild(t, tc.name)

				return
			}

			var plain ptMintOutcome

			if tc.err != nil {
				plain = ptMintRun(t, tc.source, tc.within, ptErrDown)
				require.Empty(t, plain.aborts, "a plain error writes no abort record")
				require.Empty(t, plain.defaults, "a plain error writes no abort record")
			}

			got := ptMintRun(t, tc.source, tc.within, tc.err)
			tc.assert(t, plain, got)

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(ptRanMarker + tc.name + "\n")
			}
		})
	}
}
