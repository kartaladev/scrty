package passkey_test

//go:generate mockgen -source=../../pkg/id/generator.go -destination=generator_mock_test.go -package=passkey_test -typed

// TestPortErrors_RegisterRandom replaces slog.Default() for its duration, so
// it does not run in parallel, and it restores the logger it found. It shares
// the hostile error types of register_porterr_test.go and the child-process
// helper of register_pending_porterr_test.go.

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// prandRowEnv names the row a child process runs. It is empty in the parent.
const prandRowEnv = "SCRTY_PASSKEY_RANDOM_PORTERR_ROW"

// prandRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const prandRanMarker = "SCRTY_PASSKEY_RANDOM_PORTERR_RAN: "

// prandSite names the consumer port a row fails.
type prandSite string

const (
	prandGenerator prandSite = "BeginRegistration's id generator"
	prandHandle    prandSite = "BeginRegistration's random reader, for the user handle"
	prandMint      prandSite = "BeginRegistration's random reader, for the challenge"
	prandEmailCode prandSite = "FinishRegistration's random reader, for the emailed code"
)

// prandReader reads from crypto/rand until it has let ok reads through, then
// fails every read with err.
type prandReader struct {
	ok    atomic.Int32
	err   error
	armed atomic.Bool
}

func (r *prandReader) Read(p []byte) (int, error) {
	if r.armed.Load() {
		if r.ok.Add(-1) < 0 {
			return 0, r.err
		}
	}

	return rand.Read(p)
}

// prandOutcome is what one call through a failing port produced.
type prandOutcome struct {
	ok         bool
	text       string
	throttled  bool // passkey.ErrRegistrationThrottled
	authFailed bool // authenticate.ErrAuthenticationFailed
	unwalkable bool

	challenges int // creation options rendered
	stored     int // passkeys the user holds afterwards
	sent       int // messages the sender queued

	aborts   []map[string]any // the sanitizer's records on the manager's logger
	defaults []map[string]any // the sanitizer's records on slog.Default()
}

// prandRun runs the operation site names against a port failing with portErr.
// It fails the test when the call or the classification of its error hangs,
// or when a panic escapes.
func prandRun(t *testing.T, site prandSite, portErr error) prandOutcome {
	t.Helper()

	defaults := &logBuffer{}
	slog.SetDefault(defaults.logger())

	logs := &logBuffer{}
	f := newFixture(t)
	reader := &prandReader{err: portErr}
	opts := []passkey.Option{passkey.WithLogger(logs.logger()), passkey.WithRandom(reader)}

	switch site {
	case prandGenerator:
		gen := NewMockGenerator(gomock.NewController(t))
		gen.EXPECT().NewID().Return(id.Nil, portErr).AnyTimes()

		opts = append(opts, passkey.WithIDGenerator(gen))
	case prandHandle:
		reader.armed.Store(true) // the first read is the handle's
	case prandMint:
		reader.ok.Store(1) // the handle's read succeeds, the challenge's fails
		reader.armed.Store(true)
	}

	m := f.manager(t, opts...)

	var call func() error

	switch site {
	case prandEmailCode:
		s := enrolmentSession("sess-a", "u-1")
		rc := passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: permissive(t)}
		challenge := f.begin(t, m, s)

		reader.armed.Store(true)

		call = func() error {
			_, err := m.FinishRegistration(t.Context(), s, regBody(challenge, "cred-a", ""), rc)

			return err
		}
	default:
		call = func() error {
			_, err := m.BeginRegistration(t.Context(), fullSession("sess-a", "u-1"), passkey.RegistrationContext{})

			return err
		}
	}

	type result struct {
		out      prandOutcome
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

		err := call()

		// Every classification a caller makes runs inside the bound.
		o := prandOutcome{ok: err == nil}
		if err != nil {
			o.text = err.Error()
			o.throttled = errors.Is(err, passkey.ErrRegistrationThrottled)
			o.authFailed = errors.Is(err, authenticate.ErrAuthenticationFailed)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}

		returned = true
		done <- result{out: o}
	}()

	var out prandOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a port error escaped as a panic: %v", r.value)

		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	held, err := f.creds.List(t.Context(), "u-1")
	require.NoError(t, err)

	out.stored = len(held)
	out.sent = len(f.messages())

	out.challenges = len(f.creations())
	if site == prandEmailCode {
		out.challenges-- // the begin that preceded the failing finish
	}

	for _, rec := range plogRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	for _, rec := range plogRecords(t, defaults.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.defaults = append(out.defaults, rec)
		}
	}

	return out
}

// TestPortErrors_RegisterRandom pins that an error a consumer's id generator
// or random reader returns, whose chain cannot be walked, is answered as a
// plain error from the same port is: the same refusal, nothing issued, stored
// or sent, one abort record on the manager's logger, none on slog.Default(),
// and no hang or panic. The reader of the user handle, of the challenge
// (through onetime) and of the emailed code, and the generator of the
// challenge (through onetime), are each a row.
func TestPortErrors_RegisterRandom(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(prandRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	type testCase struct {
		name  string
		site  prandSite
		err   error
		child bool

		assert func(t *testing.T, plain, got prandOutcome)
	}

	asOutage := func(reason string) func(t *testing.T, plain, got prandOutcome) {
		return func(t *testing.T, plain, got prandOutcome) {
			t.Helper()

			require.False(t, plain.ok, "precondition: a plain error is no success")

			assert.False(t, got.ok, "never answered success")
			assert.Equal(t, plain.throttled, got.throttled, "the same throttled class")
			assert.Equal(t, plain.authFailed, got.authFailed, "the same authentication-failed class")
			assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")
			assert.NotContains(t, got.text, pregSecret, "the error quotes the consumer's")
			assert.Equal(t, plain.challenges, got.challenges, "the same challenges issued")
			assert.Equal(t, plain.stored, got.stored, "the same passkeys stored")
			assert.Equal(t, plain.sent, got.sent, "the same messages sent")

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
			assert.Empty(t, got.defaults, "no abort record on slog.Default()")

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), pregSecret, "the record quotes the error")
		}
	}

	walked := func(t *testing.T, plain, got prandOutcome) {
		t.Helper()

		assert.False(t, got.ok, "never answered success")
		assert.Equal(t, plain.throttled, got.throttled)
		assert.Equal(t, plain.authFailed, got.authFailed)
		assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
		assert.Equal(t, plain.stored, got.stored)
		assert.Equal(t, plain.sent, got.sent)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
		assert.Empty(t, got.defaults, "a walk that completes writes no abort record")
	}

	rows := []struct {
		name   string
		err    error
		reason string
		child  bool
	}{
		{name: "a cycle through Unwrap() error", err: &pregCycleOne{}, reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: &pregCycleMany{}, reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: pregPanicUnwrap{}, reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: pregPanicNilUnwrap{}, reason: "panic"},
		{name: "a join that fans out", err: pregFanOut(25), reason: "budget"},
	}

	var cases []testCase

	for _, site := range []prandSite{prandGenerator, prandHandle, prandMint, prandEmailCode} {
		prefix := string(site) + ": "

		for _, row := range rows {
			cases = append(cases, testCase{
				name: prefix + row.name, site: site, err: row.err, child: row.child,
				assert: asOutage(row.reason),
			})
		}

		cases = append(cases,
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an error",
				site: site, err: (*pregTypedNil)(nil), assert: walked,
			},
			testCase{name: prefix + "a plain error, against itself", site: site, err: pregOutage, assert: walked},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				portErrInChild(t, prandRowEnv, prandRanMarker, tc.name)

				return
			}

			plain := prandRun(t, tc.site, pregOutage)
			require.Empty(t, plain.aborts, "a plain error writes no abort record")
			require.Empty(t, plain.defaults, "a plain error writes no abort record")

			got := prandRun(t, tc.site, tc.err)
			tc.assert(t, plain, got)

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(prandRanMarker + tc.name + "\n")
			}
		})
	}
}
