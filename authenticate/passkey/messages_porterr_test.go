package passkey_test

// TestPortErrors_Notices replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found. The hostile error
// types, the outage, the failing-port switch and the default-logger capture are
// those of the login and registration port-error tests; the panic(nil) rows
// rely on the //go:debug panicnil=1 directive in login_porterr_test.go.

import (
	"context"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/notify"
)

// pmsgRowEnv names the row a child process runs. It is empty in the parent.
const pmsgRowEnv = "SCRTY_PASSKEY_NOTICE_PORTERR_ROW"

// pmsgRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pmsgRanMarker = "SCRTY_PASSKEY_NOTICE_PORTERR_RAN: "

// pmsgNotQueued is the manager's record of a notice it could not queue.
const pmsgNotQueued = "passkey: a notice was not queued"

// pmsgNotice is the notice's Send, the port call a row fails.
const pmsgNotice plogSite = "the binding notice's Send"

// pmsgSender fails the notice's Send, and is non-blocking as a queued sender
// is.
type pmsgSender struct {
	notify.Sender

	ports *plogPorts
}

func (s pmsgSender) Send(ctx context.Context, msg notify.Message) error {
	if err := s.ports.fails(pmsgNotice); err != nil {
		return err
	}

	return s.Sender.Send(ctx, msg)
}

func (pmsgSender) NonBlocking() bool { return true }

// pmsgOutcome is what one registration whose binding notice failed produced.
type pmsgOutcome struct {
	err       error
	panicked  bool
	activated bool // the finish returned an activated passkey
	active    int  // active passkeys the user holds afterwards

	// notQueued are the manager's "notice was not queued" records.
	notQueued []map[string]any
	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

// runNoticeSite finishes a registration from a full session, whose passkey is
// active at once and so owes the binding notice, against a consumer sender
// that fails that notice with portErr. When cancelDuring is set the failing
// call cancels the caller's context first. It fails the test when the finish
// hangs or panics.
func runNoticeSite(t *testing.T, portErr error, cancelDuring bool) pmsgOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ports := &plogPorts{site: pmsgNotice, err: portErr}
	if cancelDuring {
		ports.cancel = cancel
	}

	f := newFixture(t)
	f.deps.Sender = pmsgSender{Sender: f.deps.Sender, ports: ports}

	logs := &logBuffer{}
	m := f.manager(t, passkey.WithLogger(logs.logger()))
	s := fullSession("sess-a", "u-1")
	challenge := f.begin(t, m, s)

	ports.armed.Store(true)

	done := make(chan pmsgOutcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- pmsgOutcome{panicked: true}
			}
		}()

		res, err := m.FinishRegistration(ctx, s, regBody(challenge, "cred-a", ""), passkey.RegistrationContext{})

		returned = true
		done <- pmsgOutcome{err: err, activated: res != nil && res.Activated}
	}()

	var out pmsgOutcome

	select {
	case out = <-done:
		require.False(t, out.panicked, "a hostile port error escaped as a panic")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the finish")
	}

	held, err := f.creds.List(t.Context(), "u-1")
	require.NoError(t, err)

	for _, c := range held {
		if c.State == passkey.StateActive {
			out.active++
		}
	}

	for _, rec := range plogRecords(t, logs.String()) {
		switch rec["msg"] {
		case pmsgNotQueued:
			out.notQueued = append(out.notQueued, rec)
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// TestPortErrors_Notices pins that a consumer sender failing a passkey notice
// with an error whose chain cannot be walked is answered exactly as a plain
// outage is: the change the notice reports stands, the failure is logged by a
// fixed reason without the error's text, and the sanitizer writes one record
// to the manager's own logger and none to slog.Default().
func TestPortErrors_Notices(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pmsgRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		err  error

		// cancelDuring makes the failing call cancel the caller's context.
		cancelDuring bool

		// child runs the row in a child process.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pmsgOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got pmsgOutcome) {
		t.Helper()

		require.NoError(t, got.err, "a notice that fails does not fail the finish")
		assert.Equal(t, plain.err, got.err)
		assert.True(t, got.activated, "the passkey is active")
		assert.Equal(t, plain.activated, got.activated)
		assert.Equal(t, 1, got.active, "the passkey stays stored and active")
		assert.Equal(t, plain.active, got.active)

		require.Len(t, got.notQueued, 1, "the failed notice is logged")
		require.Len(t, plain.notQueued, 1)
		assert.Equal(t, "registered", got.notQueued[0]["reason"])
		assert.Equal(t, plain.notQueued[0]["reason"], got.notQueued[0]["reason"])

		for _, v := range got.notQueued[0] {
			if s, ok := v.(string); ok {
				assert.NotContains(t, s, plogSecret, "the record quotes the error")
			}
		}
	}

	asOutage := func(reason string) func(t *testing.T, plain, got pmsgOutcome) {
		return func(t *testing.T, plain, got pmsgOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			for _, v := range got.aborts[0] {
				if s, ok := v.(string); ok {
					assert.NotContains(t, s, plogSecret, "the record quotes the error")
				}
			}
		}
	}

	prefix := string(pmsgNotice) + ": "

	cases := []testCase{
		{name: prefix + "a cycle through Unwrap() error", err: &plogCycleOne{}, assert: asOutage("budget")},
		{name: prefix + "a cycle through Unwrap() []error", err: &plogCycleMany{}, child: true, assert: asOutage("budget")},
		{name: prefix + "a link whose Unwrap panics", err: plogPanicUnwrap{}, assert: asOutage("panic")},
		{name: prefix + "a link whose Unwrap panics with nil", err: plogPanicNilUnwrap{}, assert: asOutage("panic")},
		{name: prefix + "a join that fans out", err: plogFanOut(25), assert: asOutage("budget")},
		{
			name: prefix + "a cycle on a context the failing call cancelled is an outage",
			err:  &plogCycleOne{}, cancelDuring: true, assert: asOutage("budget"),
		},
		{
			name: prefix + "a typed-nil root walks to the end and is answered as an outage",
			err:  (*plogTypedNil)(nil),
			assert: func(t *testing.T, plain, got pmsgOutcome) {
				t.Helper()

				sameAsPlain(t, plain, got)
				assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
			},
		},
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				portErrInChild(t, pmsgRowEnv, pmsgRanMarker, tc.name)

				return
			}

			defaults := pregDefaultRecords(t)

			plain := runNoticeSite(t, plogOutage, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runNoticeSite(t, tc.err, tc.cancelDuring)
			tc.assert(t, plain, got)

			for _, rec := range plogRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pmsgRanMarker + tc.name + "\n")
			}
		})
	}
}
