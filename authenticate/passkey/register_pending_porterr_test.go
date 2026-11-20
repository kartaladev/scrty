package passkey_test

// TestPortErrors_RegisterPending replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found. The hostile
// error types, the outage, the failing-port switch and the default-logger
// capture are those of the login and registration port-error tests; the
// panic(nil) rows rely on the //go:debug panicnil=1 directive in
// login_porterr_test.go.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
)

// ppendRowEnv names the row a child process runs. It is empty in the parent.
const ppendRowEnv = "SCRTY_PASSKEY_PENDING_PORTERR_ROW"

// ppendRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const ppendRanMarker = "SCRTY_PASSKEY_PENDING_PORTERR_RAN: "

const ppendChildRowDeadline = time.Minute

// ppendMsgNotRemoved is the manager's record of an unsettled passkey whose
// removal failed.
const ppendMsgNotRemoved = "passkey: a passkey whose registration failed after it was stored could not be removed"

// The port calls of pending registration a row fails.
const (
	ppendListAbandon  plogSite = "FinishRegistration's abandoned-registration List"
	ppendDelAbandon   plogSite = "FinishRegistration's abandoned-registration Delete"
	ppendDelUnsettled plogSite = "an unsettled finish's Delete"
	ppendListAwait    plogSite = "ConfirmEmailCode's awaiting List"
	ppendCharge       plogSite = "ConfirmEmailCode's ChargeEmailAttempt"
	ppendClear        plogSite = "ConfirmEmailCode's ClearReason"
)

// ppendCreds fails the call its ports name. A Delete after a passkey was
// stored while armed is the unsettled finish's removal; any other is the
// removal of an abandoned registration.
type ppendCreds struct {
	*passkey.MemoryCredentialStore

	ports    *plogPorts
	inserted *atomic.Bool
}

func (s ppendCreds) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	for _, site := range []plogSite{ppendListAbandon, ppendListAwait} {
		if err := s.ports.fails(site); err != nil {
			return nil, err
		}
	}

	return s.MemoryCredentialStore.List(ctx, user)
}

func (s ppendCreds) InsertWithin(ctx context.Context, c *passkey.Credential, limit int) (bool, error) {
	ok, err := s.MemoryCredentialStore.InsertWithin(ctx, c, limit)
	if ok && err == nil && s.ports.armed.Load() {
		s.inserted.Store(true)
	}

	return ok, err
}

func (s ppendCreds) Delete(ctx context.Context, user identity.UserID, cid id.ID) (bool, error) {
	site := ppendDelAbandon
	if s.inserted.Load() {
		site = ppendDelUnsettled
	}

	if err := s.ports.fails(site); err != nil {
		return false, err
	}

	return s.MemoryCredentialStore.Delete(ctx, user, cid)
}

func (s ppendCreds) ChargeEmailAttempt(
	ctx context.Context, user identity.UserID, cid id.ID, at time.Time,
) (*passkey.EmailCode, bool, error) {
	if err := s.ports.fails(ppendCharge); err != nil {
		return nil, false, err
	}

	return s.MemoryCredentialStore.ChargeEmailAttempt(ctx, user, cid, at)
}

func (s ppendCreds) ClearReason(
	ctx context.Context, user identity.UserID, cid id.ID, r passkey.PendingReason,
) (passkey.State, bool, error) {
	if err := s.ports.fails(ppendClear); err != nil {
		return 0, false, err
	}

	return s.MemoryCredentialStore.ClearReason(ctx, user, cid, r)
}

// ppendLimiter is a permissive confirmation limiter that counts the refusals
// recorded on it.
type ppendLimiter struct {
	ratelimit.Limiter

	failures atomic.Int32
}

func (l *ppendLimiter) RecordFailure(ctx context.Context, key string) error {
	l.failures.Add(1)

	return l.Limiter.RecordFailure(ctx, key)
}

// ppendOutcome is what one pending-registration call through a failing port
// produced.
type ppendOutcome struct {
	err      error
	text     string
	panicked bool

	authFailed   bool
	limit        bool
	throttled    bool // mfa.ErrEnrolmentThrottled
	rateLimited  bool // ratelimit.ErrThrottled
	invalidCode  bool // mfa.ErrInvalidCode
	emailInvalid bool // mfa.ErrEmailCodeInvalid
	interrupted  bool // matches context.Canceled or context.DeadlineExceeded
	returned     bool // a registration result or an activated passkey came back

	stored   int   // passkeys the user holds afterwards
	pending  int   // of which pending
	sent     int   // messages the sender queued
	failures int32 // refusals counted on the confirmation limiter

	// notRemoved are the manager's "could not be removed" records.
	notRemoved []map[string]any
	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

// runPendingSite runs the pending-registration call site names against a
// consumer credential store that fails it with portErr. When cancelDuring is
// set the failing call cancels the caller's context first. It fails the test
// when the call, or the classification of its error, hangs or panics.
func runPendingSite(t *testing.T, site plogSite, portErr error, cancelDuring bool) ppendOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ports := &plogPorts{site: site, err: portErr}
	if cancelDuring {
		ports.cancel = cancel
	}

	f := newFixture(t)
	f.deps.Credentials = ppendCreds{MemoryCredentialStore: f.creds, ports: ports, inserted: &atomic.Bool{}}

	logs := &logBuffer{}
	m := f.manager(t, passkey.WithLogger(logs.logger()))
	s := enrolmentSession("sess-a", "u-1")
	limiter := &ppendLimiter{Limiter: permissive(t)}
	rc := passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: limiter}

	// finishing begins a registration, before the port is armed, and returns
	// the call that finishes it.
	finishing := func(ctx context.Context, credID string) func() (bool, error) {
		challenge := f.begin(t, m, s)

		return func() (bool, error) {
			res, err := m.FinishRegistration(ctx, s, regBody(challenge, credID, ""), rc)

			return res != nil, err
		}
	}

	var call func() (bool, error)

	switch site {
	case ppendListAbandon:
		call = finishing(ctx, "cred-a")
	case ppendDelAbandon:
		_, err := finishing(t.Context(), "cred-a")()
		require.NoError(t, err)

		// Only a passkey created before the new challenge is abandoned.
		f.clock.Advance(time.Minute)

		call = finishing(ctx, "cred-b")
	case ppendDelUnsettled:
		f.sendErr = errors.New("sender: queue full")
		call = finishing(ctx, "cred-a")
	default:
		_, err := finishing(t.Context(), "cred-a")()
		require.NoError(t, err)

		code := emailedCode(t, f)
		call = func() (bool, error) {
			c, err := m.ConfirmEmailCode(ctx, s, code, rc)

			return c != nil, err
		}
	}

	ports.armed.Store(true)

	done := make(chan ppendOutcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- ppendOutcome{panicked: true}
			}
		}()

		var out ppendOutcome

		got, err := call()

		// Classified inside the bound: a hostile chain that reaches the caller
		// raw hangs here, and fails the run as a hang.
		out.err, out.returned = err, got
		if err != nil {
			out.text = err.Error()
			out.authFailed = errors.Is(err, authenticate.ErrAuthenticationFailed)
			out.limit = errors.Is(err, passkey.ErrPerUserLimitReached)
			out.throttled = errors.Is(err, mfa.ErrEnrolmentThrottled)
			out.rateLimited = errors.Is(err, ratelimit.ErrThrottled)
			out.invalidCode = errors.Is(err, mfa.ErrInvalidCode)
			out.emailInvalid = errors.Is(err, mfa.ErrEmailCodeInvalid)
			out.interrupted = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		}

		returned = true
		done <- out
	}()

	var out ppendOutcome

	select {
	case out = <-done:
		require.False(t, out.panicked, "a hostile port error escaped as a panic")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	held, err := f.creds.List(t.Context(), "u-1")
	require.NoError(t, err)

	out.stored = len(held)
	for _, c := range held {
		if c.State == passkey.StatePending {
			out.pending++
		}
	}

	out.sent = len(f.messages())
	out.failures = limiter.failures.Load()

	for _, rec := range plogRecords(t, logs.String()) {
		switch rec["msg"] {
		case ppendMsgNotRemoved:
			out.notRemoved = append(out.notRemoved, rec)
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// TestPortErrors_RegisterPending pins that a consumer credential store failing
// a pending registration with an error whose chain cannot be walked is
// answered exactly as a plain outage is, and never as one of the outcomes the
// site branches on:
//
//   - the listing or removal of abandoned registrations failing refuses the
//     finish, stores nothing new, keeps the abandoned passkey and sends no
//     code; it is never the passkey limit;
//   - the removal of a passkey whose finish failed after storing it is logged,
//     and the finish still fails with the error that caused it;
//   - the confirmation's listing, attempt charge or reason clearing failing is
//     an error: never a confirmed passkey, never a refused code counted on the
//     limiter, never a throttle, even when the error claims one of those or
//     the caller's context was cancelled during the call.
//
// The sanitizer writes one record to the manager's own logger and none to
// slog.Default().
func TestPortErrors_RegisterPending(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(ppendRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		site plogSite
		err  error

		// cancelDuring makes the failing call cancel the caller's context.
		cancelDuring bool

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got ppendOutcome)
	}

	sameAsPlain := func(t *testing.T, site plogSite, plain, got ppendOutcome) {
		t.Helper()

		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.authFailed, got.authFailed)
		assert.Equal(t, plain.limit, got.limit)
		assert.Equal(t, plain.throttled, got.throttled)
		assert.Equal(t, plain.rateLimited, got.rateLimited)
		assert.Equal(t, plain.invalidCode, got.invalidCode)
		assert.Equal(t, plain.emailInvalid, got.emailInvalid)
		assert.Equal(t, plain.interrupted, got.interrupted)
		assert.Equal(t, plain.returned, got.returned)
		assert.Equal(t, plain.stored, got.stored, "the same passkeys stored")
		assert.Equal(t, plain.pending, got.pending, "the same passkeys pending")
		assert.Equal(t, plain.sent, got.sent, "the same messages sent")
		assert.Equal(t, plain.failures, got.failures, "the same refusals counted")
		assert.Len(t, got.notRemoved, len(plain.notRemoved), "the same removal records")
		assert.NotContains(t, got.text, plogSecret)

		require.Error(t, got.err, "a hostile error is never success")

		assert.False(t, got.returned, "nothing is registered or confirmed")
		assert.False(t, got.limit, "an outage is never the passkey limit")
		assert.False(t, got.throttled, "an outage is never a throttle")
		assert.False(t, got.rateLimited, "an outage is never a throttle")
		assert.False(t, got.invalidCode, "an outage is never a refused code")
		assert.False(t, got.interrupted, "an outage is not an interrupted call")

		switch site {
		case ppendListAbandon:
			assert.Zero(t, got.stored, "no passkey is stored")
			assert.Zero(t, got.sent, "no code is sent")
		case ppendDelAbandon:
			assert.Equal(t, 1, got.stored, "the abandoned passkey stays, and no new one is stored")
			assert.Equal(t, 1, got.sent, "no second code is sent")
		case ppendDelUnsettled:
			assert.Equal(t, 1, got.stored, "the removal failed")
			require.Len(t, got.notRemoved, 1, "the failed removal is logged")
			assert.Equal(t, "delete", got.notRemoved[0]["reason"])

			for _, v := range got.notRemoved[0] {
				if s, ok := v.(string); ok {
					assert.NotContains(t, s, plogSecret, "the record quotes the error")
				}
			}
		default:
			assert.Equal(t, 1, got.pending, "the passkey stays pending")
			assert.Zero(t, got.failures, "no refused code is counted")
		}
	}

	asOutage := func(site plogSite, reason string) func(t *testing.T, plain, got ppendOutcome) {
		return func(t *testing.T, plain, got ppendOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

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

	claimed := map[plogSite][]error{
		ppendListAbandon: {passkey.ErrPerUserLimitReached},
		ppendDelAbandon:  {passkey.ErrPerUserLimitReached},
		ppendListAwait:   {mfa.ErrEmailCodeInvalid},
		ppendCharge:      {mfa.ErrEnrolmentThrottled, mfa.ErrEmailCodeInvalid, ratelimit.ErrThrottled},
		ppendClear:       {mfa.ErrInvalidCode},
	}

	sanitized := []plogSite{
		ppendListAbandon, ppendDelAbandon, ppendDelUnsettled, ppendListAwait, ppendCharge, ppendClear,
	}

	var cases []testCase

	for _, site := range sanitized {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &plogCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &plogCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: plogPanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: plogPanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: plogFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle on a context the failing call cancelled is an outage", site: site,
				err: &plogCycleOne{}, cancelDuring: true, assert: asOutage(site, "budget")},
			testCase{name: prefix + "a typed-nil root walks to the end and is answered as an outage", site: site,
				err: (*plogTypedNil)(nil),
				assert: func(t *testing.T, plain, got ppendOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				}},
		)

		for _, sentinel := range claimed[site] {
			cases = append(cases, testCase{
				name: prefix + "a cycle claiming " + sentinel.Error(), site: site, err: &plogClaim{claims: sentinel},
				assert: asOutage(site, "budget"),
			})
		}
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				ppendPortErrInChild(t, tc.name)

				return
			}

			defaults := pregDefaultRecords(t)

			plain := runPendingSite(t, tc.site, plogOutage, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runPendingSite(t, tc.site, tc.err, tc.cancelDuring)
			tc.assert(t, plain, got)

			for _, rec := range plogRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(ppendRanMarker + tc.name + "\n")
			}
		})
	}
}

// ppendPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints, as
// one whole output line, the marker proving it ran the row.
func ppendPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), ppendChildRowDeadline)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), ppendRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := ppendRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
