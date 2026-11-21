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
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
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
	ppendSendCode     plogSite = "FinishRegistration's emailed-code Send"
	ppendLoadContact  plogSite = "FinishRegistration's emailed-code LoadByUserID"
	ppendListWayBack  plogSite = "FinishRegistration's way-back awaiting List"
	ppendWayBack      plogSite = "FinishRegistration's way-back check"
	ppendGenerate     plogSite = "FinishRegistration's saved-code Generate"
	ppendConfirmSaved plogSite = "ConfirmSavedCode's saved-code Confirm"
)

// ppendRecoverySites are the sites a row reaches only with saved codes wired.
// Their ports are the saved-code store behind recovery.Codes and the way-back
// check, which sanitize at their own boundary.
var ppendRecoverySites = []plogSite{ppendListWayBack, ppendWayBack, ppendGenerate, ppendConfirmSaved}

// ppendCreds fails the call its ports name. A Delete after a passkey was
// stored while armed is the unsettled finish's removal; any other is the
// removal of an abandoned registration.
type ppendCreds struct {
	*passkey.MemoryCredentialStore

	ports    *plogPorts
	inserted *atomic.Bool
}

func (s ppendCreds) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	for _, site := range []plogSite{ppendListAbandon, ppendListAwait, ppendListWayBack} {
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

// ppendSender fails the emailed code's Send, and is non-blocking as a queued
// sender is.
type ppendSender struct {
	notify.Sender

	ports *plogPorts
}

func (s ppendSender) Send(ctx context.Context, msg notify.Message) error {
	if err := s.ports.fails(ppendSendCode); err != nil {
		return err
	}

	return s.Sender.Send(ctx, msg)
}

func (ppendSender) NonBlocking() bool { return true }

// ppendUsers fails the user load that addresses the emailed code.
type ppendUsers struct {
	identity.UserLoader

	ports *plogPorts
}

func (u ppendUsers) LoadByUserID(ctx context.Context, user identity.UserID) (*identity.Details, error) {
	if err := u.ports.fails(ppendLoadContact); err != nil {
		return nil, err
	}

	return u.UserLoader.LoadByUserID(ctx, user)
}

// ppendCodeStore is the consumer's saved-code store: it fails the call its
// ports name, and counts the sets it replaced while armed.
type ppendCodeStore struct {
	*recovery.MemoryCodeStore

	ports    *plogPorts
	replaced *atomic.Int32
}

func (s ppendCodeStore) ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error {
	if err := s.ports.fails(ppendGenerate); err != nil {
		return err
	}

	err := s.MemoryCodeStore.ReplaceSet(ctx, user, hashes, at)
	if err == nil && s.ports.armed.Load() {
		s.replaced.Add(1)
	}

	return err
}

func (s ppendCodeStore) Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error) {
	if err := s.ports.fails(ppendConfirmSaved); err != nil {
		return false, err
	}

	return s.MemoryCodeStore.Match(ctx, user, hash)
}

func (s ppendCodeStore) Remaining(ctx context.Context, user identity.UserID) (int, error) {
	if err := s.ports.fails(ppendWayBack); err != nil {
		return 0, err
	}

	return s.MemoryCodeStore.Remaining(ctx, user)
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
	codeRefused  bool // recovery.ErrRefused
	claimed      bool // the row's claimed sentinel, checked before every other
	interrupted  bool // matches context.Canceled or context.DeadlineExceeded
	returned     bool // a registration result or an activated passkey came back

	stored    int   // passkeys the user holds afterwards
	pending   int   // of which pending
	sent      int   // messages the sender queued
	failures  int32 // refusals counted on the confirmation limiter
	generated int32 // saved-code sets replaced once the port was armed

	// notRemoved are the manager's "could not be removed" records.
	notRemoved []map[string]any
	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

// runPendingSite runs the pending-registration call site names against a
// consumer port that fails it with portErr. When cancelDuring is set the
// failing call cancels the caller's context first. claims, when set, is the
// sentinel a claim row's error claims: it is classified first, so an error
// taken for it is reported as such before a later check can hang. It fails
// the test when the call, or the classification of its error, hangs or
// panics.
func runPendingSite(t *testing.T, site plogSite, portErr, claims error, cancelDuring bool) ppendOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ports := &plogPorts{site: site, err: portErr}
	if cancelDuring {
		ports.cancel = cancel
	}

	f := newFixture(t)
	f.deps.Credentials = ppendCreds{MemoryCredentialStore: f.creds, ports: ports, inserted: &atomic.Bool{}}
	f.deps.Sender = ppendSender{Sender: f.deps.Sender, ports: ports}
	f.deps.Users = ppendUsers{UserLoader: f.deps.Users, ports: ports}

	logs := &logBuffer{}
	replaced := &atomic.Int32{}

	if slices.Contains(ppendRecoverySites, site) {
		store := ppendCodeStore{MemoryCodeStore: recovery.NewMemoryCodeStore(), ports: ports, replaced: replaced}
		f.deps.Recovery = recoveryDeps(t, f, recovery.WayBackDeps{},
			recovery.WithCodesStore(store), recovery.WithCodesLogger(logs.logger()))
	}

	m := f.manager(t, passkey.WithLogger(logs.logger()))
	s := enrolmentSession("sess-a", "u-1")
	limiter := &ppendLimiter{Limiter: permissive(t)}
	rc := passkey.RegistrationContext{EmailConfirmation: true, ConfirmLimiter: limiter}

	// finishing begins a registration, before the port is armed, and returns
	// the call that finishes it.
	finish := func(ctx context.Context, credID string) func() (*passkey.RegistrationResult, error) {
		challenge := f.begin(t, m, s) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

		return func() (*passkey.RegistrationResult, error) {
			return m.FinishRegistration(ctx, s, regBody(challenge, credID, ""), rc)
		}
	}

	finishing := func(ctx context.Context, credID string) func() (bool, error) {
		run := finish(ctx, credID)

		return func() (bool, error) {
			res, err := run()

			return res != nil, err
		}
	}

	var call func() (bool, error)

	switch site {
	case ppendListAbandon, ppendSendCode, ppendLoadContact, ppendListWayBack, ppendWayBack, ppendGenerate:
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
	case ppendConfirmSaved:
		res, err := finish(t.Context(), "cred-a")()
		require.NoError(t, err)
		require.NotEmpty(t, res.RecoveryCodes, "the finish showed saved codes")

		code := res.RecoveryCodes[0]
		call = func() (bool, error) {
			c, err := m.ConfirmSavedCode(ctx, s, code, rc)

			return c != nil, err
		}
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

	// claimedHit is set as soon as the error is taken for the claimed
	// sentinel, so a run that then hangs still reports the misclassification.
	var claimedHit atomic.Bool

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
			if claims != nil && errors.Is(err, claims) {
				claimedHit.Store(true)
				out.claimed = true
			}

			out.text = err.Error()
			out.authFailed = errors.Is(err, authenticate.ErrAuthenticationFailed)
			out.limit = errors.Is(err, passkey.ErrPerUserLimitReached)
			out.throttled = errors.Is(err, mfa.ErrEnrolmentThrottled)
			out.rateLimited = errors.Is(err, ratelimit.ErrThrottled)
			out.invalidCode = errors.Is(err, mfa.ErrInvalidCode)
			out.emailInvalid = errors.Is(err, mfa.ErrEmailCodeInvalid)
			out.codeRefused = errors.Is(err, recovery.ErrRefused)
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
		require.False(t, claimedHit.Load(), "the error was taken for %v, then its classification hung", claims)
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
	out.generated = replaced.Load()

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
//     the caller's context was cancelled during the call;
//   - the emailed code's Send, or the user load that addresses it, failing
//     fails the finish and removes the passkey it stored;
//   - with saved codes wired, the way-back check's listing or saved-code count
//     failing refuses the finish before anything is stored, generated or
//     sent; the saved-code set's write failing removes the stored passkey; and
//     the saved-code confirmation's lookup failing is an error, never
//     recovery.ErrCodeThrottled or recovery.ErrRefused, whichever it claims.
//
// The sanitizer writes one record to the manager's own logger and none to
// slog.Default(). The saved-code rows reach their port through recovery.Codes,
// which sanitizes at its own boundary to the logger it was given, here the
// manager's: they pin that the pending flow still answers them as an outage.
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

		// claims is the sentinel a claim row's error claims.
		claims error

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
		assert.Equal(t, plain.codeRefused, got.codeRefused)
		assert.Equal(t, plain.generated, got.generated, "the same saved-code sets generated")
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
		assert.False(t, got.codeRefused, "an outage is never a refused saved code")
		assert.False(t, got.claimed, "an outage is never the sentinel its error claims")
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
		case ppendSendCode, ppendLoadContact, ppendGenerate:
			assert.Zero(t, got.stored, "the unsettled passkey is removed")
			assert.Zero(t, got.sent, "no code is sent")
			assert.Zero(t, got.generated, "no saved codes are generated")
			assert.Empty(t, got.notRemoved, "the removal succeeded")
		case ppendListWayBack, ppendWayBack:
			assert.Zero(t, got.stored, "no passkey is stored")
			assert.Zero(t, got.generated, "no saved codes are generated")
			assert.Zero(t, got.sent, "no code is sent")
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
		ppendSendCode:    {passkey.ErrPerUserLimitReached, authenticate.ErrAuthenticationFailed},
		ppendLoadContact: {passkey.ErrPerUserLimitReached, authenticate.ErrAuthenticationFailed},
		ppendListWayBack: {passkey.ErrPerUserLimitReached},
		ppendWayBack:     {passkey.ErrPerUserLimitReached},
		ppendGenerate:    {passkey.ErrPerUserLimitReached},
		ppendConfirmSaved: {
			recovery.ErrCodeThrottled, recovery.ErrRefused, mfa.ErrInvalidCode, ratelimit.ErrThrottled,
		},
	}

	sanitized := []plogSite{
		ppendListAbandon, ppendDelAbandon, ppendDelUnsettled, ppendListAwait, ppendCharge, ppendClear,
		ppendSendCode, ppendLoadContact, ppendListWayBack, ppendWayBack, ppendGenerate, ppendConfirmSaved,
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
				claims: sentinel, assert: asOutage(site, "budget"),
			})
		}
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				portErrInChild(t, ppendRowEnv, ppendRanMarker, tc.name)

				return
			}

			defaults := pregDefaultRecords(t)

			plain := runPendingSite(t, tc.site, errPlogOutage, nil, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runPendingSite(t, tc.site, tc.err, tc.claims, tc.cancelDuring)
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

// portErrInChild re-runs the current top-level test in a child process with
// env naming row, and fails unless it exits 0 within a minute and prints, as
// one whole output line, ranMarker followed by row, proving it ran the row.
func portErrInChild(t *testing.T, env, ranMarker, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), ppendChildRowDeadline)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), env+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := ranMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
