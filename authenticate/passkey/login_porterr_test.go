//go:debug panicnil=1

package passkey_test

// TestPortErrors_Login replaces slog.Default() for its duration, so it does not
// run in parallel, and it restores the logger it found.

import (
	"context"
	"encoding/json"
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
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// plogSecret is the text every hostile error here returns, so a test can
// assert no record and no returned error quotes it.
const plogSecret = "login-port-secret-text"

// plogRowEnv names the row a child process runs. It is empty in the parent.
const plogRowEnv = "SCRTY_PASSKEY_LOGIN_PORTERR_ROW"

// plogRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const plogRanMarker = "SCRTY_PASSKEY_LOGIN_PORTERR_RAN: "

// The manager's records the login rows compare.
const (
	plogMsgRefused       = "passkey: assertion refused"
	plogMsgGrantsKept    = "passkey: the user's application grants could not be revoked"
	plogMsgSessionsKept  = "passkey: the user's sessions could not all be ended"
	plogClonedCount      = 10 // a presented counter behind the stored 42
	plogForwardCount     = 43
	plogChildRowDeadline = time.Minute
)

// plogOutage is the plain outage the parity runs fail with.
var plogOutage = errors.New("store: connection refused")

type plogCycleOne struct{}

func (*plogCycleOne) Error() string   { return plogSecret }
func (c *plogCycleOne) Unwrap() error { return c }

type plogCycleMany struct{}

func (*plogCycleMany) Error() string     { return plogSecret }
func (c *plogCycleMany) Unwrap() []error { return []error{c} }

type plogPanicUnwrap struct{}

func (plogPanicUnwrap) Error() string { return plogSecret }
func (plogPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + plogSecret) }

type plogPanicNilUnwrap struct{}

func (plogPanicNilUnwrap) Error() string { return plogSecret }
func (plogPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type plogTypedNil struct{}

func (*plogTypedNil) Error() string { return plogSecret }

// plogClaim is a cycle whose Is claims one sentinel: unsanitized, a site that
// branches on that sentinel would read the hostile error as it.
type plogClaim struct{ claims error }

func (*plogClaim) Error() string          { return plogSecret }
func (c *plogClaim) Unwrap() error        { return c }
func (c *plogClaim) Is(target error) bool { return target == c.claims } //nolint:errorlint // identity of a sentinel

// plogFanOut is errors.Join(n, n) nested depth times.
func plogFanOut(depth int) error {
	err := errors.New(plogSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// plogSite names the port call a row fails.
type plogSite string

const (
	plogParse       plogSite = "Authenticate's ParseAssertion"
	plogFindByCred  plogSite = "Authenticate's FindByCredentialID"
	plogUserFor     plogSite = "Authenticate's UserFor"
	plogVerify      plogSite = "Authenticate's VerifyAssertion"
	plogRecord      plogSite = "Authenticate's RecordAssertion"
	plogCloneFind   plogSite = "a suspected clone's Find"
	plogSuspend     plogSite = "a suspected clone's Suspend"
	plogRevokeGrant plogSite = "a suspected clone's RevokeUserGrants"
	plogRecordUse   plogSite = "an allowed clone's RecordUse"
	plogSessions    plogSite = "a suspected clone's DeleteByUser"
)

// plogPorts fails only the call its site names, and only once armed, with err;
// a failing call first runs cancel when it is set, as a call whose context the
// caller cancelled does.
type plogPorts struct {
	site   plogSite
	err    error
	cancel context.CancelFunc

	armed atomic.Bool
}

func (p *plogPorts) fails(site plogSite) error {
	if p.site != site || !p.armed.Load() {
		return nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	return p.err
}

type plogCreds struct {
	*spyCredentials

	ports *plogPorts
}

func (s plogCreds) FindByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	if err := s.ports.fails(plogFindByCred); err != nil {
		return nil, err
	}

	return s.spyCredentials.FindByCredentialID(ctx, credID)
}

func (s plogCreds) RecordAssertion(ctx context.Context, cid id.ID, n uint32, bs bool, at time.Time) (bool, error) {
	if err := s.ports.fails(plogRecord); err != nil {
		return false, err
	}

	return s.spyCredentials.RecordAssertion(ctx, cid, n, bs, at)
}

func (s plogCreds) Find(ctx context.Context, user identity.UserID, cid id.ID) (*passkey.Credential, error) {
	if err := s.ports.fails(plogCloneFind); err != nil {
		return nil, err
	}

	return s.spyCredentials.Find(ctx, user, cid)
}

func (s plogCreds) Suspend(ctx context.Context, cid id.ID) (bool, error) {
	if err := s.ports.fails(plogSuspend); err != nil {
		return false, err
	}

	return s.spyCredentials.Suspend(ctx, cid)
}

func (s plogCreds) RecordUse(ctx context.Context, cid id.ID, bs bool, at time.Time) (bool, error) {
	if err := s.ports.fails(plogRecordUse); err != nil {
		return false, err
	}

	return s.spyCredentials.RecordUse(ctx, cid, bs, at)
}

type plogHandles struct {
	passkey.HandleStore

	ports *plogPorts
}

func (s plogHandles) UserFor(ctx context.Context, handle []byte) (identity.UserID, bool, error) {
	if err := s.ports.fails(plogUserFor); err != nil {
		return "", false, err
	}

	return s.HandleStore.UserFor(ctx, handle)
}

type plogVerifier struct {
	passkey.Verifier

	ports *plogPorts
}

func (v plogVerifier) ParseAssertion(body []byte) (passkey.ParsedAssertion, error) {
	if err := v.ports.fails(plogParse); err != nil {
		return nil, err
	}

	return v.Verifier.ParseAssertion(body)
}

func (v plogVerifier) VerifyAssertion(
	ctx context.Context, p passkey.ParsedAssertion, c *passkey.Credential, exp passkey.AssertionExpectation,
) (*passkey.AssertionResult, error) {
	if err := v.ports.fails(plogVerify); err != nil {
		return nil, err
	}

	return v.Verifier.VerifyAssertion(ctx, p, c, exp)
}

type plogSessionRevoker struct {
	passkey.SessionRevoker

	ports *plogPorts
}

func (s plogSessionRevoker) DeleteByUser(ctx context.Context, user identity.UserID) error {
	if err := s.ports.fails(plogSessions); err != nil {
		return err
	}

	return s.SessionRevoker.DeleteByUser(ctx, user)
}

type plogRevoker struct{ ports *plogPorts }

func (g plogRevoker) RevokeUserGrants(context.Context, identity.UserID, string) error {
	return g.ports.fails(plogRevokeGrant)
}

// plogOutcome is what one login through a failing port produced.
type plogOutcome struct {
	err      error
	text     string
	panicked bool

	authFailed  bool
	malformed   bool
	clone       bool
	suspended   bool
	interrupted bool // matches context.Canceled or context.DeadlineExceeded
	loggedIn    bool

	state     passkey.State // the stored credential's state afterwards
	signCount uint32        // its stored counter afterwards
	notices   int           // messages sent to the user

	// refusals are the reasons of the manager's refusal records.
	refusals []string
	// grantsKept counts the "grants could not be revoked" records.
	grantsKept int
	// sessionsKept counts the "sessions could not all be ended" records.
	sessionsKept int
	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

// runLoginSite runs a passwordless login whose port call site names fails
// with portErr. When cancelDuring is set the failing call cancels the caller's
// context first. It fails the test when the call hangs or panics.
func runLoginSite(t *testing.T, site plogSite, portErr error, cancelDuring bool) plogOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ports := &plogPorts{site: site, err: portErr}
	if cancelDuring {
		ports.cancel = cancel
	}

	e := newLoginEnv(t, nil)
	e.f.deps.Credentials = plogCreds{spyCredentials: e.creds, ports: ports}
	e.f.deps.Handles = plogHandles{HandleStore: e.f.deps.Handles, ports: ports}
	e.f.deps.Verifier = plogVerifier{Verifier: e.f.deps.Verifier, ports: ports}
	e.f.deps.Sessions = plogSessionRevoker{SessionRevoker: e.f.deps.Sessions, ports: ports}

	opts := []passkey.Option{passkey.WithGrantRevoker(plogRevoker{ports: ports})}
	if site == plogRecordUse {
		opts = append(opts, passkey.WithCloneResponse(passkey.CloneSignalOnly))
	}

	m := e.manager(t, opts...)

	count := uint32(plogForwardCount)
	switch site {
	case plogCloneFind, plogSuspend, plogRevokeGrant, plogRecordUse, plogSessions:
		count = plogClonedCount
	}

	body := assertion(e.begin(t), func(b *assertionBody) { b.Count = count })

	ports.armed.Store(true)

	done := make(chan plogOutcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- plogOutcome{panicked: true}
			}
		}()

		res, err := m.Authenticate(ctx, body, e.binding)

		// Classified inside the bound: a hostile chain that reaches the caller
		// raw hangs here, and fails the run as a hang.
		out := plogOutcome{err: err, loggedIn: res != nil}
		if err != nil {
			out.text = err.Error()
			out.authFailed = errors.Is(err, authenticate.ErrAuthenticationFailed)
			out.malformed = errors.Is(err, passkey.ErrMalformedResponse)
			out.clone = errors.Is(err, passkey.ErrCloneSuspected)
			out.suspended = errors.Is(err, passkey.ErrSuspended)
			out.interrupted = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		}

		returned = true
		done <- out
	}()

	var out plogOutcome

	select {
	case out = <-done:
		require.False(t, out.panicked, "a hostile port error escaped as a panic")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	stored := e.stored(t)
	out.state, out.signCount = stored.State, stored.SignCount
	out.notices = len(e.f.messages())

	for _, rec := range plogRecords(t, e.logs.String()) {
		switch rec["msg"] {
		case plogMsgRefused:
			reason, _ := rec["refusal"].(string)
			out.refusals = append(out.refusals, reason)
		case plogMsgGrantsKept:
			out.grantsKept++
		case plogMsgSessionsKept:
			out.sessionsKept++
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

func plogRecords(t *testing.T, out string) []map[string]any {
	t.Helper()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}

		rec := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}

	return records
}

// TestPortErrors_Login pins that a consumer store, handle store, verifier or
// grant revoker failing a passwordless login with an error whose chain cannot
// be walked is answered exactly as a plain outage is, and never as one of the
// outcomes the site branches on:
//
//   - the credential lookup's failure is never "unknown credential", so a
//     client learns nothing about which credentials exist, and never a login;
//   - the verifier's failure is a refusal, never success and never an
//     interrupted check;
//   - the counter write's failure never lets the login in, and never passes a
//     counter regression silently;
//   - a suspected clone whose read-back, suspension or grant revocation fails
//     is still never let in.
//
// The sanitizer writes one record to the manager's own logger and none to
// slog.Default().
func TestPortErrors_Login(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(plogRowEnv)
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
		assert func(t *testing.T, plain, got plogOutcome)
	}

	sameAsPlain := func(t *testing.T, site plogSite, plain, got plogOutcome) {
		t.Helper()

		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.authFailed, got.authFailed)
		assert.Equal(t, plain.malformed, got.malformed)
		assert.Equal(t, plain.clone, got.clone)
		assert.Equal(t, plain.suspended, got.suspended)
		assert.Equal(t, plain.interrupted, got.interrupted)
		assert.Equal(t, plain.loggedIn, got.loggedIn)
		assert.Equal(t, plain.state, got.state, "the same stored state")
		assert.Equal(t, plain.signCount, got.signCount, "the same stored counter")
		assert.Equal(t, plain.notices, got.notices, "the same notices")
		assert.Equal(t, plain.refusals, got.refusals, "the same refusal records")
		assert.Equal(t, plain.grantsKept, got.grantsKept)
		assert.Equal(t, plain.sessionsKept, got.sessionsKept)
		assert.NotContains(t, got.text, plogSecret)

		// Whatever the site, a hostile error never lets the login in.
		require.Error(t, got.err)
		assert.False(t, got.loggedIn)

		switch site {
		case plogParse:
			assert.True(t, got.malformed, "an unreadable assertion")
		case plogFindByCred:
			assert.False(t, got.authFailed, "an outage is never an unknown credential")
			assert.Empty(t, got.refusals, "no unknown-credential refusal")
		case plogUserFor:
			assert.False(t, got.authFailed, "an outage is never a handle mismatch")
		case plogVerify:
			assert.True(t, got.authFailed, "a failing verifier refuses")
			assert.False(t, got.interrupted, "an outage is not an interrupted check")
			assert.Equal(t, []string{"verify"}, got.refusals)
		case plogRecord:
			assert.False(t, got.authFailed)
			assert.False(t, got.clone)
			assert.Equal(t, uint32(42), got.signCount, "no counter is written")
		case plogCloneFind:
			assert.False(t, got.authFailed, "an outage is never a credential gone")
			assert.Equal(t, passkey.StateActive, got.state)
		case plogSuspend:
			assert.True(t, got.clone, "a suspected clone is refused even when it cannot be suspended")
		case plogRevokeGrant:
			assert.True(t, got.clone)
			assert.Equal(t, passkey.StateSuspended, got.state)
			assert.Equal(t, 1, got.grantsKept, "the revocation failure is logged")
		case plogRecordUse:
			assert.False(t, got.authFailed)
		case plogSessions:
			assert.True(t, got.clone)
			assert.Equal(t, passkey.StateSuspended, got.state)
			assert.Equal(t, 1, got.sessionsKept, "the failure is logged once as sessions not ended")
		}
	}

	asOutage := func(site plogSite, reason string) func(t *testing.T, plain, got plogOutcome) {
		return func(t *testing.T, plain, got plogOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), plogSecret, "the record quotes the error")
		}
	}

	claimed := map[plogSite]error{
		plogFindByCred: passkey.ErrNotFound,
		plogCloneFind:  passkey.ErrNotFound,
		plogVerify:     context.Canceled,
	}

	sites := []plogSite{
		plogParse, plogFindByCred, plogUserFor, plogVerify, plogRecord,
		plogCloneFind, plogSuspend, plogRevokeGrant, plogRecordUse, plogSessions,
	}

	var cases []testCase

	for _, site := range sites {
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
				assert: func(t *testing.T, plain, got plogOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				}},
		)

		if sentinel, ok := claimed[site]; ok {
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
				plogPortErrInChild(t, tc.name)

				return
			}

			defaults := pregDefaultRecords(t)

			plain := runLoginSite(t, tc.site, plogOutage, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runLoginSite(t, tc.site, tc.err, tc.cancelDuring)
			tc.assert(t, plain, got)

			for _, rec := range plogRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(plogRanMarker + tc.name + "\n")
			}
		})
	}
}

// plogPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints, as
// one whole output line, the marker proving it ran the row.
func plogPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), plogChildRowDeadline)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), plogRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := plogRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
