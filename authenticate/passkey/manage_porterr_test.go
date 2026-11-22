package passkey_test

// TestPortErrors_Manage replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

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

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// pmanRowEnv names the row a child process runs. It is empty in the parent.
const pmanRowEnv = "SCRTY_PASSKEY_MANAGE_PORTERR_ROW"

// pmanRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pmanRanMarker = "SCRTY_PASSKEY_MANAGE_PORTERR_RAN: "

const pmanChildRowDeadline = time.Minute

// pmanMsgSessionsKept is the record of a second revocation pass that failed.
const pmanMsgSessionsKept = "passkey: the user's sessions could not all be ended"

// errPmanOutage is the plain outage the parity runs fail with.
var errPmanOutage = errors.New("store: connection refused")

// pmanSite names the port call a row fails.
type pmanSite string

const (
	pmanList         pmanSite = "List's credentials.List"
	pmanRename       pmanSite = "Rename's credentials.Rename"
	pmanFind         pmanSite = "findOwn's credentials.Find"
	pmanRemoveFirst  pmanSite = "Remove's first DeleteByUserExcept"
	pmanRemoveSecond pmanSite = "Remove's second DeleteByUserExcept"
	pmanRemoveDelete pmanSite = "Remove's credentials.Delete"
	pmanKindHeld     pmanSite = "the recovery kind's List"
	pmanKindRemove   pmanSite = "the recovery kind's Delete"
)

// pmanPorts fails only the call its site names, with err; a failing call
// first runs cancel when it is set, as a call whose context the caller
// cancelled does.
type pmanPorts struct {
	site   pmanSite
	err    error
	cancel context.CancelFunc

	revocations atomic.Int32
}

func (p *pmanPorts) fails(sites ...pmanSite) error {
	if !slices.Contains(sites, p.site) {
		return nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	return p.err
}

type pmanCreds struct {
	*spyCredentials

	ports *pmanPorts
}

func (s pmanCreds) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	if err := s.ports.fails(pmanList, pmanKindHeld); err != nil {
		return nil, err
	}

	return s.spyCredentials.List(ctx, user)
}

func (s pmanCreds) Find(ctx context.Context, user identity.UserID, cid id.ID) (*passkey.Credential, error) {
	if err := s.ports.fails(pmanFind); err != nil {
		return nil, err
	}

	return s.spyCredentials.Find(ctx, user, cid)
}

func (s pmanCreds) Rename(ctx context.Context, user identity.UserID, cid id.ID, name string) (bool, error) {
	if err := s.ports.fails(pmanRename); err != nil {
		return false, err
	}

	return s.spyCredentials.Rename(ctx, user, cid, name)
}

func (s pmanCreds) Delete(ctx context.Context, user identity.UserID, cid id.ID) (bool, error) {
	if err := s.ports.fails(pmanRemoveDelete, pmanKindRemove); err != nil {
		return false, err
	}

	return s.spyCredentials.Delete(ctx, user, cid)
}

// pmanSessions fails the first or the second DeleteByUserExcept, as its site
// says, and passes the other through.
type pmanSessions struct {
	passkey.SessionRevoker

	ports *pmanPorts
}

func (s pmanSessions) DeleteByUserExcept(ctx context.Context, user identity.UserID, keep string) (int, error) {
	site := pmanRemoveFirst
	if s.ports.revocations.Add(1) == 2 {
		site = pmanRemoveSecond
	}

	if err := s.ports.fails(site); err != nil {
		return 0, err
	}

	return s.SessionRevoker.DeleteByUserExcept(ctx, user, keep)
}

// pmanOutcome is what one call through a failing port produced.
type pmanOutcome struct {
	err      error
	text     string
	panicked bool

	notFound    bool
	interrupted bool // matches context.Canceled or context.DeadlineExceeded
	config      bool

	removed bool // the credential is gone afterwards
	renamed bool // the credential's name changed

	// others counts the manager's own records, by message.
	others map[string]int
	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
	// defaultAborts counts the sanitizer's records on slog.Default().
	defaultAborts int
}

// runManageSite runs the call site names against ports that fail it with
// portErr. When cancelDuring is set the failing call cancels the caller's
// context first. It fails the test when the call hangs or panics.
func runManageSite(t *testing.T, site pmanSite, portErr error, cancelDuring bool) pmanOutcome {
	t.Helper()

	defaults := pregDefaultRecords(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ports := &pmanPorts{site: site, err: portErr}
	if cancelDuring {
		ports.cancel = cancel
	}

	e := newManageEnv(t)
	creds := pmanCreds{spyCredentials: e.creds, ports: ports}
	e.f.deps.Credentials = creds
	e.f.deps.Sessions = pmanSessions{SessionRevoker: e.f.deps.Sessions, ports: ports}

	m := e.manager(t)
	cid := e.cred.ID
	user := identity.UserID("u-1")

	var op func() error

	switch site {
	case pmanList:
		op = func() error { _, err := m.List(ctx, user); return err }
	case pmanRename, pmanFind:
		op = func() error { return m.Rename(ctx, user, cid, "renamed") }
	case pmanRemoveFirst, pmanRemoveSecond, pmanRemoveDelete:
		op = func() error {
			return m.Remove(ctx, fullSession("sess-1", user), cid, passkey.RegistrationContext{})
		}
	case pmanKindHeld:
		op = func() error { _, err := passkey.NewRecoveryKind(creds).Held(ctx, user); return err }
	case pmanKindRemove:
		op = func() error {
			return passkey.NewRecoveryKind(creds).Remove(ctx, user,
				[]recovery.AuthenticatorRef{{Kind: passkey.RecoveryKindName, ID: cid.String()}})
		}
	default:
		require.FailNow(t, "unknown site", "%s", site)
	}

	done := make(chan pmanOutcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- pmanOutcome{panicked: true}
			}
		}()

		err := op()

		// Classified inside the bound: a hostile chain that reaches the caller
		// raw hangs here, and fails the run as a hang.
		out := pmanOutcome{err: err}
		if err != nil {
			out.text = err.Error()
			out.notFound = errors.Is(err, passkey.ErrNotFound)
			out.config = errors.Is(err, passkey.ErrConfig)
			out.interrupted = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		}

		returned = true
		done <- out
	}()

	var out pmanOutcome

	select {
	case out = <-done:
		require.False(t, out.panicked, "a hostile port error escaped as a panic")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	out.removed = !e.exists(t, user, cid)

	if stored, err := e.f.creds.Find(t.Context(), user, cid); err == nil {
		out.renamed = stored.Name == "renamed"
	}

	out.others = map[string]int{}

	for _, rec := range plogRecords(t, e.logs.String()) {
		msg, _ := rec["msg"].(string)
		if msg == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)

			continue
		}

		out.others[msg]++
	}

	for _, rec := range plogRecords(t, defaults.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.defaultAborts++
		}
	}

	return out
}

// TestPortErrors_Manage pins that a consumer credential store or session
// revoker failing a passkey management call (list, rename, remove, and the
// recovery kind's list and delete) with an error whose chain cannot be walked
// is answered exactly as a plain outage is:
//
//   - the store's Find failing is never "not your credential" (ErrNotFound),
//     so a hostile error that claims ErrNotFound is still an outage;
//   - a failing first revocation refuses the removal and leaves the passkey;
//   - a failing second revocation is logged and does not undo the removal.
//
// The manager's sites write one record to its own logger and none to
// slog.Default(); the recovery kind has no logger, so its one record goes to
// slog.Default(). A walk that completes (a typed-nil root) writes none. An Is
// method that panics only for the site's own sentinel is accepted: it passes
// the sanitizer and the later stdlib check recovers it at the HTTP boundary.
func TestPortErrors_Manage(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pmanRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		site pmanSite
		err  error

		cancelDuring bool

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pmanOutcome)
	}

	isKind := func(site pmanSite) bool { return site == pmanKindHeld || site == pmanKindRemove }

	sameAsPlain := func(t *testing.T, site pmanSite, plain, got pmanOutcome) {
		t.Helper()

		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.notFound, got.notFound)
		assert.Equal(t, plain.config, got.config)
		assert.Equal(t, plain.interrupted, got.interrupted)
		assert.Equal(t, plain.removed, got.removed, "the same stored credential")
		assert.Equal(t, plain.renamed, got.renamed, "the same stored name")
		assert.Equal(t, plain.others, got.others, "the same records of the manager")
		assert.NotContains(t, got.text, plogSecret)

		if site == pmanRemoveSecond {
			assert.NoError(t, got.err, "a failing second pass does not undo the removal")
			assert.True(t, got.removed)
			assert.Equal(t, 1, got.others[pmanMsgSessionsKept], "the failure is logged once")

			return
		}

		require.Error(t, got.err)
		assert.False(t, got.notFound, "an outage is never a credential that is not the user's")
		assert.False(t, got.interrupted)

		switch site {
		case pmanRemoveFirst, pmanRemoveDelete, pmanKindRemove:
			assert.False(t, got.removed, "the passkey stays for a retry")
		case pmanRename:
			assert.False(t, got.renamed)
		}
	}

	asOutage := func(site pmanSite, reason string) func(t *testing.T, plain, got pmanOutcome) {
		return func(t *testing.T, plain, got pmanOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			if isKind(site) {
				assert.Empty(t, got.aborts)
				assert.Equal(t, 1, got.defaultAborts, "the kind has no logger: one record on slog.Default()")

				return
			}

			assert.Equal(t, 0, got.defaultAborts, "an abort record went to slog.Default()")
			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), plogSecret, "the record quotes the error")
		}
	}

	sites := []pmanSite{
		pmanList, pmanRename, pmanFind, pmanRemoveFirst, pmanRemoveSecond, pmanRemoveDelete,
		pmanKindHeld, pmanKindRemove,
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
				assert: func(t *testing.T, plain, got pmanOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
					assert.Equal(t, 0, got.defaultAborts)
				}},
		)

		if site == pmanFind {
			cases = append(cases, testCase{
				name: prefix + "a cycle claiming ErrNotFound", site: site, err: &plogClaim{claims: passkey.ErrNotFound},
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
				pmanPortErrInChild(t, tc.name)

				return
			}

			plain := runManageSite(t, tc.site, errPmanOutage, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.Equal(t, 0, plain.defaultAborts)

			got := runManageSite(t, tc.site, tc.err, tc.cancelDuring)
			tc.assert(t, plain, got)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pmanRanMarker + tc.name + "\n")
			}
		})
	}
}

// pmanPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints, as
// one whole output line, the marker proving it ran the row.
func pmanPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), pmanChildRowDeadline)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pmanRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := pmanRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
