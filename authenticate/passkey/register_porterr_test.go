package passkey_test

// TestPortErrors_Register replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// pregSecret is the text every hostile error here returns, so a test can
// assert no record and no returned error quotes it.
const pregSecret = "register-port-secret-text"

// pregRowEnv names the row a child process runs. It is empty in the parent.
const pregRowEnv = "SCRTY_PASSKEY_REGISTER_PORTERR_ROW"

// pregRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pregRanMarker = "SCRTY_PASSKEY_REGISTER_PORTERR_RAN: "

// pregOutage is the plain outage the parity runs fail with.
var pregOutage = errors.New("store: connection refused")

type pregCycleOne struct{}

func (*pregCycleOne) Error() string   { return pregSecret }
func (c *pregCycleOne) Unwrap() error { return c }

type pregCycleMany struct{}

func (*pregCycleMany) Error() string     { return pregSecret }
func (c *pregCycleMany) Unwrap() []error { return []error{c} }

type pregPanicUnwrap struct{}

func (pregPanicUnwrap) Error() string { return pregSecret }
func (pregPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + pregSecret) }

type pregPanicNilUnwrap struct{}

func (pregPanicNilUnwrap) Error() string { return pregSecret }
func (pregPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

type pregTypedNil struct{}

func (*pregTypedNil) Error() string { return pregSecret }

// pregClaim is a cycle whose Is claims one sentinel: unsanitized, a site that
// branches on that sentinel would read the hostile error as it.
type pregClaim struct{ claims error }

func (*pregClaim) Error() string          { return pregSecret }
func (c *pregClaim) Unwrap() error        { return c }
func (c *pregClaim) Is(target error) bool { return target == c.claims } //nolint:errorlint // identity of a sentinel

// pregFanOut is errors.Join(n, n) nested depth times.
func pregFanOut(depth int) error {
	err := errors.New(pregSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// pregSite names the port call a row fails.
type pregSite string

const (
	pregLoad      pregSite = "BeginRegistration's LoadByUserID"
	pregListBegin pregSite = "BeginRegistration's List"
	pregAssign    pregSite = "BeginRegistration's Assign"
	pregCount     pregSite = "FinishRegistration's Count"
	pregNewID     pregSite = "FinishRegistration's NewID"
	pregInsert    pregSite = "FinishRegistration's InsertWithin"
	pregListLog   pregSite = "FinishRegistration's synced-passkey List"
)

// pregPorts are the consumer ports of one row. Each fails only the call its
// site names, and only once armed, with err; a failing call first runs cancel
// when it is set, as a call whose context the caller cancelled does.
type pregPorts struct {
	site   pregSite
	err    error
	cancel context.CancelFunc

	armed    atomic.Bool
	inserted atomic.Bool
}

func (p *pregPorts) fails(site pregSite) error {
	if p.site != site || !p.armed.Load() {
		return nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	return p.err
}

type pregCreds struct {
	*passkey.MemoryCredentialStore

	ports *pregPorts
}

func (s pregCreds) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	if err := s.ports.fails(pregListBegin); err != nil {
		return nil, err
	}

	if s.ports.inserted.Load() {
		if err := s.ports.fails(pregListLog); err != nil {
			return nil, err
		}
	}

	return s.MemoryCredentialStore.List(ctx, user)
}

func (s pregCreds) Count(ctx context.Context, user identity.UserID) (int, error) {
	if err := s.ports.fails(pregCount); err != nil {
		return 0, err
	}

	return s.MemoryCredentialStore.Count(ctx, user)
}

func (s pregCreds) InsertWithin(ctx context.Context, c *passkey.Credential, limit int) (bool, error) {
	if err := s.ports.fails(pregInsert); err != nil {
		return false, err
	}

	ok, err := s.MemoryCredentialStore.InsertWithin(ctx, c, limit)
	if ok && err == nil {
		s.ports.inserted.Store(true)
	}

	return ok, err
}

type pregHandles struct {
	*passkey.MemoryHandleStore

	ports *pregPorts
}

func (s pregHandles) Assign(ctx context.Context, user identity.UserID, offered []byte) ([]byte, error) {
	if err := s.ports.fails(pregAssign); err != nil {
		return nil, err
	}

	return s.MemoryHandleStore.Assign(ctx, user, offered)
}

type pregIDs struct {
	inner id.Generator
	ports *pregPorts
}

func (g pregIDs) NewID() (id.ID, error) {
	if err := g.ports.fails(pregNewID); err != nil {
		return id.ID{}, err
	}

	return g.inner.NewID()
}

// pregOutcome is what one registration call through a failing port produced.
type pregOutcome struct {
	err      error
	text     string
	panicked bool

	userNotFound bool
	authFailed   bool
	limit        bool

	stored    int  // credentials the user holds afterwards
	creations int  // creation options rendered, so challenges issued
	noSynced  bool // the result's NoSyncedPasskey
	hasResult bool

	// failures are the manager's "synced passkey unknown" records, by level.
	failures []string
	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

func pregRecords(t *testing.T, out string) []map[string]any {
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

// pregDefaultRecords points slog.Default() at a buffer until the test ends.
// The caller must not be parallel.
func pregDefaultRecords(t *testing.T) *logBuffer {
	t.Helper()

	buf := &logBuffer{}
	prev := slog.Default()
	slog.SetDefault(buf.logger())
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// runRegisterSite runs the registration call site names against consumer ports
// that fail it with portErr. When cancelDuring is set the failing call cancels
// the caller's context first. It fails the test when the call hangs.
func runRegisterSite(t *testing.T, site pregSite, portErr error, cancelDuring bool) pregOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ports := &pregPorts{site: site, err: portErr}
	if cancelDuring {
		ports.cancel = cancel
	}

	f := newFixture(t)

	users := NewMockUserLoader(f.ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, u identity.UserID) (*identity.Details, error) {
			if site == pregLoad && ports.armed.Load() {
				if ports.cancel != nil {
					ports.cancel()
				}

				return nil, portErr
			}

			return &identity.Details{ID: u, Username: usernames[u], Active: true}, nil
		}).AnyTimes()

	creds := pregCreds{MemoryCredentialStore: f.creds, ports: ports}
	f.deps.Users = users
	f.deps.Credentials = creds
	f.deps.Handles = pregHandles{MemoryHandleStore: passkey.NewMemoryHandleStore(), ports: ports}

	logs := &logBuffer{}
	m := f.manager(t, passkey.WithLogger(logs.logger()),
		passkey.WithIDGenerator(pregIDs{inner: id.NewV7Generator(), ports: ports}))
	s := enrolmentSession("sess-a", "u-1")

	var call func() (*passkey.RegistrationResult, error)

	switch site {
	case pregLoad, pregListBegin, pregAssign:
		call = func() (*passkey.RegistrationResult, error) {
			_, err := m.BeginRegistration(ctx, s, passkey.RegistrationContext{})

			return nil, err
		}
	default:
		if site == pregListLog {
			f.adjustVerify("cred-a", func(nc *passkey.CredentialInput) error {
				nc.BackupEligible, nc.BackupState = false, false

				return nil
			})
		}

		challenge := f.begin(t, m, s)
		call = func() (*passkey.RegistrationResult, error) {
			return m.FinishRegistration(ctx, s, regBody(challenge, "cred-a", ""), passkey.RegistrationContext{})
		}
	}

	ports.armed.Store(true)

	type result struct {
		out pregOutcome
		res *passkey.RegistrationResult
	}

	done := make(chan result, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- result{out: pregOutcome{panicked: true}}
			}
		}()

		res, err := call()

		// Classified inside the bound: a hostile chain that reaches the caller
		// raw hangs here, and fails the run as a hang.
		out := pregOutcome{err: err}
		if err != nil {
			out.text = err.Error()
			out.userNotFound = errors.Is(err, identity.ErrUserNotFound)
			out.authFailed = errors.Is(err, authenticate.ErrAuthenticationFailed)
			out.limit = errors.Is(err, passkey.ErrPerUserLimitReached)
		}

		returned = true
		done <- result{out: out, res: res}
	}()

	var out pregOutcome

	select {
	case r := <-done:
		require.False(t, r.out.panicked, "a hostile port error escaped as a panic")

		out = r.out
		if r.res != nil {
			out.hasResult, out.noSynced = true, r.res.NoSyncedPasskey
		}
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	held, err := f.creds.List(t.Context(), "u-1")
	require.NoError(t, err)

	out.stored = len(held)
	out.creations = len(f.creations())

	for _, rec := range pregRecords(t, logs.String()) {
		switch rec["msg"] {
		case msgSyncedUnknownRecord:
			out.failures = append(out.failures, rec["level"].(string))
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// msgSyncedUnknownRecord is the record a finish logs when it cannot tell
// whether the user holds a synced passkey.
const msgSyncedUnknownRecord = "passkey: could not tell whether the user has a synced passkey"

// TestPortErrors_Register pins that a consumer store, user loader or ID
// generator failing the registration ceremony with an error whose chain cannot
// be walked is answered exactly as a plain outage is, and never as one of the
// outcomes the site branches on:
//
//   - the user loader's failure is never "user not found";
//   - the credential count's failure never reads as a count under the limit,
//     so nothing is stored, and is not the limit refusal either;
//   - the insert's failure is never a duplicate credential, and stores nothing;
//   - the synced-passkey listing's failure still leaves the registration
//     stored, answered "not known to be synced", with the outage's record.
//
// The sanitizer writes one record to the manager's own logger and none to
// slog.Default().
func TestPortErrors_Register(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pregRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name string
		site pregSite
		err  error

		// cancelDuring makes the failing call cancel the caller's context.
		cancelDuring bool

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pregOutcome)
	}

	sameAsPlain := func(t *testing.T, site pregSite, plain, got pregOutcome) {
		t.Helper()

		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.userNotFound, got.userNotFound)
		assert.Equal(t, plain.authFailed, got.authFailed)
		assert.Equal(t, plain.limit, got.limit)
		assert.Equal(t, plain.stored, got.stored, "the same stored state")
		assert.Equal(t, plain.creations, got.creations, "the same issued challenges")
		assert.Equal(t, plain.hasResult, got.hasResult)
		assert.Equal(t, plain.noSynced, got.noSynced)
		assert.Equal(t, plain.failures, got.failures, "the same outage record")
		assert.NotContains(t, got.text, pregSecret)

		switch site {
		case pregLoad:
			require.Error(t, got.err)
			assert.False(t, got.userNotFound, "an outage is never a missing user")
			assert.Zero(t, got.creations)
		case pregListBegin, pregAssign:
			require.Error(t, got.err)
			assert.Zero(t, got.creations, "no challenge is issued")
		case pregCount:
			require.Error(t, got.err)
			assert.False(t, got.limit, "an outage is not the limit refusal")
			assert.Zero(t, got.stored, "a count that failed never reads as under the limit")
		case pregNewID:
			require.Error(t, got.err)
			assert.Zero(t, got.stored)
		case pregInsert:
			require.Error(t, got.err)
			assert.False(t, got.authFailed, "an outage is never a duplicate credential")
			assert.False(t, got.limit)
			assert.Zero(t, got.stored)
		case pregListLog:
			require.NoError(t, got.err, "the stored registration is not failed")
			assert.True(t, got.hasResult)
			assert.Equal(t, 1, got.stored)
			assert.False(t, got.noSynced, "unknown is answered false")
			assert.Equal(t, []string{"ERROR"}, got.failures)
		}
	}

	asOutage := func(site pregSite, reason string) func(t *testing.T, plain, got pregOutcome) {
		return func(t *testing.T, plain, got pregOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			require.Len(t, got.aborts, 1, "one abort record, on the manager's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), pregSecret, "the record quotes the error")
		}
	}

	claimed := map[pregSite]error{
		pregLoad:   identity.ErrUserNotFound,
		pregCount:  passkey.ErrPerUserLimitReached,
		pregInsert: passkey.ErrDuplicateCredential,
	}

	sites := []pregSite{pregLoad, pregListBegin, pregAssign, pregCount, pregNewID, pregInsert, pregListLog}

	var cases []testCase

	for _, site := range sites {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &pregCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &pregCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: pregPanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: pregPanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: pregFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle on a context the failing call cancelled is an outage", site: site,
				err: &pregCycleOne{}, cancelDuring: true, assert: asOutage(site, "budget")},
			testCase{name: prefix + "a typed-nil root walks to the end and is answered as an outage", site: site,
				err: (*pregTypedNil)(nil),
				assert: func(t *testing.T, plain, got pregOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				}},
		)

		if sentinel, ok := claimed[site]; ok {
			cases = append(cases, testCase{
				name: prefix + "a cycle claiming " + sentinel.Error(), site: site, err: &pregClaim{claims: sentinel},
				assert: asOutage(site, "budget"),
			})
		}
	}

	cases = append(cases, testCase{
		name: string(pregInsert) + ": a walkable duplicate keeps its outcome", site: pregInsert,
		err: fmt.Errorf("driver: %w", passkey.ErrDuplicateCredential),
		assert: func(t *testing.T, _, got pregOutcome) {
			t.Helper()

			require.ErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
			assert.Zero(t, got.stored)
			assert.Empty(t, got.aborts, "a walkable error writes no abort record")
		},
	})

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pregPortErrInChild(t, tc.name)

				return
			}

			defaults := pregDefaultRecords(t)

			plain := runRegisterSite(t, tc.site, pregOutage, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runRegisterSite(t, tc.site, tc.err, tc.cancelDuring)
			tc.assert(t, plain, got)

			for _, rec := range pregRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pregRanMarker + tc.name + "\n")
			}
		})
	}
}

// pregPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker proving it ran the row.
func pregPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pregRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := pregRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
