package apikey_test

// TestPortErrors_KeyStore replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/pkg/id"
)

// keyPortErrSecret is the text every hostile error here returns, so a test can
// assert no record and no returned error quotes it.
const keyPortErrSecret = "key-store-secret-text"

// keyPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const keyPortErrRowEnv = "SCRTY_APIKEY_PORTERR_ROW"

// keyPortErrRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const keyPortErrRanMarker = "SCRTY_APIKEY_PORTERR_RAN: "

// keyCycleOne contains itself through Unwrap() error.
type keyCycleOne struct{}

func (*keyCycleOne) Error() string   { return keyPortErrSecret }
func (c *keyCycleOne) Unwrap() error { return c }

// keyCycleMany contains itself through Unwrap() []error. Unsanitized, the
// stdlib walk overflows the stack fatally, so its rows run in a child process.
type keyCycleMany struct{}

func (*keyCycleMany) Error() string     { return keyPortErrSecret }
func (c *keyCycleMany) Unwrap() []error { return []error{c} }

// keyNotFoundCycle wraps apikey.ErrKeyNotFound and itself through
// Unwrap() []error: the stdlib finds the sentinel before it loops, so
// unsanitized it reads as "not found". Its rows run in a child process.
type keyNotFoundCycle struct{}

func (*keyNotFoundCycle) Error() string { return keyPortErrSecret }
func (c *keyNotFoundCycle) Unwrap() []error {
	return []error{apikey.ErrKeyNotFound, c}
}

// keyPanicUnwrap is an error whose Unwrap panics.
type keyPanicUnwrap struct{}

func (keyPanicUnwrap) Error() string { return keyPortErrSecret }
func (keyPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + keyPortErrSecret) }

// keyPanicNilUnwrap is an error whose Unwrap panics with nil.
type keyPanicNilUnwrap struct{}

func (keyPanicNilUnwrap) Error() string { return keyPortErrSecret }
func (keyPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// keyTypedNil is returned as a nil pointer inside a non-nil error.
type keyTypedNil struct{}

func (*keyTypedNil) Error() string { return keyPortErrSecret }

// keyFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func keyFanOut(depth int) error {
	err := errors.New(keyPortErrSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// keyUUID matches the identifiers Rotate's messages name, which differ per run.
var keyUUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// errKeyStoreDown is the plain outage the parity runs fail with.
var errKeyStoreDown = errors.New("key store: connection refused")

// keySite names the Store call a row fails.
type keySite string

const (
	siteVerifyGet   keySite = "Verify's Get"
	siteVerifyTouch keySite = "Verify's TouchLastUsed"
	siteRevoke      keySite = "Revoke's Revoke"
	siteRotateGet   keySite = "Rotate's Get"

	siteIssuePut keySite = "Issue's Put"
	siteIssueID  keySite = "Issue's NewID"
	siteList     keySite = "List"

	// siteRotateRevoke fails the old key's revoke; the compensating revoke of
	// the replacement then succeeds.
	siteRotateRevoke keySite = "Rotate's Revoke of the old key"

	// siteRotateUndo fails the compensating revoke of the replacement after the
	// old key's revoke failed with a plain outage.
	siteRotateUndo keySite = "Rotate's compensating Revoke"

	// siteRotateBoth fails both revokes with the row's error.
	siteRotateBoth keySite = "Rotate's two Revokes"
)

// keyAbortRecords is how many abort records a row whose every hostile error
// aborts writes: one per hostile error, at most one each.
func keyAbortRecords(site keySite) int {
	if site == siteRotateBoth {
		return 2
	}

	return 1
}

// keyOutcome is what one call through a failing Store produced. Every error
// classification is made inside the bound, so a hostile chain that reaches the
// caller raw fails the run as a hang rather than hanging the test.
type keyOutcome struct {
	err  error
	text string

	// verificationFailed is the returned error being ErrVerificationFailed
	// itself, the value Verify answers every failure with.
	verificationFailed bool
	notFound           bool
	rotationRefused    bool
	unwalkable         bool

	// verified is Verify returning a principal.
	verified bool

	// live is how many of the principal's keys the real store holds unrevoked
	// after the call: a key left issued by a failed Issue or Rotate shows here.
	live int

	// events are the security events the manager's own sink received.
	events int

	// failures are the levels of the "apikey: verification failed" records,
	// and touches those of "apikey: could not record last use".
	failures []string
	touches  []string

	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

// runKeySite runs the call site names on ctx against a manager whose Store
// fails that call with storeErr. It fails the test when the call hangs or lets
// a panic escape.
func runKeySite(t *testing.T, ctx context.Context, site keySite, storeErr error) keyOutcome {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC))
	inner := apikey.NewMemoryStore()

	issuer, err := apikey.New(apikey.WithStore(inner), apikey.WithClock(clk))
	require.NoError(t, err)

	presented, rec, err := issuer.Issue(t.Context(), "svc-billing", "nightly export",
		[]string{"invoices:read"}, 24*time.Hour)
	require.NoError(t, err)

	// Every call the site does not fail goes to the real store; a call the
	// row does not expect fails the test through gomock.
	store := NewMockStore(gomock.NewController(t))

	switch site {
	case siteVerifyGet, siteRotateGet:
		store.EXPECT().Get(gomock.Any(), rec.ID).Return(apikey.Key{}, storeErr)
	case siteVerifyTouch:
		store.EXPECT().Get(gomock.Any(), rec.ID).DoAndReturn(inner.Get)
		store.EXPECT().TouchLastUsed(gomock.Any(), rec.ID, gomock.Any()).Return(storeErr)
	case siteRevoke:
		store.EXPECT().Revoke(gomock.Any(), rec.ID, gomock.Any()).Return(false, storeErr)
	case siteIssuePut:
		store.EXPECT().Put(gomock.Any(), gomock.Any()).Return(storeErr)
	case siteList:
		store.EXPECT().List(gomock.Any(), identity.UserID("svc-billing")).Return(nil, storeErr)
	case siteRotateRevoke, siteRotateUndo, siteRotateBoth:
		store.EXPECT().Get(gomock.Any(), rec.ID).DoAndReturn(inner.Get)
		store.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(inner.Put)

		oldErr, undoErr := storeErr, error(nil)

		switch site {
		case siteRotateUndo:
			oldErr, undoErr = errKeyStoreDown, storeErr
		case siteRotateBoth:
			undoErr = storeErr
		}

		store.EXPECT().Revoke(gomock.Any(), rec.ID, gomock.Any()).Return(false, oldErr)

		if undoErr != nil {
			store.EXPECT().Revoke(gomock.Any(), gomock.Not(rec.ID), gomock.Any()).Return(false, undoErr)
		} else {
			store.EXPECT().Revoke(gomock.Any(), gomock.Not(rec.ID), gomock.Any()).DoAndReturn(inner.Revoke)
		}
	}

	events := &keyEvents{}
	buf := &keySyncBuffer{}

	opts := []apikey.Option{
		apikey.WithStore(store),
		apikey.WithClock(clk),
		apikey.WithSecurityEvents(events.sink),
		apikey.WithLogger(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	}

	if site == siteIssueID {
		ids := NewMockGenerator(gomock.NewController(t))
		ids.EXPECT().NewID().Return(id.ID{}, storeErr)

		opts = append(opts, apikey.WithIDGenerator(ids))
	}

	keys, err := apikey.New(opts...)
	require.NoError(t, err)

	type result struct {
		out      keyOutcome
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

		var out keyOutcome

		switch site {
		case siteVerifyGet, siteVerifyTouch:
			p, _, err := keys.Verify(ctx, presented)
			out.err = err
			out.verified = err == nil && p.ID != ""
		case siteRevoke:
			out.err = keys.Revoke(ctx, rec.ID)
		case siteRotateGet, siteRotateRevoke, siteRotateUndo, siteRotateBoth:
			_, _, err := keys.Rotate(ctx, rec.ID, time.Hour)
			out.err = err
		case siteIssuePut, siteIssueID:
			_, _, err := keys.Issue(ctx, "svc-billing", "second", []string{"invoices:read"}, time.Hour)
			out.err = err
		case siteList:
			_, err := keys.List(ctx, "svc-billing")
			out.err = err
		}

		if out.err != nil {
			out.text = keyUUID.ReplaceAllString(out.err.Error(), "<id>")
			out.verificationFailed = out.err == apikey.ErrVerificationFailed //nolint:errorlint // identity is the claim
			out.notFound = errors.Is(out.err, apikey.ErrKeyNotFound)
			out.rotationRefused = errors.Is(out.err, apikey.ErrRotationRefused)
			out.unwalkable = errors.Is(out.err, porterr.ErrUnwalkable)
		}

		returned = true
		done <- result{out: out}
	}()

	var r result

	select {
	case r = <-done:
		require.False(t, r.panicked, "a hostile store error escaped as a panic: %v", r.value)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile store error hung the call, or its classification")
	}

	out := r.out
	out.events = len(events.all())

	held, err := inner.List(t.Context(), "svc-billing")
	require.NoError(t, err)

	for _, k := range held {
		if k.RevokedAt == nil {
			out.live++
		}
	}

	for _, rec := range keyJSONRecords(t, buf.Bytes()) {
		switch rec["msg"] {
		case "apikey: verification failed":
			out.failures = append(out.failures, rec["level"].(string))
		case "apikey: could not record last use":
			out.touches = append(out.touches, rec["level"].(string))
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// keySyncBuffer is a bytes.Buffer safe for the handler and the test to share.
type keySyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *keySyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *keySyncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]byte(nil), b.buf.Bytes()...)
}

// keyJSONRecords decodes every JSON record in out.
func keyJSONRecords(t *testing.T, out []byte) []map[string]any {
	t.Helper()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}

		rec := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}

	return records
}

// keyDefaultRecords points slog.Default() at a JSON buffer until the test
// ends. The caller must not be parallel.
func keyDefaultRecords(t *testing.T) *keySyncBuffer {
	t.Helper()

	buf := &keySyncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return buf
}

// TestPortErrors_KeyStore pins that a Store call failing with an error whose
// chain cannot be walked is answered exactly as a plain store outage is, at
// each of Verify's record read and last-use write, Revoke, and Rotate's read:
//
//   - Verify's read answers the bare ErrVerificationFailed, the value a wrong
//     key also gets, with the outage's error-level record and no unknown-key
//     event, never the not-found branch;
//   - Verify's last-use write leaves the verification successful, with the
//     outage's warning;
//   - Revoke and Rotate answer the wrapped store failure, never ErrKeyNotFound.
//
// The sanitizer writes one record, to the manager's own logger, and none to
// slog.Default().
func TestPortErrors_KeyStore(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(keyPortErrRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name string
		site keySite
		err  error

		// ctx modifies the context every run of the row uses. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows
		// the stack fatally.
		child bool

		// assert receives the plain outage's outcome, a wrong key's (Verify's
		// read only, else the zero value) and the row's.
		assert func(t *testing.T, plain, wrong, got keyOutcome)
	}

	// sameAsPlain is what every row asserts of the outcome against the plain
	// outage, by site.
	sameAsPlain := func(t *testing.T, site keySite, plain, got keyOutcome) {
		t.Helper()

		assert.Equal(t, plain.verificationFailed, got.verificationFailed, "the same Verify answer")
		assert.Equal(t, plain.verified, got.verified, "the same verification result")
		assert.Equal(t, plain.notFound, got.notFound, "never the not-found answer")
		assert.Equal(t, plain.rotationRefused, got.rotationRefused)
		assert.Equal(t, plain.live, got.live, "the same keys left live")

		if site != siteIssueID {
			// Issue's identifier failure wraps the error's text into its own;
			// the sanitized fault's text stands in for it.
			assert.Equal(t, plain.text, got.text, "the same fixed text")
		}
		assert.Equal(t, plain.events, got.events, "the same security events")
		assert.Equal(t, plain.failures, got.failures, "the same verification-failed record")
		assert.Equal(t, plain.touches, got.touches, "the same last-use record")

		switch site {
		case siteVerifyGet:
			require.True(t, plain.verificationFailed, "precondition: a plain outage is ErrVerificationFailed")
			assert.Equal(t, plain.err, got.err, "the bare ErrVerificationFailed, by identity")
			assert.Zero(t, got.events, "an outage reports no unknown-key event")
			assert.Equal(t, []string{"ERROR"}, got.failures, "an outage is error level, an unknown key debug")
		case siteVerifyTouch:
			require.True(t, plain.verified, "precondition: a failed last-use write leaves the verification successful")
			assert.Equal(t, []string{"WARN"}, got.touches)
		case siteRevoke, siteRotateGet, siteIssuePut, siteIssueID, siteList,
			siteRotateRevoke, siteRotateUndo, siteRotateBoth:
			require.Error(t, plain.err)
			assert.False(t, got.notFound, "an outage never reads as ErrKeyNotFound")
		}

		// Issue's identifier failure quotes the consumer's error text, as it
		// always did, when the walk completes and nothing is sanitized.
		if got.err != nil && (site != siteIssueID || len(got.aborts) > 0) {
			assert.NotContains(t, got.text, keyPortErrSecret)
		}
	}

	// asOutage is what every row whose walk aborts asserts: the plain
	// outage's outcome, and one abort record with reason on the manager's
	// logger.
	asOutage := func(site keySite, reason string) func(t *testing.T, plain, wrong, got keyOutcome) {
		return func(t *testing.T, plain, wrong, got keyOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)

			if site != siteVerifyGet && site != siteVerifyTouch {
				assert.True(t, got.unwalkable, "the store failure wraps the sanitizer's fault")
			}

			if site == siteVerifyGet {
				// The caller cannot tell an outage, hostile or plain, from a
				// wrong key: the same value comes back. Only the operator's
				// signals differ.
				require.True(t, wrong.verificationFailed, "precondition: a wrong key is ErrVerificationFailed")
				assert.Equal(t, wrong.err, got.err, "the caller's answer is a wrong key's")
				assert.Equal(t, 1, wrong.events, "precondition: a wrong key reports one unknown-key event")
				assert.Equal(t, []string{"DEBUG"}, wrong.failures, "precondition: a wrong key is debug level")
			}

			require.Len(t, got.aborts, keyAbortRecords(site), "one abort record per hostile error, on the manager's logger")

			for _, abort := range got.aborts {
				assert.Equal(t, "ERROR", abort["level"])
				assert.Equal(t, reason, abort["reason"])

				raw, err := json.Marshal(abort)
				require.NoError(t, err)
				assert.NotContains(t, string(raw), keyPortErrSecret, "the record quotes the error")
			}
		}
	}

	var cases []testCase

	for _, site := range []keySite{
		siteVerifyGet, siteVerifyTouch, siteRevoke, siteRotateGet,
		siteIssuePut, siteIssueID, siteList, siteRotateRevoke, siteRotateUndo, siteRotateBoth,
	} {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &keyCycleOne{},
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &keyCycleMany{}, child: true,
				assert: asOutage(site, "budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: keyPanicUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: keyPanicNilUnwrap{},
				assert: asOutage(site, "panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: keyFanOut(25),
				assert: asOutage(site, "budget")},
			testCase{
				name: prefix + "a cycle wrapping ErrKeyNotFound is an outage, never not-found",
				site: site, err: &keyNotFoundCycle{}, child: true,
				assert: asOutage(site, "budget"),
			},
			testCase{
				name: prefix + "a cycle on a context the caller cancelled is an outage",
				site: site, err: &keyCycleOne{}, ctx: cancelled,
				assert: asOutage(site, "budget"),
			},
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an outage",
				site: site, err: (*keyTypedNil)(nil),
				assert: func(t *testing.T, plain, _, got keyOutcome) {
					t.Helper()

					sameAsPlain(t, site, plain, got)
					assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
				},
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				keyPortErrInChild(t, tc.name)

				return
			}

			defaults := keyDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runKeySite(t, ctx, tc.site, errKeyStoreDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			var wrong keyOutcome
			if tc.site == siteVerifyGet {
				wrong = runKeySite(t, ctx, tc.site, apikey.ErrKeyNotFound)
			}

			got := runKeySite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, wrong, got)

			for _, rec := range keyJSONRecords(t, defaults.Bytes()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(keyPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// keyPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute: a stack
// overflow is fatal and only a child can watch for one.
func keyPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), keyPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// The marker must be one whole line: a substring check would accept the
	// marker followed by a suffix.
	want := keyPortErrRanMarker + row

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimRight(line, "\r") == want {
			return
		}
	}

	require.Fail(t, "the child never ran the row: its name matches no case",
		"row %q: no output line equals %q", row, want)
}
