package passkey_test

// TestPortErrors_MFAMethod replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found. The hostile error
// types, the outage and the default-logger capture are those of the login and
// registration port-error tests; the panic(nil) rows rely on the
// //go:debug panicnil=1 directive in login_porterr_test.go.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
)

// pmfaRowEnv names the row a child process runs. It is empty in the parent.
const pmfaRowEnv = "SCRTY_PASSKEY_MFA_PORTERR_ROW"

// pmfaRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pmfaRanMarker = "SCRTY_PASSKEY_MFA_PORTERR_RAN: "

const pmfaChildRowDeadline = time.Minute

// The port calls of the MFA method a row fails.
const (
	pmfaParse       plogSite = "PresentedChallenge's ParseAssertion"
	pmfaVerifyParse plogSite = "Verify's ParseAssertion"
	pmfaFind        plogSite = "Verify's FindByCredentialID"
	pmfaUserFor     plogSite = "Verify's UserFor"
	pmfaVerify      plogSite = "Verify's VerifyAssertion"
	pmfaRemove      plogSite = "RemoveEnrolment's DeleteUser"
	pmfaListEnrol   plogSite = "Enrolled's List"
	pmfaListBegin   plogSite = "BeginChallenge's List"
)

type pmfaCreds struct {
	*spyCredentials

	ports *plogPorts
}

func (s pmfaCreds) FindByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	if err := s.ports.fails(pmfaFind); err != nil {
		return nil, err
	}

	return s.spyCredentials.FindByCredentialID(ctx, credID)
}

func (s pmfaCreds) List(ctx context.Context, user identity.UserID) ([]*passkey.Credential, error) {
	for _, site := range []plogSite{pmfaListEnrol, pmfaListBegin} {
		if err := s.ports.fails(site); err != nil {
			return nil, err
		}
	}

	return s.spyCredentials.List(ctx, user)
}

func (s pmfaCreds) DeleteUser(ctx context.Context, user identity.UserID) (int, error) {
	if err := s.ports.fails(pmfaRemove); err != nil {
		return 0, err
	}

	return s.spyCredentials.DeleteUser(ctx, user)
}

type pmfaHandles struct {
	passkey.HandleStore

	ports *plogPorts
}

func (s pmfaHandles) UserFor(ctx context.Context, handle []byte) (identity.UserID, bool, error) {
	if err := s.ports.fails(pmfaUserFor); err != nil {
		return "", false, err
	}

	return s.HandleStore.UserFor(ctx, handle)
}

type pmfaVerifier struct {
	passkey.Verifier

	ports *plogPorts
}

func (v pmfaVerifier) ParseAssertion(body []byte) (passkey.ParsedAssertion, error) {
	for _, site := range []plogSite{pmfaParse, pmfaVerifyParse} {
		if err := v.ports.fails(site); err != nil {
			return nil, err
		}
	}

	return v.Verifier.ParseAssertion(body)
}

func (v pmfaVerifier) VerifyAssertion(
	ctx context.Context, p passkey.ParsedAssertion, c *passkey.Credential, exp passkey.AssertionExpectation,
) (*passkey.AssertionResult, error) {
	if err := v.ports.fails(pmfaVerify); err != nil {
		return nil, err
	}

	return v.Verifier.VerifyAssertion(ctx, p, c, exp)
}

// pmfaOutcome is what one MFA method call through a failing port produced.
type pmfaOutcome struct {
	err      error
	text     string
	panicked bool

	enrolled  bool
	challenge string

	invalidCode bool // mfa.ErrInvalidCode
	authRefused bool // mfa.ErrAuthenticatorRefused
	malformed   bool
	notFound    bool
	authFailed  bool
	interrupted bool // matches context.Canceled or context.DeadlineExceeded

	signCount uint32 // the stored credential's counter afterwards

	// refusals are the reasons of the manager's refusal records.
	refusals []string
	// aborts are the sanitizer's records on the manager's logger.
	aborts []map[string]any
}

// runMFASite runs the MFA method call site names against consumer ports that
// fail it with portErr. When cancelDuring is set the failing call cancels the
// caller's context first. It fails the test when the call hangs or panics.
func runMFASite(t *testing.T, site plogSite, portErr error, cancelDuring bool) pmfaOutcome {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	ports := &plogPorts{site: site, err: portErr}
	if cancelDuring {
		ports.cancel = cancel
	}

	e := newLoginEnv(t, nil)
	e.f.deps.Credentials = pmfaCreds{spyCredentials: e.creds, ports: ports}
	e.f.deps.Handles = pmfaHandles{HandleStore: e.f.deps.Handles, ports: ports}
	e.f.deps.Verifier = pmfaVerifier{Verifier: e.f.deps.Verifier, ports: ports}

	method := e.manager(t).MFAMethod()
	body := assertion(slotChallenge, nil)

	ports.armed.Store(true)

	done := make(chan pmfaOutcome, 1)

	go func() {
		returned := false

		defer func() {
			if !returned {
				_ = recover()
				done <- pmfaOutcome{panicked: true}
			}
		}()

		var out pmfaOutcome

		var err error

		switch site {
		case pmfaParse:
			out.challenge, err = method.PresentedChallenge(body)
		case pmfaListEnrol:
			out.enrolled, err = method.Enrolled(ctx, "u-1")
		case pmfaListBegin:
			_, err = method.BeginChallenge(ctx, "u-1", slotChallenge)
		case pmfaRemove:
			err = method.RemoveEnrolment(ctx, "u-1")
		default:
			err = method.Verify(ctx, "u-1", body)
		}

		// Classified inside the bound: a hostile chain that reaches the caller
		// raw hangs here, and fails the run as a hang.
		out.err = err
		if err != nil {
			out.text = err.Error()
			out.invalidCode = errors.Is(err, mfa.ErrInvalidCode)
			out.authRefused = errors.Is(err, mfa.ErrAuthenticatorRefused)
			out.malformed = errors.Is(err, passkey.ErrMalformedResponse)
			out.notFound = errors.Is(err, passkey.ErrNotFound)
			out.authFailed = errors.Is(err, authenticate.ErrAuthenticationFailed)
			out.interrupted = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
		}

		returned = true
		done <- out
	}()

	var out pmfaOutcome

	select {
	case out = <-done:
		require.False(t, out.panicked, "a hostile port error escaped as a panic")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	out.signCount = e.stored(t).SignCount

	for _, rec := range plogRecords(t, e.logs.String()) {
		switch rec["msg"] {
		case plogMsgRefused:
			reason, _ := rec["refusal"].(string)
			out.refusals = append(out.refusals, reason)
		case porterr.MsgClassificationAborted:
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// TestPortErrors_MFAMethod pins that a consumer store, handle store or
// verifier failing the passkey MFA method with an error whose chain cannot be
// walked is answered exactly as a plain outage is, and never as one of the
// outcomes the site branches on:
//
//   - an unreadable assertion is still ErrMalformedResponse;
//   - the credential lookup's failure is never "unknown credential" (an
//     invalid code) and never a store answer of not found;
//   - the verifier's failure is a refusal (an invalid code the slot counts),
//     never success, and never an interrupted check, even when the error
//     claims context.Canceled or the caller's context was cancelled during the
//     call;
//   - a listing or a removal failing is an error, never an empty list, never
//     not found.
//
// Verify's ParseAssertion error is only compared with nil, so that site is not
// sanitized: its rows pin that a hostile error there is answered as plain.
// The sanitizer writes one record to the manager's own logger and none to
// slog.Default().
func TestPortErrors_MFAMethod(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pmfaRowEnv)
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
		assert func(t *testing.T, plain, got pmfaOutcome)
	}

	sameAsPlain := func(t *testing.T, site plogSite, plain, got pmfaOutcome) {
		t.Helper()

		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.invalidCode, got.invalidCode)
		assert.Equal(t, plain.authRefused, got.authRefused)
		assert.Equal(t, plain.malformed, got.malformed)
		assert.Equal(t, plain.notFound, got.notFound)
		assert.Equal(t, plain.authFailed, got.authFailed)
		assert.Equal(t, plain.interrupted, got.interrupted)
		assert.Equal(t, plain.enrolled, got.enrolled)
		assert.Equal(t, plain.challenge, got.challenge)
		assert.Equal(t, plain.signCount, got.signCount, "the same stored counter")
		assert.Equal(t, plain.refusals, got.refusals, "the same refusal records")
		assert.NotContains(t, got.text, plogSecret)

		require.Error(t, got.err, "a hostile error is never success")

		assert.False(t, got.notFound, "an outage is never not found")
		assert.False(t, got.interrupted, "an outage is not an interrupted check")
		assert.Equal(t, uint32(42), got.signCount, "no counter is written")

		switch site {
		case pmfaParse:
			assert.True(t, got.malformed, "an unreadable assertion")
			assert.Empty(t, got.challenge)
		case pmfaVerifyParse:
			assert.True(t, got.invalidCode, "an unreadable assertion is an invalid code")
			assert.Equal(t, []string{"malformed"}, got.refusals)
		case pmfaFind:
			assert.False(t, got.invalidCode, "an outage is never an unknown credential")
			assert.Empty(t, got.refusals, "no unknown-credential refusal")
		case pmfaUserFor:
			assert.False(t, got.invalidCode, "an outage is never a handle mismatch")
			assert.Empty(t, got.refusals, "no handle refusal")
		case pmfaVerify:
			assert.True(t, got.invalidCode, "a failing verifier is an invalid code")
			assert.False(t, got.authRefused, "the slot counts it as a wrong guess")
			assert.Equal(t, []string{"verify"}, got.refusals)
		case pmfaRemove:
			assert.False(t, got.invalidCode)
		case pmfaListEnrol:
			assert.False(t, got.enrolled, "an outage is an error, not a verdict")
		case pmfaListBegin:
			assert.False(t, got.invalidCode)
		}
	}

	asOutage := func(site plogSite, reason string) func(t *testing.T, plain, got pmfaOutcome) {
		return func(t *testing.T, plain, got pmfaOutcome) {
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

	// notSanitized is the answer at a site whose error is only compared with
	// nil: the same as a plain outage, and no record is promised.
	notSanitized := func(site plogSite) func(t *testing.T, plain, got pmfaOutcome) {
		return func(t *testing.T, plain, got pmfaOutcome) {
			t.Helper()

			sameAsPlain(t, site, plain, got)
		}
	}

	claimed := map[plogSite]error{
		pmfaFind:      passkey.ErrNotFound,
		pmfaVerify:    context.Canceled,
		pmfaListEnrol: passkey.ErrNotFound,
		pmfaListBegin: passkey.ErrNotFound,
	}

	sanitized := []plogSite{
		pmfaParse, pmfaFind, pmfaUserFor, pmfaVerify, pmfaRemove, pmfaListEnrol, pmfaListBegin,
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
				assert: func(t *testing.T, plain, got pmfaOutcome) {
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

	cases = append(cases,
		testCase{name: string(pmfaVerifyParse) + ": a cycle is only nil-checked and answered as a malformed response",
			site: pmfaVerifyParse, err: &plogCycleOne{}, assert: notSanitized(pmfaVerifyParse)},
		testCase{name: string(pmfaVerifyParse) + ": a link whose Unwrap panics is answered as a malformed response",
			site: pmfaVerifyParse, err: plogPanicUnwrap{}, assert: notSanitized(pmfaVerifyParse)},
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pmfaPortErrInChild(t, tc.name)

				return
			}

			defaults := pregDefaultRecords(t)

			plain := runMFASite(t, tc.site, plogOutage, tc.cancelDuring)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := runMFASite(t, tc.site, tc.err, tc.cancelDuring)
			tc.assert(t, plain, got)

			for _, rec := range plogRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pmfaRanMarker + tc.name + "\n")
			}
		})
	}
}

// pmfaPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints, as
// one whole output line, the marker proving it ran the row.
func pmfaPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), pmfaChildRowDeadline)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pmfaRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	marker := pmfaRanMarker + row
	ran := slices.ContainsFunc(strings.Split(string(out), "\n"), func(line string) bool {
		return strings.TrimSuffix(line, "\r") == marker
	})
	require.True(t, ran, "the child never ran row %q: no output line equals %q:\n%s", row, marker, string(out))
}
