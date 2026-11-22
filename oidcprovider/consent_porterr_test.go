package oidcprovider_test

// TestPortErrors_ConsentAndSessionTouch and TestPortErrors_ReplacedSessionDelete
// replace slog.Default() for their duration, so they do not run in parallel,
// and they restore the logger they found.

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// pe7hRowEnv names the row a child process runs. It is empty in the parent.
const pe7hRowEnv = "SCRTY_OIDCPROVIDER_PE7H_PORTERR_ROW"

// pe7hRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7hRanMarker = "SCRTY_OIDCPROVIDER_PE7H_PORTERR_RAN: "

// errPe7hNoRecord is not returned: a site given it answers a load with neither a
// record nor an error, a port breaking its contract.
var errPe7hNoRecord = errors.New("pe7h: answer no record and no error")

const (
	// An authorization request answered from a browser session whose user
	// already gave the client every scope asked for.
	pe7hConsentLoad pe7eSite = "the remembered consent's ConsentStore.Load"
	pe7hTouch       pe7eSite = "the answering session's BrowserSessionStore.Touch"
)

// pe7hAuthorizeRun holds a browser session and a remembered consent, and sends
// an authorization request the session answers from at once, on ctx, while
// site's port call fails with portErr. errPe7hNoRecord makes the consent load
// answer (nil, nil). It fails the test when the request hangs, lets a panic
// escape, or never reaches site.
func pe7hAuthorizeRun(ctx context.Context, t *testing.T, site pe7eSite, portErr error) pe7eAuthorizeOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed atomic.Bool
		hits  atomic.Int32
		now   = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	)

	memSessions, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	memConsents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	require.NoError(t, memConsents.Give(t.Context(), "u-1", "billing-web", []string{"openid", "profile"}, false, now)) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	digest := digestOf(t, pe7eSessionSecret)
	require.NoError(t, memSessions.Put(t.Context(), &oidcprovider.BrowserSession{ //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		Digest: digest,
		SignIn: oidcprovider.SignIn{
			User: "u-1", Family: family, AuthenticatedAt: now.Add(-time.Minute), AMR: []string{"pwd"},
			AbsoluteExpiresAt: now.Add(time.Hour),
		},
		IdleExpiresAt:     now.Add(time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}))

	ctrl := gomock.NewController(t)

	sessions := NewMockBrowserSessionStore(ctrl)
	sessions.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Put).AnyTimes()
	sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, at time.Time) (*oidcprovider.BrowserSession, error) {
			return memSessions.Load(context.WithoutCancel(ctx), digest, at)
		}).AnyTimes()
	sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, idleUntil time.Time) error {
			if armed.Load() && site == pe7hTouch {
				hits.Add(1)

				return portErr
			}

			return memSessions.Touch(context.WithoutCancel(ctx), digest, idleUntil)
		}).AnyTimes()
	sessions.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Delete).AnyTimes()
	sessions.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteBySignIn).AnyTimes()
	sessions.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteExpired).AnyTimes()

	consents := NewMockConsentStore(ctrl)
	consents.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, user identity.UserID, clientID string) (*oidcprovider.Consent, error) {
			if armed.Load() && site == pe7hConsentLoad {
				hits.Add(1)
				if portErr == errPe7hNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
					return nil, nil
				}

				return nil, portErr
			}

			return memConsents.Load(context.WithoutCancel(ctx), user, clientID)
		}).AnyTimes()
	consents.EXPECT().Give(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		memConsents.Give).AnyTimes()
	consents.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memConsents.Revoke).AnyTimes()
	consents.EXPECT().ListByUser(gomock.Any(), gomock.Any()).DoAndReturn(memConsents.ListByUser).AnyTimes()

	f := newSessionFixture(t, plainKeys(t),
		oidcprovider.WithBrowserSessionStore(sessions),
		oidcprovider.WithConsentStore(consents),
		oidcprovider.WithLogger(logger),
	)

	armed.Store(true)

	out := pe7eBounded(t, func() pe7eAuthorizeOutcome {
		res, err := f.p.Authorize(ctx, oidcprovider.AuthorizeInput{
			Params: authzParams(), BrowserSessionSecret: pe7eSessionSecret, IdleTimeout: sessionIdle,
		})

		var o pe7eAuthorizeOutcome
		if err != nil {
			o.errText = err.Error()
			o.dependency = errors.Is(err, oidcprovider.ErrDependency)
			o.notFound = errors.Is(err, oidcprovider.ErrNotFound) || errors.Is(err, identity.ErrUserNotFound)
			o.canceled = errors.Is(err, context.Canceled)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}
		o.hasFlow = res.FlowSecret != ""
		if u, perr := url.Parse(res.Location); perr == nil && res.Location != "" {
			o.at = u.Scheme + "://" + u.Host + u.Path
			o.errorCode = u.Query().Get("error")
			o.state = u.Query().Get("state")
			o.hasCode = u.Query().Get("code") != ""
		}

		return o
	})

	armed.Store(false)
	require.Positive(t, hits.Load(), "the request reached %s", site)

	_, err = memSessions.Load(t.Context(), digest, now.Add(2*time.Minute)) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	if !errors.Is(err, oidcprovider.ErrNotFound) {
		require.NoError(t, err)
		out.touched = true
	}
	out.codes = codesHeld(t, f.parkFixture, "u-1", "billing-web") //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

	out.aborts, _ = pe7eAbortsAndLogs(t, logs.String(), "")

	return out
}

// TestPortErrors_ConsentAndSessionTouch pins that an authorization request a
// browser session answers, when the remembered consent's load or the session's
// touch fails with an error whose chain cannot be walked, is answered exactly
// as a plain outage of that port is: a server_error at the redirect URI. It is
// never the login page or the consent page that a missing session, or a
// consent nobody remembers, would get, also when the chain reaches ErrNotFound.
// A consent store answering no record and no error breaks its contract, and is
// answered as an outage too. The sanitizer writes one record, to the
// provider's logger, and none to slog.Default().
func TestPortErrors_ConsentAndSessionTouch(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7hRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name  string
		site  pe7eSite
		err   error
		child bool
		ctx   func(ctx context.Context) context.Context
		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pe7eAuthorizeOutcome)
	}

	asOutage := func(reason string) func(*testing.T, pe7eAuthorizeOutcome, pe7eAuthorizeOutcome) {
		return func(t *testing.T, plain, got pe7eAuthorizeOutcome) {
			t.Helper()

			pe7eAuthorizeSameAsPlain(t, plain, got)
			assert.Equal(t, "server_error", got.errorCode, "answered as a dependency failure, never the login or consent page")
			pe7eOneAbort(t, got.aborts, nil, reason)
		}
	}

	walked := func(t *testing.T, plain, got pe7eAuthorizeOutcome) {
		t.Helper()

		pe7eAuthorizeSameAsPlain(t, plain, got)
		assert.Equal(t, "server_error", got.errorCode, "answered as a dependency failure")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	for _, site := range []pe7eSite{pe7hConsentLoad, pe7hTouch} {
		prefix := string(site) + ": "

		for _, row := range pe7eRows() {
			tc := testCase{name: prefix + row.name, site: site, err: row.err(site), child: row.child, assert: asOutage(row.reason)}
			if row.cancel {
				tc.ctx = pe7eCancelled
			}

			cases = append(cases, tc)
		}

		cases = append(cases,
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an outage",
				site: site, err: (*pe7bTypedNil)(nil), assert: walked,
			},
			testCase{name: prefix + "a plain outage, against itself", site: site, err: errPe7bDown, assert: walked},
		)
	}

	cases = append(cases, testCase{
		name: string(pe7hConsentLoad) + ": a store answering no record and no error is answered as an outage",
		site: pe7hConsentLoad, err: errPe7hNoRecord, assert: walked,
	})

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7hInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7hAuthorizeRun(ctx, t, tc.site, errPe7bDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7hAuthorizeRun(ctx, t, tc.site, tc.err)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7hRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7hDeleteOutcome is what a login-stage resume produced while the delete of
// the session it replaced failed.
type pe7hDeleteOutcome struct {
	err       error
	at        string
	hasSecret bool

	aborts, failures []map[string]any
}

// pe7hDeleteRun resumes a request at its login stage, held by a browser session
// the resume replaces, on ctx, while the delete of the replaced session fails
// with portErr. It fails the test when the resume hangs, lets a panic escape,
// or never deletes.
func pe7hDeleteRun(ctx context.Context, t *testing.T, portErr error) pe7hDeleteOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var hits atomic.Int32

	memSessions, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)

	sessions := NewMockBrowserSessionStore(ctrl)
	sessions.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, s *oidcprovider.BrowserSession) error {
			return memSessions.Put(context.WithoutCancel(ctx), s)
		}).AnyTimes()
	sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Load).AnyTimes()
	sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Touch).AnyTimes()
	sessions.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(
		func(context.Context, []byte) error {
			hits.Add(1)

			return portErr
		}).AnyTimes()
	sessions.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteBySignIn).AnyTimes()
	sessions.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteExpired).AnyTimes()

	f := newSessionFixture(t, plainKeys(t),
		oidcprovider.WithBrowserSessionStore(sessions),
		oidcprovider.WithLogger(logger),
	)

	r := park(t, f.parkFixture, nil) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	signIn := testSignIn(f.parkFixture, "u-1")
	in := r.input(&signIn)
	in.BrowserSessionSecret = pe7eSessionSecret

	out := pe7eBounded(t, func() pe7hDeleteOutcome {
		res, err := f.p.Resume(ctx, in)

		o := pe7hDeleteOutcome{err: err, hasSecret: res.BrowserSessionSecret != ""}
		if u, perr := url.Parse(res.RedirectTo); perr == nil && res.RedirectTo != "" {
			o.at = u.Scheme + "://" + u.Host + u.Path
		}

		return o
	})

	require.Positive(t, hits.Load(), "the resume deleted the replaced session")

	out.aborts, out.failures = pe7eAbortsAndLogs(t, logs.String(), "oidcprovider: the replaced browser session could not be deleted")

	return out
}

// TestPortErrors_ReplacedSessionDelete pins that a resume whose delete of the
// browser session it replaced fails with an error whose chain cannot be walked
// answers exactly as when the delete fails plainly: the resume still wins, with
// the new session, and only a failure record is written. The sanitizer writes
// one abort record, to the provider's logger, and none to slog.Default().
func TestPortErrors_ReplacedSessionDelete(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7hRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	const site pe7eSite = "the replaced session's BrowserSessionStore.Delete"

	type testCase struct {
		name   string
		err    error
		reason string
		child  bool
		ctx    func(ctx context.Context) context.Context
	}

	var cases []testCase

	for _, row := range pe7eRows() {
		tc := testCase{name: row.name, err: row.err(site), reason: row.reason, child: row.child}
		if row.cancel {
			tc.ctx = pe7eCancelled
		}

		cases = append(cases, tc)
	}

	cases = append(cases,
		testCase{name: "a typed-nil root walks to the end and is answered as an outage", err: (*pe7bTypedNil)(nil)},
		testCase{name: "a plain outage, against itself", err: errPe7bDown},
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7hInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7hDeleteRun(ctx, t, errPe7bDown)
			require.NoError(t, plain.err, "precondition: a plain failure of the delete costs no answer")
			require.True(t, plain.hasSecret, "precondition: the resume hands out the new session")
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.Len(t, plain.failures, 1, "precondition: a plain failure of the delete is logged")

			got := pe7hDeleteRun(ctx, t, tc.err)
			assert.NoError(t, got.err, "the resume still wins")
			assert.Equal(t, plain.at, got.at, "redirected to the same place")
			assert.Equal(t, plain.hasSecret, got.hasSecret, "the new session, as for a plain failure")
			assert.Len(t, got.failures, len(plain.failures), "the same failure records")

			if tc.reason != "" {
				pe7eOneAbort(t, got.aborts, got.failures, tc.reason)
			} else {
				assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
			}

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7hRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7hInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7hInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7hRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7hRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
