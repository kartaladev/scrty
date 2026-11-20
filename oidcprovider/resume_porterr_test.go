package oidcprovider_test

// TestPortErrors_Resume replaces slog.Default() for its duration, so it does
// not run in parallel, and it restores the logger it found.

import (
	"bytes"
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

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
)

// pe7gRowEnv names the row a child process runs. It is empty in the parent.
const pe7gRowEnv = "SCRTY_OIDCPROVIDER_PE7G_PORTERR_ROW"

// pe7gRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7gRanMarker = "SCRTY_OIDCPROVIDER_PE7G_PORTERR_RAN: "

// pe7gNoRecord is not returned: a site given it answers a load with neither a
// record nor an error, a port breaking its contract.
var pe7gNoRecord = errors.New("pe7g: answer no record and no error")

// pe7gSite names the port call a row fails.
type pe7gSite string

const (
	// The login stage, answered with a sign-in.
	pe7gPut          pe7gSite = "the login stage's BrowserSessionStore.Put"
	pe7gAdvanceLogin pe7gSite = "the login stage's PendingRequestStore.Advance"

	// The consent stage, answered through the browser session the login
	// stage stored.
	pe7gSessionLoad    pe7gSite = "the consent answer's BrowserSessionStore.Load"
	pe7gSessionUser    pe7gSite = "the consent answer's UserLoader.LoadByUserID"
	pe7gConfirmTouch   pe7gSite = "the consent grant's BrowserSessionStore.Touch"
	pe7gAdvanceConsent pe7gSite = "the consent grant's PendingRequestStore.Advance"
	pe7gGive           pe7gSite = "the consent grant's ConsentStore.Give"
	pe7gDenyTouch      pe7gSite = "the consent denial's BrowserSessionStore.Touch"
)

// pe7gAtLogin reports whether site's run answers the login stage.
func pe7gAtLogin(site pe7gSite) bool { return site == pe7gPut || site == pe7gAdvanceLogin }

// pe7gLogged is the message of the failure record a log-only site writes, and
// empty for a site whose failure is answered.
func pe7gLogged(site pe7gSite) string {
	switch site {
	case pe7gGive:
		return "oidcprovider: a consent the user gave could not be remembered"
	case pe7gDenyTouch:
		return "oidcprovider: a browser session's use could not be recorded"
	}

	return ""
}

// pe7gNotFound is the not-found sentinel of site's port.
func pe7gNotFound(site pe7gSite) error {
	if site == pe7gSessionUser {
		return identity.ErrUserNotFound
	}

	return oidcprovider.ErrNotFound
}

// pe7gOutcome is what one resume through a failing port produced, the state it
// left, and the provider's records. Every error classification is made inside
// the bound.
type pe7gOutcome struct {
	text       string
	dependency bool
	notFound   bool
	canceled   bool
	unwalkable bool
	reauth     bool
	unknown    bool

	// The answer: where it redirects, with which OAuth error, whether it
	// carries a code, and whether it hands the browser a session secret.
	at        string
	errorCode string
	hasCode   bool
	hasSecret bool

	// The state afterwards: the request's stage, the codes held, the consent
	// remembered, the login stage's session extended, and the sessions held.
	stage      oidcprovider.Stage
	codes      int
	remembered bool
	touched    bool
	sessions   int

	aborts, failures []map[string]any
}

// pe7gRun parks a request and resumes it on ctx while site's port call fails
// with portErr: at the login stage for a login site, and otherwise at the
// consent stage through the browser session the login stage stored, five
// minutes later. It fails the test when the resume hangs, lets a panic
// escape, or never reaches site.
func pe7gRun(t *testing.T, ctx context.Context, site pe7gSite, portErr error) pe7gOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed atomic.Bool
		hits  atomic.Int32
	)

	failing := func(at pe7gSite) bool { return armed.Load() && site == at }
	answer := func() error {
		hits.Add(1)
		if portErr == pe7gNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
			return nil
		}

		return portErr
	}

	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC))
	memPending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	memSessions, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	memConsents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	registry, err := oidcprovider.NewMemoryRegistry(authzClients())
	require.NoError(t, err)

	ctrl := gomock.NewController(t)

	pending := NewMockPendingRequestStore(ctrl)
	pending.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.PendingRequest) error {
			return memPending.Create(context.WithoutCancel(ctx), r)
		}).AnyTimes()
	pending.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
			return memPending.Load(context.WithoutCancel(ctx), digest)
		}).AnyTimes()
	pending.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, from, to oidcprovider.Stage, s *oidcprovider.SignIn) error {
			if failing(pe7gAdvanceLogin) || failing(pe7gAdvanceConsent) {
				return answer()
			}

			return memPending.Advance(context.WithoutCancel(ctx), digest, from, to, s)
		}).AnyTimes()
	pending.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memPending.DeleteExpired).AnyTimes()

	sessions := NewMockBrowserSessionStore(ctrl)
	sessions.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, s *oidcprovider.BrowserSession) error {
			if failing(pe7gPut) {
				return answer()
			}

			return memSessions.Put(context.WithoutCancel(ctx), s)
		}).AnyTimes()
	sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, at time.Time) (*oidcprovider.BrowserSession, error) {
			if failing(pe7gSessionLoad) {
				return nil, answer()
			}

			return memSessions.Load(context.WithoutCancel(ctx), digest, at)
		}).AnyTimes()
	sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, idleUntil time.Time) error {
			if failing(pe7gConfirmTouch) || failing(pe7gDenyTouch) {
				return answer()
			}

			return memSessions.Touch(context.WithoutCancel(ctx), digest, idleUntil)
		}).AnyTimes()
	sessions.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Delete).AnyTimes()
	sessions.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteBySignIn).AnyTimes()
	sessions.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteExpired).AnyTimes()

	consents := NewMockConsentStore(ctrl)
	consents.EXPECT().Give(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, user identity.UserID, clientID string, scopes []string, offline bool, at time.Time) error {
			if failing(pe7gGive) {
				return answer()
			}

			return memConsents.Give(context.WithoutCancel(ctx), user, clientID, scopes, offline, at)
		}).AnyTimes()
	consents.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, user identity.UserID, clientID string) (*oidcprovider.Consent, error) {
			return memConsents.Load(context.WithoutCancel(ctx), user, clientID)
		}).AnyTimes()
	consents.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memConsents.Revoke).AnyTimes()
	consents.EXPECT().ListByUser(gomock.Any(), gomock.Any()).DoAndReturn(memConsents.ListByUser).AnyTimes()

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			if failing(pe7gSessionUser) {
				return nil, answer()
			}

			return activeUser(user)
		}).AnyTimes()

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         plainKeys(t),
		Users:        users,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	},
		oidcprovider.WithClock(clk),
		oidcprovider.WithPendingRequestStore(pending),
		oidcprovider.WithConsentStore(consents),
		oidcprovider.WithBrowserSessionStore(sessions),
		oidcprovider.WithLogger(logger),
	)
	require.NoError(t, err)

	f := &parkFixture{p: p, store: memPending, consents: memConsents, registry: registry, clk: clk, logs: &bytes.Buffer{}}

	r := park(t, f, nil)
	signIn := testSignIn(f, "u-1")
	in := r.input(&signIn)

	var secret string
	if !pe7gAtLogin(site) {
		res, err := p.Resume(t.Context(), in)
		require.NoError(t, err, "precondition: the login stage is answered")
		require.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r), "precondition: consent is asked")
		require.NotEmpty(t, res.BrowserSessionSecret, "precondition: a browser session is held")
		secret = res.BrowserSessionSecret

		clk.Advance(5 * time.Minute)
		in.SignIn = nil
		in.BrowserSessionSecret = secret
		in.Answer = &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}
		if site == pe7gDenyTouch {
			in.Answer = &oidcprovider.ConsentAnswer{Deny: true}
		}
	}

	armed.Store(true)

	out := pe7eBounded(t, func() pe7gOutcome {
		res, err := p.Resume(ctx, in)

		var o pe7gOutcome
		if err != nil {
			o.text = err.Error()
			o.dependency = errors.Is(err, oidcprovider.ErrDependency)
			o.notFound = errors.Is(err, oidcprovider.ErrNotFound) || errors.Is(err, identity.ErrUserNotFound)
			o.canceled = errors.Is(err, context.Canceled)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
			o.reauth = errors.Is(err, oidcprovider.ErrReauthenticate)
			o.unknown = errors.Is(err, oidcprovider.ErrUnknownHandle)
		}
		o.hasSecret = res.BrowserSessionSecret != ""
		if u, perr := url.Parse(res.RedirectTo); perr == nil && res.RedirectTo != "" {
			o.at = u.Scheme + "://" + u.Host + u.Path
			o.errorCode = u.Query().Get("error")
			o.hasCode = u.Query().Get("code") != ""
		}

		return o
	})

	armed.Store(false)
	require.Positive(t, hits.Load(), "the resume reached %s", site)

	out.stage = stageOf(t, f, r)
	out.codes = codesHeld(t, f, "u-1", "billing-web")
	_, consentErr := memConsents.Load(t.Context(), "u-1", "billing-web")
	if !errors.Is(consentErr, oidcprovider.ErrNotFound) {
		require.NoError(t, consentErr)
		out.remembered = true
	}
	if secret != "" {
		// The login stage's session ran out 15 minutes after it was stored,
		// unless a touch 5 minutes later extended it.
		_, loadErr := memSessions.Load(t.Context(), digestOf(t, secret), clk.Now().Add(11*time.Minute))
		if !errors.Is(loadErr, oidcprovider.ErrNotFound) {
			require.NoError(t, loadErr)
			out.touched = true
		}
	}
	held, err := memSessions.DeleteExpired(t.Context(), clk.Now().Add(1000*time.Hour))
	require.NoError(t, err)
	out.sessions = held

	out.aborts, out.failures = pe7eAbortsAndLogs(t, logs.String(), pe7gLogged(site))

	return out
}

// pe7gSameAsPlain asserts got is the plain outage's outcome in every class,
// text and piece of state.
func pe7gSameAsPlain(t *testing.T, site pe7gSite, plain, got pe7gOutcome) {
	t.Helper()

	if pe7gLogged(site) == "" {
		require.True(t, plain.dependency || plain.canceled, "precondition: a plain outage is a dependency failure")
		require.False(t, plain.reauth || plain.unknown, "precondition: a plain outage is no refusal")
	} else {
		require.Empty(t, plain.text, "precondition: a plain outage of a log-only site costs no answer")
		require.NotEmpty(t, plain.failures, "precondition: a plain outage of a log-only site is logged")
	}

	assert.Equal(t, plain.text, got.text, "the same returned error")
	assert.Equal(t, plain.dependency, got.dependency, "the same dependency class")
	assert.Equal(t, plain.notFound, got.notFound, "the same not-found class")
	assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
	assert.Equal(t, plain.reauth, got.reauth, "never ErrReauthenticate where an outage is not")
	assert.Equal(t, plain.unknown, got.unknown, "never ErrUnknownHandle where an outage is not")
	assert.Equal(t, plain.at, got.at, "redirected to the same place")
	assert.Equal(t, plain.errorCode, got.errorCode, "the same OAuth error")
	assert.Equal(t, plain.hasCode, got.hasCode, "a code, or none, as for a plain outage")
	assert.Equal(t, plain.hasSecret, got.hasSecret, "a session secret, or none, as for a plain outage")
	assert.Equal(t, plain.stage, got.stage, "the stage spent, or not, as for a plain outage")
	assert.Equal(t, plain.codes, got.codes, "the same codes held")
	assert.Equal(t, plain.remembered, got.remembered, "the consent remembered, or not, as for a plain outage")
	assert.Equal(t, plain.touched, got.touched, "the session touched, or not, as for a plain outage")
	assert.Equal(t, plain.sessions, got.sessions, "the same sessions held")
	assert.Len(t, got.failures, len(plain.failures), "the same failure records")
	assert.NotContains(t, got.text, pe7bSecret)
}

// pe7gRow is one hostile port error, tried at every site.
type pe7gRow struct {
	name   string
	err    func(site pe7gSite) error
	reason string
	// child runs the row in a child process: unsanitized, a cycle through
	// Unwrap() []error can overflow the stack fatally.
	child bool
	// cancel runs the row on a context the caller cancelled.
	cancel bool
}

func pe7gFixed(err error) func(pe7gSite) error { return func(pe7gSite) error { return err } }

// pe7gRows are the hostile errors every site is tried with.
func pe7gRows() []pe7gRow {
	return []pe7gRow{
		{name: "a cycle through Unwrap() error", err: pe7gFixed(&pe7bCycleOne{}), reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: pe7gFixed(&pe7bCycleMany{}), reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: pe7gFixed(pe7bPanicUnwrap{}), reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: pe7gFixed(pe7bPanicNilUnwrap{}), reason: "panic"},
		{name: "a join that fans out", err: pe7gFixed(pe7bFanOut(25, errors.New(pe7bSecret))), reason: "budget"},
		{
			name:   "a join that fans out over the not-found sentinel",
			err:    func(site pe7gSite) error { return pe7bFanOut(25, pe7gNotFound(site)) },
			reason: "budget",
		},
		{
			name:   "a cycle around the not-found sentinel",
			err:    func(site pe7gSite) error { return &pe7bCycleAround{sentinel: pe7gNotFound(site)} },
			reason: "budget", child: true,
		},
		{
			name: "a join that fans out over context.Canceled on a context the caller cancelled",
			err:  pe7gFixed(pe7bFanOut(25, context.Canceled)), reason: "budget", cancel: true,
		},
		{
			name: "a cycle around context.Canceled on a context the caller cancelled",
			err:  pe7gFixed(&pe7bCycleAround{sentinel: context.Canceled}), reason: "budget", child: true, cancel: true,
		},
		{name: "a cycle on a context the caller cancelled", err: pe7gFixed(&pe7bCycleOne{}), reason: "budget", cancel: true},
	}
}

// TestPortErrors_Resume pins that each store a resume writes or reads through
// failing with an error whose chain cannot be walked, or a load answering no
// record and no error, is answered and leaves state exactly as a plain outage
// of that port: ErrDependency where the outage is answered, never
// ErrReauthenticate or ErrUnknownHandle, and only a log where the answer is
// already owed. The sanitizer writes one record, to the provider's logger,
// and none to slog.Default().
func TestPortErrors_Resume(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7gRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name  string
		site  pe7gSite
		err   error
		child bool
		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context
		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, site pe7gSite, plain, got pe7gOutcome)
	}

	asOutage := func(reason string) func(*testing.T, pe7gSite, pe7gOutcome, pe7gOutcome) {
		return func(t *testing.T, site pe7gSite, plain, got pe7gOutcome) {
			t.Helper()

			pe7gSameAsPlain(t, site, plain, got)
			if pe7gLogged(site) == "" {
				assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")
			}
			pe7eOneAbort(t, got.aborts, got.failures, reason)
		}
	}

	walked := func(t *testing.T, site pe7gSite, plain, got pe7gOutcome) {
		t.Helper()

		pe7gSameAsPlain(t, site, plain, got)
		assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	sites := []pe7gSite{
		pe7gPut, pe7gAdvanceLogin,
		pe7gSessionLoad, pe7gSessionUser, pe7gConfirmTouch, pe7gAdvanceConsent, pe7gGive, pe7gDenyTouch,
	}

	var cases []testCase

	for _, site := range sites {
		prefix := string(site) + ": "

		for _, row := range pe7gRows() {
			tc := testCase{
				name: prefix + row.name, site: site, err: row.err(site), child: row.child, assert: asOutage(row.reason),
			}
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
			testCase{name: prefix + "a plain outage, against itself", site: site, err: pe7bErrDown, assert: walked},
		)

		switch site {
		case pe7gSessionLoad, pe7gSessionUser:
			cases = append(cases, testCase{
				name: prefix + "a port answering no record and no error is answered as an outage",
				site: site, err: pe7gNoRecord, assert: walked,
			})
		}
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7gInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7gRun(t, ctx, tc.site, pe7bErrDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7gRun(t, ctx, tc.site, tc.err)
			tc.assert(t, tc.site, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7gRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7gInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7gInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7gRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7gRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
