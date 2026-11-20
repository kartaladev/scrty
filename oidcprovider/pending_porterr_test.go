package oidcprovider_test

// TestPortErrors_ParkLoadAndCode replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found.

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

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// pe7jRowEnv names the row a child process runs. It is empty in the parent.
const pe7jRowEnv = "SCRTY_OIDCPROVIDER_PE7J_PORTERR_ROW"

// pe7jRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7jRanMarker = "SCRTY_OIDCPROVIDER_PE7J_PORTERR_RAN: "

const (
	// A request parked at the login stage: its identifier, then its record.
	pe7jParkID     pe7eSite = "parking a request's id.Generator.NewID"
	pe7jParkCreate pe7eSite = "parking a request's PendingRequestStore.Create"
	// The page's read of a parked request.
	pe7jPendingLoad pe7eSite = "PendingRequest's PendingRequestStore.Load"
	// A code written for a sign-in a browser session answers: its grant family,
	// then its record.
	pe7jCodeID     pe7eSite = "issuing a code's id.Generator.NewID"
	pe7jCodeCreate pe7eSite = "issuing a code's CodeStore.Create"
	// A logout the browser confirms, asking its session which sign-in to end.
	pe7jSessionLoad pe7eSite = "ConfirmLogout's BrowserSessionStore.Load"
)

// pe7jOutcome is what one call produced through a failing port, the state it
// left, and what the provider logged.
type pe7jOutcome struct {
	errText       string
	failed        bool
	dependency    bool
	notFound      bool
	unknownHandle bool
	canceled      bool
	unwalkable    bool

	// What an authorization request answered.
	errorCode string
	at        string
	state     string
	hasCode   bool
	hasFlow   bool
	// What a read of a parked request, or a confirmed logout, answered.
	viewed bool
	ended  bool

	// The state afterwards.
	codes       int
	grantEnded  bool
	sessionHeld bool

	aborts []map[string]any
}

// pe7jRun calls site's flow on ctx while site's port call fails with portErr.
// It fails the test when the call hangs, lets a panic escape, or never reaches
// site.
func pe7jRun(t *testing.T, ctx context.Context, site pe7eSite, portErr error) pe7jOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed atomic.Bool
		hits  atomic.Int32
		now   = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
		user  = identity.UserID("u-1")
	)

	// fail reports the port call a row breaks, counting that it was reached.
	fail := func(at pe7eSite) bool {
		if armed.Load() && site == at {
			hits.Add(1)

			return true
		}

		return false
	}

	memPending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	memSessions, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	memConsents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	memGrants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	memCodes, err := oidcprovider.NewMemoryCodeStore()
	require.NoError(t, err)

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	grantFamily, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	digest := digestOf(t, pe7eSessionSecret)

	require.NoError(t, memSessions.Put(t.Context(), &oidcprovider.BrowserSession{
		Digest: digest,
		SignIn: oidcprovider.SignIn{
			User: user, Family: family, AuthenticatedAt: now.Add(-time.Minute), AMR: []string{"pwd"},
			AbsoluteExpiresAt: now.Add(time.Hour),
		},
		IdleExpiresAt:     now.Add(time.Minute),
		AbsoluteExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, memConsents.Give(t.Context(), user, "billing-web", []string{"openid", "profile"}, false, now))
	require.NoError(t, memGrants.Create(t.Context(), &oidcprovider.Grant{
		Family: grantFamily, User: user, ClientID: "billing-web", Scopes: []string{"openid"},
		SignInFamily: family, AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	ctrl := gomock.NewController(t)

	pending := NewMockPendingRequestStore(ctrl)
	pending.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.PendingRequest) error {
			if fail(pe7jParkCreate) {
				return portErr
			}

			return memPending.Create(context.WithoutCancel(ctx), r)
		}).AnyTimes()
	pending.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
			if fail(pe7jPendingLoad) {
				return nil, portErr
			}

			return memPending.Load(context.WithoutCancel(ctx), digest)
		}).AnyTimes()
	pending.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memPending.Advance).AnyTimes()
	pending.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memPending.DeleteExpired).AnyTimes()

	sessions := NewMockBrowserSessionStore(ctrl)
	sessions.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Put).AnyTimes()
	sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, d []byte, at time.Time) (*oidcprovider.BrowserSession, error) {
			if fail(pe7jSessionLoad) {
				return nil, portErr
			}

			return memSessions.Load(context.WithoutCancel(ctx), d, at)
		}).AnyTimes()
	sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Touch).AnyTimes()
	sessions.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Delete).AnyTimes()
	sessions.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteBySignIn).AnyTimes()
	sessions.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteExpired).AnyTimes()

	codes := NewMockCodeStore(ctrl)
	codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.CodeRecord) error {
			if fail(pe7jCodeCreate) {
				return portErr
			}

			return memCodes.Create(context.WithoutCancel(ctx), r)
		}).AnyTimes()
	codes.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(memCodes.Load).AnyTimes()
	codes.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memCodes.DeleteExpired).AnyTimes()
	codes.EXPECT().UnspentBySignIn(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memCodes.UnspentBySignIn).AnyTimes()
	codes.EXPECT().UnspentByClient(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memCodes.UnspentByClient).AnyTimes()

	// The generator fails the first identifier asked for once armed, at the
	// site that names it.
	ids := &pe7fIDs{armed: &armed, hits: &hits}
	if site == pe7jParkID || site == pe7jCodeID {
		ids.err = portErr
	}

	registry, err := oidcprovider.NewMemoryRegistry(authzClients())
	require.NoError(t, err)

	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         logoutSigningKeys(),
		Users:        activeUsers(t),
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	},
		oidcprovider.WithClock(clockwork.NewFakeClockAt(now)),
		oidcprovider.WithLogger(logger),
		oidcprovider.WithIDGenerator(ids),
		oidcprovider.WithPendingRequestStore(pending),
		oidcprovider.WithBrowserSessionStore(sessions),
		oidcprovider.WithConsentStore(memConsents),
		oidcprovider.WithGrantStore(memGrants),
		oidcprovider.WithCodeStore(codes),
	)
	require.NoError(t, err)

	// Whatever a flow needs parked first is parked while every port works.
	var handle, flow string

	switch site {
	case pe7jPendingLoad:
		res, err := p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
		require.NoError(t, err)

		loc, err := url.Parse(res.Location)
		require.NoError(t, err)

		handle, flow = loc.Query().Get(oidcprovider.HandleParam), res.FlowSecret
	case pe7jSessionLoad:
		res, err := p.EndSession(t.Context(), oidcprovider.EndSessionInput{Params: url.Values{}})
		require.NoError(t, err)

		loc, err := url.Parse(res.Location)
		require.NoError(t, err)

		handle, flow = loc.Query().Get(oidcprovider.HandleParam), res.FlowSecret
	}

	armed.Store(true)

	out := pe7eBounded(t, func() pe7jOutcome {
		var (
			o   pe7jOutcome
			err error
		)

		switch site {
		case pe7jParkID, pe7jParkCreate, pe7jCodeID, pe7jCodeCreate:
			in := oidcprovider.AuthorizeInput{Params: authzParams()}
			if site == pe7jCodeID || site == pe7jCodeCreate {
				in.BrowserSessionSecret, in.IdleTimeout = pe7eSessionSecret, sessionIdle
			}

			var res oidcprovider.AuthorizeResult

			res, err = p.Authorize(ctx, in)
			o.hasFlow = res.FlowSecret != ""

			if u, perr := url.Parse(res.Location); perr == nil && res.Location != "" {
				o.at = u.Scheme + "://" + u.Host + u.Path
				o.errorCode = u.Query().Get("error")
				o.state = u.Query().Get("state")
				o.hasCode = u.Query().Get("code") != ""
				// The response a browser is sent to never carries the port's text.
				assert.NotContains(t, res.Location, pe7bSecret)
			}
		case pe7jPendingLoad:
			var view *oidcprovider.PendingView

			view, err = p.PendingRequest(ctx, handle, flow)
			o.viewed = view != nil
		case pe7jSessionLoad:
			var res *oidcprovider.LogoutResult

			res, err = p.ConfirmLogout(ctx, handle, flow, pe7eSessionSecret, true)
			o.ended = res != nil && res.Ended != nil
		}

		if err != nil {
			o.failed = true
			o.errText = err.Error()
			o.dependency = errors.Is(err, oidcprovider.ErrDependency)
			o.notFound = errors.Is(err, oidcprovider.ErrNotFound)
			o.unknownHandle = errors.Is(err, oidcprovider.ErrUnknownHandle)
			o.canceled = errors.Is(err, context.Canceled)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}

		return o
	})

	armed.Store(false)
	require.Positive(t, hits.Load(), "the call reached %s", site)

	held, err := p.CodesForTest().UnspentByClient(t.Context(), user, "billing-web")
	require.NoError(t, err)
	out.codes = len(held)

	g, err := memGrants.Load(t.Context(), grantFamily)
	require.NoError(t, err)
	out.grantEnded = !g.SignInEndedAt.IsZero()

	_, err = memSessions.Load(t.Context(), digest, now)
	out.sessionHeld = err == nil

	out.aborts, _ = pe7eAbortsAndLogs(t, logs.String(), "")

	return out
}

// pe7jSameAsPlain asserts a hostile row is answered and leaves state exactly as
// the plain outage of the same call did, and never as the sentinel the hostile
// chain reaches.
func pe7jSameAsPlain(t *testing.T, plain, got pe7jOutcome) {
	t.Helper()

	assert.Equal(t, plain.failed, got.failed)
	assert.Equal(t, plain.errText, got.errText, "the same returned error")
	assert.Equal(t, plain.dependency, got.dependency, "answered as a dependency failure")
	assert.Equal(t, plain.canceled, got.canceled)
	assert.False(t, got.notFound, "never answered as the port's not-found sentinel")
	assert.False(t, got.unknownHandle, "never answered as an unknown handle")
	assert.Equal(t, plain.errorCode, got.errorCode, "the same OAuth error")
	assert.Equal(t, plain.at, got.at, "answered at the same place")
	assert.Equal(t, plain.state, got.state)
	assert.Equal(t, plain.hasCode, got.hasCode, "no code")
	assert.Equal(t, plain.hasFlow, got.hasFlow, "nothing parked a page could resume")
	assert.Equal(t, plain.viewed, got.viewed)
	assert.Equal(t, plain.ended, got.ended)
	assert.Equal(t, plain.codes, got.codes, "the same codes held")
	assert.Equal(t, plain.grantEnded, got.grantEnded, "the same grants ended")
	assert.Equal(t, plain.sessionHeld, got.sessionHeld, "the browser session kept as after a plain outage")
	assert.NotContains(t, got.errText, pe7bSecret)
}

// TestPortErrors_ParkLoadAndCode pins that parking a request, reading a parked
// request, writing a code and a logout's read of the browser session, failing
// at a port with an error whose chain cannot be walked, are answered exactly as
// a plain outage of that port is: a dependency failure (server_error at the
// redirect URI where the flow answers one), never ErrUnknownHandle for the
// store's not-found sentinel nor "no session" for the session store's, and
// never with the port's own text in the response. The sanitizer writes one
// record, to the provider's logger, and none to slog.Default().
func TestPortErrors_ParkLoadAndCode(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7jRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name   string
		site   pe7eSite
		err    error
		child  bool
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, plain, got pe7jOutcome)
	}

	asOutage := func(reason string) func(*testing.T, pe7jOutcome, pe7jOutcome) {
		return func(t *testing.T, plain, got pe7jOutcome) {
			t.Helper()

			pe7jSameAsPlain(t, plain, got)
			pe7eOneAbort(t, got.aborts, nil, reason)
		}
	}

	walked := func(t *testing.T, plain, got pe7jOutcome) {
		t.Helper()

		pe7jSameAsPlain(t, plain, got)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	sites := []pe7eSite{pe7jParkID, pe7jParkCreate, pe7jPendingLoad, pe7jCodeID, pe7jCodeCreate, pe7jSessionLoad}

	var cases []testCase

	for _, site := range sites {
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
			testCase{name: prefix + "a plain outage, against itself", site: site, err: pe7bErrDown, assert: walked},
		)
	}

	// A store's honest not-found keeps the answer the site gives it.
	cases = append(cases,
		testCase{
			name: string(pe7jPendingLoad) + ": a plain ErrNotFound is an unknown handle",
			site: pe7jPendingLoad, err: oidcprovider.ErrNotFound,
			assert: func(t *testing.T, _, got pe7jOutcome) {
				t.Helper()

				assert.True(t, got.failed)
				assert.True(t, got.unknownHandle, "an unknown handle")
				assert.False(t, got.dependency)
				assert.Empty(t, got.aborts)
			},
		},
		testCase{
			name: string(pe7jSessionLoad) + ": a plain ErrNotFound is no session, and ends nothing",
			site: pe7jSessionLoad, err: oidcprovider.ErrNotFound,
			assert: func(t *testing.T, _, got pe7jOutcome) {
				t.Helper()

				assert.False(t, got.failed, "no session is an answer")
				assert.False(t, got.ended)
				assert.False(t, got.grantEnded)
				assert.Empty(t, got.aborts)
			},
		},
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7jInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7jRun(t, ctx, tc.site, pe7bErrDown)
			// An authorization request answers a dependency failure at the redirect URI,
			// the other calls return it.
			require.True(t, plain.failed && plain.dependency || plain.errorCode == "server_error",
				"precondition: a plain outage is a dependency failure, or a server_error at the redirect URI")
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7jRun(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7jRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7jInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7jInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7jRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7jRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
