package oidcprovider_test

// TestPortErrors_EndAndRevoke replaces slog.Default() for its duration, so it
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

// pe7iRowEnv names the row a child process runs. It is empty in the parent.
const pe7iRowEnv = "SCRTY_OIDCPROVIDER_PE7I_PORTERR_ROW"

// pe7iRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7iRanMarker = "SCRTY_OIDCPROVIDER_PE7I_PORTERR_RAN: "

const (
	// An end of a sign-in the chain asks for: the browser sessions go, then the grants.
	pe7iBrowserDelete pe7eSite = "EndSignIn's BrowserSessionStore.DeleteBySignIn"
	pe7iEndSignIns    pe7eSite = "EndSignIn's GrantStore.EndSignIns"
	// A logout the browser confirms: the grants alone.
	pe7iConfirmEnd pe7eSite = "ConfirmLogout's GrantStore.EndSignIns"
	// A security event revoking every grant of a user.
	pe7iRevokeByUser pe7eSite = "RevokeUserGrants's GrantStore.RevokeByUser"
	// The user's list of consents.
	pe7iListConsents pe7eSite = "Consents's ConsentStore.ListByUser"
	// A consent revoked: its grants, then the consent.
	pe7iRevokeByClient pe7eSite = "RevokeConsent's GrantStore.RevokeByUserAndClient"
	pe7iRevokeConsent  pe7eSite = "RevokeConsent's ConsentStore.Revoke"
)

// pe7iCalls counts what the provider asked of each store call a site reaches.
type pe7iCalls struct {
	browserDelete, endSignIns, revokeByUser, revokeByClient, listConsents, revokeConsent int32
}

// pe7iOutcome is what one call produced through a failing port, the state it
// left, and what the provider logged.
type pe7iOutcome struct {
	errText    string
	failed     bool
	dependency bool
	notFound   bool
	canceled   bool
	unwalkable bool

	// clients names who is told, by client and user: the family differs per run.
	clients []string
	views   int
	ended   bool

	grantRevoked, grantEnded, browserHeld, consentHeld bool

	calls  pe7iCalls
	aborts []map[string]any
}

// pe7iRun seeds a grant, a browser session and a consent of one user, then
// calls site's flow on ctx while site's port call fails with portErr. It fails
// the test when the call hangs, lets a panic escape, or never reaches site.
func pe7iRun(t *testing.T, ctx context.Context, site pe7eSite, portErr error) pe7iOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed atomic.Bool
		calls struct{ browserDelete, endSignIns, revokeByUser, revokeByClient, listConsents, revokeConsent atomic.Int32 }
		now   = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
		user  = identity.UserID("u-1")
	)

	clientID := authzClients()[0].ID
	failing := func(at ...pe7eSite) bool {
		if !armed.Load() {
			return false
		}
		for _, s := range at {
			if s == site {
				return true
			}
		}

		return false
	}

	memGrants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	memSessions, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	memConsents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)
	memPending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	grantFamily, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	digest := digestOf(t, pe7eSessionSecret)

	require.NoError(t, memGrants.Create(t.Context(), &oidcprovider.Grant{
		Family: grantFamily, User: user, ClientID: clientID, Scopes: []string{"openid"},
		SignInFamily: family, AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, memSessions.Put(t.Context(), &oidcprovider.BrowserSession{
		Digest: digest,
		SignIn: oidcprovider.SignIn{
			User: user, Family: family, AuthenticatedAt: now, AMR: []string{"pwd"}, AbsoluteExpiresAt: now.Add(time.Hour),
		},
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, memConsents.Give(t.Context(), user, clientID, []string{"openid"}, false, now))

	ctrl := gomock.NewController(t)

	grants := NewMockGrantStore(ctrl)
	grants.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(memGrants.Create).AnyTimes()
	grants.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(memGrants.Load).AnyTimes()
	grants.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memGrants.Revoke).AnyTimes()
	grants.EXPECT().UseCodes(gomock.Any()).DoAndReturn(memGrants.UseCodes).AnyTimes()
	grants.EXPECT().DeleteExpired(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memGrants.DeleteExpired).AnyTimes()
	grants.EXPECT().EndSignIns(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, sel oidcprovider.SignInSelector, at time.Time) ([]oidcprovider.Grant, error) {
			if armed.Load() {
				calls.endSignIns.Add(1)
			}
			if failing(pe7iEndSignIns, pe7iConfirmEnd) {
				return nil, portErr
			}

			return memGrants.EndSignIns(context.WithoutCancel(ctx), sel, at)
		}).AnyTimes()
	grants.EXPECT().RevokeByUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, u identity.UserID, cause oidcprovider.RevocationCause, at time.Time) ([]oidcprovider.Grant, error) {
			if armed.Load() {
				calls.revokeByUser.Add(1)
			}
			if failing(pe7iRevokeByUser) {
				return nil, portErr
			}

			return memGrants.RevokeByUser(context.WithoutCancel(ctx), u, cause, at)
		}).AnyTimes()
	grants.EXPECT().RevokeByUserAndClient(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, u identity.UserID, c string, cause oidcprovider.RevocationCause, at time.Time) ([]oidcprovider.Grant, error) {
			if armed.Load() {
				calls.revokeByClient.Add(1)
			}
			if failing(pe7iRevokeByClient) {
				return nil, portErr
			}

			return memGrants.RevokeByUserAndClient(context.WithoutCancel(ctx), u, c, cause, at)
		}).AnyTimes()

	sessions := NewMockBrowserSessionStore(ctrl)
	sessions.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Put).AnyTimes()
	sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, d []byte, at time.Time) (*oidcprovider.BrowserSession, error) {
			return memSessions.Load(context.WithoutCancel(ctx), d, at)
		}).AnyTimes()
	sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Touch).AnyTimes()
	sessions.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Delete).AnyTimes()
	sessions.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteExpired).AnyTimes()
	sessions.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, sel oidcprovider.SignInSelector) (int, error) {
			if armed.Load() {
				calls.browserDelete.Add(1)
			}
			if failing(pe7iBrowserDelete) {
				return 0, portErr
			}

			return memSessions.DeleteBySignIn(context.WithoutCancel(ctx), sel)
		}).AnyTimes()

	consents := NewMockConsentStore(ctrl)
	consents.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memConsents.Load).AnyTimes()
	consents.EXPECT().Give(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		memConsents.Give).AnyTimes()
	consents.EXPECT().ListByUser(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, u identity.UserID) ([]oidcprovider.Consent, error) {
			if armed.Load() {
				calls.listConsents.Add(1)
			}
			if failing(pe7iListConsents) {
				return nil, portErr
			}

			return memConsents.ListByUser(context.WithoutCancel(ctx), u)
		}).AnyTimes()
	consents.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, u identity.UserID, c string) (bool, error) {
			if armed.Load() {
				calls.revokeConsent.Add(1)
			}
			if failing(pe7iRevokeConsent) {
				return false, portErr
			}

			return memConsents.Revoke(context.WithoutCancel(ctx), u, c)
		}).AnyTimes()

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
		oidcprovider.WithPendingRequestStore(memPending),
		oidcprovider.WithBrowserSessionStore(sessions),
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithConsentStore(consents),
	)
	require.NoError(t, err)

	var handle, flow string
	if site == pe7iConfirmEnd {
		res, err := p.EndSession(t.Context(), oidcprovider.EndSessionInput{Params: url.Values{}})
		require.NoError(t, err)

		loc, err := url.Parse(res.Location)
		require.NoError(t, err)

		handle, flow = loc.Query().Get(oidcprovider.HandleParam), res.FlowSecret
	}

	armed.Store(true)

	out := pe7eBounded(t, func() pe7iOutcome {
		var (
			o   pe7iOutcome
			err error
		)

		switch site {
		case pe7iBrowserDelete, pe7iEndSignIns:
			var told []oidcprovider.ClientToNotify

			told, err = p.EndSignIn(ctx, oidcprovider.SignInSelector{Family: family})
			for _, c := range told {
				o.clients = append(o.clients, c.ClientID+"/"+string(c.User))
			}
		case pe7iConfirmEnd:
			var res *oidcprovider.LogoutResult

			res, err = p.ConfirmLogout(ctx, handle, flow, pe7eSessionSecret, true)
			o.ended = res != nil && res.Ended != nil
		case pe7iRevokeByUser:
			err = p.RevokeUserGrants(ctx, user, string(oidcprovider.CauseRecovery))
		case pe7iListConsents:
			var views []oidcprovider.ConsentView

			views, err = p.Consents(ctx, user)
			o.views = len(views)
		case pe7iRevokeByClient, pe7iRevokeConsent:
			err = p.RevokeConsent(ctx, user, clientID)
		}

		if err != nil {
			o.failed = true
			o.errText = err.Error()
			o.dependency = errors.Is(err, oidcprovider.ErrDependency)
			o.notFound = errors.Is(err, oidcprovider.ErrNotFound) || errors.Is(err, oidcprovider.ErrForeignConsent)
			o.canceled = errors.Is(err, context.Canceled)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		}

		return o
	})

	armed.Store(false)

	out.calls = pe7iCalls{
		browserDelete: calls.browserDelete.Load(), endSignIns: calls.endSignIns.Load(), revokeByUser: calls.revokeByUser.Load(),
		revokeByClient: calls.revokeByClient.Load(), listConsents: calls.listConsents.Load(), revokeConsent: calls.revokeConsent.Load(),
	}

	reached := map[pe7eSite]int32{
		pe7iBrowserDelete: out.calls.browserDelete, pe7iEndSignIns: out.calls.endSignIns, pe7iConfirmEnd: out.calls.endSignIns,
		pe7iRevokeByUser: out.calls.revokeByUser, pe7iListConsents: out.calls.listConsents,
		pe7iRevokeByClient: out.calls.revokeByClient, pe7iRevokeConsent: out.calls.revokeConsent,
	}
	require.Positive(t, reached[site], "the call reached %s", site)

	g, err := memGrants.Load(t.Context(), grantFamily)
	require.NoError(t, err)
	out.grantRevoked, out.grantEnded = g.Revoked, !g.SignInEndedAt.IsZero()

	_, err = memSessions.Load(t.Context(), digest, now)
	out.browserHeld = err == nil

	_, err = memConsents.Load(t.Context(), user, clientID)
	out.consentHeld = err == nil

	out.aborts, _ = pe7eAbortsAndLogs(t, logs.String(), "")

	return out
}

// pe7iSameAsPlain asserts a hostile row is answered and leaves state exactly as
// the plain outage of the same call did, and never as the sentinel the hostile
// chain reaches.
func pe7iSameAsPlain(t *testing.T, plain, got pe7iOutcome) {
	t.Helper()

	assert.Equal(t, plain.failed, got.failed)
	assert.Equal(t, plain.dependency, got.dependency, "answered as a dependency failure")
	assert.Equal(t, plain.canceled, got.canceled)
	assert.False(t, got.notFound, "never answered as the port's not-found sentinel")
	assert.Equal(t, plain.clients, got.clients, "the same clients are returned")
	assert.Equal(t, plain.views, got.views)
	assert.Equal(t, plain.ended, got.ended)
	assert.Equal(t, plain.grantRevoked, got.grantRevoked, "the same grants are revoked or kept")
	assert.Equal(t, plain.grantEnded, got.grantEnded, "the same grants are marked ended")
	assert.Equal(t, plain.browserHeld, got.browserHeld, "the same browser sessions are kept")
	assert.Equal(t, plain.consentHeld, got.consentHeld, "the same consent is kept")
	assert.Equal(t, plain.calls, got.calls, "the other store is called exactly as after a plain outage")
	assert.NotContains(t, got.errText, pe7bSecret)
}

// TestPortErrors_EndAndRevoke pins that an end of a sign-in, a revocation of a
// user's grants or of a consent, and the list of a user's consents, failing at a
// store with an error whose chain cannot be walked, are answered and leave
// state exactly as a plain outage of that store does: a dependency failure,
// never the store's not-found sentinel, the same grants revoked or kept, and
// where an end runs on "whatever became of the other" the other store still
// called. The sanitizer writes one record, to the provider's logger, and none
// to slog.Default().
func TestPortErrors_EndAndRevoke(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7iRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name   string
		site   pe7eSite
		err    error
		child  bool
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, plain, got pe7iOutcome)
	}

	asOutage := func(reason string) func(*testing.T, pe7iOutcome, pe7iOutcome) {
		return func(t *testing.T, plain, got pe7iOutcome) {
			t.Helper()

			pe7iSameAsPlain(t, plain, got)
			pe7eOneAbort(t, got.aborts, nil, reason)
		}
	}

	walked := func(t *testing.T, plain, got pe7iOutcome) {
		t.Helper()

		pe7iSameAsPlain(t, plain, got)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	sites := []pe7eSite{
		pe7iBrowserDelete, pe7iEndSignIns, pe7iConfirmEnd,
		pe7iRevokeByUser, pe7iListConsents, pe7iRevokeByClient, pe7iRevokeConsent,
	}

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

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7iInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7iRun(t, ctx, tc.site, pe7bErrDown)
			require.True(t, plain.failed, "precondition: a plain outage fails the call")
			require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7iRun(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7iRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7iInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7iInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7iRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7iRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
