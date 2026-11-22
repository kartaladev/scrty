package oidcprovider_test

// TestPortErrors_RefreshRest and TestPortErrors_BrowserSession replace
// slog.Default() for their duration, so they do not run in parallel, and they
// restore the logger they found.

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
	"github.com/kartaladev/scrty/internal/oplineage"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// pe7eRowEnv names the row a child process runs. It is empty in the parent.
const pe7eRowEnv = "SCRTY_OIDCPROVIDER_PE7E_PORTERR_ROW"

// pe7eRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7eRanMarker = "SCRTY_OIDCPROVIDER_PE7E_PORTERR_RAN: "

// pe7eFaultType is the error_type a failure record names for a sanitized
// error.
const pe7eFaultType = "*porterr.Fault"

// pe7eSite names the port call a row fails.
type pe7eSite string

const (
	// The refresh grant: a refresh of the exchange's token.
	pe7eStillLive pe7eSite = "the refresh's second GrantStore.Load"
	pe7eDiscard   pe7eSite = "an unanswered refresh's AccessTokenStore.Revoke"
	// A reuse: the exchange's token presented again past its grace, after it
	// was rotated, the manager deleting the family and telling its observer.
	pe7eReuseObserved pe7eSite = "the reuse observer's GrantStore.Revoke"

	// The authorization endpoint answering from a browser session.
	pe7eSessionLoad pe7eSite = "the browser session's BrowserSessionStore.Load"
	pe7eSessionUser pe7eSite = "the browser session's UserLoader.LoadByUserID"
	pe7eAdvance     pe7eSite = "the consent park's PendingRequestStore.Advance"
)

// pe7eLogged is the message of the failure record a log-only site writes, and
// empty for a site whose failure is answered.
func pe7eLogged(site pe7eSite) string {
	switch site {
	case pe7eDiscard:
		return "oidcprovider: an access token no refresh answered could not be ended"
	case pe7eReuseObserved:
		return "oidcprovider: a reused refresh token's grant could not be marked revoked"
	}

	return ""
}

// pe7eNotFound is the not-found sentinel of site's port.
func pe7eNotFound(site pe7eSite) error {
	if site == pe7eSessionUser {
		return identity.ErrUserNotFound
	}

	return oidcprovider.ErrNotFound
}

// pe7eAbortsAndLogs splits the provider's records into the sanitizer's aborts
// and the site's own failure records.
func pe7eAbortsAndLogs(t *testing.T, out, logged string) (aborts, failures []map[string]any) {
	t.Helper()

	for _, rec := range pe7bJSONRecords(t, out) {
		switch rec["msg"] {
		case porterr.MsgClassificationAborted:
			aborts = append(aborts, rec)
		case logged:
			if logged != "" {
				failures = append(failures, rec)
			}
		}
	}

	return aborts, failures
}

// pe7eBounded runs call on a goroutine, and fails the test when it hangs or
// lets a panic escape.
func pe7eBounded[T any](t *testing.T, call func() T) T {
	t.Helper()

	type result struct {
		out      T
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

		out := call()
		returned = true
		done <- result{out: out}
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a port error escaped as a panic: %v", r.value)

		return r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the call, or its classification")
	}

	panic("unreachable")
}

// pe7eRefreshOutcome is what one refresh through a failing port produced, the
// state it left, and what the provider logged.
type pe7eRefreshOutcome struct {
	pe7dOutcome

	// failures are the site's own failure records.
	failures []map[string]any
}

// pe7eRefreshRun exchanges an opaque-app code for openid and offline_access,
// sets up site's scene, and refreshes on ctx while site's port call fails with
// portErr. errPe7dNoRecord makes the second grant load answer (nil, nil). It
// fails the test when the refresh hangs, lets a panic escape, or never reaches
// site.
func pe7eRefreshRun(ctx context.Context, t *testing.T, site pe7eSite, portErr error) pe7eRefreshOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed            atomic.Bool
		hits             atomic.Int32
		loads, revokes   atomic.Int32
		stored           atomic.Int32
		storedIDs        = make(chan id.ID, 16)
		clk              = clockwork.NewFakeClockAt(exchangeFixtureStart)
		memLineage, err0 = session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	)
	require.NoError(t, err0)

	memGrants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	memAccess, err := oidcprovider.NewMemoryAccessTokenStore()
	require.NoError(t, err)

	ctrl := gomock.NewController(t)

	grants := NewMockGrantStore(ctrl)
	grants.EXPECT().UseCodes(gomock.Any()).DoAndReturn(memGrants.UseCodes).AnyTimes()
	grants.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, g *oidcprovider.Grant) error {
			return memGrants.Create(context.WithoutCancel(ctx), g)
		}).AnyTimes()
	grants.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, family id.ID) (*oidcprovider.Grant, error) {
			// The refresh reads its grant first, and again once the lineage has
			// moved: the second read is the one these sites fail.
			if armed.Load() && loads.Add(1) == 2 {
				switch site {
				case pe7eStillLive:
					hits.Add(1)
					if portErr == errPe7dNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
						return nil, nil
					}

					return nil, portErr
				case pe7eDiscard:
					return nil, errPe7bDown
				}
			}

			return memGrants.Load(context.WithoutCancel(ctx), family)
		}).AnyTimes()
	grants.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) (bool, error) {
			// A reuse marks the row ahead of the verdict, and the observer marks
			// it again once the manager deleted the family.
			if armed.Load() && revokes.Add(1) == 2 && site == pe7eReuseObserved {
				hits.Add(1)

				return false, portErr
			}

			return memGrants.Revoke(context.WithoutCancel(ctx), family, cause, at)
		}).AnyTimes()

	access := NewMockAccessTokenStore(ctrl)
	access.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.AccessTokenRecord) error {
			if err := memAccess.Create(context.WithoutCancel(ctx), r); err != nil {
				return err
			}
			if armed.Load() {
				stored.Add(1)
				storedIDs <- r.ID
			}

			return nil
		}).AnyTimes()
	access.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) (*oidcprovider.AccessTokenRecord, error) {
			return memAccess.Load(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()
	access.EXPECT().Revoke(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) error {
			if armed.Load() && site == pe7eDiscard {
				hits.Add(1)

				return portErr
			}

			return memAccess.Revoke(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) { return activeUser(user) }).AnyTimes()

	f := pe7bFixture(t, users,
		oidcprovider.WithClock(clk),
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithAccessTokenStore(access),
		oidcprovider.WithRefreshTokenStore(oplineage.New(memLineage)),
		oidcprovider.WithRefreshSuccessorKey(successorKeyA),
		oidcprovider.WithLogger(logger),
	)

	c := issueCodeFor(t, f, opaqueClient, func(v url.Values) { //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		asClient(v, opaqueClient, opaqueRedirect)
		v.Set("scope", "openid offline_access")
	}, testSignIn(f, "u-1"), "openid", "offline_access")
	first, err := f.p.Token(t.Context(), confidentialExchange(opaqueClient, opaqueRedirect, c, nil)) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, err, "precondition: the exchange succeeds")
	require.NotEmpty(t, first.RefreshToken, "precondition: the grant holds a refresh token")
	family := grantOf(t, &exchangeFixture{parkFixture: f}, c).Family //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

	refreshOf := func(raw string) oidcprovider.TokenRequest { return refreshRequest(opaqueClient, raw, nil) }

	var newest string

	if site == pe7eReuseObserved {
		second, err := f.p.Token(t.Context(), refreshOf(first.RefreshToken)) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		require.NoError(t, err, "precondition: the first refresh succeeds")
		newest = second.RefreshToken
		clk.Advance(30 * time.Second)
	}

	request := refreshOf(first.RefreshToken)

	armed.Store(true)

	out := pe7eBounded(t, func() pe7eRefreshOutcome {
		res, err := f.p.Token(ctx, request)
		o := pe7dClassify(err)
		o.issued = res != nil

		return pe7eRefreshOutcome{pe7dOutcome: o}
	})

	armed.Store(false)
	require.Positive(t, hits.Load(), "the refresh reached %s", site)

	grant, err := memGrants.Load(t.Context(), family) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, err)
	out.grantRevoked, out.revokeCause = grant.Revoked, grant.RevokeCause

	heads, err := memLineage.ListByUser(t.Context(), "u-1", clk.Now()) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, err)
	out.liveHeads = len(heads)

	out.stored = stored.Load()
	close(storedIDs)
	for tokenID := range storedIDs {
		held, err := memAccess.Load(t.Context(), tokenID) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		require.NoError(t, err)
		if !held.Revoked {
			out.storedLive++
		}
	}

	answer := func(raw string) pe7dAnswer { //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		res, err := f.p.Token(t.Context(), refreshOf(raw))
		o := pe7dClassify(err)

		return pe7dAnswer{issued: res != nil, dependency: o.dependency, code: o.code}
	}
	out.again = answer(first.RefreshToken)
	if newest != "" {
		out.newest = answer(newest)
	}

	out.aborts, out.failures = pe7eAbortsAndLogs(t, logs.String(), pe7eLogged(site))

	return out
}

// pe7eRefreshSameAsPlain asserts got is the plain outage's outcome in every
// class, text and piece of state, and that the site's own failure record was
// written alike.
func pe7eRefreshSameAsPlain(t *testing.T, site pe7eSite, plain, got pe7eRefreshOutcome) {
	t.Helper()

	switch site {
	case pe7eReuseObserved:
		require.Equal(t, "invalid_grant", plain.code, "precondition: a reuse is refused whatever the observer's store does")
		require.True(t, plain.grantRevoked, "precondition: the grant was marked ahead of the verdict")
	default:
		require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
		require.Empty(t, plain.code, "precondition: a plain outage is no protocol refusal")
	}
	require.False(t, plain.issued, "precondition: a plain outage hands out no token")
	if site == pe7eDiscard {
		require.Equal(t, int32(1), plain.stored, "precondition: the refresh stored an access token")
		require.Equal(t, 1, plain.storedLive, "precondition: the token could not be ended")
	}

	assert.Equal(t, plain.dependency, got.dependency, "the same dependency class")
	assert.False(t, got.issued, "no token handed out")
	assert.Equal(t, plain.text, got.text, "the same fixed text")
	assert.Equal(t, plain.notFound, got.notFound, "the same not-found class")
	assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
	assert.Equal(t, plain.code, got.code, "the same protocol code")
	assert.Equal(t, plain.grantRevoked, got.grantRevoked, "the grant is revoked, or not, as for a plain outage")
	assert.Equal(t, plain.revokeCause, got.revokeCause, "the same revocation cause")
	assert.Equal(t, plain.liveHeads, got.liveHeads, "the token family is left as a plain outage leaves it")
	assert.Equal(t, plain.stored, got.stored, "the same opaque access tokens stored")
	assert.Equal(t, plain.storedLive, got.storedLive, "the same stored access tokens still usable")
	assert.Equal(t, plain.again, got.again, "presenting the token again is answered as after a plain outage")
	assert.Equal(t, plain.newest, got.newest, "the newest token is answered as after a plain outage")
	assert.Len(t, got.failures, len(plain.failures), "the site's failure record is written as for a plain outage")
	assert.NotContains(t, got.text, pe7bSecret)
}

// pe7eRow is one hostile port error, tried at every site.
type pe7eRow struct {
	name   string
	err    func(site pe7eSite) error
	reason string
	// child runs the row in a child process: unsanitized, a cycle through
	// Unwrap() []error can overflow the stack fatally.
	child bool
	// cancel runs the row on a context the caller cancelled.
	cancel bool
}

// pe7eFixed is a row error that is the same at every site.
func pe7eFixed(err error) func(pe7eSite) error { return func(pe7eSite) error { return err } }

// pe7eRows are the hostile errors every site is tried with.
func pe7eRows() []pe7eRow {
	return []pe7eRow{
		{name: "a cycle through Unwrap() error", err: pe7eFixed(&pe7bCycleOne{}), reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: pe7eFixed(&pe7bCycleMany{}), reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: pe7eFixed(pe7bPanicUnwrap{}), reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: pe7eFixed(pe7bPanicNilUnwrap{}), reason: "panic"},
		{name: "a join that fans out", err: pe7eFixed(pe7bFanOut(25, errors.New(pe7bSecret))), reason: "budget"},
		{
			name:   "a join that fans out over the site's not-found sentinel",
			err:    func(site pe7eSite) error { return pe7bFanOut(25, pe7eNotFound(site)) },
			reason: "budget",
		},
		{
			name:   "a cycle around the site's not-found sentinel",
			err:    func(site pe7eSite) error { return &pe7bCycleAround{sentinel: pe7eNotFound(site)} },
			reason: "budget", child: true,
		},
		{
			name: "a join that fans out over context.Canceled on a context the caller cancelled",
			err:  pe7eFixed(pe7bFanOut(25, context.Canceled)), reason: "budget", cancel: true,
		},
		{
			name: "a cycle around context.Canceled on a context the caller cancelled",
			err:  pe7eFixed(&pe7bCycleAround{sentinel: context.Canceled}), reason: "budget", child: true, cancel: true,
		},
		{name: "a cycle on a context the caller cancelled", err: pe7eFixed(&pe7bCycleOne{}), reason: "budget", cancel: true},
	}
}

// pe7eCancelled is a ctx modifier that cancels the context.
func pe7eCancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// pe7eOneAbort asserts exactly one abort record, at Error, with reason, and a
// failure record of the site's naming the sanitizer's fault.
func pe7eOneAbort(t *testing.T, aborts, failures []map[string]any, reason string) {
	t.Helper()

	require.Len(t, aborts, 1, "one abort record, on the provider's logger")
	assert.Equal(t, "ERROR", aborts[0]["level"])
	assert.Equal(t, reason, aborts[0]["reason"])
	for _, rec := range failures {
		assert.Equal(t, pe7eFaultType, rec["error_type"], "the failure record names the sanitized error")
	}
}

// TestPortErrors_RefreshRest pins that the refresh grant's second read of its
// grant, its ending of an access token stored for a refresh nobody was
// answered, and the reuse observer's revocation of the grant, failing with an
// error whose chain cannot be walked, are answered and leave state exactly as
// a plain outage of that port does. The second read is ErrDependency
// (server_error), never invalid_grant, also when its store answers no record
// and no error. The other two only log, as for a plain outage. The sanitizer
// writes one record, to the provider's logger, and none to slog.Default().
func TestPortErrors_RefreshRest(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7eRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name  string
		site  pe7eSite
		err   error
		child bool
		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context
		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, site pe7eSite, plain, got pe7eRefreshOutcome)
	}

	asOutage := func(reason string) func(*testing.T, pe7eSite, pe7eRefreshOutcome, pe7eRefreshOutcome) {
		return func(t *testing.T, site pe7eSite, plain, got pe7eRefreshOutcome) {
			t.Helper()

			pe7eRefreshSameAsPlain(t, site, plain, got)
			if site == pe7eStillLive {
				assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")
			}
			pe7eOneAbort(t, got.aborts, got.failures, reason)
		}
	}

	walked := func(t *testing.T, site pe7eSite, plain, got pe7eRefreshOutcome) {
		t.Helper()

		pe7eRefreshSameAsPlain(t, site, plain, got)
		assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	for _, site := range []pe7eSite{pe7eStillLive, pe7eDiscard, pe7eReuseObserved} {
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
		name: string(pe7eStillLive) + ": a store answering no record and no error is answered as an outage",
		site: pe7eStillLive, err: errPe7dNoRecord, assert: walked,
	})

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7eInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7eRefreshRun(ctx, t, tc.site, errPe7bDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7eRefreshRun(ctx, t, tc.site, tc.err)
			tc.assert(t, tc.site, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7eRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7eSessionSecret is the well-formed secret of the browser session a run
// holds.
const pe7eSessionSecret = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"

// pe7eAuthorizeOutcome is what one authorization request answered from a
// browser session produced, the state it left, and the provider's records.
type pe7eAuthorizeOutcome struct {
	errText   string
	errorCode string
	state     string
	hasCode   bool
	hasFlow   bool
	at        string

	dependency bool
	notFound   bool
	canceled   bool
	unwalkable bool

	// The state afterwards: the session extended, the codes held.
	touched bool
	codes   int

	aborts []map[string]any
}

// pe7eAuthorizeRun holds a browser session and sends an authorization request
// that the session would answer at its consent page, on ctx, while site's port
// call fails with portErr. errPe7dNoRecord makes the session load or the user
// load answer no record and no error. It fails the test when the request
// hangs, lets a panic escape, or never reaches site.
func pe7eAuthorizeRun(ctx context.Context, t *testing.T, site pe7eSite, portErr error) pe7eAuthorizeOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed atomic.Bool
		hits  atomic.Int32
		hit   = func() error { hits.Add(1); return portErr }
		now   = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	)

	memSessions, err := oidcprovider.NewMemoryBrowserSessionStore()
	require.NoError(t, err)
	memPending, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)

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
			if armed.Load() && site == pe7eSessionLoad {
				if portErr == errPe7dNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
					hits.Add(1)

					return nil, nil
				}

				return nil, hit()
			}

			return memSessions.Load(context.WithoutCancel(ctx), digest, at)
		}).AnyTimes()
	sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, idleUntil time.Time) error {
			return memSessions.Touch(context.WithoutCancel(ctx), digest, idleUntil)
		}).AnyTimes()
	sessions.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Delete).AnyTimes()
	sessions.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteBySignIn).AnyTimes()
	sessions.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteExpired).AnyTimes()

	pending := NewMockPendingRequestStore(ctrl)
	pending.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.PendingRequest) error {
			return memPending.Create(context.WithoutCancel(ctx), r)
		}).AnyTimes()
	pending.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(memPending.Load).AnyTimes()
	pending.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, handle []byte, from, to oidcprovider.Stage, s *oidcprovider.SignIn) error {
			if armed.Load() && site == pe7eAdvance {
				return hit()
			}

			return memPending.Advance(context.WithoutCancel(ctx), handle, from, to, s)
		}).AnyTimes()
	pending.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memPending.DeleteExpired).AnyTimes()

	f := newSessionFixture(t, plainKeys(t),
		oidcprovider.WithBrowserSessionStore(sessions),
		oidcprovider.WithPendingRequestStore(pending),
		oidcprovider.WithLogger(logger),
	)
	f.user = func(user identity.UserID) (*identity.Details, error) {
		if armed.Load() && site == pe7eSessionUser {
			if portErr == errPe7dNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
				hits.Add(1)

				return nil, nil
			}

			return nil, hit()
		}

		return activeUser(user)
	}

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

// pe7eAuthorizeSameAsPlain asserts got is the plain outage's outcome: a
// server_error at the redirect URI, nothing parked a page could resume, no
// code, the session untouched, and the same error classes.
func pe7eAuthorizeSameAsPlain(t *testing.T, plain, got pe7eAuthorizeOutcome) {
	t.Helper()

	require.Equal(t, "server_error", plain.errorCode, "precondition: a plain outage is answered with server_error")
	require.Equal(t, authzRedirect, plain.at, "precondition: at the redirect URI")
	require.False(t, plain.hasCode, "precondition: a plain outage hands out no code")

	assert.Equal(t, plain.errText, got.errText, "the same returned error")
	assert.Equal(t, plain.errorCode, got.errorCode, "the same OAuth error")
	assert.Equal(t, plain.at, got.at, "answered at the same place")
	assert.Equal(t, plain.state, got.state, "the same state")
	assert.Equal(t, plain.hasCode, got.hasCode, "no code")
	assert.Equal(t, plain.hasFlow, got.hasFlow, "nothing parked a page could resume")
	assert.Equal(t, plain.dependency, got.dependency, "the same dependency class")
	assert.Equal(t, plain.notFound, got.notFound, "the same not-found class")
	assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
	assert.Equal(t, plain.touched, got.touched, "the session is touched, or not, as for a plain outage")
	assert.Equal(t, plain.codes, got.codes, "the same codes held")
	assert.NotContains(t, got.errText, pe7bSecret)
}

// TestPortErrors_BrowserSession pins that answering an authorization request
// from a browser session, when the session's load, its user's load or the move
// of the parked request to its consent stage fails with an error whose chain
// cannot be walked, is answered exactly as a plain outage of that port is: a
// server_error at the redirect URI, never the login page a missing session or
// an inactive user would get. A session store or user loader answering no
// record and no error breaks its contract, and is answered as an outage too.
// The sanitizer writes one record, to the provider's logger, and none to
// slog.Default().
func TestPortErrors_BrowserSession(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7eRowEnv)
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
			pe7eOneAbort(t, got.aborts, nil, reason)
		}
	}

	walked := func(t *testing.T, plain, got pe7eAuthorizeOutcome) {
		t.Helper()

		pe7eAuthorizeSameAsPlain(t, plain, got)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	for _, site := range []pe7eSite{pe7eSessionLoad, pe7eSessionUser, pe7eAdvance} {
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

		if site != pe7eAdvance {
			cases = append(cases, testCase{
				name: prefix + "a port answering no record and no error is answered as an outage",
				site: site, err: errPe7dNoRecord, assert: walked,
			})
		}
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7eInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7eAuthorizeRun(ctx, t, tc.site, errPe7bDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7eAuthorizeRun(ctx, t, tc.site, tc.err)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7eRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7eInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7eInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7eRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7eRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
