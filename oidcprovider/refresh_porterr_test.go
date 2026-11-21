package oidcprovider_test

// TestPortErrors_RefreshGrant and TestPortErrors_RefreshGrantAnswersNothing
// replace slog.Default() for their duration, so they do not run in parallel,
// and they restore the logger they found.

import (
	"context"
	"encoding/json"
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

// pe7dRowEnv names the row a child process runs. It is empty in the parent.
const pe7dRowEnv = "SCRTY_OIDCPROVIDER_PE7D_PORTERR_ROW"

// pe7dRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7dRanMarker = "SCRTY_OIDCPROVIDER_PE7D_PORTERR_RAN: "

// pe7dNoRecord is no error a port returns: the grant store given it answers a
// load with neither a record nor an error, a port breaking its contract.
var pe7dNoRecord = errors.New("pe7d: answer no record and no error")

// pe7dSite names the port call of a refresh a row fails, and through it the
// scene the refresh starts from.
type pe7dSite string

const (
	// A refresh of the exchange's token.
	pe7dGrantLoad    pe7dSite = "the refresh's GrantStore.Load"
	pe7dUserLoad     pe7dSite = "the refresh's UserLoader.LoadByUserID"
	pe7dUserGoneRevo pe7dSite = "a gone user's GrantStore.Revoke"
	pe7dAccessCreate pe7dSite = "the refresh's AccessTokenStore.Create"
	// A reuse: the exchange's token presented again past its grace, after it
	// was rotated.
	pe7dReuseMark   pe7dSite = "a reuse's GrantStore.Revoke ahead of the verdict"
	pe7dReuseFamily pe7dSite = "a reuse's GrantStore.Revoke when its family cannot be deleted"
)

// pe7dReuses reports whether site's scene is a reuse.
func pe7dReuses(site pe7dSite) bool { return site == pe7dReuseMark || site == pe7dReuseFamily }

// pe7dNotFound is the not-found sentinel of site's port.
func pe7dNotFound(site pe7dSite) error {
	if site == pe7dUserLoad {
		return identity.ErrUserNotFound
	}

	return oidcprovider.ErrNotFound
}

// pe7dLineage is a memory lineage store whose family deletion fails while
// failDelete is set.
type pe7dLineage struct {
	session.Store

	failDelete atomic.Bool
}

// DeleteFamily implements session.Store.
func (l *pe7dLineage) DeleteFamily(ctx context.Context, family id.ID) (int, error) {
	if l.failDelete.Load() {
		return 0, pe7bErrDown
	}

	return l.Store.DeleteFamily(ctx, family)
}

// pe7dAnswer is how a token request was answered.
type pe7dAnswer struct {
	issued     bool
	dependency bool
	code       string
}

// pe7dOutcome is what one refresh through a failing port produced, and the
// state it left. Every error classification is made inside the bound, so a
// hostile chain that reaches the caller raw fails the run as a hang rather
// than hanging the test.
type pe7dOutcome struct {
	issued bool
	text   string

	dependency bool
	notFound   bool
	canceled   bool
	unwalkable bool
	// code is the protocol refusal's code, empty when the error is none.
	code string

	// The stores' state afterwards: the grant revoked and why, the grant's
	// lineage records that could still be rotated from, the opaque access
	// tokens the refresh stored and how many of them are still usable.
	grantRevoked bool
	revokeCause  oidcprovider.RevocationCause
	liveHeads    int
	stored       int32
	storedLive   int

	// again is the same request sent once more with every port working, and
	// newest a refresh of the newest token after it, for a reuse's scene.
	again, newest pe7dAnswer

	// aborts are the sanitizer's records on the provider's logger.
	aborts []map[string]any
}

// pe7dClassify answers err, made inside the caller's bound.
func pe7dClassify(err error) (o pe7dOutcome) {
	if err == nil {
		return o
	}
	o.text = err.Error()
	// ErrDependency first: a library fault lists its sentinels before its
	// cause, so this check never reaches a raw port error.
	o.dependency = errors.Is(err, oidcprovider.ErrDependency)
	o.notFound = errors.Is(err, oidcprovider.ErrNotFound) || errors.Is(err, identity.ErrUserNotFound)
	o.canceled = errors.Is(err, context.Canceled)
	o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)

	var refusal *oidcprovider.Error
	if errors.As(err, &refusal) {
		o.code = refusal.Code
	}

	return o
}

// pe7dRun exchanges an opaque-app code for openid and offline_access, sets up
// site's scene, and refreshes on ctx while site's port call fails with
// portErr. It fails the test when the refresh hangs, lets a panic escape, or
// never reaches site.
func pe7dRun(t *testing.T, ctx context.Context, site pe7dSite, portErr error) pe7dOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed            atomic.Bool
		hits             atomic.Int32
		loads, revokes   atomic.Int32
		stored           atomic.Int32
		storedIDs        = make(chan id.ID, 16)
		failWith         = func() error { hits.Add(1); return portErr }
		failing          = func(at pe7dSite) bool { return armed.Load() && site == at }
		clk              = clockwork.NewFakeClockAt(exchangeFixtureStart)
		memLineage, err0 = session.NewMemoryStore(session.WithMemoryStoreClock(clk))
	)
	require.NoError(t, err0)

	memGrants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	memAccess, err := oidcprovider.NewMemoryAccessTokenStore()
	require.NoError(t, err)
	lineage := &pe7dLineage{Store: memLineage}

	ctrl := gomock.NewController(t)

	grants := NewMockGrantStore(ctrl)
	grants.EXPECT().UseCodes(gomock.Any()).DoAndReturn(memGrants.UseCodes).AnyTimes()
	grants.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, g *oidcprovider.Grant) error {
			return memGrants.Create(context.WithoutCancel(ctx), g)
		}).AnyTimes()
	grants.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, family id.ID) (*oidcprovider.Grant, error) {
			if armed.Load() && loads.Add(1) == 1 && site == pe7dGrantLoad {
				if portErr == pe7dNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
					hits.Add(1)

					return nil, nil
				}

				return nil, failWith()
			}

			return memGrants.Load(context.WithoutCancel(ctx), family)
		}).AnyTimes()
	grants.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) (bool, error) {
			if armed.Load() {
				nth := revokes.Add(1)
				if failing(pe7dUserGoneRevo) && nth == 1 || failing(pe7dReuseMark) && nth == 1 || failing(pe7dReuseFamily) && nth == 2 {
					return false, failWith()
				}
			}

			return memGrants.Revoke(context.WithoutCancel(ctx), family, cause, at)
		}).AnyTimes()

	access := NewMockAccessTokenStore(ctrl)
	access.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.AccessTokenRecord) error {
			if failing(pe7dAccessCreate) {
				return failWith()
			}
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
			return memAccess.Revoke(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			switch {
			case failing(pe7dUserLoad):
				return nil, failWith()
			case failing(pe7dUserGoneRevo):
				return nil, identity.ErrUserNotFound
			}

			return activeUser(user)
		}).AnyTimes()

	f := pe7bFixture(t, users,
		oidcprovider.WithClock(clk),
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithAccessTokenStore(access),
		oidcprovider.WithRefreshTokenStore(oplineage.New(lineage)),
		oidcprovider.WithRefreshSuccessorKey(successorKeyA),
		oidcprovider.WithLogger(logger),
	)

	c := issueCodeFor(t, f, opaqueClient, func(v url.Values) {
		asClient(v, opaqueClient, opaqueRedirect)
		v.Set("scope", "openid offline_access")
	}, testSignIn(f, "u-1"), "openid", "offline_access")
	first, err := f.p.Token(t.Context(), confidentialExchange(opaqueClient, opaqueRedirect, c, nil))
	require.NoError(t, err, "precondition: the exchange succeeds")
	require.NotEmpty(t, first.RefreshToken, "precondition: the grant holds a refresh token")
	family := grantOf(t, &exchangeFixture{parkFixture: f}, c).Family

	refreshOf := func(raw string) oidcprovider.TokenRequest { return refreshRequest(opaqueClient, raw, nil) }

	var newest string

	if pe7dReuses(site) {
		second, err := f.p.Token(t.Context(), refreshOf(first.RefreshToken))
		require.NoError(t, err, "precondition: the first refresh succeeds")
		newest = second.RefreshToken
		clk.Advance(30 * time.Second)
	}

	request := refreshOf(first.RefreshToken)

	lineage.failDelete.Store(site == pe7dReuseFamily)
	armed.Store(true)

	type result struct {
		out      pe7dOutcome
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

		res, err := f.p.Token(ctx, request)
		o := pe7dClassify(err)
		o.issued = res != nil

		returned = true
		done <- result{out: o}
	}()

	var out pe7dOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a port error escaped as a panic: %v", r.value)
		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the refresh, or its classification")
	}

	armed.Store(false)
	lineage.failDelete.Store(false)
	require.Positive(t, hits.Load(), "the refresh reached %s", site)

	grant, err := memGrants.Load(t.Context(), family)
	require.NoError(t, err)
	out.grantRevoked, out.revokeCause = grant.Revoked, grant.RevokeCause

	heads, err := memLineage.ListByUser(t.Context(), "u-1", clk.Now())
	require.NoError(t, err)
	out.liveHeads = len(heads)

	out.stored = stored.Load()
	close(storedIDs)
	for tokenID := range storedIDs {
		held, err := memAccess.Load(t.Context(), tokenID)
		require.NoError(t, err)
		if !held.Revoked {
			out.storedLive++
		}
	}

	answer := func(raw string) pe7dAnswer {
		res, err := f.p.Token(t.Context(), refreshOf(raw))
		o := pe7dClassify(err)

		return pe7dAnswer{issued: res != nil, dependency: o.dependency, code: o.code}
	}
	out.again = answer(first.RefreshToken)
	if newest != "" {
		out.newest = answer(newest)
	}

	for _, rec := range pe7bJSONRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// pe7dRow is one hostile port error, tried at every site.
type pe7dRow struct {
	name   string
	err    func(site pe7dSite) error
	reason string
	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally.
	child bool
	// cancel runs the row on a context the caller cancelled.
	cancel bool
}

// pe7dFixed is a row error that is the same at every site.
func pe7dFixed(err error) func(pe7dSite) error { return func(pe7dSite) error { return err } }

// pe7dRows are the hostile errors every site is tried with.
func pe7dRows() []pe7dRow {
	return []pe7dRow{
		{name: "a cycle through Unwrap() error", err: pe7dFixed(&pe7bCycleOne{}), reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: pe7dFixed(&pe7bCycleMany{}), reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: pe7dFixed(pe7bPanicUnwrap{}), reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: pe7dFixed(pe7bPanicNilUnwrap{}), reason: "panic"},
		{name: "a join that fans out", err: pe7dFixed(pe7bFanOut(25, errors.New(pe7bSecret))), reason: "budget"},
		{
			name:   "a join that fans out over the site's not-found sentinel",
			err:    func(site pe7dSite) error { return pe7bFanOut(25, pe7dNotFound(site)) },
			reason: "budget",
		},
		{
			name:   "a cycle around the site's not-found sentinel",
			err:    func(site pe7dSite) error { return &pe7bCycleAround{sentinel: pe7dNotFound(site)} },
			reason: "budget", child: true,
		},
		{
			name: "a join that fans out over context.Canceled on a context the caller cancelled",
			err:  pe7dFixed(pe7bFanOut(25, context.Canceled)), reason: "budget", cancel: true,
		},
		{
			name: "a cycle around context.Canceled on a context the caller cancelled",
			err:  pe7dFixed(&pe7bCycleAround{sentinel: context.Canceled}), reason: "budget", child: true, cancel: true,
		},
		{name: "a cycle on a context the caller cancelled", err: pe7dFixed(&pe7bCycleOne{}), reason: "budget", cancel: true},
	}
}

// pe7dSameAsPlain asserts got is the plain outage's outcome in every class,
// text and piece of state.
func pe7dSameAsPlain(t *testing.T, plain, got pe7dOutcome) {
	t.Helper()

	require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
	require.Empty(t, plain.code, "precondition: a plain outage is no protocol refusal")
	require.False(t, plain.issued, "precondition: a plain outage hands out no token")

	assert.True(t, got.dependency, "answered as ErrDependency")
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
	assert.NotContains(t, got.text, pe7bSecret)
}

// pe7dSites are the port calls of a refresh this file pins.
func pe7dSites() []pe7dSite {
	return []pe7dSite{pe7dGrantLoad, pe7dReuseMark, pe7dReuseFamily, pe7dUserLoad, pe7dUserGoneRevo, pe7dAccessCreate}
}

// TestPortErrors_RefreshGrant pins that the refresh grant's read of its grant,
// its revocations of a reused token's grant and of a gone user's grant, its
// user load, and its store of an opaque access token, failing with an error
// whose chain cannot be walked, are answered exactly as a plain outage of that
// port is: ErrDependency (server_error) with the same fixed text, never
// invalid_grant, and the same state left: the grant revoked or not, the token
// family intact or not, no token handed out, and the next presentation of the
// token and of the newest one answered alike. A fan-out over a not-found
// sentinel is never read as "no such grant" or "no such user". The sanitizer
// writes one record, to the provider's logger, and none to slog.Default().
func TestPortErrors_RefreshGrant(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7dRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name  string
		site  pe7dSite
		err   error
		child bool

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pe7dOutcome)
	}

	asOutage := func(reason string) func(t *testing.T, plain, got pe7dOutcome) {
		return func(t *testing.T, plain, got pe7dOutcome) {
			t.Helper()

			pe7dSameAsPlain(t, plain, got)
			assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")

			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), pe7bSecret, "the record quotes the error")
		}
	}

	walked := func(t *testing.T, plain, got pe7dOutcome) {
		t.Helper()

		pe7dSameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	for _, site := range pe7dSites() {
		prefix := string(site) + ": "

		for _, row := range pe7dRows() {
			tc := testCase{name: prefix + row.name, site: site, err: row.err(site), child: row.child, assert: asOutage(row.reason)}
			if row.cancel {
				tc.ctx = cancelled
			}

			cases = append(cases, tc)
		}

		cases = append(cases,
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as an outage",
				site: site, err: (*pe7bTypedNil)(nil), assert: walked,
			},
			testCase{
				name: prefix + "a plain outage, against itself",
				site: site, err: pe7bErrDown, assert: walked,
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7dInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7dRun(t, ctx, tc.site, pe7bErrDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7dRun(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7dRanMarker + tc.name + "\n")
			}
		})
	}
}

// TestPortErrors_RefreshGrantAnswersNothing pins that a grant store or user
// loader whose load answers neither a record nor an error, breaking its
// contract, is answered at the refresh's read of its grant or of the grant's
// user as that port failing outright: the same dependency failure and state as
// a plain outage, no panic, and never a user-disabled revocation.
func TestPortErrors_RefreshGrantAnswersNothing(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name string
		site pe7dSite
		// nothing is the port error that makes site's port answer no record
		// and no error: pe7dNoRecord for the grant store, and nil for the user
		// loader, which then answers (nil, nil).
		nothing error
		assert  func(t *testing.T, plain, got pe7dOutcome)
	}

	nothingWalked := func(t *testing.T, plain, got pe7dOutcome) {
		t.Helper()

		pe7dSameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "no chain was walked")
		assert.Empty(t, got.aborts, "no abort record")
	}

	cases := []testCase{
		{name: "the refresh's grant", site: pe7dGrantLoad, nothing: pe7dNoRecord, assert: nothingWalked},
		{name: "the grant's user", site: pe7dUserLoad, nothing: nil, assert: nothingWalked},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defaults := pe7cSwapDefault(t)

			plain := pe7dRun(t, t.Context(), tc.site, pe7bErrDown)
			got := pe7dRun(t, t.Context(), tc.site, tc.nothing)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)
		})
	}
}

// pe7dInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7dInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7dRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7dRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
