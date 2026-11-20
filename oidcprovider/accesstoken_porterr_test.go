package oidcprovider_test

// TestPortErrors_AccessTokenUse and TestPortErrors_UserInfo replace
// slog.Default() for their duration, so they do not run in parallel, and they
// restore the logger they found.

import (
	"context"
	"errors"
	"fmt"
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

// pe7fRowEnv names the row a child process runs. It is empty in the parent.
const pe7fRowEnv = "SCRTY_OIDCPROVIDER_PE7F_PORTERR_ROW"

// pe7fRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7fRanMarker = "SCRTY_OIDCPROVIDER_PE7F_PORTERR_RAN: "

// pe7fNoRecord is not returned: a site given it answers a load with neither a
// record nor an error, a port breaking its contract.
var pe7fNoRecord = errors.New("pe7f: answer no record and no error")

// pe7fSite names the port call a row fails.
type pe7fSite string

const (
	pe7fMintID      pe7fSite = "the opaque access token's id.Generator.NewID"
	pe7fGrantLoad   pe7fSite = "the token's GrantStore.Load"
	pe7fAccessLoad  pe7fSite = "the opaque token's AccessTokenStore.Load"
	pe7fUserLoad    pe7fSite = "UserInfo's UserLoader.LoadByUserID"
	pe7fClaimSource pe7fSite = "UserInfo's ClaimSource.Claims"
)

// pe7fEntry names the provider entry point a run drives.
type pe7fEntry string

const (
	pe7fExchange   pe7fEntry = "the code exchange"
	pe7fVerify     pe7fEntry = "VerifyAccessToken"
	pe7fIntrospect pe7fEntry = "Introspect"
	pe7fRevoke     pe7fEntry = "Revoke"
	pe7fUserInfo   pe7fEntry = "UserInfo"
)

// pe7fRoute is one site reached through one entry point.
type pe7fRoute struct {
	site  pe7fSite
	entry pe7fEntry
}

func (r pe7fRoute) String() string { return string(r.site) + " via " + string(r.entry) }

// pe7fNotFound is the not-found sentinel of site's port, or of the store the
// provider reads beside it where the port has none.
func pe7fNotFound(site pe7fSite) error {
	if site == pe7fUserLoad {
		return identity.ErrUserNotFound
	}

	return oidcprovider.ErrNotFound
}

// pe7fIDs mints with a working generator, and fails the first identifier
// asked for once armed, then mints again.
type pe7fIDs struct {
	next  markedIDs
	armed *atomic.Bool
	hits  *atomic.Int32
	err   error
}

func (g *pe7fIDs) NewID() (id.ID, error) {
	if g.err != nil && g.armed.Load() && g.hits.Add(1) == 1 {
		return id.ID{}, g.err
	}

	return g.next.NewID()
}

// pe7fOutcome is what one run through a failing port produced, and what the
// same token or code is answered afterwards with every port working.
type pe7fOutcome struct {
	pe7dOutcome

	// answered is whether the entry point answered with a value: a token, a
	// verified token, an introspection, claims, or a 200 at revocation.
	answered bool
	// active is the introspection's "active" member, "" when there is none.
	active string
	// afterOK and afterCode are the token verified, or the code exchanged,
	// again with every port working.
	afterOK   bool
	afterCode string
}

// pe7fRun issues an opaque-app code for openid, exchanges it unless route's
// entry is the exchange, and drives route's entry on ctx while route's site
// fails with portErr. It fails the test when the call hangs, lets a panic
// escape, or never reaches the site.
func pe7fRun(t *testing.T, ctx context.Context, route pe7fRoute, portErr error) pe7fOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed atomic.Bool
		hits  atomic.Int32
	)

	failing := func(at pe7fSite) bool { return armed.Load() && route.site == at }
	answer := func() error {
		hits.Add(1)
		if portErr == pe7fNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
			return nil
		}

		return portErr
	}

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
			if failing(pe7fGrantLoad) {
				return nil, answer()
			}

			return memGrants.Load(context.WithoutCancel(ctx), family)
		}).AnyTimes()

	access := NewMockAccessTokenStore(ctrl)
	access.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.AccessTokenRecord) error {
			return memAccess.Create(context.WithoutCancel(ctx), r)
		}).AnyTimes()
	access.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) (*oidcprovider.AccessTokenRecord, error) {
			if failing(pe7fAccessLoad) {
				return nil, answer()
			}

			return memAccess.Load(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()
	access.EXPECT().Revoke(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) error {
			return memAccess.Revoke(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			if failing(pe7fUserLoad) {
				return nil, answer()
			}

			return activeUser(user)
		}).AnyTimes()

	ids := &pe7fIDs{armed: &armed, hits: &hits}
	opts := []oidcprovider.Option{
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithAccessTokenStore(access),
		oidcprovider.WithIDGenerator(ids),
		oidcprovider.WithLogger(logger),
	}

	if route.site == pe7fClaimSource {
		source := NewMockClaimSource(ctrl)
		source.EXPECT().Claims(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(context.Context, identity.UserID, []string) (map[string]any, error) {
				if failing(pe7fClaimSource) {
					return nil, answer()
				}

				return map[string]any{"department": "ops"}, nil
			}).AnyTimes()
		opts = append(opts, oidcprovider.WithClaimSource(source))
	}

	f := pe7bFixture(t, users, opts...)

	c := issueCodeFor(t, f, opaqueClient, func(v url.Values) {
		asClient(v, opaqueClient, opaqueRedirect)
		v.Set("scope", "openid")
	}, testSignIn(f, "u-1"), "openid")
	exchange := confidentialExchange(opaqueClient, opaqueRedirect, c, nil)
	creds := oidcprovider.ClientCredentials{Authorization: basic(opaqueClient, exchangeSecret)}

	var (
		flow  func(ctx context.Context) (pe7fOutcome, error)
		after func() (bool, error)
	)

	if route.entry == pe7fExchange {
		ids.err = portErr
		flow = func(ctx context.Context) (pe7fOutcome, error) {
			res, err := f.p.Token(ctx, exchange)

			return pe7fOutcome{answered: res != nil}, err
		}
		after = func() (bool, error) {
			res, err := f.p.Token(t.Context(), exchange)

			return res != nil, err
		}
	} else {
		first, err := f.p.Token(t.Context(), exchange)
		require.NoError(t, err, "precondition: the exchange succeeds")
		require.True(t, strings.HasPrefix(first.AccessToken, "at."), "precondition: the access token is opaque")
		raw := first.AccessToken

		after = func() (bool, error) {
			at, err := f.p.VerifyAccessToken(t.Context(), raw)

			return at != nil, err
		}

		switch route.entry {
		case pe7fVerify:
			flow = func(ctx context.Context) (pe7fOutcome, error) {
				at, err := f.p.VerifyAccessToken(ctx, raw)

				return pe7fOutcome{answered: at != nil}, err
			}
		case pe7fIntrospect:
			flow = func(ctx context.Context) (pe7fOutcome, error) {
				res, err := f.p.Introspect(ctx, creds, url.Values{"token": {raw}})
				o := pe7fOutcome{answered: res != nil}
				if res != nil {
					o.active = fmt.Sprint(res["active"])
				}

				return o, err
			}
		case pe7fRevoke:
			flow = func(ctx context.Context) (pe7fOutcome, error) {
				err := f.p.Revoke(ctx, creds, url.Values{"token": {raw}})

				return pe7fOutcome{answered: err == nil}, err
			}
		case pe7fUserInfo:
			at, err := f.p.VerifyAccessToken(t.Context(), raw)
			require.NoError(t, err, "precondition: the token verifies")
			flow = func(ctx context.Context) (pe7fOutcome, error) {
				claims, err := f.p.UserInfo(ctx, at)

				return pe7fOutcome{answered: claims != nil}, err
			}
		default:
			require.FailNow(t, "no flow for "+route.String())
		}
	}

	armed.Store(true)

	out := pe7eBounded(t, func() pe7fOutcome {
		o, err := flow(ctx)
		o.pe7dOutcome = pe7dClassify(err)

		return o
	})

	armed.Store(false)
	require.Positive(t, hits.Load(), "the run reached %s", route)

	afterOK, afterErr := after()
	out.afterOK = afterOK
	out.afterCode = pe7dClassify(afterErr).code

	for _, rec := range pe7bJSONRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// pe7fSameAsPlain asserts got is the plain outage's outcome in every class,
// text and piece of state.
func pe7fSameAsPlain(t *testing.T, route pe7fRoute, plain, got pe7fOutcome) {
	t.Helper()

	require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
	require.Empty(t, plain.code, "precondition: a plain outage is no protocol refusal")
	require.False(t, plain.answered, "precondition: a plain outage answers nothing")
	if route.site == pe7fMintID {
		require.Contains(t, plain.text, "access token's identifier", "precondition: the access token's NewID failed")
	}

	assert.Equal(t, plain.answered, got.answered, "the entry point answers, or not, as for a plain outage")
	assert.Equal(t, plain.active, got.active, "the same introspection")
	assert.Equal(t, plain.dependency, got.dependency, "the same dependency class")
	assert.Equal(t, plain.text, got.text, "the same fixed text")
	assert.Equal(t, plain.notFound, got.notFound, "the same not-found class")
	assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
	assert.Equal(t, plain.code, got.code, "the same protocol code: never invalid_token")
	assert.Equal(t, plain.afterOK, got.afterOK, "the token or code is answered afterwards as after a plain outage")
	assert.Equal(t, plain.afterCode, got.afterCode, "the same answer afterwards")
	assert.NotContains(t, got.text, pe7bSecret)
}

// pe7fRow is one hostile port error, tried at every route.
type pe7fRow struct {
	name   string
	err    func(site pe7fSite) error
	reason string
	// child runs the row in a child process: unsanitized, a cycle through
	// Unwrap() []error can overflow the stack fatally.
	child bool
	// cancel runs the row on a context the caller cancelled.
	cancel bool
}

func pe7fFixed(err error) func(pe7fSite) error { return func(pe7fSite) error { return err } }

// pe7fRows are the hostile errors every route is tried with.
func pe7fRows() []pe7fRow {
	return []pe7fRow{
		{name: "a cycle through Unwrap() error", err: pe7fFixed(&pe7bCycleOne{}), reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: pe7fFixed(&pe7bCycleMany{}), reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: pe7fFixed(pe7bPanicUnwrap{}), reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: pe7fFixed(pe7bPanicNilUnwrap{}), reason: "panic"},
		{name: "a join that fans out", err: pe7fFixed(pe7bFanOut(25, errors.New(pe7bSecret))), reason: "budget"},
		{
			name:   "a join that fans out over the not-found sentinel",
			err:    func(site pe7fSite) error { return pe7bFanOut(25, pe7fNotFound(site)) },
			reason: "budget",
		},
		{
			name:   "a cycle around the not-found sentinel",
			err:    func(site pe7fSite) error { return &pe7bCycleAround{sentinel: pe7fNotFound(site)} },
			reason: "budget", child: true,
		},
		{
			name: "a join that fans out over context.Canceled on a context the caller cancelled",
			err:  pe7fFixed(pe7bFanOut(25, context.Canceled)), reason: "budget", cancel: true,
		},
		{
			name: "a cycle around context.Canceled on a context the caller cancelled",
			err:  pe7fFixed(&pe7bCycleAround{sentinel: context.Canceled}), reason: "budget", child: true, cancel: true,
		},
		{name: "a cycle on a context the caller cancelled", err: pe7fFixed(&pe7bCycleOne{}), reason: "budget", cancel: true},
	}
}

// pe7fTable runs every hostile row, a typed-nil root and a plain outage at
// each route, and a store answering no record and no error at each route
// whose site is a load, against a plain outage of the same port.
func pe7fTable(t *testing.T, routes []pe7fRoute) {
	t.Helper()

	only := os.Getenv(pe7fRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name  string
		route pe7fRoute
		err   error
		child bool
		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context
		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, route pe7fRoute, plain, got pe7fOutcome)
	}

	asOutage := func(reason string) func(*testing.T, pe7fRoute, pe7fOutcome, pe7fOutcome) {
		return func(t *testing.T, route pe7fRoute, plain, got pe7fOutcome) {
			t.Helper()

			pe7fSameAsPlain(t, route, plain, got)
			assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")
			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
		}
	}

	walked := func(t *testing.T, route pe7fRoute, plain, got pe7fOutcome) {
		t.Helper()

		pe7fSameAsPlain(t, route, plain, got)
		assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	for _, route := range routes {
		prefix := route.String() + ": "

		for _, row := range pe7fRows() {
			tc := testCase{
				name: prefix + row.name, route: route, err: row.err(route.site), child: row.child, assert: asOutage(row.reason),
			}
			if row.cancel {
				tc.ctx = pe7eCancelled
			}

			cases = append(cases, tc)
		}

		cases = append(cases,
			testCase{
				name:  prefix + "a typed-nil root walks to the end and is answered as an outage",
				route: route, err: (*pe7bTypedNil)(nil), assert: walked,
			},
			testCase{name: prefix + "a plain outage, against itself", route: route, err: pe7bErrDown, assert: walked},
		)

		switch route.site {
		case pe7fGrantLoad, pe7fAccessLoad, pe7fUserLoad:
			cases = append(cases, testCase{
				name:  prefix + "a port answering no record and no error is answered as an outage",
				route: route, err: pe7fNoRecord, assert: walked,
			})
		}
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7fInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7fRun(t, ctx, tc.route, pe7bErrDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7fRun(t, ctx, tc.route, tc.err)
			tc.assert(t, tc.route, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7fRanMarker + tc.name + "\n")
			}
		})
	}
}

// TestPortErrors_AccessTokenUse pins that minting an opaque access token's
// identifier, and reading an access token's record and its grant, through
// verification, introspection and revocation, failing with an error whose
// chain cannot be walked, or a load answering no record and no error, are
// answered exactly as a plain outage of that port: ErrDependency
// (server_error), never invalid_token, an inactive token or a 200 that revoked
// nothing, with the code unspent and the token as it was. The sanitizer writes
// one record, to the provider's logger, and none to slog.Default().
func TestPortErrors_AccessTokenUse(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	pe7fTable(t, []pe7fRoute{
		{site: pe7fMintID, entry: pe7fExchange},
		{site: pe7fGrantLoad, entry: pe7fVerify},
		{site: pe7fGrantLoad, entry: pe7fIntrospect},
		{site: pe7fAccessLoad, entry: pe7fVerify},
		{site: pe7fAccessLoad, entry: pe7fIntrospect},
		{site: pe7fAccessLoad, entry: pe7fRevoke},
	})
}

// TestPortErrors_UserInfo pins that UserInfo's read of the token's grant, of
// its user and of a consumer's claim source, failing with an error whose
// chain cannot be walked, or a load answering no record and no error, are
// answered exactly as a plain outage of that port: ErrDependency, never
// invalid_token. The sanitizer writes one record, to the provider's logger,
// and none to slog.Default().
func TestPortErrors_UserInfo(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	pe7fTable(t, []pe7fRoute{
		{site: pe7fGrantLoad, entry: pe7fUserInfo},
		{site: pe7fUserLoad, entry: pe7fUserInfo},
		{site: pe7fClaimSource, entry: pe7fUserInfo},
	})
}

// pe7fInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7fInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7fRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7fRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
