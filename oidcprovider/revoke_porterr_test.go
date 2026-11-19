package oidcprovider_test

// TestPortErrors_ReplayAndRevocation and TestPortErrors_StoreAnswersNothing
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// pe7cRowEnv names the row a child process runs. It is empty in the parent.
const pe7cRowEnv = "SCRTY_OIDCPROVIDER_PE7C_PORTERR_ROW"

// pe7cRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7cRanMarker = "SCRTY_OIDCPROVIDER_PE7C_PORTERR_RAN: "

// pe7cNoRecord is no error a port returns: a site's double given it answers
// a load with neither a record nor an error, a port breaking its contract.
var pe7cNoRecord = errors.New("pe7c: answer no record and no error")

// pe7cSite names the port call a row fails, and through it the flow it runs.
type pe7cSite string

const (
	// The first exchange of a code.
	pe7cExchangeCodeLoad  pe7cSite = "the exchange's CodeStore.Load"
	pe7cExchangeGrantLoad pe7cSite = "the exchange's GrantStore.Load"
	// A valid replay of a code already exchanged.
	pe7cReplayCodeLoad pe7cSite = "the replay's CodeStore.Load"
	pe7cReplayRevoke   pe7cSite = "the replay's GrantStore.Revoke"
	// The revocation endpoint, given the exchange's refresh token.
	pe7cRevokeGrantLoad pe7cSite = "revocation's GrantStore.Load"
	pe7cRevokeGrant     pe7cSite = "revocation's GrantStore.Revoke"
	// The revocation endpoint, given the exchange's opaque access token.
	pe7cRevokeAccess pe7cSite = "revocation's AccessTokenStore.Revoke"
)

// pe7cOutcome is what one run through a failing port produced, and the state
// it left. Every error classification is made inside the bound, so a hostile
// chain that reaches the caller raw fails the run as a hang rather than
// hanging the test.
type pe7cOutcome struct {
	// ok is a nil error: a 200 at the revocation endpoint.
	ok   bool
	text string

	dependency bool
	notFound   bool
	canceled   bool
	unwalkable bool
	// code is the protocol refusal's code, empty when the error is none.
	code string
	// issued is whether a token request answered with tokens.
	issued bool

	// The stores' state afterwards: the code spent, the grant stored and
	// revoked, the exchange's opaque access token revoked, and its refresh
	// token still active at introspection.
	spent         bool
	grantStored   bool
	grantRevoked  bool
	accessRevoked bool
	refreshActive bool

	// aborts are the sanitizer's records on the provider's logger.
	aborts []map[string]any
}

// pe7cRun issues an opaque-app code for openid and offline_access, and runs
// site's flow on ctx while site's port call fails with portErr. Every site but
// the first exchange's runs after a successful exchange. It fails the test
// when the flow hangs or lets a panic escape.
func pe7cRun(t *testing.T, ctx context.Context, site pe7cSite, portErr error) pe7cOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed    atomic.Bool
		accessID atomic.Pointer[id.ID]
	)

	failing := func(at pe7cSite) bool { return armed.Load() && site == at }

	memGrants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	memAccess, err := oidcprovider.NewMemoryAccessTokenStore()
	require.NoError(t, err)
	memCodes, err := oidcprovider.NewMemoryCodeStore()
	require.NoError(t, err)
	memTokens, err := onetime.NewMemoryStore()
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
			if failing(pe7cExchangeGrantLoad) || failing(pe7cRevokeGrantLoad) {
				if portErr == pe7cNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
					return nil, nil
				}

				return nil, portErr
			}

			return memGrants.Load(context.WithoutCancel(ctx), family)
		}).AnyTimes()
	grants.EXPECT().Revoke(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time) (bool, error) {
			if failing(pe7cReplayRevoke) || failing(pe7cRevokeGrant) {
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
			tokenID := r.ID
			accessID.Store(&tokenID)

			return nil
		}).AnyTimes()
	access.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) (*oidcprovider.AccessTokenRecord, error) {
			return memAccess.Load(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()
	access.EXPECT().Revoke(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) error {
			if failing(pe7cRevokeAccess) {
				return portErr
			}

			return memAccess.Revoke(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()

	codes := NewMockCodeStore(ctrl)
	codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.CodeRecord) error {
			return memCodes.Create(context.WithoutCancel(ctx), r)
		}).AnyTimes()
	codes.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) (*oidcprovider.CodeRecord, error) {
			if failing(pe7cExchangeCodeLoad) || failing(pe7cReplayCodeLoad) {
				if portErr == pe7cNoRecord { //nolint:errorlint // identity: errors.Is would walk the hostile error
					return nil, nil
				}

				return nil, portErr
			}

			return memCodes.Load(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()

	tokens := NewMockCodeTokenStore(ctrl)
	tokens.EXPECT().Insert(gomock.Any(), gomock.Any()).DoAndReturn(memTokens.Insert).AnyTimes()
	tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memTokens.Consume).AnyTimes()
	tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(memTokens.FindByID).AnyTimes()

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) { return activeUser(user) }).AnyTimes()

	f := pe7bFixture(t, users,
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithAccessTokenStore(access),
		oidcprovider.WithCodeStore(codes),
		oidcprovider.WithCodeTokenStore(tokens),
		oidcprovider.WithLogger(logger),
	)

	c := issueCodeFor(t, f, opaqueClient, func(v url.Values) {
		asClient(v, opaqueClient, opaqueRedirect)
		v.Set("scope", "openid offline_access")
	}, testSignIn(f, "u-1"), "openid", "offline_access")
	exchange := confidentialExchange(opaqueClient, opaqueRedirect, c, nil)

	var first *oidcprovider.TokenResponse

	var flow func(ctx context.Context) (bool, error)

	switch site {
	case pe7cExchangeCodeLoad, pe7cExchangeGrantLoad:
		flow = func(ctx context.Context) (bool, error) {
			res, err := f.p.Token(ctx, exchange)

			return res != nil, err
		}
	default:
		first, err = f.p.Token(t.Context(), exchange)
		require.NoError(t, err, "precondition: the first exchange succeeds")
		require.NotEmpty(t, first.RefreshToken, "precondition: the grant holds a refresh token")
		require.True(t, strings.HasPrefix(first.AccessToken, "at."), "precondition: the access token is opaque")

		creds := oidcprovider.ClientCredentials{Authorization: basic(opaqueClient, exchangeSecret)}

		switch site {
		case pe7cReplayCodeLoad, pe7cReplayRevoke:
			flow = func(ctx context.Context) (bool, error) {
				res, err := f.p.Token(ctx, exchange)

				return res != nil, err
			}
		case pe7cRevokeGrantLoad, pe7cRevokeGrant:
			flow = func(ctx context.Context) (bool, error) {
				return false, f.p.Revoke(ctx, creds, url.Values{"token": {first.RefreshToken}})
			}
		case pe7cRevokeAccess:
			flow = func(ctx context.Context) (bool, error) {
				return false, f.p.Revoke(ctx, creds, url.Values{"token": {first.AccessToken}})
			}
		default:
			require.FailNow(t, "no flow for site "+string(site))
		}
	}

	armed.Store(true)

	type result struct {
		out      pe7cOutcome
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

		issued, err := flow(ctx)

		o := pe7cOutcome{ok: err == nil, issued: issued}
		if err != nil {
			o.text = err.Error()
			// ErrDependency first: a library fault lists its sentinels before
			// its cause, so this check never reaches a raw port error.
			o.dependency = errors.Is(err, oidcprovider.ErrDependency)
			o.notFound = errors.Is(err, oidcprovider.ErrNotFound)
			o.canceled = errors.Is(err, context.Canceled)
			o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)

			var refusal *oidcprovider.Error
			if errors.As(err, &refusal) {
				o.code = refusal.Code
			}
		}

		returned = true
		done <- result{out: o}
	}()

	var out pe7cOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a port error escaped as a panic: %v", r.value)
		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow, or its classification")
	}

	armed.Store(false)

	tokenID := tokenIDOf(t, c.code)
	stored, err := memTokens.FindByID(t.Context(), tokenID)
	require.NoError(t, err)
	out.spent = !stored.ConsumedAt.IsZero()

	record, err := memCodes.Load(t.Context(), tokenID)
	require.NoError(t, err)
	grant, err := memGrants.Load(t.Context(), record.GrantFamily)
	if !errors.Is(err, oidcprovider.ErrNotFound) {
		require.NoError(t, err)
		out.grantStored = true
		out.grantRevoked = grant.Revoked
	}

	if tokenID := accessID.Load(); tokenID != nil {
		held, err := memAccess.Load(t.Context(), *tokenID)
		require.NoError(t, err)
		out.accessRevoked = held.Revoked
	}

	if first != nil {
		answer, err := f.p.Introspect(t.Context(), oidcprovider.ClientCredentials{Authorization: basic(opaqueClient, exchangeSecret)},
			url.Values{"token": {first.RefreshToken}})
		require.NoError(t, err)
		out.refreshActive, _ = answer["active"].(bool)
	}

	for _, rec := range pe7bJSONRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// pe7cRow is one hostile port error, tried at every site.
type pe7cRow struct {
	name   string
	err    error
	reason string
	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally.
	child bool
	// cancel runs the row on a context the caller cancelled.
	cancel bool
}

// pe7cRows are the hostile errors every site is tried with. ErrNotFound is
// the not-found sentinel of every site here.
func pe7cRows() []pe7cRow {
	return []pe7cRow{
		{name: "a cycle through Unwrap() error", err: &pe7bCycleOne{}, reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: &pe7bCycleMany{}, reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: pe7bPanicUnwrap{}, reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: pe7bPanicNilUnwrap{}, reason: "panic"},
		{name: "a join that fans out", err: pe7bFanOut(25, errors.New(pe7bSecret)), reason: "budget"},
		{
			name: "a join that fans out over ErrNotFound",
			err:  pe7bFanOut(25, oidcprovider.ErrNotFound), reason: "budget",
		},
		{
			name: "a cycle around ErrNotFound",
			err:  &pe7bCycleAround{sentinel: oidcprovider.ErrNotFound}, reason: "budget", child: true,
		},
		{
			name: "a join that fans out over context.Canceled on a context the caller cancelled",
			err:  pe7bFanOut(25, context.Canceled), reason: "budget", cancel: true,
		},
		{
			name: "a cycle around context.Canceled on a context the caller cancelled",
			err:  &pe7bCycleAround{sentinel: context.Canceled}, reason: "budget", child: true, cancel: true,
		},
		{name: "a cycle on a context the caller cancelled", err: &pe7bCycleOne{}, reason: "budget", cancel: true},
	}
}

// pe7cSameAsPlain asserts got is the plain outage's outcome in every class,
// text and piece of state.
func pe7cSameAsPlain(t *testing.T, plain, got pe7cOutcome) {
	t.Helper()

	require.False(t, plain.ok, "precondition: a plain outage is no success")
	require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
	require.Empty(t, plain.code, "precondition: a plain outage is no protocol refusal")
	require.False(t, plain.issued, "precondition: a plain outage hands out no token")

	assert.False(t, got.ok, "never answered success")
	assert.True(t, got.dependency, "answered as ErrDependency")
	assert.False(t, got.issued, "no token handed out")
	assert.Equal(t, plain.text, got.text, "the same fixed text")
	assert.Equal(t, plain.notFound, got.notFound, "the same not-found class")
	assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
	assert.Equal(t, plain.code, got.code, "the same protocol code")
	assert.Equal(t, plain.spent, got.spent, "the code is spent, or not, as for a plain outage")
	assert.Equal(t, plain.grantStored, got.grantStored, "the grant is stored, or not, as for a plain outage")
	assert.Equal(t, plain.grantRevoked, got.grantRevoked, "the grant is revoked, or not, as for a plain outage")
	assert.Equal(t, plain.accessRevoked, got.accessRevoked, "the access token is revoked, or not, as for a plain outage")
	assert.Equal(t, plain.refreshActive, got.refreshActive, "the refresh token is active, or not, as for a plain outage")
	assert.NotContains(t, got.text, pe7bSecret)
}

// pe7cSites are the port calls of the replay and the revocation endpoint.
func pe7cSites() []pe7cSite {
	return []pe7cSite{pe7cReplayCodeLoad, pe7cReplayRevoke, pe7cRevokeGrantLoad, pe7cRevokeGrant, pe7cRevokeAccess}
}

// TestPortErrors_ReplayAndRevocation pins that the code store's read and the
// grant store's revocation of a valid replay, and the grant store's read and
// revocation and the access token store's revocation at the revocation
// endpoint, failing with an error whose chain cannot be walked, are answered
// exactly as a plain outage of that port is: ErrDependency (server_error) with
// the same fixed text, never invalid_grant and never a 200, and the same state
// left: the grant revoked or not, the access token revoked or not, the refresh
// token active or not. A fan-out over ErrNotFound is never read as "no such
// token": it neither refuses a replay without revoking, nor answers a
// revocation 200 with nothing revoked. The sanitizer writes one record, to the
// provider's logger, and none to slog.Default().
func TestPortErrors_ReplayAndRevocation(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7cRowEnv)
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
		site  pe7cSite
		err   error
		child bool

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pe7cOutcome)
	}

	asOutage := func(reason string) func(t *testing.T, plain, got pe7cOutcome) {
		return func(t *testing.T, plain, got pe7cOutcome) {
			t.Helper()

			pe7cSameAsPlain(t, plain, got)
			assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")

			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), pe7bSecret, "the record quotes the error")
		}
	}

	walked := func(t *testing.T, plain, got pe7cOutcome) {
		t.Helper()

		pe7cSameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	for _, site := range pe7cSites() {
		prefix := string(site) + ": "

		for _, row := range pe7cRows() {
			tc := testCase{name: prefix + row.name, site: site, err: row.err, child: row.child, assert: asOutage(row.reason)}
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
				pe7cInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7cRun(t, ctx, tc.site, pe7bErrDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7cRun(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7cRanMarker + tc.name + "\n")
			}
		})
	}
}

// TestPortErrors_StoreAnswersNothing pins that a code or grant store whose
// load answers neither a record nor an error, breaking its contract, is
// answered as that store failing outright: the same dependency failure and
// state as a plain outage, and no panic.
func TestPortErrors_StoreAnswersNothing(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name   string
		site   pe7cSite
		assert func(t *testing.T, plain, got pe7cOutcome)
	}

	asOutage := func(t *testing.T, plain, got pe7cOutcome) {
		t.Helper()

		pe7cSameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "no chain was walked")
		assert.Empty(t, got.aborts, "no abort record")
	}

	cases := []testCase{
		{name: "the exchange's code record", site: pe7cExchangeCodeLoad, assert: asOutage},
		{name: "the exchange's grant", site: pe7cExchangeGrantLoad, assert: asOutage},
		{name: "a replay's code record", site: pe7cReplayCodeLoad, assert: asOutage},
		{name: "revocation's grant", site: pe7cRevokeGrantLoad, assert: asOutage},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defaults := pe7cSwapDefault(t)

			plain := pe7cRun(t, t.Context(), tc.site, pe7bErrDown)
			got := pe7cRun(t, t.Context(), tc.site, pe7cNoRecord)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)
		})
	}
}

// pe7cSwapDefault replaces slog.Default() with a logger writing to the
// returned buffer until the test ends.
func pe7cSwapDefault(t *testing.T) *lockedBuffer {
	t.Helper()

	defaults := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(defaults, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return defaults
}

// pe7cNoDefaultAbort asserts no abort record reached slog.Default().
func pe7cNoDefaultAbort(t *testing.T, defaults *lockedBuffer) {
	t.Helper()

	for _, rec := range pe7bJSONRecords(t, defaults.String()) {
		assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
	}
}

// pe7cInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7cInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7cRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7cRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
