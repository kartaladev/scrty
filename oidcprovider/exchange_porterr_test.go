package oidcprovider_test

// TestPortErrors_CodeExchange replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found.

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
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
	"github.com/kartaladev/scrty/token/signingkey"
)

// pe7bSecret is the text every hostile error here returns, so a test can
// assert no record or error quotes it.
const pe7bSecret = "pe7b-port-secret-text"

// pe7bRowEnv names the row a child process runs. It is empty in the parent.
const pe7bRowEnv = "SCRTY_OIDCPROVIDER_PE7B_PORTERR_ROW"

// pe7bRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7bRanMarker = "SCRTY_OIDCPROVIDER_PE7B_PORTERR_RAN: "

// errPe7bDown is the plain outage the parity runs fail with.
var errPe7bDown = errors.New("pe7b: connection refused, " + pe7bSecret)

// errPe7bCheckDown is the plain outage the code's check meets first, so that
// the exchange asks the code-token store again, directly.
var errPe7bCheckDown = errors.New("pe7b: the check's read failed")

// pe7bCycleOne contains itself through Unwrap() error.
type pe7bCycleOne struct{}

func (*pe7bCycleOne) Error() string   { return pe7bSecret }
func (c *pe7bCycleOne) Unwrap() error { return c }

// pe7bCycleMany contains itself through Unwrap() []error. Unsanitized, a
// stdlib walk overflows the stack fatally, so its rows run in a child process.
type pe7bCycleMany struct{}

func (*pe7bCycleMany) Error() string     { return pe7bSecret }
func (c *pe7bCycleMany) Unwrap() []error { return []error{c} }

// pe7bCycleAround holds sentinel first and then itself, through
// Unwrap() []error: a stdlib errors.Is asking for sentinel answers yes at
// once, and one asking for anything else overflows the stack. Its rows run in
// a child process.
type pe7bCycleAround struct{ sentinel error }

func (*pe7bCycleAround) Error() string     { return pe7bSecret }
func (c *pe7bCycleAround) Unwrap() []error { return []error{c.sentinel, c} }

// pe7bPanicUnwrap is an error whose Unwrap panics.
type pe7bPanicUnwrap struct{}

func (pe7bPanicUnwrap) Error() string { return pe7bSecret }
func (pe7bPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + pe7bSecret) }

// pe7bPanicNilUnwrap is an error whose Unwrap panics with nil.
type pe7bPanicNilUnwrap struct{}

func (pe7bPanicNilUnwrap) Error() string { return pe7bSecret }
func (pe7bPanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// pe7bTypedNil is returned as a nil pointer inside a non-nil error.
type pe7bTypedNil struct{}

func (*pe7bTypedNil) Error() string { return pe7bSecret }

// pe7bFanOut is errors.Join(n, n) nested depth times over leaf: no cycle, but
// 2^depth paths for an unbounded walk, and a depth-first errors.Is reaches
// leaf on its first path.
func pe7bFanOut(depth int, leaf error) error {
	err := leaf
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// pe7bSite names the port call of the code exchange a row fails.
type pe7bSite string

const (
	pe7bGrantCreate  pe7bSite = "GrantStore.Create"
	pe7bAccessCreate pe7bSite = "AccessTokenStore.Create"
	pe7bCodeLoad     pe7bSite = "CodeStore.Load"
	pe7bGrantLoad    pe7bSite = "GrantStore.Load"
	pe7bUserLoad     pe7bSite = "UserLoader.LoadByUserID"
	pe7bTokenFind    pe7bSite = "the code-token store's direct FindByID"
)

// pe7bNotFound is the not-found sentinel each site's switch branches on, or
// the one its store would answer with where the site has no such branch.
func pe7bNotFound(site pe7bSite) error {
	switch site {
	case pe7bUserLoad:
		return identity.ErrUserNotFound
	case pe7bTokenFind:
		return onetime.ErrTokenNotFound
	default:
		return oidcprovider.ErrNotFound
	}
}

// pe7bOutcome is what one exchange through a failing port produced, and the
// state it left. Every error classification is made inside the bound, so a
// hostile chain that reaches the caller raw fails the run as a hang rather
// than hanging the test.
type pe7bOutcome struct {
	err  error
	text string

	dependency bool
	notFound   bool
	canceled   bool
	unwalkable bool
	// code is the protocol refusal's code, empty when the error is none.
	code string
	// issued is whether the exchange answered with tokens.
	issued bool

	// spent, grantStored and accessTokens are the stores' state afterwards.
	spent        bool
	grantStored  bool
	accessTokens int64

	// aborts are the sanitizer's records on the provider's logger.
	aborts []map[string]any
}

// pe7bRun issues an opaque-app code, then exchanges it on ctx while site's
// port call fails with portErr. It fails the test when the call hangs or lets a
// panic escape.
func pe7bRun(ctx context.Context, t *testing.T, site pe7bSite, portErr error) pe7bOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var (
		armed        atomic.Bool
		finds        atomic.Int64
		accessTokens atomic.Int64
	)

	failing := func(at pe7bSite) bool { return armed.Load() && site == at }

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
			if failing(pe7bGrantCreate) {
				return portErr
			}

			return memGrants.Create(context.WithoutCancel(ctx), g)
		}).AnyTimes()
	grants.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, family id.ID) (*oidcprovider.Grant, error) {
			if failing(pe7bGrantLoad) {
				return nil, portErr
			}

			return memGrants.Load(context.WithoutCancel(ctx), family)
		}).AnyTimes()

	access := NewMockAccessTokenStore(ctrl)
	access.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.AccessTokenRecord) error {
			if failing(pe7bAccessCreate) {
				return portErr
			}
			if err := memAccess.Create(context.WithoutCancel(ctx), r); err != nil {
				return err
			}
			accessTokens.Add(1)

			return nil
		}).AnyTimes()

	codes := NewMockCodeStore(ctrl)
	codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, r *oidcprovider.CodeRecord) error {
			return memCodes.Create(context.WithoutCancel(ctx), r)
		}).AnyTimes()
	codes.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) (*oidcprovider.CodeRecord, error) {
			if failing(pe7bCodeLoad) {
				return nil, portErr
			}

			return memCodes.Load(context.WithoutCancel(ctx), tokenID)
		}).AnyTimes()

	tokens := NewMockCodeTokenStore(ctrl)
	tokens.EXPECT().Insert(gomock.Any(), gomock.Any()).DoAndReturn(memTokens.Insert).AnyTimes()
	tokens.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memTokens.Consume).AnyTimes()
	tokens.EXPECT().FindByID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, tokenID id.ID) (*onetime.Token, error) {
			if failing(pe7bTokenFind) {
				// The check's read fails plainly, and the direct read that
				// follows it is the site.
				switch finds.Add(1) {
				case 1:
					return nil, errPe7bCheckDown
				case 2:
					return nil, portErr
				}
			}

			return memTokens.FindByID(ctx, tokenID)
		}).AnyTimes()

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, user identity.UserID) (*identity.Details, error) {
			if failing(pe7bUserLoad) {
				return nil, portErr
			}

			return activeUser(user)
		}).AnyTimes()

	f := pe7bFixture(t, users,
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithAccessTokenStore(access),
		oidcprovider.WithCodeStore(codes),
		oidcprovider.WithCodeTokenStore(tokens),
		oidcprovider.WithLogger(logger),
	)

	c := issueCodeFor(t, f, opaqueClient, func(v url.Values) { //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
		asClient(v, opaqueClient, opaqueRedirect)
		v.Set("scope", "openid")
	}, testSignIn(f, "u-1"), "openid")
	armed.Store(true)

	type result struct {
		out      pe7bOutcome
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

		res, err := f.p.Token(ctx, confidentialExchange(opaqueClient, opaqueRedirect, c, nil))

		o := pe7bOutcome{err: err, issued: res != nil}
		if err != nil {
			o.text = err.Error()
			// ErrDependency first: a library fault lists its sentinels before
			// its cause, so this check never reaches a raw port error.
			o.dependency = errors.Is(err, oidcprovider.ErrDependency)
			o.notFound = errors.Is(err, pe7bNotFound(site))
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

	var out pe7bOutcome

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile port error escaped as a panic: %v", r.value)
		out = r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the exchange, or its classification")
	}

	tokenID := tokenIDOf(t, c.code)
	stored, err := memTokens.FindByID(t.Context(), tokenID) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, err)
	out.spent = !stored.ConsumedAt.IsZero()

	record, err := memCodes.Load(t.Context(), tokenID) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, err)
	_, err = memGrants.Load(t.Context(), record.GrantFamily) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	if !errors.Is(err, oidcprovider.ErrNotFound) {
		require.NoError(t, err)
		out.grantStored = true
	}
	out.accessTokens = accessTokens.Load()

	for _, rec := range pe7bJSONRecords(t, logs.String()) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			out.aborts = append(out.aborts, rec)
		}
	}

	return out
}

// pe7bFixture is a provider over users and opts, with authzClients and the
// opaque-app client, on a fixed clock, ready for issueCodeFor.
func pe7bFixture(t *testing.T, users identity.UserLoader, opts ...oidcprovider.Option) *parkFixture {
	t.Helper()

	return pe7bFixtureKeys(t, newExchangeKeys(t), users, opts...)
}

// pe7bFixtureKeys is pe7bFixture over a key source the row chose.
func pe7bFixtureKeys(t *testing.T, keys signingkey.KeySource, users identity.UserLoader, opts ...oidcprovider.Option) *parkFixture {
	t.Helper()

	clk := clockwork.NewFakeClockAt(exchangeFixtureStart)
	store, err := oidcprovider.NewMemoryPendingRequestStore()
	require.NoError(t, err)
	consents, err := oidcprovider.NewMemoryConsentStore()
	require.NoError(t, err)

	clients := append(authzClients(), oidcprovider.Client{
		ID: opaqueClient, Type: oidcprovider.Confidential, Secret: []byte(exchangeSecret),
		RedirectURIs: []string{opaqueRedirect}, Scopes: []string{"openid", "profile", "offline_access"},
		OpaqueAccessTokens: true,
		GrantTypes:         []oidcprovider.GrantType{oidcprovider.GrantAuthorizationCode, oidcprovider.GrantRefreshToken},
	})
	registry, err := oidcprovider.NewMemoryRegistry(clients)
	require.NoError(t, err)

	base := []oidcprovider.Option{
		oidcprovider.WithClock(clk),
		oidcprovider.WithPendingRequestStore(store),
		oidcprovider.WithConsentStore(consents),
	}
	p, err := oidcprovider.New(oidcprovider.Deps{
		Issuer:       issuer,
		Registry:     registry,
		Keys:         keys,
		Users:        users,
		LoginURL:     issuer + "/login",
		ConsentURL:   issuer + "/consent",
		LogoutURL:    issuer + "/logout",
		LoggedOutURL: issuer + "/bye",
	}, append(base, opts...)...)
	require.NoError(t, err)

	return &parkFixture{p: p, store: store, consents: consents, registry: registry, clk: clk}
}

// pe7bJSONRecords decodes every JSON record in out.
func pe7bJSONRecords(t *testing.T, out string) []map[string]any {
	t.Helper()

	var records []map[string]any

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}

		rec := map[string]any{}
		require.NoError(t, json.Unmarshal([]byte(line), &rec))
		records = append(records, rec)
	}

	return records
}

// pe7bRow is one hostile port error, tried at every site.
type pe7bRow struct {
	name   string
	err    func(site pe7bSite) error
	reason string
	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally.
	child bool
	// cancel runs the row on a context the caller cancelled.
	cancel bool
}

func pe7bFixed(err error) func(pe7bSite) error { return func(pe7bSite) error { return err } }

// pe7bRows are the hostile errors every site is tried with. A typed-nil root
// is not among them: its walk completes, so it writes no record.
func pe7bRows() []pe7bRow {
	return []pe7bRow{
		{name: "a cycle through Unwrap() error", err: pe7bFixed(&pe7bCycleOne{}), reason: "budget"},
		{name: "a cycle through Unwrap() []error", err: pe7bFixed(&pe7bCycleMany{}), reason: "budget", child: true},
		{name: "a link whose Unwrap panics", err: pe7bFixed(pe7bPanicUnwrap{}), reason: "panic"},
		{name: "a link whose Unwrap panics with nil", err: pe7bFixed(pe7bPanicNilUnwrap{}), reason: "panic"},
		{name: "a join that fans out", err: pe7bFixed(pe7bFanOut(25, errors.New(pe7bSecret))), reason: "budget"},
		{
			name: "a join that fans out over the site's not-found sentinel",
			err:  func(site pe7bSite) error { return pe7bFanOut(25, pe7bNotFound(site)) }, reason: "budget",
		},
		{
			name: "a cycle around the site's not-found sentinel",
			err:  func(site pe7bSite) error { return &pe7bCycleAround{sentinel: pe7bNotFound(site)} }, reason: "budget", child: true,
		},
		{
			name: "a join that fans out over context.Canceled on a context the caller cancelled",
			err:  pe7bFixed(pe7bFanOut(25, context.Canceled)), reason: "budget", cancel: true,
		},
		{
			name: "a cycle around context.Canceled on a context the caller cancelled",
			err:  pe7bFixed(&pe7bCycleAround{sentinel: context.Canceled}), reason: "budget", child: true, cancel: true,
		},
		{
			name: "a cycle on a context the caller cancelled",
			err:  pe7bFixed(&pe7bCycleOne{}), reason: "budget", cancel: true,
		},
	}
}

// TestPortErrors_CodeExchange pins that every store read and write of the
// authorization code exchange, failing with an error whose chain cannot be
// walked, is answered exactly as a plain outage of that port is: the same
// error, ErrDependency (server_error) with the same fixed text, never
// invalid_grant, never tokens, never the site's not-found answer, and the same
// state left behind: the code spent or not, the grant and the access token
// stored or not. The sanitizer writes one record, to the provider's logger,
// and none to slog.Default().
func TestPortErrors_CodeExchange(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(pe7bRowEnv)
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
		site  pe7bSite
		err   error
		child bool

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// assert receives the plain outage's outcome and the row's.
		assert func(t *testing.T, plain, got pe7bOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got pe7bOutcome) {
		t.Helper()

		require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
		require.Empty(t, plain.code, "precondition: a plain outage is no protocol refusal")
		require.False(t, plain.issued, "precondition: a plain outage hands out no token")

		assert.True(t, got.dependency, "answered as ErrDependency")
		assert.False(t, got.issued, "no token handed out")
		assert.Equal(t, plain.text, got.text, "the same fixed text")
		assert.Equal(t, plain.dependency, got.dependency, "the same dependency-failure class")
		assert.Equal(t, plain.notFound, got.notFound, "the same not-found class")
		assert.Equal(t, plain.canceled, got.canceled, "the same hang-up class")
		assert.Equal(t, plain.code, got.code, "the same protocol code")
		assert.Equal(t, plain.spent, got.spent, "the code is spent, or not, as for a plain outage")
		assert.Equal(t, plain.grantStored, got.grantStored, "the grant is stored, or not, as for a plain outage")
		assert.Equal(t, plain.accessTokens, got.accessTokens, "access tokens stored as for a plain outage")
		assert.NotContains(t, got.text, pe7bSecret)
	}

	asOutage := func(reason string) func(t *testing.T, plain, got pe7bOutcome) {
		return func(t *testing.T, plain, got pe7bOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)
			assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")

			require.Len(t, got.aborts, 1, "one abort record, on the provider's logger")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])

			raw, err := json.Marshal(got.aborts[0])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), pe7bSecret, "the record quotes the error")
		}
	}

	walked := func(t *testing.T, plain, got pe7bOutcome) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error is passed on unchanged")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	var cases []testCase

	sites := []pe7bSite{pe7bGrantCreate, pe7bAccessCreate, pe7bCodeLoad, pe7bGrantLoad, pe7bUserLoad, pe7bTokenFind}
	for _, site := range sites {
		prefix := string(site) + ": "

		for _, row := range pe7bRows() {
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
				site: site, err: errPe7bDown, assert: walked,
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7bInChild(t, tc.name)

				return
			}

			defaults := &lockedBuffer{}
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(defaults, &slog.HandlerOptions{Level: slog.LevelDebug})))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := pe7bRun(ctx, t, tc.site, errPe7bDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := pe7bRun(ctx, t, tc.site, tc.err)
			tc.assert(t, plain, got)

			for _, rec := range pe7bJSONRecords(t, defaults.String()) {
				assert.NotEqual(t, porterr.MsgClassificationAborted, rec["msg"], "an abort record went to slog.Default()")
			}

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7bRanMarker + tc.name + "\n")
			}
		})
	}
}

// pe7bInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7bInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7bRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := pe7bRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
