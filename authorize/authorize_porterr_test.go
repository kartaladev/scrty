package authorize_test

// TestPortErrors_Authorize replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
)

// azPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const azPortErrRowEnv = "SCRTY_AUTHORIZE_PORTERR_ROW"

// azPortErrRanMarker is the line a child prints once its row ran and passed;
// the parent requires one whole line of the child's output to equal it.
func azPortErrRanMarker(row string) string { return "SCRTY-AUTHORIZE-PORTERR-ROW-RAN:" + row }

// errAZPortDown is the plain outage every parity run fails with.
var errAZPortDown = errors.New("port: connection refused")

// azCycleOne is an error whose Unwrap returns itself. claims, when set, is a
// sentinel its own Is method reports a match for, as a hostile error claiming
// to be a declination or a not-found would.
type azCycleOne struct{ claims error }

func (*azCycleOne) Error() string   { return "authorize: hostile text" }
func (c *azCycleOne) Unwrap() error { return c }

func (c *azCycleOne) Is(target error) bool {
	return c.claims != nil && target == c.claims //nolint:errorlint // identity of a sentinel
}

// azCycleMany is an error whose Unwrap() []error lists claims, when set, and
// then itself. Without a claim it overflows a stdlib walk's stack; with one,
// stdlib errors.Is finds the claim first and never sees the cycle.
type azCycleMany struct{ claims error }

func (*azCycleMany) Error() string { return "authorize: hostile text" }

func (c *azCycleMany) Unwrap() []error {
	if c.claims != nil {
		return []error{c.claims, c}
	}

	return []error{c}
}

// azUnwrapPanics is an error whose Unwrap panics with value.
type azUnwrapPanics struct{ value any }

func (azUnwrapPanics) Error() string   { return "authorize: hostile text" }
func (p azUnwrapPanics) Unwrap() error { panic(p.value) }

// azTypedNil is returned as a nil pointer inside a non-nil error. Its methods
// are nil-safe, so only a walk that calls them on the nil value could fail.
type azTypedNil struct{}

func (*azTypedNil) Error() string { return "authorize: typed nil" }

// azFanOut joins node with itself depth times: no cycle, but a stdlib walk
// visits 2^depth leaves, each one leaf.
func azFanOut(leaf error, depth int) error {
	node := leaf
	for range depth {
		node = errors.Join(node, node)
	}

	return node
}

// azSink collects the records written to a logger.
type azSink struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (*azSink) Enabled(context.Context, slog.Level) bool { return true }

func (h *azSink) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.recs = append(h.recs, r.Clone())

	return nil
}

func (h *azSink) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *azSink) WithGroup(string) slog.Handler      { return h }

func (h *azSink) records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]slog.Record(nil), h.recs...)
}

// azOutcome is the decision one call through a failing port produced. Every
// classification is made inside the bound, so a hostile error that reached it
// unsanitized hangs or panics there and fails the row.
type azOutcome struct {
	allowed      bool
	same         bool // the error returned is the port's own value
	next         int  // how often the member after the failing one ran
	denied       bool
	unsupported  bool
	authRequired bool
	notFound     bool
	unwalkable   bool
}

func azClassify(err, sent error, next int) azOutcome {
	return azOutcome{
		allowed:      err == nil,
		same:         err != nil && err == sent, //nolint:errorlint // identity: returned unchanged
		next:         next,
		denied:       errors.Is(err, authorize.ErrAccessDenied),
		unsupported:  errors.Is(err, authorize.ErrUnsupportedAttributes),
		authRequired: errors.Is(err, authorize.ErrAuthenticationRequired),
		notFound:     errors.Is(err, identity.ErrPrivilegesNotFound),
		unwalkable:   errors.Is(err, porterr.ErrUnwalkable),
	}
}

// azFlow runs one flow with its consumer port failing with err, and returns
// the decision.
type azFlow func(ctx context.Context, t *testing.T, err error) azOutcome

// azPrincipal is the subject every flow runs for.
func azPrincipal(ctx context.Context) context.Context { return withRole(ctx, "clerk") }

var azPrivilege = authorize.PrivilegeAttributes{
	Group: "billing", Resource: "invoice", Required: []string{"read"},
}

// azFirstOf: the first authorizer fails with err, the second allows. A
// failure that is not a declination must stop the manager there.
func azFirstOf(ctx context.Context, t *testing.T, err error) azOutcome {
	ctrl := gomock.NewController(t)

	var next atomic.Int32

	failing := NewMockAuthorizer(ctrl)
	failing.EXPECT().Authorize(gomock.Any(), gomock.Any()).AnyTimes().Return(err)

	allowing := NewMockAuthorizer(ctrl)
	allowing.EXPECT().Authorize(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, authorize.Attributes) error {
			next.Add(1)

			return nil
		})

	m, merr := authorize.NewFirstOf(failing, allowing)
	if merr != nil {
		panic(merr)
	}

	got := m.Authorize(azPrincipal(ctx), azPrivilege)

	return azClassify(got, err, int(next.Load()))
}

// azPrivilegeLoad: the role loader fails with err, while handing back a grant
// of the very privilege asked for, so taking its answer would allow.
func azPrivilegeLoad(ctx context.Context, t *testing.T, err error) azOutcome {
	roles := NewMockRoleLoader(gomock.NewController(t))
	roles.EXPECT().LoadPrivileges(gomock.Any(), "clerk").AnyTimes().
		Return(grantOn("billing", "invoice", map[string]bool{"read": true}), err)

	a, aerr := authorize.NewPrivilegeAuthorizer(roles)
	if aerr != nil {
		panic(aerr)
	}

	return azClassify(a.Authorize(azPrincipal(ctx), azPrivilege), err, 0)
}

// azOwnership builds ownership attributes whose resolver or check fails with
// err. A failing check also answers "owner", so taking it would allow.
func azOwnership(resolveFails bool) azFlow {
	return func(ctx context.Context, _ *testing.T, err error) azOutcome {
		attrs := authorize.OwnershipAttributes{
			Group:    "billing",
			Resource: "invoice",
			ResolveID: func(context.Context) (string, error) {
				if resolveFails {
					return "inv-1", err
				}

				return "inv-1", nil
			},
			OwnedBy: func(context.Context, *identity.Principal, string) (bool, error) {
				if resolveFails {
					return false, nil
				}

				return true, err
			},
		}

		got := authorize.NewOwnershipAuthorizer().Authorize(azPrincipal(ctx), attrs)

		return azClassify(got, err, 0)
	}
}

// azAnyOf: a consumer's requirement fails with err; the member after it asks
// the caller to authenticate. A failure that is not a demand to authenticate
// makes the answer a denial.
func azAnyOf(ctx context.Context, _ *testing.T, err error) azOutcome {
	var next atomic.Int32

	req := authorize.AnyOf(
		func(context.Context) error { return err },
		func(context.Context) error {
			next.Add(1)

			return fmt.Errorf("%w: log in first", authorize.ErrAuthenticationRequired)
		},
	)

	return azClassify(req(azPrincipal(ctx)), err, int(next.Load()))
}

// azBounded runs flow inside a bound and fails the test when it hangs or lets
// a panic escape, panic(nil) included.
func azBounded(ctx context.Context, t *testing.T, flow azFlow, err error) azOutcome {
	t.Helper()

	type result struct {
		out      azOutcome
		returned bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		var r result

		defer func() {
			if !r.returned {
				r.value = recover()
			}

			done <- r
		}()

		r.out = flow(ctx, t, err)
		r.returned = true
	}()

	select {
	case r := <-done:
		require.True(t, r.returned, "a hostile port error escaped as a panic: %v", r.value)

		return r.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow")

		return azOutcome{}
	}
}

// TestPortErrors_Authorize pins that a hostile error from a consumer's port —
// an authorizer under FirstOf, the role loader, the ownership resolver and
// check, a requirement under AnyOf — takes exactly the branch a plain outage
// of that port takes: never an allow, never a skip to the next authorizer,
// never a not-found or a demand to authenticate it merely claims, and one
// abort record on slog.Default().
func TestPortErrors_Authorize(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(azPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	prev := slog.Default()
	sink := &azSink{}
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type flowCase struct {
		name   string
		flow   azFlow
		claims error // the sentinel whose match would change this site's branch
		plain  func(t *testing.T, o azOutcome)
		// ownAnswer is set where the flow answers with an error of its own
		// that never carries the port's, so no fault shows through it.
		ownAnswer bool
	}

	flows := []flowCase{
		{
			name: "FirstOf authorizer", flow: azFirstOf, claims: authorize.ErrUnsupportedAttributes,
			plain: func(t *testing.T, o azOutcome) {
				assert.False(t, o.allowed)
				assert.True(t, o.same, "a walkable authorizer error comes back as the same value")
				assert.Zero(t, o.next, "an outage stops the manager")
			},
		},
		{
			name: "role loader", flow: azPrivilegeLoad, claims: identity.ErrPrivilegesNotFound,
			plain: func(t *testing.T, o azOutcome) {
				assert.False(t, o.allowed)
				assert.False(t, o.denied, "an outage is not a denial")
				assert.False(t, o.notFound)
			},
		},
		{
			name: "ownership resolver", flow: azOwnership(true), claims: authorize.ErrUnsupportedAttributes,
			plain: func(t *testing.T, o azOutcome) {
				assert.False(t, o.allowed)
				assert.False(t, o.denied)
				assert.False(t, o.unsupported)
			},
		},
		{
			name: "ownership check", flow: azOwnership(false), claims: authorize.ErrUnsupportedAttributes,
			plain: func(t *testing.T, o azOutcome) {
				assert.False(t, o.allowed, "a failing check that also says owner never allows")
				assert.False(t, o.denied)
				assert.False(t, o.unsupported)
			},
		},
		{
			name: "AnyOf requirement", flow: azAnyOf, claims: authorize.ErrAuthenticationRequired, ownAnswer: true,
			plain: func(t *testing.T, o azOutcome) {
				assert.False(t, o.allowed)
				assert.True(t, o.denied, "an outage in one member makes the answer a denial")
				assert.False(t, o.authRequired)
				assert.Equal(t, 1, o.next)
			},
		},
	}

	type testCase struct {
		name   string
		err    func(claims error) error
		ctx    func(context.Context) context.Context
		reason string // "" when the walk completes and nothing is recorded
		child  bool
	}

	cases := []testCase{
		{name: "self-cycle through Unwrap() error", err: func(error) error { return &azCycleOne{} }, reason: "budget"},
		{
			name: "self-cycle claiming the site's sentinel through Is",
			err:  func(c error) error { return &azCycleOne{claims: c} }, reason: "budget",
		},
		{
			name: "Unwrap() []error cycle listing the site's sentinel first", child: true,
			err: func(c error) error { return &azCycleMany{claims: c} }, reason: "budget",
		},
		{
			name: "fan-out with no cycle",
			err:  func(error) error { return azFanOut(errAZPortDown, 26) }, reason: "budget",
		},
		{
			name: "fan-out whose leaves are the site's sentinel",
			err:  func(c error) error { return azFanOut(c, 26) }, reason: "budget",
		},
		{
			name: "panicking Unwrap",
			err:  func(error) error { return azUnwrapPanics{value: "boom"} }, reason: "panic",
		},
		{
			name: "Unwrap panicking with nil",
			err:  func(error) error { return azUnwrapPanics{value: nil} }, reason: "panic",
		},
		{
			name: "self-cycle claiming the site's sentinel on a cancelled context",
			err:  func(c error) error { return &azCycleOne{claims: c} }, ctx: cancelled, reason: "budget",
		},
		{
			name: "a typed-nil root walks to the end and is answered as a plain error",
			err:  func(error) error { return (*azTypedNil)(nil) },
		},
		{
			name: "self-cycle through Unwrap() []error", child: true,
			err: func(error) error { return &azCycleMany{} }, reason: "budget",
		},
	}

	for _, fc := range flows {
		for _, tc := range cases {
			row := fc.name + "/" + tc.name
			if childRow != "" && (!tc.child || row != childRow) {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if tc.child && childRow == "" {
					azRunChild(t, row)

					return
				}

				ctx := t.Context()

				before := len(sink.records())
				plain := azBounded(ctx, t, fc.flow, errAZPortDown)
				require.Len(t, sink.records(), before, "a plain outage writes no record")
				fc.plain(t, plain)

				if tc.ctx != nil {
					ctx = tc.ctx(ctx)
				}

				before = len(sink.records())
				got := azBounded(ctx, t, fc.flow, tc.err(fc.claims))
				recs := sink.records()[before:]

				want := plain
				want.same = false
				want.unwalkable = tc.reason != "" && !fc.ownAnswer

				if tc.reason == "" {
					// The typed nil passes the sanitizer unchanged: the same
					// value comes back wherever the plain error does.
					want.same = plain.same
				}

				assert.Equal(t, want, got, "the hostile error takes the plain outage's branch")

				if tc.reason == "" {
					assert.Empty(t, recs, "a walk that completes writes nothing")

					return
				}

				require.Len(t, recs, 1, "one abort record")
				assert.Equal(t, slog.LevelError, recs[0].Level)
				assert.Equal(t, porterr.MsgClassificationAborted, recs[0].Message)

				var reason string

				recs[0].Attrs(func(a slog.Attr) bool {
					if a.Key == "reason" {
						reason = a.Value.String()
					}

					assert.NotContains(t, a.Value.String(), "hostile text")

					return true
				})
				assert.Equal(t, tc.reason, reason)

				if childRow != "" && !t.Failed() {
					fmt.Println(azPortErrRanMarker(row))
				}
			})
		}
	}
}

// azRunChild re-runs this test binary for one row and requires it to exit 0
// within a minute, having printed the row's marker as a whole line.
func azRunChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPortErrors_Authorize$", "-test.count=1")
	cmd.Env = append(os.Environ(), azPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	want := azPortErrRanMarker(row)
	ran := false

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			ran = true
		}
	}

	require.True(t, ran, "the child never ran row %q (no line equals %q); output:\n%s", row, want, out)
}

// TestAnyOf_RefusalTextCarriesNoMemberText pins that a member's own denial text
// does not reach the text of the refusal AnyOf returns, while the denial stays
// reachable beneath it.
func TestAnyOf_RefusalTextCarriesNoMemberText(t *testing.T) {
	t.Parallel()

	const secret = "member-denial-secret-0123"

	req := authorize.AnyOf(func(context.Context) error {
		return fmt.Errorf("%w: %s", authorize.ErrAccessDenied, secret)
	})

	err := req(azPrincipal(t.Context()))

	require.ErrorIs(t, err, authorize.ErrAccessDenied)
	assert.NotContains(t, err.Error(), secret)
}
