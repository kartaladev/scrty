package recovery_test

// TestPortErrors_MFAWayBack replaces slog.Default() for its duration, so it
// does not run in parallel, and it restores the logger it found.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/recovery"
)

// wbPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const wbPortErrRowEnv = "SCRTY_RECOVERY_MFAWAYBACK_PORTERR_ROW"

// wbPortErrRanMarker prefixes the line a child prints, followed by the row's
// name, after the row ran and passed.
const wbPortErrRanMarker = "SCRTY_RECOVERY_MFAWAYBACK_PORTERR_RAN: "

// errWBPortDown is the plain outage every parity run fails with.
var errWBPortDown = errors.New("port: connection refused")

// wbSite names the port call a row fails.
type wbSite string

const (
	wbEnrolled wbSite = "an MFA method's Enrolled"
	wbRemoval  wbSite = "an MFA method's RemoveEnrolment"
	wbLinks    wbSite = "the linked-login lookup"
	wbAdmits   wbSite = "the linked-login admission lookup"
	wbUser     wbSite = "the user loader"
	wbUsable   wbSite = "a kind's Usable"
	wbHeld     wbSite = "a kind's Held, read for a kind with no Usable"
)

// wbOutcome is what one call through a failing port produced. Every error
// classification is made inside the bound.
type wbOutcome struct {
	text string

	failed     bool
	unwalkable bool
	dependency bool

	// yes is the way-back answer, and listed how many authenticators a
	// listing returned.
	yes    bool
	listed int

	// records are the records other than abort records, raw all of the
	// default logger's output, and aborts the sanitizer's records. These
	// sites hold no logger, so every abort record is expected on
	// slog.Default().
	records []cmpRecord
	raw     string
	aborts  []map[string]any
}

func (o *wbOutcome) wbClassify(err error) {
	if err == nil {
		return
	}

	o.failed = true
	o.text = err.Error()
	o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
	o.dependency = errors.Is(err, recovery.ErrDependency)
}

func (o *wbOutcome) wbSplit(t *testing.T, def string) {
	t.Helper()

	o.raw = def

	for _, rec := range limJSONRecords(t, def) {
		if rec["msg"] == porterr.MsgClassificationAborted {
			o.aborts = append(o.aborts, rec)

			continue
		}

		level, okLevel := rec["level"].(string)
		msg, okMsg := rec["msg"].(string)
		require.True(t, okLevel && okMsg, "a malformed log record: %v", rec)

		reason, _ := rec["reason"].(string)
		o.records = append(o.records, cmpRecord{level: level, msg: msg, reason: reason})
	}
}

// wbBounded runs call and fails the test when it hangs or lets a panic escape.
func wbBounded(t *testing.T, call func() wbOutcome) wbOutcome {
	t.Helper()

	type result struct {
		out      wbOutcome
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
	case res := <-done:
		require.False(t, res.panicked, "a hostile port error escaped the flow as a panic: %v", res.value)

		return res.out
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow, or the classification of its error")
	}

	return wbOutcome{}
}

// wbCheck builds a way-back check over deps and an empty saved-code set.
func wbCheck(t *testing.T, deps recovery.WayBackDeps) *recovery.WayBackCheck {
	t.Helper()

	deps.Codes = newCodes(t)

	c, err := recovery.NewWayBackCheck(deps)
	require.NoError(t, err)

	return c
}

// runWBSite runs the flow that reaches the site's call, on ctx, against a port
// that fails that call with portErr.
func runWBSite(t *testing.T, ctx context.Context, site wbSite, portErr error) wbOutcome {
	t.Helper()

	def := limDefaultRecords(t)
	ctrl := gomock.NewController(t)

	var out wbOutcome

	switch site {
	case wbEnrolled, wbRemoval:
		set, methods := removableMethods(ctrl)

		if site == wbEnrolled {
			set.methods["totp"].EXPECT().Enrolled(gomock.Any(), anaID).Return(false, portErr).Times(1)
			// The second method has no Enrolled expectation: a lookup after
			// the first failed would fail the mock.
		} else {
			set.removers["totp"].EXPECT().RemoveEnrolment(gomock.Any(), anaID).Return(portErr).Times(1)
			// The second remover has none either: nothing is removed after a
			// failed removal.
		}

		kind, err := recovery.MFAEnrolments(methods...)
		require.NoError(t, err)

		out = wbBounded(t, func() wbOutcome {
			o := wbOutcome{}

			if site == wbEnrolled {
				refs, err := kind.Held(ctx, anaID)
				o.listed = len(refs)
				o.wbClassify(err)

				return o
			}

			o.wbClassify(kind.Remove(ctx, anaID, []recovery.AuthenticatorRef{
				{Kind: recovery.MFAKind, ID: "totp"}, {Kind: recovery.MFAKind, ID: "email-code"},
			}))

			return o
		})
	case wbLinks, wbAdmits:
		deps := recovery.WayBackDeps{
			Users: NewMockUserLoader(ctrl),
			LinkedLogins: func(context.Context, identity.UserID) ([]factor.Kind, error) {
				return []factor.Kind{factor.OIDC, factor.OIDC}, nil
			},
		}

		if site == wbLinks {
			deps.LinkedLogins = func(context.Context, identity.UserID) ([]factor.Kind, error) { return nil, portErr }
		} else {
			// A second kind is not asked after the first failed.
			asked := 0
			deps.Admits = func(context.Context, identity.UserID, factor.Kind) (bool, error) {
				asked++
				if asked != 1 {
					t.Errorf("an admission lookup after the first failed")
				}

				return false, portErr
			}
		}

		c := wbCheck(t, deps)

		out = wbBounded(t, func() wbOutcome {
			ok, err := c.HasWayBack(ctx, anaID)
			o := wbOutcome{yes: ok}
			o.wbClassify(err)

			return o
		})
	case wbUser, wbUsable, wbHeld:
		users := NewMockUserLoader(ctrl)

		var kind recovery.AuthenticatorKind

		// A kind after the failing one. It has no Usable or Held expectation,
		// so asking it after the first failed would fail the mock.
		next := namedKind(ctrl, "after-the-failure")

		switch site {
		case wbUser:
			users.EXPECT().LoadByUserID(gomock.Any(), anaID).Return(nil, portErr).Times(1)
		case wbUsable:
			users.EXPECT().LoadByUserID(gomock.Any(), anaID).Return(&identity.Details{ID: anaID, Active: true}, nil).Times(1)

			u := usableKind{MockAuthenticatorKind: namedKind(ctrl, "passkey"), MockUsableLister: NewMockUsableLister(ctrl)}
			u.MockUsableLister.EXPECT().Usable(gomock.Any(), anaID).Return(nil, portErr).Times(1)
			kind = u
		case wbHeld:
			users.EXPECT().LoadByUserID(gomock.Any(), anaID).Return(&identity.Details{ID: anaID, Active: true}, nil).Times(1)

			k := namedKind(ctrl, "passkey")
			k.EXPECT().Held(gomock.Any(), anaID).Return(nil, portErr).Times(1)
			kind = k
		}

		deps := recovery.WayBackDeps{Users: users, IssuedCodes: true}
		if kind != nil {
			deps.Kinds = []recovery.AuthenticatorKind{kind, next}
		}

		c := wbCheck(t, deps)

		out = wbBounded(t, func() wbOutcome {
			ok, err := c.HasWayBack(ctx, anaID)
			o := wbOutcome{yes: ok}
			o.wbClassify(err)

			return o
		})
	}

	out.wbSplit(t, def.String())

	return out
}

// TestPortErrors_MFAWayBack pins that each of these port calls failing with an
// error whose chain cannot be walked is answered exactly as a plain outage of
// that port is: an error under the flow's fixed text, never a yes, never a no,
// and no further port called after the failed one. The sanitizer writes one
// record, to slog.Default(), since these sites hold no logger, and none
// elsewhere. A context the caller cancelled, with a cycle claiming
// context.Canceled, is never taken for a hang-up. An Is that panics only for
// the site's own sentinel is accepted (design decision 11): it passes the
// sanitizer.
func TestPortErrors_MFAWayBack(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(wbPortErrRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name string
		site wbSite
		err  error

		// ctx modifies the context both runs of the row use. nil means the
		// test's own.
		ctx func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it may
		// overflow the stack fatally.
		child bool

		assert func(t *testing.T, plain, got wbOutcome)
	}

	sameAsPlain := func(t *testing.T, plain, got wbOutcome) {
		t.Helper()

		assert.Equal(t, plain.failed, got.failed, "an error returned alike")
		assert.Equal(t, plain.dependency, got.dependency, "ErrDependency")
		assert.Equal(t, plain.yes, got.yes, "the way-back answer alike")
		assert.Equal(t, plain.listed, got.listed, "the listing alike")
		assert.Equal(t, plain.records, got.records, "the same records, levels and reasons")
	}

	asOutage := func(reason string) func(t *testing.T, plain, got wbOutcome) {
		return func(t *testing.T, plain, got wbOutcome) {
			t.Helper()

			sameAsPlain(t, plain, got)

			require.True(t, plain.failed, "precondition: a plain outage fails the call")
			assert.False(t, got.yes, "a failed lookup is never a yes")
			assert.Zero(t, got.listed, "a failed lookup lists nothing")
			assert.True(t, got.unwalkable, "the answer carries the fault standing for the error")
			assert.NotContains(t, got.text, limPortErrSecret, "the returned error quotes the port's")
			assert.NotContains(t, got.raw, limPortErrSecret, "a record quotes the port's error")

			require.Len(t, got.aborts, 1, "one abort record, on slog.Default()")
			assert.Equal(t, "ERROR", got.aborts[0]["level"])
			assert.Equal(t, reason, got.aborts[0]["reason"])
		}
	}

	// walked is a chain the sanitizer reads to its end: answered as a plain
	// error is, with no abort record.
	walked := func(t *testing.T, plain, got wbOutcome) {
		t.Helper()

		sameAsPlain(t, plain, got)
		assert.False(t, got.unwalkable, "a walkable error replaced by a fault")
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	sites := []wbSite{wbEnrolled, wbRemoval, wbLinks, wbAdmits, wbUser, wbUsable, wbHeld}

	var cases []testCase

	for _, site := range sites {
		prefix := string(site) + ": "

		cases = append(cases,
			testCase{name: prefix + "a cycle through Unwrap() error", site: site, err: &limCycleOne{},
				assert: asOutage("budget")},
			testCase{name: prefix + "a cycle through Unwrap() []error", site: site, err: &limCycleMany{}, child: true,
				assert: asOutage("budget")},
			testCase{name: prefix + "a link whose Unwrap panics", site: site, err: limPanicUnwrap{},
				assert: asOutage("panic")},
			testCase{name: prefix + "a link whose Unwrap panics with nil", site: site, err: limPanicNilUnwrap{},
				assert: asOutage("panic")},
			testCase{name: prefix + "a join that fans out", site: site, err: limFanOut(25),
				assert: asOutage("budget")},
			testCase{
				name: prefix + "a typed-nil root walks to the end and is answered as a plain error",
				site: site, err: (*limTypedNil)(nil),
				assert: walked,
			},
			testCase{
				name: prefix + "a cycle on a context the caller cancelled is an outage",
				site: site, err: &limCycleOne{}, ctx: cancelled,
				assert: asOutage("budget"),
			},
			testCase{
				name: prefix + "a cycle claiming context.Canceled on a cancelled context is an outage",
				site: site, err: &recClaimCycle{claims: context.Canceled}, ctx: cancelled,
				assert: asOutage("budget"),
			},
			testCase{
				name: prefix + "a cycle wrapping context.Canceled beside itself is an outage",
				site: site, err: &recWrapCycleMany{wraps: context.Canceled}, ctx: cancelled, child: true,
				assert: asOutage("budget"),
			},
		)
	}

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				wbPortErrInChild(t, tc.name)

				return
			}

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runWBSite(t, ctx, tc.site, errWBPortDown)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.True(t, plain.failed, "precondition: a plain outage fails the call")

			got := runWBSite(t, ctx, tc.site, tc.err)
			tc.assert(t, plain, got)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(wbPortErrRanMarker + tc.name + "\n")
			}
		})
	}
}

// wbPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute and prints the
// marker that shows it ran the row: a stack overflow is fatal and only a
// child can watch for one.
func wbPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), wbPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// A child whose row name matched no case skips every row and exits 0: it
	// proves it ran the row only by printing the marker after the row passed.
	// One whole line must equal the marker.
	want := wbPortErrRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
