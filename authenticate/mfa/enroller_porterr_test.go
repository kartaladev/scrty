package mfa_test

// This file covers the enrolment path's port calls: TestPortErrors_Enroller
// the enrolment store's reads in ProveDevice, CompleteEnrolment and
// RedeemEmailCode, the random source that draws the emailed code, and the
// device-proof store's ProveDevice and CompleteEnrolment's Complete. It
// replaces slog.Default() for its duration, so it does not run in parallel,
// and it restores the logger it found.
//
// It reuses the hostile errors, the bounded runner and the child-process
// helper of totp_porterr_test.go, whose go:debug panicnil=1 line applies to
// the whole test binary of this package, this file included.

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/internal/porterr"
)

// penrStore is an enrolment store that also implements DeviceProofStore,
// each half a mock of its own.
type penrStore struct {
	*MockEnrolmentStore
	*MockDeviceProofStore
}

// penrInvalidCycle claims ErrInvalidCode through a chain that cycles back to
// itself: stdlib errors.Is finds the sentinel first and answers "wrong code",
// while anything that walks past it never ends.
type penrInvalidCycle struct{}

func (*penrInvalidCycle) Error() string     { return ptotpSecret }
func (c *penrInvalidCycle) Unwrap() []error { return []error{mfa.ErrInvalidCode, c} }

// penrSite names the enrolment-path port call a row fails, and the entry
// point that reaches it.
type penrSite string

const (
	penrProveGet    penrSite = "ProveDevice's Get"
	penrRandom      penrSite = "the emailed code's random source"
	penrProveProof  penrSite = "the device-proof store's ProveDevice"
	penrCompleteGet penrSite = "CompleteEnrolment's Get"
	penrComplete    penrSite = "CompleteEnrolment's Complete"
	penrRedeemGet   penrSite = "RedeemEmailCode's Get"
)

var penrSites = []penrSite{penrProveGet, penrRandom, penrProveProof, penrCompleteGet, penrComplete, penrRedeemGet}

// penrEager reports whether site's error is wrapped with fmt.Errorf, so a
// walkable error's own text ends the returned text.
func penrEager(site penrSite) bool { return site == penrRandom }

// runPenrSite calls the entry point that reaches site, with that port failing
// with portErr and every earlier call answered as a healthy port does. A call
// the flow must not make has no expectation, so gomock fails the test if the
// flow makes it: a proof whose code could not be drawn records nothing. A
// failing read claims "not found" and a failing write claims success, so the
// error alone must decide. The outcome's provisioned field reports whether
// ProveDevice handed back an emailed code. It is bounded: a hang is reported,
// not waited for.
func runPenrSite(t *testing.T, ctx context.Context, site penrSite, portErr error) ptotpOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)
	store := penrStore{NewMockEnrolmentStore(ctrl), NewMockDeviceProofStore(ctrl)}
	enrol, proofs := store.MockEnrolmentStore, store.MockDeviceProofStore

	logs := &rstSyncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	opts := []mfa.Option{mfa.WithClock(clockwork.NewFakeClockAt(ptotpNow)), mfa.WithLogger(logger)}

	pending := mfa.Enrolment{User: "u-1", Secret: ptotpKey, Generation: fixtureGen, CreatedAt: ptotpNow}
	proven := pending
	proven.DeviceProvenAt = ptotpNow.Add(-time.Minute)
	code := codeAt(t, ptotpKey, ptotpNow, 6, 30*time.Second)

	switch site {
	case penrProveGet, penrCompleteGet:
		enrol.EXPECT().Get(gomock.Any(), gomock.Any()).Return(mfa.Enrolment{}, false, portErr)
	case penrRandom:
		enrol.EXPECT().Get(gomock.Any(), gomock.Any()).Return(pending, true, nil)
		opts = append(opts, mfa.WithRandom(ptotpReader{err: portErr}))
	case penrProveProof:
		enrol.EXPECT().Get(gomock.Any(), gomock.Any()).Return(pending, true, nil)
		proofs.EXPECT().ProveDevice(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any()).Return(true, portErr)
	case penrComplete:
		enrol.EXPECT().Get(gomock.Any(), gomock.Any()).Return(proven, true, nil)
		proofs.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(true, portErr)
	case penrRedeemGet:
		proofs.EXPECT().ChargeEmailCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(1, true, nil)
		enrol.EXPECT().Get(gomock.Any(), gomock.Any()).Return(mfa.Enrolment{}, false, portErr)
	}

	totpm, err := mfa.NewTOTP(store, "scrty-test", opts...)
	require.NoError(t, err)
	require.True(t, totpm.SupportsEnrolmentPath())

	return ptotpBounded(t, logs, func(out *ptotpOutcome) {
		switch site {
		case penrCompleteGet, penrComplete:
			out.err = totpm.CompleteEnrolment(ctx, "u-1", fixtureGen)
		case penrRedeemGet:
			out.err = totpm.RedeemEmailCode(ctx, "u-1", fixtureGen, "123456")
		default:
			var emailed string
			emailed, out.err = totpm.ProveDevice(ctx, "u-1", fixtureGen, code, true, time.Minute)
			out.provisioned = emailed != ""
		}
	})
}

// TestPortErrors_Enroller pins that an enrolment-path port (the enrolment
// store's reads, the emailed code's random source, and the device-proof
// store's ProveDevice and Complete) failing with an error whose chain cannot
// be walked ends exactly as a plain outage does: refused, no emailed code
// handed back, nothing proven or confirmed, the same records, and never
// ErrInvalidCode or ErrEmailCodeInvalid, whatever the hostile chain claims. A
// read that also claims "not found" is the outage, never "not pending". Where
// the method wraps the random source's error with fmt.Errorf, the hostile
// error is replaced before the wrap, so it is in neither the chain nor the
// text. The one abort record goes to the method's own logger, none to
// slog.Default().
func TestPortErrors_Enroller(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	only := os.Getenv(ptotpRowEnv)
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
		site penrSite
		err  error
		ctx  func(ctx context.Context) context.Context

		// child runs the row in a child process: unsanitized, it overflows the
		// stack fatally.
		child bool

		// aborts is the number of abort records expected on the method's logger.
		aborts int
		// reason is the abort record's reason, when aborts is 1.
		reason string
	}

	var cases []testCase

	for _, site := range penrSites {
		p := string(site) + ": "

		cases = append(cases,
			testCase{name: p + "a cycle through Unwrap() error", site: site, err: &ptotpCycleOne{}, aborts: 1, reason: "budget"},
			testCase{name: p + "a cycle through Unwrap() []error", site: site, err: &ptotpCycleMany{}, child: true,
				aborts: 1, reason: "budget"},
			testCase{name: p + "a link whose Unwrap panics", site: site, err: ptotpPanicUnwrap{}, aborts: 1, reason: "panic"},
			testCase{name: p + "a link whose Unwrap panics with nil", site: site, err: ptotpPanicNilUnwrap{},
				aborts: 1, reason: "panic"},
			testCase{name: p + "a join that fans out", site: site, err: ptotpFanOut(25), aborts: 1, reason: "budget"},
			testCase{name: p + "a cycle on a context the caller cancelled", site: site, err: &ptotpCycleOne{},
				ctx: cancelled, aborts: 1, reason: "budget"},
			testCase{name: p + "a typed-nil root walks to the end", site: site, err: (*ptotpTypedNil)(nil)},
			testCase{name: p + "a cycle that leads with ErrInvalidCode", site: site, err: &penrInvalidCycle{},
				child: true, aborts: 1, reason: "budget"},
		)
	}

	fault := new(porterr.Fault).Error()

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				ptotpPortErrInChild(t, tc.name)

				return
			}

			defaults := rstDefaultRecords(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := runPenrSite(t, ctx, tc.site, errPtotpDown)
			require.False(t, plain.hung)
			require.False(t, plain.panicked)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")
			require.ErrorIs(t, plain.err, errPtotpDown, "the plain outage is returned")
			require.NotErrorIs(t, plain.err, mfa.ErrInvalidCode)
			require.NotErrorIs(t, plain.err, mfa.ErrEmailCodeInvalid)
			require.False(t, plain.provisioned)
			require.Empty(t, plain.msgs, "a plain outage records no change")

			got := runPenrSite(t, ctx, tc.site, tc.err)
			require.False(t, got.hung, "the enrolment path hung on a hostile error")
			require.False(t, got.panicked, "the enrolment path panicked on a hostile error")
			require.Error(t, got.err, "refused as the plain outage is")

			// Neither check walks the returned chain, so a row that is not
			// sanitized fails here rather than hanging in a later errors.Is.
			require.Len(t, got.aborts, tc.aborts, "abort records on the method's logger")
			require.Empty(t, rstAborts(t, defaults.Bytes()), "no abort record on slog.Default()")

			if penrEager(tc.site) {
				prefix, ok := strings.CutSuffix(plain.text, errPtotpDown.Error())
				require.True(t, ok, "the plain outage's text ends with the port's: %q", plain.text)

				if tc.aborts == 1 {
					assert.Equal(t, prefix+fault, got.text, "the method's text, then the fixed fault's")
				} else {
					assert.Equal(t, prefix+tc.err.Error(), got.text, "a walkable error is wrapped unchanged")
				}
			} else {
				assert.Equal(t, plain.text, got.text, "the same fixed text as a plain outage")
			}

			if tc.aborts == 1 || !penrEager(tc.site) {
				assert.NotContains(t, got.text, ptotpSecret)
			}

			assert.False(t, got.provisioned, "no emailed code is handed back on a failing port")
			assert.Equal(t, plain.msgs, got.msgs, "the same records, abort aside")

			if tc.aborts == 1 {
				assert.Equal(t, tc.reason, got.aborts[0]["reason"])

				raw, err := json.Marshal(got.aborts[0])
				require.NoError(t, err)
				assert.NotContains(t, string(raw), ptotpSecret)

				require.NotErrorIs(t, got.err, mfa.ErrInvalidCode, "a hostile error is never a wrong code")
				require.ErrorIs(t, got.err, porterr.ErrUnwalkable, "the fixed error, not the hostile one")
				assert.NotErrorIs(t, got.err, mfa.ErrEmailCodeInvalid)
			} else {
				require.ErrorIs(t, got.err, tc.err, "a walkable error is kept")
				assert.NotErrorIs(t, got.err, mfa.ErrInvalidCode)
			}

			if only != "" && !t.Failed() {
				_, _ = os.Stdout.WriteString(ptotpRanMarker + tc.name + "\n")
			}
		})
	}
}
