package policy_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/policy"
)

// peHostileText is in every hostile error's text, so a record can be checked
// for not quoting it.
const peHostileText = "policy-port: hostile text"

// peCycleOne contains itself through Unwrap() error.
type peCycleOne struct{}

func (*peCycleOne) Error() string   { return peHostileText }
func (c *peCycleOne) Unwrap() error { return c }

// peCycleMany contains itself through Unwrap() []error.
type peCycleMany struct{}

func (*peCycleMany) Error() string     { return peHostileText }
func (c *peCycleMany) Unwrap() []error { return []error{c} }

// pePanicUnwrap panics when unwrapped.
type pePanicUnwrap struct{}

func (pePanicUnwrap) Error() string { return peHostileText }
func (pePanicUnwrap) Unwrap() error { panic("policy-port: Unwrap panicked") }

// pePanicNilUnwrap panics with nil when unwrapped.
type pePanicNilUnwrap struct{}

func (pePanicNilUnwrap) Error() string { return peHostileText }
func (pePanicNilUnwrap) Unwrap() error { panic(nil) } //nolint:govet // the hostile case under test

// peClaimCycle is a cycle that claims, through Is, every sentinel a site or
// the status mapping behind it branches on.
type peClaimCycle struct{}

func (*peClaimCycle) Error() string   { return peHostileText }
func (c *peClaimCycle) Unwrap() error { return c }
func (*peClaimCycle) Is(target error) bool {
	for _, s := range peClasses {
		if target == s { //nolint:errorlint // identity of a sentinel
			return true
		}
	}

	return false
}

// peTypedNil is an error type whose nil pointer is handed back as a non-nil
// error interface.
type peTypedNil struct{}

func (*peTypedNil) Error() string { return "policy-port: typed nil" }

// peFanOut is errors.Join(e, e) nested depth times: no cycle, but 2^depth
// paths for a stdlib walk.
func peFanOut(depth int) error {
	e := errors.New(peHostileText)
	for range depth {
		e = errors.Join(e, e)
	}

	return e
}

// peClasses are the sentinels a decision's reason is matched against, by the
// library and by the status mapping. A hostile error must match exactly those
// a plain outage matches.
var peClasses = []error{
	policy.ErrDenied,
	policy.ErrMFARequired,
	policy.ErrMFAEnrolmentRequired,
	policy.ErrFederatedAssuranceNotMet,
	policy.ErrSecondFactorSameChannel,
	policy.ErrMFARequirementUnsatisfiable,
	context.Canceled,
	context.DeadlineExceeded,
}

// peResult is what a flow answered, read inside the bound: every errors.Is a
// caller would make, and the status the chain maps the error to.
type peResult struct {
	outcome    string
	text       string
	unwalkable bool
	classes    []bool
	status     int
}

// peSink names the logger a site writes its abort record to.
type peSink int

const (
	// The zero value is the logger the component was given (lg in build), whatever the
	// context carries.
	_ peSink = iota
	// peContext is the logger the request context carries (the chain's,
	// inside a chain), and slog.Default() when it carries none: the site has
	// no logger of its own.
	peContext
)

// peRecords are the abort records a row wrote, by logger, and whether its
// context carried a logger.
type peRecords struct {
	own, ctx, def []slog.Record
	carried       bool
}

// peFlow is one call site, reached through the public API.
type peFlow struct {
	name string
	// build wires the component whose port answers err; lg is the logger the
	// component is given. It runs on the test goroutine.
	build func(t *testing.T, err error, lg *slog.Logger) func(ctx context.Context) (string, error)
	// sink is the logger the abort record goes to.
	sink peSink
	// refusal is the outcome a consumer policy refuses with, for the engine's
	// own refusing flows, and the zero Outcome for every other.
	refusal policy.Outcome
	// aborts is how many abort records a hostile port error writes.
	aborts int
}

const peRowEnv = "SCRTY_POLICY_A1_PORTERR_ROW"

// peRanMarker is the line a child prints on stdout once its row passed.
func peRanMarker(row string) string { return "SCRTY-POLICY-A1-PORTERR-RAN:" + row }

// peAborts counts the abort records in recs.
func peAborts(recs []slog.Record) []slog.Record {
	var out []slog.Record

	for _, r := range recs {
		if r.Message == porterr.MsgClassificationAborted {
			out = append(out, r)
		}
	}

	return out
}

// peRunWithin runs call on its own goroutine and reads its answer there, so a
// hang or a panic in the flow or in any check of its error fails the row
// instead of the binary.
func peRunWithin(t *testing.T, call func() (string, error)) peResult {
	t.Helper()

	type out struct {
		r        peResult
		panicked bool
		value    any
	}

	done := make(chan out, 1)

	go func() {
		var o out

		defer func() {
			if v := recover(); v != nil {
				o.panicked, o.value = true, v
			}

			done <- o
		}()

		outcome, err := call()

		o.r.outcome = outcome
		if err != nil {
			o.r.text = err.Error()
		}

		o.r.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		for _, c := range peClasses {
			o.r.classes = append(o.r.classes, errors.Is(err, c))
		}

		o.r.status, _ = httpsec.LookupStatus(err)
	}()

	select {
	case o := <-done:
		require.False(t, o.panicked, "a hostile port error escaped as a panic: %v", o.value)

		return o.r
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile port error hung the flow or a check of its error")

		return peResult{}
	}
}

func peDecision(d policy.Decision) string { return fmt.Sprintf("%v/%v", d.Outcome, d.Challenge) }

// peEngineFlow is a consumer policy answering outcome with err as its reason.
func peEngineFlow(name string, outcome policy.Outcome, kind policy.ChallengeKind, aborts int) peFlow {
	return peFlow{
		name: name, sink: peContext, aborts: aborts, refusal: refusalOf(outcome),
		build: func(t *testing.T, err error, _ *slog.Logger) func(context.Context) (string, error) {
			t.Helper()

			p := NewMockPolicy(gomock.NewController(t))
			p.EXPECT().Name().Return("consumer").AnyTimes()
			p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
			p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).
				Return(policy.Decision{Outcome: outcome, Challenge: kind, Reason: err}).AnyTimes()

			e, eerr := policy.NewEngine(p)
			require.NoError(t, eerr)

			return func(ctx context.Context) (string, error) {
				d := e.EvaluatePhase(ctx, policy.PostAuthentication, mfaInput(factor.Password))

				return peDecision(d), d.Reason
			}
		},
	}
}

// refusalOf is outcome when it refuses, and the zero Outcome when it does not.
func refusalOf(outcome policy.Outcome) policy.Outcome {
	if outcome == policy.Deny || outcome == policy.Challenge {
		return outcome
	}

	return 0
}

// peFlows are the sites, each reached the way a caller reaches it.
func peFlows() []peFlow {
	evaluate := func(p policy.Policy, in func() *policy.Input) func(context.Context) (string, error) {
		return func(ctx context.Context) (string, error) {
			d := p.Evaluate(policy.ContextWithPhase(ctx, policy.PostAuthentication), in())

			return peDecision(d), d.Reason
		}
	}
	password := func() *policy.Input { return mfaInput(factor.Password) }
	oidc := func() *policy.Input { return federatedInput(factor.OIDC, federatedEvidence("pwd")) }

	return []peFlow{
		peEngineFlow("engine: a consumer policy's deny reason", policy.Deny, policy.ChallengeNone, 1),
		peEngineFlow("engine: a consumer policy's challenge reason", policy.Challenge, policy.ChallengeMFA, 1),
		peEngineFlow("engine: a consumer policy's allow reason is dropped", policy.Allow, policy.ChallengeNone, 0),
		{
			name: "mfa: enrolment lookup in the second walk (enrolledOnAny)", aborts: 1,
			build: func(t *testing.T, err error, lg *slog.Logger) func(context.Context) (string, error) {
				t.Helper()

				p := mfaPolicyFor(t, &sequentialMethodLookup{
					name: mfaMethodName(factor.AuthenticatorApp), channel: factor.AuthenticatorApp, err: err,
				}, policy.WithMFALogger(lg))

				return evaluate(p, password)
			},
		},
		{
			name: "mfa: enrolment lookup in UsableMFAMethods", aborts: 1,
			build: func(t *testing.T, err error, lg *slog.Logger) func(context.Context) (string, error) {
				t.Helper()

				p := mfaPolicyFor(t, mfaMethod(t, factor.AuthenticatorApp, true, err), policy.WithMFALogger(lg))

				return evaluate(p, password)
			},
		},
		{
			name: "UsableMFAMethods: a failing lookup after a usable one", sink: peContext, aborts: 1,
			build: func(t *testing.T, err error, _ *slog.Logger) func(context.Context) (string, error) {
				t.Helper()

				methods := mfaMethods(
					mfaMethod(t, factor.AuthenticatorApp, true, nil),
					mfaMethod(t, factor.Email, true, err),
				)

				return func(ctx context.Context) (string, error) {
					usable, uerr := policy.UsableMFAMethods(ctx, methods, mfaUser, factor.Password)

					return fmt.Sprintf("methods=%d nil=%v", len(usable), usable == nil), uerr
				}
			},
		},
		{
			name: "mfa: federated assurance source answering (true, err)", aborts: 1,
			build: func(t *testing.T, err error, lg *slog.Logger) func(context.Context) (string, error) {
				t.Helper()

				p := mfaPolicyFor(t, idleMFAMethod(t, "totp"),
					policy.WithMFAFederatedChallengeWhenUnmet(true),
					policy.WithFederatedAssuranceSource(assuranceSource(t, true, true, err)),
					policy.WithMFALogger(lg))

				return evaluate(p, oidc)
			},
		},
		{
			name: "requirement: lookup at Evaluate", aborts: 1,
			build: func(t *testing.T, err error, lg *slog.Logger) func(context.Context) (string, error) {
				t.Helper()

				p := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, err),
					idleMFAMethod(t, "totp"), policy.WithMFARequirementLogger(lg))

				return evaluate(p, password)
			},
		},
		{
			name: "requirement: lookup at AdmitsWithoutLocalSecondFactor", aborts: 1,
			build: func(t *testing.T, err error, lg *slog.Logger) func(context.Context) (string, error) {
				t.Helper()

				p := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, err),
					idleMFAMethod(t, "totp"), policy.WithMFARequirementLogger(lg))

				return func(ctx context.Context) (string, error) {
					ok, aerr := p.AdmitsWithoutLocalSecondFactor(ctx, mfaUser, factor.Password)

					return fmt.Sprintf("admitted=%v", ok), aerr
				}
			},
		},
		{
			name: "requirement: enrolment lookup in UsableMFAMethods", aborts: 1,
			build: func(t *testing.T, err error, lg *slog.Logger) func(context.Context) (string, error) {
				t.Helper()

				p := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, nil),
					mfaMethod(t, factor.AuthenticatorApp, true, err), policy.WithMFARequirementLogger(lg))

				return evaluate(p, password)
			},
		},
		{
			name: "requirement: federated assurance source answering (true, err)", aborts: 1,
			build: func(t *testing.T, err error, lg *slog.Logger) func(context.Context) (string, error) {
				t.Helper()

				p := mfaRequirementPolicyFor(t, mfaRequirementLookup(t, true, true, nil),
					idleMFAMethod(t, "totp"),
					policy.WithFederatedAssuranceSource(assuranceSource(t, true, true, err)),
					policy.WithMFARequirementLogger(lg))

				return evaluate(p, oidc)
			},
		},
	}
}

// TestPolicy_PortErrors pins that a hostile error from a consumer's policy,
// enrolment lookup, requirement lookup or assurance source is decided exactly
// as a plain outage of it is — a deny stays a deny, never an allow or a
// shorter method list — and is reported once, on the logger the site uses: the
// component's own when it holds one, otherwise the one the context carries
// (the chain's, inside a chain), and slog.Default() when it carries none.
func TestPolicy_PortErrors(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(peRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	prev := slog.Default()
	defSink := &recordSink{}
	slog.SetDefault(slog.New(defSink))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cancelled := func(ctx context.Context) context.Context {
		cctx, cancel := context.WithCancel(ctx)
		cancel()

		return cctx
	}

	type testCase struct {
		name   string
		err    func() error
		ctx    func(ctx context.Context) context.Context
		child  bool
		assert func(t *testing.T, f peFlow, plain, got peResult, recs peRecords)
	}

	// asPlain is a hostile row: decided as the plain outage, reported once.
	asPlain := func(reason string) func(*testing.T, peFlow, peResult, peResult, peRecords) {
		return func(t *testing.T, f peFlow, plain, got peResult, recs peRecords) {
			t.Helper()

			assert.Equal(t, plain.outcome, got.outcome, "decided as a plain outage is")
			assert.Equal(t, plain.classes, got.classes, "matching the same library sentinels")
			assert.Equal(t, plain.status, got.status, "mapped to the same status")
			assert.NotContains(t, got.text, peHostileText, "the consumer's text travelled on")
			assert.Equal(t, f.aborts == 1, got.unwalkable, "the error is the library's fault")

			want, others := recs.own, [][]slog.Record{recs.ctx, recs.def}
			if f.sink == peContext {
				want, others = recs.def, [][]slog.Record{recs.own, recs.ctx}
				if recs.carried {
					want, others = recs.ctx, [][]slog.Record{recs.own, recs.def}
				}
			}

			for _, other := range others {
				assert.Empty(t, other, "an abort record on the wrong logger")
			}

			require.Len(t, want, f.aborts, "abort records on the site's logger")

			for _, r := range want {
				r.Attrs(func(a slog.Attr) bool {
					if a.Key == "reason" {
						assert.Equal(t, reason, a.Value.String())
					}

					assert.NotContains(t, a.Value.String(), peHostileText)

					return true
				})
			}
		}
	}

	cases := []testCase{
		{name: "self-cycle through Unwrap() error", err: func() error { return &peCycleOne{} }, assert: asPlain("budget")},
		{name: "panicking Unwrap", err: func() error { return pePanicUnwrap{} }, assert: asPlain("panic")},
		{name: "Unwrap panicking with nil", err: func() error { return pePanicNilUnwrap{} }, assert: asPlain("panic")},
		{name: "fan-out join", err: func() error { return peFanOut(64) }, assert: asPlain("budget")},
		{name: "a cycle claiming every sentinel", err: func() error { return &peClaimCycle{} }, assert: asPlain("budget")},
		{
			name: "a cycle on a cancelled context", err: func() error { return &peCycleOne{} },
			ctx: cancelled, assert: asPlain("budget"),
		},
		{
			name: "self-cycle through Unwrap() []error", err: func() error { return &peCycleMany{} },
			child: true, assert: asPlain("budget"),
		},
		{
			// A consumer's reason that wraps ErrDenied but cannot be walked is
			// the library's fault: it still refuses, as a plain outage does,
			// but no longer reads as the ordinary denial ErrDenied maps to.
			name: "a cycle wrapping ErrDenied",
			err:  func() error { return errors.Join(policy.ErrDenied, &peCycleOne{}) },
			assert: func(t *testing.T, f peFlow, plain, got peResult, recs peRecords) {
				t.Helper()

				asPlain("budget")(t, f, plain, got, recs)

				if f.refusal == 0 {
					return
				}

				assert.True(t, strings.HasPrefix(got.outcome, fmt.Sprintf("%v/", f.refusal)),
					"the policy's %v stands, got %s", f.refusal, got.outcome)
				assert.False(t, got.classes[0], "an unwalkable reason must not read as ErrDenied")
				assert.True(t, got.unwalkable, "the reason is the library's fault")
				assert.Equal(t, 500, got.status, "the fault maps to 500, not ErrDenied's status")
			},
		},
		{
			name: "a typed-nil error",
			err:  func() error { return (*peTypedNil)(nil) },
			assert: func(t *testing.T, _ peFlow, plain, got peResult, recs peRecords) {
				t.Helper()

				assert.Equal(t, plain.outcome, got.outcome, "a typed nil is an error, decided as a plain outage")
				assert.Equal(t, plain.classes, got.classes)
				assert.Equal(t, plain.status, got.status)
				assert.False(t, got.unwalkable, "a walkable error is passed on as it is")
				assert.Empty(t, recs.own)
				assert.Empty(t, recs.ctx)
				assert.Empty(t, recs.def)
			},
		},
	}

	for _, f := range peFlows() {
		t.Run(f.name, func(t *testing.T) {
			if childRow != "" && !strings.HasPrefix(childRow, f.name+"|") {
				return
			}

			// The parity row: a plain outage of the same port.
			ownSink := &recordSink{}
			before := len(defSink.records())
			plainErr := errors.New("the consumer's dependency is unreachable")
			runPlain := f.build(t, plainErr, slog.New(ownSink))
			plain := peRunWithin(t, func() (string, error) { return runPlain(t.Context()) })

			require.Empty(t, peAborts(ownSink.records()), "a plain outage wrote an abort record")
			require.Empty(t, peAborts(defSink.records()[before:]), "a plain outage wrote an abort record")
			require.False(t, plain.unwalkable)

			if f.aborts > 0 {
				require.NotContains(t, plain.outcome, "Allow/", "the plain outage of a refusing site must refuse")
				require.NotEqual(t, "admitted=true", plain.outcome)
			}

			for _, tc := range cases {
				row := f.name + "|" + tc.name
				if childRow != "" && (!tc.child || row != childRow) {
					continue
				}

				t.Run(tc.name, func(t *testing.T) {
					if tc.child && childRow == "" {
						peRunChild(t, row)

						return
					}

					// Each row runs on a bare context and on one carrying a
					// logger, as a chain's request context does.
					for _, carried := range []bool{false, true} {
						variant := "bare context"
						if carried {
							variant = "context carrying a logger"
						}

						t.Run(variant, func(t *testing.T) {
							ctx := t.Context()
							if tc.ctx != nil {
								ctx = tc.ctx(ctx)
							}

							ctxSink := &recordSink{}
							if carried {
								ctx = ctxlog.With(ctx, slog.New(ctxSink))
							}

							own := &recordSink{}
							run := f.build(t, tc.err(), slog.New(own))
							before := len(defSink.records())

							got := peRunWithin(t, func() (string, error) { return run(ctx) })

							tc.assert(t, f, plain, got, peRecords{
								own:     peAborts(own.records()),
								ctx:     peAborts(ctxSink.records()),
								def:     peAborts(defSink.records()[before:]),
								carried: carried,
							})
						})
					}

					if childRow != "" && !t.Failed() {
						fmt.Println(peRanMarker(row))
					}
				})
			}
		})
	}
}

// peRunChild re-runs this test in a child process for row, which on unbounded
// code overflows the stack fatally, and requires that the child passed and
// printed the row's marker as a whole line.
func peRunChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPolicy_PortErrors$", "-test.count=1")
	cmd.Env = append(os.Environ(), peRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	want := peRanMarker(row)
	ran := false

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			ran = true
		}
	}

	require.True(t, ran, "the child never ran row %q (no line equals %q); output:\n%s", row, want, out)
}
