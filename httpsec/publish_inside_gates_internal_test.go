package httpsec

import (
	"context"
	"math/bits"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/policy"
)

// gatedChain is a chain enabling exactly the gates of kinds, as far as the
// walk can tell: only its gate set is filled in.
func gatedChain(t *testing.T, kinds ...policy.ChallengeKind) *Chain {
	t.Helper()

	var s gateSet

	for _, k := range kinds {
		i := slices.Index(gateOrder[:], k)
		require.GreaterOrEqual(t, i, 0, "kind %v has no position in gateOrder", k)

		s |= 1 << i
	}

	return &Chain{gates: s}
}

// mark is the state of one run nestRuns marks on a context: the chain it is a
// run of, and whether it is inside its gates or finished.
type mark struct {
	chain            *Chain
	gatesBegun, done bool
}

// nestRuns marks runs on ctx outermost first, each the parent of the next,
// with chain, gatesBegun and done as given. A mark with no chain is a run of
// a chain enabling no gate.
func nestRuns(ctx context.Context, marks ...mark) context.Context {
	var parent *chainRun

	for _, m := range marks {
		c := m.chain
		if c == nil {
			c = &Chain{}
		}

		r := &chainRun{Context: ctx, chain: c, parent: parent}
		r.gatesBegun.Store(m.gatesBegun)
		r.done.Store(m.done)
		ctx, parent = r, r
	}

	return ctx
}

// TestGateSet_HoldsEveryGateKind pins that gateSet cannot drift from the gates:
// every kind gateKind names has a position in gateOrder, and gateOrder fits
// in the bits of a gateSet.
func TestGateSet_HoldsEveryGateKind(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T)
	}

	cases := []testCase{
		{
			name: "every kind gateKind returns is in gateOrder",
			assert: func(t *testing.T) {
				t.Helper()

				gates := []Interceptor{&recoveryGate{}, &enrolmentInterceptor{}, &mfaInterceptor{}, &passwordChangeGate{}}
				for _, g := range gates {
					kind, ok := gateKind(g)
					require.True(t, ok, "%T is not named by gateKind", g)
					assert.GreaterOrEqual(t, slices.Index(gateOrder[:], kind), 0, "kind %v of %T is missing from gateOrder", kind, g)
				}
			},
		},
		{
			name: "gateOrder fits in a gateSet",
			assert: func(t *testing.T) {
				t.Helper()

				assert.LessOrEqual(t, len(gateOrder), bits.Len(uint(^gateSet(0))))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t)
		})
	}
}

// TestGatesRunning pins the walk PublishSession and publishSession take to find
// a run inside gates the publishing chain does not cover: any run in progress,
// nearest or enclosing, of another chain counts when its chain enables a gate
// the publisher does not, a run of the publisher itself never counts, and a
// finished run counts for nothing, its gate mark included.
func TestGatesRunning(t *testing.T) {
	t.Parallel()

	mfa := gatedChain(t, policy.ChallengeMFA)
	mfaAndPassword := gatedChain(t, policy.ChallengeMFA, policy.ChallengePasswordChange)
	password := gatedChain(t, policy.ChallengePasswordChange)
	every := gatedChain(t, gateOrder[:]...)

	type testCase struct {
		name string
		// publisher is the chain publishing; nil for one enabling no gate.
		publisher *Chain
		marks     []mark
		assert    func(t *testing.T, running bool)
	}

	running := func(t *testing.T, got bool) { t.Helper(); assert.True(t, got) }
	notRunning := func(t *testing.T, got bool) { t.Helper(); assert.False(t, got) }

	cases := []testCase{
		{name: "no run", assert: notRunning},
		{name: "one run before its gates", marks: []mark{{chain: mfa}}, assert: notRunning},
		{name: "one run of another chain inside its gates", marks: []mark{{chain: mfa, gatesBegun: true}}, assert: running},
		{name: "run inside an enclosing run's gates", marks: []mark{{chain: mfa, gatesBegun: true}, {}}, assert: running},
		{name: "three deep, the outermost inside its gates", marks: []mark{{chain: mfa, gatesBegun: true}, {}, {}}, assert: running},
		{name: "finished enclosing run with its mark left set", marks: []mark{{chain: mfa, gatesBegun: true, done: true}, {}}, assert: notRunning},
		{name: "finished nearest run with its mark left set", marks: []mark{{}, {chain: mfa, gatesBegun: true, done: true}}, assert: notRunning},
		{name: "marked enclosing run of a chain enabling no gate", marks: []mark{{gatesBegun: true}, {}}, assert: notRunning},
		{name: "marked enclosing run of the publishing chain itself", publisher: mfa, marks: []mark{{chain: mfa, gatesBegun: true}, {chain: mfa}}, assert: notRunning},
		{
			name: "marked enclosing run whose gates the publisher covers", publisher: mfaAndPassword,
			marks: []mark{{chain: mfa, gatesBegun: true}, {chain: mfaAndPassword}}, assert: notRunning,
		},
		{
			name: "marked enclosing run with the same gates as the publisher", publisher: gatedChain(t, policy.ChallengeMFA),
			marks: []mark{{chain: mfa, gatesBegun: true}, {}}, assert: notRunning,
		},
		{
			name: "marked enclosing run with a gate the publisher lacks", publisher: password,
			marks: []mark{{chain: mfaAndPassword, gatesBegun: true}, {chain: password}}, assert: running,
		},
		{
			name: "two marked enclosing runs, only the outer one uncovered", publisher: mfa,
			marks: []mark{{chain: every, gatesBegun: true}, {chain: mfa, gatesBegun: true}, {chain: mfa}}, assert: running,
		},
		{
			name: "two marked enclosing runs, both covered", publisher: every,
			marks: []mark{{chain: mfa, gatesBegun: true}, {chain: password, gatesBegun: true}, {chain: every}}, assert: notRunning,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			publisher := tc.publisher
			if publisher == nil {
				publisher = &Chain{}
			}

			tc.assert(t, gatesRunning(nestRuns(t.Context(), tc.marks...), publisher))
		})
	}
}

// TestGatesRunning_AllocatesNothing pins that the walk, which runs on every
// publication, allocates nothing however deep the runs nest, gate-set
// comparisons included. It is not parallel: AllocsPerRun counts every
// allocation in the process.
func TestGatesRunning_AllocatesNothing(t *testing.T) {
	publisher := gatedChain(t, policy.ChallengeMFA, policy.ChallengePasswordChange)
	ctx := nestRuns(t.Context(),
		mark{chain: gatedChain(t, policy.ChallengeMFA), gatesBegun: true},
		mark{done: true},
		mark{chain: publisher, gatesBegun: true},
		mark{chain: gatedChain(t, policy.ChallengePasswordChange), gatesBegun: true},
		mark{chain: publisher},
	)

	allocs := testing.AllocsPerRun(100, func() { _ = gatesRunning(ctx, publisher) })
	assert.Zero(t, allocs, "the walk allocates")
}

// TestExchange_PublishingChain pins the filter that skips a run whose terminal is
// running: through the public path another check refuses the same publication.
func TestExchange_PublishingChain(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		stack  func(below, top *Chain) []runTerminal
		assert func(t *testing.T, got, below, top *Chain)
	}

	cases := []testCase{
		{
			name: "a top entry whose terminal is running yields the entry below",
			stack: func(below, top *Chain) []runTerminal {
				return []runTerminal{{chain: below}, {chain: top, running: true}}
			},
			assert: func(t *testing.T, got, below, _ *Chain) { t.Helper(); require.Same(t, below, got) },
		},
		{
			name: "nothing running yields the top entry",
			stack: func(below, top *Chain) []runTerminal {
				return []runTerminal{{chain: below}, {chain: top}}
			},
			assert: func(t *testing.T, got, _, top *Chain) { t.Helper(); require.Same(t, top, got) },
		},
		{
			name: "every terminal running yields no chain",
			stack: func(below, top *Chain) []runTerminal {
				return []runTerminal{{chain: below, running: true}, {chain: top, running: true}}
			},
			assert: func(t *testing.T, got, _, _ *Chain) { t.Helper(); require.Nil(t, got) },
		},
		{
			name:   "no run yields no chain",
			stack:  func(_, _ *Chain) []runTerminal { return nil },
			assert: func(t *testing.T, got, _, _ *Chain) { t.Helper(); require.Nil(t, got) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			below := gatedChain(t, gateOrder[0])
			top := gatedChain(t, gateOrder[1])

			e := &Exchange{}
			for _, entry := range tc.stack(below, top) {
				e.pushTerminal(entry.chain, entry.next)
				e.terminalAt(e.terminalCount() - 1).running = entry.running
			}

			tc.assert(t, e.publishingChain(), below, top)
		})
	}
}

// TestExchange_GateMarkRefusal pins how the gate marks of the runs on one
// exchange judge a publication: a mark of the publishing run makes it late, a
// mark of another run refuses it unless the publishing chain covers that
// run's gates, and a publication with no chain running interceptors, from
// the handler, is refused by any mark.
func TestExchange_GateMarkRefusal(t *testing.T) {
	t.Parallel()

	password := gatedChain(t, policy.ChallengePasswordChange)
	mfaAndPassword := gatedChain(t, policy.ChallengeMFA, policy.ChallengePasswordChange)

	type testCase struct {
		name   string
		stack  []runTerminal
		assert func(t *testing.T, err error)
	}

	published := func(t *testing.T, err error) { t.Helper(); require.NoError(t, err) }
	late := func(t *testing.T, err error) { t.Helper(); require.ErrorIs(t, err, errLatePublication) }
	inside := func(t *testing.T, err error) { t.Helper(); require.ErrorIs(t, err, errPublishedInsideGates) }

	cases := []testCase{
		{name: "no run", assert: published},
		{name: "one run before its gates", stack: []runTerminal{{chain: password}}, assert: published},
		{name: "one run inside its own gates", stack: []runTerminal{{chain: password, gatesBegun: true}}, assert: late},
		{
			name:   "covering chain nested inside another run's gates",
			stack:  []runTerminal{{chain: password, gatesBegun: true, running: true}, {chain: mfaAndPassword}},
			assert: published,
		},
		{
			name:   "same chain nested inside its own earlier run's gates",
			stack:  []runTerminal{{chain: password, gatesBegun: true, running: true}, {chain: password}},
			assert: published,
		},
		{
			name:   "nested chain inside its own gates, the outer run's gates covered",
			stack:  []runTerminal{{chain: password, gatesBegun: true, running: true}, {chain: password, gatesBegun: true}},
			assert: late,
		},
		{
			name:   "nested chain lacking a gate of another run",
			stack:  []runTerminal{{chain: mfaAndPassword, gatesBegun: true, running: true}, {chain: password}},
			assert: inside,
		},
		{
			name:   "outer run's interceptor inside a nested run's gates it lacks",
			stack:  []runTerminal{{chain: password}, {chain: mfaAndPassword, gatesBegun: true, running: true}},
			assert: inside,
		},
		{
			name: "outer run past its own gates, behind a nested covered run",
			stack: []runTerminal{
				{chain: mfaAndPassword, gatesBegun: true}, {chain: password, gatesBegun: true, running: true},
			},
			assert: late,
		},
		{
			name:   "handler inside a run's gates",
			stack:  []runTerminal{{chain: password, gatesBegun: true, running: true}},
			assert: inside,
		},
		{
			name:   "handler, no run inside its gates",
			stack:  []runTerminal{{chain: password, running: true}},
			assert: published,
		},
		{
			name: "three deep, the spilled publisher lacking the outermost run's gate",
			stack: []runTerminal{
				{chain: mfaAndPassword, gatesBegun: true, running: true},
				{chain: password, running: true},
				{chain: password},
			},
			assert: inside,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, exchangeWith(tc.stack).gateMarkRefusal())
		})
	}
}

// TestExchange_GateMarkRefusal_AllocatesNothing pins that the walk over the
// exchange's runs, which runs on every publication, allocates nothing, the
// spilled entries included. It is not parallel: AllocsPerRun counts every
// allocation in the process.
func TestExchange_GateMarkRefusal_AllocatesNothing(t *testing.T) {
	password := gatedChain(t, policy.ChallengePasswordChange)
	e := exchangeWith([]runTerminal{
		{chain: password, gatesBegun: true, running: true},
		{chain: gatedChain(t, policy.ChallengeMFA, policy.ChallengePasswordChange), gatesBegun: true, running: true},
		{chain: password},
	})

	allocs := testing.AllocsPerRun(100, func() { _ = e.gateMarkRefusal() })
	assert.Zero(t, allocs, "the walk allocates")
}

// exchangeWith returns an exchange whose stack of runs is stack, bottom
// first.
func exchangeWith(stack []runTerminal) *Exchange {
	e := &Exchange{}
	for _, entry := range stack {
		e.pushTerminal(entry.chain, entry.next)

		top := e.terminalAt(e.terminalCount() - 1)
		top.running = entry.running
		top.gatesBegun = entry.gatesBegun
	}

	return e
}
