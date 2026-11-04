package httpsecconformance

import (
	"testing"
)

// Run puts every scenario in Scenarios through adapter.
//
// The groups that need their own wiring run beside it, not inside it: an
// adapter's suite also calls RunScenarios with ChallengeScenarios, and
// RunCertificateBinding. An adapter author who calls only Run does not run
// those rows.
//
// Run is otherwise a framework's whole conformance run: the scenarios are the same
// values every other adapter is given, so a row that passes on one framework
// and fails on another is a difference in that adapter and nowhere else.
//
// Each scenario builds its own stores, so the frameworks are never compared on
// state one of them left for another, and the rows are independent: a failing
// row does not stop the rest, because knowing which behaviours an adapter got
// wrong is worth more than stopping at the first.
func Run(t *testing.T, adapter Adapter) {
	t.Helper()

	RunScenarios(t, adapter, Scenarios())
}

// RunScenarios puts scenarios through adapter, each row as Run puts it. It is
// how an adapter's suite runs one group on its own, such as ChallengeScenarios,
// which Run does not include.
func RunScenarios(t *testing.T, adapter Adapter, scenarios []Scenario) {
	t.Helper()

	for _, sc := range scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			t.Parallel()

			if sc.Stream != nil {
				streams, ok := adapter.(StreamAdapter)
				if !ok {
					t.Skip("the adapter cannot serve a chain on a real listener: it is no StreamAdapter")
				}

				sc.Stream(t, func(spec ChainSpec) StreamServer {
					t.Helper()

					return streams.Listen(t, spec, StreamWriteTimeout)
				})

				return
			}

			spec := sc.Build(t)

			if sc.Steps != nil {
				sc.Steps(t, spec, func(req RequestSpec) Result {
					t.Helper()

					res := adapter.Serve(t, spec, req)
					res.Effects = spec.Effects

					return res
				})

				return
			}

			res := adapter.Serve(t, spec, sc.Request(spec))

			// Carried rather than looked up, so an assertion reads the response
			// and the side effects the same run produced, in one place.
			res.Effects = spec.Effects

			sc.Assert(t, res)
		})
	}
}
