package httpsecconformance

import (
	"testing"
)

// Run puts every scenario through adapter.
//
// One call is a framework's whole conformance run: the scenarios are the same
// values every other adapter is given, so a row that passes on one framework
// and fails on another is a difference in that adapter and nowhere else.
//
// Each scenario builds its own stores, so the frameworks are never compared on
// state one of them left for another, and the rows are independent: a failing
// row does not stop the rest, because knowing which behaviours an adapter got
// wrong is worth more than stopping at the first.
func Run(t *testing.T, adapter Adapter) {
	t.Helper()

	for _, sc := range Scenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			t.Parallel()

			spec := sc.Build(t)

			res := adapter.Serve(t, spec, sc.Request(spec))

			// Carried rather than looked up, so an assertion reads the response
			// and the side effects the same run produced, in one place.
			res.Effects = spec.Effects

			sc.Assert(t, res)
		})
	}
}
