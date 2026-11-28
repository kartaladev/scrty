package oidcprovider

import (
	"github.com/kartaladev/scrty/pkg/clock"
	"github.com/kartaladev/scrty/session"
)

// LineageWrappersForTest wraps inner in each of the session-store wrappers the
// provider puts around its lineage store, keyed by the wrapper's name.
func LineageWrappersForTest(inner session.Store, clk clock.Clock) map[string]session.Store {
	return map[string]session.Store{
		"sweepingLineages":  &sweepingLineages{Store: inner, sweep: memorySweep{clock: clk}},
		"budgetedLineage":   budgetedLineage{Store: inner},
		"firstRotationOnly": firstRotationOnly{Store: inner},
	}
}
