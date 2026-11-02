package httpsecconformance_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kartaladev/scrty/test/httpsecconformance"
)

// TestScenarios_ChallengeRowsRunOnce pins that the automation-challenge rows
// are in one group only. Each adapter's suite runs them by name
// (TestChallenge*), and a second copy in Scenarios, which the conformance run
// puts through the same adapters, would run every row twice.
func TestScenarios_ChallengeRowsRunOnce(t *testing.T) {
	t.Parallel()

	inScenarios := make(map[string]bool)
	for _, sc := range httpsecconformance.Scenarios() {
		inScenarios[sc.Name] = true
	}

	for _, sc := range httpsecconformance.ChallengeScenarios() {
		assert.False(t, inScenarios[sc.Name], "%q is in Scenarios as well as in ChallengeScenarios", sc.Name)
	}
}
