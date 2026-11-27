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

// TestScenarios_SessionCookieRowsAreRegistered pins that the cookie chain rows
// are part of Scenarios, which every adapter's suite runs.
func TestScenarios_SessionCookieRowsAreRegistered(t *testing.T) {
	t.Parallel()

	inScenarios := make(map[string]bool)
	for _, sc := range httpsecconformance.Scenarios() {
		inScenarios[sc.Name] = true
	}

	names := httpsecconformance.SessionCookieScenarioNames()
	assert.NotEmpty(t, names)

	for _, name := range names {
		assert.True(t, inScenarios[name], "%q is not in Scenarios, so no adapter runs it", name)
	}
}
