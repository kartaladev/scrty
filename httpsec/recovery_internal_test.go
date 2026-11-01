package httpsec

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssueRecovered_NilUserIsAnIssuingFailure pins the one branch of the
// recovery issuer that has to mark its own error: with no user details there
// is nothing for the shared issuer to run on, so the mark cannot come from it.
// The refusal is still a dependency failure, answered 500, never a refusal.
func TestIssueRecovered_NilUserIsAnIssuingFailure(t *testing.T) {
	t.Parallel()

	i := &recoveryInterceptor{}

	tok, err := i.issueRecovered(t.Context(), nil, nil)

	require.Error(t, err)
	assert.Empty(t, tok)
	assert.Equal(t, 500, StatusForError(err), "a missing user is an outage, not a refusal")
	assert.True(t, errors.As(err, new(*issueFailure)), "the error is marked as an issuing failure")
	assert.ErrorIs(t, err, errRecoveryNotIssued)
}
