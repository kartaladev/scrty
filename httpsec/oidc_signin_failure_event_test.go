package httpsec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/event"
)

// TestOIDCProvider_SignInEnds_FailureIsReportedAsAnEvent pins that a sign-in's end the
// provider could not carry through to the grants is reported to the chain's sink, and
// that the report names the user and none of the store's text.
func TestOIDCProvider_SignInEnds_FailureIsReportedAsAnEvent(t *testing.T) {
	t.Parallel()

	f := newSignInEnds(t, endsSetup{})
	s := f.signIn(t)
	f.grantFrom(t, s, endsOnlineScope)
	f.grants.failing.Store(true)

	_, err := f.sessions.RevokeFamily(t.Context(), s.FamilyID)
	require.NoError(t, err)
	require.Contains(t, f.logs.String(), "could not be ended")

	f.toldOf(t)

	failed := f.events.named(event.GrantEndFailed)
	require.Len(t, failed, 1, "the failed end is reported once; saw %v", f.events.all)
	assert.Equal(t, event.OutcomeFailure, failed[0].Outcome)
	assert.NotContains(t, failed[0].Cause, endsOutageText)
}
