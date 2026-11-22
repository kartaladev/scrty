package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
)

// signalsPortErrRowEnv names the row a child process of
// TestPortErrors_ChallengeSignals runs. It is empty in the parent.
const signalsPortErrRowEnv = "SCRTY_HTTPSEC_SIGNALS_PORTERR_ROW"

// signalsPortErrRan is what a child prints, as a line of its own followed by
// the row's name, once it has run its row to the end.
const signalsPortErrRan = "signals-porterr-row-ran:"

// attemptCountThrough serves a form login for "ada" whose attempt store's
// FailureCount, read for the challenge's identifier signal, fails with portErr.
// The verifier refuses, so no password is checked, and records whether it was
// told the identifier has failures: an error read as "none" would hide a
// suspicious identifier from a verifier that asks only suspicious requests.
func attemptCountThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	h := newAuthHarness(t)
	h.attempts.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).
		DoAndReturn(func(context.Context, string, time.Time) (int, error) {
			onCall()

			return 0, portErr
		})

	var told atomic.Bool

	v := NewMockChallengeVerifier(gomock.NewController(t))
	v.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ httpsec.Request, s httpsec.ChallengeSignals) (httpsec.ChallengeDecision, error) {
			told.Store(s.IdentifierHasFailures)

			return httpsec.ChallengeRefuse, nil
		})

	logs := &capturingHandler{}
	returned := &stepUpReturned{}

	chain, err := httpsec.New(
		stepUpObserver(returned, run.swallow),
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableFormLogin(h.formLoginDeps()),
		challengeFor(httpsec.ChallengeFlowFormLogin, v),
	)
	require.NoError(t, err)

	rec, panicked := stepUpServeWithin(t, chain,
		formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=wrong"))

	require.True(t, told.Load(), "the verifier was told the identifier has failures")

	return stepUpOutcomeOf(rec, panicked, nil, fmt.Sprintf("identifierHasFailures=%v", told.Load()), logs, returned)
}

// TestPortErrors_ChallengeSignals pins that a hostile error from the attempt
// store's FailureCount, read for the challenge verifier's identifier signal, is
// answered exactly as a plain outage of the store is: the verifier is told the
// identifier has failures and the request is answered as the verifier decides.
// The error is only logged at this site, never returned, so what shows of it
// is the one abort record, written to the chain's logger and not to
// slog.Default().
func TestPortErrors_ChallengeSignals(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runStepUpPortErrors(t, signalsPortErrRowEnv, signalsPortErrRan, []stepUpPortSite{
		{name: "the attempt store's failure count", through: attemptCountThrough, logOnly: true},
	}, errors.New("attempt store: connection refused"))
}
