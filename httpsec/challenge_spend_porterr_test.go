package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// beginPortErrRowEnv names the row a child process of
// TestPortErrors_ChallengeBegin runs. It is empty in the parent.
const beginPortErrRowEnv = "SCRTY_HTTPSEC_CHALLENGE_BEGIN_PORTERR_ROW"

// beginPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const beginPortErrRan = "challenge-begin-porterr-row-ran:"

// challengeBeginThrough serves a second-factor begin whose challenge method's
// BeginChallenge fails with portErr.
func challengeBeginThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp)

	// The method stands in for a challenge method that enrols the user and
	// fails to build its begin data. Everything but BeginChallenge is the
	// scripted stub's.
	stub := newChallengeStub()

	m := NewMockChallengeMethod(gomock.NewController(t))
	m.EXPECT().Name().DoAndReturn(stub.Name).AnyTimes()
	m.EXPECT().Channel().DoAndReturn(stub.Channel).AnyTimes()
	m.EXPECT().Response().DoAndReturn(stub.Response).AnyTimes()
	m.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(stub.Verify).AnyTimes()
	m.EXPECT().Enrolled(gomock.Any(), gomock.Any()).DoAndReturn(stub.Enrolled).AnyTimes()
	m.EXPECT().PresentedChallenge(gomock.Any()).DoAndReturn(stub.PresentedChallenge).AnyTimes()
	m.EXPECT().BeginChallenge(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, identity.UserID, string) (json.RawMessage, error) {
			onCall()

			return nil, portErr
		})
	h.extra = []mfa.Method{m}

	charges := &stepUpCharges{}

	h.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	h.limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(context.Context, string) error {
			charges.add()

			return nil
		})

	s := h.pendingSession(t, factor.Password)

	logs := &capturingHandler{}
	returned := &stepUpReturned{}
	chain := h.chain(t, s, httpsec.WithLogger(slog.New(logs)), stepUpObserver(returned, run.swallow))

	rec, panicked := stepUpServeWithin(t, chain, post(ctx, testMFABeginPath, ""))

	stored := h.stored(t, s.ID)

	return stepUpOutcomeOf(rec, panicked, charges, fmt.Sprintf("%v", stored.MFA), logs, returned)
}

// TestPortErrors_ChallengeBegin pins that a hostile error from a challenge
// method's BeginChallenge is answered exactly as a plain outage of the method
// is: the same refusal behind the same fixed text, nothing charged to the
// user, and the session left pending. It is reported once, to the chain's
// logger, and not to slog.Default(). The re-proof begin endpoint shares the
// site (issueChallenge), so this covers it too.
//
// BeginChallenge has no unavailable sentinel and the site tests none, so the
// fixed error is porterr.ErrUnwalkable and the site's one branch for a failing
// method answers it.
func TestPortErrors_ChallengeBegin(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runStepUpPortErrors(t, beginPortErrRowEnv, beginPortErrRan, []stepUpPortSite{
		{name: "a challenge method's BeginChallenge", through: challengeBeginThrough},
	}, errors.New("dependency: connection refused"))
}
