package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
)

// jwksPortErrRowEnv names the row a child process of TestPortErrors_JWKS runs.
// It is empty in the parent.
const jwksPortErrRowEnv = "SCRTY_HTTPSEC_JWKS_PORTERR_ROW"

// jwksPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const jwksPortErrRan = "jwks-porterr-row-ran:"

// jwksThrough serves a GET on the key set path whose provider fails with
// portErr, as run says.
func jwksThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	keys := NewMockKeySetProvider(gomock.NewController(t))
	keys.EXPECT().JWKS(gomock.Any()).DoAndReturn(func(context.Context) ([]byte, error) {
		onCall()

		return nil, portErr
	})

	logs := &capturingHandler{}
	returned := &stepUpReturned{}

	chain, err := httpsec.New(
		stepUpObserver(returned, run.swallow),
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableJWKSEndpoint(keys),
	)
	require.NoError(t, err)

	rec, panicked := stepUpServeWithin(t, chain, jwksRequest(ctx, http.MethodGet, httpsec.DefaultJWKSPath))

	return stepUpOutcomeOf(rec, panicked, nil, "", logs, returned)
}

// TestPortErrors_JWKS pins that a hostile error from the consumer's key set
// provider is answered exactly as a plain outage of the provider is: the same
// status and body through the chain, and no key set served in its place. The
// error is reported once, to the chain's logger and not to slog.Default().
func TestPortErrors_JWKS(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runStepUpPortErrors(t, jwksPortErrRowEnv, jwksPortErrRan, []stepUpPortSite{
		{name: "the key set provider", through: jwksThrough},
	}, errors.New("key service: connection refused"))
}
