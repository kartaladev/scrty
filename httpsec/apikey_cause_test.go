package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apiKeyCauseRowEnv names the row a child process runs. It is empty in the
// parent.
const apiKeyCauseRowEnv = "SCRTY_HTTPSEC_APIKEY_CAUSE_ROW"

// apiKeyCauseRan is what a child prints once it has run its row to the end,
// followed by the row's name.
const apiKeyCauseRan = "apikey-cause-row-ran:"

// TestAPIKeyOwner_HostileCancelCause pins that the cause a request's context
// was cancelled with, which any middleware may set, is consumer input: the
// owner check reads it under the library's bounded, recovering walk. A client
// that leaves mid-load with a cause the walk gives up on is answered exactly
// as one that leaves with a plain unrelated cause is, without a hang or a
// crash, and the abort is recorded once on the chain's logger.
func TestAPIKeyOwner_HostileCancelCause(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(apiKeyCauseRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	kinds := []loginPortErrKind{
		{name: "the context's own error as the cause", err: context.Canceled},
		{name: "a wrapped context error as the cause", err: fmt.Errorf("middleware: %w", context.Canceled)},
		{name: "a typed-nil cause", err: (*loginTypedNil)(nil)},
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
	}

	for _, kind := range kinds {
		if childRow != "" && childRow != kind.name {
			continue
		}

		t.Run(kind.name, func(t *testing.T) {
			if kind.child && childRow == "" {
				limiterPortErrInChild(t, apiKeyCauseRowEnv, apiKeyCauseRan, kind.name)

				return
			}

			defaults := swapDefaultLogger(t)

			serve := func(cause error) apiKeyPortOutcome {
				return apiKeyOwnerSequenceCause(t, leavable(t.Context()), []error{context.Canceled}, true, cause)
			}

			plain := serve(errors.New("client gone"))
			require.Empty(t, abortRecords(plain.logs), "the reference writes no abort record")
			require.Equal(t, 1, plain.loads, "the reference reached the owner load")
			require.Equal(t, 1, plain.count(apiKeyPortErrOwnerCallerEnded), "the reference is a hang-up")
			require.Equal(t, http.StatusUnauthorized, plain.status, "the reference is refused")

			got := serve(kind.err)

			assert.Equal(t, plain.status, got.status, "status")
			assert.Equal(t, plain.header, got.header, "headers")
			assert.Equal(t, plain.body, got.body, "body")
			assert.Equal(t, plain.loads, got.loads, "owner loads")
			assert.Equal(t, plain.charged, got.charged, "charges to the source")
			assert.Equal(t, 1, got.count(apiKeyPortErrOwnerCallerEnded), "the hang-up's own record")
			assert.Zero(t, got.count(apiKeyPortErrOwnerUnavailable), "no outage record")

			aborts := abortRecords(got.logs)
			if kind.reason == "" {
				assert.Empty(t, aborts, "a walk that completes writes no abort record")
			} else {
				require.Len(t, aborts, 1, "one abort record, on the chain's logger")
				assertAbortRecord(t, aborts[0], kind.reason)
			}

			assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

			if childRow != "" && !t.Failed() {
				fmt.Fprintln(os.Stdout, apiKeyCauseRan+kind.name)
			}
		})
	}
}
