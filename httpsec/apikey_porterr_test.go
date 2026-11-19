package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// apiKeyPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const apiKeyPortErrRowEnv = "SCRTY_HTTPSEC_APIKEY_PORTERR_ROW"

// apiKeyPortErrRan is what a child prints once it has run its row to the end,
// followed by the row's name. A child whose row matched nothing prints
// nothing, and its parent fails rather than passing on an empty run.
const apiKeyPortErrRan = "apikey-porterr-row-ran:"

// The owner check's records for an outage and for a caller that left.
const (
	apiKeyPortErrOwnerUnavailable = "httpsec: an API key's owner could not be loaded"
	apiKeyPortErrOwnerCallerEnded = "httpsec: the caller left while an API key's owner was loaded"
)

// errOwnerStoreDown is the user loader's plain outage, the parity row.
var errOwnerStoreDown = errors.New("users: dial tcp 10.0.0.5:5432: connection refused")

// apiKeyPortOutcome is what one request through a failing owner load produced
// that a client or the source limiter can observe, and the records the chain's
// logger received.
type apiKeyPortOutcome struct {
	status int
	header http.Header
	body   string

	// loads and charged are the user loader's and the source limiter's
	// RecordFailure calls.
	loads, charged int

	logs []slog.Record
}

// count is how many records of logs carry msg.
func (o apiKeyPortOutcome) count(msg string) int {
	n := 0

	for _, r := range o.logs {
		if r.Message == msg {
			n++
		}
	}

	return n
}

// apiKeyOwnerThrough serves one request carrying a valid key on ctx, through
// the chain's net/http middleware, whose user loader fails with portErr. With
// leaves, the loader ends the request's context before it answers, as a
// client hanging up mid-load does; ctx must then come from leavable.
func apiKeyOwnerThrough(t *testing.T, ctx context.Context, portErr error, leaves bool) apiKeyPortOutcome {
	t.Helper()

	ctrl := gomock.NewController(t)

	var (
		mu  sync.Mutex
		out apiKeyPortOutcome
	)

	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, string) error {
			mu.Lock()
			defer mu.Unlock()

			out.charged++

			return nil
		}).AnyTimes()

	users := NewMockUserLoader(ctrl)
	users.EXPECT().LoadByUserID(gomock.Any(), apiKeyPrincipal).
		DoAndReturn(func(ctx context.Context, _ identity.UserID) (*identity.Details, error) {
			mu.Lock()
			out.loads++
			mu.Unlock()

			if leaves {
				leave(ctx, context.Canceled)
			}

			return nil, portErr
		}).AnyTimes()

	h := newAPIKeyHarness(t)
	logs := &capturingHandler{}

	chain, err := httpsec.New(httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableAPIKey(h.keys, httpsec.WithAPIKeyLimiter(limiter), httpsec.WithAPIKeyOwners(users)))
	require.NoError(t, err)

	built := len(logs.records())

	req := rawBasicRequest(ctx, "")
	req.RemoteAddr = apiKeySource + ":51000"
	req.Header.Set("Authorization", httpsec.DefaultAPIKeyScheme+h.valid)

	rec := loginServeWithin(t, chain, req)

	mu.Lock()
	defer mu.Unlock()

	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	out.logs = logs.records()[built:]

	return out
}

// TestPortErrors_APIKeyOwner pins that a hostile error from the API-key
// interceptor's user loader is answered exactly as a plain loader outage is,
// through the real request path: the same response, byte for byte, no charge
// to the source, and the outage's own record. It is reported once, to the
// chain's own logger and not to slog.Default(). A hostile error is an outage:
// never a missing owner (which charges the source), never the caller's
// hang-up (which writes its own record), never a protected handler reached.
func TestPortErrors_APIKeyOwner(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(apiKeyPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name   string
		leaves bool
	}{
		{name: "live"},
		{name: "caller left mid-load", leaves: true},
	}

	kinds := []loginPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		// The stdlib reads this one as a missing owner: errors.Is finds the
		// sentinel before it loops.
		{name: "cycle wrapping ErrUserNotFound", err: &loginNotFoundCycle{}, reason: "budget", child: true},
		// Read unsanitized, it overflows the stack looking for ErrUserNotFound,
		// before the hang-up check could even ask about context.Canceled.
		{name: "cycle wrapping context.Canceled", err: &loginCanceledCycle{}, reason: "budget", child: true},
		// Walked to the end, so it passes unchanged and is answered as the
		// plain outage is.
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}

	for _, c := range contexts {
		for _, kind := range kinds {
			row := c.name + "/" + kind.name
			if childRow != "" && childRow != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if kind.child && childRow == "" {
					apiKeyPortErrInChild(t, row)

					return
				}

				defaults := swapDefaultLogger(t)

				serve := func(portErr error) apiKeyPortOutcome {
					ctx := t.Context()
					if c.leaves {
						ctx = leavable(ctx)
					}

					return apiKeyOwnerThrough(t, ctx, portErr, c.leaves)
				}

				plain := serve(errOwnerStoreDown)
				require.Empty(t, abortRecords(plain.logs), "the reference writes no abort record")
				require.Equal(t, 1, plain.loads, "the reference reached the owner load")
				require.Equal(t, 1, plain.count(apiKeyPortErrOwnerUnavailable), "the reference is an outage")
				require.NotEqual(t, http.StatusTeapot, plain.status, "the reference is refused")

				got := serve(kind.err)

				assert.Equal(t, plain.status, got.status, "status")
				assert.Equal(t, plain.header, got.header, "headers")
				assert.Equal(t, plain.body, got.body, "body")
				assert.Equal(t, plain.loads, got.loads, "owner loads")
				assert.Equal(t, plain.charged, got.charged, "charges to the source")
				assert.Equal(t, 1, got.count(apiKeyPortErrOwnerUnavailable), "the outage's own record")
				assert.Zero(t, got.count(apiKeyPortErrOwnerCallerEnded), "no hang-up record")
				assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")

				aborts := abortRecords(got.logs)
				if kind.reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, aborts, 1, "one abort record, on the chain's logger")
					assertAbortRecord(t, aborts[0], kind.reason)
				}

				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

				if childRow != "" && !t.Failed() {
					fmt.Fprintln(os.Stdout, apiKeyPortErrRan+row)
				}
			})
		}
	}
}

// apiKeyPortErrInChild re-runs the current top-level test in a child process
// limited to row, and fails unless it exits 0 within a minute having run the
// row: a stack overflow is fatal and only a child can watch for one, and a row
// name that matched nothing would otherwise pass without running.
func apiKeyPortErrInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), apiKeyPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
	assert.Contains(t, string(out), apiKeyPortErrRan+row+"\n", "the child ran its row")
}
