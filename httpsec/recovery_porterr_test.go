package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/recovery"
)

// cooldownPortErrRowEnv names the row a child process runs. It is empty in the
// parent.
const cooldownPortErrRowEnv = "SCRTY_HTTPSEC_COOLDOWN_PORTERR_ROW"

// cooldownPortErrRan is what a child prints, as a line of its own followed by
// the row's name, once it has run its row to the end.
const cooldownPortErrRan = "cooldown-porterr-row-ran:"

// cooldownWorld builds a chain whose cool-down guard reads a record store
// answering err on every lookup, logging to log, and the marked request of a
// session that passes the bearer check. lookups counts the store's lookups.
func cooldownWorld(ctx context.Context, t *testing.T, err error, log *slog.Logger) (*httpsec.Chain, *http.Request, *atomic.Int32) {
	t.Helper()

	var lookups atomic.Int32

	store := NewMockRecordStore(gomock.NewController(t))
	store.EXPECT().LatestCompletion(gomock.Any(), e2eUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (time.Time, bool, error) {
			lookups.Add(1)

			return time.Time{}, false, err
		})

	h := newRecoveryHarness(t) //nolint:contextcheck // the case's ctx is the caller's; fixtures are built on t.Context()

	chain, buildErr := httpsec.New(httpsec.WithLogger(log),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: h.tokens, Sessions: h.sessions, Users: h.users}),
		httpsec.EnableRecoveryCooldown(store, recoveryCooldown, emailRoute))
	require.NoError(t, buildErr)

	s, createErr := h.sessions.Create(t.Context(), e2eUser) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	require.NoError(t, createErr)

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/account/email", nil)
	req.RemoteAddr = e2eSource + ":51000"
	req.Header.Set("Authorization", "Bearer "+mfaTokenFor(s.ID))

	return chain, req, &lookups
}

// cooldownServe sends the marked request through the chain's net/http
// middleware and returns the response, whether the guarded handler (which
// answers 418) was reached, and the store's lookups.
func cooldownServe(ctx context.Context, t *testing.T, err error, log *slog.Logger) (*httptest.ResponseRecorder, bool, int) {
	t.Helper()

	chain, req, lookups := cooldownWorld(ctx, t, err, log)
	rec := loginServeWithin(t, chain, req)

	return rec, rec.Code == http.StatusTeapot, int(lookups.Load())
}

// cooldownReadWithin runs the marked request through the chain and reads the
// error it returns with errors.Is, as a consumer's own error handler does, and
// fails the test when that hangs or panics.
func cooldownReadWithin(ctx context.Context, t *testing.T, err error, log *slog.Logger) {
	t.Helper()

	chain, req, _ := cooldownWorld(ctx, t, err, log)

	done := make(chan any, 1)

	go func() { //nolint:contextcheck // serve runs the exchange on t.Context(), not the case's ctx; the request itself carries ctx
		defer func() { done <- recover() }()

		out := serve(t, chain, req)
		_ = errors.Is(out.err, recovery.ErrCooldown)
		_ = errors.Is(out.err, context.Canceled)
		_ = out.err.Error()
	}()

	select {
	case v := <-done:
		require.Nil(t, v, "reading the returned error panicked")
	case <-time.After(porterrWithin):
		require.FailNow(t, "reading the returned error hung")
	}
}

// TestPortErrors_RecoveryCooldown pins that a hostile error from the record
// store's LatestCompletion is answered exactly as a plain store outage is: the
// same response, byte for byte, the guarded handler never reached (a hostile
// error is never "no completion recorded", which would let a recovery skip its
// cool-down), one abort record on the chain's logger and none on
// slog.Default().
func TestPortErrors_RecoveryCooldown(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(cooldownPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name string
		ctx  func(ctx context.Context) context.Context
	}{
		{name: "live"},
		{name: "cancelled", ctx: func(ctx context.Context) context.Context {
			cctx, cancel := context.WithCancel(ctx)
			cancel()

			return cctx
		}},
	}

	kinds := append(redemptionPortErrKinds(),
		loginPortErrKind{
			name: "cycle wrapping context.Canceled",
			err:  &loginCanceledCycle{}, reason: "budget", child: true,
		})

	for _, c := range contexts {
		for _, kind := range kinds {
			row := c.name + "/" + kind.name
			if childRow != "" && childRow != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if kind.child && childRow == "" {
					limiterPortErrInChild(t, cooldownPortErrRowEnv, cooldownPortErrRan, row)

					return
				}

				defaults := swapDefaultLogger(t)

				ctx := t.Context()
				if c.ctx != nil {
					ctx = c.ctx(ctx)
				}

				plainLogs, gotLogs := &capturingHandler{}, &capturingHandler{}

				plain, plainRan, plainLookups := cooldownServe(ctx, t, errRecordStoreDown, slog.New(plainLogs))
				require.Empty(t, abortRecords(plainLogs.records()), "the plain error writes no abort record")
				require.False(t, plainRan, "a store outage never reaches the guarded handler")

				if c.ctx == nil {
					require.Positive(t, plainLookups, "the request reaches the store")
					require.Equal(t, http.StatusInternalServerError, plain.Code)
				}

				got, ran, lookups := cooldownServe(ctx, t, kind.err, slog.New(gotLogs))

				assert.Equal(t, plain.Code, got.Code, "status")
				assert.Equal(t, plain.Header(), got.Header(), "headers")
				assert.Equal(t, plain.Body.String(), got.Body.String(), "body")
				assert.NotContains(t, got.Body.String(), hostileSecret, "the response quotes the error")
				assert.False(t, ran, "a hostile error is never read as no completion recorded")
				assert.Equal(t, plainLookups, lookups, "the store is asked as often")

				aborts := abortRecords(gotLogs.records())
				if kind.reason == "" || lookups == 0 {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, aborts, 1, "one abort record, on the chain's logger")
					assertAbortRecord(t, aborts[0], kind.reason)
				}

				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

				// A consumer reading the returned error with errors.Is must
				// neither hang nor panic, and the verdict is the plain
				// outage's: not a cool-down, not a hang-up.
				cooldownReadWithin(ctx, t, kind.err, slog.New(&capturingHandler{}))

				if childRow != "" && !t.Failed() {
					_, _ = fmt.Fprintln(os.Stdout, cooldownPortErrRan+row)
				}
			})
		}
	}
}
