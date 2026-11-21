package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// logoutPortErrRowEnv names the row a child process of
// TestPortErrors_LogoutEndSessionURL runs. It is empty in the parent.
const logoutPortErrRowEnv = "SCRTY_HTTPSEC_LOGOUT_PORTERR_ROW"

// logoutPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const logoutPortErrRan = "logout-porterr-row-ran:"

// logoutOutcome is everything one logout through a failing end-session step
// produced that a client can observe, and the records the chain's logger
// received.
type logoutOutcome struct {
	status   int
	header   http.Header
	body     string
	logs     []slog.Record
	panicked bool
}

// logoutEndSessionThrough serves a federated logout whose end-session step
// fails with portErr, cancelling the request inside the call when asked.
func logoutEndSessionThrough(t *testing.T, portErr error, cancelDuring bool) logoutOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, cancelDuring)

	h := newAuthHarness(t)
	h.expectVerified()
	h.expectResolvedSession(federatedSession())
	h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(1, nil)

	b := NewMockEndSessionBuilder(gomock.NewController(t))
	b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, *session.Session, string) (string, error) {
			onCall()

			return "", portErr
		})

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.EnableBearerToken(h.bearerTokenDeps()),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions, EndSession: b}),
	)
	require.NoError(t, err)

	rec, panicked := stepUpServeWithin(t, chain, logoutFormRequest(ctx, url.Values{"state": {"s-1"}}))

	out := logoutOutcome{panicked: panicked, logs: h.logs.records()}
	if !panicked {
		out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	}

	return out
}

// TestPortErrors_LogoutEndSessionURL pins that a hostile error from the
// end-session step, which logout only logs, is answered exactly as a plain
// outage of the step is: the logout still succeeds with the same empty 200,
// and the same warning is logged. The abort is reported once, to the chain's
// logger, and not to slog.Default(), and no record quotes the error.
//
// The step has no unavailable sentinel and nothing at the site tests one, so
// the fixed error is porterr.ErrUnwalkable, which only the log reads.
func TestPortErrors_LogoutEndSessionURL(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(logoutPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	plainOutage := errors.New("dependency: connection refused")

	for _, cancelDuring := range []bool{false, true} {
		ctxName := "live"
		if cancelDuring {
			ctxName = "cancelled"
		}

		for _, kind := range stepUpPortErrKinds(nil) {
			row := ctxName + "/" + kind.name
			if childRow != "" && childRow != row {
				continue
			}

			if kind.ctx != "" && kind.ctx != ctxName {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if kind.child && childRow == "" {
					limiterPortErrInChild(t, logoutPortErrRowEnv, logoutPortErrRan, row)

					return
				}

				defaults := swapDefaultLogger(t)

				plain := logoutEndSessionThrough(t, plainOutage, cancelDuring)
				require.False(t, plain.panicked, "the plain outage does not panic")
				require.Empty(t, abortRecords(plain.logs), "the plain outage writes no abort record")
				require.Equal(t, http.StatusOK, plain.status, "the logout still succeeds")
				require.Len(t, nonAbortMessages(plain.logs), 1, "the plain outage is warned of once")

				got := logoutEndSessionThrough(t, kind.err, cancelDuring)
				assert.False(t, got.panicked, "a hostile port error escaped as a panic")
				assert.Equal(t, plain.status, got.status, "status")
				assert.Equal(t, plain.header, got.header, "headers")
				assert.Equal(t, plain.body, got.body, "body")
				assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")

				for _, r := range got.logs {
					assert.NotContains(t, r.Message, hostileSecret)
					r.Attrs(func(a slog.Attr) bool {
						assert.NotContains(t, a.Value.String(), hostileSecret, "attribute %q quotes the error", a.Key)

						return true
					})
				}

				aborts := abortRecords(got.logs)
				if kind.reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, aborts, 1, "one abort record, on the chain's logger")
					assertAbortRecord(t, aborts[0], kind.reason)
				}

				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

				if childRow != "" && !t.Failed() {
					_, _ = fmt.Fprintln(os.Stdout, logoutPortErrRan+row)
				}
			})
		}
	}
}
