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
	"regexp"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
)

// rehashPortErrRowEnv names the row a child process of
// TestPortErrors_RehashWrite runs. It is empty in the parent.
const rehashPortErrRowEnv = "SCRTY_HTTPSEC_REHASH_PORTERR_ROW"

// rehashPortErrRan is what a child prints, as a line of its own followed by the
// row's name, once it has run its row to the end.
const rehashPortErrRan = "rehash-porterr-row-ran:"

// rehashValidUntil is the token's expiry in a login's body, which moves with
// the clock and is not something a hostile error could change.
var rehashValidUntil = regexp.MustCompile(`"valid_until":"[^"]*"`)

// rehashOutcome is everything one login with a failing rehash write produced
// that a client can observe, and the records the chain's logger received.
type rehashOutcome struct {
	status   int
	header   http.Header
	body     string
	logs     []slog.Record
	panicked bool
}

// rehashWriteThrough serves a login on the named surface whose password hash
// is outdated, so the rehash write runs and fails with portErr, cancelling the
// request inside the write when asked.
func rehashWriteThrough(t *testing.T, surface string, portErr error, cancelDuring bool) rehashOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, cancelDuring)

	r := newRehashRig(t, rehashOldMemory)
	r.h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

	write := func(context.Context, *identity.Details, []byte, []byte) error {
		onCall()

		return portErr
	}

	var (
		opt httpsec.Option
		req *http.Request
	)

	switch surface {
	case "form login":
		r.h.expectSessionOpened("issued-token")

		opt = httpsec.EnableFormLogin(r.loginDeps(), httpsec.WithLoginRehash(write))
		req = formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password="+rehashPassword)
	default:
		opt = httpsec.EnableBasicAuth(r.basicDeps(), httpsec.WithBasicAuthRehash(write))
		req = basicRequest(ctx, "ada", rehashPassword)
	}

	chain, err := httpsec.New(httpsec.WithLogger(r.h.logger()), opt)
	require.NoError(t, err)

	rec, panicked := stepUpServeWithin(t, chain, req)

	out := rehashOutcome{panicked: panicked, logs: r.h.logs.records()}
	if !panicked {
		out.status, out.header, out.body = rec.Code, rec.Header(),
			rehashValidUntil.ReplaceAllString(rec.Body.String(), `"valid_until":"-"`)
	}

	return out
}

// TestPortErrors_RehashWrite pins that a hostile error from the consumer's
// rehash write, which the login only logs, is answered exactly as a plain
// write failure is: the login's response is unchanged and the same records are
// written. The abort is reported once, to the chain's logger, and not to
// slog.Default(), and no record quotes the error.
//
// The write has no unavailable sentinel and nothing at the site tests one, so
// the fixed error is porterr.ErrUnwalkable, which only the log reads.
func TestPortErrors_RehashWrite(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(rehashPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	plainOutage := errors.New("dependency: connection refused")

	for _, surface := range []string{"form login", "Basic"} {
		for _, cancelDuring := range []bool{false, true} {
			ctxName := "live"
			if cancelDuring {
				ctxName = "cancelled"
			}

			for _, kind := range stepUpPortErrKinds(nil) {
				row := surface + "/" + ctxName + "/" + kind.name
				if childRow != "" && childRow != row {
					continue
				}

				if kind.ctx != "" && kind.ctx != ctxName {
					continue
				}

				t.Run(row, func(t *testing.T) {
					if kind.child && childRow == "" {
						limiterPortErrInChild(t, rehashPortErrRowEnv, rehashPortErrRan, row)

						return
					}

					defaults := swapDefaultLogger(t)

					plain := rehashWriteThrough(t, surface, plainOutage, cancelDuring)
					require.False(t, plain.panicked, "the plain failure does not panic")
					require.Empty(t, abortRecords(plain.logs), "the plain failure writes no abort record")
					require.Contains(t, nonAbortMessages(plain.logs),
						"ERROR httpsec: an upgraded password hash could not be stored", "the plain failure is logged")

					got := rehashWriteThrough(t, surface, kind.err, cancelDuring)
					assert.False(t, got.panicked, "a hostile write error escaped as a panic")
					assert.Equal(t, plain.status, got.status, "status")
					assert.Equal(t, plain.header, got.header, "headers")
					assert.Equal(t, plain.body, got.body, "body")
					assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")

					for _, rec := range got.logs {
						assert.NotContains(t, rec.Message, hostileSecret)
						rec.Attrs(func(a slog.Attr) bool {
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
						fmt.Fprintln(os.Stdout, rehashPortErrRan+row)
					}
				})
			}
		}
	}
}
