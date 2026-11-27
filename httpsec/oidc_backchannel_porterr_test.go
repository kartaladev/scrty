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
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/porterr"
)

// backchannelPortErrRowEnv names the row a child process runs. It is empty in
// the parent.
const backchannelPortErrRowEnv = "SCRTY_HTTPSEC_BACKCHANNEL_PORTERR_ROW"

// backchannelPortErrRan is what a child prints, as a line of its own followed
// by the row's name, once it has run its row to the end.
const backchannelPortErrRan = "backchannel-porterr-row-ran:"

// backchannelLinkNotFoundCycle wraps oidc.ErrLinkNotFound and itself through
// Unwrap() []error: errors.Is finds the sentinel before it loops, so an
// unsanitized walk reads it as an unlinked subject.
type backchannelLinkNotFoundCycle struct{}

func (*backchannelLinkNotFoundCycle) Error() string { return hostileSecret }
func (c *backchannelLinkNotFoundCycle) Unwrap() []error {
	return []error{oidc.ErrLinkNotFound, c}
}

// backchannelLinkNotFoundClaim claims oidc.ErrLinkNotFound through its own Is
// and unwraps to itself: errors.Is asks Is before it follows the cycle.
type backchannelLinkNotFoundClaim struct{}

func (*backchannelLinkNotFoundClaim) Error() string   { return hostileSecret }
func (c *backchannelLinkNotFoundClaim) Unwrap() error { return c }
func (*backchannelLinkNotFoundClaim) Is(target error) bool {
	return target == oidc.ErrLinkNotFound //nolint:errorlint // identity of a sentinel
}

// backchannelPortOutcome is what one back-channel logout produced that the
// provider or the user's sessions can observe, and the records the chain's
// logger received.
type backchannelPortOutcome struct {
	status int
	header http.Header
	body   string

	// alive is whether the linked user's federated session survived.
	alive bool

	// The error the chain returned, classified inside the bound.
	errStatus             int
	notFound, canceled    bool
	unwalkable, returnErr bool

	chainLogs, errLogs []slog.Record
}

// backchannelPortChain builds a chain whose link store answers every lookup
// with (nil, portErr), with one federated session of the linked user, and the
// chain logging to logs.
func backchannelPortChain(
	t *testing.T, portErr error, logs *capturingHandler,
) (*backchannelHarness, *httpsec.Chain) {
	t.Helper()

	h := newBackchannelHarness(t)

	ctrl := gomock.NewController(t)
	links := NewMockLinkStore(ctrl)
	links.EXPECT().FindByExternal(gomock.Any(), testOIDCProvider, h.issuer(), oidcTestSubject).
		Return(nil, portErr).Times(1)

	broker, err := oidc.NewBroker(links, NewMockUserLoader(ctrl))
	require.NoError(t, err)

	h.manager = h.managerWith(t, broker, nil, oidc.WithClock(h.clock))
	h.federated(t, "federated", testOIDCProvider, h.issuer(), "abc")

	c, err := httpsec.New(
		httpsec.WithLogger(slog.New(logs)),
		httpsec.WithRefusalLogInterval(0),
		httpsec.EnableOIDCLogin(httpsec.OIDCDeps{RelyingParty: h.manager, Handoff: h.handoffs},
			httpsec.WithOIDCTokens(h.tokens),
			httpsec.WithOIDCSessions(h.sessions)),
	)
	require.NoError(t, err)

	return h, c
}

// backchannelPortRequest is a subject-only logout delivery on a context that
// is cancelled during verification when cancel is set.
func backchannelPortRequest(t *testing.T, h *backchannelHarness, cancel bool) *http.Request {
	t.Helper()

	token := h.provider.logoutToken(t, oidcTestSubject, "")

	ctx := t.Context()
	if cancel {
		cctx, stop := context.WithCancel(ctx)
		ctx = cctx

		f := func() { stop() }
		h.clock.onRead.Store(&f)
	}

	return backchannelRequest(ctx, testOIDCProvider, "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
}

// backchannelLogoutThrough delivers one subject-only logout through the
// chain's net/http middleware, then once more through the chain's own run on a
// fresh harness, classifying the returned error inside a bound.
func backchannelLogoutThrough(t *testing.T, portErr error, cancel bool) backchannelPortOutcome {
	t.Helper()

	var out backchannelPortOutcome

	chainLogs := &capturingHandler{}
	h, c := backchannelPortChain(t, portErr, chainLogs)

	rec := loginServeWithin(t, c, backchannelPortRequest(t, h, cancel))
	out.status, out.header, out.body = rec.Code, rec.Header(), rec.Body.String()
	out.alive = h.alive(t, "federated")
	out.chainLogs = chainLogs.records()

	errLogs := &capturingHandler{}
	h2, c2 := backchannelPortChain(t, portErr, errLogs)
	req := backchannelPortRequest(t, h2, cancel)

	type result struct {
		out      backchannelPortOutcome
		panicked bool
		value    any
	}

	done := make(chan result, 1)

	go func() {
		var r result

		returned := false

		defer func() {
			if !returned {
				r.panicked, r.value = true, recover()
			}

			done <- r
		}()

		run := c2.Assemble(func(*httpsec.Exchange) error { return nil })
		ex := httpsec.NewExchange(req.Context(), httpsec.NewHTTPRequest(req),
			httpsec.NewHTTPResponseWriter(httptest.NewRecorder()))
		err := run(ex)

		r.out.returnErr = err != nil
		r.out.errStatus = httpsec.StatusForError(err)
		r.out.notFound = errors.Is(err, oidc.ErrLinkNotFound)
		r.out.canceled = errors.Is(err, context.Canceled)
		r.out.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
		returned = true
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "a hostile link store error escaped as a panic: %v", r.value)

		out.errStatus, out.returnErr = r.out.errStatus, r.out.returnErr
		out.notFound, out.canceled, out.unwalkable = r.out.notFound, r.out.canceled, r.out.unwalkable
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a hostile link store error hung the classification of the returned error")
	}

	out.errLogs = errLogs.records()

	return out
}

type backchannelPortErrKind struct {
	name string
	err  error

	// reason is the abort record's reason, and "" when the walk completes.
	reason string

	// child runs the row in a child process: unsanitized, it overflows the
	// stack fatally.
	child bool
}

func backchannelPortErrKinds() []backchannelPortErrKind {
	return []backchannelPortErrKind{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), reason: "budget"},
		// The shapes the stdlib reads as an unlinked subject: unsanitized,
		// the logout is answered 200 and ends nothing.
		{name: "cycle wrapping ErrLinkNotFound", err: &backchannelLinkNotFoundCycle{}, reason: "budget", child: true},
		{name: "cycle claiming ErrLinkNotFound through Is", err: &backchannelLinkNotFoundClaim{}, reason: "budget"},
		// Read unsanitized as the caller's hang-up.
		{name: "cycle wrapping context.Canceled", err: &loginCanceledCycle{}, reason: "budget", child: true},
		// Walked to the end, so it passes unchanged and is answered as any
		// plain link store error.
		{name: "typed-nil root", err: (*loginTypedNil)(nil)},
	}
}

// TestPortErrors_BackchannelLinkStore pins that a link store error a
// back-channel logout meets while resolving the token's subject is answered
// exactly as a plain link store outage, whether or not its chain can be
// walked: the same status, headers and body, the same returned error class,
// and the user's sessions left as the outage leaves them. A fault never reads
// as an unlinked subject, which would answer 200 and silently end nothing. Each
// abort is reported once, on the chain's logger, and none to slog.Default().
func TestPortErrors_BackchannelLinkStore(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(backchannelPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	contexts := []struct {
		name   string
		cancel bool
	}{
		{name: "live"},
		{name: "caller gone during verification", cancel: true},
	}

	plainOutage := errors.New("oidc_backchannel_porterr_test: link store unavailable")

	for _, c := range contexts {
		for _, kind := range backchannelPortErrKinds() {
			row := c.name + "/" + kind.name
			if childRow != "" && childRow != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if kind.child && childRow == "" {
					backchannelPortErrInChild(t, row)

					return
				}

				defaults := swapDefaultLogger(t)

				plain := backchannelLogoutThrough(t, plainOutage, c.cancel)
				require.GreaterOrEqual(t, plain.status, http.StatusInternalServerError, "the plain outage is a server failure")
				require.True(t, plain.alive, "the plain outage ends nothing")
				require.Empty(t, abortRecords(plain.chainLogs), "the plain error writes no abort record")

				got := backchannelLogoutThrough(t, kind.err, c.cancel)

				assert.Equal(t, plain.status, got.status, "status")
				assert.Equal(t, plain.header, got.header, "headers")
				assert.Equal(t, plain.body, got.body, "body")
				assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
				assert.Equal(t, plain.alive, got.alive, "the sessions left alive")

				assert.True(t, got.returnErr, "the chain returned an error")
				assert.Equal(t, plain.errStatus, got.errStatus, "the returned error's status")
				assert.False(t, got.notFound, "a fault reads as an unlinked subject")
				assert.False(t, got.canceled, "a fault reads as the caller's hang-up")
				assert.Equal(t, kind.reason != "", got.unwalkable, "the fault matches ErrUnwalkable")

				for _, logs := range [][]slog.Record{got.chainLogs, got.errLogs} {
					aborts := abortRecords(logs)
					if kind.reason == "" {
						assert.Empty(t, aborts, "a walk that completes writes no abort record")

						continue
					}

					if assert.Len(t, aborts, 1, "one abort record, on the chain's logger") {
						assertAbortRecord(t, aborts[0], kind.reason)
					}
				}

				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

				if childRow != "" && !t.Failed() {
					_, _ = fmt.Fprintln(os.Stdout, backchannelPortErrRan+row)
				}
			})
		}
	}
}

// backchannelPortErrInChild re-runs the current top-level test in a child
// process limited to row, and fails unless it exits 0 within a minute having
// printed the row's marker as a whole line: a stack overflow is fatal and only
// a child can watch for one, and a row name that matched nothing would
// otherwise pass without running.
// It goes through limiterPortErrInChild, so it marks t parallel, and its
// callers are bound by that helper's contract.
func backchannelPortErrInChild(t *testing.T, row string) {
	t.Helper()

	limiterPortErrInChild(t, backchannelPortErrRowEnv, backchannelPortErrRan, row)
}
