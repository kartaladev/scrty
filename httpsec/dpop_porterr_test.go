package httpsec_test

// Every test in this file replaces slog.Default() for its duration, so none of
// them runs in parallel, and each restores the logger it found.

import (
	"context"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/internal/errwalk"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// dpopPortErrRowEnv names the row a child process of TestPortErrors_DPoP runs.
// It is empty in the parent.
const dpopPortErrRowEnv = "SCRTY_HTTPSEC_DPOP_PORTERR_ROW"

// dpopPortErrRan is what a child of TestPortErrors_DPoP prints, as a line of
// its own followed by the row's name, once it has run its row to the end.
const dpopPortErrRan = "dpop-porterr-row-ran:"

// dpopOpenPortErrRowEnv names the row a child process of
// TestPortErrors_DPoPNonceOpen runs. It is empty in the parent.
const dpopOpenPortErrRowEnv = "SCRTY_HTTPSEC_DPOP_OPEN_PORTERR_ROW"

// dpopOpenPortErrRan is what a child of TestPortErrors_DPoPNonceOpen prints, as
// a line of its own followed by the row's name, once it has run its row.
const dpopOpenPortErrRan = "dpop-open-porterr-row-ran:"

// dpopPortSealed is what a healthy mock nonce cipher seals every nonce as.
var dpopPortSealed = []byte("sealed-nonce")

// dpopPortServe builds a chain whose DPoP is d, behind the outcome observer,
// logging to its own capturing logger, and serves one DPoP-bound GET under
// ctx whose proof carries nonce unless it is empty.
func dpopPortServe(t *testing.T, ctx context.Context, d httpsec.DPoP, nonce string, run stepUpRun) stepUpOutcome {
	t.Helper()

	world := newDPoPBearerWorld(t)
	logs := &capturingHandler{}
	returned := &stepUpReturned{}

	chain, err := httpsec.New(
		stepUpObserver(returned, run.swallow),
		httpsec.WithClock(world.clk),
		httpsec.WithLogger(slog.New(logs)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: world.gen, Sessions: world.sessions, Users: world.users}),
		httpsec.EnableDPoP(d),
	)
	require.NoError(t, err)

	key := newDPoPKey(t, elliptic.P256())
	tok := world.token(token.Confirmation{JKT: key.jkt})

	parts := key.validProof("j-1").with(map[string]any{"ath": tokenHash(tok), "iat": world.clk.Now().Unix()})
	if nonce != "" {
		parts = parts.with(map[string]any{"nonce": nonce})
	}

	req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", parts.sign(t)).WithContext(ctx)
	req.Header.Set("Authorization", "DPoP "+tok)

	rec, panicked := stepUpServeWithin(t, chain, req)

	return stepUpOutcomeOf(rec, panicked, nil, "", logs, returned)
}

// dpopStaleNonce is the plaintext of a nonce issued three minutes before
// dpopNow: still accepted under the default five-minute lifetime, and past
// half of it, so an accepted proof carrying it is handed the next nonce.
func dpopStaleNonce() []byte {
	plain := make([]byte, 9)
	plain[0] = 1
	binary.BigEndian.PutUint64(plain[1:], uint64(dpopNow.Add(-3*time.Minute).Unix())) //nolint:gosec // G115: after 1970

	return plain
}

// dpopReplayThrough serves a proof the consumer's replay store fails to
// record, with portErr.
func dpopReplayThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	store := NewMockReplayStore(gomock.NewController(t))
	store.EXPECT().Record(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, string, time.Time) (bool, error) {
			onCall()

			return false, portErr
		})

	return dpopPortServe(t, ctx, httpsec.DPoP{PublicURL: dpopPublicURL, Replay: store}, "", run)
}

// dpopSealRefusedThrough serves a proof carrying no nonce, on a chain whose
// server nonces are on, so the refusal asks for one, and the consumer's nonce
// cipher fails to seal it with portErr.
func dpopSealRefusedThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	cipher := NewMockNonceCipher(gomock.NewController(t))
	cipher.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, []byte, []byte) ([]byte, error) {
			onCall()

			return nil, portErr
		})

	return dpopPortServe(t, ctx, httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: cipher}, "", run)
}

// dpopSealRefreshThrough serves an accepted proof whose nonce is past half its
// lifetime, so the chain refreshes it, and the consumer's nonce cipher fails
// to seal the next one with portErr. The refresh is best effort: the error is
// only logged, and the request is served.
func dpopSealRefreshThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	cipher := NewMockNonceCipher(gomock.NewController(t))
	cipher.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return(dpopStaleNonce(), nil)
	cipher.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, []byte, []byte) ([]byte, error) {
			onCall()

			return nil, portErr
		})

	return dpopPortServe(t, ctx, httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: cipher}, "c2VhbGVk", run)
}

// TestPortErrors_DPoP pins that a hostile error from the consumer's replay
// store, or from its nonce cipher's Seal, is answered exactly as a plain
// outage of that port is: the same status, headers and body through the
// chain, the proof never accepted as fresh, and on a refresh the request
// served without a nonce, as on a plain Seal failure. The error is reported
// once, to the chain's logger and not to slog.Default(), and travels no
// further than the site.
func TestPortErrors_DPoP(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	runStepUpPortErrors(t, dpopPortErrRowEnv, dpopPortErrRan, []stepUpPortSite{
		{name: "the replay store", through: dpopReplayThrough},
		{name: "the nonce seal on a refusal", through: dpopSealRefusedThrough},
		{name: "the nonce seal on a refresh", through: dpopSealRefreshThrough, logOnly: true},
	}, errors.New("dpop dependency: connection refused"))
}

// dpopOpenThrough serves a proof carrying a nonce the consumer's nonce cipher
// fails to open, with portErr. A refusal's next nonce seals as dpopPortSealed.
func dpopOpenThrough(t *testing.T, portErr error, run stepUpRun) stepUpOutcome {
	t.Helper()

	ctx, onCall := requestContext(t, run.cancelDuring)

	cipher := NewMockNonceCipher(gomock.NewController(t))
	cipher.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, []byte, []byte) ([]byte, error) {
			onCall()

			return nil, portErr
		})
	cipher.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return(dpopPortSealed, nil).AnyTimes()

	return dpopPortServe(t, ctx, httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: cipher}, "c2VhbGVk", run)
}

// TestPortErrors_DPoPNonceOpen pins that a hostile error from the consumer's
// nonce cipher's Open is never an accepted nonce, and never a refused one that
// asks the client to retry against the same cipher: it is answered exactly as
// a plain Open outage, one marked session.ErrCipherUnavailable, with one abort
// record on the chain's logger and none on slog.Default(). The error never
// travels past the site: the request fails behind the cipher's unavailable
// sentinel.
//
// Its rows differ from runStepUpPortErrors' in two ways, so it has a runner of
// its own. A typed-nil root walks to the end and is the plain unmarked failure
// it reads as, a refused nonce. And an Is that panics only for the site's
// sentinel, or for the request's own end, is no accepted panic here: the site
// reads the error with the library's bounded walk, which recovers it.
func TestPortErrors_DPoPNonceOpen(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(dpopOpenPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	outage := fmt.Errorf("kms: connection refused: %w", session.ErrCipherUnavailable)
	refused := errors.New("kms: authentication tag mismatch")

	type testCase struct {
		name string
		err  error

		// parity is the plain Open failure the row is answered as.
		parity error

		// reason is the abort record's reason, and "" when the walk completes.
		reason string

		// child runs the row in a child process: an unbounded read of it
		// overflows the stack fatally.
		child bool

		// ctx, when set, restricts the row to the named context.
		ctx string
	}

	cases := []testCase{
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, parity: outage, reason: "budget"},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, parity: outage, reason: "budget", child: true},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, parity: outage, reason: "panic"},
		{name: "Unwrap panicking with nil", err: loginUnwrapPanicsNil{}, parity: outage, reason: "panic"},
		{name: "join fanning out", err: loginFanOut(25), parity: outage, reason: "budget"},
		{
			name: "cycle wrapping context.Canceled", err: &throttleCycleWrapping{sentinel: context.Canceled},
			parity: outage, reason: "budget", child: true, ctx: "cancelled",
		},
		{
			name: "cycle wrapping the site's sentinel", err: &throttleCycleWrapping{sentinel: session.ErrCipherUnavailable},
			parity: outage, reason: "budget", child: true,
		},
		{
			name: "Is panicking only for the site's sentinel", err: stepUpIsPanicsFor{target: session.ErrCipherUnavailable},
			parity: outage, reason: "panic",
		},
		{
			name: "Is panicking only for the request's end", err: stepUpIsPanicsFor{target: context.Canceled},
			parity: outage, reason: "panic", ctx: "cancelled",
		},
		// Walked to the end, so it is read as any plain unmarked failure.
		{name: "typed-nil root", err: (*loginTypedNil)(nil), parity: refused},
	}

	contexts := []struct {
		name         string
		cancelDuring bool
	}{
		{name: "live"},
		{name: "cancelled", cancelDuring: true},
	}

	for _, c := range contexts {
		for _, tc := range cases {
			row := "the nonce open/" + c.name + "/" + tc.name
			if childRow != "" && childRow != row {
				continue
			}

			if tc.ctx != "" && tc.ctx != c.name {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if tc.child && childRow == "" {
					limiterPortErrInChild(t, dpopOpenPortErrRowEnv, dpopOpenPortErrRan, row)

					return
				}

				defaults := swapDefaultLogger(t)

				plain := dpopOpenThrough(t, tc.parity, stepUpRun{cancelDuring: c.cancelDuring})
				require.False(t, plain.panicked, "the plain failure does not panic")
				require.Empty(t, abortRecords(plain.logs), "the plain failure writes no abort record")
				require.GreaterOrEqual(t, plain.status, http.StatusBadRequest, "a plain failure refuses")

				got := dpopOpenThrough(t, tc.err, stepUpRun{cancelDuring: c.cancelDuring})

				assert.False(t, got.panicked, "a hostile port error escaped as a panic")
				assert.Equal(t, plain.status, got.status, "status")
				assert.Equal(t, plain.header, got.header, "headers")
				assert.Equal(t, plain.body, got.body, "body")
				assert.NotContains(t, got.body, hostileSecret, "the response quotes the error")
				assert.Equal(t, nonAbortMessages(plain.logs), nonAbortMessages(got.logs), "the chain's records")
				assert.False(t, got.escaped, "an unwalkable error travelled on past the site")

				aborts := abortRecords(got.logs)
				if tc.reason == "" {
					assert.Empty(t, aborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, aborts, 1, "one abort record, on the chain's logger")
					assertAbortRecord(t, aborts[0], tc.reason)
				}

				// With the chain's dispatch out of the way, the site's own
				// record is the only one.
				alone := dpopOpenThrough(t, tc.err, stepUpRun{cancelDuring: c.cancelDuring, swallow: true})
				assert.False(t, alone.panicked, "a hostile port error escaped as a panic")

				soleAborts := abortRecords(alone.logs)
				if tc.reason == "" {
					assert.Empty(t, soleAborts, "a walk that completes writes no abort record")
				} else {
					require.Len(t, soleAborts, 1, "the site writes the one abort record")
					assertAbortRecord(t, soleAborts[0], tc.reason)
				}

				assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

				if childRow != "" && !t.Failed() {
					fmt.Fprintln(os.Stdout, dpopOpenPortErrRan+row)
				}
			})
		}
	}
}

// dpopWaitersPortErrRowEnv names the row a child process of
// TestPortErrors_DPoPNonceSealWaiters runs. It is empty in the parent.
const dpopWaitersPortErrRowEnv = "SCRTY_HTTPSEC_DPOP_WAITERS_PORTERR_ROW"

// dpopWaitersPortErrRan is what a child of TestPortErrors_DPoPNonceSealWaiters
// prints, as a line of its own followed by the row's name, once it has run its
// row to the end.
const dpopWaitersPortErrRan = "dpop-waiters-porterr-row-ran:"

// dpopSealWaiters is how many requests wait on the one seal in progress,
// besides the request sealing.
const dpopSealWaiters = 3

// msgDPoPNonceFailedText is the record a nonce cipher failure writes.
const msgDPoPNonceFailedText = "httpsec: a DPoP nonce could not be sealed or opened; the nonce cipher failed"

// dpopWaiterResponse is what one request through the shared seal answered.
type dpopWaiterResponse struct {
	status   int
	header   http.Header
	body     string
	panicked bool
}

// dpopSealWaitersOutcome is what every request of one shared seal produced,
// and what the chain's logger received.
type dpopSealWaitersOutcome struct {
	sealer  dpopWaiterResponse
	waiters []dpopWaiterResponse
	logs    []slog.Record

	// escaped counts the requests whose returned error could not be walked.
	escaped int
}

// dpopSealWaiterServe serves req through h, delivering what it answered on
// out. Its name marks the goroutines dpopAwaitSealWaiters counts.
func dpopSealWaiterServe(h http.Handler, req *http.Request, out chan<- dpopWaiterResponse) {
	rec := httptest.NewRecorder()
	returned := false

	defer func() {
		r := dpopWaiterResponse{panicked: !returned}
		if returned {
			r.status, r.header, r.body = rec.Code, rec.Header(), rec.Body.String()
		} else {
			// A panic(nil) recovers as a *runtime.PanicNilError, so returned
			// is what tells a panic apart, not recover's value.
			_ = recover()
		}

		out <- r
	}()

	h.ServeHTTP(rec, req)

	returned = true
}

// dpopAwaitSealWaiters blocks until n goroutines started by
// dpopSealWaiterServe are parked in the nonce issuer's select, waiting on the
// seal in progress, and fails the test if that has not happened within five
// seconds. It reads the goroutines' own stacks: the issuer exposes no hook,
// and a goroutine's stack is where waiting on the seal is observable.
func dpopAwaitSealWaiters(t *testing.T, n int) {
	t.Helper()

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()

	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()

	buf := make([]byte, 1<<20)

	for {
		size := runtime.Stack(buf, true)
		for size == len(buf) {
			buf = make([]byte, 2*len(buf))
			size = runtime.Stack(buf, true)
		}

		parked := 0

		for g := range strings.SplitSeq(string(buf[:size]), "\n\n") {
			header, frames, _ := strings.Cut(g, "\n")
			top, _, _ := strings.Cut(frames, "\n")

			if strings.Contains(header, "[select") &&
				strings.Contains(top, "(*dpopVerifier).issueNonce(") &&
				strings.Contains(g, "dpopSealWaiterServe(") {
				parked++
			}
		}

		if parked == n {
			return
		}

		select {
		case <-tick.C:
		case <-deadline.C:
			require.FailNow(t, "the requests never waited on the seal", "%d of %d parked", parked, n)
		}
	}
}

// dpopSealWaitersThrough serves, on one chain with sampling off, a proof
// carrying no nonce whose seal the consumer's nonce cipher holds, then
// dpopSealWaiters more such proofs, each of which waits on that one seal. Once
// every one waits, the cipher fails the seal with portErr.
func dpopSealWaitersThrough(t *testing.T, portErr error) dpopSealWaitersOutcome {
	t.Helper()

	world := newDPoPBearerWorld(t)
	logs := &capturingHandler{}

	var escaped atomic.Int32

	observe := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		err := next(ex)
		if _, abort := errwalk.Flatten(err); abort != nil {
			escaped.Add(1)
		}

		return err
	})

	entered := make(chan struct{})
	release := make(chan struct{})

	cipher := NewMockNonceCipher(gomock.NewController(t))
	cipher.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Times(1).
		DoAndReturn(func(ctx context.Context, _, _ []byte) ([]byte, error) {
			close(entered)

			select {
			case <-release:
				return nil, portErr
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})

	chain, err := httpsec.New(
		httpsec.RegisterInterceptor(observe, httpsec.Before(httpsec.OrderSecurityHeaders)),
		httpsec.WithClock(world.clk),
		httpsec.WithLogger(slog.New(logs)),
		httpsec.WithRefusalLogInterval(0),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: world.gen, Sessions: world.sessions, Users: world.users}),
		httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL, Nonce: true, NonceCipher: cipher}),
	)
	require.NoError(t, err)

	h := chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	key := newDPoPKey(t, elliptic.P256())
	tok := world.token(token.Confirmation{JKT: key.jkt})

	request := func(i int) *http.Request {
		parts := key.validProof(fmt.Sprintf("j-%d", i)).
			with(map[string]any{"ath": tokenHash(tok), "iat": world.clk.Now().Unix()})
		req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", parts.sign(t)).WithContext(t.Context())
		req.Header.Set("Authorization", "DPoP "+tok)

		return req
	}

	sealerOut := make(chan dpopWaiterResponse, 1)
	go dpopSealWaiterServe(h, request(0), sealerOut)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the first request never began the seal")
	}

	waiterOut := make(chan dpopWaiterResponse, dpopSealWaiters)
	for i := 1; i <= dpopSealWaiters; i++ {
		go dpopSealWaiterServe(h, request(i), waiterOut)
	}

	dpopAwaitSealWaiters(t, dpopSealWaiters)
	close(release)

	collect := func(ch <-chan dpopWaiterResponse) dpopWaiterResponse {
		t.Helper()

		select {
		case r := <-ch:
			return r
		case <-time.After(5 * time.Second):
			require.FailNow(t, "a request hung on the failed seal")

			return dpopWaiterResponse{}
		}
	}

	out := dpopSealWaitersOutcome{sealer: collect(sealerOut)}
	for range dpopSealWaiters {
		out.waiters = append(out.waiters, collect(waiterOut))
	}

	out.logs = logs.records()
	out.escaped = int(escaped.Load())

	return out
}

// sortedNonAbortMessages is nonAbortMessages in a fixed order: concurrent
// requests write theirs in whatever order they run.
func sortedNonAbortMessages(recs []slog.Record) []string {
	msgs := nonAbortMessages(recs)
	slices.Sort(msgs)

	return msgs
}

// TestPortErrors_DPoPNonceSealWaiters pins that requests waiting on a nonce
// seal the consumer's cipher fails with a hostile error are answered exactly
// as when it fails with a plain error: every waiter, and the request sealing,
// gets the same status, headers and body, none panics or hangs, each writes
// the same records, and the error is reported once, by the seal's own
// sanitizer, on the chain's logger and not on slog.Default(). The waiters are
// handed the sanitized fault, never the consumer's error.
func TestPortErrors_DPoPNonceSealWaiters(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	childRow := os.Getenv(dpopWaitersPortErrRowEnv)
	if childRow != "" {
		debug.SetMaxStack(64 << 20)
	}

	plainOutage := errors.New("kms: connection refused")

	type testCase struct {
		name string
		err  error

		// child runs the row in a child process: an unbounded read of it
		// overflows the stack fatally.
		child bool

		assert func(t *testing.T, plain, got dpopSealWaitersOutcome)
	}

	sameAsPlain := func(reason string) func(t *testing.T, plain, got dpopSealWaitersOutcome) {
		return func(t *testing.T, plain, got dpopSealWaitersOutcome) {
			t.Helper()

			require.Len(t, got.waiters, dpopSealWaiters)

			for i, w := range append([]dpopWaiterResponse{got.sealer}, got.waiters...) {
				assert.False(t, w.panicked, "request %d panicked", i)
				assert.Equal(t, plain.sealer.status, w.status, "request %d: status", i)
				assert.Equal(t, plain.sealer.header, w.header, "request %d: headers", i)
				assert.Equal(t, plain.sealer.body, w.body, "request %d: body", i)
				assert.NotContains(t, w.body, hostileSecret, "request %d quotes the error", i)
			}

			assert.Equal(t, sortedNonAbortMessages(plain.logs), sortedNonAbortMessages(got.logs), "the chain's records")
			assert.Zero(t, got.escaped, "an unwalkable error travelled on past the site")

			aborts := abortRecords(got.logs)
			if reason == "" {
				assert.Empty(t, aborts, "a plain failure writes no abort record")

				return
			}

			require.Len(t, aborts, 1, "one abort record for the one seal, on the chain's logger")
			assertAbortRecord(t, aborts[0], reason)
		}
	}

	cases := []testCase{
		{name: "plain error", err: errors.New("kms: throttled"), assert: sameAsPlain("")},
		{name: "self-cycle through Unwrap() error", err: &cycleOne{}, assert: sameAsPlain("budget")},
		{name: "self-cycle through Unwrap() []error", err: &cycleMany{}, child: true, assert: sameAsPlain("budget")},
		{name: "panicking Unwrap", err: loginUnwrapPanics{}, assert: sameAsPlain("panic")},
	}

	for _, tc := range cases {
		row := "the nonce seal waiters/" + tc.name
		if childRow != "" && childRow != row {
			continue
		}

		t.Run(row, func(t *testing.T) {
			if tc.child && childRow == "" {
				limiterPortErrInChild(t, dpopWaitersPortErrRowEnv, dpopWaitersPortErrRan, row)

				return
			}

			defaults := swapDefaultLogger(t)

			plain := dpopSealWaitersThrough(t, plainOutage)
			require.Len(t, plain.waiters, dpopSealWaiters)

			for i, w := range append([]dpopWaiterResponse{plain.sealer}, plain.waiters...) {
				require.False(t, w.panicked, "request %d of the plain failure panicked", i)
				require.Equal(t, http.StatusInternalServerError, w.status, "request %d: a plain seal failure is an outage", i)
				require.Equal(t, plain.sealer.body, w.body, "request %d: every request of a plain failure answers alike", i)
			}

			require.Empty(t, abortRecords(plain.logs), "the plain failure writes no abort record")

			nonceFailed := 0

			for _, r := range plain.logs {
				if r.Message == msgDPoPNonceFailedText {
					nonceFailed++
				}
			}

			require.Equal(t, 1+dpopSealWaiters, nonceFailed, "every request of a plain failure records it, unsampled")

			got := dpopSealWaitersThrough(t, tc.err)
			tc.assert(t, plain, got)

			assert.Empty(t, abortRecords(defaults.records()), "none on slog.Default()")

			if childRow != "" && !t.Failed() {
				fmt.Fprintln(os.Stdout, dpopWaitersPortErrRan+row)
			}
		})
	}
}
