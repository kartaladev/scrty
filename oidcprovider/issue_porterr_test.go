package oidcprovider_test

// TestPortErrors_AccessTokenJTI and TestPortErrors_LogoutTokenJTI pin the two
// callers of the provider's token issuing other than the ID token: a JWT
// access token and a back-channel logout token. Both draw the token's jti from
// the consumer's identifier generator, which the provider sanitizes where the
// error enters. They replace slog.Default() for their duration, so they do not
// run in parallel, and they restore the logger they found.
//
// The key source's and the signer's errors are sanitized in the token package,
// and are rows of TestPortErrors_TokenKeys below: their abort records go to
// the provider's logger, else the chain's.

import (
	"context"
	"crypto"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/ctxlog"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/signingkey"
)

// pe7nRowEnv names the row a child process runs. It is empty in the parent.
const pe7nRowEnv = "SCRTY_OIDCPROVIDER_PE7N_PORTERR_ROW"

// pe7nRanMarker prefixes the line a child prints, followed by the row's name,
// after the row ran and passed.
const pe7nRanMarker = "SCRTY_OIDCPROVIDER_PE7N_PORTERR_RAN: "

// pe7nSite is the site both tables fail: the identifier a signed token's jti
// is drawn from. It is a pe7fSite so the shared hostile rows apply.
const pe7nSite pe7fSite = "the signed token's id.Generator.NewID"

// pe7nIDs mints with a working generator, and fails every identifier asked
// for while armed.
type pe7nIDs struct {
	next  markedIDs
	armed atomic.Bool
	calls atomic.Int32
	err   error
}

func (g *pe7nIDs) NewID() (id.ID, error) {
	if g.armed.Load() {
		g.calls.Add(1)

		return id.ID{}, g.err
	}

	return g.next.NewID()
}

// pe7nOutcome is what one run produced, and what the provider logged.
type pe7nOutcome struct {
	pe7dOutcome

	// answered is whether the exchange answered with tokens.
	answered bool
	// afterOK and afterCode are the exchange sent again with every port working.
	afterOK   bool
	afterCode string

	// reasons are the failure seam's reasons, and handed the tokens a
	// delivery received, for the logout run.
	reasons []string
	handed  int

	aborts     []map[string]any
	failures   []map[string]any
	logText    string
	endErr     error
	shutdownOK bool
}

// pe7nExchange exchanges a code of billing-web, a JWT access token client,
// while the access token's jti fails with portErr, then exchanges it again
// with every port working.
func pe7nExchange(ctx context.Context, t *testing.T, portErr error) pe7nOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ids := &pe7nIDs{err: portErr}

	f := pe7bFixture(t, activeUsers(t), oidcprovider.WithIDGenerator(ids), oidcprovider.WithLogger(logger))
	c := issueCodeFor(t, f, "billing-web", nil, testSignIn(f, "u-1"), "openid", "profile") //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	exchange := billingExchange(c, nil)

	ids.armed.Store(true)

	out := pe7eBounded(t, func() pe7nOutcome {
		res, err := f.p.Token(ctx, exchange)
		o := pe7nOutcome{answered: res != nil}
		o.pe7dOutcome = pe7dClassify(err)

		return o
	})

	ids.armed.Store(false)
	require.Positive(t, ids.calls.Load(), "the exchange reached the token's identifier")

	res, err := f.p.Token(t.Context(), exchange) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
	out.afterOK = res != nil
	out.afterCode = pe7dClassify(err).code

	out.aborts, _ = pe7eAbortsAndLogs(t, logs.String(), "")
	out.logText = logs.String()

	return out
}

// pe7nLogout ends one sign-in whose client listens on its back channel while
// the logout token's jti fails with portErr, and waits for the pool.
func pe7nLogout(ctx context.Context, t *testing.T, portErr error) pe7nOutcome {
	t.Helper()

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ids := &pe7nIDs{err: portErr}
	delivered := &logoutRecorder{}

	x := newEnding(t, []oidcprovider.Client{listeningClient("billing-web", billingBackChannel)}, nil,
		oidcprovider.WithLogoutDelivery(delivered), oidcprovider.WithIDGenerator(ids), oidcprovider.WithLogger(logger))

	family, err := id.NewV7Generator().NewID()
	require.NoError(t, err)
	x.grants.push(family, []oidcprovider.Grant{{ClientID: "billing-web", User: "u-1", SignInFamily: family}})

	ids.armed.Store(true)

	out := pe7eBounded(t, func() pe7nOutcome {
		var o pe7nOutcome

		_, o.endErr = x.p.EndSignIn(ctx, oidcprovider.SignInSelector{Family: family})

		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Second)
		defer cancel()

		o.shutdownOK = x.p.Shutdown(shutdown) == nil

		return o
	})

	require.Positive(t, ids.calls.Load(), "the delivery reached the token's identifier")

	for _, f := range x.failed() {
		out.reasons = append(out.reasons, f.Reason)
		out.unwalkable = out.unwalkable || errors.Is(f.Err, porterr.ErrUnwalkable)
	}

	out.handed = len(delivered.handed())
	out.aborts, out.failures = pe7eAbortsAndLogs(t, logs.String(), pe7kDeliveryFailed)
	out.logText = logs.String()

	return out
}

// pe7nTable runs every hostile row, a typed-nil root and a plain outage of the
// identifier generator through run, against a plain outage of the same port.
func pe7nTable(t *testing.T, run func(context.Context, *testing.T, error) pe7nOutcome, precondition func(*testing.T, pe7nOutcome),
	same func(*testing.T, pe7nOutcome, pe7nOutcome),
) {
	t.Helper()

	only := os.Getenv(pe7nRowEnv)
	if only != "" {
		debug.SetMaxStack(64 << 20)
	}

	type testCase struct {
		name   string
		err    error
		child  bool
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, plain, got pe7nOutcome)
	}

	asOutage := func(reason string) func(*testing.T, pe7nOutcome, pe7nOutcome) {
		return func(t *testing.T, plain, got pe7nOutcome) {
			t.Helper()

			same(t, plain, got)
			assert.True(t, got.unwalkable, "the failure carries the sanitizer's fault")
			pe7eOneAbort(t, got.aborts, got.failures, reason)
			assert.NotContains(t, got.logText, pe7bSecret, "the provider's log never carries the hostile error's text")
		}
	}

	walked := func(t *testing.T, plain, got pe7nOutcome) {
		t.Helper()

		same(t, plain, got)
		assert.Empty(t, got.aborts, "a walk that completes writes no abort record")
	}

	prefix := string(pe7nSite) + ": "

	var cases []testCase

	for _, row := range pe7fRows() {
		tc := testCase{name: prefix + row.name, err: row.err(pe7nSite), child: row.child, assert: asOutage(row.reason)}
		if row.cancel {
			tc.ctx = pe7eCancelled
		}

		cases = append(cases, tc)
	}

	cases = append(cases,
		testCase{
			name: prefix + "a typed-nil root walks to the end and is answered as an outage",
			err:  (*pe7bTypedNil)(nil), assert: walked,
		},
		testCase{name: prefix + "a plain outage, against itself", err: errPe7bDown, assert: walked},
	)

	for _, tc := range cases {
		if only != "" && only != tc.name {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			if tc.child && only == "" {
				pe7nInChild(t, tc.name)

				return
			}

			defaults := pe7cSwapDefault(t)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			plain := run(ctx, t, errPe7bDown)
			precondition(t, plain)
			require.Empty(t, plain.aborts, "a plain outage writes no abort record")

			got := run(ctx, t, tc.err)
			tc.assert(t, plain, got)

			pe7cNoDefaultAbort(t, defaults)

			if only != "" && !t.Failed() {
				// Stdout, so the parent's CombinedOutput carries it.
				_, _ = os.Stdout.WriteString(pe7nRanMarker + tc.name + "\n")
			}
		})
	}
}

// TestPortErrors_AccessTokenJTI pins that the identifier a JWT access token's
// jti is drawn from, failing with an error whose chain cannot be walked, is
// answered as a plain outage of the generator is: no token, a dependency
// failure with the same fixed text, never a protocol refusal, and the code
// still redeemable once the generator works. The sanitizer writes one record,
// to the provider's logger, and none to slog.Default().
func TestPortErrors_AccessTokenJTI(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	pe7nTable(t, pe7nExchange,
		func(t *testing.T, plain pe7nOutcome) {
			t.Helper()

			require.True(t, plain.dependency, "precondition: a plain outage is a dependency failure")
			require.Empty(t, plain.code, "precondition: a plain outage is no protocol refusal")
			require.False(t, plain.answered, "precondition: a plain outage answers nothing")
			require.Contains(t, plain.text, "sign the access token", "precondition: the access token's jti failed")
		},
		func(t *testing.T, plain, got pe7nOutcome) {
			t.Helper()

			assert.Equal(t, plain.answered, got.answered, "no tokens, as after a plain outage")
			assert.Equal(t, plain.dependency, got.dependency, "the same dependency class")
			assert.Equal(t, plain.text, got.text, "the same fixed text")
			assert.Equal(t, plain.notFound, got.notFound)
			assert.Equal(t, plain.canceled, got.canceled)
			assert.Equal(t, plain.code, got.code, "never a protocol refusal")
			assert.Equal(t, plain.afterOK, got.afterOK, "the code answered afterwards as after a plain outage")
			assert.Equal(t, plain.afterCode, got.afterCode)
			assert.True(t, got.afterOK, "the code is still redeemable")
			assert.NotContains(t, got.text, pe7bSecret)
		})
}

// TestPortErrors_LogoutTokenJTI pins that the identifier a back-channel logout
// token's jti is drawn from, failing with an error whose chain cannot be
// walked, is reported as a plain outage of the generator is: one failed
// delivery, reason "sign", nothing handed to the delivery, and an end that
// succeeds. The sanitizer writes one record, to the provider's logger, and none
// to slog.Default().
func TestPortErrors_LogoutTokenJTI(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	pe7nTable(t, pe7nLogout,
		func(t *testing.T, plain pe7nOutcome) {
			t.Helper()

			require.Equal(t, []string{"sign"}, plain.reasons, "precondition: a plain outage is a failed signing")
			require.Len(t, plain.failures, 1, "precondition: a plain outage is logged once")
			require.Zero(t, plain.handed, "precondition: no token is handed on")
		},
		func(t *testing.T, plain, got pe7nOutcome) {
			t.Helper()

			require.NoError(t, got.endErr, "whatever becomes of its delivery, an end succeeds")
			require.True(t, got.shutdownOK, "the pool finished")
			assert.Equal(t, plain.reasons, got.reasons, "the same failure, for the same reason")
			assert.Len(t, got.failures, len(plain.failures), "the same failure records")
			assert.Zero(t, got.handed, "no token is handed on")
		})
}

// pe7nKeys is the exchange's key source with a failing key source or a
// failing signer, for the two sanitizers of the token package that sit under
// the provider's token issuing.
type pe7nKeys struct {
	*exchangeKeys

	// sourceErr is what Signer answers with, when set.
	sourceErr error
	// signErr is what the signer's Sign answers with, when set.
	signErr error
}

func (k pe7nKeys) Signer(ctx context.Context, alg signingkey.Alg) (string, crypto.Signer, error) {
	if k.sourceErr != nil {
		return "", nil, k.sourceErr
	}

	kid, signer, err := k.exchangeKeys.Signer(ctx, alg)
	if err != nil || k.signErr == nil {
		return kid, signer, err
	}

	return kid, pe7nFailingSigner{Signer: signer, err: k.signErr}, nil
}

// pe7nFailingSigner signs with an error.
type pe7nFailingSigner struct {
	crypto.Signer

	err error
}

func (s pe7nFailingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

// TestPortErrors_TokenKeys pins that the key source's and the signer's errors,
// sanitized in the token package, write their abort record where the provider's
// records go: the logger of the chain handling the request when the provider
// was given none, the provider's own logger when it was, and never
// slog.Default() while either is set. A plain outage of either writes no abort
// record. It replaces slog.Default() for its duration, so it does not run in
// parallel.
func TestPortErrors_TokenKeys(t *testing.T) { //nolint:paralleltest // it replaces slog.Default()
	type testCase struct {
		name string
		keys func(k *exchangeKeys, portErr error) pe7nKeys
		// own gives the provider its own logger, beside the chain's.
		own bool
		// plain fails the port with a plain outage instead of the hostile error.
		plain  bool
		assert func(t *testing.T, own, chain, def *lockedBuffer)
	}

	source := func(k *exchangeKeys, err error) pe7nKeys { return pe7nKeys{exchangeKeys: k, sourceErr: err} }
	signer := func(k *exchangeKeys, err error) pe7nKeys { return pe7nKeys{exchangeKeys: k, signErr: err} }

	inChain := func(t *testing.T, _, chain, def *lockedBuffer) {
		t.Helper()
		assert.Len(t, lrAborts(t, chain), 1, "the chain's logger takes the record")
		assert.Empty(t, lrAborts(t, def), "the default logger must see no abort record")
	}
	inOwn := func(t *testing.T, own, chain, def *lockedBuffer) {
		t.Helper()
		assert.Len(t, lrAborts(t, own), 1, "the provider's own logger takes the record")
		assert.Empty(t, lrAborts(t, chain))
		assert.Empty(t, lrAborts(t, def))
	}
	nowhere := func(t *testing.T, own, chain, def *lockedBuffer) {
		t.Helper()
		assert.Empty(t, lrAborts(t, own))
		assert.Empty(t, lrAborts(t, chain))
		assert.Empty(t, lrAborts(t, def))
	}

	cases := []testCase{
		{name: "key source, inside a configured chain", keys: source, assert: inChain},
		{name: "key source, own option wins", keys: source, own: true, assert: inOwn},
		{name: "signer, inside a configured chain", keys: signer, assert: inChain},
		{name: "signer, own option wins", keys: signer, own: true, assert: inOwn},
		{name: "key source, a plain outage", keys: source, plain: true, assert: nowhere},
		{name: "signer, a plain outage", keys: signer, plain: true, assert: nowhere},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			own, chain, def := &lockedBuffer{}, &lockedBuffer{}, &lockedBuffer{}

			previous := slog.Default()
			slog.SetDefault(lrJSON(def))
			t.Cleanup(func() { slog.SetDefault(previous) })

			portErr := error(&pe7bCycleOne{})
			if tc.plain {
				portErr = errPe7bDown
			}

			var opts []oidcprovider.Option
			if tc.own {
				opts = append(opts, oidcprovider.WithLogger(lrJSON(own)))
			}

			f := pe7bFixtureKeys(t, tc.keys(newExchangeKeys(t), portErr), activeUsers(t), opts...)
			c := issueCodeFor(t, f, "billing-web", nil, testSignIn(f, "u-1"), "openid", "profile")

			ctx := ctxlog.With(t.Context(), lrJSON(chain))

			_, err := f.p.Token(ctx, billingExchange(c, nil))
			require.Error(t, err, "the key source or the signer failed, so no token")

			tc.assert(t, own, chain, def)
		})
	}
}

// pe7nInChild re-runs the current top-level test in a child process limited
// to row, and fails unless it exits 0 within a minute and prints the marker
// that shows it ran the row: a stack overflow is fatal and only a child can
// watch for one.
func pe7nInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), pe7nRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	// One whole line must equal the marker: a child whose row matched no case
	// exits 0 having run nothing.
	want := pe7nRanMarker + row
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q: no line equals %q; output:\n%s", row, want, out)
}
