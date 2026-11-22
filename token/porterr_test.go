package token_test

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/token"
	"github.com/kartaladev/scrty/token/signingkey"
)

// The port errors of this package: the consumer's KeySource (Signer and
// VerificationKeys) and the crypto.Signer it hands over. Each row drives a
// site with an error the library cannot walk and compares what a caller sees
// with what a plain outage of the same port gives.

// tpeSecret stands for the consumer's own text: it must reach no returned
// error and no record.
const tpeSecret = "tpe-consumer-secret-do-not-leak" //nolint:gosec // G101: a fixture, not a credential

// tpeCycleOne's Unwrap returns itself.
type tpeCycleOne struct{}

func (*tpeCycleOne) Error() string   { return "cycle one: " + tpeSecret }
func (c *tpeCycleOne) Unwrap() error { return c }

// tpeCycleMany's Unwrap() []error contains itself: unprotected, stdlib's
// errors.Is overflows the stack, fatally.
type tpeCycleMany struct{}

func (*tpeCycleMany) Error() string     { return "cycle many: " + tpeSecret }
func (c *tpeCycleMany) Unwrap() []error { return []error{c} }

// tpeClaimCycle is a cycle that also claims, through its Is method, to be one
// sentinel: stdlib errors.Is believes it at the first node.
type tpeClaimCycle struct{ claim error }

func (*tpeClaimCycle) Error() string          { return "claiming cycle: " + tpeSecret }
func (c *tpeClaimCycle) Unwrap() error        { return c }
func (c *tpeClaimCycle) Is(target error) bool { return target == c.claim } //nolint:errorlint // identity

// tpePanicUnwrap's Unwrap panics with a value carrying the consumer's text.
type tpePanicUnwrap struct{}

func (tpePanicUnwrap) Error() string { return "panic unwrap: " + tpeSecret }
func (tpePanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + tpeSecret) }

// tpePanicNil's Unwrap calls panic(nil).
type tpePanicNil struct{}

func (tpePanicNil) Error() string { return "panic nil: " + tpeSecret }
func (tpePanicNil) Unwrap() error { panic(nil) }

// tpeTypedNil is returned as a typed nil; its methods never dereference the
// receiver, so only the library could make it panic.
type tpeTypedNil struct{}

func (*tpeTypedNil) Error() string { return "typed nil: " + tpeSecret }

// tpeFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func tpeFanOut(depth int) error {
	err := errors.New("fan-out leaf: " + tpeSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// tpeRecorder keeps every record it is handed.
type tpeRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (*tpeRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *tpeRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.records = append(r.records, rec.Clone())

	return nil
}

func (r *tpeRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *tpeRecorder) WithGroup(string) slog.Handler      { return r }

// aborts counts the abort records written that name a reason.
func (r *tpeRecorder) aborts() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := 0
	for _, rec := range r.records {
		if rec.Message != porterr.MsgClassificationAborted {
			continue
		}
		rec.Attrs(func(a slog.Attr) bool {
			if a.Key == "reason" {
				n++

				return false
			}

			return true
		})
	}

	return n
}

// texts returns every record's message and attributes as text.
func (r *tpeRecorder) texts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]string, 0, len(r.records))
	for _, rec := range r.records {
		var b strings.Builder
		b.WriteString(rec.Message)
		rec.Attrs(func(a slog.Attr) bool {
			b.WriteString(" " + a.String())

			return true
		})
		out = append(out, b.String())
	}

	return out
}

// tpeSwapDefault routes slog.Default() to a recorder until the test ends.
func tpeSwapDefault(t *testing.T) *tpeRecorder {
	t.Helper()

	rec := new(tpeRecorder)
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return rec
}

// tpeOutcome is what a caller of a site can see, read inside the bound, so a
// check that would hang on a hostile error hangs the bound instead of the
// test.
type tpeOutcome struct {
	failed     bool
	issued     bool // a token string came back
	verified   bool // claims came back: the verification passed
	invalid    bool // token.ErrInvalid: the verdict on a presented token
	noKey      bool // signingkey.ErrNoKey: "no current key for algorithm"
	noKeys     bool // token.ErrNoVerificationKeys
	unwalkable bool // porterr.ErrUnwalkable: only a sanitized fault
	text       string
	err        error // the error itself, for the reachability rows only
}

func tpeClassify(raw string, claims *token.Claims, err error) tpeOutcome {
	o := tpeOutcome{failed: err != nil, issued: raw != "", verified: claims != nil}
	if err == nil {
		return o
	}

	o.invalid = errors.Is(err, token.ErrInvalid)
	o.noKey = errors.Is(err, signingkey.ErrNoKey)
	o.noKeys = errors.Is(err, token.ErrNoVerificationKeys)
	o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
	o.text = err.Error()
	o.err = err

	return o
}

// tpeWithin runs call on its own goroutine and fails the test when it does
// not return within two seconds or lets a panic escape.
func tpeWithin(t *testing.T, call func() tpeOutcome) tpeOutcome {
	t.Helper()

	type result struct {
		got      tpeOutcome
		panicked bool
		value    any
	}

	done := make(chan result, 1)
	go func() {
		r := result{panicked: true}
		defer func() {
			if r.panicked {
				r.value = recover()
			}
			done <- r
		}()
		r.got = call()
		r.panicked = false
	}()

	select {
	case r := <-done:
		require.False(t, r.panicked, "the call panicked: %T", r.value)

		return r.got
	case <-time.After(2 * time.Second):
		require.FailNow(t, "the call did not return within 2s")

		return tpeOutcome{}
	}
}

// tpeFailingSigner is a consumer's crypto.Signer over a real key whose Sign
// fails with err.
type tpeFailingSigner struct {
	crypto.Signer

	err error
}

func (s tpeFailingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

// tpeIssue is a request an Issuer accepts in every respect.
func tpeIssue() token.Issue {
	return token.Issue{
		Type:     token.TypeAccessToken,
		Subject:  "u-1",
		ID:       "j-1",
		Audience: []string{"orders-api"},
	}
}

func tpeGenerator(t *testing.T, keys signingkey.KeySource) *token.JWTGenerator {
	t.Helper()

	gen, err := token.NewGenerator(keys,
		token.WithIssuer("https://issuer.example"), token.WithAudience("orders-api"))
	require.NoError(t, err)

	return gen
}

func tpeIssuer(t *testing.T, keys signingkey.KeySource) *token.Issuer {
	t.Helper()

	iss, err := token.NewIssuer(keys, signingkey.RS256, "https://issuer.example")
	require.NoError(t, err)

	return iss
}

// tpeFailingSignerSource is a key source whose signer is a real RS256 key
// that fails to sign with err.
func tpeFailingSignerSource(t *testing.T, err error) signingkey.KeySource {
	t.Helper()

	kid, key, signerErr := newKeySource(t).Signer(t.Context(), signingkey.RS256)
	require.NoError(t, signerErr)

	keys := NewMockKeySource(gomock.NewController(t))
	keys.EXPECT().Signer(gomock.Any(), signingkey.RS256).
		Return(kid, tpeFailingSigner{Signer: key, err: err}, nil).Times(1)

	return keys
}

// tpeSite is one port call: run arranges the port to fail with err and drives
// the flow that reaches it, classifying what its caller sees.
type tpeSite struct {
	name string
	run  func(t *testing.T, ctx context.Context, err error) tpeOutcome
}

func tpeSites() []tpeSite {
	return []tpeSite{
		{name: "Verify asks the key source for its key set",
			run: func(t *testing.T, ctx context.Context, err error) tpeOutcome {
				raw := signClaims(t, newKeySource(t), validClaims(time.Now())) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().VerificationKeys(gomock.Any()).Return(nil, err).Times(1)

				v, newErr := token.NewVerifier(token.WithVerifyKeySource(keys),
					token.WithoutVerifyIssuer(), token.WithoutVerifyAudience())
				require.NoError(t, newErr)

				return tpeWithin(t, func() tpeOutcome {
					claims, got := v.Verify(ctx, raw)

					return tpeClassify("", claims, got)
				})
			}},
		{name: "Generate asks the key source for a signer",
			run: func(t *testing.T, ctx context.Context, err error) tpeOutcome {
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().Signer(gomock.Any(), signingkey.RS256).Return("", nil, err).Times(1)
				gen := tpeGenerator(t, keys)

				return tpeWithin(t, func() tpeOutcome {
					raw, got := gen.Generate(ctx, "jti-1", alice())

					return tpeClassify(raw, nil, got)
				})
			}},
		{name: "Issue asks the key source for a signer",
			run: func(t *testing.T, ctx context.Context, err error) tpeOutcome {
				keys := NewMockKeySource(gomock.NewController(t))
				keys.EXPECT().Signer(gomock.Any(), signingkey.RS256).Return("", nil, err).Times(1)
				iss := tpeIssuer(t, keys)

				return tpeWithin(t, func() tpeOutcome {
					raw, got := iss.Issue(ctx, tpeIssue())

					return tpeClassify(raw, nil, got)
				})
			}},
		{name: "Generate has the consumer's signer sign",
			run: func(t *testing.T, ctx context.Context, err error) tpeOutcome {
				gen := tpeGenerator(t, tpeFailingSignerSource(t, err)) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

				return tpeWithin(t, func() tpeOutcome {
					raw, got := gen.Generate(ctx, "jti-1", alice())

					return tpeClassify(raw, nil, got)
				})
			}},
		{name: "Issue has the consumer's signer sign",
			run: func(t *testing.T, ctx context.Context, err error) tpeOutcome {
				iss := tpeIssuer(t, tpeFailingSignerSource(t, err)) //nolint:contextcheck // fixtures are built on t.Context(); the case's ctx is the caller's

				return tpeWithin(t, func() tpeOutcome {
					raw, got := iss.Issue(ctx, tpeIssue())

					return tpeClassify(raw, nil, got)
				})
			}},
	}
}

// tpeKind is one hostile error a port returns.
type tpeKind struct {
	name      string
	make      func() error
	cancelled bool
	child     bool // overflows the stack unprotected: runs in a child process
}

// tpeKinds: the claims are the verdicts a hostile error must never buy. A
// claimed ErrNoKey would read as "no current key"; a claimed ErrInvalid would
// read as a refused token rather than an outage.
func tpeKinds() []tpeKind {
	return []tpeKind{
		{name: "cycle through Unwrap() error", make: func() error { return &tpeCycleOne{} }},
		{name: "cycle claiming ErrNoKey", make: func() error { return &tpeClaimCycle{claim: signingkey.ErrNoKey} }},
		{name: "cycle claiming ErrInvalid", make: func() error { return &tpeClaimCycle{claim: token.ErrInvalid} }},
		{name: "panicking Unwrap", make: func() error { return tpePanicUnwrap{} }},
		{name: "panic(nil) in Unwrap", make: func() error { return tpePanicNil{} }},
		{name: "join fanning out past the budget", make: func() error { return tpeFanOut(26) }},
		{name: "cycle under a cancelled context", cancelled: true, make: func() error { return &tpeCycleOne{} }},
		{name: "cycle through Unwrap() []error", child: true, make: func() error { return &tpeCycleMany{} }},
	}
}

const tpeChildEnv = "SCRTY_TOKEN_PORTERR_CHILD"

func tpeChildMarker(row string) string { return "SCRTY-TOKEN-PORTERR-ROW-RAN:" + row }

// tpeInChild re-runs the current top-level test in a child process limited to
// row, and fails unless the child exits 0 within a minute and prints a line
// equal to row's marker, which it does on stdout only after the row passed.
func tpeInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), tpeChildEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	want := tpeChildMarker(row)
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q (no line equals %q); output:\n%s", row, want, out)
}

func tpeCancelled(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	return cctx
}

// TestPortErrors_Token: a key source, or the signer it hands over, that fails
// with an error the library cannot walk gets the outcome of a plain outage of
// that port: no hang, no panic, no token issued, no verification passed, never
// "no current key" and never a refused token, exactly one abort record on
// slog.Default() (the package holds no logger), and nothing of the consumer's
// text in the error or any record. Not parallel: it swaps slog.Default().
func TestPortErrors_Token(t *testing.T) {
	child := os.Getenv(tpeChildEnv)
	if child != "" {
		debug.SetMaxStack(64 << 20)
	}

	for _, site := range tpeSites() {
		for _, kind := range tpeKinds() {
			row := site.name + "/" + kind.name
			if child != "" && child != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if child == "" && kind.child {
					tpeInChild(t, row)

					return
				}

				ctx := t.Context()
				if kind.cancelled {
					ctx = tpeCancelled(ctx)
				}

				rec := tpeSwapDefault(t)

				plain := site.run(t, ctx, errors.New("key service down: "+tpeSecret))
				require.Zero(t, rec.aborts(), "a plain outage writes no abort record")
				require.True(t, plain.failed)
				require.False(t, plain.noKey)
				require.False(t, plain.invalid)

				got := site.run(t, ctx, kind.make())

				assert.Equal(t, 1, rec.aborts(), "abort records on slog.Default()")
				assert.True(t, got.failed, "the call fails")
				assert.False(t, got.issued, "no token is issued")
				assert.False(t, got.verified, "no verification passes")
				assert.False(t, got.noKey, "a hostile error is never a missing key")
				assert.False(t, got.invalid, "a hostile error is never a refused token")
				assert.True(t, got.unwalkable, "the error is the sanitizer's fault")
				assert.NotContains(t, got.text, tpeSecret, "the returned error carries no consumer text")

				want, have := plain, got
				want.unwalkable, have.unwalkable = false, false
				want.err, have.err = nil, nil
				assert.Equal(t, want, have, "the hostile error takes the plain outage's branch")

				for _, text := range rec.texts() {
					assert.NotContains(t, text, tpeSecret)
				}

				if child != "" && !t.Failed() {
					fmt.Println(tpeChildMarker(row))
				}
			})
		}
	}
}

// TestPortErrors_TokenOutcomes pins what the sites answer for errors that are
// not hostile, so the sanitizer changes none of them and writes no record.
func TestPortErrors_TokenOutcomes(t *testing.T) {
	const (
		verifySite = iota
		generateSignerSite
		issueSignerSite
		generateSignSite
		issueSignSite
	)

	plain := errors.New("key service down: " + tpeSecret)

	type testCase struct {
		name   string
		site   int
		err    error
		assert func(t *testing.T, o tpeOutcome, err error, aborts int)
	}

	outage := func(t *testing.T, o tpeOutcome, _ error, aborts int) {
		t.Helper()
		assert.True(t, o.failed)
		assert.False(t, o.issued)
		assert.False(t, o.verified)
		assert.False(t, o.noKey)
		assert.False(t, o.invalid)
		assert.False(t, o.unwalkable)
		assert.NotContains(t, o.text, tpeSecret)
		assert.Zero(t, aborts)
	}

	cases := []testCase{
		{name: "Verify: a plain outage is no verdict and stays reachable", site: verifySite, err: plain,
			assert: func(t *testing.T, o tpeOutcome, err error, aborts int) {
				outage(t, o, err, aborts)
				assert.ErrorIs(t, err, plain)
			}},
		{name: "Verify: a cancelled context from the source stays reachable", site: verifySite,
			err: fmt.Errorf("keys: %w", context.Canceled),
			assert: func(t *testing.T, o tpeOutcome, err error, aborts int) {
				outage(t, o, err, aborts)
				assert.ErrorIs(t, err, context.Canceled)
			}},
		{name: "Verify: a typed-nil error is an outage, no panic, no record", site: verifySite,
			err: (*tpeTypedNil)(nil), assert: outage},
		{name: "Generate: a walkable ErrNoKey keeps the no-key branch", site: generateSignerSite,
			err: fmt.Errorf("kms: %w", signingkey.ErrNoKey),
			assert: func(t *testing.T, o tpeOutcome, _ error, aborts int) {
				assert.True(t, o.noKey)
				assert.False(t, o.issued)
				assert.False(t, o.unwalkable)
				assert.Equal(t, `token: no current key for algorithm "RS256"`, o.text)
				assert.Zero(t, aborts)
			}},
		{name: "Generate: a plain source outage is not a missing key", site: generateSignerSite, err: plain,
			assert: func(t *testing.T, o tpeOutcome, err error, aborts int) {
				outage(t, o, err, aborts)
				assert.Equal(t, "token: signing key unavailable", o.text)
				assert.ErrorIs(t, err, plain)
			}},
		{name: "Generate: a typed-nil source error is an outage, no panic, no record", site: generateSignerSite,
			err: (*tpeTypedNil)(nil), assert: outage},
		{name: "Issue: a walkable ErrNoKey keeps the no-key branch", site: issueSignerSite,
			err: fmt.Errorf("kms: %w", signingkey.ErrNoKey),
			assert: func(t *testing.T, o tpeOutcome, _ error, aborts int) {
				assert.True(t, o.noKey)
				assert.False(t, o.issued)
				assert.False(t, o.unwalkable)
				assert.Zero(t, aborts)
			}},
		{name: "Issue: a plain source outage is not a missing key", site: issueSignerSite, err: plain,
			assert: func(t *testing.T, o tpeOutcome, err error, aborts int) {
				outage(t, o, err, aborts)
				assert.Equal(t, "token: signing key unavailable", o.text)
			}},
		{name: "Generate: a signer failure stays reachable behind fixed text", site: generateSignSite, err: plain,
			assert: func(t *testing.T, o tpeOutcome, err error, aborts int) {
				outage(t, o, err, aborts)
				assert.Equal(t, "token: sign", o.text)
				assert.ErrorIs(t, err, plain)
			}},
		{name: "Generate: a typed-nil signer error is a failure, no panic, no record", site: generateSignSite,
			err: (*tpeTypedNil)(nil), assert: outage},
		{name: "Issue: a signer failure stays reachable behind fixed text", site: issueSignSite, err: plain,
			assert: func(t *testing.T, o tpeOutcome, err error, aborts int) {
				outage(t, o, err, aborts)
				assert.Equal(t, "token: sign", o.text)
				assert.ErrorIs(t, err, plain)
			}},
	}

	sites := tpeSites()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tpeSwapDefault(t)

			o := sites[tc.site].run(t, t.Context(), tc.err)
			tc.assert(t, o, o.err, rec.aborts())
		})
	}
}

// TestPortErrors_TokenNoKeyClaim pins, by text alone, which branch a key
// source's cycle claiming ErrNoKey takes: stdlib errors.Is believes the claim
// at the first node, so unsanitized it reads as "no current key". Only the
// text is read, which the library fixes, so no stdlib walk of the result can
// hang the row before the branch shows. Not parallel: it swaps slog.Default().
func TestPortErrors_TokenNoKeyClaim(t *testing.T) {
	type testCase struct {
		name   string
		issuer func(t *testing.T, keys signingkey.KeySource) func() (string, error)
	}

	cases := []testCase{
		{name: "Generate", issuer: func(t *testing.T, keys signingkey.KeySource) func() (string, error) {
			gen := tpeGenerator(t, keys)

			return func() (string, error) { return gen.Generate(t.Context(), "jti-1", alice()) }
		}},
		{name: "Issue", issuer: func(t *testing.T, keys signingkey.KeySource) func() (string, error) {
			iss := tpeIssuer(t, keys)

			return func() (string, error) { return iss.Issue(t.Context(), tpeIssue()) }
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tpeSwapDefault(t)
			keys := NewMockKeySource(gomock.NewController(t))
			keys.EXPECT().Signer(gomock.Any(), signingkey.RS256).
				Return("", nil, &tpeClaimCycle{claim: signingkey.ErrNoKey}).Times(1)

			issue := tc.issuer(t, keys)
			got := tpeWithin(t, func() tpeOutcome {
				raw, err := issue()
				if err == nil {
					return tpeOutcome{issued: raw != ""}
				}

				return tpeOutcome{failed: true, issued: raw != "", text: err.Error()}
			})

			require.True(t, got.failed, "the call fails")
			assert.Equal(t, "token: signing key unavailable", got.text, "the outage branch, not the no-key one")
			assert.False(t, got.issued, "no token is issued")
			assert.Equal(t, 1, rec.aborts(), "abort records on slog.Default()")
		})
	}
}

// tpeOpaqueSigner is a consumer's own crypto.Signer over a real key: a type
// the JOSE stack does not know, so it signs through Sign alone.
type tpeOpaqueSigner struct{ inner crypto.Signer }

func (s tpeOpaqueSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s tpeOpaqueSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(rand, digest, opts)
}

// tpeOpaqueSource hands out its keys' signers inside tpeOpaqueSigner.
type tpeOpaqueSource struct{ signingkey.KeySource }

func (s tpeOpaqueSource) Signer(ctx context.Context, alg signingkey.Alg) (string, crypto.Signer, error) {
	kid, signer, err := s.KeySource.Signer(ctx, alg)
	if err != nil {
		return "", nil, err
	}

	return kid, tpeOpaqueSigner{inner: signer}, nil
}

// TestPortErrors_TokenSignerShapes pins that sanitizing the signer's error
// changes nothing else about signing: a consumer's own signer and the
// standard library's keys both issue a token that verifies, under every
// algorithm, and a standard library key of another family than the
// algorithm is still refused by the JOSE stack, so no token is issued.
func TestPortErrors_TokenSignerShapes(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		alg    signingkey.Alg
		source func(t *testing.T) signingkey.KeySource
		assert func(t *testing.T, gen *token.JWTGenerator, raw string, err error)
	}

	verifies := func(t *testing.T, gen *token.JWTGenerator, raw string, err error) {
		t.Helper()
		require.NoError(t, err)
		claims, verifyErr := gen.Verify(t.Context(), raw)
		require.NoError(t, verifyErr)
		assert.Equal(t, "u-1", claims.Subject())
	}

	var cases []testCase
	for _, alg := range []signingkey.Alg{signingkey.RS256, signingkey.ES256, signingkey.EdDSA} {
		cases = append(cases,
			testCase{name: string(alg) + ": the standard library's key", alg: alg,
				source: func(t *testing.T) signingkey.KeySource { return newKeySource(t, alg) },
				assert: verifies},
			testCase{name: string(alg) + ": a consumer's own signer", alg: alg,
				source: func(t *testing.T) signingkey.KeySource {
					return tpeOpaqueSource{KeySource: newKeySource(t, alg)}
				},
				assert: verifies},
		)
	}

	cases = append(cases, testCase{
		name: "RS256: a standard library ECDSA key is refused, no token issued",
		alg:  signingkey.RS256,
		source: func(t *testing.T) signingkey.KeySource {
			kid, ecKey, err := newKeySource(t, signingkey.ES256).Signer(t.Context(), signingkey.ES256)
			require.NoError(t, err)

			keys := NewMockKeySource(gomock.NewController(t))
			keys.EXPECT().Signer(gomock.Any(), signingkey.RS256).Return(kid, ecKey, nil).Times(1)

			return keys
		},
		assert: func(t *testing.T, _ *token.JWTGenerator, raw string, err error) {
			require.EqualError(t, err, "token: sign")
			assert.Empty(t, raw, "no token is issued")
		},
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen, err := token.NewGenerator(tc.source(t), token.WithSigningAlg(tc.alg),
				token.WithIssuer("https://issuer.example"), token.WithAudience("orders-api"))
			require.NoError(t, err)

			raw, err := gen.Generate(t.Context(), "jti-1", alice())
			tc.assert(t, gen, raw, err)
		})
	}
}
