package seal_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/store/seal"
)

// cpeSecret is consumer text no record and no returned hostile error may carry.
const cpeSecret = "cpe-consumer-secret-do-not-leak"

// cpeCycleOne is an error whose Unwrap() error returns itself.
type cpeCycleOne struct{}

func (*cpeCycleOne) Error() string   { return "cycle one: " + cpeSecret }
func (c *cpeCycleOne) Unwrap() error { return c }

// cpeCycleMany contains itself through Unwrap() []error. Walked by stdlib it
// overflows the stack, a fatal error, so only a child process runs it.
type cpeCycleMany struct{}

func (*cpeCycleMany) Error() string     { return "cycle many: " + cpeSecret }
func (c *cpeCycleMany) Unwrap() []error { return []error{c} }

// cpeClaimCycle is a cycle through Unwrap() error whose Is claims one
// sentinel, so a stdlib errors.Is for that sentinel answers true at once.
type cpeClaimCycle struct{ claim error }

func (*cpeClaimCycle) Error() string          { return "claiming cycle: " + cpeSecret }
func (c *cpeClaimCycle) Unwrap() error        { return c }
func (c *cpeClaimCycle) Is(target error) bool { return target == c.claim } //nolint:errorlint // identity

// cpePanicUnwrap panics from Unwrap.
type cpePanicUnwrap struct{}

func (cpePanicUnwrap) Error() string { return "panic unwrap: " + cpeSecret }
func (cpePanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + cpeSecret) }

// cpePanicNil panics with nil from Unwrap.
type cpePanicNil struct{}

func (cpePanicNil) Error() string { return "panic nil: " + cpeSecret }
func (cpePanicNil) Unwrap() error { panic(nil) }

// cpeTypedNil is returned as a typed nil; its methods never dereference the
// receiver, so only the library could make it panic.
type cpeTypedNil struct{}

func (*cpeTypedNil) Error() string { return "typed nil: " + cpeSecret }

// cpeFanOut is errors.Join(n, n) nested depth times: no cycle, but 2^depth
// paths for an unbounded walk.
func cpeFanOut(depth int) error {
	err := errors.New("fan-out leaf: " + cpeSecret)
	for range depth {
		err = errors.Join(err, err)
	}

	return err
}

// cpeRecorder keeps every record it is handed.
type cpeRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (*cpeRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *cpeRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.records = append(r.records, rec.Clone())

	return nil
}

func (r *cpeRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *cpeRecorder) WithGroup(string) slog.Handler      { return r }

// aborts counts the abort records written.
func (r *cpeRecorder) aborts() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := 0
	for _, rec := range r.records {
		if rec.Message == porterr.MsgClassificationAborted {
			n++
		}
	}

	return n
}

// texts returns every record's message and attributes as text.
func (r *cpeRecorder) texts() []string {
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

// cpeOutcome is what a caller of a cipher site can see, read inside the
// bound, so a check that would hang on a hostile error hangs the bound
// instead of the test.
type cpeOutcome struct {
	failed            bool
	unavailable       bool // seal.ErrUnavailable
	cipherUnavailable bool // session.ErrCipherUnavailable
	unknownKey        bool // seal.ErrUnknownKeyID
	decryption        bool // seal.ErrDecryptionFailed
	config            bool // seal.ErrConfig
	keyID             string
	output            bool // a sealed value or a plaintext came back
	unwalkable        bool // porterr.ErrUnwalkable: only a sanitized fault
	text              string
}

func cpeClassify(out []byte, keyID string, err error) cpeOutcome {
	o := cpeOutcome{keyID: keyID, output: out != nil, failed: err != nil}
	if err == nil {
		return o
	}

	o.unavailable = errors.Is(err, seal.ErrUnavailable)
	o.cipherUnavailable = errors.Is(err, session.ErrCipherUnavailable)
	o.unknownKey = errors.Is(err, seal.ErrUnknownKeyID)
	o.decryption = errors.Is(err, seal.ErrDecryptionFailed)
	o.config = errors.Is(err, seal.ErrConfig)
	o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
	o.text = err.Error()

	return o
}

// cpeWithin runs call on its own goroutine and fails the test when it does
// not return within two seconds or lets a panic escape.
func cpeWithin(t *testing.T, call func() cpeOutcome) cpeOutcome {
	t.Helper()

	type result struct {
		got      cpeOutcome
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

		return cpeOutcome{}
	}
}

// cpeSite is one port call in cipher.go: run arranges the port's mock to
// return err (with key material or a plaintext beside it) and drives the
// site, classifying what its caller sees.
type cpeSite struct {
	name string
	run  func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) cpeOutcome
}

// cpeEnvelope is a value sealed under "k1", so Open asks the keyring for k1.
func cpeEnvelope(t *testing.T) []byte {
	t.Helper()

	return mustSeal(t, mustCipher(t, seal.WithKeyringEncryptionKey("k1", keyOne)), secretPlaintext, boundAAD)
}

func cpeAEAD(t *testing.T, kr seal.Keyring) *seal.AEADCipher {
	t.Helper()

	c, err := seal.NewAEADCipher(kr)
	require.NoError(t, err)

	return c
}

func cpeSites() []cpeSite {
	return []cpeSite{
		{name: "AEADCipher.Open asks Keyring.ByID",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) cpeOutcome {
				envelope := cpeEnvelope(t)
				kr := NewMockKeyring(ctrl)
				kr.EXPECT().ByID(gomock.Any(), "k1").Return(keyOne, err)
				c := cpeAEAD(t, kr)

				return cpeWithin(t, func() cpeOutcome {
					plaintext, keyID, got := c.Open(ctx, envelope, boundAAD)

					return cpeClassify(plaintext, keyID, got)
				})
			}},
		{name: "AEADCipher.Seal asks Keyring.Active",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) cpeOutcome {
				kr := NewMockKeyring(ctrl)
				kr.EXPECT().Active(gomock.Any()).Return("k1", keyOne, err)
				c := cpeAEAD(t, kr)

				return cpeWithin(t, func() cpeOutcome {
					sealed, got := c.Seal(ctx, []byte(secretPlaintext), boundAAD)

					return cpeClassify(sealed, "", got)
				})
			}},
		{name: "AEADCipher.ActiveKeyID asks Keyring.Active",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) cpeOutcome {
				kr := NewMockKeyring(ctrl)
				kr.EXPECT().Active(gomock.Any()).Return("k1", keyOne, err)
				c := cpeAEAD(t, kr)

				return cpeWithin(t, func() cpeOutcome {
					id, got := c.ActiveKeyID(ctx)
					if got != nil {
						return cpeClassify(nil, id, got)
					}

					return cpeClassify([]byte(id), id, nil)
				})
			}},
		{name: "SessionCipher.Seal asks Cipher.Seal",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) cpeOutcome {
				mc := NewMockCipher(ctrl)
				mc.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte(secretPlaintext), err)
				sc := seal.SessionCipher(mc)

				return cpeWithin(t, func() cpeOutcome {
					sealed, got := sc.Seal(ctx, []byte(secretPlaintext), boundAAD)

					return cpeClassify(sealed, "", got)
				})
			}},
		{name: "SessionCipher.Open asks Cipher.Open",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) cpeOutcome {
				mc := NewMockCipher(ctrl)
				mc.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte(secretPlaintext), "k1", err)
				sc := seal.SessionCipher(mc)

				return cpeWithin(t, func() cpeOutcome {
					plaintext, got := sc.Open(ctx, []byte("sealed"), boundAAD)

					return cpeClassify(plaintext, "", got)
				})
			}},
		{name: "SessionCipher over AEADCipher, Keyring.ByID",
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) cpeOutcome {
				envelope := cpeEnvelope(t)
				kr := NewMockKeyring(ctrl)
				kr.EXPECT().ByID(gomock.Any(), "k1").Return(keyOne, err)
				sc := seal.SessionCipher(cpeAEAD(t, kr))

				return cpeWithin(t, func() cpeOutcome {
					plaintext, got := sc.Open(ctx, envelope, boundAAD)

					return cpeClassify(plaintext, "", got)
				})
			}},
	}
}

// cpeKind is one error a port returns.
type cpeKind struct {
	name      string
	make      func() error
	hostile   bool // the walk aborts: one record
	cancelled bool
	child     bool // overflows the stack unprotected: runs in a child process
}

// cpePlainOutage is a port outage marked as the Keyring and Cipher contracts
// ask: errors.Join(seal.ErrUnavailable, cause).
func cpePlainOutage() error {
	return errors.Join(seal.ErrUnavailable, errors.New("kms endpoint refused: "+cpeSecret))
}

func cpeKinds() []cpeKind {
	return []cpeKind{
		{name: "cycle through Unwrap() error", hostile: true, make: func() error { return &cpeCycleOne{} }},
		{name: "cycle claiming ErrUnknownKeyID", hostile: true,
			make: func() error { return &cpeClaimCycle{claim: seal.ErrUnknownKeyID} }},
		{name: "cycle claiming ErrUnavailable", hostile: true,
			make: func() error { return &cpeClaimCycle{claim: seal.ErrUnavailable} }},
		{name: "panicking Unwrap", hostile: true, make: func() error { return cpePanicUnwrap{} }},
		{name: "panic(nil) in Unwrap", hostile: true, make: func() error { return cpePanicNil{} }},
		{name: "join fanning out past the budget", hostile: true, make: func() error { return cpeFanOut(26) }},
		{name: "cycle under a cancelled context", hostile: true, cancelled: true,
			make: func() error { return &cpeCycleOne{} }},
		{name: "cycle through Unwrap() []error", hostile: true, child: true,
			make: func() error { return &cpeCycleMany{} }},
	}
}

const cpeChildEnv = "SCRTY_SEAL_CIPHER_PORTERR_CHILD"

func cpeChildMarker(row string) string { return "SCRTY-SEAL-CIPHER-PORTERR-ROW-RAN:" + row }

// cpeInChild re-runs the current top-level test in a child process limited
// to row, and fails unless the child exits 0 within a minute and prints a
// line equal to row's marker, which it does only after the row passed.
func cpeInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), cpeChildEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	want := cpeChildMarker(row)
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q (no line equals %q); output:\n%s", row, want, out)
}

// TestPortErrors_SealCipher: a Keyring or Cipher that returns an error the
// library cannot walk gets the outcome of a marked outage of that port: no
// hang, no panic, the same sealed/opened answer and error class, exactly one
// abort record on slog.Default(), and nothing of the consumer's text or key
// material in any record. Not parallel: it swaps slog.Default().
func TestPortErrors_SealCipher(t *testing.T) {
	child := os.Getenv(cpeChildEnv)
	if child != "" {
		debug.SetMaxStack(64 << 20)
	}

	for _, site := range cpeSites() {
		for _, kind := range cpeKinds() {
			row := site.name + "/" + kind.name
			if child != "" && child != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if child == "" && kind.child {
					cpeInChild(t, row)

					return
				}

				ctx := t.Context()
				if kind.cancelled {
					ctx = cancelled(ctx)
				}

				ctrl := gomock.NewController(t)

				rec := new(cpeRecorder)
				prev := slog.Default()
				slog.SetDefault(slog.New(rec))
				t.Cleanup(func() { slog.SetDefault(prev) })

				plain := site.run(t, ctx, ctrl, cpePlainOutage())
				require.Zero(t, rec.aborts(), "a plain outage writes no abort record")
				require.True(t, plain.failed)

				got := site.run(t, ctx, ctrl, kind.make())

				assert.Equal(t, 1, rec.aborts(), "abort records on slog.Default()")
				assert.True(t, got.unwalkable, "the error is the sanitizer's fault")
				assert.NotContains(t, got.text, cpeSecret, "the returned error carries no consumer text")

				// Same outcome as the plain outage, the fault's identity aside.
				want, have := plain, got
				want.unwalkable, have.unwalkable = false, false
				want.text, have.text = "", ""
				assert.Equal(t, want, have, "the hostile error takes the plain outage's branch")

				for _, text := range rec.texts() {
					assert.NotContains(t, text, cpeSecret)
					assert.NotContains(t, text, string(keyOne))
					assert.NotContains(t, text, hex.EncodeToString(keyOne))
					assert.NotContains(t, text, secretPlaintext)
				}

				if child != "" && !t.Failed() {
					fmt.Println(cpeChildMarker(row))
				}
			})
		}
	}
}

// TestPortErrors_SealCipherOutcomes pins what each site answers for the port
// errors that are not hostile, so the sanitizer changes none of them, and
// what a hostile error is answered as: an outage of the port, never an
// unknown key or a value that does not open.
func TestPortErrors_SealCipherOutcomes(t *testing.T) {
	type testCase struct {
		name   string
		site   int // index into cpeSites
		err    error
		assert func(t *testing.T, o cpeOutcome, aborts int)
	}

	byID, active, sessionSeal, sessionOpen, endToEnd := 0, 1, 3, 4, 5

	cases := []testCase{
		{name: "ByID: a marked outage is an outage", site: byID, err: cpePlainOutage(),
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.unavailable)
				assert.False(t, o.unknownKey)
				assert.False(t, o.decryption)
				assert.Empty(t, o.keyID)
				assert.Zero(t, aborts)
			}},
		{name: "ByID: ErrUnknownKeyID keeps its branch and reports the id", site: byID,
			err: fmt.Errorf("ring: %w", seal.ErrUnknownKeyID),
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.unknownKey)
				assert.False(t, o.unavailable)
				assert.Equal(t, "k1", o.keyID)
				assert.Zero(t, aborts)
			}},
		{name: "ByID: an unmarked failure stays unmarked", site: byID, err: errors.New("ring down: " + cpeSecret),
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.unavailable)
				assert.False(t, o.unknownKey)
				assert.NotContains(t, o.text, cpeSecret)
				assert.Zero(t, aborts)
			}},
		{name: "ByID: a typed-nil error is an unmarked failure, no panic", site: byID, err: (*cpeTypedNil)(nil),
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.unavailable)
				assert.False(t, o.unknownKey)
				assert.Empty(t, o.keyID)
				assert.Zero(t, aborts)
			}},
		{name: "ByID: a cycle claiming ErrUnknownKeyID is an outage, never an unknown key", site: byID,
			err: &cpeClaimCycle{claim: seal.ErrUnknownKeyID},
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.unavailable)
				assert.False(t, o.unknownKey)
				assert.Empty(t, o.keyID)
				assert.Equal(t, 1, aborts)
			}},
		{name: "Active: a typed-nil error is an unmarked failure, no panic", site: active, err: (*cpeTypedNil)(nil),
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.unavailable)
				assert.False(t, o.output)
				assert.Zero(t, aborts)
			}},
		{name: "SessionCipher.Seal: an unmarked failure is returned unchanged", site: sessionSeal,
			err: errors.New("cipher down"),
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.cipherUnavailable)
				assert.Equal(t, "cipher down", o.text)
				assert.Zero(t, aborts)
			}},
		{name: "SessionCipher.Open: a context error is returned unchanged", site: sessionOpen,
			err: context.Canceled,
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.False(t, o.cipherUnavailable)
				assert.Equal(t, context.Canceled.Error(), o.text)
				assert.Zero(t, aborts)
			}},
		{name: "SessionCipher.Open: a hostile cipher error is session.ErrCipherUnavailable", site: sessionOpen,
			err: &cpeCycleOne{},
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.cipherUnavailable)
				assert.True(t, o.unavailable)
				assert.False(t, o.output)
				assert.Equal(t, 1, aborts)
			}},
		{name: "SessionCipher over AEADCipher: a hostile keyring error is session.ErrCipherUnavailable",
			site: endToEnd, err: &cpeCycleOne{},
			assert: func(t *testing.T, o cpeOutcome, aborts int) {
				assert.True(t, o.cipherUnavailable, "an outage, so the session is not ended as unreadable")
				assert.False(t, o.unknownKey)
				assert.False(t, o.decryption)
				assert.Equal(t, 1, aborts)
			}},
	}

	sites := cpeSites()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := new(cpeRecorder)
			prev := slog.Default()
			slog.SetDefault(slog.New(rec))
			t.Cleanup(func() { slog.SetDefault(prev) })

			o := sites[tc.site].run(t, t.Context(), gomock.NewController(t), tc.err)
			tc.assert(t, o, rec.aborts())
		})
	}
}

// TestPortErrors_SealCipherNilKey: a keyring that answers neither a key nor
// an error breaks its contract; the cipher's key length check refuses it as
// ErrConfig rather than sealing or opening under no key.
func TestPortErrors_SealCipherNilKey(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, kr *MockKeyring, c *seal.AEADCipher) ([]byte, error)
		assert func(t *testing.T, out []byte, err error)
	}

	refused := func(t *testing.T, out []byte, err error) {
		require.ErrorIs(t, err, seal.ErrConfig)
		assert.NotErrorIs(t, err, seal.ErrUnknownKeyID)
		assert.Nil(t, out)
	}

	cases := []testCase{
		{name: "ByID answers (nil, nil)",
			run: func(t *testing.T, kr *MockKeyring, c *seal.AEADCipher) ([]byte, error) {
				envelope := cpeEnvelope(t)
				kr.EXPECT().ByID(gomock.Any(), "k1").Return(nil, nil)
				out, _, err := c.Open(t.Context(), envelope, boundAAD)

				return out, err
			},
			assert: refused},
		{name: "Active answers an id, a nil key and no error",
			run: func(t *testing.T, kr *MockKeyring, c *seal.AEADCipher) ([]byte, error) {
				kr.EXPECT().Active(gomock.Any()).Return("k1", nil, nil)

				return c.Seal(t.Context(), []byte(secretPlaintext), boundAAD)
			},
			assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kr := NewMockKeyring(gomock.NewController(t))
			out, err := tc.run(t, kr, cpeAEAD(t, kr))
			tc.assert(t, out, err)
		})
	}
}
