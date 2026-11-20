package seal_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/internal/porterr"
	"github.com/kartaladev/scrty/store/seal"
)

// The hostile error types, the abort recorder and the secret text are the
// ones cipher_porterr_test.go declares for this package's port tests.

// mpeOutcome is what a caller of an enrolment store site can see, read inside
// the bound, so a check that would hang on a hostile error hangs the bound
// instead of the test.
type mpeOutcome struct {
	failed          bool
	ok              bool // the found or accepted flag the site returned
	alreadyEnrolled bool // mfa.ErrAlreadyEnrolled
	decryption      bool // seal.ErrDecryptionFailed
	unknownKey      bool // seal.ErrUnknownKeyID
	unavailable     bool // seal.ErrUnavailable
	unwalkable      bool // porterr.ErrUnwalkable: only a sanitized fault
	text            string
}

func mpeClassify(ok bool, err error) mpeOutcome {
	o := mpeOutcome{ok: ok, failed: err != nil}
	if err == nil {
		return o
	}

	o.alreadyEnrolled = errors.Is(err, mfa.ErrAlreadyEnrolled)
	o.decryption = errors.Is(err, seal.ErrDecryptionFailed)
	o.unknownKey = errors.Is(err, seal.ErrUnknownKeyID)
	o.unavailable = errors.Is(err, seal.ErrUnavailable)
	o.unwalkable = errors.Is(err, porterr.ErrUnwalkable)
	o.text = err.Error()

	return o
}

// mpeWithin runs call on its own goroutine and fails the test when it does
// not return within two seconds or lets a panic escape.
func mpeWithin(t *testing.T, call func() mpeOutcome) mpeOutcome {
	t.Helper()

	type result struct {
		got      mpeOutcome
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

		return mpeOutcome{}
	}
}

// mpeStore wraps inner in the sealing enrolment store.
func mpeStore(t *testing.T, inner mfa.EnrolmentStore) mfa.EnrolmentStore {
	t.Helper()

	store, err := seal.NewEnrolmentStore(inner, nil, newCiphers(t).current, seal.WithResealOnRead(false))
	require.NoError(t, err)

	return store
}

// mpeSite is one call on the inner enrolment store in mfa.go: run arranges
// the inner store's mock to return err and drives the sealing store.
type mpeSite struct {
	name string
	run  func(t *testing.T, ctx context.Context, inner *MockEnrolmentStore, store mfa.EnrolmentStore, err error) mpeOutcome
}

func mpeSites() []mpeSite {
	gen := fixedGen

	return []mpeSite{
		{name: "Get asks the inner store",
			run: func(t *testing.T, ctx context.Context, inner *MockEnrolmentStore, store mfa.EnrolmentStore, err error) mpeOutcome {
				inner.EXPECT().Get(gomock.Any(), userRef).Return(mfa.Enrolment{User: userRef, Secret: []byte("stored")}, true, err)

				return mpeWithin(t, func() mpeOutcome {
					_, found, got := store.Get(ctx, userRef)

					return mpeClassify(found, got)
				})
			}},
		{name: "PutPending stores in the inner store",
			run: func(t *testing.T, ctx context.Context, inner *MockEnrolmentStore, store mfa.EnrolmentStore, err error) mpeOutcome {
				inner.EXPECT().PutPending(gomock.Any(), gomock.Any()).Return(err)
				e := pendingEnrolment(t, userRef)

				return mpeWithin(t, func() mpeOutcome { return mpeClassify(false, store.PutPending(ctx, e)) })
			}},
		{name: "Confirm asks the inner store",
			run: func(t *testing.T, ctx context.Context, inner *MockEnrolmentStore, store mfa.EnrolmentStore, err error) mpeOutcome {
				inner.EXPECT().Confirm(gomock.Any(), userRef, gen, int64(1), gomock.Any()).Return(true, err)

				return mpeWithin(t, func() mpeOutcome {
					ok, got := store.Confirm(ctx, userRef, gen, 1, time.Now())

					return mpeClassify(ok, got)
				})
			}},
		{name: "AcceptStep asks the inner store",
			run: func(t *testing.T, ctx context.Context, inner *MockEnrolmentStore, store mfa.EnrolmentStore, err error) mpeOutcome {
				inner.EXPECT().AcceptStep(gomock.Any(), userRef, gen, int64(1)).Return(true, err)

				return mpeWithin(t, func() mpeOutcome {
					ok, got := store.AcceptStep(ctx, userRef, gen, 1)

					return mpeClassify(ok, got)
				})
			}},
		{name: "Delete asks the inner store",
			run: func(t *testing.T, ctx context.Context, inner *MockEnrolmentStore, store mfa.EnrolmentStore, err error) mpeOutcome {
				inner.EXPECT().Delete(gomock.Any(), userRef).Return(err)

				return mpeWithin(t, func() mpeOutcome { return mpeClassify(false, store.Delete(ctx, userRef)) })
			}},
		{name: "ChargeVerifyAttempt asks the inner store",
			run: func(t *testing.T, ctx context.Context, inner *MockEnrolmentStore, store mfa.EnrolmentStore, err error) mpeOutcome {
				inner.EXPECT().ChargeVerifyAttempt(gomock.Any(), userRef, gomock.Any(), 5, time.Minute).
					Return(time.Time{}, true, err)

				return mpeWithin(t, func() mpeOutcome {
					_, ok, got := store.ChargeVerifyAttempt(ctx, userRef, time.Now(), 5, time.Minute)

					return mpeClassify(ok, got)
				})
			}},
	}
}

// mpeKind is one error the inner store returns.
type mpeKind struct {
	name      string
	make      func() error
	cancelled bool
	child     bool // overflows the stack unprotected: runs in a child process
}

func mpeKinds() []mpeKind {
	return []mpeKind{
		{name: "cycle through Unwrap() error", make: func() error { return &cpeCycleOne{} }},
		{name: "cycle claiming ErrAlreadyEnrolled",
			make: func() error { return &cpeClaimCycle{claim: mfa.ErrAlreadyEnrolled} }},
		{name: "cycle claiming ErrDecryptionFailed",
			make: func() error { return &cpeClaimCycle{claim: seal.ErrDecryptionFailed} }},
		{name: "panicking Unwrap", make: func() error { return cpePanicUnwrap{} }},
		{name: "panic(nil) in Unwrap", make: func() error { return cpePanicNil{} }},
		{name: "join fanning out past the budget", make: func() error { return cpeFanOut(26) }},
		{name: "cycle under a cancelled context", cancelled: true, make: func() error { return &cpeCycleOne{} }},
		{name: "cycle through Unwrap() []error", child: true, make: func() error { return &cpeCycleMany{} }},
	}
}

const mpeChildEnv = "SCRTY_SEAL_MFA_PORTERR_CHILD"

func mpeChildMarker(row string) string { return "SCRTY-SEAL-MFA-PORTERR-ROW-RAN:" + row }

// mpeInChild re-runs the current top-level test in a child process limited to
// row, and fails unless the child exits 0 within a minute and prints a line
// equal to row's marker, which it does only after the row passed.
func mpeInChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), mpeChildEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))

	want := mpeChildMarker(row)
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return
		}
	}

	t.Fatalf("the child never ran row %q (no line equals %q); output:\n%s", row, want, out)
}

// mpeSwapDefault routes slog.Default() to a recorder until the test ends.
func mpeSwapDefault(t *testing.T) *cpeRecorder {
	t.Helper()

	rec := new(cpeRecorder)
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return rec
}

// TestPortErrors_SealEnrolmentStore: an inner enrolment store that returns an
// error the library cannot walk gets the outcome of a plain outage of that
// store: no hang, no panic, the same flags and error class, never a bare
// mfa.ErrAlreadyEnrolled, a decryption refusal or an unknown key, exactly one
// abort record on slog.Default(), and nothing of the consumer's text in the
// error or any record. Not parallel: it swaps slog.Default().
func TestPortErrors_SealEnrolmentStore(t *testing.T) {
	child := os.Getenv(mpeChildEnv)
	if child != "" {
		debug.SetMaxStack(64 << 20)
	}

	for _, site := range mpeSites() {
		for _, kind := range mpeKinds() {
			row := site.name + "/" + kind.name
			if child != "" && child != row {
				continue
			}

			t.Run(row, func(t *testing.T) {
				if child == "" && kind.child {
					mpeInChild(t, row)

					return
				}

				ctx := t.Context()
				if kind.cancelled {
					ctx = cancelled(ctx)
				}

				ctrl := gomock.NewController(t)
				rec := mpeSwapDefault(t)

				runOn := func(err error) mpeOutcome {
					inner := NewMockEnrolmentStore(ctrl)

					return site.run(t, ctx, inner, mpeStore(t, inner), err)
				}

				plain := runOn(errors.New("store down: " + cpeSecret))
				require.Zero(t, rec.aborts(), "a plain outage writes no abort record")
				require.True(t, plain.failed)

				got := runOn(kind.make())

				assert.Equal(t, 1, rec.aborts(), "abort records on slog.Default()")
				assert.True(t, got.unwalkable, "the error is the sanitizer's fault")
				assert.False(t, got.alreadyEnrolled, "a hostile error is never read as an existing enrolment")
				assert.False(t, got.decryption, "a hostile error is never read as a value that does not open")
				assert.False(t, got.unknownKey)
				assert.NotContains(t, got.text, cpeSecret, "the returned error carries no consumer text")

				// Same outcome as the plain outage, the fault's identity aside.
				want, have := plain, got
				want.unwalkable, have.unwalkable = false, false
				want.text, have.text = "", ""
				assert.Equal(t, want, have, "the hostile error takes the plain outage's branch")

				for _, text := range rec.texts() {
					assert.NotContains(t, text, cpeSecret)
				}

				if child != "" && !t.Failed() {
					fmt.Println(mpeChildMarker(row))
				}
			})
		}
	}
}

// TestPortErrors_SealEnrolmentStoreOutcomes pins what the sites answer for the
// inner store errors that are not hostile, so the sanitizer changes none of
// them.
func TestPortErrors_SealEnrolmentStoreOutcomes(t *testing.T) {
	type testCase struct {
		name   string
		site   int // index into mpeSites
		err    error
		assert func(t *testing.T, o mpeOutcome, aborts int)
	}

	get, putPending, confirm, _, del, _ := 0, 1, 2, 3, 4, 5

	cases := []testCase{
		{name: "Get: a plain failure stays a failure, with no consumer text", site: get,
			err: errors.New("db down: " + cpeSecret),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.ok)
				assert.False(t, o.unwalkable)
				assert.NotContains(t, o.text, cpeSecret)
				assert.Zero(t, aborts)
			}},
		{name: "Get: a wrapped decryption error from the store keeps matching it", site: get,
			err: fmt.Errorf("store: %w", seal.ErrDecryptionFailed),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.decryption)
				assert.False(t, o.unwalkable)
				assert.Zero(t, aborts)
			}},
		{name: "PutPending: ErrAlreadyEnrolled comes back as the bare sentinel", site: putPending,
			err: fmt.Errorf("store: %w: %s", mfa.ErrAlreadyEnrolled, cpeSecret),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.alreadyEnrolled)
				assert.Equal(t, mfa.ErrAlreadyEnrolled.Error(), o.text)
				assert.Zero(t, aborts)
			}},
		{name: "PutPending: a cycle claiming ErrAlreadyEnrolled is an outage, never an existing enrolment",
			site: putPending, err: &cpeClaimCycle{claim: mfa.ErrAlreadyEnrolled},
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.alreadyEnrolled)
				assert.True(t, o.unwalkable)
				assert.Equal(t, 1, aborts)
			}},
		{name: "Confirm: a typed-nil error is a failure, no panic, no record", site: confirm,
			err: (*cpeTypedNil)(nil),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.alreadyEnrolled)
				assert.Zero(t, aborts)
			}},
		{name: "Delete: a plain failure stays a failure", site: del,
			err: errors.New("db down"),
			assert: func(t *testing.T, o mpeOutcome, aborts int) {
				assert.True(t, o.failed)
				assert.False(t, o.unwalkable)
				assert.Zero(t, aborts)
			}},
	}

	sites := mpeSites()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := mpeSwapDefault(t)
			inner := NewMockEnrolmentStore(gomock.NewController(t))

			o := sites[tc.site].run(t, t.Context(), inner, mpeStore(t, inner), tc.err)
			tc.assert(t, o, rec.aborts())
		})
	}
}
