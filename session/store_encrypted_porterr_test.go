package session_test

import (
	"context"
	"errors"
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
)

// peSecret is text no returned error may carry.
const peSecret = "pe-secret-do-not-leak"

// peCycleOne is an error whose Unwrap() error returns itself.
type peCycleOne struct{}

func (*peCycleOne) Error() string   { return "cycle one: " + peSecret }
func (c *peCycleOne) Unwrap() error { return c }

// peCycleMany contains itself through Unwrap() []error. Walked by stdlib it
// overflows the stack, a fatal error, so only a child process runs it.
type peCycleMany struct{}

func (*peCycleMany) Error() string     { return "cycle many: " + peSecret }
func (c *peCycleMany) Unwrap() []error { return []error{c} }

// pePanicUnwrap panics from Unwrap.
type pePanicUnwrap struct{}

func (pePanicUnwrap) Error() string { return "panic unwrap: " + peSecret }
func (pePanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + peSecret) }

// pePanicNil panics with nil from Unwrap.
type pePanicNil struct{}

func (pePanicNil) Error() string { return "panic nil: " + peSecret }
func (pePanicNil) Unwrap() error { panic(nil) }

// peNilPtr is an error whose methods dereference the receiver, so a typed nil
// panics if anything calls them.
type peNilPtr struct{ text string }

func (e *peNilPtr) Error() string { return e.text }

// peRecorder keeps every record it is handed.
type peRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (*peRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *peRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.records = append(r.records, rec.Clone())

	return nil
}

func (r *peRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *peRecorder) WithGroup(string) slog.Handler      { return r }

// aborts returns the reason of each abort record written.
func (r *peRecorder) aborts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var reasons []string
	for _, rec := range r.records {
		if rec.Message != porterr.MsgClassificationAborted {
			continue
		}
		reason := ""
		rec.Attrs(func(a slog.Attr) bool {
			if a.Key == "reason" {
				reason = a.Value.String()
			}

			return true
		})
		reasons = append(reasons, reason)
	}

	return reasons
}

// peRecording points slog.Default() at a recorder until the test ends. The
// default logger is process-wide, so the test using it is not parallel.
func peRecording(t *testing.T) *peRecorder {
	t.Helper()

	rec := new(peRecorder)
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return rec
}

const peChildEnv = "SCRTY_SESSION_PORTERR_CHILD"

// peInChild re-runs the current top-level test in a child process that runs
// only the cycle-many kind, and fails unless the child exits 0 within a
// minute. A stack overflow is fatal, so only a child can watch for one.
func peInChild(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	top, _, _ := strings.Cut(t.Name(), "/")

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), peChildEnv+"=1")

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 8)], "\n"))
}

// peWithin runs call on its own goroutine and fails the test when it does not
// return within two seconds or lets a panic escape.
func peWithin[T any](t *testing.T, call func() T) T {
	t.Helper()

	type result struct {
		got      T
		panicked any
	}

	done := make(chan result, 1)
	go func() {
		var r result
		defer func() {
			r.panicked = recover()
			done <- r
		}()
		r.got = call()
	}()

	select {
	case r := <-done:
		require.Nil(t, r.panicked, "the call panicked")

		return r.got
	case <-time.After(2 * time.Second):
		require.FailNow(t, "the call did not return within 2s")

		var zero T

		return zero
	}
}

// peKind is one error a port returns.
type peKind struct {
	name string
	// make builds the error; unavailable is the sentinel the flow's sanitizer
	// uses, for the kind that arrives already sanitized.
	make func(unavailable error) error
	// hostile kinds abort the walk: one record, and the flow's unavailable
	// class. A kind that is not hostile writes no record.
	hostile   bool
	cancelled bool
	// child marks the kind that overflows the stack unprotected.
	child bool
}

var errPePlain = errors.New("pe: store down")

func peKinds() []peKind {
	return []peKind{
		{name: "a plain outage", make: func(error) error { return errPePlain }},
		{name: "a cycle through Unwrap() error", hostile: true, make: func(error) error { return &peCycleOne{} }},
		{name: "a panicking Unwrap", hostile: true, make: func(error) error { return pePanicUnwrap{} }},
		{name: "a panic(nil) in Unwrap", hostile: true, make: func(error) error { return pePanicNil{} }},
		{name: "a cycle under a cancelled context", hostile: true, cancelled: true,
			make: func(error) error { return &peCycleOne{} }},
		{name: "a fault the inner store already sanitized", make: func(unavailable error) error {
			return porterr.SanitizeTo(context.Background(), slog.New(slog.DiscardHandler), &peCycleOne{}, unavailable)
		}},
		{name: "a typed-nil root", make: func(error) error { return (*peNilPtr)(nil) }},
		{name: "a cycle through Unwrap() []error", hostile: true, child: true,
			make: func(error) error { return &peCycleMany{} }},
	}
}

// peFlow is one call site: it arranges the mocks to return err from the port
// and runs the flow.
type peFlow struct {
	name string
	// unavailable is the sentinel the site hands the sanitizer.
	unavailable error
	// outage reports whether the flow's outcome is the outage class for err.
	run func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error
}

const peStored = "eA" // base64url of "x": a stored envelope

func peStore(t *testing.T, ctrl *gomock.Controller, cipher session.Cipher) (session.Store, *MockStore) {
	t.Helper()

	inner := NewMockStore(ctrl)
	sealing, err := session.NewEncryptedStore(inner, cipher)
	require.NoError(t, err)

	return sealing, inner
}

func peFlows() []peFlow {
	return append(peSealingFlows(), peForwardFlows()...)
}

// peFamilyStore is an inner store that also offers the narrowed family read.
type peFamilyStore struct {
	*MockStore
	*MockFamilyReader
}

// peForwardFlows are the inner-store calls the decorator only forwards: each
// answers a hostile error as it answers a plain outage.
func peForwardFlows() []peFlow {
	user := testUser

	return []peFlow{
		{name: "Delete on the inner store", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().Delete(gomock.Any(), "pe-del").Return(err)

				return sealing.Delete(ctx, "pe-del")
			}},
		{name: "DeleteByUser on the inner store", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().DeleteByUser(gomock.Any(), user).Return(err)

				return sealing.DeleteByUser(ctx, user)
			}},
		{name: "DeleteByUserExcept on the inner store", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().DeleteByUserExcept(gomock.Any(), user, "keep").Return(0, err)

				_, got := sealing.DeleteByUserExcept(ctx, user, "keep")

				return got
			}},
		{name: "CountActiveByUser on the inner store", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().CountActiveByUser(gomock.Any(), user).Return(0, err)

				_, got := sealing.CountActiveByUser(ctx, user)

				return got
			}},
		{name: "ListByUser on the inner store", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().ListByUser(gomock.Any(), user, gomock.Any()).Return(nil, err)

				_, got := sealing.ListByUser(ctx, user, createdAt)

				return got
			}},
		{name: "ListByFamily on the inner family reader", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				inner := peFamilyStore{NewMockStore(ctrl), NewMockFamilyReader(ctrl)}
				sealing, serr := session.NewEncryptedStore(inner, NewMockCipher(ctrl))
				require.NoError(t, serr)
				inner.MockFamilyReader.EXPECT().ListByFamily(gomock.Any(), user, storedFamily, gomock.Any()).Return(nil, err)

				_, got := sealing.(session.FamilyReader).ListByFamily(ctx, user, storedFamily, createdAt)

				return got
			}},
		{name: "ListByFamily through the inner listing", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().ListByUser(gomock.Any(), user, gomock.Any()).Return(nil, err)

				_, got := sealing.(session.FamilyReader).ListByFamily(ctx, user, storedFamily, createdAt)

				return got
			}},
	}
}

func peSealingFlows() []peFlow {
	return []peFlow{
		{name: "Create on the inner store", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().Create(gomock.Any(), gomock.Any()).Return(err)

				return sealing.Create(ctx, storedSession("pe-create"))
			}},
		{name: "Save on the inner store", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().Save(gomock.Any(), gomock.Any()).Return(err)

				return sealing.Save(ctx, storedSession("pe-save"))
			}},
		{name: "Load on the inner store", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				sealing, inner := peStore(t, ctrl, NewMockCipher(ctrl))
				inner.EXPECT().Load(gomock.Any(), "pe-load").Return(nil, err)

				_, got := sealing.Load(ctx, "pe-load")

				return got
			}},
		{name: "Seal of the ID token", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				cipher := NewMockCipher(ctrl)
				cipher.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, err)
				sealing, _ := peStore(t, ctrl, cipher)

				return sealing.Create(ctx, federatedSession("pe-seal-id"))
			}},
		{name: "Seal of the CSRF token", unavailable: porterr.ErrUnwalkable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				cipher := NewMockCipher(ctrl)
				cipher.EXPECT().Seal(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, err)
				sealing, _ := peStore(t, ctrl, cipher)

				s := storedSession("pe-seal-csrf")
				s.CSRFToken = csrfPlaintext

				return sealing.Create(ctx, s)
			}},
		{name: "Open of the ID token", unavailable: session.ErrCipherUnavailable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				cipher := NewMockCipher(ctrl)
				cipher.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, peOpenErr(err))
				sealing, inner := peStore(t, ctrl, cipher)
				s := storedSession("pe-open-id")
				s.ExternalIDToken = peStored
				inner.EXPECT().Load(gomock.Any(), "pe-open-id").Return(s, nil)

				_, got := sealing.Load(ctx, "pe-open-id")

				return got
			}},
		{name: "Open of the CSRF token", unavailable: session.ErrCipherUnavailable,
			run: func(t *testing.T, ctx context.Context, ctrl *gomock.Controller, err error) error {
				cipher := NewMockCipher(ctrl)
				cipher.EXPECT().Open(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, peOpenErr(err))
				sealing, inner := peStore(t, ctrl, cipher)
				s := storedSession("pe-open-csrf")
				s.CSRFToken = peStored
				inner.EXPECT().Load(gomock.Any(), "pe-open-csrf").Return(s, nil)

				_, got := sealing.Load(ctx, "pe-open-csrf")

				return got
			}},
	}
}

// peOpenErr is the error the cipher returns for an Open. The plain outage is
// marked as the Cipher contract asks; every other kind is returned as it is.
func peOpenErr(err error) error {
	if err == errPePlain { //nolint:errorlint // identity: a hostile error must not be walked here
		return errors.Join(session.ErrCipherUnavailable, err)
	}

	return err
}

// peClass asserts the outcome class of a flow's error: the library's
// dependency-failure class, never a verdict about the session or the value.
//
// The chain is walked within a bound: on a cycle stdlib errors.Is never ends,
// so a missing sanitizer must fail the row, not hang the package.
func peClass(t *testing.T, flow peFlow, got error) peFacts {
	t.Helper()

	f := peWithin(t, func() peFacts { return peProbe(got) })

	require.False(t, f.isNil, "the flow must fail")
	assert.False(t, f.notFound, "not a verdict that the session is missing")
	assert.False(t, f.expired, "not a verdict that the session expired")
	assert.False(t, f.unreadable, "a hostile error must not end the session")
	assert.NotContains(t, f.text, peSecret)

	if flow.unavailable == session.ErrCipherUnavailable {
		assert.True(t, f.cipher, "the outage branch of the cipher read")
	}

	return f
}

// peFacts is what a caller can tell of a flow's error, computed inside peWithin.
type peFacts struct {
	isNil, notFound, expired, unreadable, cipher, unwalkable bool
	text                                                     string
}

func peProbe(got error) peFacts {
	if got == nil {
		return peFacts{isNil: true}
	}

	return peFacts{
		notFound:   errors.Is(got, session.ErrNotFound),
		expired:    errors.Is(got, session.ErrExpired),
		unreadable: errors.Is(got, session.ErrUnreadable),
		cipher:     errors.Is(got, session.ErrCipherUnavailable),
		unwalkable: errors.Is(got, porterr.ErrUnwalkable),
		text:       got.Error(),
	}
}

func TestPortErrors_EncryptedStore(t *testing.T) { //nolint:paralleltest // swaps slog.Default
	inChildProcess := os.Getenv(peChildEnv) != ""
	if inChildProcess {
		debug.SetMaxStack(64 << 20)
	}

	for _, kind := range peKinds() {
		if kind.child && !inChildProcess {
			t.Run(kind.name, func(t *testing.T) { peInChild(t) })

			continue
		}
		if inChildProcess && !kind.child {
			continue
		}

		for _, flow := range peFlows() {
			t.Run(flow.name+"/"+kind.name, func(t *testing.T) {
				rec := peRecording(t)
				ctrl := gomock.NewController(t)

				ctx := t.Context()
				if kind.cancelled {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}

				err := kind.make(flow.unavailable)
				got := peWithin(t, func() error { return flow.run(t, ctx, ctrl, err) })

				switch {
				case err == errPePlain: //nolint:errorlint // identity: a hostile error must not be walked here
					require.Error(t, got)
					assert.Empty(t, rec.aborts(), "a plain error is not an abort")
					assert.ErrorIs(t, got, errPePlain, "a plain outage keeps its cause")
					peClass(t, flow, got)
				case kind.hostile:
					f := peClass(t, flow, got)
					assert.Len(t, rec.aborts(), 1, "exactly one abort record, to slog.Default()")
					if flow.unavailable == porterr.ErrUnwalkable {
						assert.True(t, f.unwalkable)
					}
				case kind.name == "a typed-nil root":
					assert.Empty(t, rec.aborts(), "a typed nil is not an abort")
				default: // already sanitized
					f := peClass(t, flow, got)
					assert.Empty(t, rec.aborts(), "a fault already sanitized writes no second record")
					if flow.unavailable == session.ErrCipherUnavailable {
						assert.True(t, f.cipher)
					} else {
						assert.True(t, f.unwalkable)
					}
				}
			})
		}
	}
}

// TestPortErrors_EncryptedStore_ForwardedSentinels: a real sentinel from the
// inner store still comes back as itself from every forwarded call, and a
// hostile error never matches one.
func TestPortErrors_EncryptedStore_ForwardedSentinels(t *testing.T) { //nolint:paralleltest // swaps slog.Default
	sentinels := []error{
		session.ErrNotFound, session.ErrSuperseded, session.ErrSuccessorAdvanced, session.ErrExpired,
	}

	for _, flow := range peForwardFlows() {
		for _, sentinel := range sentinels {
			t.Run(flow.name+"/"+sentinel.Error(), func(t *testing.T) {
				peRecording(t)

				got := peWithin(t, func() error { return flow.run(t, t.Context(), gomock.NewController(t), sentinel) })

				assert.True(t, got == sentinel, "the bare sentinel comes back as itself, got %v", got) //nolint:errorlint // identity
				assert.False(t, peWithin(t, func() bool { return errors.Is(got, porterr.ErrUnwalkable) }))
			})
		}

		t.Run(flow.name+"/a hostile error matches no sentinel", func(t *testing.T) {
			peRecording(t)

			got := peWithin(t, func() error { return flow.run(t, t.Context(), gomock.NewController(t), &peCycleOne{}) })

			for _, sentinel := range sentinels {
				assert.False(t, peWithin(t, func() bool { return errors.Is(got, sentinel) }), "%v", sentinel)
			}
		})
	}
}
