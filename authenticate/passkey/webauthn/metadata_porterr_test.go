package webauthn_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/authenticate/passkey/webauthn"
)

// The consumer's port in trusted attestation is the fetch function given to
// MetadataBlob. MetadataSource itself has unexported methods, so only the
// library implements it. The fetch's error is compared with nil and dropped:
// the source answers its own unavailable error instead, so nothing ever reads
// the consumer's chain. These rows pin that a hostile fetch error takes
// exactly the branch a plain metadata outage takes: the registration is
// refused with passkey.ErrAttestationRefused, never trusted, never hanging or
// panicking, and nothing is logged on its behalf.

// mdSecret stands for consumer data an error might carry.
const mdSecret = "metadata-secret-7f3a"

// mdCycleOne contains itself through Unwrap() error.
type mdCycleOne struct{}

func (*mdCycleOne) Error() string   { return "cycle one: " + mdSecret }
func (c *mdCycleOne) Unwrap() error { return c }

// mdCycleMany contains itself through Unwrap() []error. A stdlib walk of it
// overflows the stack fatally, so its row runs in a child process.
type mdCycleMany struct{}

func (*mdCycleMany) Error() string     { return "cycle many: " + mdSecret }
func (c *mdCycleMany) Unwrap() []error { return []error{c} }

// mdPanicUnwrap is a link whose Unwrap panics.
type mdPanicUnwrap struct{}

func (mdPanicUnwrap) Error() string { return "panic unwrap: " + mdSecret }
func (mdPanicUnwrap) Unwrap() error { panic("test: Unwrap panicked for " + mdSecret) }

// mdPanicNilUnwrap is a link whose Unwrap panics with nil.
type mdPanicNilUnwrap struct{}

func (mdPanicNilUnwrap) Error() string { return "panic nil unwrap: " + mdSecret }
func (mdPanicNilUnwrap) Unwrap() error { panic(nil) }

// mdPanicIs is a link whose Is panics for every target.
type mdPanicIs struct{}

func (mdPanicIs) Error() string { return "panic is: " + mdSecret }
func (mdPanicIs) Is(error) bool { panic("test: Is panicked for " + mdSecret) }

// mdTypedNil is the error type of a typed-nil root.
type mdTypedNil struct{}

func (*mdTypedNil) Error() string { return "typed nil" }

// mdFanOut is 25 levels of errors.Join(n, n): seconds for a stdlib walk.
func mdFanOut() error {
	err := errors.New("leaf: " + mdSecret)
	for range 25 {
		err = errors.Join(err, err)
	}

	return err
}

const (
	mdPortErrRowEnv  = "SCRTY_WEBAUTHN_PORTERR_ROW"
	mdPortErrTimeout = 10 * time.Second
	mdPlainOutage    = "a plain metadata outage"
	mdCycleManyRow   = "a cycle through Unwrap() []error"
)

// mdPortErrRanMarker is the line a child prints once its row has run and
// passed. The parent requires one line of the child's output to equal it.
func mdPortErrRanMarker(row string) string { return "WEBAUTHN-PORTERR-ROW-RAN:" + row }

// mdCountingHandler counts every record handed to it.
type mdCountingHandler struct{ n *atomic.Int32 }

func (mdCountingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h mdCountingHandler) Handle(context.Context, slog.Record) error {
	h.n.Add(1)
	return nil
}

func (h mdCountingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h mdCountingHandler) WithGroup(string) slog.Handler      { return h }

// mdRegisterWithFetchError runs one trusted registration against a source
// whose fetch answers fetchErr, bounded by mdPortErrTimeout. A panic on the
// registration's goroutine is returned, not raised.
func mdRegisterWithFetchError(
	ctx context.Context, t *testing.T, fetchErr func() error,
) (nc *passkey.CredentialInput, panicked any, err error) {
	t.Helper()

	e := newAttestationEnv(t)
	src := webauthn.MetadataBlob(
		func(context.Context) ([]byte, error) { return nil, fetchErr() },
		webauthn.WithMDSRoot(e.mdsRoot.cert),
	)
	r := &gatedRegistrar{env: e, v: newVerifier(t, webauthn.WithTrustedAttestation(src))}
	body := r.body(t)

	type result struct {
		o        outcome
		panicked any
		didPanic bool
	}

	done := make(chan result, 1)

	go func() {
		res := result{didPanic: true}
		defer func() {
			if res.didPanic {
				res.panicked = recover()
				if res.panicked == nil {
					res.panicked = "panic(nil)"
				}
			}
			done <- res
		}()

		res.o = r.register(ctx, body)
		res.didPanic = false
	}()

	select {
	case res := <-done:
		return res.o.nc, res.panicked, res.o.err
	case <-time.After(mdPortErrTimeout):
		t.Fatalf("the registration did not return within %s", mdPortErrTimeout)
		return nil, nil, nil
	}
}

// TestMetadataPortErrors pins that a consumer metadata fetch answering a
// hostile error refuses the registration exactly as a plain outage does.
//
// It swaps slog.Default to count records, so neither it nor its rows run in
// parallel.
func TestMetadataPortErrors(t *testing.T) { //nolint:paralleltest // swaps slog.Default
	childRow := os.Getenv(mdPortErrRowEnv)

	records := &atomic.Int32{}
	prev := slog.Default()
	slog.SetDefault(slog.New(mdCountingHandler{n: records}))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_, outagePanic, outageErr := mdRegisterWithFetchError(t.Context(), t,
		func() error { return errors.New("metadata service unavailable") })
	require.Nil(t, outagePanic)
	require.ErrorIs(t, outageErr, passkey.ErrAttestationRefused)

	// refusedAsOutage asserts the outcome a plain outage gets: refused with the
	// same error text, no credential, no panic, nothing logged.
	refusedAsOutage := func(t *testing.T, nc *passkey.CredentialInput, err error, panicked any) {
		t.Helper()
		require.Nil(t, panicked, "the registration panicked")
		assert.Nil(t, nc, "a credential was returned")
		require.ErrorIs(t, err, passkey.ErrAttestationRefused)
		assert.Equal(t, outageErr.Error(), err.Error(), "the refusal differs from the outage's")
		assert.NotContains(t, err.Error(), mdSecret)
		assert.Zero(t, records.Load(), "a record was written")
	}

	type testCase struct {
		name     string
		fetchErr func() error
		ctx      func(ctx context.Context) context.Context
		child    bool
		assert   func(t *testing.T, nc *passkey.CredentialInput, err error, panicked any)
	}

	cases := []testCase{
		{name: mdPlainOutage, fetchErr: func() error { return errors.New("metadata service unavailable") }, assert: refusedAsOutage},
		{name: "a cycle through Unwrap() error", fetchErr: func() error { return &mdCycleOne{} }, assert: refusedAsOutage},
		{name: mdCycleManyRow, fetchErr: func() error { return &mdCycleMany{} }, child: true, assert: refusedAsOutage},
		{name: "a join that fans out", fetchErr: mdFanOut, assert: refusedAsOutage},
		{
			name:     "a link whose Unwrap panics",
			fetchErr: func() error { return fmt.Errorf("fetch: %w", mdPanicUnwrap{}) },
			assert:   refusedAsOutage,
		},
		{
			name:     "a link whose Unwrap panics with nil",
			fetchErr: func() error { return fmt.Errorf("fetch: %w", mdPanicNilUnwrap{}) },
			assert:   refusedAsOutage,
		},
		{
			name:     "a link whose Is panics",
			fetchErr: func() error { return fmt.Errorf("fetch: %w", mdPanicIs{}) },
			assert:   refusedAsOutage,
		},
		{
			name: "a typed-nil root",
			fetchErr: func() error {
				var p *mdTypedNil
				return p
			},
			assert: refusedAsOutage,
		},
		{
			name:     "a cancelled context answers the context's error, not a refusal",
			fetchErr: func() error { return &mdCycleOne{} },
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, nc *passkey.CredentialInput, err error, panicked any) {
				t.Helper()
				require.Nil(t, panicked, "the registration panicked")
				assert.Nil(t, nc)
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, passkey.ErrAttestationRefused)
				assert.Zero(t, records.Load(), "a record was written")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if childRow != "" && childRow != tc.name {
				t.Skip("the child runs one row only")
			}

			if tc.child && childRow == "" {
				mdRunChild(t, tc.name)
				return
			}

			records.Store(0)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			nc, panicked, err := mdRegisterWithFetchError(ctx, t, tc.fetchErr)
			tc.assert(t, nc, err, panicked)

			if childRow == tc.name && !t.Failed() {
				fmt.Println(mdPortErrRanMarker(tc.name)) //nolint:forbidigo // the parent reads this line
			}
		})
	}
}

// mdRunChild runs row in a child test process, where a fatal stack overflow
// cannot take the parent down. The child must exit 0 within a minute and print
// a line equal to the row's marker, so a row the child never ran fails.
func mdRunChild(t *testing.T, row string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	//nolint:gosec // G204: re-runs this test binary with this test's own name
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMetadataPortErrors$", "-test.count=1")
	cmd.Env = append(os.Environ(), mdPortErrRowEnv+"="+row)

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the child did not finish within a minute")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	require.NoError(t, err, "the child failed:\n%s", strings.Join(lines[:min(len(lines), 12)], "\n"))

	want := mdPortErrRanMarker(row)
	ran := false

	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			ran = true
		}
	}

	require.True(t, ran, "the child never ran row %q (no line equals %q); output:\n%s", row, want, out)
}
