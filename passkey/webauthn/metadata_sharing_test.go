package webauthn_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/passkey/webauthn"
	"github.com/kartaladev/scrty/passkey/webauthn/webauthntest"
)

// gatedFetch is a consumer BLOB fetch that holds every call until release is
// closed, counting the calls and noting whether a call saw its context end.
type gatedFetch struct {
	raw     []byte
	fail    bool
	release chan struct{}
	started chan struct{}

	calls     atomic.Int32
	sawCancel atomic.Bool
}

func newGatedFetch(raw []byte, fail bool) *gatedFetch {
	return &gatedFetch{raw: raw, fail: fail, release: make(chan struct{}), started: make(chan struct{}, 16)}
}

func (g *gatedFetch) fetch(ctx context.Context) ([]byte, error) {
	g.calls.Add(1)
	g.started <- struct{}{}
	select {
	case <-g.release:
	case <-ctx.Done():
		g.sawCancel.Store(true)
		return nil, ctx.Err()
	}
	if g.fail {
		return nil, errors.New("metadata service unavailable")
	}
	return g.raw, nil
}

// gatedRegistrar is a verifier requiring trusted attestation from a source
// whose fetch is gated, and a supply of registration bodies to verify.
type gatedRegistrar struct {
	env  *attestationEnv
	gate *gatedFetch
	v    *webauthn.Verifier
}

func newGatedRegistrar(t *testing.T, fail bool) *gatedRegistrar {
	t.Helper()
	e := newAttestationEnv(t)
	raw := blob{no: 1, nextUpdate: time.Now().Add(72 * time.Hour), entries: []map[string]any{mdsEntry(e.aaguid, e.attRoot, "FIDO_CERTIFIED")}}.
		sign(t, e.signer, e.mdsRoot.cert)
	g := newGatedFetch(raw, fail)
	src := webauthn.MetadataBlob(g.fetch, webauthn.WithMDSRoot(e.mdsRoot.cert))
	return &gatedRegistrar{env: e, gate: g, v: newVerifier(t, webauthn.WithTrustedAttestation(src))}
}

// body is a basic-attested registration response, built on the test
// goroutine so that a failure to build it stops the test.
func (r *gatedRegistrar) body(t *testing.T) []byte {
	t.Helper()
	a := webauthntest.New(t)
	a.AAGUID = r.env.aaguid
	return basicAttestation(t, a, r.env.att)
}

type outcome struct {
	nc  *passkey.NewCredential
	err error
}

// register verifies body under ctx; it is safe to call off the test
// goroutine.
func (r *gatedRegistrar) register(ctx context.Context, body []byte) outcome {
	p, err := r.v.ParseRegistration(body)
	if err != nil {
		return outcome{err: err}
	}
	nc, err := r.v.VerifyRegistration(ctx, p, passkey.RegistrationExpectation{Challenge: challenge, UV: passkey.UVRequired})
	return outcome{nc: nc, err: err}
}

// registerAsync runs register on its own goroutine.
func (r *gatedRegistrar) registerAsync(ctx context.Context, body []byte) <-chan outcome {
	out := make(chan outcome, 1)
	go func() { out <- r.register(ctx, body) }()
	return out
}

// await returns the outcome, failing the test if it does not arrive in time.
func await(t *testing.T, ch <-chan outcome, what string) outcome {
	t.Helper()
	select {
	case o := <-ch:
		return o
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
		return outcome{}
	}
}

func awaitStarted(t *testing.T, g *gatedFetch) {
	t.Helper()
	select {
	case <-g.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the metadata fetch did not start")
	}
}

// TestMetadataSource_ConcurrentCallersShareOneFetch pins that registrations
// arriving while the BLOB is being fetched wait for that fetch and share its
// result, whether it succeeds or fails, rather than fetching again.
func TestMetadataSource_ConcurrentCallersShareOneFetch(t *testing.T) {
	t.Parallel()

	const callers = 5

	type testCase struct {
		name   string
		fail   bool
		assert func(t *testing.T, outcomes []outcome)
	}

	cases := []testCase{
		{
			name: "a failed fetch is shared and refuses every waiter",
			fail: true,
			assert: func(t *testing.T, outcomes []outcome) {
				for _, o := range outcomes {
					require.ErrorIs(t, o.err, passkey.ErrAttestationRefused)
				}
			},
		},
		{
			name: "a successful fetch is shared and trusts every waiter",
			assert: func(t *testing.T, outcomes []outcome) {
				for _, o := range outcomes {
					trustedOK(t, o.nc, o.err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				r := newGatedRegistrar(t, tc.fail)
				bodies := make([][]byte, callers)
				for i := range bodies {
					bodies[i] = r.body(t)
				}

				outcomes := make([]outcome, callers)
				var wg sync.WaitGroup
				for i := range callers {
					wg.Go(func() { outcomes[i] = r.register(t.Context(), bodies[i]) })
				}
				synctest.Wait() // every caller is now waiting on the fetch
				close(r.gate.release)
				wg.Wait()

				assert.Equal(t, int32(1), r.gate.calls.Load(), "concurrent callers each fetched the BLOB")
				tc.assert(t, outcomes)
			})
		})
	}
}

// TestMetadataSource_CallerContext pins that each caller is bound by its own
// context while the BLOB is fetched, and that one caller's cancellation does
// not fail the fetch others share.
func TestMetadataSource_CallerContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		run  func(t *testing.T, r *gatedRegistrar)
	}

	cases := []testCase{
		{
			name: "a waiter whose context expires returns its context error while another caller's fetch is in flight",
			run: func(t *testing.T, r *gatedRegistrar) {
				first := r.registerAsync(t.Context(), r.body(t))
				awaitStarted(t, r.gate)

				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
				defer cancel()
				o := await(t, r.registerAsync(ctx, r.body(t)), "a waiter whose context expired")
				require.ErrorIs(t, o.err, context.DeadlineExceeded)
				assert.NotErrorIs(t, o.err, passkey.ErrAttestationRefused)
				assert.Nil(t, o.nc)

				close(r.gate.release)
				o = await(t, first, "the fetching caller")
				trustedOK(t, o.nc, o.err)
			},
		},
		{
			name: "a caller cancelled during its own fetch returns its context error, not a refusal",
			run: func(t *testing.T, r *gatedRegistrar) {
				ctx, cancel := context.WithCancel(t.Context())
				first := r.registerAsync(ctx, r.body(t))
				awaitStarted(t, r.gate)
				cancel()

				o := await(t, first, "the cancelled caller")
				require.ErrorIs(t, o.err, context.Canceled)
				assert.NotErrorIs(t, o.err, passkey.ErrAttestationRefused)
				assert.Nil(t, o.nc)
				close(r.gate.release)
			},
		},
		{
			name: "one caller cancelling does not fail the fetch another caller shares",
			run: func(t *testing.T, r *gatedRegistrar) {
				ctx, cancel := context.WithCancel(t.Context())
				first := r.registerAsync(ctx, r.body(t))
				awaitStarted(t, r.gate)
				cancel()
				o := await(t, first, "the cancelled caller")
				require.ErrorIs(t, o.err, context.Canceled)

				second := r.registerAsync(t.Context(), r.body(t))
				close(r.gate.release)
				o = await(t, second, "the remaining caller")
				trustedOK(t, o.nc, o.err)
				assert.False(t, r.gate.sawCancel.Load(), "the shared fetch saw one caller's cancellation")
				assert.Equal(t, int32(1), r.gate.calls.Load())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGatedRegistrar(t, false)
			t.Cleanup(func() {
				select {
				case <-r.gate.release:
				default:
					close(r.gate.release)
				}
			})
			tc.run(t, r)
		})
	}
}
