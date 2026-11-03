package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
)

// replayClock is a clock a replay case moves forward between proofs.
type replayClock struct{ at atomic.Pointer[time.Time] }

func newReplayClock(at time.Time) *replayClock {
	c := &replayClock{}
	c.set(at)

	return c
}

func (c *replayClock) set(at time.Time)        { c.at.Store(&at) }
func (c *replayClock) now() time.Time          { return *c.at.Load() }
func (c *replayClock) advance(d time.Duration) { c.set(c.now().Add(d)) }

// errReplayStoreFixture is a replay store's own error, worded with what the
// refusal must never repeat.
var errReplayStoreFixture = errors.New("redis: dial tcp 10.0.0.7:6379 for jti j-secret")

func TestDPoP_Replay(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	other := newDPoPKey(t, elliptic.P256())

	// fixture is one checker and the clock it reads, and what a case records
	// through it.
	type fixture struct {
		checker *httpsec.DPoPChecker
		clock   *replayClock
		logs    *capturingHandler
	}

	// present runs p through f's checker on a GET of the proof's own URL.
	present := func(t *testing.T, ctx context.Context, f fixture, p proofParts) error {
		t.Helper()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/api/orders", nil)
		req.Header.Set("DPoP", p.sign(t))

		_, err := f.checker.Check(ctx, httpsec.NewHTTPRequest(req), "")

		return err
	}

	// at re-issues p at the clock's current instant.
	at := func(f fixture, p proofParts) proofParts {
		return p.with(map[string]any{"iat": f.clock.now().Unix()})
	}

	// accepted is a prior presentation that must succeed.
	accepted := func(t *testing.T, ctx context.Context, f fixture, p proofParts) {
		t.Helper()
		require.NoError(t, present(t, ctx, f, p), "the first presentation")
	}

	refusedAsInvalid := func(t *testing.T, _ fixture, err error) {
		require.ErrorIs(t, err, httpsec.ErrInvalidDPoPProof)
	}

	errorRecords := func(h *capturingHandler) []slog.Record {
		var out []slog.Record
		for _, r := range h.records() {
			if r.Level >= slog.LevelError {
				out = append(out, r)
			}
		}

		return out
	}

	type testCase struct {
		name  string
		store func(t *testing.T) httpsec.ReplayStore // nil: the default in-memory store
		// storeLag is how far the default store's clock runs ahead of the
		// verifier's, as when the two read the clock at different moments.
		storeLag time.Duration
		ctx      func(ctx context.Context) context.Context
		// before presents the proofs that come first, and moves the clock;
		// nil presents none.
		before func(t *testing.T, ctx context.Context, f fixture)
		// proof is the presentation under test.
		proof  func(f fixture) proofParts
		assert func(t *testing.T, f fixture, err error)
	}

	cases := []testCase{
		{
			name:  "a fresh proof is accepted",
			proof: func(fixture) proofParts { return key.validProof("j-1") },
			assert: func(t *testing.T, _ fixture, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a proof replayed within its lifetime is refused",
			before: func(t *testing.T, ctx context.Context, f fixture) {
				accepted(t, ctx, f, key.validProof("j-1"))
				f.clock.advance(10 * time.Second)
			},
			proof:  func(fixture) proofParts { return key.validProof("j-1") },
			assert: refusedAsInvalid,
		},
		{
			// The iat check passes at the lifetime's last instant, and the
			// store reads its clock a moment later: the record must still
			// be there.
			name: "a proof replayed at the last instant of its lifetime is refused",
			before: func(t *testing.T, ctx context.Context, f fixture) {
				f.clock.set(dpopNow.Add(59 * time.Second))
				accepted(t, ctx, f, key.validProof("j-edge"))
				f.clock.set(dpopNow.Add(60 * time.Second))
			},
			storeLag: time.Millisecond,
			proof:    func(fixture) proofParts { return key.validProof("j-edge") },
			assert:   refusedAsInvalid,
		},
		{
			name: "a jti is refused until its record has expired",
			before: func(t *testing.T, ctx context.Context, f fixture) {
				accepted(t, ctx, f, key.validProof("j-1"))
				f.clock.advance(120*time.Second - time.Millisecond)
			},
			proof:  func(f fixture) proofParts { return at(f, key.validProof("j-1")) },
			assert: refusedAsInvalid,
		},
		{
			name: "a jti is accepted again once its record has expired",
			before: func(t *testing.T, ctx context.Context, f fixture) {
				accepted(t, ctx, f, key.validProof("j-1"))
				f.clock.advance(120 * time.Second)
			},
			proof: func(f fixture) proofParts { return at(f, key.validProof("j-1")) },
			assert: func(t *testing.T, _ fixture, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a proof refused for its htm leaves its jti unrecorded",
			before: func(t *testing.T, ctx context.Context, f fixture) {
				wrong := key.validProof("j-1").with(map[string]any{"htm": http.MethodPost})
				require.ErrorIs(t, present(t, ctx, f, wrong), httpsec.ErrInvalidDPoPProof)
			},
			proof: func(fixture) proofParts { return key.validProof("j-1") },
			assert: func(t *testing.T, _ fixture, err error) {
				require.NoError(t, err, "not refused as a replay")
			},
		},
		{
			name: "the same jti from another key is another proof",
			before: func(t *testing.T, ctx context.Context, f fixture) {
				accepted(t, ctx, f, key.validProof("j-1"))
			},
			proof: func(fixture) proofParts { return other.validProof("j-1") },
			assert: func(t *testing.T, _ fixture, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:  "a jti of 256 bytes is accepted",
			proof: func(fixture) proofParts { return key.validProof(strings.Repeat("j", 256)) },
			assert: func(t *testing.T, _ fixture, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:   "a jti of 300 bytes is refused",
			proof:  func(fixture) proofParts { return key.validProof(strings.Repeat("j", 300)) },
			assert: refusedAsInvalid,
		},
		{
			name: "a consumer's store is asked with a digest, until twice the proof's lifetime",
			store: func(t *testing.T) httpsec.ReplayStore {
				store := NewMockReplayStore(gomock.NewController(t))
				store.EXPECT().Record(gomock.Any(), gomock.Any(), dpopNow.Add(120*time.Second)).
					DoAndReturn(func(_ context.Context, k string, _ time.Time) (bool, error) {
						assert.NotContains(t, k, "j-visible", "the jti is digested, not stored")
						assert.NotContains(t, k, key.jkt)
						assert.NotEmpty(t, k)

						return true, nil
					})

				return store
			},
			proof: func(fixture) proofParts { return key.validProof("j-visible") },
			assert: func(t *testing.T, _ fixture, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "a store that fails is a dependency failure",
			store: func(t *testing.T) httpsec.ReplayStore {
				store := NewMockReplayStore(gomock.NewController(t))
				store.EXPECT().Record(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(false, errReplayStoreFixture)

				return store
			},
			proof: func(fixture) proofParts { return key.validProof("j-secret") },
			assert: func(t *testing.T, f fixture, err error) {
				require.Error(t, err)
				require.ErrorIs(t, err, errReplayStoreFixture, "the store's error stays reachable")
				assert.NotErrorIs(t, err, httpsec.ErrInvalidDPoPProof, "not a refusal")
				assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired, "not charged as a refusal")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err))
				assert.NotContains(t, err.Error(), "10.0.0.7", "fixed library text")
				assert.NotContains(t, err.Error(), "j-secret")

				recs := errorRecords(f.logs)
				require.Len(t, recs, 1, "recorded at ERROR")
				recs[0].Attrs(func(a slog.Attr) bool {
					assert.NotContains(t, a.Value.String(), "10.0.0.7", "by type, never by text")

					return true
				})
			},
		},
		{
			name: "a client that leaves while the store answers is a hang-up",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			store: func(t *testing.T) httpsec.ReplayStore {
				store := NewMockReplayStore(gomock.NewController(t))
				store.EXPECT().Record(gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ string, _ time.Time) (bool, error) {
						return false, ctx.Err()
					})

				return store
			},
			proof: func(fixture) proofParts { return key.validProof("j-1") },
			assert: func(t *testing.T, f fixture, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.NotErrorIs(t, err, httpsec.ErrInvalidDPoPProof)
				assert.Empty(t, errorRecords(f.logs), "nothing at ERROR")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			clk := newReplayClock(dpopNow)
			logs := &capturingHandler{}

			d := httpsec.DPoP{PublicURL: dpopPublicURL}
			if tc.store != nil {
				d.Replay = tc.store(t)
			} else {
				d.Replay = httpsec.NewMemoryReplayStoreForTest(func() time.Time {
					return clk.now().Add(tc.storeLag)
				})
			}

			checker, err := httpsec.NewDPoPChecker(d, clk.now, slog.New(logs))
			require.NoError(t, err)

			f := fixture{checker: checker, clock: clk, logs: logs}
			if tc.before != nil {
				tc.before(t, ctx, f)
			}

			err = present(t, ctx, f, tc.proof(f))
			tc.assert(t, f, err)
		})
	}
}

// TestDPoP_ReplayConcurrent pins that the same valid proof presented by many
// requests at once is accepted exactly once. Run it with -race.
//
// Standalone: a barrier test, not a row of inputs.
func TestDPoP_ReplayConcurrent(t *testing.T) {
	t.Parallel()

	key := newDPoPKey(t, elliptic.P256())
	proof := key.validProof("j-1").sign(t)

	checker, err := httpsec.NewDPoPChecker(httpsec.DPoP{PublicURL: dpopPublicURL}, func() time.Time { return dpopNow },
		slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	const presenters = 32

	var (
		start    sync.WaitGroup
		done     sync.WaitGroup
		accepted atomic.Int64
		refused  atomic.Int64
	)

	start.Add(1)
	for range presenters {
		done.Add(1)
		go func() {
			defer done.Done()

			req := httpsec.NewHTTPRequest(dpopRequest(t, http.MethodGet, "http://example.com/api/orders", proof))
			start.Wait()

			_, err := checker.Check(t.Context(), req, "")
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, httpsec.ErrInvalidDPoPProof):
				refused.Add(1)
			}
		}()
	}
	start.Done()
	done.Wait()

	assert.EqualValues(t, 1, accepted.Load(), "exactly one accepted")
	assert.EqualValues(t, presenters-1, refused.Load(), "every other refused as a replay")
}
