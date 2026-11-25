package httpsec_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/ratelimit"
)

// faultyTokenStore is an opaque-token store that fails every Load while down, or has the request's
// caller leave while it loads while hangup.
type faultyTokenStore struct {
	*oidcprovider.MemoryAccessTokenStore

	down, hangup *atomic.Bool
	leave        func()
}

func (s *faultyTokenStore) Load(ctx context.Context, tokenID id.ID) (*oidcprovider.AccessTokenRecord, error) {
	switch {
	case s.hangup.Load():
		s.leave()

		return nil, ctx.Err()
	case s.down.Load():
		return nil, errors.New("token store secret text")
	}

	return s.MemoryAccessTokenStore.Load(ctx, tokenID)
}

// TestResourceServer_ProviderStoreFailures pins that a provider store that fails is a dependency
// failure, answered 500 and never as an invalid token, and that a caller who leaves while it loads
// gets the context's error.
func TestResourceServer_ProviderStoreFailures(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())

	type testCase struct {
		name   string
		fault  func(s *faultyTokenStore)
		assert func(t *testing.T, out psCall, failure error)
	}

	cases := []testCase{
		{
			name:  "a store that fails is a dependency failure",
			fault: func(s *faultyTokenStore) { s.down.Store(true) },
			assert: func(t *testing.T, out psCall, failure error) {
				assert.Equal(t, http.StatusInternalServerError, out.status)
				assert.Empty(t, out.header.Values("WWW-Authenticate"))
				assert.False(t, out.passedOn)
				require.Error(t, failure)
				assert.NotErrorIs(t, failure, httpsec.ErrInvalidToken)
				assert.NotContains(t, failure.Error(), "secret text")
			},
		},
		{
			name:  "a caller who leaves while the store loads gets the context's error",
			fault: func(s *faultyTokenStore) { s.hangup.Store(true) },
			assert: func(t *testing.T, out psCall, failure error) {
				assert.False(t, out.passedOn)
				require.ErrorIs(t, failure, context.Canceled)
				assert.NotErrorIs(t, failure, httpsec.ErrInvalidToken)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var w *psWorld

			store := &faultyTokenStore{
				MemoryAccessTokenStore: must.Must(oidcprovider.NewMemoryAccessTokenStore()),
				down:                   &atomic.Bool{}, hangup: &atomic.Bool{},
			}
			store.leave = func() {
				if leave := w.leave.Load(); leave != nil {
					(*leave)()
				}
			}

			failure := &atomic.Pointer[error]{}
			w = newPSWorld(t, psSetup{
				failure:  failure,
				provider: []oidcprovider.Option{oidcprovider.WithAccessTokenStore(store)},
			})

			tok := w.token(t, psOpaqueClient, &k, forAPI)
			tc.fault(store)

			out := w.call(t, tok, &k, "j-1")

			var err error
			if f := failure.Load(); f != nil {
				err = *f
			}

			tc.assert(t, out, err)
		})
	}
}

// TestResourceServer_ReplayRace pins that two requests racing one DPoP proof through a resource
// server are judged by the one replay store: one is accepted, the other refused as a replayed proof.
// Both are held until both have verified their token, so both reach the replay store together.
func TestResourceServer_ReplayRace(t *testing.T) {
	t.Parallel()

	k := newDPoPKey(t, elliptic.P256())
	clk := clockwork.NewFakeClockAt(dpopNow)

	var arrived sync.WaitGroup

	arrived.Add(2)

	src := &httpsec.StubSource{
		Name: "stub", Fallback: true,
		Verify: func(context.Context, string) (*identity.Principal, map[string]string, error) {
			// The barrier: neither request goes on to its proof until both have verified.
			arrived.Done()
			arrived.Wait()

			return &identity.Principal{ID: "u-1", Kind: identity.KindUser}, map[string]string{"jkt": k.jkt}, nil
		},
	}

	chain, err := httpsec.New(httpsec.WithClock(clk), httpsec.EnableDPoP(httpsec.DPoP{PublicURL: dpopPublicURL}),
		httpsec.EnableResourceServer("urn:orders", httpsec.WithStubSource(src)))
	require.NoError(t, err)

	const tok = "opaque-token"

	proof := k.validProof("one-jti").with(map[string]any{"ath": tokenHash(tok)}).sign(t)

	results := make([]served, 2)

	var done sync.WaitGroup

	for i := range results {
		done.Go(func() {
			req := dpopRequest(t, http.MethodGet, "http://example.com/api/orders", proof)
			req.Header.Set("Authorization", "DPoP "+tok)
			results[i] = serve(t, chain, req)
		})
	}

	done.Wait()

	accepted, replayed := 0, 0

	for _, r := range results {
		switch {
		case r.err == nil && r.handlerRan:
			accepted++
		case errors.Is(r.err, httpsec.ErrInvalidDPoPProof):
			replayed++
		}
	}

	assert.Equal(t, 1, accepted, "exactly one request is accepted")
	assert.Equal(t, 1, replayed, "the other is refused as a replayed proof")
	assert.Equal(t, 2, src.Offered())
}

// failingLinks is a link store whose lookup fails with err.
type failingLinks struct {
	oidc.LinkStore

	err error
}

func (l failingLinks) FindByExternal(context.Context, string, string, string) (*oidc.Link, error) {
	return nil, l.err
}

// TestResourceServer_StrategyFailuresWrappingRefusals pins that a caller strategy's port that fails
// is a dependency failure, answered 500 and not counted against the client, even when the consumer's
// error wraps a sentinel the refusal table answers 401 (or the challenge it answers 401 with).
func TestResourceServer_StrategyFailuresWrappingRefusals(t *testing.T) {
	t.Parallel()

	const secret = "consumer secret text"

	sentinels := map[string]error{
		"ErrInvalidToken":                      httpsec.ErrInvalidToken,
		"ErrInsufficientUserAuthentication":    httpsec.ErrInsufficientUserAuthentication,
		"authenticate.ErrAuthenticationFailed": authenticate.ErrAuthenticationFailed,
	}

	type testCase struct {
		name  string
		build func(t *testing.T, w *isWorld, cause error) httpsec.SourceOption
	}

	cases := []testCase{
		{
			name: "a user loader",
			build: func(t *testing.T, w *isWorld, cause error) httpsec.SourceOption {
				users := NewMockUserLoader(gomock.NewController(t))
				users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).Return(nil, cause).AnyTimes()

				return httpsec.WithLinkedUsers(isLinks(t, w.ep.srv.URL, true), "corp", users)
			},
		},
		{
			name: "a link store",
			build: func(t *testing.T, w *isWorld, cause error) httpsec.SourceOption {
				return httpsec.WithLinkedUsers(failingLinks{LinkStore: isLinks(t, w.ep.srv.URL, true), err: cause},
					"corp", isUsers(t, false))
			},
		},
		{
			name: "a claims mapper",
			build: func(_ *testing.T, _ *isWorld, cause error) httpsec.SourceOption {
				return httpsec.WithClaimsMapper("corp",
					func(context.Context, map[string]any) (httpsec.MappedCaller, error) {
						return httpsec.MappedCaller{}, cause
					})
			},
		},
	}

	for _, tc := range cases {
		for sentinelName, sentinel := range sentinels {
			t.Run(tc.name+" whose error wraps "+sentinelName, func(t *testing.T) {
				t.Parallel()

				cause := fmt.Errorf("%s: %w", secret, sentinel)

				w := newISWorld(t, isSetup{
					opts: func(w *isWorld) []httpsec.SourceOption { return []httpsec.SourceOption{tc.build(t, w, cause)} },
					rs: []httpsec.ResourceServerOption{
						httpsec.WithRefusalLimiter(must.Must(ratelimit.NewMemoryLimiter(1, time.Hour))),
					},
				})

				// Two calls, with a refusal budget of one: a counted failure would throttle the second.
				for range 2 {
					out := w.call(t, "opaque-1", nil)

					assert.Equal(t, http.StatusInternalServerError, out.status)
					assert.False(t, out.ran)
					assert.Empty(t, out.header.Values("WWW-Authenticate"))
					require.Error(t, out.failure)
					assert.NotContains(t, out.failure.Error(), secret)
				}
			})
		}
	}
}
