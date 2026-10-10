package pglimiter_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/internal/pglimiter"
	"github.com/kartaladev/scrty/ratelimit"
)

// builtLimiter stands for the limiter a claim's build returns; its id tells
// the builds apart.
type builtLimiter struct{ id int }

func (*builtLimiter) Exceeded(context.Context, string) (bool, error) { return false, nil }
func (*builtLimiter) RecordFailure(context.Context, string) error    { return nil }

// claim is one Registry.Claim call: buildErr makes its build fail.
type claim struct {
	namespace string
	policy    pglimiter.Policy
	buildErr  error
}

// claimResult is what one claim returned, and whether its build ran.
type claimResult struct {
	limiter ratelimit.Limiter
	err     error
	built   bool
}

var errBuild = errors.New("build refused")

func TestRegistryClaim(t *testing.T) {
	t.Parallel()

	threePerMinute := pglimiter.Policy{Limit: 3, Window: time.Minute}

	type testCase struct {
		name   string
		claims []claim
		assert func(t *testing.T, results []claimResult)
	}

	cases := []testCase{
		{
			name: "same policy twice builds twice",
			claims: []claim{
				{namespace: "mfa-verify", policy: threePerMinute},
				{namespace: "mfa-verify", policy: threePerMinute},
			},
			assert: func(t *testing.T, results []claimResult) {
				for i, r := range results {
					require.NoError(t, r.err)
					assert.True(t, r.built, "claim %d built", i)
					assert.Equal(t, &builtLimiter{id: i}, r.limiter)
				}
			},
		},
		{
			name: "different limit is refused, naming both policies",
			claims: []claim{
				{namespace: "mfa-verify", policy: threePerMinute},
				{namespace: "mfa-verify", policy: pglimiter.Policy{Limit: 4, Window: time.Minute}},
			},
			assert: func(t *testing.T, results []claimResult) {
				require.NoError(t, results[0].err)
				refusedWith(`namespace "mfa-verify" is already built with 3 per 1m0s, and was asked for 4 per 1m0s; `+
					"one bucket cannot hold two policies")(t, results[1].err)
				assert.Nil(t, results[1].limiter)
				assert.False(t, results[1].built, "a refused claim builds nothing")
			},
		},
		{
			name: "different window is refused",
			claims: []claim{
				{namespace: "mfa-verify", policy: threePerMinute},
				{namespace: "mfa-verify", policy: pglimiter.Policy{Limit: 3, Window: time.Hour}},
			},
			assert: func(t *testing.T, results []claimResult) {
				refusedWith(`namespace "mfa-verify" is already built with 3 per 1m0s, and was asked for 3 per 1h0m0s; `+
					"one bucket cannot hold two policies")(t, results[1].err)
				assert.False(t, results[1].built)
			},
		},
		{
			name: "failed build does not claim the namespace",
			claims: []claim{
				{namespace: "mfa-verify", policy: threePerMinute, buildErr: errBuild},
				{namespace: "mfa-verify", policy: pglimiter.Policy{Limit: 4, Window: time.Minute}},
			},
			assert: func(t *testing.T, results []claimResult) {
				require.ErrorIs(t, results[0].err, errBuild)
				assert.Nil(t, results[0].limiter)
				require.NoError(t, results[1].err)
				assert.Equal(t, &builtLimiter{id: 1}, results[1].limiter)
			},
		},
		{
			name: "namespaces are claimed apart",
			claims: []claim{
				{namespace: "mfa-verify", policy: threePerMinute},
				{namespace: "login", policy: pglimiter.Policy{Limit: 10, Window: time.Hour}},
			},
			assert: func(t *testing.T, results []claimResult) {
				require.NoError(t, results[0].err)
				require.NoError(t, results[1].err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := pglimiter.NewRegistry()
			results := make([]claimResult, len(tc.claims))
			for i, c := range tc.claims {
				l, err := r.Claim(c.namespace, c.policy, func() (ratelimit.Limiter, error) {
					results[i].built = true
					if c.buildErr != nil {
						return nil, c.buildErr
					}
					return &builtLimiter{id: i}, nil
				})
				results[i].limiter, results[i].err = l, err
			}
			tc.assert(t, results)
		})
	}
}

// TestRegistryClaim_ConcurrentPolicies pins that a claim's build runs under
// the registry's lock: while the first claim of a namespace is still
// building, a claim of the same namespace with another policy waits, and once
// the first build has claimed the namespace, the second is refused.
func TestRegistryClaim_ConcurrentPolicies(t *testing.T) {
	t.Parallel()

	// held is how long the second claim is given to return while the first
	// build is held. A claim that does not wait returns in microseconds, so
	// this only bounds how long a correct run takes.
	const held = 100 * time.Millisecond

	r := pglimiter.NewRegistry()
	building := make(chan struct{})
	release := make(chan struct{})

	first := make(chan error, 1)
	go func() {
		_, err := r.Claim("mfa-verify", pglimiter.Policy{Limit: 3, Window: time.Minute}, func() (ratelimit.Limiter, error) {
			close(building)
			<-release
			return &builtLimiter{id: 0}, nil
		})
		first <- err
	}()
	<-building

	second := make(chan claimResult, 1)
	go func() {
		var res claimResult
		res.limiter, res.err = r.Claim("mfa-verify", pglimiter.Policy{Limit: 4, Window: time.Minute}, func() (ratelimit.Limiter, error) {
			res.built = true
			return &builtLimiter{id: 1}, nil
		})
		second <- res
	}()

	select {
	case res := <-second:
		close(release)
		t.Fatalf("the second claim returned while the first build was held: %+v", res)
	case <-time.After(held):
	}
	close(release)

	require.NoError(t, <-first)
	res := <-second
	refusedWith(`namespace "mfa-verify" is already built with 3 per 1m0s, and was asked for 4 per 1m0s; `+
		"one bucket cannot hold two policies")(t, res.err)
	assert.Nil(t, res.limiter)
	assert.False(t, res.built, "a refused claim builds nothing")
}
