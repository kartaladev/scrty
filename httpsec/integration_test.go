package httpsec_test

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

// challengeIssuanceWindow is the issuance window of the chain's challenge
// managers: a one-time manager's default, which the chain does not change.
const challengeIssuanceWindow = time.Hour

// TestChain_ClockMFA pins that the pending-challenge managers the chain builds,
// and their default store, read the chain's time source, and that a store the
// consumer gave keeps its own. Time moves only on a fake clock handed to
// WithClock, never by waiting.
func TestChain_ClockMFA(t *testing.T) {
	t.Parallel()

	// observed is what a row reports: the answers it gave, in order, and what
	// each run of the method's expiry task removed.
	type observed struct {
		answers []served
		removed []int
	}

	type testCase struct {
		name string
		// at is the instant the chain's clock starts at.
		at time.Time
		// store is the consumer's challenge store; nil keeps the default.
		store func() onetime.Store
		// opts are further MFA options.
		opts []httpsec.MFAOption
		// failures is how many failed verifications the row counts.
		failures int
		act      func(t *testing.T, r *clockMFARun) observed
		assert   func(t *testing.T, stub *challengeStub, got observed)
	}

	cases := []testCase{
		{
			name:     "a challenge expires on the chain's clock",
			at:       clockInstant,
			failures: 1,
			act: func(t *testing.T, r *clockMFARun) observed {
				challenge := r.begin(t)
				r.clk.Advance(httpsec.DefaultMFAChallengeTTL + time.Second)

				return observed{answers: []served{r.answer(t, challenge)}}
			},
			assert: func(t *testing.T, stub *challengeStub, got observed) {
				require.Len(t, got.answers, 1)
				require.ErrorIs(t, got.answers[0].err, mfa.ErrInvalidCode,
					"the challenge's lifetime passed on the chain's clock")
				assert.Equal(t, int32(0), stub.verifyCalls.Load(), "an expired challenge never reaches the method")
			},
		},
		{
			name: "the expiry task purges on the chain's clock",
			at:   clockInstant,
			act: func(t *testing.T, r *clockMFARun) observed {
				r.begin(t)
				r.clk.Advance(httpsec.DefaultMFAChallengeTTL + challengeIssuanceWindow + time.Second)

				return observed{removed: []int{r.purge(t)}}
			},
			assert: func(t *testing.T, _ *challengeStub, got observed) {
				assert.Equal(t, []int{1}, got.removed,
					"the lifetime and the issuance window passed on the chain's clock")
			},
		},
		{
			// Review Focus 2: on a clock a year and more behind the system
			// clock, nothing reading the system clock may judge a live
			// challenge expired, and the challenge still expires on the
			// chain's clock.
			name: "a clock behind the system clock keeps a live challenge",
			at:   time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
			act: func(t *testing.T, r *clockMFARun) observed {
				challenge := r.begin(t)
				r.clk.Advance(time.Minute)

				got := observed{answers: []served{r.answer(t, challenge)}}
				got.removed = append(got.removed, r.purge(t))

				r.clk.Advance(httpsec.DefaultMFAChallengeTTL + challengeIssuanceWindow)
				got.removed = append(got.removed, r.purge(t))

				return got
			},
			assert: func(t *testing.T, stub *challengeStub, got observed) {
				require.Len(t, got.answers, 1)
				require.NoError(t, got.answers[0].err, "a challenge begun a minute ago on the chain's clock is live")
				assert.Equal(t, int32(1), stub.verifyCalls.Load())
				assert.Equal(t, []int{0, 1}, got.removed,
					"kept while live, purged once the lifetime and window pass on the chain's clock")
			},
		},
		{
			// Review Focus 2 again, where only the purge could get it wrong: a
			// challenge living longer than the issuance window is a purge
			// candidate while still live, so a store judging expiry on the
			// system clock, years ahead, would delete it.
			name: "a purge on a clock behind the system clock keeps a live challenge",
			at:   time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
			opts: []httpsec.MFAOption{httpsec.WithMFAChallengeTTL(2 * challengeIssuanceWindow)},
			act: func(t *testing.T, r *clockMFARun) observed {
				challenge := r.begin(t)
				r.clk.Advance(challengeIssuanceWindow + time.Minute)

				got := observed{removed: []int{r.purge(t)}}
				got.answers = []served{r.answer(t, challenge)}

				return got
			},
			assert: func(t *testing.T, stub *challengeStub, got observed) {
				assert.Equal(t, []int{0}, got.removed, "the challenge is still live on the chain's clock")
				require.Len(t, got.answers, 1)
				require.NoError(t, got.answers[0].err, "the purge left the live challenge in place")
				assert.Equal(t, int32(1), stub.verifyCalls.Load())
			},
		},
		{
			// The consumer's store reads the system clock, which does not
			// move, so it never finds the challenge expired.
			name:  "a consumer's challenge store keeps its own clock",
			at:    clockInstant,
			store: func() onetime.Store { return onetime.NewMemoryStore() },
			act: func(t *testing.T, r *clockMFARun) observed {
				r.begin(t)
				r.clk.Advance(httpsec.DefaultMFAChallengeTTL + challengeIssuanceWindow + time.Second)

				return observed{removed: []int{r.purge(t)}}
			},
			assert: func(t *testing.T, _ *challengeStub, got observed) {
				assert.Equal(t, []int{0}, got.removed, "the chain did not re-clock the consumer's store")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies()
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(false, nil).AnyTimes()
			h.limiter.EXPECT().RecordFailure(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(nil).Times(tc.failures)

			stub := newChallengeStub()
			h.extra = []mfa.Method{stub}

			h.mfaOpts = tc.opts
			if tc.store != nil {
				h.mfaOpts = append(h.mfaOpts, httpsec.WithMFAChallengeStore(tc.store()))
			}

			clk := clockwork.NewFakeClockAt(tc.at)
			h.chainOpts = []httpsec.Option{httpsec.WithClock(clk)}

			r := &clockMFARun{clk: clk, chain: h.bearerChain(t), session: h.pendingSession(t, factor.Password)}

			tc.assert(t, stub, tc.act(t, r))
		})
	}
}

// clockMFARun is one TestChain_ClockMFA row's chain, its clock and the session
// it begins and answers on.
type clockMFARun struct {
	clk     *clockwork.FakeClock
	chain   *httpsec.Chain
	session *session.Session
}

// begin begins the passkey and returns the challenge issued.
func (r *clockMFARun) begin(t *testing.T) string {
	t.Helper()

	out := serve(t, r.chain, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(r.session.ID)))
	require.NoError(t, out.err, "the begin succeeds")

	challenge := issuedChallenge(t, out)
	require.NotEmpty(t, challenge)

	return challenge
}

// answer answers the passkey with challenge.
func (r *clockMFARun) answer(t *testing.T, challenge string) served {
	t.Helper()

	return serve(t, r.chain, bearerJSON(t.Context(), testPasskeyVerifyPath, mfaTokenFor(r.session.ID), answer(challenge)))
}

// purge runs the passkey's expiry task and returns what it removed.
func (r *clockMFARun) purge(t *testing.T) int {
	t.Helper()

	removed, err := runExpiryTask(t, r.chain.ExpiryTasks(), "mfa-challenges:passkey")
	require.NoError(t, err)

	return removed
}

// TestChain_ClockThrottle pins that the limiters the chain's default factory
// builds read the chain's time source, the IPv6 aggregate included, and that a
// factory the consumer gave keeps its own.
func TestChain_ClockThrottle(t *testing.T) {
	t.Parallel()

	// observed is what a row reports: whether the source was refused for
	// throttling before the chain's clock moved past the window, and after.
	type observed struct {
		before, after bool
	}

	type testCase struct {
		name   string
		act    func(t *testing.T, clk *clockwork.FakeClock) observed
		assert func(t *testing.T, got observed)
	}

	// passwordLogin spends the password-login allowance from one source, tries
	// once more, moves the chain's clock past the window and tries again.
	passwordLogin := func(opts ...httpsec.Option) func(*testing.T, *clockwork.FakeClock) observed {
		return func(t *testing.T, clk *clockwork.FakeClock) observed {
			t.Helper()

			h := newLoginGuardHarness(t)
			c := h.chain(t, nil, nil, append([]httpsec.Option{httpsec.WithClock(clk)}, opts...)...)

			throttled := func(username string) bool {
				out := formLoginFrom(t, c, loginGuardSource, username, "wrong")
				require.Error(t, out.err, "a wrong password never signs in")

				return errors.Is(out.err, ratelimit.ErrThrottled)
			}

			failForm(t, c, 50, "user") // the password-login default: 50 per 15 minutes
			before := throttled("next")

			clk.Advance(15*time.Minute + time.Second)

			return observed{before: before, after: throttled("after")}
		}
	}

	cases := []testCase{
		{
			name: "a throttle window follows the chain's clock",
			act:  passwordLogin(),
			assert: func(t *testing.T, got observed) {
				assert.True(t, got.before, "the allowance is spent")
				assert.False(t, got.after, "the window passed on the chain's clock")
			},
		},
		{
			// Review Focus 3: the consumer's factory builds limiters on the
			// system clock, which does not move.
			name: "a consumer's factory keeps its own clock",
			act: passwordLogin(httpsec.WithRateLimiterFactory(
				ratelimit.MemoryLimiterFactory(ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler))))),
			assert: func(t *testing.T, got observed) {
				assert.True(t, got.before, "the allowance is spent")
				assert.True(t, got.after, "the chain did not re-clock the consumer's factory")
			},
		},
		{
			// The fifth /64 has failed nothing itself: only the /56 aggregate,
			// which the chain's default factory builds, refuses it. A refused
			// key never reaches the key store.
			name: "the IPv6 aggregate follows the chain's clock",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newAPIKeyHarness(t)

				c, err := httpsec.New(httpsec.WithLogger(slog.New(slog.DiscardHandler)),
					httpsec.EnableAPIKey(h.keys), httpsec.WithClock(clk))
				require.NoError(t, err)

				for i := 1; i <= 4; i++ {
					for range 20 { // the API-key default: 20 a minute
						require.True(t, presentUnknownKey(t, h, c, fmt.Sprintf("2001:db8:1:%d::1", i)))
					}
				}

				const fifth = "2001:db8:1:5::1"
				before := !presentUnknownKey(t, h, c, fifth)

				clk.Advance(time.Minute + time.Second)

				return observed{before: before, after: !presentUnknownKey(t, h, c, fifth)}
			},
			assert: func(t *testing.T, got observed) {
				assert.True(t, got.before, "the /56 aggregate is spent")
				assert.False(t, got.after, "the aggregate's window passed on the chain's clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(clockInstant)
			tc.assert(t, tc.act(t, clk))
		})
	}
}

// TestChain_ClockSourceGuardSampling pins that a source guard the chain builds
// samples its throttled-source records on the chain's time source, even over
// a limiter the consumer gave, whose own sense of time it leaves alone.
func TestChain_ClockSourceGuardSampling(t *testing.T) {
	t.Parallel()

	const msgThrottled = "ratelimit: refusing an attempt from a source over its limit"

	h := newAPIKeyHarness(t)
	logs := &capturingHandler{}
	clk := clockwork.NewFakeClockAt(clockInstant)

	// The consumer's limiter reads the system clock: one failure an hour, so
	// the source stays throttled however far the chain's clock moves.
	own, err := ratelimit.NewMemoryLimiter(1, time.Hour,
		ratelimit.WithMemoryLimiterLogger(slog.New(slog.DiscardHandler)))
	require.NoError(t, err)

	c, err := httpsec.New(httpsec.WithLogger(slog.New(logs)), httpsec.WithClock(clk),
		httpsec.EnableAPIKey(h.keys, httpsec.WithAPIKeyLimiter(own)))
	require.NoError(t, err)

	throttledRecords := func() int {
		var n int
		for _, r := range logs.records() {
			if r.Message == msgThrottled {
				n++
			}
		}

		return n
	}

	require.True(t, presentUnknownKey(t, h, c, "203.0.113.9"), "the first failure is within the allowance")
	require.False(t, presentUnknownKey(t, h, c, "203.0.113.9"))
	require.False(t, presentUnknownKey(t, h, c, "203.0.113.9"))
	require.Equal(t, 1, throttledRecords(), "one record per refusal window")

	clk.Advance(ratelimit.DefaultLogInterval + time.Second)

	require.False(t, presentUnknownKey(t, h, c, "203.0.113.9"), "the consumer's limiter still throttles")
	assert.Equal(t, 2, throttledRecords(), "the refusal window passed on the chain's clock")
}

// TestChain_ClockRecovery pins that the recovery core the chain builds reads
// the chain's time source unless the consumer gave it one of its own, which
// then wins.
func TestChain_ClockRecovery(t *testing.T) {
	t.Parallel()

	const (
		issuedTTL = 10 * time.Minute
		window    = time.Hour // the issued-code manager's default issuance window
	)

	type testCase struct {
		name string
		// hold configures the recovery's hold, so a finish and a cancel token exist.
		hold bool
		// coreOpts are the consumer's further core options.
		coreOpts func(other *clockwork.FakeClock) []recovery.Option
		act      func(t *testing.T, h *recoveryHarness, other *clockwork.FakeClock) []int
		assert   func(t *testing.T, removed []int)
	}

	purgeTask := func(t *testing.T, h *recoveryHarness, task string) int {
		t.Helper()

		removed, err := runExpiryTask(t, h.chain.ExpiryTasks(), task)
		require.NoError(t, err)

		return removed
	}

	purge := func(t *testing.T, h *recoveryHarness) int {
		t.Helper()

		return purgeTask(t, h, "recovery-issued-codes")
	}

	// pastHold is past the hold, its 24-hour completion window and the
	// issuance window.
	const pastHold = recoveryHoldDelay + 26*time.Hour

	cases := []testCase{
		{
			name: "recovery codes expire on the chain's clock",
			act: func(t *testing.T, h *recoveryHarness, _ *clockwork.FakeClock) []int {
				h.issued(t)
				h.clock.Advance(issuedTTL + window + time.Second)

				return []int{purge(t, h)}
			},
			assert: func(t *testing.T, removed []int) {
				assert.Equal(t, []int{1}, removed, "the code's lifetime and window passed on the chain's clock")
			},
		},
		{
			// Review Focus 4.
			name: "a recovery core with its own clock keeps it",
			coreOpts: func(other *clockwork.FakeClock) []recovery.Option {
				return []recovery.Option{recovery.WithClock(other)}
			},
			act: func(t *testing.T, h *recoveryHarness, other *clockwork.FakeClock) []int {
				h.issued(t)
				h.clock.Advance(issuedTTL + window + time.Second)
				before := purge(t, h)

				other.Advance(issuedTTL + window + time.Second)

				return []int{before, purge(t, h)}
			},
			assert: func(t *testing.T, removed []int) {
				assert.Equal(t, []int{0, 1}, removed,
					"the code expires on the core's own clock, not the chain's")
			},
		},
		{
			name: "recovery hold tokens expire on the chain's clock",
			hold: true,
			act: func(t *testing.T, h *recoveryHarness, _ *clockwork.FakeClock) []int {
				h.hold(t)
				before := purgeTask(t, h, "recovery-finish-tokens")

				h.clock.Advance(pastHold)

				return []int{before, purgeTask(t, h, "recovery-finish-tokens")}
			},
			assert: func(t *testing.T, removed []int) {
				assert.Equal(t, []int{0, 1}, removed,
					"the finish token is kept while live and removed once its lifetime and window pass on the chain's clock")
			},
		},
		{
			name: "hold tokens keep a recovery core's own clock",
			hold: true,
			coreOpts: func(other *clockwork.FakeClock) []recovery.Option {
				return []recovery.Option{recovery.WithClock(other)}
			},
			act: func(t *testing.T, h *recoveryHarness, other *clockwork.FakeClock) []int {
				h.hold(t)
				h.clock.Advance(pastHold)
				before := purgeTask(t, h, "recovery-finish-tokens")

				other.Advance(pastHold)

				return []int{before, purgeTask(t, h, "recovery-finish-tokens")}
			},
			assert: func(t *testing.T, removed []int) {
				assert.Equal(t, []int{0, 1}, removed,
					"the token expires on the core's own clock, not the chain's")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newRecoveryHarness(t)
			h.clock.Advance(clockInstant.Sub(h.clock.Now()))
			other := clockwork.NewFakeClockAt(time.Date(2050, time.January, 1, 0, 0, 0, 0, time.UTC))

			h.noCoreClock = true
			h.coreOpts = []recovery.Option{recovery.WithIssuedCodeTTL(issuedTTL)}

			if tc.hold {
				h.withHold()
			}

			if tc.coreOpts != nil {
				h.coreOpts = append(h.coreOpts, tc.coreOpts(other)...)
			}
			h.chainOpts = append(h.chainOpts, httpsec.WithClock(h.clock))
			h.build(t)

			tc.assert(t, tc.act(t, h, other))
		})
	}
}

// TestChain_ClockMFAVerify pins that the verification throttle the chain
// builds reads the chain's time source: the default limiter's window and the
// sampling of the throttle's refusal records, the second over a limiter the
// consumer gave, whose own sense of time the chain leaves alone.
func TestChain_ClockMFAVerify(t *testing.T) {
	t.Parallel()

	const msgThrottled = "mfa: verification throttled"

	// run is what a row hands its assertion: the chain's clock, the records the
	// chain's logger took, and a function that answers one wrong code.
	type run struct {
		clk    *clockwork.FakeClock
		logs   *capturingHandler
		answer func(t *testing.T) error
	}

	type testCase struct {
		name string
		// limiter is the consumer's limiter; nil keeps the default.
		limiter func(h *mfaHarness) ratelimit.Limiter
		assert  func(t *testing.T, r run)
	}

	throttledRecords := func(logs *capturingHandler) int {
		var n int

		for _, rec := range logs.records() {
			if rec.Message == msgThrottled {
				n++
			}
		}

		return n
	}

	cases := []testCase{
		{
			name: "the throttle window follows the chain's clock",
			assert: func(t *testing.T, r run) {
				for range 5 {
					require.ErrorIs(t, r.answer(t), mfa.ErrInvalidCode)
				}

				require.ErrorIs(t, r.answer(t), mfa.ErrVerifyThrottled, "the allowance is spent")

				r.clk.Advance(15*time.Minute + time.Second)

				err := r.answer(t)
				require.Error(t, err, "the wrong code is still refused")
				assert.NotErrorIs(t, err, mfa.ErrVerifyThrottled, "the window passed on the chain's clock")
			},
		},
		{
			// The consumer's limiter always throttles, so only the sampler's
			// clock decides how many records are written.
			name: "the throttle's log is sampled on the chain's clock",
			limiter: func(h *mfaHarness) ratelimit.Limiter {
				h.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				return h.limiter
			},
			assert: func(t *testing.T, r run) {
				require.ErrorIs(t, r.answer(t), mfa.ErrVerifyThrottled)
				require.ErrorIs(t, r.answer(t), mfa.ErrVerifyThrottled)
				require.Equal(t, 1, throttledRecords(r.logs), "one record per refusal window")

				r.clk.Advance(61 * time.Second)

				require.ErrorIs(t, r.answer(t), mfa.ErrVerifyThrottled)
				assert.Equal(t, 2, throttledRecords(r.logs), "the refusal window passed on the chain's clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)
			h.method.EXPECT().Verify(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(mfa.ErrInvalidCode).AnyTimes()

			mfaOpts := []httpsec.MFAOption{httpsec.WithMFATokens(h.tokens)}
			if tc.limiter != nil {
				mfaOpts = append(mfaOpts, httpsec.WithMFAVerifyLimiter(tc.limiter(h)))
			}

			clk := clockwork.NewFakeClockAt(clockInstant)
			logs := &capturingHandler{}

			c, err := httpsec.New(
				httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
					Verifier: h.tokens,
					Sessions: h.sessions,
					Users:    h.users,
				}),
				httpsec.EnableMFA([]mfa.Method{h.method}, mfaOpts...),
				httpsec.WithLogger(slog.New(logs)),
				httpsec.WithClock(clk),
			)
			require.NoError(t, err)

			s := h.pendingSession(t, factor.Password)

			tc.assert(t, run{clk: clk, logs: logs, answer: func(t *testing.T) error {
				t.Helper()

				return serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
					testMFAVerifyPath, mfaTokenFor(s.ID), "code="+testMFACode)).err
			}})
		})
	}
}
