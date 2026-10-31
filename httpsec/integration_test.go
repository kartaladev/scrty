package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/apikey"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/authenticate/password"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
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

// The two callers in these tests: a person who signs in by link and then proves
// a second factor, and a machine that presents a key.
const (
	integrationUser    identity.UserID = "u-1"
	integrationAddress                 = "ada@example.com"
	integrationService identity.UserID = "svc-billing"
	integrationSource                  = "203.0.113.7"
	otherSource                        = "198.51.100.4"
)

// integrationHarness is one deployment: one session store, one token
// generator, and all three authentication methods wired into one chain behind a
// second-factor policy — which is the only way to find out whether they
// compose.
type integrationHarness struct {
	sessions *session.Sessions
	tokens   *MockGenerator
	users    *MockUserLoader
	sender   *capturingSender

	links  *magiclink.Links
	totp   *mfa.TOTP
	secret string
	clock  *clockwork.FakeClock

	keys   *apikey.Keys
	apiKey string

	// shared is one limiter handed to both the magic-link and the API key
	// flow, for the case that asks whether one instance merges their
	// allowances.
	shared ratelimit.Limiter

	chain *httpsec.Chain
}

func newIntegrationHarness(t *testing.T) *integrationHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	ctx := t.Context()

	sessions, err := session.New()
	require.NoError(t, err)

	h := &integrationHarness{
		sessions: sessions,
		tokens:   NewMockGenerator(ctrl),
		users:    NewMockUserLoader(ctrl),
		sender:   &capturingSender{},
		clock:    clockwork.NewFakeClockAt(time.Date(2026, time.September, 24, 9, 0, 0, 0, time.UTC)),
	}

	h.wireUsers()
	h.wireTokens()

	onetimes, err := onetime.New("magic-link", onetime.WithTokenTTL(magicLinkTTL))
	require.NoError(t, err)

	h.links, err = magiclink.New(
		onetimes, h.users, h.sender, "https://app.example.com")
	require.NoError(t, err)

	h.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll",
		mfa.WithClock(h.clock))
	require.NoError(t, err)

	h.enrol(ctx, t)

	h.keys, err = apikey.New()
	require.NoError(t, err)

	h.apiKey, _, err = h.keys.Issue(ctx, integrationService, "billing", nil, 0)
	require.NoError(t, err)

	h.chain = h.buildChain(t)

	return h
}

// shareOneLimiter rebuilds the chain with a single limiter behind both the
// magic-link and the API key flow.
func (h *integrationHarness) shareOneLimiter(t *testing.T) {
	t.Helper()

	limiter, err := ratelimit.NewMemoryLimiter(10, 15*time.Minute)
	require.NoError(t, err)

	h.shared = limiter
	h.chain = h.buildChain(t)
}

// wireUsers answers for the one person in these tests, by address and by
// reference: a link records the reference and redemption loads by it.
func (h *integrationHarness) wireUsers() {
	details := func() *identity.Details {
		return &identity.Details{
			ID:       integrationUser,
			Name:     "Ada Lovelace",
			Username: integrationAddress,
			Active:   true,
		}
	}

	h.users.EXPECT().LoadByUsername(gomock.Any(), integrationAddress).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) {
			return details(), nil
		})

	h.users.EXPECT().LoadByUserID(gomock.Any(), integrationUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			return details(), nil
		})

	h.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, identity.ErrUserNotFound)
	h.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, identity.ErrUserNotFound)
}

// wireTokens issues tokens that name the session they were issued for and
// verifies them back, which is what a real generator does through the jti and
// what makes a rotation observable from the client's side.
func (h *integrationHarness) wireTokens() {
	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			return mfaTokenFor(id), nil
		})

	h.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(integrationAddress, id), nil
		})
}

// enrol gives the user a confirmed authenticator enrolment, then moves the
// clock past the step the confirmation spent, so the next code is a new one.
func (h *integrationHarness) enrol(ctx context.Context, t *testing.T) {
	t.Helper()

	provisioning, err := h.totp.BeginEnrolment(ctx, integrationUser, integrationAddress)
	require.NoError(t, err)

	h.secret = provisioning.Secret

	require.NoError(t, h.totp.ConfirmEnrolment(ctx, integrationUser, h.code(t)))

	h.clock.Advance(2 * 30 * time.Second)

	enrolled, err := h.totp.Enrolled(ctx, integrationUser)
	require.NoError(t, err)
	require.True(t, enrolled)
}

// code is the code an authenticator would show at the current instant.
func (h *integrationHarness) code(t *testing.T) string {
	t.Helper()

	c, err := totp.GenerateCode(h.secret, h.clock.Now())
	require.NoError(t, err)

	return c
}

// buildChain wires all three methods into one chain behind the real
// second-factor policy.
func (h *integrationHarness) buildChain(t *testing.T) *httpsec.Chain {
	t.Helper()

	lookups, err := mfa.LookupsFor(h.totp)
	require.NoError(t, err)

	challenge, err := policy.NewMFA(lookups)
	require.NoError(t, err)

	engine, err := policy.NewEngine(challenge)
	require.NoError(t, err)

	linkOpts := []httpsec.MagicLinkOption{
		httpsec.WithMagicLinkSessions(h.sessions),
		httpsec.WithMagicLinkTokens(h.tokens),
	}

	var keyOpts []httpsec.APIKeyOption

	if h.shared != nil {
		linkOpts = append(linkOpts, httpsec.WithMagicLinkLimiter(h.shared))
		keyOpts = append(keyOpts, httpsec.WithAPIKeyLimiter(h.shared))
	}

	c, err := httpsec.New(
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableMagicLink(h.links, linkOpts...),
		httpsec.EnableAPIKey(h.keys, keyOpts...),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: h.tokens,
			Sessions: h.sessions,
			Users:    h.users,
		}),
		httpsec.EnableMFA([]mfa.Method{h.totp}, httpsec.WithMFATokens(h.tokens)),
	)
	require.NoError(t, err)

	return c
}

// requestLink asks for a link from source and returns the token the message
// carried and the binding the browser now holds.
func (h *integrationHarness) requestLink(t *testing.T, source string) (token, nonce string) {
	t.Helper()

	out := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath,
		source, url.Values{"email": {integrationAddress}, "next": {"/"}}))
	require.NoError(t, out.err)
	require.Equal(t, http.StatusAccepted, out.rec.Code)

	cookie := cookieNamed(out.rec, httpsec.DefaultBindingCookieName)
	require.NotNil(t, cookie)

	return h.sender.lastToken(t), cookie.Value
}

// redeem posts a link back from source, as the confirmation page would.
func (h *integrationHarness) redeem(t *testing.T, source, link, nonce string) served {
	t.Helper()

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, source,
		url.Values{"token": {link}})
	if nonce != "" {
		req.AddCookie(bindingCookie(nonce))
	}

	return serve(t, h.chain, req)
}

// get requests a protected route with an access token, as a client does.
func (h *integrationHarness) get(t *testing.T, accessToken string) served {
	t.Helper()

	req := getFrom(t.Context(), "/invoices", integrationSource)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	return serve(t, h.chain, req)
}

// getWithKey requests a protected route with an API key, as a machine does.
func (h *integrationHarness) getWithKey(t *testing.T, source, key string) served {
	t.Helper()

	req := getFrom(t.Context(), "/invoices", source)
	req.Header.Set("Authorization", httpsec.DefaultAPIKeyScheme+key)

	return serve(t, h.chain, req)
}

// verify posts a code from source with the credential the caller currently
// holds.
func (h *integrationHarness) verify(t *testing.T, source, accessToken, code string) served {
	t.Helper()

	req := postValues(t.Context(), testMFAVerifyPath, source,
		url.Values{"code": {code}})
	req.Header.Set("Authorization", "Bearer "+accessToken)

	return serve(t, h.chain, req)
}

// accessTokenFrom reads the credential a verify response returned.
func accessTokenFrom(t *testing.T, out served) string {
	t.Helper()

	var body verifyBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)

	return body.AccessToken
}

// TestMagicLinkThenMFA is the whole flow a person goes through when a
// deployment runs passwordless sign-in behind a second-factor policy: ask for a
// link, follow it, be challenged, prove the second factor, and carry on — with
// nothing but the credentials the responses handed back.
func TestMagicLinkThenMFA(t *testing.T) {
	t.Parallel()

	h := newIntegrationHarness(t)

	// 1. A link is asked for and sent.
	link, nonce := h.requestLink(t, integrationSource)

	// 2. Following it spends the link and opens a session, which the policy
	//    challenges because the user has an authenticator enrolment on a
	//    channel other than the link's.
	redeemed := h.redeem(t, integrationSource, link, nonce)

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, redeemed.err, &ch)
	assert.Equal(t, policy.ChallengeMFA, ch.Kind)
	assert.Equal(t, []httpsec.MFAMethod{{Name: "totp", Channel: factor.AuthenticatorApp}}, ch.Methods,
		"the magic-link login's challenge names the method the user can answer it with")
	require.NotNil(t, ch.Session)
	assert.Equal(t, factor.MagicLink, ch.Session.FirstFactor)
	assert.Equal(t, session.MFAPending, ch.Session.MFA)
	require.NotEmpty(t, ch.Token, "the credential the prompt is answered with")

	pending := ch.Session.ID

	// The credential the login handed back. It is kept in its own variable
	// because the gate's refusal below carries no token — a gate challenges a
	// session that already exists, so it issues nothing.
	pendingToken := ch.Token

	// 3. That credential reaches nothing but the endpoints a pending session
	//    may reach.
	held := h.get(t, pendingToken)

	var gate *httpsec.ChallengeError
	require.ErrorAs(t, held.err, &gate)
	assert.Equal(t, policy.ChallengeMFA, gate.Kind)
	assert.Equal(t, ch.Methods, gate.Methods, "the gate's challenge names the same methods")
	assert.Empty(t, gate.Token)
	assert.False(t, held.handlerRan, "the gate holds the protected route")

	// 4. The second factor is accepted and the handle rotates.
	verified := h.verify(t, integrationSource, pendingToken, h.code(t))
	require.NoError(t, verified.err)
	require.Equal(t, http.StatusOK, verified.rec.Code)

	rotated := accessTokenFrom(t, verified)
	assert.NotEqual(t, pendingToken, rotated,
		"the credential the caller carries away is a new one")

	_, err := h.sessions.Load(t.Context(), pending)
	require.Error(t, err, "the pre-MFA handle is gone")

	// 5. The protected route now serves — with the credential the verify
	//    response returned, which is all a real client has.
	served := h.get(t, rotated)
	require.NoError(t, served.err)
	assert.True(t, served.handlerRan)

	// And the credential the caller arrived with is dead.
	stale := h.get(t, pendingToken)
	require.ErrorIs(t, stale.err, httpsec.ErrAuthenticationRequired)
	assert.False(t, stale.handlerRan)
}

// TestAPIKeyBypassesMFAGate pins that a machine caller is unaffected by a
// second-factor policy. Its first factor is exempt, and it holds no session for
// the gate to judge.
func TestAPIKeyBypassesMFAGate(t *testing.T) {
	t.Parallel()

	h := newIntegrationHarness(t)

	out := h.getWithKey(t, integrationSource, h.apiKey)

	require.NoError(t, out.err)
	require.True(t, out.handlerRan, "a valid key reaches the application")
	require.NotNil(t, out.handled.Authentication)
	assert.Equal(t, integrationService, out.handled.Authentication.Principal.ID)
	assert.Nil(t, out.handled.Session, "and establishes no session")

	count, err := h.sessions.CountActiveByUser(t.Context(), integrationService)
	require.NoError(t, err)
	assert.Zero(t, count)
}

// TestFlowLimitersAreIndependent pins that exhausting one flow's allowance from
// a source leaves the other flows open to it. A shared bucket would let anyone
// who can guess links lock a deployment's machines out of its API.
//
// The second case asks the sharper question: a consumer who hands one limiter
// to both flows is choosing one store and one limit, not one allowance. The
// flow name is part of every key, so the two still count separately — and a
// deployment that wires one Redis limiter everywhere does not discover
// otherwise under attack.
func TestFlowLimitersAreIndependent(t *testing.T) {
	t.Parallel()

	t.Run("the default limiters", func(t *testing.T) {
		t.Parallel()

		assertFlowsAreIndependent(t, newIntegrationHarness(t))
	})

	t.Run("one limiter shared by both flows", func(t *testing.T) {
		t.Parallel()

		h := newIntegrationHarness(t)
		h.shareOneLimiter(t)

		assertFlowsAreIndependent(t, h)
	})
}

// assertFlowsAreIndependent exhausts the magic-link allowance for one source
// and then asks the other two flows to serve it.
func assertFlowsAreIndependent(t *testing.T, h *integrationHarness) {
	t.Helper()

	// A session that owes a second factor, established from another source so
	// the throttling below cannot be what refuses it.
	link, nonce := h.requestLink(t, otherSource)

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, h.redeem(t, otherSource, link, nonce).err, &ch)
	require.NotEmpty(t, ch.Token)

	// Exhaust the magic-link allowance from the source under test.
	for range 10 {
		require.ErrorIs(t, h.redeem(t, integrationSource, "wrong-token", nonce).err,
			magiclink.ErrInvalidLink)
	}

	second, secondNonce := h.requestLink(t, otherSource)
	require.ErrorIs(t, h.redeem(t, integrationSource, second, secondNonce).err,
		magiclink.ErrInvalidLink, "the source is throttled for redemptions")

	// The same source still authenticates by key.
	byKey := h.getWithKey(t, integrationSource, h.apiKey)
	require.NoError(t, byKey.err, "the API key flow keeps its own allowance")
	assert.True(t, byKey.handlerRan)

	// And still verifies a second-factor code.
	verified := h.verify(t, integrationSource, ch.Token, h.code(t))
	require.NoError(t, verified.err, "the code verification flow keeps its own allowance")
	assert.Equal(t, http.StatusOK, verified.rec.Code)
}

// errFixtureFailure is the dependency error every row below drives its site
// with. Its text quotes an address and a user reference, neither of which may
// reach a written record: this is the reproduction task 3.1 is a defect claim
// against, one per site.
var errFixtureFailure = errors.New(
	"store: Key (username)=(alice@example.com) for user u-123")

// The two values errFixtureFailure quotes, which no record may carry.
const (
	leakedAddress = "alice@example.com"
	leakedUserRef = "u-123"
)

// recordText renders r's message and every attribute as one string, so a test
// can assert on what the record carries without depending on a handler's own
// formatting.
func recordText(r slog.Record) string {
	var sb strings.Builder

	sb.WriteString(r.Message)

	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(a.Value.String())

		return true
	})

	return sb.String()
}

// assertNoLeak asserts that no record in records carries the fixture's
// address or user reference, whatever else it carries.
func assertNoLeak(t *testing.T, records []slog.Record) {
	t.Helper()

	for i, r := range records {
		text := recordText(r)
		assert.NotContains(t, text, leakedAddress, "record %d leaked the address", i)
		assert.NotContains(t, text, leakedUserRef, "record %d leaked the user reference", i)
	}
}

// assertFailureRecord asserts that one of records carries reason and a
// non-empty error_type, and returns it so a caller can assert anything more it
// needs (flow, source).
func assertFailureRecord(t *testing.T, records []slog.Record, reason string) slog.Record {
	t.Helper()

	for _, r := range records {
		v, ok := attrValue(r, "reason")
		if !ok || v.String() != reason {
			continue
		}

		assert.Equal(t, 1, attrCount(r, "reason"),
			"the record carries reason=%s, and must carry it exactly once", reason)

		errType, ok := attrValue(r, "error_type")
		require.True(t, ok, "the record carries reason=%s but no error_type", reason)
		assert.NotEmpty(t, errType.String(), "error_type must not be empty")

		return r
	}

	require.Fail(t, fmt.Sprintf("no record carried reason=%s", reason))

	return slog.Record{}
}

// attrCount is how many of r's attributes are named key. slog keeps every
// attribute it is handed, so a key added twice is written twice by a JSON or
// text handler, and a reader of the record sees two values for one field.
func attrCount(r slog.Record, key string) int {
	n := 0

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			n++
		}

		return true
	})

	return n
}

// assertNoDuplicateKeys asserts that no record in records carries any
// attribute key more than once.
func assertNoDuplicateKeys(t *testing.T, records []slog.Record) {
	t.Helper()

	for i, r := range records {
		seen := map[string]int{}

		r.Attrs(func(a slog.Attr) bool {
			seen[a.Key]++

			return true
		})

		for key, n := range seen {
			assert.Equal(t, 1, n, "record %d (%q) carries %q %d times", i, r.Message, key, n)
		}
	}
}

// recordWithMessage returns the first of records written with msg.
func recordWithMessage(t *testing.T, records []slog.Record, msg string) slog.Record {
	t.Helper()

	for _, r := range records {
		if r.Message == msg {
			return r
		}
	}

	require.Fail(t, fmt.Sprintf("no record was written with message %q", msg))

	return slog.Record{}
}

// failingHandoffStore is an oidc.HandoffStore whose Insert always fails with
// err, quoting whatever a real store's row might. Issue is the only method the
// handoff-issue site exercises; the others are never reached by it.
type failingHandoffStore struct {
	err error
}

func (s failingHandoffStore) Insert(context.Context, oidc.HandoffRecord) error { return s.err }

func (failingHandoffStore) FindByTokenID(context.Context, string) (*oidc.HandoffRecord, error) {
	return nil, oidc.ErrHandoffNotFound
}

func (failingHandoffStore) Consume(context.Context, string, time.Time) error {
	return oidc.ErrHandoffNotFound
}

func (failingHandoffStore) DeleteExpired(context.Context, time.Time) (int, error) {
	return 0, nil
}

// TestHTTPSecFailureRecords is the reproduction for task 3.1: one row per
// site that today writes a failed dependency's own error text into a log
// record. Each row drives the chain so the dependency returns
// errFixtureFailure, and asserts that no written record carries either value
// the error's text quotes, while the record still names what failed.
func TestHTTPSecFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		reason string
		// message picks the record to assert on by its message instead, for
		// a row whose record deliberately names no failed dependency.
		message string
		act     func(t *testing.T) []slog.Record
		assert  func(t *testing.T, r slog.Record)
	}

	cases := []testCase{
		{
			name:   "form login: the attempt store's record could not be written",
			reason: "attempt-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "carol", gomock.Any()).
					Return(errFixtureFailure)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(h.formLoginDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, formRequest(t.Context(), "/login", "username=carol&password=wrong"))
				require.Error(t, out.err)

				return h.logs.records()
			},
		},
		{
			name:   "form login: the attempt store's reset could not be written",
			reason: "attempt-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "carol").Return(errFixtureFailure)
				h.expectSessionOpened("issued-token")

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(h.formLoginDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, formRequest(t.Context(), "/login", "username=carol&password=s3cret"))
				require.NoError(t, out.err)

				return h.logs.records()
			},
		},
		{
			name:   "basic auth: the attempt store's record could not be written",
			reason: "attempt-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "carol", gomock.Any()).
					Return(errFixtureFailure)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBasicAuth(h.basicAuthDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, basicRequest(t.Context(), "carol", "wrong"))
				require.Error(t, out.err)

				return h.logs.records()
			},
		},
		{
			name:   "session touch: the activity write-back could not be recorded",
			reason: "session-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.expectActivity(&activityWrites{}, errFixtureFailure)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, bearerRequest(t.Context(), "Bearer a-token"))
				require.NoError(t, out.err)

				return h.logs.records()
			},
		},
		{
			name:   "oidc callback: the handoff code could not be issued",
			reason: "handoff-issue",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newOIDCHarness(t)

				users := NewMockUserLoader(gomock.NewController(t))
				handoffs, err := oidc.NewHandoff(
					failingHandoffStore{err: errFixtureFailure}, users)
				require.NoError(t, err)

				var log capturingHandler

				chain, err := httpsec.New(
					httpsec.WithLogger(slog.New(&log)),
					httpsec.WithRefusalLogInterval(0),
					httpsec.EnableOIDCLogin(h.manager, handoffs,
						httpsec.WithOIDCTokens(h.tokens),
						httpsec.WithOIDCSessions(h.sessions)),
				)
				require.NoError(t, err)

				login := startLogin(t, chain, "")
				out := serve(t, chain, callbackRequest(t.Context(), login.genuineCallback(), login.handle))
				require.Error(t, out.err)

				return log.records()
			},
		},
		{
			name:   "throttle: the rate limiter could not answer",
			reason: "limiter",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				var log capturingHandler

				limiter := NewMockLimiter(gomock.NewController(t))
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					Return(true, errFixtureFailure)

				_, err := httpsec.SourceThrottledForTest(t.Context(), guardOver(t, limiter),
					"198.51.100.7", "login", nil, slog.New(&log), time.Now())
				require.Error(t, err)

				return log.records()
			},
			assert: func(t *testing.T, r slog.Record) {
				t.Helper()

				flow, ok := attrValue(r, "flow")
				require.True(t, ok, "the limiter record must still name its flow")
				assert.Equal(t, "login", flow.String())
			},
		},
		{
			name:   "throttle: the request ended before the rate limiter answered",
			reason: "limiter",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				var log capturingHandler

				wrapped := fmt.Errorf("%w: %s", context.Canceled, errFixtureFailure.Error())

				limiter := NewMockLimiter(gomock.NewController(t))
				limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).
					DoAndReturn(func(context.Context, string) (bool, error) {
						return true, wrapped
					})

				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				_, err := httpsec.SourceThrottledForTest(ctx, guardOver(t, limiter),
					"198.51.100.7", "login", nil, slog.New(&log), time.Now())
				require.Error(t, err)

				return log.records()
			},
			assert: func(t *testing.T, r slog.Record) {
				t.Helper()

				assert.Equal(t, "httpsec: the request ended before the rate limiter answered", r.Message)

				flow, ok := attrValue(r, "flow")
				require.True(t, ok, "the limiter record must still name its flow")
				assert.Equal(t, "login", flow.String())

				cancelled, ok := attrValue(r, "cancelled")
				require.True(t, ok, "a request that ended says so")
				assert.True(t, cancelled.Bool())
			},
		},
		{
			// The throttled address is the one value a throttle record carries
			// on purpose: an operator needs to know who was throttled.
			name:    "throttle: a source over its limit stays visible",
			message: guardThrottledMsg,
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				var log capturingHandler

				// The guard writes the one throttled-source record, through the
				// chain's logger, which is what every chain-built guard has.
				g, err := ratelimit.NewSourceGuard("login", limiterThrottling(t),
					ratelimit.WithSourceGuardLogger(slog.New(&log)))
				require.NoError(t, err)

				_, err = httpsec.SourceThrottledForTest(t.Context(), g,
					"198.51.100.7", "login", nil, slog.New(&log), time.Now())
				require.Error(t, err)

				return log.records()
			},
			assert: func(t *testing.T, r slog.Record) {
				t.Helper()

				source, ok := attrValue(r, "source")
				require.True(t, ok, "the throttle record names the throttled source")
				assert.Equal(t, "198.51.100.7", source.String())
			},
		},
		{
			name:   "bearer: the session store could not read the session",
			reason: "session-store",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).
					Return(nil, fmt.Errorf("%w: %w", session.ErrUnreadable, errFixtureFailure))

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
				)
				require.NoError(t, err)

				out := serve(t, chain, bearerRequest(t.Context(), "Bearer a-token"))
				require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)

				return h.logs.records()
			},
		},
		{
			name:   "logout: the end-session step could not build the provider's URL",
			reason: "end-session",
			act: func(t *testing.T) []slog.Record {
				t.Helper()

				h := newAuthHarness(t)
				h.expectVerified()
				h.expectResolvedSession(federatedSession())
				h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(1, nil)

				b := NewMockEndSessionBuilder(gomock.NewController(t))
				b.EXPECT().EndSessionURL(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("", errFixtureFailure)

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions, EndSession: b}),
				)
				require.NoError(t, err)

				out := serve(t, chain, logoutFormRequest(t.Context(), nil))
				require.NoError(t, out.err)

				return h.logs.records()
			},
			assert: func(t *testing.T, r slog.Record) {
				t.Helper()

				provider, ok := attrValue(r, "provider")
				require.True(t, ok, "the record still names the provider")
				assert.Equal(t, "corp", provider.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			records := tc.act(t)
			require.NotEmpty(t, records, "the site under test wrote no record at all")

			assertNoLeak(t, records)
			assertNoDuplicateKeys(t, records)

			var r slog.Record
			if tc.message != "" {
				r = recordWithMessage(t, records, tc.message)
			} else {
				r = assertFailureRecord(t, records, tc.reason)
			}

			if tc.assert != nil {
				tc.assert(t, r)
			}
		})
	}
}

// The person the end-to-end runs sign in as.
const (
	e2eUser     identity.UserID = "u-1"
	e2eAddress  string          = "grace@example.com"
	e2ePassword string          = "correct horse battery staple"
	e2eSource   string          = "203.0.113.7"
)

// requiredFlag is the requirement lookup: whether the user must use a second
// factor, which an operator may change while a session is live.
type requiredFlag struct{ on atomic.Bool }

func (r *requiredFlag) Required(context.Context, identity.UserID) (bool, error) {
	return r.on.Load(), nil
}

// e2eDeployment is one deployment wired the way a consumer wires the path:
// the real MFA policies over the real TOTP method and its in-memory store, a
// real session manager, form login over the real password authenticator, magic
// link, bearer tokens, the verify endpoint, the enrolment path and logout, all
// in one chain. Only the user store and the token generator are doubles, since
// scrty ships neither.
type e2eDeployment struct {
	sessions *session.Sessions
	totp     *mfa.TOTP
	clock    *clockwork.FakeClock
	users    *MockUserLoader
	sender   *capturingSender
	tokens   *MockGenerator
	links    *magiclink.Links
	required *requiredFlag
	hash     []byte

	// pathOpts configure the policy's enrolment path, and enrolOpts the
	// chain's; both are read when the chain is built.
	pathOpts  []policy.EnrolmentPathOption
	enrolOpts []httpsec.EnrolmentOption

	chain *httpsec.Chain
}

func newE2EDeployment(t *testing.T) *e2eDeployment {
	t.Helper()

	ctrl := gomock.NewController(t)

	sessions, err := session.New()
	require.NoError(t, err)

	d := &e2eDeployment{
		sessions: sessions,
		clock:    clockwork.NewFakeClockAt(time.Now().Truncate(time.Second)),
		users:    NewMockUserLoader(ctrl),
		sender:   &capturingSender{},
		tokens:   NewMockGenerator(ctrl),
		required: &requiredFlag{},
	}
	d.required.on.Store(true)

	d.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll", mfa.WithClock(d.clock))
	require.NoError(t, err)

	onetimes, err := onetime.New("magic-link", onetime.WithTokenTTL(magicLinkTTL))
	require.NoError(t, err)

	d.links, err = magiclink.New(onetimes, d.users, d.sender, "https://app.example.com")
	require.NoError(t, err)

	d.wireUsers(t)
	d.wireTokens()

	return d
}

// e2eEncoder is Argon2id at the cheapest parameters the encoder accepts, so
// a run of logins stays quick.
func e2eEncoder(t *testing.T) password.Encoder {
	t.Helper()

	enc, err := password.NewArgon2idEncoder(password.WithArgon2idMemory(19456),
		password.WithArgon2idIterations(2), password.WithArgon2idThreads(1))
	require.NoError(t, err)

	return enc
}

func (d *e2eDeployment) wireUsers(t *testing.T) {
	t.Helper()

	var err error
	d.hash, err = e2eEncoder(t).Encode(e2ePassword)
	require.NoError(t, err)

	details := func() *identity.Details {
		return &identity.Details{
			ID: e2eUser, Name: "Grace Hopper", Username: e2eAddress,
			Password: d.hash, Active: true,
		}
	}

	d.users.EXPECT().LoadByUsername(gomock.Any(), e2eAddress).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) { return details(), nil })
	d.users.EXPECT().LoadByUserID(gomock.Any(), e2eUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return details(), nil })
}

// wireTokens issues tokens naming the session they were issued for and
// verifies them back, as a real generator does through the jti.
func (d *e2eDeployment) wireTokens() {
	d.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			return mfaTokenFor(id), nil
		})
	d.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(e2eAddress, id), nil
		})
}

// build assembles the chain from the deployment's current configuration.
func (d *e2eDeployment) build(t *testing.T) *e2eDeployment {
	t.Helper()

	lookups, err := mfa.LookupsFor(d.totp)
	require.NoError(t, err)

	challenge, err := policy.NewMFA(lookups)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirement(d.required, lookups,
		policy.WithMFAEnrolmentPath(d.pathOpts...))
	require.NoError(t, err)

	authn, err := authenticate.NewUsernamePasswordAuthenticator(d.users,
		authenticate.WithPasswordEncoder(e2eEncoder(t)))
	require.NoError(t, err)

	d.chain, err = httpsec.New(
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableFormLogin(httpsec.FormLoginDeps{
			Authenticator: authn,
			Sessions:      d.sessions,
			Tokens:        d.tokens,
			Attempts:      lockout.NewMemoryAttemptStore(),
		}),
		httpsec.EnableMagicLink(d.links,
			httpsec.WithMagicLinkSessions(d.sessions), httpsec.WithMagicLinkTokens(d.tokens)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: d.tokens, Sessions: d.sessions, Users: d.users,
		}),
		httpsec.EnableMFA([]mfa.Method{d.totp}, httpsec.WithMFATokens(d.tokens)),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: d.users, Sender: d.sender}, d.enrolOpts...),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions}),
	)
	require.NoError(t, err)

	return d
}

// login posts the user's password to the form login endpoint.
func (d *e2eDeployment) login(t *testing.T) served {
	t.Helper()

	return serve(t, d.chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	}))
}

// magicLinkLogin asks for a link, follows it, and returns what following it
// answered.
func (d *e2eDeployment) magicLinkLogin(t *testing.T) served {
	t.Helper()

	asked := serve(t, d.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath, e2eSource,
		url.Values{httpsec.DefaultMagicLinkAddressParam: {e2eAddress}, httpsec.DefaultMagicLinkNextParam: {"/"}}))
	require.NoError(t, asked.err)

	cookie := cookieNamed(asked.rec, httpsec.DefaultBindingCookieName)
	require.NotNil(t, cookie)

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, e2eSource,
		url.Values{httpsec.DefaultMagicLinkTokenParam: {d.sender.lastToken(t)}})
	req.AddCookie(bindingCookie(cookie.Value))

	return serve(t, d.chain, req)
}

// send posts values to path with the credential the caller holds.
func (d *e2eDeployment) send(t *testing.T, path, credential string, values url.Values) served {
	t.Helper()

	req := postValues(t.Context(), path, e2eSource, values)
	req.Header.Set("Authorization", "Bearer "+credential)

	return serve(t, d.chain, req)
}

// invoices requests a protected route with the credential the caller holds.
func (d *e2eDeployment) invoices(t *testing.T, credential string) served {
	t.Helper()

	req := getFrom(t.Context(), "/invoices", e2eSource)
	req.Header.Set("Authorization", "Bearer "+credential)

	return serve(t, d.chain, req)
}

// code is what an authenticator holding secret shows now.
func (d *e2eDeployment) code(t *testing.T, secret string) string {
	t.Helper()

	c, err := totp.GenerateCode(secret, d.clock.Now())
	require.NoError(t, err)

	return c
}

// lastEmailed is the code the latest message the user received carries.
func (d *e2eDeployment) lastEmailed(t *testing.T) string {
	t.Helper()

	d.sender.mu.Lock()
	defer d.sender.mu.Unlock()

	require.NotEmpty(t, d.sender.sent)

	code := sixDigits.FindString(d.sender.sent[len(d.sender.sent)-1].TextBody)
	require.NotEmpty(t, code, "the message carries a code")

	return code
}

// enrolmentChallenged asserts out is the enrolment challenge a login answers
// with, and returns the credential it hands back.
func enrolmentChallenged(t *testing.T, out served) string {
	t.Helper()

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch, "got %v", out.err)
	require.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
	assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
	require.NotNil(t, ch.Session)
	assert.Equal(t, session.MFAEnrolmentPending, ch.Session.MFA, "the session is enrolment-only")
	require.NotEmpty(t, ch.Token, "the credential the enrolment is carried out with")
	assert.False(t, out.handlerRan)

	return ch.Token
}

// challengedFor asserts out is a refusal with a challenge of kind, and returns
// the credential the challenge carries.
func challengedFor(t *testing.T, out served, kind policy.ChallengeKind) string {
	t.Helper()

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch, "got %v", out.err)
	assert.Equal(t, kind, ch.Kind)
	assert.False(t, out.handlerRan)

	return ch.Token
}

// confined asserts an enrolment-only credential reaches nothing but the path.
func (d *e2eDeployment) confined(t *testing.T, credential string) {
	t.Helper()

	challengedFor(t, d.invoices(t, credential), policy.ChallengeMFAEnrolment)
}

// enrolAndVerify carries an enrolment-only credential through the path: begin,
// prove the device, redeem the emailed code when email confirmation is on, and
// verify a fresh code. It returns the credential the verification rotated to.
func (d *e2eDeployment) enrolAndVerify(t *testing.T, credential string, emailed bool) string {
	t.Helper()

	begun := d.send(t, enrolBeginPath, credential, nil)
	require.NoError(t, begun.err)

	var doc beginBody
	require.NoError(t, json.Unmarshal(begun.rec.Body.Bytes(), &doc))
	require.NotEmpty(t, doc.Secret)

	sentBefore := d.sender.count()

	proven := d.send(t, enrolConfirmPath, credential,
		url.Values{"code": {d.code(t, doc.Secret)}})
	require.NoError(t, proven.err)
	assert.Equal(t, http.StatusNoContent, proven.rec.Code)

	if emailed {
		require.Equal(t, sentBefore+1, d.sender.count(), "the emailed code was sent")
		enrolled, err := d.totp.Enrolled(t.Context(), e2eUser)
		require.NoError(t, err)
		require.False(t, enrolled, "a proven device alone does not count")

		redeemed := d.send(t, enrolEmailPath, credential,
			url.Values{"code": {d.lastEmailed(t)}})
		require.NoError(t, redeemed.err)
		assert.Equal(t, http.StatusNoContent, redeemed.rec.Code)
		assert.Equal(t, sentBefore+2, d.sender.count(), "the binding was notified")
	} else {
		assert.Equal(t, sentBefore+1, d.sender.count(), "only the binding was notified")
	}

	enrolled, err := d.totp.Enrolled(t.Context(), e2eUser)
	require.NoError(t, err)
	require.True(t, enrolled)

	// Completing the enrolment is not a second factor.
	challengedFor(t, d.invoices(t, credential), policy.ChallengeMFA)

	// The proof spent this step's code; the verification needs a later one.
	d.clock.Advance(30 * time.Second)

	verified := d.send(t, testMFAVerifyPath, credential, url.Values{"code": {d.code(t, doc.Secret)}})
	require.NoError(t, verified.err)
	require.Equal(t, http.StatusOK, verified.rec.Code)

	rotated := accessTokenFrom(t, verified)
	require.NotEqual(t, credential, rotated)

	return rotated
}

// reached asserts credential now reaches the protected route.
func (d *e2eDeployment) reached(t *testing.T, credential string) {
	t.Helper()

	out := d.invoices(t, credential)
	require.NoError(t, out.err)
	assert.True(t, out.handlerRan, "the protected route is reached")
}

// oidcEnrolmentChain is the OIDC harness's chain under the default
// classification, which does not exempt an OIDC login: the real MFA policies
// over a real, unenrolled TOTP method, with the enrolment path on under
// pathOpts.
func oidcEnrolmentChain(t *testing.T, h *oidcHarness, pathOpts ...policy.EnrolmentPathOption) *httpsec.Chain {
	t.Helper()

	method, err := mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll")
	require.NoError(t, err)

	lookups, err := mfa.LookupsFor(method)
	require.NoError(t, err)

	challenge, err := policy.NewMFA(lookups)
	require.NoError(t, err)

	requirement, err := policy.NewMFARequirement(nil, lookups,
		policy.WithMFARequiredForAll(), policy.WithMFAEnrolmentPath(pathOpts...),
		policy.WithFederatedAssuranceSource(h.manager))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), oidcTestUserID).AnyTimes().
		Return(&identity.Details{ID: oidcTestUserID, Username: "ada@example.com", Active: true}, nil)

	h.chainOpts = []httpsec.Option{
		httpsec.WithPolicyEngine(engineOf(t, challenge, requirement)),
		httpsec.EnableMFA([]mfa.Method{method}, httpsec.WithMFATokens(h.tokens)),
		httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{Users: users, Sender: &capturingSender{}}),
	}

	return h.chain(t)
}

// TestEnrolmentPathEndToEnd runs the enrolment path through one real chain, as
// a required user with no second factor meets it: from each first factor the
// path admits, through the emailed code or without it, to a protected route
// reached with the credential the verification rotated to; and the logins it
// refuses — a federated login the allowlist leaves out, a login after the path
// closed — refused as they would be with the path off.
func TestEnrolmentPathEndToEnd(t *testing.T) {
	t.Parallel()

	t.Run("a password login enrols through the emailed code and verifies", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t).build(t)

		pending := enrolmentChallenged(t, d.login(t))
		d.confined(t, pending)

		rotated := d.enrolAndVerify(t, pending, true)
		d.reached(t, rotated)

		stale := d.invoices(t, pending)
		require.ErrorIs(t, stale.err, httpsec.ErrAuthenticationRequired, "the enrolment-only handle is gone")
		assert.False(t, stale.handlerRan)
	})

	t.Run("a password login enrols without email confirmation and verifies", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t)
		d.enrolOpts = append(d.enrolOpts, httpsec.WithoutEnrolmentEmailConfirmation())
		d.build(t)

		pending := enrolmentChallenged(t, d.login(t))
		d.confined(t, pending)

		d.reached(t, d.enrolAndVerify(t, pending, false))
	})

	t.Run("a magic-link login is sent to enrol", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t).build(t)

		out := d.magicLinkLogin(t)
		pending := enrolmentChallenged(t, out)

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch)
		assert.Equal(t, factor.MagicLink, ch.Session.FirstFactor)

		d.confined(t, pending)
		d.reached(t, d.enrolAndVerify(t, pending, true))
	})

	t.Run("a federated login with the exemption removed", func(t *testing.T) {
		t.Parallel()

		t.Run("is refused under the default allowlist, and its handoff kept", func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			c := oidcEnrolmentChain(t, h)
			code := h.issueHandoff(t, "")

			out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))
			require.ErrorIs(t, out.err, policy.ErrMFAEnrolmentRequired)
			assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

			var ch *httpsec.ChallengeError
			assert.NotErrorAs(t, out.err, &ch, "no enrolment challenge")
			assert.Zero(t, h.activeSessions(t), "no session is established")

			// Presented again, it is judged again rather than refused as spent.
			again := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))
			require.ErrorIs(t, again.err, policy.ErrMFAEnrolmentRequired, "the handoff was kept")
		})

		t.Run("is sent to enrol when OIDC is on the allowlist", func(t *testing.T) {
			t.Parallel()

			h := newOIDCHarness(t)
			h.issueTokens()

			c := oidcEnrolmentChain(t, h,
				policy.WithEnrolmentFirstFactors(factor.Password, factor.MagicLink, factor.OIDC))
			code := h.issueHandoff(t, "")

			out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))
			enrolmentChallenged(t, out)

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch)
			assert.Equal(t, factor.OIDC, ch.Session.FirstFactor)
			assert.Equal(t, 1, h.activeSessions(t))

			again := serve(t, c, handoffRequest(t.Context(), oidcAnotherSource, code))
			require.ErrorIs(t, again.err, oidc.ErrInvalidHandoff, "the handoff was consumed")
		})
	})

	t.Run("a login after the path closed is refused", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t)
		d.pathOpts = append(d.pathOpts, policy.WithEnrolmentPathUntil(time.Now().Add(-time.Minute)))
		d.build(t)

		out := d.login(t)
		require.ErrorIs(t, out.err, policy.ErrMFAEnrolmentRequired)
		assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

		var ch *httpsec.ChallengeError
		assert.NotErrorAs(t, out.err, &ch, "no enrolment challenge")

		count, err := d.sessions.CountActiveByUser(t.Context(), e2eUser)
		require.NoError(t, err)
		assert.Zero(t, count, "no session is established")
	})

	t.Run("an enrolment reset by an operator sends the next login to enrol", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t).build(t)

		// Enrolled out of band, so a login is challenged for the factor.
		provisioning, err := d.totp.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
		require.NoError(t, err)
		require.NoError(t, d.totp.ConfirmEnrolment(t.Context(), e2eUser, d.code(t, provisioning.Secret)))
		d.clock.Advance(30 * time.Second)

		held := challengedFor(t, d.login(t), policy.ChallengeMFA)

		require.NoError(t, mfa.ResetEnrolment(t.Context(), e2eUser, mfa.ResetDeps{
			Enrolments: []mfa.EnrolmentRemover{d.totp}, Sessions: d.sessions, Users: d.users, Sender: d.sender,
		}))

		stale := d.invoices(t, held)
		require.ErrorIs(t, stale.err, httpsec.ErrAuthenticationRequired,
			"the session held before the reset no longer authenticates")
		assert.False(t, stale.handlerRan)

		pending := enrolmentChallenged(t, d.login(t))
		d.confined(t, pending)
		d.reached(t, d.enrolAndVerify(t, pending, true))
	})

	t.Run("a user no longer required stays confined until a fresh login", func(t *testing.T) {
		t.Parallel()

		d := newE2EDeployment(t).build(t)

		pending := enrolmentChallenged(t, d.login(t))

		// The operator lifts the requirement while the session is live. The
		// gate reads the session's state, not the policy, so it stays
		// confined.
		d.required.on.Store(false)
		d.confined(t, pending)

		fresh := d.login(t)
		require.NoError(t, fresh.err)
		require.Equal(t, http.StatusOK, fresh.rec.Code)

		var body loginBody
		require.NoError(t, json.Unmarshal(fresh.rec.Body.Bytes(), &body))
		require.NotEmpty(t, body.AccessToken)

		d.reached(t, body.AccessToken)
		d.confined(t, pending)
	})
}

// The passkey method's MFA paths under the default prefixes.
const (
	passkeyMFABeginPath  = httpsec.DefaultMFABeginPrefix + "/" + passkey.MethodName
	passkeyMFAVerifyPath = httpsec.DefaultMFAVerifyPrefix + "/" + passkey.MethodName
)

// enrolTOTP enrols the user on the deployment's TOTP method.
func (d *pwlDeployment) enrolTOTP(t *testing.T) {
	t.Helper()

	prov, err := d.totp.BeginEnrolment(t.Context(), e2eUser, e2eAddress)
	require.NoError(t, err)

	code, err := totp.GenerateCode(prov.Secret, d.totpClock.Now())
	require.NoError(t, err)

	require.NoError(t, d.totp.ConfirmEnrolment(t.Context(), e2eUser, code))
}

// passwordLogin logs the user in with their password through form login.
func (d *pwlDeployment) passwordLogin(t *testing.T) served {
	t.Helper()

	return serve(t, d.chain, postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
		httpsec.DefaultLoginUsernameParam: {e2eAddress},
		httpsec.DefaultLoginPasswordParam: {e2ePassword},
	}))
}

// challenged requires out to be a second-factor challenge and returns it.
func challenged(t *testing.T, out served) *httpsec.ChallengeError {
	t.Helper()

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch)
	require.Equal(t, policy.ChallengeMFA, ch.Kind)
	require.NotEmpty(t, ch.Token)

	return ch
}

// mfaBegun begins the passkey method's challenge with the pending session's
// token and returns the challenge the request options carry.
func (d *pwlDeployment) mfaBegun(t *testing.T, tok string) string {
	t.Helper()

	out := serve(t, d.chain, bearerPost(t.Context(), passkeyMFABeginPath, tok))
	require.NoError(t, out.err)
	require.Equal(t, http.StatusOK, out.rec.Code)

	return d.verifier.lastRequest(t)
}

// mfaVerify posts body to the passkey method's verify path with tok.
func (d *pwlDeployment) mfaVerify(t *testing.T, tok, body string) served {
	t.Helper()

	return serve(t, d.chain, bearerJSON(t.Context(), passkeyMFAVerifyPath, tok, body))
}

// limiterCounting is an MFA verification limiter that never refuses and
// expects exactly failures recorded failures.
func limiterCounting(t *testing.T, failures int) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).Times(failures)

	return l
}

// suspended asserts the user's one passkey is suspended.
func suspended(t *testing.T, d *pwlDeployment) {
	t.Helper()

	list, err := d.creds.List(t.Context(), e2eUser)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, passkey.StateSuspended, list[0].State, "the credential is suspended")
}

// TestPasskeyMFA drives the passkey MFA method through the MFA slot, after a
// password login, and after a passkey login.
func TestPasskeyMFA(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		setup  func(t *testing.T, d *pwlDeployment)
		act    func(t *testing.T, d *pwlDeployment) served
		assert func(t *testing.T, d *pwlDeployment, out served)
	}

	// stillPending asserts the challenge was not resolved: the session the
	// challenge's token names still owes it.
	stillPending := func(t *testing.T, d *pwlDeployment, tok string) {
		t.Helper()

		assert.Equal(t, session.MFAPending, d.sessionOf(t, tok).MFA, "the challenge stays pending")
	}

	cases := []testCase{
		{
			name: "a password login is challenged, and the passkey resolves it",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 0)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.enrolTOTP(t)
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				d.seed(t, e2eUser, "cred-2", passkey.StateSuspended)

				ch := challenged(t, d.passwordLogin(t))
				assert.Equal(t, []httpsec.MFAMethod{
					{Name: "totp", Channel: factor.AuthenticatorApp, Begins: false},
					{Name: passkey.MethodName, Channel: factor.PublicKey, Begins: true},
				}, ch.Methods)

				challenge := d.mfaBegun(t, ch.Token)

				d.verifier.mu.Lock()
				allowed := d.verifier.allowed[len(d.verifier.allowed)-1]
				d.verifier.mu.Unlock()
				require.Len(t, allowed, 1, "only the active passkey is allowed")
				assert.Equal(t, []byte("cred-1"), allowed[0].ID)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-1"))

				rotated := accessTokenFrom(t, out)
				assert.NotEqual(t, ch.Token, rotated, "the session is rotated")
				assert.Equal(t, session.MFASatisfied, d.sessionOf(t, rotated).MFA)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "after a passkey login without user verification, the passkey is the same channel",
			setup: func(_ *testing.T, d *pwlDeployment) {
				d.pkOpts = append(d.pkOpts, passkey.WithUserVerification(passkey.UserVerificationPreferred))
				d.verifier.notUserVerified.Store(true)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.enrolTOTP(t)

				ch := challenged(t, d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive)))
				assert.Equal(t, []httpsec.MFAMethod{
					{Name: "totp", Channel: factor.AuthenticatorApp, Begins: false},
				}, ch.Methods, "the passkey is not offered as the passkey login's second factor")

				return d.mfaVerify(t, ch.Token, assertionBody("anything", "cred-1"))
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, mfa.ErrSameChannel)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a suspected clone at verify is refused, forbidden, not counted, and ends every session of the user",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 0)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seedCounted(t, e2eUser, "cred-1", passkey.StateActive, 5)
				other := d.otherSession(t)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-1"))

				d.sessionGone(t, sessionIDOf(t, ch.Token), "the pending session is ended, and the refusal did not save it back")
				d.sessionGone(t, other, "the user's other session is ended")

				// The same handle, presented again, names nothing: no path
				// after the refusal re-created the session it carried.
				again := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-1"))
				require.ErrorIs(t, again.err, httpsec.ErrAuthenticationRequired)
				d.sessionGone(t, sessionIDOf(t, ch.Token), "a follow-up request does not re-create the session")

				return out
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, passkey.ErrCloneSuspected)
				require.ErrorIs(t, out.err, mfa.ErrAuthenticatorRefused)
				assert.NotErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.Zero(t, d.sessionCount(t, out), "no session of the user is left")

				suspended(t, d)
			},
		},
		{
			name: "a suspected clone at verify keeps the sessions when the consumer turned revocation off",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 0)
				d.pkOpts = append(d.pkOpts, passkey.WithoutSessionRevocationOnClone())
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seedCounted(t, e2eUser, "cred-1", passkey.StateActive, 5)
				other := d.otherSession(t)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-1"))

				stillPending(t, d, ch.Token)
				assert.Equal(t, sessionIDOf(t, ch.Token), d.sessionOf(t, ch.Token).ID, "the handle is unchanged")

				_, err := d.sessions.Load(t.Context(), other)
				require.NoError(t, err, "the user's other session is kept")

				return out
			},
			assert: func(t *testing.T, d *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, passkey.ErrCloneSuspected)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))

				suspended(t, d)
			},
		},
		{
			name: "a suspended passkey at verify is refused, forbidden and not counted",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 0)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				d.seed(t, e2eUser, "cred-2", passkey.StateSuspended)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-2"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, passkey.ErrSuspended)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "an assertion over a challenge never issued is refused and counted",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 1)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)

				ch := challenged(t, d.passwordLogin(t))
				d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody("a-challenge-the-library-never-issued", "cred-1"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "a wrong signature over an issued challenge is refused and counted",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 1)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				d.verifier.refuseAssertions.Store(true)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-1"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			},
		},
		{
			name: "another user's passkey is an invalid code",
			setup: func(t *testing.T, d *pwlDeployment) {
				d.mfaLimiter = limiterCounting(t, 1)
			},
			act: func(t *testing.T, d *pwlDeployment) served {
				d.seed(t, e2eUser, "cred-1", passkey.StateActive)
				d.seed(t, "u-2", "cred-other", passkey.StateActive)

				ch := challenged(t, d.passwordLogin(t))
				challenge := d.mfaBegun(t, ch.Token)

				out := d.mfaVerify(t, ch.Token, assertionBody(challenge, "cred-other"))
				stillPending(t, d, ch.Token)

				return out
			},
			assert: func(t *testing.T, _ *pwlDeployment, out served) {
				require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := newPwlDeployment(t)
			if tc.setup != nil {
				tc.setup(t, d)
			}

			d.build(t)

			tc.assert(t, d, tc.act(t, d))
		})
	}
}

// TestPasskeyFlushRefusalLogs pins that flushing the chain's refusal logs
// reaches the passkey components: the passkey manager's sampler, and the
// passwordless begin's source guard.
func TestPasskeyFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		arrange func(t *testing.T, d *pwlDeployment, log *slog.Logger)
		drive   func(t *testing.T, d *pwlDeployment)
		assert  func(t *testing.T, flushed []slog.Record)
	}

	cases := []testCase{
		{
			name: "the passkey manager's sampler",
			arrange: func(_ *testing.T, d *pwlDeployment, log *slog.Logger) {
				d.pkOpts = append(d.pkOpts, passkey.WithLogger(log), passkey.WithLogInterval(time.Hour))
			},
			drive: func(t *testing.T, d *pwlDeployment) {
				// Three finishes without a ceremony cookie: one refusal record
				// written, two held back.
				for range 3 {
					_, challenge := d.begun(t)
					out := d.finish(t, assertionBody(challenge, "cred-1"))
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
				}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, "passkey: records suppressed", "key", "refused|binding"))
			},
		},
		{
			name: "the passwordless begin's source guard",
			arrange: func(t *testing.T, d *pwlDeployment, _ *slog.Logger) {
				d.settings = append(d.settings, httpsec.PasswordlessLimiter(exceededLimiter(t)))
			},
			drive: func(t *testing.T, d *pwlDeployment) {
				for range 3 {
					out := serve(t, d.chain, postValues(t.Context(), passwordlessBeginPath, flushSource, url.Values{}))
					require.Error(t, out.err)
				}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "passkey-login"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &capturingHandler{}
			log := slog.New(logs)

			d := newPwlDeployment(t)
			d.extra = append(d.extra, httpsec.WithLogger(log))
			tc.arrange(t, d, log)
			d.build(t)

			tc.drive(t, d)
			before := len(logs.records())

			require.NoError(t, d.chain.FlushRefusalLogs())

			tc.assert(t, logs.records()[before:])
		})
	}
}

// TestPasskeyRecoveryRoute runs a recovered session through the passkey
// route over HTTP: created and confined at 09:00 under a 12-hour absolute
// timeout, it registers a passkey, owes a second factor while keeping its
// deadline and recovery time, proves the passkey at the MFA slot at 09:05,
// and ends with a rotated full session whose deadline is 21:00 and whose
// recovery time is 09:00.
func TestPasskeyRecoveryRoute(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	clk := clockwork.NewFakeClockAt(recoveryStart)

	sessions, err := session.New(session.WithClock(clk), session.WithAbsoluteTimeout(12*time.Hour),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	d := &e2eDeployment{
		sessions: sessions,
		clock:    clk,
		users:    NewMockUserLoader(ctrl),
		sender:   &capturingSender{},
		tokens:   NewMockGenerator(ctrl),
		required: &requiredFlag{},
	}
	d.wireUsers(t)
	d.wireTokens()

	d.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll", mfa.WithClock(clk))
	require.NoError(t, err)

	v := newPasskeyVerifierStub(t)

	pm, err := passkey.New(passkey.Deps{Verifier: v.mock, Users: d.users, Sender: d.sender, Sessions: d.sessions},
		passkey.WithRepudiationContact("help@example.com"))
	require.NoError(t, err)

	method := pm.MFAMethod()

	lookups, err := mfa.LookupsFor(d.totp, method)
	require.NoError(t, err)

	challenge, err := policy.NewMFA(lookups)
	require.NoError(t, err)

	d.chain, err = httpsec.New(
		httpsec.WithPolicyEngine(engineOf(t, challenge)),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: d.tokens, Sessions: d.sessions, Users: d.users}),
		httpsec.EnableMFA([]mfa.Method{d.totp, method}, httpsec.WithMFATokens(d.tokens)),
		httpsec.EnablePasskeys(httpsec.PasskeyDeps{Passkeys: pm, Sessions: d.sessions}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: d.sessions}),
		httpsec.EnableRecoveryGateForTest(),
	)
	require.NoError(t, err)

	s, err := d.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Recovery))
	require.NoError(t, err)

	d.sessions.MarkRecoveryPending(s, recoveryLifetime, clk.Now())
	require.NoError(t, d.sessions.Save(t.Context(), s))

	credential := mfaTokenFor(s.ID)

	bearer := func(req *http.Request) *http.Request {
		req.Header.Set("Authorization", "Bearer "+credential)

		return req
	}

	stored := func(handle string) *session.Session {
		got, err := d.sessions.Load(t.Context(), handle)
		require.NoError(t, err)

		return got
	}

	begun := serve(t, d.chain, bearer(jsonPost(t.Context(), passkeyBeginPath, "")))
	require.NoError(t, begun.err)

	finished := serve(t, d.chain, bearer(jsonPost(t.Context(), passkeyFinishPath,
		registrationBody(v.lastCreation(t), "cred-1"))))
	require.NoError(t, finished.err)
	require.Equal(t, http.StatusOK, finished.rec.Code)

	// The binding moves the session on to its second factor, and keeps its
	// confinement marker, its deadline and its recovery time until the
	// passkey is proven.
	bound := stored(s.ID)
	assert.Equal(t, session.MFAPending, bound.MFA)
	assert.Equal(t, s.EnrolmentOriginDeadline, bound.EnrolmentOriginDeadline)
	assert.Equal(t, s.AbsoluteExpiresAt, bound.AbsoluteExpiresAt)
	assert.True(t, bound.RecoveredAt.Equal(recoveryStart), "the recovery time is kept, got %s", bound.RecoveredAt)

	challengedFor(t, d.invoices(t, credential), policy.ChallengeMFA)

	clk.Advance(5 * time.Minute)

	mfaBegun := serve(t, d.chain, bearer(jsonPost(t.Context(), httpsec.DefaultMFABeginPrefix+"/"+passkey.MethodName, "")))
	require.NoError(t, mfaBegun.err)

	verified := serve(t, d.chain, bearer(jsonPost(t.Context(), httpsec.DefaultMFAVerifyPrefix+"/"+passkey.MethodName,
		assertionBody(v.lastRequest(t), "cred-1"))))
	require.NoError(t, verified.err)
	require.Equal(t, http.StatusOK, verified.rec.Code)

	rotated := accessTokenFrom(t, verified)
	require.NotEqual(t, credential, rotated, "the verification rotates the session")

	id, ok := strings.CutPrefix(rotated, mfaTokenPrefix)
	require.True(t, ok)

	got := stored(id)
	assert.Equal(t, session.MFASatisfied, got.MFA)
	assert.True(t, got.AbsoluteExpiresAt.Equal(recoveryStart.Add(12*time.Hour)),
		"the absolute deadline is restored to 21:00, got %s", got.AbsoluteExpiresAt)
	assert.True(t, got.RecoveredAt.Equal(recoveryStart), "the recovery time is kept, got %s", got.RecoveredAt)
	assert.True(t, got.EnrolmentOriginDeadline.IsZero(), "the confinement marker is cleared")

	_, err = d.sessions.Load(t.Context(), s.ID)
	require.Error(t, err, "the recovery-pending handle no longer loads")

	d.reached(t, rotated)
}

// errorSink is the consumer's error handler: it records what the chain
// refused with and the status the library maps it to, which is everything a
// consumer rendering a refusal has to go on.
type errorSink struct {
	called bool
	err    error
	status int
}

// option installs the sink as the chain's error handler.
func (s *errorSink) option() httpsec.Option {
	return httpsec.WithErrorHandler(s.handle)
}

// guardOption installs the sink as a guard's error handler.
func (s *errorSink) guardOption() httpsec.GuardOption {
	return httpsec.WithGuardErrorHandler(s.handle)
}

func (s *errorSink) handle(w http.ResponseWriter, _ *http.Request, err error) {
	s.called = true
	s.err = err
	s.status = httpsec.StatusForError(err)
	w.WriteHeader(s.status)
}

// refusedBy builds a chain from opts with the sink as its error handler,
// mounts it as net/http middleware and runs req through it.
func refusedBy(t *testing.T, req *http.Request, opts ...httpsec.Option) *errorSink {
	t.Helper()

	sink := &errorSink{}

	c, err := httpsec.New(append(opts, sink.option())...)
	require.NoError(t, err)

	return throughMiddleware(t, c, sink, req)
}

// throughMiddleware runs req through c's net/http middleware; c must have been
// built with sink's option.
func throughMiddleware(t *testing.T, c *httpsec.Chain, sink *errorSink, req *http.Request) *errorSink {
	t.Helper()

	c.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the downstream handler ran for a request the chain should have refused")
	})).ServeHTTP(httptest.NewRecorder(), req)

	require.True(t, sink.called, "the consumer's error handler was never called")

	return sink
}

// carrying publishes s and a caller on every exchange, standing in for the
// first factor that resolved them, immediately outside the MFA slot.
func carrying(s *session.Session) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ex.Authentication = &authenticate.Authentication{Principal: testPrincipal(), Time: time.Now()}
		ex.Session = s
		ex.SetContext(httpsec.WithSession(httpsec.WithCaller(ex.Context(), ex.Authentication), s))

		return next(ex)
	}), httpsec.Before(httpsec.OrderMFAChallenge))
}

// allowingVerifyLimiter is a verification limiter that never throttles and
// accepts every failure it is asked to count.
func allowingVerifyLimiter(t *testing.T) *MockLimiter {
	t.Helper()

	l := NewMockLimiter(gomock.NewController(t))
	l.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	l.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	return l
}

// oidcManagerOver builds a manager for testOIDCProvider, whose endpoints are
// pinned so nothing is fetched, keeping its login flows in flows.
func oidcManagerOver(t *testing.T, flows oidc.FlowStore) *oidc.RelyingParty {
	t.Helper()

	registry, err := oidc.NewRegistry(oidc.Provider{ //nolint:gosec // G101: a fixture, not a credential
		Name:                  testOIDCProvider,
		Issuer:                "https://idp.example.com",
		ClientID:              "app",
		ClientSecret:          "secret-" + testOIDCProvider,
		RedirectURL:           "https://app.example.com/login/oauth2/callback/" + testOIDCProvider,
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		JWKSURI:               "https://idp.example.com/jwks",
	})
	require.NoError(t, err)

	broker, err := oidc.NewBroker(oidc.NewMemoryLinkStore(), NewMockUserLoader(gomock.NewController(t)))
	require.NoError(t, err)

	m, err := oidc.NewRelyingParty(registry, broker, oidc.WithFlowStore(flows))
	require.NoError(t, err)

	return m
}

// oidcLoginOver is the chain options of a federated login over m, with a
// token generator and a session manager that are never reached.
func oidcLoginOver(t *testing.T, m *oidc.RelyingParty) httpsec.Option {
	t.Helper()

	sessions, err := session.New()
	require.NoError(t, err)

	return httpsec.EnableOIDCLogin(m, newTestHandoffManager(t),
		httpsec.WithOIDCTokens(NewMockGenerator(gomock.NewController(t))),
		httpsec.WithOIDCSessions(sessions))
}

// failingSessionsOn is a session manager over a store double, wired by wire.
func failingSessionsOn(t *testing.T, wire func(store *MockStore)) *session.Sessions {
	t.Helper()

	store := NewMockStore(gomock.NewController(t))
	wire(store)

	m, err := session.New(session.WithStore(store))
	require.NoError(t, err)

	return m
}

// backchannelRefusal delivers a logout token naming sub and sid to the
// harness's chain, built with opts, and returns what the consumer's handler
// saw.
func backchannelRefusal(t *testing.T, h *oidcHarness, sub, sid string, opts ...httpsec.OIDCOption) *errorSink {
	t.Helper()

	sink := &errorSink{}
	h.chainOpts = append(h.chainOpts, sink.option())

	req := backchannelRequest(t.Context(), testOIDCProvider, "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"logout_token": {h.provider.logoutToken(t, sub, sid)}}.Encode()))

	return throughMiddleware(t, h.chain(t, opts...), sink, req)
}

// sentinelsNotMatched are the library sentinels a refusal caused by a
// dependency must not newly match: every one the status table answers, and the
// ones a session store or an OIDC flow names. A fixture error wraps none of
// them, so the refusal must not either.
var sentinelsNotMatched = []error{
	httpsec.ErrAuthenticationRequired,
	httpsec.ErrCredentialsMissing,
	httpsec.ErrRequestTooLarge,
	authorize.ErrAuthenticationRequired,
	authorize.ErrAccessDenied,
	authenticate.ErrAuthenticationFailed,
	policy.ErrSessionIdle,
	lockout.ErrAccountLocked,
	policy.ErrTooManySessions,
	policy.ErrDenied,
	policy.ErrMFARequired,
	policy.ErrMFAEnrolmentRequired,
	ratelimit.ErrThrottled,
	mfa.ErrInvalidCode,
	mfa.ErrVerifyThrottled,
	mfa.ErrSameChannel,
	mfa.ErrAlreadyEnrolled,
	oidc.ErrInvalidLogoutToken,
	oidc.ErrUnknownProvider,
	oidc.ErrInvalidState,
	oidc.ErrFlowUnspent,
	session.ErrNotFound,
	session.ErrExpired,
	session.ErrUnreadable,
}

// failingRoleLoader is an identity.RoleLoader whose every lookup fails with
// err, standing in for the store behind the library's own PrivilegeAuthorizer.
type failingRoleLoader struct{ err error }

func (l failingRoleLoader) LoadPrivileges(context.Context, string) ([]*identity.ResourcePrivileges, error) {
	return nil, l.err
}

// activeRolePrincipal is a principal whose active role is name, which is the
// only thing the library's PrivilegeAuthorizer reads about a caller.
func activeRolePrincipal(name string) *identity.Principal {
	role := &identity.AssignedRole{ID: "r-1", Name: name, Primary: true}

	return &identity.Principal{
		ID:         "u-1",
		Username:   "ada",
		Roles:      []*identity.AssignedRole{role},
		ActiveRole: role,
	}
}

// TestReturnedErrorsCarryFixedText is the reproduction for task 6.1: one row
// per path on which an httpsec interceptor returns an error a consumer-supplied
// dependency caused. The dependency fails with errFixtureFailure, whose text
// quotes an address and a user reference, and the consumer's error handler
// records what it was handed. The refusal it reads must carry neither value,
// must still match the dependency's error, must match no library sentinel the
// dependency's error did not, and must map to the status it mapped to before
// the text was fixed.
//
// The consumer's own words — a magic-link check, a guard's authorizer, a
// policy's reason — and a store's bare library sentinel are the other side of
// the rule: they come back as themselves, compared by identity.
func TestReturnedErrorsCarryFixedText(t *testing.T) {
	t.Parallel()

	errTermsNotAccepted := errors.New("terms not accepted for alice@example.com")
	errRolesOnHold := errors.New("roles: alice@example.com (u-123) is on hold")
	errPolicyHold := errors.New("policy: alice@example.com is under review")

	// fixedText is the assertion every dependency row makes.
	fixedText := func(status int) func(t *testing.T, s *errorSink) {
		return func(t *testing.T, s *errorSink) {
			t.Helper()

			require.Error(t, s.err)

			text := s.err.Error()
			assert.NotContains(t, text, leakedAddress, "the refusal's text quotes the dependency")
			assert.NotContains(t, text, leakedUserRef, "the refusal's text quotes the dependency")
			require.ErrorIs(t, s.err, errFixtureFailure, "the dependency's error is no longer reachable")
			assert.Equal(t, status, s.status, "the refusal maps to a different status than it did")

			for _, sentinel := range sentinelsNotMatched {
				assert.NotErrorIs(t, s.err, sentinel, "the refusal newly matches %v", sentinel)
			}
		}
	}

	// unchanged is the assertion for an error that is the consumer's own, or a
	// bare library sentinel: it is returned as itself, text included.
	unchanged := func(want error, status int) func(t *testing.T, s *errorSink) {
		return func(t *testing.T, s *errorSink) {
			t.Helper()

			require.Error(t, s.err)
			assert.Same(t, want, s.err, "the error was rewritten; it must come back as itself")
			assert.Equal(t, want.Error(), s.err.Error(), "the text must be returned byte for byte")
			assert.Equal(t, status, s.status)
		}
	}

	type testCase struct {
		name   string
		act    func(t *testing.T) *errorSink
		assert func(t *testing.T, s *errorSink)
	}

	loginRequest := func(t *testing.T) *http.Request {
		t.Helper()

		return formRequest(t.Context(), "/login", "username=carol&password=s3cret")
	}

	// formLogin wires h for a login that authenticates and reaches the tail.
	formLogin := func(h *authHarness) {
		h.expectAuthenticated(testPrincipal())
		h.attempts.EXPECT().Reset(gomock.Any(), "carol").Return(nil)
	}

	// mfaVerify runs a code submission for a pending session held by sessions,
	// verified by method, issuing through tokens.
	mfaVerify := func(
		t *testing.T, s *session.Session, sessions *session.Sessions, method mfa.Method, tokens *MockGenerator,
	) *errorSink {
		t.Helper()

		return refusedBy(t, postCode(t.Context(), testMFAVerifyPath),
			carrying(s),
			httpsec.EnableMFA([]mfa.Method{method},
				httpsec.WithMFAVerifyLimiter(allowingVerifyLimiter(t)),
				httpsec.WithMFATokens(tokens)),
			httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
	}

	// pendingIn creates a password session owing a second factor in sessions.
	pendingIn := func(t *testing.T, sessions *session.Sessions) *session.Session {
		t.Helper()

		s, err := sessions.Create(t.Context(), testMFAUser, session.WithFirstFactor(factor.Password))
		require.NoError(t, err)

		s.MFA = session.MFAPending
		require.NoError(t, sessions.Save(t.Context(), s))

		return s
	}

	acceptingMethod := func(t *testing.T) *MockMethod {
		t.Helper()

		m := mfaMethod(t, factor.AuthenticatorApp)
		m.EXPECT().Enrolled(gomock.Any(), testMFAUser).Return(true, nil).AnyTimes()
		m.EXPECT().Verify(gomock.Any(), testMFAUser, []byte(testMFACode)).Return(nil)

		return m
	}

	issuing := func(t *testing.T) *MockGenerator {
		t.Helper()

		g := NewMockGenerator(gomock.NewController(t))
		g.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("issued-token", nil).AnyTimes()

		return g
	}

	cases := []testCase{
		{
			name: "login completion: the session could not be created",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errFixtureFailure)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "login completion: the challenged session could not be saved",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errFixtureFailure)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)),
					httpsec.EnableGateForTest(policy.ChallengeMFA))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			// Review Focus 3: a store answering with the sentinel its contract
			// names gets that same value back.
			name: "login completion: a store's bare ErrNotFound is returned as itself",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(session.ErrNotFound)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)),
					httpsec.EnableGateForTest(policy.ChallengeMFA))
			},
			assert: unchanged(session.ErrNotFound, http.StatusInternalServerError),
		},
		{
			name: "login completion: the token could not be generated",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("", errFixtureFailure)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "login: a consumer policy's reason is returned as itself",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				formLogin(h)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.WithPolicyEngine(denyingEngine(t, errPolicyHold)))
			},
			assert: unchanged(errPolicyHold, http.StatusInternalServerError),
		},
		{
			// The scenario spec's own pin ("Dependency text stays out of the
			// refusal"): pre-authentication is denied because the lockout
			// policy's attempt store could not say how often carol has
			// failed. This matches policy.ErrDenied on purpose, so it
			// gets its own assert rather than the shared fixedText, which
			// asserts the opposite of every sentinel in sentinelsNotMatched.
			name: "login: denied because the lockout policy's attempt store could not be consulted",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				h.attempts.EXPECT().FailureCount(gomock.Any(), "carol", gomock.Any()).
					Return(0, errFixtureFailure)

				lockoutPolicy, err := lockout.New(lockout.WithAttemptStore(h.attempts))
				require.NoError(t, err)

				return refusedBy(t, loginRequest(t),
					httpsec.WithLogger(h.logger()), httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.WithPolicyEngine(engineOf(t, lockoutPolicy)))
			},
			assert: func(t *testing.T, s *errorSink) {
				t.Helper()

				require.Error(t, s.err)

				text := s.err.Error()
				assert.NotContains(t, text, leakedAddress, "the refusal's text quotes the dependency")
				assert.NotContains(t, text, leakedUserRef, "the refusal's text quotes the dependency")
				assert.ErrorIs(t, s.err, errFixtureFailure, "the dependency's error is no longer reachable")
				assert.ErrorIs(t, s.err, policy.ErrDenied,
					"the refusal must still match the policy's own reason")
				assert.Equal(t, http.StatusForbidden, s.status)
			},
		},
		{
			name: "bearer: the per-request enrolment mark could not be saved",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				h.expectVerified()
				h.expectResolvedSession(liveSession())
				h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(errFixtureFailure).AnyTimes()

				return refusedBy(t, bearerRequest(t.Context(), "Bearer a-token"),
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.WithPolicyEngine(challengingIn(t, policy.PerRequest, policy.ChallengeMFAEnrolment)),
					httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "verify endpoint: the TOTP enrolment could not be read",
			act: func(t *testing.T) *errorSink {
				enrolments := NewMockEnrolmentStore(gomock.NewController(t))
				enrolments.EXPECT().Get(gomock.Any(), testMFAUser).Return(mfa.Enrolment{}, false, errFixtureFailure)

				totp, err := mfa.NewTOTP(enrolments, "Example")
				require.NoError(t, err)

				sessions, err := session.New()
				require.NoError(t, err)

				return mfaVerify(t, pendingIn(t, sessions), sessions, totp, issuing(t))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "verify endpoint: the session could not be rotated",
			act: func(t *testing.T) *errorSink {
				sessions := failingSessionsOn(t, func(store *MockStore) {
					store.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, errFixtureFailure)
					store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				})

				s := liveSession()
				s.MFA = session.MFAPending

				return mfaVerify(t, s, sessions, acceptingMethod(t), issuing(t))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "verify endpoint: the token could not be generated",
			act: func(t *testing.T) *errorSink {
				sessions, err := session.New()
				require.NoError(t, err)

				tokens := NewMockGenerator(gomock.NewController(t))
				tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("", errFixtureFailure)

				return mfaVerify(t, pendingIn(t, sessions), sessions, acceptingMethod(t), tokens)
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "logout: the session could not be deleted",
			act: func(t *testing.T) *errorSink {
				h := newAuthHarness(t)
				h.expectVerified()
				h.expectResolvedSession(familiedSession())
				h.acceptsActivityWriteBack()
				h.store.EXPECT().DeleteFamily(gomock.Any(), testFamily).Return(0, errFixtureFailure)

				return refusedBy(t, logoutFormRequest(t.Context(), nil),
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "oidc authorize: the login flow could not be begun",
			act: func(t *testing.T) *errorSink {
				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Begin(gomock.Any(), gomock.Any()).Return("", errFixtureFailure)

				return refusedBy(t,
					httptest.NewRequestWithContext(t.Context(), http.MethodGet,
						httpsec.DefaultOIDCAuthorizePath+testOIDCProvider, nil),
					oidcLoginOver(t, oidcManagerOver(t, flows)))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "oidc callback: the flow the provider refused could not be ended",
			act: func(t *testing.T) *errorSink {
				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), "h-1", testOIDCProvider, "s-1").
					Return(oidc.Flow{}, errFixtureFailure)

				return refusedBy(t,
					callbackRequest(t.Context(), "error=access_denied&state=s-1", "h-1"),
					oidcLoginOver(t, oidcManagerOver(t, flows)))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "oidc callback: the handoff code could not be issued",
			act: func(t *testing.T) *errorSink {
				h := newOIDCHarness(t)

				handoffs, err := oidc.NewHandoff(
					failingHandoffStore{err: errFixtureFailure}, NewMockUserLoader(gomock.NewController(t)))
				require.NoError(t, err)

				sink := &errorSink{}

				c, err := httpsec.New(sink.option(),
					httpsec.EnableOIDCLogin(h.manager, handoffs,
						httpsec.WithOIDCTokens(h.tokens),
						httpsec.WithOIDCSessions(h.sessions)))
				require.NoError(t, err)

				login := startLogin(t, c, "")

				return throughMiddleware(t, c, sink,
					callbackRequest(t.Context(), login.genuineCallback(), login.handle))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "back-channel logout: the subject's link could not be looked up",
			act: func(t *testing.T) *errorSink {
				h := newOIDCHarness(t)

				ctrl := gomock.NewController(t)
				links := NewMockLinkStore(ctrl)
				links.EXPECT().FindByExternal(gomock.Any(), testOIDCProvider, gomock.Any(), oidcTestSubject).
					Return(nil, errFixtureFailure)

				broker, err := oidc.NewBroker(links, NewMockUserLoader(ctrl))
				require.NoError(t, err)

				h.manager = h.managerWith(t, broker, nil)

				return backchannelRefusal(t, h, oidcTestSubject, "")
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "back-channel logout: the provider session's sessions could not be deleted",
			act: func(t *testing.T) *errorSink {
				sessions := failingSessionsOn(t, func(store *MockStore) {
					store.EXPECT().DeleteByExternalSession(gomock.Any(), gomock.Any(), "abc").
						Return(0, errFixtureFailure)
				})

				return backchannelRefusal(t, newOIDCHarness(t), oidcTestSubject, "abc",
					httpsec.WithOIDCSessions(sessions))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "back-channel logout: the subject's sessions from the issuer could not be deleted",
			act: func(t *testing.T) *errorSink {
				sessions := failingSessionsOn(t, func(store *MockStore) {
					store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), oidcTestUserID, gomock.Any()).
						Return(0, errFixtureFailure)
				})

				return backchannelRefusal(t, newOIDCHarness(t), oidcTestSubject, "",
					httpsec.WithOIDCSessions(sessions))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "back-channel logout: every session of the subject could not be deleted",
			act: func(t *testing.T) *errorSink {
				sessions := failingSessionsOn(t, func(store *MockStore) {
					store.EXPECT().DeleteByUser(gomock.Any(), oidcTestUserID).Return(errFixtureFailure)
				})

				return backchannelRefusal(t, newOIDCHarness(t), oidcTestSubject, "",
					httpsec.WithOIDCSessions(sessions),
					httpsec.WithOIDCBackchannelLogoutScope(httpsec.BackchannelLogoutScopeAll))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			name: "jwks endpoint: the public key set could not be read",
			act: func(t *testing.T) *errorSink {
				keys := NewMockKeySetProvider(gomock.NewController(t))
				keys.EXPECT().JWKS().Return(nil, errFixtureFailure)

				return refusedBy(t,
					httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultJWKSPath, nil),
					httpsec.EnableJWKSEndpoint(keys))
			},
			assert: fixedText(http.StatusInternalServerError),
		},
		{
			// Review Focus 4: the consumer's own check, in the consumer's own
			// words, even when those words quote an address.
			name: "magic link: a consumer check's refusal is returned byte for byte",
			act: func(t *testing.T) *errorSink {
				h := newMagicLinkHarness(t)
				token, nonce := h.link(t, h.chain(t))

				sink := &errorSink{}
				h.chainOpts = append(h.chainOpts, sink.option())
				h.linkOpts = append(h.linkOpts, httpsec.WithMagicLinkChecks(
					func(context.Context, identity.Principal, time.Time) error { return errTermsNotAccepted }))

				req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, magicLinkSource,
					url.Values{"token": {token}})
				if nonce != "" {
					req.AddCookie(bindingCookie(nonce))
				}

				return throughMiddleware(t, h.chain(t), sink, req)
			},
			assert: func(t *testing.T, s *errorSink) {
				t.Helper()

				require.ErrorIs(t, s.err, errTermsNotAccepted)
				assert.Equal(t, errTermsNotAccepted.Error(), s.err.Error(),
					"the consumer's words must reach them unchanged")
				assert.NotErrorIs(t, s.err, magiclink.ErrInvalidLink)
				assert.Equal(t, http.StatusInternalServerError, s.status)
			},
		},
		{
			name: "guard: a consumer authorizer's refusal is returned as itself",
			act: func(t *testing.T) *errorSink {
				sink := &errorSink{}
				g := httpsec.NewGuards(refusingAuthorizer(t, errRolesOnHold), sink.guardOption())

				runGuard(t, g.ResourcePrivileges("admin", "user").RequireOne("read"),
					guardRequest(t, testPrincipal(), nil))
				require.True(t, sink.called, "the guard's error handler was never called")

				return sink
			},
			assert: unchanged(errRolesOnHold, http.StatusInternalServerError),
		},
		{
			// Task 5.8's own path, one level up: the library's
			// PrivilegeAuthorizer wraps a failing role loader's error with
			// fixed text before a guard built over it ever sees it.
			name: "guard: a ResourcePrivileges guard over the library's own PrivilegeAuthorizer",
			act: func(t *testing.T) *errorSink {
				authorizer, err := authorize.NewPrivilegeAuthorizer(failingRoleLoader{err: errFixtureFailure})
				require.NoError(t, err)

				sink := &errorSink{}
				g := httpsec.NewGuards(authorizer, sink.guardOption())

				runGuard(t, g.ResourcePrivileges("billing", "invoice").RequireOne("read"),
					guardRequest(t, activeRolePrincipal("editor"), nil))
				require.True(t, sink.called, "the guard's error handler was never called")

				return sink
			},
			assert: fixedText(http.StatusInternalServerError),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.act(t))
		})
	}
}
