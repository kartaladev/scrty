package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// testMFABeginPath is where the scripted passkey begins under the default
// prefix, and testPasskeyVerifyPath where it is verified.
const (
	testMFABeginPath      = httpsec.DefaultMFABeginPrefix + "/passkey"
	testPasskeyVerifyPath = httpsec.DefaultMFAVerifyPrefix + "/passkey"
)

// bearerJSON is a JSON POST carrying an access token, as a client answering a
// challenge method posts its response.
func bearerJSON(ctx context.Context, path, token, body string) *http.Request {
	req := jsonRequest(ctx, path, body)
	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

// bearerPost is a body-less POST carrying an access token, as a client asking
// for a challenge sends it.
func bearerPost(ctx context.Context, path, token string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

// issuedChallenge reads the challenge a begin answered with, the way a client
// of the scripted method would.
func issuedChallenge(t *testing.T, out served) string {
	t.Helper()

	var doc struct {
		Challenge string `json:"challenge"`
	}
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc), "the begin document is JSON")

	return doc.Challenge
}

// TestMFABegin pins the begin endpoint of a challenge method: which requests it
// answers, what it refuses before issuing anything, and what it issues.
//
// The chain authenticates by bearer token, as a deployment does, so a request
// names its session through the credential it carries and every request loads
// its own copy of that session.
func TestMFABegin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// first is the factor the session was established by: password
		// unless a case needs another.
		first factor.Kind
		// anonymous sends no credential at all.
		anonymous bool
		stub      func(c *challengeStub)
		wire      func(h *mfaHarness)
		opts      func(t *testing.T) []httpsec.MFAOption
		request   func(ctx context.Context, t *testing.T, token string) *http.Request
		assert    func(t *testing.T, h *mfaHarness, c *challengeStub, s *session.Session, out served)
	}

	begin := func(path string) func(context.Context, *testing.T, string) *http.Request {
		return func(ctx context.Context, _ *testing.T, token string) *http.Request {
			return bearerPost(ctx, path, token)
		}
	}

	// issued pins a begin that did its job: the method's document, answered
	// by the library rather than the application, carrying the challenge the
	// method was handed, with the session left exactly as it was.
	issued := func(t *testing.T, h *mfaHarness, c *challengeStub, s *session.Session, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.NotErrorAs(t, out.err, &ch, "the gate does not hold a begin")
		require.NoError(t, out.err)
		assert.False(t, out.handlerRan, "the endpoint is the library's own")
		assert.Equal(t, http.StatusOK, out.rec.Code)
		assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))

		challenge := issuedChallenge(t, out)
		require.NotEmpty(t, challenge, "a challenge is issued")
		assert.Equal(t, c.lastIssued(), challenge, "the method's document is written unchanged")
		assert.Equal(t, int32(0), c.verifyCalls.Load(), "a begin verifies nothing")
		assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
	}

	// refusedWith pins a begin refused before anything was issued.
	refusedWith := func(want error) func(*testing.T, *mfaHarness, *challengeStub, *session.Session, served) {
		return func(t *testing.T, _ *mfaHarness, c *challengeStub, _ *session.Session, out served) {
			t.Helper()

			require.ErrorIs(t, out.err, want)
			assert.False(t, out.handlerRan)
			assert.Empty(t, c.lastIssued(), "no challenge is issued")
			assert.Zero(t, out.rec.Body.Len(), "nothing is written")
		}
	}

	// untouched wires a refusal decided before the throttle is consulted, and
	// one that is never counted.
	untouched := func(h *mfaHarness) { h.neverChecked().recordsNoFailure() }

	errLookup := errors.New("mfabegin_test: enrolment store unavailable for alice@example.com")
	errBegin := errors.New("mfabegin_test: begin data could not be built for alice@example.com")

	cases := []testCase{
		{
			name:    "a pending session begins a challenge method",
			wire:    func(h *mfaHarness) { h.allows().recordsNoFailure() },
			request: begin(testMFABeginPath),
			assert:  issued,
		},
		{
			name:    "begin for a method without a begin step",
			wire:    untouched,
			request: begin(httpsec.DefaultMFABeginPrefix + "/totp"),
			assert:  refusedWith(httpsec.ErrUnknownMFAMethod),
		},
		{
			name:    "a begin path naming no method",
			wire:    untouched,
			request: begin(httpsec.DefaultMFABeginPrefix + "/sms"),
			assert:  refusedWith(httpsec.ErrUnknownMFAMethod),
		},
		{
			name:    "an empty segment",
			wire:    untouched,
			request: begin(httpsec.DefaultMFABeginPrefix + "/"),
			assert:  refusedWith(httpsec.ErrUnknownMFAMethod),
		},
		{
			name:    "an extra segment",
			wire:    untouched,
			request: begin(testMFABeginPath + "/x"),
			assert:  refusedWith(httpsec.ErrUnknownMFAMethod),
		},
		{
			name:      "no session",
			anonymous: true,
			wire:      untouched,
			request: func(ctx context.Context, t *testing.T, _ string) *http.Request {
				return postUnread(ctx, t, testMFABeginPath)
			},
			assert: refusedWith(httpsec.ErrAuthenticationRequired),
		},
		{
			name:    "the method's channel is the first factor's",
			first:   factor.MagicLink,
			stub:    func(c *challengeStub) { c.channel = factor.Email },
			wire:    untouched,
			request: begin(testMFABeginPath),
			assert:  refusedWith(mfa.ErrSameChannel),
		},
		{
			name:    "a method the user is not enrolled on",
			stub:    func(c *challengeStub) { c.enrolled = false },
			wire:    untouched,
			request: begin(testMFABeginPath),
			assert:  refusedWith(httpsec.ErrMFAMethodNotUsable),
		},
		{
			// The lookup is the consumer's enrolment store: its failure is
			// refused behind fixed text, with its error still reachable.
			name:    "an enrolment lookup that fails",
			stub:    func(c *challengeStub) { c.enrolledErr = errLookup },
			wire:    untouched,
			request: begin(testMFABeginPath),
			assert: func(t *testing.T, h *mfaHarness, c *challengeStub, s *session.Session, out served) {
				refusedWith(errLookup)(t, h, c, s, out)
				assert.NotContains(t, out.err.Error(), "alice@example.com")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
			},
		},
		{
			name:    "begin while throttled",
			wire:    func(h *mfaHarness) { h.throttles().recordsNoFailure() },
			request: begin(testMFABeginPath),
			assert:  refusedWith(mfa.ErrVerifyThrottled),
		},
		{
			// A method that cannot build its document is a dependency that
			// failed: its text stays out of the refusal, and its error stays
			// reachable.
			name:    "the method cannot build its begin data",
			stub:    func(c *challengeStub) { c.beginErr = errBegin },
			wire:    func(h *mfaHarness) { h.allows().recordsNoFailure() },
			request: begin(testMFABeginPath),
			assert: func(t *testing.T, _ *mfaHarness, _ *challengeStub, _ *session.Session, out served) {
				require.ErrorIs(t, out.err, errBegin)
				assert.NotContains(t, out.err.Error(), "alice@example.com")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
			},
		},
		{
			// Only POST begins: a link cannot make a session spend a
			// challenge nobody asked for, and a pending session reading the
			// path is held like anywhere else.
			name: "a pending session reading the begin path",
			wire: untouched,
			request: func(ctx context.Context, _ *testing.T, token string) *http.Request {
				return bearerRequestTo(ctx, http.MethodGet, testMFABeginPath, token, "")
			},
			assert: func(t *testing.T, _ *mfaHarness, c *challengeStub, _ *session.Session, out served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &ch)
				assert.Empty(t, c.lastIssued())
			},
		},
		{
			name: "consumer begin prefix",
			wire: func(h *mfaHarness) { h.allows().recordsNoFailure() },
			opts: func(*testing.T) []httpsec.MFAOption {
				return []httpsec.MFAOption{httpsec.WithMFABeginPrefix("/auth/second-factor/begin")}
			},
			request: begin("/auth/second-factor/begin/passkey"),
			assert:  issued,
		},
		{
			name: "consumer begin responder",
			wire: func(h *mfaHarness) { h.allows().recordsNoFailure() },
			opts: func(*testing.T) []httpsec.MFAOption {
				return []httpsec.MFAOption{httpsec.WithMFABeginResponder(
					func(ex *httpsec.Exchange, data json.RawMessage) error {
						ex.Writer.SetHeader("Content-Type", "application/vnd.test+json")
						ex.Writer.WriteHeader(http.StatusCreated)
						_, err := ex.Writer.Write([]byte(`{"wrapped":` + string(data) + `}`))

						return err
					})}
			},
			request: begin(testMFABeginPath),
			assert: func(t *testing.T, _ *mfaHarness, c *challengeStub, _ *session.Session, out served) {
				require.NoError(t, out.err)
				assert.Equal(t, http.StatusCreated, out.rec.Code)
				assert.Equal(t, "application/vnd.test+json", out.rec.Header().Get("Content-Type"))

				var doc struct {
					Wrapped stubChallengeDocument `json:"wrapped"`
				}
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &doc))
				require.NotEmpty(t, c.lastIssued())
				assert.Equal(t, c.lastIssued(), doc.Wrapped.Challenge,
					"the responder is handed the method's data unchanged")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies()

			stub := newChallengeStub()
			if tc.stub != nil {
				tc.stub(stub)
			}
			h.extra = []mfa.Method{stub}

			if tc.opts != nil {
				h.mfaOpts = tc.opts(t)
			}

			tc.wire(h)

			first := tc.first
			if first == "" {
				first = factor.Password
			}

			s := h.pendingSession(t, first)

			token := mfaTokenFor(s.ID)
			if tc.anonymous {
				token = ""
			}

			out := serve(t, h.bearerChain(t), tc.request(t.Context(), t, token))
			tc.assert(t, h, stub, s, out)
		})
	}
}

// TestMFABeginIssuance pins how many challenges begin issues, and that the
// pending-challenge store does not grow without bound: begin refuses as
// throttled once a user has been issued the limit for a method within the
// store's issuance window, and sweeps a method's expired challenges at most
// once per window.
//
// Every case begins through the chain, several times over, on the harness's
// fake clock, which the chain reads through WithClock and a case moves with
// advance. Two cases still run inside a synctest bubble, for a reason that is
// not the clock: the slow sweep races a consumer's store against real timers (a
// request deadline and the store's own three-second wait), and the atomic claim
// holds a purge on a one-minute timer that a bubble lets fail at once, rather
// than hang, when a begin never arrives.
func TestMFABeginIssuance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// bubble runs the case inside synctest, for the two cases that race
		// real timers of a store the consumer supplies.
		bubble bool
		// store is the consumer's challenge store; nil keeps the default.
		store func(clk *clockwork.FakeClock) onetime.Store
		opts  []httpsec.MFAOption
		// act begins, as often as the case needs, and returns every outcome.
		act    func(t *testing.T, b beginner) []served
		assert func(t *testing.T, stub *challengeStub, store onetime.Store, logs *capturingHandler, outs []served)
	}

	// times begins n times.
	times := func(t *testing.T, begin func() served, n int) []served {
		t.Helper()

		outs := make([]served, 0, n)
		for range n {
			outs = append(outs, begin())
		}

		return outs
	}

	// beginsThen begins n times, sleeps wait, and begins once more on a new
	// session of the same user.
	beginsThen := func(n int, wait time.Duration) func(*testing.T, beginner) []served {
		return func(t *testing.T, b beginner) []served {
			t.Helper()

			outs := times(t, b.begin, n)
			b.advance(wait)
			b.relogin()

			return append(outs, b.begin())
		}
	}

	// purgeLogged pins one failed sweep logged for the scripted method, with
	// reason as its reason.
	purgeLogged := func(t *testing.T, logs *capturingHandler, reason string) {
		t.Helper()

		var found int
		for _, r := range logs.records() {
			if r.Message != "httpsec: expired MFA challenges could not be purged" {
				continue
			}

			found++
			method, ok := attrValue(r, "method")
			require.True(t, ok)
			assert.Equal(t, "passkey", method.String())

			got, ok := attrValue(r, "reason")
			require.True(t, ok)
			assert.Equal(t, reason, got.String())
		}
		assert.Equal(t, 1, found, "the failed purge is logged")
	}

	// throttledAfter pins n begins issued and the next refused as throttled,
	// with nothing issued for it.
	throttledAfter := func(n int) func(*testing.T, *challengeStub, onetime.Store, *capturingHandler, []served) {
		return func(t *testing.T, stub *challengeStub, _ onetime.Store, _ *capturingHandler, outs []served) {
			t.Helper()

			require.Len(t, outs, n+1)
			for _, out := range outs[:n] {
				require.NoError(t, out.err)
			}

			last := outs[n]
			require.ErrorIs(t, last.err, mfa.ErrVerifyThrottled)
			assert.Zero(t, last.rec.Body.Len(), "nothing is written")
			assert.Len(t, stub.issuedAll(), n, "the refused begin reaches no method")
		}
	}

	errCount := errors.New("mfabegin_test: challenge store unavailable for alice@example.com")
	errPurge := errors.New("mfabegin_test: challenge store unavailable")

	window := time.Hour // the default issuance window of a one-time manager

	cases := []testCase{
		{
			name:   "too many challenges",
			act:    func(t *testing.T, b beginner) []served { return times(t, b.begin, 11) },
			assert: throttledAfter(httpsec.DefaultMFAChallengeLimit),
		},
		{
			name:   "consumer challenge limit",
			opts:   []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(3)},
			act:    func(t *testing.T, b beginner) []served { return times(t, b.begin, 4) },
			assert: throttledAfter(3),
		},
		{
			// The limit is over the issuance window: once it has passed, the
			// user may ask again.
			name: "the limit counts within the issuance window",
			act:  beginsThen(httpsec.DefaultMFAChallengeLimit, window+time.Second),
			assert: func(t *testing.T, stub *challengeStub, _ onetime.Store, _ *capturingHandler, outs []served) {
				for _, out := range outs {
					require.NoError(t, out.err)
				}
				assert.Len(t, stub.issuedAll(), httpsec.DefaultMFAChallengeLimit+1)
			},
		},
		{
			name: "expired challenges are removed",
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))
			},
			opts: []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(1000)},
			act:  beginsThen(200, httpsec.DefaultMFAChallengeTTL+window+time.Second),
			assert: func(t *testing.T, _ *challengeStub, store onetime.Store, _ *capturingHandler, outs []served) {
				require.Len(t, outs, 201)
				for _, out := range outs {
					require.NoError(t, out.err)
				}
				assert.Equal(t, 1, store.(*onetime.MemoryStore).Len(), "only the newest challenge is held")
			},
		},
		{
			name: "expired challenges are swept at most once per issuance window",
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return &countingReaper{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}
			},
			act: beginsThen(5, window+time.Second),
			assert: func(t *testing.T, _ *challengeStub, store onetime.Store, _ *capturingHandler, outs []served) {
				for _, out := range outs {
					require.NoError(t, out.err)
				}
				assert.Equal(t, int32(2), store.(*countingReaper).sweeps.Load(),
					"one sweep for the first window, one for the next")
			},
		},
		{
			// A store that cannot purge is the consumer's choice: the begin
			// is served, and the failure is logged rather than refused.
			name: "a store that cannot purge does not refuse the begin",
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return storeOnly{Store: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}
			},
			act: func(t *testing.T, b beginner) []served { return times(t, b.begin, 1) },
			assert: func(t *testing.T, stub *challengeStub, _ onetime.Store, logs *capturingHandler, outs []served) {
				require.Len(t, outs, 1)
				require.NoError(t, outs[0].err)
				assert.Len(t, stub.issuedAll(), 1)
				purgeLogged(t, logs, "purge-unsupported")
			},
		},
		{
			// A store that cannot purge would not start purging on a retry, so
			// its turn is kept: a second begin in the same window neither
			// tries again nor logs again.
			name: "a store that cannot purge keeps its turn",
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return &unsupportedReaper{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}
			},
			act: func(t *testing.T, b beginner) []served { return times(t, b.begin, 2) },
			assert: func(t *testing.T, _ *challengeStub, store onetime.Store, logs *capturingHandler, outs []served) {
				require.Len(t, outs, 2)
				for _, out := range outs {
					require.NoError(t, out.err)
				}
				assert.Equal(t, int32(1), store.(*unsupportedReaper).attempts.Load(), "one reap attempt a window")
				purgeLogged(t, logs, "purge-unsupported")
			},
		},
		{
			// A store that fails the purge is logged as unavailable, and the
			// begin in hand is still served.
			name: "a store that fails the purge does not refuse the begin",
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return failingPurge{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk)), err: errPurge}
			},
			act: func(t *testing.T, b beginner) []served { return times(t, b.begin, 1) },
			assert: func(t *testing.T, stub *challengeStub, _ onetime.Store, logs *capturingHandler, outs []served) {
				require.Len(t, outs, 1)
				require.NoError(t, outs[0].err)
				assert.Len(t, stub.issuedAll(), 1)
				purgeLogged(t, logs, "store-unavailable")
			},
		},
		{
			// A sweep holds a begin no longer than the begin's own request
			// allows, and one cut short is not counted as this window's: the
			// next begin sweeps again.
			name:   "a slow sweep does not hold the begin past its deadline",
			bubble: true,
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return &slowReaper{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}
			},
			act: func(_ *testing.T, b beginner) []served {
				return []served{b.within(100 * time.Millisecond), b.begin()}
			},
			assert: func(t *testing.T, _ *challengeStub, store onetime.Store, logs *capturingHandler, outs []served) {
				require.Len(t, outs, 2)
				require.NoError(t, outs[1].err)

				slow := store.(*slowReaper)
				assert.Equal(t, 100*time.Millisecond, slow.held.Load().(time.Duration),
					"the purge gave up at the begin's deadline")
				assert.Equal(t, int32(2), slow.sweeps.Load(), "the cut-short sweep is retried by the next begin")
				purgeLogged(t, logs, "store-unavailable")
			},
		},
		{
			// A sweep removes only what is both expired and older than the
			// issuance window, so the count the limit rests on is untouched:
			// A, issued a window ago, goes; B, expired but inside the window,
			// and C, unexpired, stay and still count.
			name: "a sweep leaves the count intact",
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return &countingReaper{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}
			},
			opts: []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(3)},
			act: func(_ *testing.T, b beginner) []served {
				outs := []served{b.begin()} // A, and the first window's sweep
				b.advance(50 * time.Minute)
				b.relogin()
				outs = append(outs, b.begin()) // B
				b.advance(9 * time.Minute)
				b.relogin()
				outs = append(outs, b.begin()) // C
				b.advance(time.Minute + time.Second)
				b.relogin()

				return append(outs, b.begin(), b.begin()) // the second sweep, D, then refused
			},
			assert: func(t *testing.T, _ *challengeStub, store onetime.Store, _ *capturingHandler, outs []served) {
				require.Len(t, outs, 5)
				for _, out := range outs[:4] {
					require.NoError(t, out.err)
				}
				require.ErrorIs(t, outs[4].err, mfa.ErrVerifyThrottled, "B, C and D still count")

				reaper := store.(*countingReaper)
				assert.Equal(t, int32(2), reaper.sweeps.Load())
				assert.Equal(t, 3, reaper.Len(), "only A was swept")
			},
		},
		{
			// Of begins racing once a window has passed, exactly one sweeps.
			name: "concurrent begins sweep once",
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return &countingReaper{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk))}
			},
			opts: []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(1000)},
			act: func(_ *testing.T, b beginner) []served {
				outs := []served{b.begin()}
				b.advance(window + time.Second)
				b.relogin()

				racing := make([]served, 16)

				var wg sync.WaitGroup
				for n := range racing {
					wg.Go(func() { racing[n] = b.begin() })
				}
				wg.Wait()

				return append(outs, racing...)
			},
			assert: func(t *testing.T, _ *challengeStub, store onetime.Store, _ *capturingHandler, outs []served) {
				require.Len(t, outs, 17)
				for _, out := range outs {
					require.NoError(t, out.err)
				}
				assert.Equal(t, int32(2), store.(*countingReaper).sweeps.Load(),
					"one sweep for the first window, one for the racing begins")
			},
		},
		{
			// The sweep is claimed before the purge runs, not recorded after
			// it: while the first purge is held until every other begin has
			// issued its challenge, none of them purges too.
			name:   "the sweep claim is atomic",
			bubble: true,
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return &holdingReaper{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk)), others: 15, arrived: make(chan struct{})}
			},
			opts: []httpsec.MFAOption{httpsec.WithMFAChallengeLimit(1000)},
			act: func(_ *testing.T, b beginner) []served {
				racing := make([]served, 16)

				var wg sync.WaitGroup
				for n := range racing {
					wg.Go(func() { racing[n] = b.begin() })
				}
				wg.Wait()

				return racing
			},
			assert: func(t *testing.T, _ *challengeStub, store onetime.Store, _ *capturingHandler, outs []served) {
				require.Len(t, outs, 16)
				for _, out := range outs {
					require.NoError(t, out.err)
				}

				holding := store.(*holdingReaper)
				assert.True(t, holding.held.Load(), "the first purge was held until the others had issued")
				assert.Equal(t, int32(1), holding.sweeps.Load(), "only the claimed sweep purged")
			},
		},
		{
			// The count is what the limit rests on, so a store that cannot
			// answer it refuses the begin rather than lifting the limit, and
			// its own text stays out of the refusal.
			name: "a store that cannot count refuses the begin",
			store: func(clk *clockwork.FakeClock) onetime.Store {
				return failingCount{MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(clk)), err: errCount}
			},
			act: func(t *testing.T, b beginner) []served { return times(t, b.begin, 1) },
			assert: func(t *testing.T, stub *challengeStub, _ onetime.Store, _ *capturingHandler, outs []served) {
				require.Len(t, outs, 1)
				require.ErrorIs(t, outs[0].err, errCount)
				assert.NotContains(t, outs[0].err.Error(), "alice@example.com")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(outs[0].err))
				assert.Empty(t, stub.issuedAll(), "nothing is issued")
			},
		},
	}

	for _, tc := range cases {
		run := func(t *testing.T) {
			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(false, nil).AnyTimes()

			stub := newChallengeStub()
			h.extra = []mfa.Method{stub}

			logs := &capturingHandler{}
			h.chainOpts = []httpsec.Option{httpsec.WithLogger(slog.New(logs))}

			var store onetime.Store
			h.mfaOpts = tc.opts
			if tc.store != nil {
				store = tc.store(h.clock)
				h.mfaOpts = append([]httpsec.MFAOption{httpsec.WithMFAChallengeStore(store)}, h.mfaOpts...)
			}

			s := h.pendingSession(t, factor.Password)
			c := h.bearerChain(t)

			var mu sync.Mutex

			within := func(d time.Duration) served {
				ctx, cancel := context.WithTimeout(t.Context(), d)
				defer cancel()

				mu.Lock()
				handle := s.ID
				mu.Unlock()

				// The exchange carries the deadline, as a server's request
				// context does.
				out := served{rec: httptest.NewRecorder()}
				run := c.Assemble(func(*httpsec.Exchange) error {
					out.handlerRan = true

					return nil
				})
				out.err = run(httpsec.NewExchange(ctx,
					httpsec.NewHTTPRequest(bearerPost(ctx, testMFABeginPath, mfaTokenFor(handle))),
					httpsec.NewHTTPResponseWriter(out.rec)))

				return out
			}

			b := beginner{
				begin: func() served {
					mu.Lock()
					handle := s.ID
					mu.Unlock()

					return serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(handle)))
				},
				within:  within,
				advance: h.clock.Advance,
				relogin: func() {
					next := h.pendingSession(t, factor.Password)

					mu.Lock()
					s = next
					mu.Unlock()
				},
			}

			tc.assert(t, stub, store, logs, tc.act(t, b))
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.bubble {
				synctest.Test(t, run)

				return
			}

			run(t)
		})
	}
}

// TestMFAChallengeVerify pins how a challenge method is verified: only against
// a challenge this library issued to the same session, which every attempt
// presenting it spends, before the method is asked anything.
//
// Every case begins through the chain and answers through it, authenticating
// by bearer token as a deployment does. The cases about expiry move the
// harness's fake clock, which the chain reads through WithClock.
func TestMFAChallengeVerify(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		stub func(c *challengeStub)
		// extra are challenge methods configured after the passkey.
		extra []mfa.Method
		// failures is how many failed verifications the case must count.
		failures int
		opts     []httpsec.MFAOption
		// act begins and answers, and returns what each answer came back with.
		act    func(t *testing.T, h *mfaHarness, c *httpsec.Chain, s *session.Session) []served
		assert func(t *testing.T, h *mfaHarness, stub *challengeStub, outs []served)
	}

	// beginOn begins the passkey on s and returns the challenge issued.
	beginOn := func(t *testing.T, c *httpsec.Chain, s *session.Session) string {
		t.Helper()

		out := serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID)))
		require.NoError(t, out.err, "the begin succeeds")

		challenge := issuedChallenge(t, out)
		require.NotEmpty(t, challenge)

		return challenge
	}

	// answerOn posts body to the passkey's verify path on s.
	answerOn := func(t *testing.T, c *httpsec.Chain, s *session.Session, body string) served {
		t.Helper()

		return serve(t, c, bearerJSON(t.Context(), testPasskeyVerifyPath, mfaTokenFor(s.ID), body))
	}

	// beginThenAnswer begins, waits wait, and answers with what respond
	// builds from the issued challenge.
	beginThenAnswer := func(wait time.Duration, respond func(challenge string) string) func(
		*testing.T, *mfaHarness, *httpsec.Chain, *session.Session,
	) []served {
		return func(t *testing.T, h *mfaHarness, c *httpsec.Chain, s *session.Session) []served {
			t.Helper()

			challenge := beginOn(t, c, s)
			if wait > 0 {
				h.clock.Advance(wait)
			}

			return []served{answerOn(t, c, s, respond(challenge))}
		}
	}

	// refusedUnasked pins answers refused as an invalid code without the
	// method being asked to verify anything.
	refusedUnasked := func(t *testing.T, _ *mfaHarness, stub *challengeStub, outs []served) {
		t.Helper()

		for _, out := range outs {
			require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
			assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
			assert.False(t, out.handlerRan)
		}
		assert.Equal(t, int32(0), stub.verifyCalls.Load(), "the method is never asked")
	}

	// spentBeforeVerify pins the order of the spend: when the method is asked
	// to verify, the challenge it answers is already consumed in the store. An
	// order that checked, verified and only then consumed would let
	// concurrent attempts all reach the method, which the concurrency row
	// below only catches when the scheduler happens to interleave them.
	spentBeforeVerify := func() testCase {
		store := newRecordingStore()

		var spent, asked atomic.Bool

		return testCase{
			name: "a challenge is spent before the method verifies",
			opts: []httpsec.MFAOption{httpsec.WithMFAChallengeStore(store)},
			stub: func(c *challengeStub) {
				c.onVerify = func(ctx context.Context, _ []byte) {
					asked.Store(true)
					spent.Store(store.allConsumed(ctx))
				}
			},
			act: beginThenAnswer(0, answer),
			assert: func(t *testing.T, _ *mfaHarness, _ *challengeStub, outs []served) {
				require.Len(t, outs, 1)
				require.NoError(t, outs[0].err)
				require.True(t, asked.Load(), "the method verifies the answer")
				assert.True(t, spent.Load(), "the challenge was consumed before Verify ran")
			},
		}
	}

	// twoMethodsKeepTheirPurposes pins that two challenge methods sharing one
	// store never honour each other's challenges.
	twoMethodsKeepTheirPurposes := func() testCase {
		other := newChallengeStub()
		other.name = "security-key"

		return testCase{
			name:     "two challenge methods keep their purposes apart",
			extra:    []mfa.Method{other},
			failures: 1,
			act: func(t *testing.T, _ *mfaHarness, c *httpsec.Chain, s *session.Session) []served {
				t.Helper()

				challenge := beginOn(t, c, s)

				return []served{serve(t, c, bearerJSON(t.Context(),
					httpsec.DefaultMFAVerifyPrefix+"/security-key", mfaTokenFor(s.ID), answer(challenge)))}
			},
			assert: func(t *testing.T, h *mfaHarness, stub *challengeStub, outs []served) {
				refusedUnasked(t, h, stub, outs)
				assert.Equal(t, int32(0), other.verifyCalls.Load(),
					"the other method is never asked either")
			},
		}
	}

	cases := []testCase{
		{
			name: "begin then verify",
			act:  beginThenAnswer(0, answer),
			assert: func(t *testing.T, h *mfaHarness, stub *challengeStub, outs []served) {
				require.Len(t, outs, 1)
				require.NoError(t, outs[0].err)
				assert.Equal(t, http.StatusOK, outs[0].rec.Code)
				assert.Equal(t, int32(1), stub.verifyCalls.Load())

				var body verifyBody
				require.NoError(t, json.Unmarshal(outs[0].rec.Body.Bytes(), &body))
				rotated, ok := strings.CutPrefix(body.AccessToken, mfaTokenPrefix)
				require.True(t, ok)
				assert.Equal(t, session.MFASatisfied, h.stored(t, rotated).MFA, "the challenge is resolved")
			},
		},
		{
			name:     "one try per challenge",
			stub:     func(c *challengeStub) { c.verifyErr = mfa.ErrInvalidCode },
			failures: 2,
			act: func(t *testing.T, _ *mfaHarness, c *httpsec.Chain, s *session.Session) []served {
				t.Helper()

				challenge := beginOn(t, c, s)

				return []served{
					answerOn(t, c, s, answer(challenge)),
					answerOn(t, c, s, answer(challenge)),
				}
			},
			assert: func(t *testing.T, _ *mfaHarness, stub *challengeStub, outs []served) {
				require.Len(t, outs, 2)
				require.ErrorIs(t, outs[0].err, mfa.ErrInvalidCode, "the method refused the first")
				require.ErrorIs(t, outs[1].err, mfa.ErrInvalidCode, "the challenge is spent")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(outs[1].err),
					"a spent pending challenge maps as an invalid code")
				assert.Equal(t, int32(1), stub.verifyCalls.Load(),
					"the second attempt never reaches the method")
			},
		},
		{
			name:     "challenge from another session",
			failures: 1,
			act: func(t *testing.T, h *mfaHarness, c *httpsec.Chain, a *session.Session) []served {
				t.Helper()

				challenge := beginOn(t, c, a)
				b := h.pendingSession(t, factor.Password)

				return []served{answerOn(t, c, b, answer(challenge))}
			},
			assert: refusedUnasked,
		},
		{
			// Session B's attempt matches no challenge issued to B, so it
			// spends nothing: A still answers its own challenge.
			name:     "a challenge presented on another session is not spent",
			failures: 1,
			act: func(t *testing.T, h *mfaHarness, c *httpsec.Chain, a *session.Session) []served {
				t.Helper()

				challenge := beginOn(t, c, a)
				b := h.pendingSession(t, factor.Password)

				return []served{
					answerOn(t, c, b, answer(challenge)),
					answerOn(t, c, a, answer(challenge)),
				}
			},
			assert: func(t *testing.T, _ *mfaHarness, stub *challengeStub, outs []served) {
				require.Len(t, outs, 2)
				require.ErrorIs(t, outs[0].err, mfa.ErrInvalidCode, "B is refused")
				require.NoError(t, outs[1].err, "A's challenge survives B's attempt")
				assert.Equal(t, int32(1), stub.verifyCalls.Load(), "only A's answer reaches the method")
			},
		},
		spentBeforeVerify(),
		twoMethodsKeepTheirPurposes(),
		{
			name:     "expired challenge",
			failures: 1,
			act:      beginThenAnswer(6*time.Minute, answer),
			assert:   refusedUnasked,
		},
		{
			name:     "consumer challenge lifetime",
			failures: 1,
			opts:     []httpsec.MFAOption{httpsec.WithMFAChallengeTTL(2 * time.Minute)},
			act:      beginThenAnswer(3*time.Minute, answer),
			assert:   refusedUnasked,
		},
		{
			// The control for the two above: the same wait, inside the
			// default lifetime, is answered.
			name: "a challenge answered within its lifetime",
			act:  beginThenAnswer(3*time.Minute, answer),
			assert: func(t *testing.T, _ *mfaHarness, stub *challengeStub, outs []served) {
				require.Len(t, outs, 1)
				require.NoError(t, outs[0].err)
				assert.Equal(t, int32(1), stub.verifyCalls.Load())
			},
		},
		{
			name:     "no challenge in the response",
			failures: 1,
			act:      beginThenAnswer(0, func(string) string { return `{}` }),
			assert:   refusedUnasked,
		},
		{
			name:     "a response whose challenge cannot be read",
			failures: 1,
			act:      beginThenAnswer(0, func(string) string { return `{"challenge":5}` }),
			assert:   refusedUnasked,
		},
		{
			name:     "a challenge the library never issued",
			failures: 1,
			act:      beginThenAnswer(0, func(string) string { return answer("forged-by-the-client") }),
			assert:   refusedUnasked,
		},
		{
			// The method refuses every answer here, so no attempt rotates the
			// session out from under the others and each is judged on the
			// challenge alone.
			name:     "concurrent attempts",
			stub:     func(c *challengeStub) { c.verifyErr = mfa.ErrInvalidCode },
			failures: 16,
			act: func(t *testing.T, _ *mfaHarness, c *httpsec.Chain, s *session.Session) []served {
				t.Helper()

				body := answer(beginOn(t, c, s))

				const attempts = 16

				outs := make([]served, attempts)
				start := make(chan struct{})
				done := make(chan struct{})

				for n := range attempts {
					go func() {
						defer func() { done <- struct{}{} }()
						<-start
						outs[n] = answerOn(t, c, s, body)
					}()
				}

				close(start)
				for range attempts {
					<-done
				}

				return outs
			},
			assert: func(t *testing.T, _ *mfaHarness, stub *challengeStub, outs []served) {
				for _, out := range outs {
					require.ErrorIs(t, out.err, mfa.ErrInvalidCode)
				}
				assert.Equal(t, int32(1), stub.verifyCalls.Load(),
					"exactly one attempt reaches the method")
			},
		},
	}

	for _, tc := range cases {
		run := func(t *testing.T) {
			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies()
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(false, nil).AnyTimes()
			h.limiter.EXPECT().RecordFailure(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(nil).Times(tc.failures)

			stub := newChallengeStub()
			if tc.stub != nil {
				tc.stub(stub)
			}
			h.extra = append([]mfa.Method{stub}, tc.extra...)
			h.mfaOpts = tc.opts

			s := h.pendingSession(t, factor.Password)

			tc.assert(t, h, stub, tc.act(t, h, h.bearerChain(t), s))
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			run(t)
		})
	}
}

// recordingStore is a consumer's pending-challenge store: the in-memory one,
// remembering the identifier of every record inserted into it, so a case can
// read back what the chain issued.
type recordingStore struct {
	*onetime.MemoryStore

	mu       sync.Mutex
	inserted []id.ID
}

func newRecordingStore() *recordingStore {
	return &recordingStore{MemoryStore: onetime.NewMemoryStore()}
}

func (s *recordingStore) Insert(ctx context.Context, tok onetime.Token) error {
	if err := s.MemoryStore.Insert(ctx, tok); err != nil {
		return err
	}

	s.mu.Lock()
	s.inserted = append(s.inserted, tok.ID)
	s.mu.Unlock()

	return nil
}

// allConsumed reports whether at least one record was inserted and every one
// of them has been consumed.
func (s *recordingStore) allConsumed(ctx context.Context) bool {
	s.mu.Lock()
	ids := slices.Clone(s.inserted)
	s.mu.Unlock()

	if len(ids) == 0 {
		return false
	}

	for _, tokenID := range ids {
		tok, err := s.FindByID(ctx, tokenID)
		if err != nil || tok.ConsumedAt.IsZero() {
			return false
		}
	}

	return true
}

// countingReaper is a consumer's challenge store that counts the sweeps asked
// of it.
type countingReaper struct {
	*onetime.MemoryStore

	sweeps atomic.Int32
}

func (s *countingReaper) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	s.sweeps.Add(1)

	return s.MemoryStore.DeleteExpiredBefore(ctx, purpose, retainSince)
}

// beginner is how a TestMFABeginIssuance case begins: begin under the test's
// own context, within under a request deadline d from now, and relogin starts
// a new pending session for the same user, which later begins use. A case that
// moves time past the session's idle deadline needs one, and the limit is the
// user's, not the session's.
type beginner struct {
	begin   func() served
	within  func(d time.Duration) served
	relogin func()
	// advance moves the chain's clock on by d.
	advance func(d time.Duration)
}

// slowReaper is a consumer's challenge store whose first purge answers only
// when its context ends, as a SQL store's query does against a database that
// has stopped answering, or after three seconds; its later purges are the
// in-memory store's. It records how long the first one held its caller.
type slowReaper struct {
	*onetime.MemoryStore

	sweeps atomic.Int32
	held   atomic.Value // time.Duration
}

func (s *slowReaper) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	if s.sweeps.Add(1) > 1 {
		return s.MemoryStore.DeleteExpiredBefore(ctx, purpose, retainSince)
	}

	start := time.Now()
	defer func() { s.held.Store(time.Since(start)) }()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(3 * time.Second):
		return 0, nil
	}
}

// failingPurge is a consumer's challenge store that cannot purge for a reason
// of its own.
type failingPurge struct {
	*onetime.MemoryStore

	err error
}

func (s failingPurge) DeleteExpiredBefore(context.Context, string, time.Time) (int, error) {
	return 0, s.err
}

// unsupportedReaper is a consumer's challenge store that reports, on every
// purge, that it cannot purge, and counts how often it was asked.
type unsupportedReaper struct {
	*onetime.MemoryStore

	attempts atomic.Int32
}

func (s *unsupportedReaper) DeleteExpiredBefore(context.Context, string, time.Time) (int, error) {
	s.attempts.Add(1)

	return 0, fmt.Errorf("mfabegin_test: read-only replica: %w", onetime.ErrReapUnsupported)
}

// holdingReaper is a challenge store that holds its first purge until the others'
// challenges have been issued, so every begin racing it has passed its sweep
// before the first sweep ends. It gives up after a minute, which inside a
// synctest bubble passes only once every goroutine is blocked, so a begin
// that never arrives fails the case rather than hanging it.
type holdingReaper struct {
	*onetime.MemoryStore

	others  int32
	inserts atomic.Int32
	arrived chan struct{}
	sweeps  atomic.Int32
	held    atomic.Bool
}

func (s *holdingReaper) Insert(ctx context.Context, tok onetime.Token) error {
	if err := s.MemoryStore.Insert(ctx, tok); err != nil {
		return err
	}

	if s.inserts.Add(1) == s.others {
		close(s.arrived)
	}

	return nil
}

func (s *holdingReaper) DeleteExpiredBefore(ctx context.Context, purpose string, retainSince time.Time) (int, error) {
	if s.sweeps.Add(1) == 1 {
		select {
		case <-s.arrived:
			s.held.Store(true)
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Minute):
		}
	}

	return s.MemoryStore.DeleteExpiredBefore(ctx, purpose, retainSince)
}

// storeOnly is a consumer's challenge store that implements onetime.Store and
// nothing else, so it cannot purge.
type storeOnly struct {
	onetime.Store
}

// failingCount is a consumer's challenge store that cannot count issuance.
type failingCount struct {
	*onetime.MemoryStore

	err error
}

func (s failingCount) CountRecentBySubject(context.Context, string, string, time.Time) (int, error) {
	return 0, s.err
}
