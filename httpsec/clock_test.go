package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/passkey"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// expiryStore is a challenge store that keeps the last token it was asked
// to insert, so a test can read the expiry the chain's challenge manager gave
// it.
type expiryStore struct {
	*onetime.MemoryStore

	mu   sync.Mutex
	last onetime.Token
}

func (s *expiryStore) Insert(ctx context.Context, tok onetime.Token) error {
	s.mu.Lock()
	s.last = tok
	s.mu.Unlock()

	return s.MemoryStore.Insert(ctx, tok)
}

func (s *expiryStore) lastExpiry() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.last.ExpiresAt
}

// TestWithClock pins the option itself: a nil or typed-nil clock is refused at
// construction, the option alone builds a chain, and without it the chain
// reads the system clock.
func TestWithClock(t *testing.T) {
	t.Parallel()

	// observed is what a row reports: the error of building or driving the
	// chain, and, for the row that reads it, the instant the request began and
	// the expiry the chain's challenge manager gave the token.
	type observed struct {
		err    error
		began  time.Time
		expiry time.Time
	}

	type testCase struct {
		name   string
		act    func(t *testing.T) observed
		assert func(t *testing.T, got observed)
	}

	refusedNamingTheOption := func(t *testing.T, got observed) {
		t.Helper()

		require.ErrorIs(t, got.err, httpsec.ErrConfig)
		assert.Contains(t, got.err.Error(), "WithClock")
	}

	cases := []testCase{
		{
			name: "nil clock",
			act: func(*testing.T) observed {
				_, err := httpsec.New(httpsec.WithClock(nil))

				return observed{err: err}
			},
			assert: refusedNamingTheOption,
		},
		{
			name: "typed nil clock",
			act: func(*testing.T) observed {
				var fc *clockwork.FakeClock

				_, err := httpsec.New(httpsec.WithClock(fc))

				return observed{err: err}
			},
			assert: refusedNamingTheOption,
		},
		{
			// The option governs the chain as a whole, so it is not refused
			// as unused when no interceptor is enabled.
			name: "WithClock alone builds",
			act: func(*testing.T) observed {
				_, err := httpsec.New(httpsec.WithClock(clockwork.NewFakeClock()))

				return observed{err: err}
			},
			assert: func(t *testing.T, got observed) { require.NoError(t, got.err) },
		},
		{
			name: "System clock by default",
			act: func(t *testing.T) observed {
				h := newMFAHarness(t)
				h.systemClock = true
				h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
				h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
					Return(false, nil).AnyTimes()

				stub := newChallengeStub()
				h.extra = []mfa.Method{stub}

				store := &expiryStore{MemoryStore: onetime.NewMemoryStore()}
				h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAChallengeStore(store)}

				s := h.pendingSession(t, factor.Password)

				began := time.Now()
				out := serve(t, h.bearerChain(t), bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID)))

				return observed{err: out.err, began: began, expiry: store.lastExpiry()}
			},
			assert: func(t *testing.T, got observed) {
				require.NoError(t, got.err)
				assert.WithinDuration(t, got.began.Add(httpsec.DefaultMFAChallengeTTL), got.expiry,
					time.Second, "with no WithClock the chain reads the system clock")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.act(t))
		})
	}
}

// clockInstant is the instant every row of TestChain_Clock sets its clock to:
// far from the system clock, so a component still reading time.Now is told
// apart from one reading the chain's clock.
var clockInstant = time.Date(2040, time.January, 1, 0, 0, 0, 0, time.UTC)

// recordNow is a policy that allows everything in phases and remembers the
// instant it was last asked to judge by, so a test can read the time an
// interceptor handed the policy phase.
func recordNow(t *testing.T, phases ...policy.Phase) (*policy.Engine, func() time.Time) {
	t.Helper()

	var (
		mu   sync.Mutex
		seen time.Time
	)

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: time recorder").AnyTimes()
	p.EXPECT().Phases().Return(phases).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
			mu.Lock()
			seen = in.Now
			mu.Unlock()

			return policy.Decision{Outcome: policy.Allow}
		})

	return engineOf(t, p), func() time.Time {
		mu.Lock()
		defer mu.Unlock()

		return seen
	}
}

// codeExpiryMessages is an enrolment message renderer that remembers the
// expiry it was told the emailed code carries.
type codeExpiryMessages struct {
	boundMessages

	mu    sync.Mutex
	until time.Time
}

func (m *codeExpiryMessages) Code(code string, until time.Time) (string, string) {
	m.mu.Lock()
	m.until = until
	m.mu.Unlock()

	return m.boundMessages.Code(code, until)
}

func (m *codeExpiryMessages) expiry() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.until
}

// TestChain_Clock pins that every built-in interceptor reads the chain's time
// source rather than the system clock. Each row sets the chain's clock to
// 2040-01-01 and drives a path whose outcome depends on the time; the rows
// that cannot read a time out of the outcome pick a state that only the
// chain's clock judges one way.
func TestChain_Clock(t *testing.T) {
	t.Parallel()

	// observed is what a row reports: the instant a component read when the
	// row can see it, the outcome of the request, and a count for the rows
	// about how often something ran.
	type observed struct {
		at  time.Time
		out served
		n   int32
	}

	type testCase struct {
		name   string
		act    func(t *testing.T, clk *clockwork.FakeClock) observed
		assert func(t *testing.T, clk *clockwork.FakeClock, got observed)
	}

	// readsTheChainClock is the assertion of the rows that can read the
	// instant: it is the chain's, not the present day's.
	readsTheChainClock := func(t *testing.T, clk *clockwork.FakeClock, got observed) {
		t.Helper()

		require.NoError(t, got.out.err)
		assert.WithinDuration(t, clk.Now(), got.at, 24*time.Hour,
			"the interceptor read %s, not the chain's clock", got.at)
	}

	mfaSweep := func(afterEnableMFA bool) func(*testing.T, *clockwork.FakeClock) observed {
		return func(t *testing.T, clk *clockwork.FakeClock) observed {
			t.Helper()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
			h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
				Return(false, nil).AnyTimes()

			h.extra = []mfa.Method{newChallengeStub()}

			store := &countingReaper{MemoryStore: onetime.NewMemoryStore()}
			h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAChallengeStore(store)}

			var c *httpsec.Chain

			if afterEnableMFA {
				h.chainOpts = []httpsec.Option{httpsec.WithClock(clk)}
				c = h.bearerChain(t)
			} else {
				var err error

				c, err = httpsec.New(
					httpsec.WithClock(clk),
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: h.tokens, Sessions: h.sessions, Users: h.users}),
					httpsec.EnableMFA(append([]mfa.Method{h.method}, h.extra...),
						append([]httpsec.MFAOption{httpsec.WithMFAVerifyLimiter(h.limiter), httpsec.WithMFATokens(h.tokens)}, h.mfaOpts...)...),
				)
				require.NoError(t, err)
			}

			s := h.pendingSession(t, factor.Password)
			begin := func() served {
				return serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID)))
			}

			require.NoError(t, begin().err)

			// An issuance window of the chain's clock passes; the system
			// clock does not move, so only the chain's reading is due again.
			clk.Advance(time.Hour + time.Second)

			out := begin()

			return observed{out: out, n: store.sweeps.Load()}
		}
	}

	sweptAgain := func(t *testing.T, _ *clockwork.FakeClock, got observed) {
		t.Helper()

		require.NoError(t, got.out.err)
		assert.Equal(t, int32(2), got.n, "a window passed on the chain's clock, so the sweep is due again")
	}

	cases := []testCase{
		{
			name: "form login",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newAuthHarness(t)
				engine, seen := recordNow(t, policy.PreAuthentication)

				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")

				c, err := httpsec.New(httpsec.WithLogger(h.logger()), httpsec.WithPolicyEngine(engine),
					httpsec.EnableFormLogin(h.formLoginDeps()), httpsec.WithClock(clk))
				require.NoError(t, err)

				out := serve(t, c, formRequest(t.Context(), "/login", "username=ada&password=s3cret"))

				return observed{at: seen(), out: out}
			},
			assert: readsTheChainClock,
		},
		{
			name: "Basic authentication",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newAuthHarness(t)
				engine, seen := recordNow(t, policy.PreAuthentication)

				h.expectAuthenticated(testPrincipal())

				c, err := httpsec.New(httpsec.WithLogger(h.logger()), httpsec.WithPolicyEngine(engine),
					httpsec.EnableBasicAuth(h.basicAuthDeps()), httpsec.WithClock(clk))
				require.NoError(t, err)

				out := serve(t, c, basicRequest(t.Context(), "ada", "s3cret"))

				return observed{at: seen(), out: out}
			},
			assert: readsTheChainClock,
		},
		{
			name: "bearer token",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newAuthHarness(t)
				engine, seen := recordNow(t, policy.PerRequest)

				h.expectVerified()
				h.expectLiveSessionAndUser(liveSession())

				out := serveBearerOn(t, h, engine, bearerRequest(t.Context(), "Bearer abc.def.ghi"),
					[]httpsec.Option{httpsec.WithClock(clk)})

				return observed{at: seen(), out: out}
			},
			assert: readsTheChainClock,
		},
		{
			name: "API key",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newAPIKeyHarness(t)
				engine, seen := recordNow(t, policy.StatelessAuthentication)

				c, err := httpsec.New(httpsec.EnableAPIKey(h.keys), httpsec.WithPolicyEngine(engine), httpsec.WithClock(clk))
				require.NoError(t, err)

				out := h.withKey(t, c, apiKeySource, h.valid)

				return observed{at: seen(), out: out}
			},
			assert: readsTheChainClock,
		},
		{
			name: "magic link",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newMagicLinkHarness(t)
				engine, seen := recordNow(t, policy.PostAuthentication)

				h.engine = engine
				h.chainOpts = []httpsec.Option{httpsec.WithClock(clk)}

				c := h.chain(t)
				tok, nonce := h.link(t, c)

				return observed{out: h.redeem(t, c, tok, nonce), at: seen()}
			},
			assert: readsTheChainClock,
		},
		{
			name: "OIDC login",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newOIDCHarness(t, oidc.WithClock(clk))
				h.chainOpts = []httpsec.Option{httpsec.WithClock(clk)}

				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					httpsec.DefaultOIDCAuthorizePath+testOIDCProvider, nil)

				return observed{out: serve(t, h.chain(t), req)}
			},
			assert: func(t *testing.T, _ *clockwork.FakeClock, got observed) {
				require.NoError(t, got.out.err)

				cookie := cookieNamed(got.out.rec, httpsec.DefaultOIDCFlowCookieName)
				require.NotNil(t, cookie)
				assert.Equal(t, int(oidc.DefaultFlowTTL.Seconds()), cookie.MaxAge,
					"the flow cookie lives as long as the flow, counted on the chain's clock")
			},
		},
		{
			name:   "MFA begin",
			act:    mfaSweep(false),
			assert: sweptAgain,
		},
		{
			// Review Focus 1: the option may come after the Enable options.
			name:   "WithClock after EnableMFA still drives MFA",
			act:    mfaSweep(true),
			assert: sweptAgain,
		},
		{
			name: "MFA enrolment",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newEnrolHarness(t)
				o := &outbox{}
				msgs := &codeExpiryMessages{}

				h.enrolOpts = append(h.enrolOpts, httpsec.WithEnrolmentMessages(msgs))
				h.extra = append(h.extra, httpsec.WithClock(clk))
				o.accepting(h, nil)

				c := h.chain(t, h.enrolmentOnly(t, factor.Password))
				h.prove(t, c, o, h.beginDoc(t, c).Secret)

				return observed{at: msgs.expiry()}
			},
			assert: func(t *testing.T, clk *clockwork.FakeClock, got observed) {
				assert.WithinDuration(t, clk.Now(), got.at, 24*time.Hour,
					"the emailed code's expiry counts from the chain's clock")
			},
		},
		{
			// The password is older than the policy allows only on the chain's
			// clock; on the present day it has not been changed yet.
			name: "passwordless login",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				d := newPwlDeployment(t)
				d.passwordAge = true
				d.extra = append(d.extra, httpsec.WithClock(clk))
				d.build(t)

				d.passwordChangedAt = clk.Now().Add(-2 * pwlMaxPasswordAge)

				return observed{out: d.login(t, "cred-1", d.seed(t, e2eUser, "cred-1", passkey.StateActive))}
			},
			assert: func(t *testing.T, _ *clockwork.FakeClock, got observed) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, got.out.err, &ch)
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
			},
		},
		{
			// A session last authenticated at the chain's 09:00 is stale 20
			// minutes later on that clock; on the present day it was
			// authenticated in the future, and so is fresh.
			name: "recovery regeneration freshness",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newRecoveryHarness(t)
				h.clock.Advance(clk.Now().Sub(h.clock.Now()))
				h.chainOpts = append(h.chainOpts,
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: h.tokens, Sessions: h.sessions, Users: h.users}),
					httpsec.WithClock(h.clock))
				h.build(t)
				h.saved(t)

				s := h.fullSession(t)
				h.elapse(t, s, 20*time.Minute)

				return observed{out: h.codesRequest(t, http.MethodPost, s)}
			},
			assert: func(t *testing.T, _ *clockwork.FakeClock, got observed) {
				require.ErrorIs(t, got.out.err, recovery.ErrReauthenticationRequired)
			},
		},
		{
			// A recovery completed on the chain's clock 49 hours ago is out of
			// its 48-hour cool-down; on the present day it has not happened yet.
			name: "recovery cool-down",
			act: func(t *testing.T, clk *clockwork.FakeClock) observed {
				h := newRecoveryHarness(t)
				h.clock.Advance(clk.Now().Sub(h.clock.Now()))

				rid, err := id.NewV7Generator().NewID()
				require.NoError(t, err)

				at := h.clock.Now()
				records := recovery.NewMemoryRecordStore()
				require.NoError(t, records.Insert(t.Context(), recovery.Record{
					ID: rid, User: e2eUser, StartedAt: at, NotBefore: at, CompletedAt: at,
				}))

				h.clock.Advance(49 * time.Hour)

				c, err := httpsec.New(
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: h.tokens, Sessions: h.sessions, Users: h.users}),
					httpsec.EnableRecoveryCooldown(records, recoveryCooldown, emailRoute),
					httpsec.WithClock(h.clock),
				)
				require.NoError(t, err)

				s, err := h.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/account/email", nil)
				req.RemoteAddr = e2eSource + ":51000"
				req.Header.Set("Authorization", "Bearer "+mfaTokenFor(s.ID))

				return observed{out: serve(t, c, req)}
			},
			assert: func(t *testing.T, _ *clockwork.FakeClock, got observed) {
				require.NoError(t, got.out.err)
				assert.True(t, got.out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			clk := clockwork.NewFakeClockAt(clockInstant)
			tc.assert(t, clk, tc.act(t, clk))
		})
	}
}

// timeNowReads returns the file:line of every direct read of the system clock
// in src: a selector Now on the local name the file gives the "time" import.
// It parses the source, so comments and string literals never match and an
// aliased import does. A dot import is reported at the import itself, since it
// would hide every read from this check.
func timeNowReads(t *testing.T, name, src string) []string {
	t.Helper()

	fset := token.NewFileSet()
	// Object resolution stays on: an identifier declared inside the file
	// carries its Obj, which is how a local shadowing the import is told
	// apart from the package, whose name resolves to no Obj.
	file, err := parser.ParseFile(fset, name, src, 0)
	require.NoError(t, err)

	var (
		hits   []string
		locals = map[string]bool{}
	)

	for _, imp := range file.Imports {
		if path, err := strconv.Unquote(imp.Path.Value); err != nil || path != "time" {
			continue
		}

		local := "time"
		if imp.Name != nil {
			local = imp.Name.Name
		}

		switch local {
		case "_":
		case ".":
			hits = append(hits, fmt.Sprintf("%s:%d", name, fset.Position(imp.Pos()).Line))
		default:
			locals[local] = true
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Now" {
			return true
		}

		if x, ok := sel.X.(*ast.Ident); ok && x.Obj == nil && locals[x.Name] {
			hits = append(hits, fmt.Sprintf("%s:%d", name, fset.Position(sel.Pos()).Line))
		}

		return true
	})

	return hits
}

// TestTimeNowReads pins the detector behind TestNoDirectTimeNow on fixture
// sources: it must read the syntax, not the text.
func TestTimeNowReads(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		src    string
		assert func(t *testing.T, hits []string)
	}

	found := func(want ...string) func(*testing.T, []string) {
		return func(t *testing.T, hits []string) {
			t.Helper()

			assert.Equal(t, want, hits)
		}
	}

	cases := []testCase{
		{
			name:   "plain call",
			src:    "package p\n\nimport \"time\"\n\nvar _ = time.Now()\n",
			assert: found("p.go:5"),
		},
		{
			name:   "function value",
			src:    "package p\n\nimport \"time\"\n\nvar _ = time.Now\n",
			assert: found("p.go:5"),
		},
		{
			name:   "aliased import",
			src:    "package p\n\nimport t \"time\"\n\nvar _ = t.Now()\n",
			assert: found("p.go:5"),
		},
		{
			name:   "after a slash pair inside a string",
			src:    "package p\n\nimport \"time\"\n\nvar _, _ = \"http://x\", time.Now\n",
			assert: found("p.go:5"),
		},
		{
			name:   "block comment",
			src:    "package p\n\n/* time.Now */\nvar _ = 1\n",
			assert: found(),
		},
		{
			name:   "line comment",
			src:    "package p\n\n// time.Now\nvar _ = 1\n",
			assert: found(),
		},
		{
			name:   "raw string",
			src:    "package p\n\nvar _ = `time.Now`\n",
			assert: found(),
		},
		{
			name:   "other time function",
			src:    "package p\n\nimport \"time\"\n\nvar _ = time.Since\n",
			assert: found(),
		},
		{
			name:   "a local named time is not the package",
			src:    "package p\n\ntype clk struct{}\n\nfunc (clk) Now() int { return 0 }\n\nvar time clk\n\nvar _ = time.Now()\n",
			assert: found(),
		},
		{
			name:   "a local shadowing the imported time is not the package",
			src:    "package p\n\nimport \"time\"\n\ntype clk struct{}\n\nfunc (clk) Now() int { return 0 }\n\nvar _ = time.Second\n\nfunc f() { time := clk{}; _ = time.Now() }\n",
			assert: found(),
		},
		{
			name:   "a raw-string import path",
			src:    "package p\n\nimport `time`\n\nvar _ = time.Now()\n",
			assert: found("p.go:5"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, timeNowReads(t, "p.go", tc.src))
		})
	}
}

// TestNoDirectTimeNow pins that no non-test file of the package reads the
// system clock directly: every reading goes through the chain's time source,
// whose default is the one place the system clock is named.
func TestNoDirectTimeNow(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		src, err := os.ReadFile(name) //nolint:gosec // G304: name comes from a glob of this directory
		require.NoError(t, err)

		for _, hit := range timeNowReads(t, name, string(src)) {
			assert.Fail(t, "direct system clock read",
				"%s reads time.Now directly; read the chain's clock instead", hit)
		}
	}
}

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
