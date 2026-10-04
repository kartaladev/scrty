package httpsec_test

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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
