package httpsec_test

import (
	"context"
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

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/magiclink"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token/onetime"
)

//go:generate mockgen -source=options_test.go -package=httpsec_test -destination=decoyauthenticator_mock_test.go -typed -mock_names=DecoyAuthenticator=MockDecoyAuthenticator

// DecoyAuthenticator is an authenticator that can also spend decoy password
// verifications, as the chain's lock refusal looks for.
type DecoyAuthenticator interface {
	authenticate.Authenticator
	authenticate.DecoyVerifier
}

// expiryStore is a challenge store that keeps the last token it was asked
// to insert, so a test can read the expiry the chain's challenge manager gave
// it.
type expiryStore struct {
	*onetime.MemoryStore

	mu   sync.Mutex
	last onetime.Token
}

func (s *expiryStore) InsertWithin(ctx context.Context, tok onetime.Token, since time.Time, limit int) (bool, error) {
	s.mu.Lock()
	s.last = tok
	s.mu.Unlock()

	return s.MemoryStore.InsertWithin(ctx, tok, since, limit)
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
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)

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

// stubSessionManager and stubUserLoader stand in for the collaborators an
// Enable* option is handed. Nothing calls them: construction validation only
// asks whether they are there.
type stubSessionManager struct{}

type stubUserLoader struct{}

func TestNewRefusesWiring(t *testing.T) {
	t.Parallel()

	noop := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		return next(ex)
	})

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "an enabled built-in missing a dependency",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableTestBuiltIn(httpsec.TestBuiltInDeps{
						Users: &stubUserLoader{},
						// Sessions deliberately absent.
					}),
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c, "no usable chain may be returned alongside a configuration error")
				assert.Contains(t, err.Error(), "EnableTestBuiltIn")
				assert.Contains(t, err.Error(), "session manager")
			},
		},
		{
			name: "a nil interceptor",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.RegisterInterceptor(nil, httpsec.OrderBearerToken)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
			},
		},
		{
			name: "an absent rate-limiter factory",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRateLimiterFactory(nil)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithRateLimiterFactory")
				assert.Contains(t, err.Error(), "rate-limiter factory")
			},
		},
		{
			name: "a nil refusal log reporter",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogReporter(nil)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithRefusalLogReporter")
				assert.Contains(t, err.Error(), "reporter")
			},
		},
		{
			name: "a nil policy engine",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithPolicyEngine(nil)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithPolicyEngine")
				assert.Contains(t, err.Error(), "policy engine")
			},
		},
		{
			name: "a nil logger",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(nil)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithLogger")
				assert.Contains(t, err.Error(), "logger")
			},
		},
		{
			name: "an IPv6 source prefix above the address width",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithIPv6SourcePrefix(129)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithIPv6SourcePrefix")
				assert.Contains(t, err.Error(), "129")
			},
		},
		{
			name: "an IPv6 source prefix of zero",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithIPv6SourcePrefix(0)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithIPv6SourcePrefix")
			},
		},
		{
			name: "the minimum wiring succeeds",
			opts: func(_ *testing.T) []httpsec.Option { return nil },
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "a consumer who wires nothing must still get a usable chain")
				assert.NotNil(t, c)
			},
		},
		{
			name: "a nil option in the list is skipped rather than refused",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{
					nil,
					httpsec.RegisterInterceptor(noop, httpsec.OrderBearerToken),
					nil,
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "a consumer building the option slice conditionally need not filter it")
				assert.NotNil(t, c)
			},
		},
		{
			name: "a refusal log interval of zero disables sampling rather than failing",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogInterval(0)}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err, "a disabled interval is a documented choice, not a wiring fault")
				assert.NotNil(t, c)
			},
		},
		{
			name: "every dependency present builds",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableTestBuiltIn(httpsec.TestBuiltInDeps{
						Sessions: &stubSessionManager{},
						Users:    &stubUserLoader{},
					}),
					httpsec.WithRateLimiterFactory(ratelimit.MemoryLimiterFactory()),
					httpsec.WithLogger(slog.New(slog.DiscardHandler)),
					httpsec.WithIPv6SourcePrefix(48),
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, c)
			},
		},
		{
			// A missing session manager is a configuration error from New.
			name: "with session manager refuses nil",
			opts: func(_ *testing.T) []httpsec.Option {
				var m *session.Sessions

				return []httpsec.Option{httpsec.WithSessions(m)}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, chain)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts(t)...)
			tc.assert(t, c, err)
		})
	}
}

// TestNewRejectsTypedNil covers the nil a plain == comparison misses: an
// interface that is not nil because it carries a type, but holds a nil pointer.
// It is the shape an unchecked constructor error hands over, and without the
// reflective check it panics on the first request instead of failing here.
func TestNewRejectsTypedNil(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	cases := []testCase{
		{
			name: "a dependency present but holding a typed nil",
			opts: []httpsec.Option{
				httpsec.EnableTestBuiltIn(httpsec.TestBuiltInDeps{
					Sessions: &stubSessionManager{},
					Users:    (*stubUserLoader)(nil),
				}),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "EnableTestBuiltIn")
				assert.Contains(t, err.Error(), "user loader")
			},
		},
		{
			name: "an interceptor holding a typed nil",
			opts: []httpsec.Option{
				httpsec.RegisterInterceptor((*nilInterceptor)(nil), httpsec.OrderBearerToken),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
			},
		},
		{
			name: "a rate-limiter factory holding a typed nil",
			opts: []httpsec.Option{
				httpsec.WithRateLimiterFactory((*MockLimiterFactory)(nil)),
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, err.Error(), "WithRateLimiterFactory")
				assert.Contains(t, err.Error(), "rate-limiter factory")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts...)
			tc.assert(t, c, err)
		})
	}
}

// TestNewDefaults pins what a consumer gets with no configuration at all, and
// that each of those defaults is replaceable by the option that names it. The
// rate-limit settings are pinned by what they do, in throttle_test.go.
func TestNewDefaults(t *testing.T) {
	t.Parallel()

	engine, err := policy.NewEngine()
	require.NoError(t, err)

	consumerLogger := slog.New(slog.DiscardHandler)

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, s httpsec.ChainSettings)
	}

	cases := []testCase{
		{
			name: "no options: the safe defaults",
			opts: func(_ *testing.T) []httpsec.Option { return nil },
			assert: func(t *testing.T, s httpsec.ChainSettings) {
				assert.Nil(t, s.PolicyEngine, "with no engine every phase allows")
				assert.Same(t, slog.Default(), s.Logger)
				assert.Equal(t, time.Minute, s.RefusalLogInterval)
				assert.Nil(t, s.RefusalLogReporter, "the default summary reporter is supplied where the sampler is built")
			},
		},
		{
			name: "the consumer replaces the policy engine",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithPolicyEngine(engine)}
			},
			assert: func(t *testing.T, s httpsec.ChainSettings) {
				assert.Same(t, engine, s.PolicyEngine)
			},
		},
		{
			name: "the consumer replaces the logger",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithLogger(consumerLogger)}
			},
			assert: func(t *testing.T, s httpsec.ChainSettings) {
				assert.Same(t, consumerLogger, s.Logger)
			},
		},
		{
			name: "the consumer replaces the refusal log interval and reporter",
			opts: func(_ *testing.T) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithRefusalLogInterval(5 * time.Second),
					httpsec.WithRefusalLogReporter(func(_ string, _ int) {}),
				}
			},
			assert: func(t *testing.T, s httpsec.ChainSettings) {
				assert.Equal(t, 5*time.Second, s.RefusalLogInterval)
				assert.NotNil(t, s.RefusalLogReporter)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(tc.opts(t)...)
			require.NoError(t, err)
			require.NotNil(t, c)

			tc.assert(t, httpsec.Settings(c))
		})
	}
}

// TestCeremonyCookieTTL_RefusesSubSecond pins that the cookies binding a
// magic link, or a passkey ceremony, to the browser that began it carry the
// lifetime of what they bind, in whole seconds: a fractional lifetime would be
// truncated, and the cookie would expire before the credential does or, for
// less than a second, never be set to live at all.
//
// Not rows of TestNewRefusesWiring: each case builds its own feature's harness.
func TestCeremonyCookieTTL_RefusesSubSecond(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T) error
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "whole number of seconds")
	}
	accepted := func(t *testing.T, err error) {
		t.Helper()
		require.NoError(t, err)
	}

	magicLink := func(ttl time.Duration) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			h := newMagicLinkHarness(t)

			onetimes, err := onetime.New("magic-link", onetime.WithTokenTTL(ttl))
			require.NoError(t, err)

			h.manager, err = magiclink.New(onetimes, h.users, h.sender, "https://app.example.com")
			require.NoError(t, err)

			_, err = h.build()

			return err
		}
	}

	passwordless := func(ttl time.Duration) func(t *testing.T) error {
		return func(t *testing.T) error {
			t.Helper()

			d := newPwlDeployment(t)
			d.pkOpts = append(d.pkOpts, passkey.WithChallengeTTL(ttl))

			_, err := httpsec.New(d.options(t)...)

			return err
		}
	}

	cases := []testCase{
		{name: "magic link, whole seconds", build: magicLink(90 * time.Second), assert: accepted},
		{name: "magic link, fractional seconds", build: magicLink(1500 * time.Millisecond), assert: refused},
		{name: "magic link, under a second", build: magicLink(500 * time.Millisecond), assert: refused},
		{name: "passkey ceremony, whole seconds", build: passwordless(90 * time.Second), assert: accepted},
		{name: "passkey ceremony, fractional seconds", build: passwordless(1500 * time.Millisecond), assert: refused},
		{name: "passkey ceremony, under a second", build: passwordless(500 * time.Millisecond), assert: refused},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, tc.build(t))
		})
	}
}

// TestHeld pins that an identifier held by a capped lockout policy is refused
// by the password logins exactly as any locked one is: concealed as a failed
// authentication with one decoy spent by default, answered 429 when locks are
// disclosed, identifiable as a hold either way, and alike for a username with
// no account. The password is never checked while the hold stands.
func TestHeld(t *testing.T) {
	t.Parallel()

	const heldCap = 20

	form := func(ctx context.Context, user string) *http.Request {
		return formRequest(ctx, httpsec.DefaultLoginPath, "username="+user+"&password=correct")
	}
	basic := func(ctx context.Context, user string) *http.Request {
		return basicRequest(ctx, user, "correct")
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		users  []string
		send   func(ctx context.Context, user string) *http.Request
		assert func(t *testing.T, out map[string]served, spent map[string]int)
	}

	cases := []testCase{
		{
			name:  "Held by default: refused as a failed authentication, one decoy spent",
			users: []string{"ada"},
			send:  form,
			assert: func(t *testing.T, out map[string]served, spent map[string]int) {
				got := out["ada"]

				assert.False(t, got.handlerRan)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(got.err))
				require.ErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
				require.ErrorIs(t, got.err, lockout.ErrAccountLocked)
				require.ErrorIs(t, got.err, lockout.ErrAccountHeld)
				assert.Equal(t, 1, spent["ada"], "one decoy verification is spent")
			},
		},
		{
			name:  "Held by default: Basic is refused as a failed authentication with the challenge, one decoy spent",
			users: []string{"ada"},
			send:  basic,
			assert: func(t *testing.T, out map[string]served, spent map[string]int) {
				got := out["ada"]

				assert.False(t, got.handlerRan)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(got.err))
				assert.Equal(t, `Basic realm="Restricted"`, got.rec.Header().Get("WWW-Authenticate"))
				require.ErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
				require.ErrorIs(t, got.err, lockout.ErrAccountHeld)
				assert.Equal(t, 1, spent["ada"], "one decoy verification is spent")
			},
		},
		{
			name:  "Held, disclosure chosen: Basic is answered 429 with no challenge header",
			opts:  []httpsec.Option{httpsec.WithLockDisclosure()},
			users: []string{"ada"},
			send:  basic,
			assert: func(t *testing.T, out map[string]served, spent map[string]int) {
				got := out["ada"]

				assert.False(t, got.handlerRan)
				assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(got.err))
				require.ErrorIs(t, got.err, lockout.ErrAccountLocked)
				require.ErrorIs(t, got.err, lockout.ErrAccountHeld)
				assert.NotErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
				assert.Empty(t, got.rec.Header().Get("WWW-Authenticate"))
				assert.Zero(t, spent["ada"], "a disclosed lock spends no decoy")
			},
		},
		{
			name:  "Unknown username held alike: same error and status, one decoy each",
			users: []string{"ada", "nobody"},
			send:  form,
			assert: func(t *testing.T, out map[string]served, spent map[string]int) {
				known, unknown := out["ada"], out["nobody"]

				for _, got := range []served{known, unknown} {
					assert.False(t, got.handlerRan)
					require.ErrorIs(t, got.err, authenticate.ErrAuthenticationFailed)
					require.ErrorIs(t, got.err, lockout.ErrAccountHeld)
				}

				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(known.err))
				assert.Equal(t, httpsec.StatusForError(known.err), httpsec.StatusForError(unknown.err))
				assert.Equal(t, known.err.Error(), unknown.err.Error())
				assert.Equal(t, 1, spent["ada"], "ada: decoys spent")
				assert.Equal(t, 1, spent["nobody"], "nobody: decoys spent")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lockoutPolicy, err := lockout.New(
				lockout.WithAttemptStore(lockout.NewMemoryAttemptStore()), lockout.WithFailureStreakLimit(heldCap))
			require.NoError(t, err)

			// Each identifier is held before any request: heldCap failures
			// recorded through the policy's view, as the logins record them.
			at := time.Now().Add(-time.Hour)
			for _, user := range tc.users {
				for i := range heldCap {
					require.NoError(t, lockoutPolicy.Attempts().RecordFailure(t.Context(), user,
						at.Add(time.Duration(i)*time.Second)))
				}
			}

			sessions, err := session.New(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			// No Authenticate expectation: the password is never checked while
			// the hold stands, and a call fails the test.
			spent := map[string]int{}
			authn := NewMockDecoyAuthenticator(gomock.NewController(t))
			authn.EXPECT().VerifyDecoy(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, c identity.Credentials) bool {
					up, ok := c.(*identity.UsernamePassword)
					require.True(t, ok, "decoys are spent on username and password credentials")

					spent[up.Username]++

					return true
				}).AnyTimes()

			chain, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithPolicyEngine(engineOf(t, lockoutPolicy)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: sessions,
					Tokens: NewMockGenerator(gomock.NewController(t)), Attempts: lockoutPolicy.Attempts(),
				}),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: lockoutPolicy.Attempts()}),
			}, tc.opts...)...)
			require.NoError(t, err)

			out := map[string]served{}
			for _, user := range tc.users {
				out[user] = serve(t, chain, tc.send(t.Context(), user))
			}

			tc.assert(t, out, spent)
		})
	}
}

// TestUnknownUsernameLock pins that a username with no account is locked
// exactly like one with an account, over Basic and over form login, and that
// each refused attempt spends one decoy password verification when locks are
// concealed and none when they are disclosed.
func TestUnknownUsernameLock(t *testing.T) {
	t.Parallel()

	basic := func(ctx context.Context, user string) *http.Request {
		return basicRequest(ctx, user, "wrong")
	}
	form := func(ctx context.Context, user string) *http.Request {
		return formRequest(ctx, httpsec.DefaultLoginPath, "username="+user+"&password=wrong")
	}

	type testCase struct {
		name   string
		opts   []httpsec.Option
		send   func(ctx context.Context, user string) *http.Request
		assert func(t *testing.T, known, unknown served, spent map[string]int)
	}

	alike := func(t *testing.T, known, unknown served, spent map[string]int) {
		t.Helper()

		assert.Equal(t, 1, spent["ada"], "ada: decoys spent by the locked attempt")
		assert.Equal(t, 1, spent["nobody"], "nobody: decoys spent by the locked attempt")

		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(known.err))
		assert.Equal(t, httpsec.StatusForError(known.err), httpsec.StatusForError(unknown.err))
		require.ErrorIs(t, known.err, lockout.ErrAccountLocked)
		require.ErrorIs(t, unknown.err, lockout.ErrAccountLocked)
		require.ErrorIs(t, known.err, authenticate.ErrAuthenticationFailed)
		require.ErrorIs(t, unknown.err, authenticate.ErrAuthenticationFailed)
		assert.Equal(t, known.err.Error(), unknown.err.Error())
		assert.Equal(t, known.rec.Header().Get("WWW-Authenticate"), unknown.rec.Header().Get("WWW-Authenticate"))
	}

	disclosed := func(t *testing.T, known, unknown served, spent map[string]int) {
		t.Helper()

		assert.Zero(t, spent["ada"], "ada: a disclosed lock spends no decoy")
		assert.Zero(t, spent["nobody"], "nobody: a disclosed lock spends no decoy")

		for _, out := range []served{known, unknown} {
			require.ErrorIs(t, out.err, lockout.ErrAccountLocked)
			assert.NotErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
			assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(out.err))
		}
	}

	cases := []testCase{
		{name: "over Basic, both are refused alike", send: basic, assert: alike},
		{name: "over form login, both are refused alike, one decoy each", send: form, assert: alike},
		{
			name: "over Basic with locks disclosed, both are answered 429",
			opts: []httpsec.Option{httpsec.WithLockDisclosure()}, send: basic, assert: disclosed,
		},
		{
			name: "over form login with locks disclosed, both are answered 429",
			opts: []httpsec.Option{httpsec.WithLockDisclosure()}, send: form, assert: disclosed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			attempts := lockout.NewMemoryAttemptStore()
			lockoutPolicy, err := lockout.New(lockout.WithAttemptStore(attempts))
			require.NoError(t, err)

			sessions, err := session.New(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			// Each user's sixth, locked, attempt is the only one that may spend a
			// decoy, and a spend is told apart by the username it was asked for.
			spent := map[string]int{}
			authn := NewMockDecoyAuthenticator(gomock.NewController(t))
			authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
				Return(nil, authenticate.ErrAuthenticationFailed).AnyTimes()
			authn.EXPECT().VerifyDecoy(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, c identity.Credentials) bool {
					up, ok := c.(*identity.UsernamePassword)
					require.True(t, ok, "decoys are spent on username and password credentials")

					spent[up.Username]++

					return true
				}).AnyTimes()

			chain, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithPolicyEngine(engineOf(t, lockoutPolicy)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: sessions, Tokens: NewMockGenerator(gomock.NewController(t)), Attempts: attempts,
				}),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts}),
			}, tc.opts...)...)
			require.NoError(t, err)

			sixth := map[string]served{}

			for _, user := range []string{"ada", "nobody"} {
				for range 5 {
					out := serve(t, chain, tc.send(t.Context(), user))
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
					require.NotErrorIs(t, out.err, lockout.ErrAccountLocked, "five failures are still free")
				}

				require.Zero(t, spent[user], "the five free failures spend no decoy")

				sixth[user] = serve(t, chain, tc.send(t.Context(), user))
			}

			tc.assert(t, sixth["ada"], sixth["nobody"], spent)
		})
	}
}

// TestUnknownUsernameLockRealAuthenticator pins that a username the real
// password authenticator cannot find (the loader answers identity.ErrUserNotFound)
// is locked after the same five failures as one it can, and that both locked
// attempts are refused alike. It has its own table because the SUT is wired
// with the real authenticator rather than a mocked one.
func TestUnknownUsernameLockRealAuthenticator(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		send   func(ctx context.Context, user string) *http.Request
		assert func(t *testing.T, known, unknown served)
	}

	alike := func(t *testing.T, known, unknown served) {
		t.Helper()

		for _, out := range []served{known, unknown} {
			require.ErrorIs(t, out.err, lockout.ErrAccountLocked)
			require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
		}

		assert.Equal(t, httpsec.StatusForError(known.err), httpsec.StatusForError(unknown.err))
		assert.Equal(t, known.err.Error(), unknown.err.Error())
		assert.Equal(t, known.rec.Header().Get("WWW-Authenticate"), unknown.rec.Header().Get("WWW-Authenticate"))
	}

	cases := []testCase{
		{
			name:   "over Basic, an unknown username is refused like a known one",
			send:   func(ctx context.Context, user string) *http.Request { return basicRequest(ctx, user, "wrong") },
			assert: alike,
		},
		{
			name: "over form login, an unknown username is refused like a known one",
			send: func(ctx context.Context, user string) *http.Request {
				return formRequest(ctx, httpsec.DefaultLoginPath, "username="+user+"&password=wrong")
			},
			assert: alike,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			// ada exists with a hash that never matches; nobody has no account.
			loader := NewMockUserLoader(ctrl)
			loader.EXPECT().LoadByUsername(gomock.Any(), "ada").
				Return(&identity.Details{Username: "ada", Password: []byte("stored"), Active: true}, nil).AnyTimes()
			loader.EXPECT().LoadByUsername(gomock.Any(), "nobody").
				Return(nil, identity.ErrUserNotFound).AnyTimes()

			enc := NewMockEncoder(ctrl)
			enc.EXPECT().Encode(gomock.Any()).Return([]byte("reference"), nil).AnyTimes()
			enc.EXPECT().Match(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

			authn, err := authenticate.NewUsernamePasswordAuthenticator(loader, authenticate.WithPasswordEncoder(enc))
			require.NoError(t, err)

			attempts := lockout.NewMemoryAttemptStore()
			lockoutPolicy, err := lockout.New(lockout.WithAttemptStore(attempts))
			require.NoError(t, err)

			sessions, err := session.New(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			chain, err := httpsec.New(
				httpsec.WithPolicyEngine(engineOf(t, lockoutPolicy)),
				httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: authn, Sessions: sessions, Tokens: NewMockGenerator(ctrl), Attempts: attempts,
				}),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: authn, Attempts: attempts}),
			)
			require.NoError(t, err)

			sixth := map[string]served{}

			for _, user := range []string{"ada", "nobody"} {
				for range 5 {
					out := serve(t, chain, tc.send(t.Context(), user))
					require.ErrorIs(t, out.err, authenticate.ErrAuthenticationFailed)
					require.NotErrorIs(t, out.err, lockout.ErrAccountLocked, "five failures are still free")
				}

				sixth[user] = serve(t, chain, tc.send(t.Context(), user))
			}

			tc.assert(t, sixth["ada"], sixth["nobody"])
		})
	}
}

// TestLockoutCapWiring pins that a chain refuses to build when a capped
// lockout policy's view is bypassed by a password login, since only the view
// advances the consecutive count, and that every other wiring still builds.
//
// Not rows of TestNewRefusesWiring: each case wires attempt stores into form login and Basic.
func TestLockoutCapWiring(t *testing.T) {
	t.Parallel()

	// wiring is the policies the engine holds and the store each login is
	// given; a nil store leaves that login out.
	type wiring struct {
		lockouts    []*lockout.Policy
		form, basic policy.AttemptStore
	}

	type testCase struct {
		name   string
		wire   func(t *testing.T) wiring
		assert func(t *testing.T, err error)
	}

	capped := func(t *testing.T, store policy.AttemptStore) *lockout.Policy {
		t.Helper()

		p, err := lockout.New(lockout.WithAttemptStore(store), lockout.WithFailureStreakLimit(20))
		require.NoError(t, err)

		return p
	}

	refusedNaming := func(field string) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Contains(t, err.Error(), field)
			assert.Contains(t, err.Error(), `"account-lockout"`, "the requiring policy is named")
			assert.EqualError(t, err, httpsec.ErrConfig.Error()+": "+field+
				" records failures into a store other than the view the \"account-lockout\" policy requires: "+
				"give it that policy's view (lockout.Policy.Attempts for an account-lockout policy)")
		}
	}

	refusedDifferentViews := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "different")
		assert.Equal(t, 2, strings.Count(err.Error(), `"account-lockout"`), "both policies are named")
		assert.Contains(t, err.Error(), "only one store")
	}

	lockouts := func(ps ...*lockout.Policy) []*lockout.Policy { return ps }

	builds := func(t *testing.T, err error) {
		t.Helper()

		require.NoError(t, err)
	}

	cases := []testCase{
		{
			name: "Raw store with a cap: form login is refused",
			wire: func(t *testing.T) wiring {
				store := lockout.NewMemoryAttemptStore()

				return wiring{lockouts: lockouts(capped(t, store)), form: store}
			},
			assert: refusedNaming("FormLoginDeps.Attempts"),
		},
		{
			name: "Raw store with a cap: Basic is refused",
			wire: func(t *testing.T) wiring {
				store := lockout.NewMemoryAttemptStore()
				p := capped(t, store)

				return wiring{lockouts: lockouts(p), form: p.Attempts(), basic: store}
			},
			assert: refusedNaming("BasicAuthDeps.Attempts"),
		},
		{
			name: "View with a cap: both logins given the view build",
			wire: func(t *testing.T) wiring {
				p := capped(t, lockout.NewMemoryAttemptStore())

				return wiring{lockouts: lockouts(p), form: p.Attempts(), basic: p.Attempts()}
			},
			assert: builds,
		},
		{
			name: "Raw store without a cap: Basic given the store builds",
			wire: func(t *testing.T) wiring {
				store := lockout.NewMemoryAttemptStore()
				p, err := lockout.New(lockout.WithAttemptStore(store))
				require.NoError(t, err)

				return wiring{lockouts: lockouts(p), basic: store}
			},
			assert: builds,
		},
		{
			name: "a cap with no password login builds",
			wire: func(t *testing.T) wiring {
				return wiring{lockouts: lockouts(capped(t, lockout.NewMemoryAttemptStore()))}
			},
			assert: builds,
		},
		{
			name: "Two capped policies: Basic given the first's view is refused",
			wire: func(t *testing.T) wiring {
				first, second := capped(t, lockout.NewMemoryAttemptStore()), capped(t, lockout.NewMemoryAttemptStore())

				return wiring{lockouts: lockouts(first, second), basic: first.Attempts()}
			},
			assert: refusedDifferentViews,
		},
		{
			name: "Two capped policies: Basic given the second's view is refused",
			wire: func(t *testing.T) wiring {
				first, second := capped(t, lockout.NewMemoryAttemptStore()), capped(t, lockout.NewMemoryAttemptStore())

				return wiring{lockouts: lockouts(first, second), basic: second.Attempts()}
			},
			assert: refusedDifferentViews,
		},
		{
			name: "Two capped policies, no password login: builds",
			wire: func(t *testing.T) wiring {
				first, second := capped(t, lockout.NewMemoryAttemptStore()), capped(t, lockout.NewMemoryAttemptStore())

				return wiring{lockouts: lockouts(first, second)}
			},
			assert: builds,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := tc.wire(t)
			ctrl := gomock.NewController(t)

			sessions, err := session.New(session.WithStore(session.NewMemoryStore()))
			require.NoError(t, err)

			opts := []httpsec.Option{httpsec.WithPolicyEngine(engineOf(t, lockoutPolicies(w.lockouts)...))}

			if w.form != nil {
				opts = append(opts, httpsec.EnableFormLogin(httpsec.FormLoginDeps{
					Authenticator: NewMockAuthenticator(ctrl), Sessions: sessions,
					Tokens: NewMockGenerator(ctrl), Attempts: w.form,
				}))
			}

			if w.basic != nil {
				opts = append(opts, httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{
					Authenticator: NewMockAuthenticator(ctrl), Attempts: w.basic,
				}))
			}

			_, err = httpsec.New(opts...)
			tc.assert(t, err)
		})
	}
}

// lockoutPolicies widens lockout policies to the policy.Policy values an
// engine takes.
func lockoutPolicies(ps []*lockout.Policy) []policy.Policy {
	out := make([]policy.Policy, 0, len(ps))
	for _, p := range ps {
		out = append(out, p)
	}

	return out
}

// TestWithSessionManager pins which manager the chain records activity
// through: none for a chain no built-in gave one, the explicit one when given,
// whatever the option order and whichever manager a built-in brought.
func TestWithSessionManager(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, f resolveFixture) []httpsec.Option
		assert  func(t *testing.T, f resolveFixture, out served)
	}

	recorded := func(t *testing.T, f resolveFixture, out served) {
		t.Helper()

		require.NoError(t, out.err)

		stored, err := f.sessions.Load(t.Context(), f.session.ID)
		require.NoError(t, err)
		assert.True(t, stored.LastAccessedAt.Equal(f.clk.Now()),
			"activity is recorded through the explicit manager, got %s, want %s",
			stored.LastAccessedAt, f.clk.Now())
	}

	cases := []testCase{
		{
			name: "default: no built-in, no manager, nothing recorded",
			options: func(_ *testing.T, _ resolveFixture) []httpsec.Option {
				return nil
			},
			assert: func(t *testing.T, f resolveFixture, out served) {
				t.Helper()

				require.NoError(t, out.err)

				stored, err := f.sessions.Load(t.Context(), f.session.ID)
				require.NoError(t, err)
				assert.True(t, stored.LastAccessedAt.Before(f.clk.Now()),
					"a chain with no session manager records no activity, got %s", stored.LastAccessedAt)
			},
		},
		{
			name: "explicit manager alone",
			options: func(_ *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(f.sessions)}
			},
			assert: recorded,
		},
		{
			name: "explicit manager before a built-in with another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.WithSessions(f.sessions),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: otherManager(t, f)}),
				}
			},
			assert: recorded,
		},
		{
			name: "explicit manager after a built-in with another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: otherManager(t, f)}),
					httpsec.WithSessions(f.sessions),
				}
			},
			assert: recorded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			opts := append(tc.options(t, f),
				httpsec.RegisterInterceptor(consumerAuthenticating(f, false), httpsec.OrderBearerToken))

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, f, serve(t, chain, bearerRequest(t.Context(), "")))
		})
	}
}

// TestWithSessionManager_MustBeTheBearers pins that an explicit manager other
// than the one a built-in bearer loads sessions from is a configuration error,
// whatever the option order, and that the same manager, or no built-in bearer,
// builds.
//
// Not rows of TestNewRefusesWiring: every case builds on a resolve fixture's manager.
func TestWithSessionManager_MustBeTheBearers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, f resolveFixture) []httpsec.Option
		assert  func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "WithSessions")
		assert.Nil(t, chain)
	}

	built := func(t *testing.T, chain *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, chain)
	}

	signed := func(t *testing.T, m *session.Sessions) httpsec.Option {
		t.Helper()

		ctrl := gomock.NewController(t)

		return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: NewMockVerifier(ctrl), Sessions: m, Users: NewMockUserLoader(ctrl),
		})
	}

	reference := func(t *testing.T, m *session.Sessions) httpsec.Option {
		t.Helper()

		ctrl := gomock.NewController(t)

		return httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: m, Users: NewMockUserLoader(ctrl)})
	}

	cases := []testCase{
		{
			name: "signed-token bearer, explicit manager after, another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{signed(t, f.sessions), httpsec.WithSessions(otherManager(t, f))}
			},
			assert: refused,
		},
		{
			name: "signed-token bearer, explicit manager before, another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(otherManager(t, f)), signed(t, f.sessions)}
			},
			assert: refused,
		},
		{
			name: "session-reference bearer, explicit manager after, another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{reference(t, f.sessions), httpsec.WithSessions(otherManager(t, f))}
			},
			assert: refused,
		},
		{
			name: "session-reference bearer, explicit manager before, another",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(otherManager(t, f)), reference(t, f.sessions)}
			},
			assert: refused,
		},
		{
			name: "signed-token bearer, the same manager",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{signed(t, f.sessions), httpsec.WithSessions(f.sessions)}
			},
			assert: built,
		},
		{
			name: "session-reference bearer, the same manager, manager before bearer",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{httpsec.WithSessions(f.sessions), reference(t, f.sessions)}
			},
			assert: built,
		},
		{
			name: "session-reference bearer, the same manager, bearer before manager",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{reference(t, f.sessions), httpsec.WithSessions(f.sessions)}
			},
			assert: built,
		},
		{
			name: "no built-in bearer, an explicit manager is unchecked",
			options: func(t *testing.T, f resolveFixture) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: f.sessions}),
					httpsec.WithSessions(otherManager(t, f)),
				}
			},
			assert: built,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			chain, err := httpsec.New(tc.options(t, f)...)
			tc.assert(t, chain, err)
		})
	}
}
