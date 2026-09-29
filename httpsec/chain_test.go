package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// errDeepRefusal is what a recording interceptor refuses with, so a test can
// assert the very error it registered is the one the chain's caller receives.
var errDeepRefusal = errors.New("chain_test: refused deep in the chain")

// chainBuilder registers recording interceptors and remembers the order they
// were entered and left in. The trace is mutex-guarded because every frame of
// the assembled fold writes to the one slice, which is what -race is pointed
// at here.
type chainBuilder struct {
	mu      sync.Mutex
	records []string
	opts    []httpsec.Option
}

func newChainBuilder() *chainBuilder { return &chainBuilder{} }

func (b *chainBuilder) record(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.records = append(b.records, name)
}

func (b *chainBuilder) trace() []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return slices.Clone(b.records)
}

// at registers an interceptor that records its name, continues, and records
// again once everything inside it has returned.
func (b *chainBuilder) at(order httpsec.Order, name string) {
	b.register(order, func(ex *httpsec.Exchange, next httpsec.Next) error {
		b.record(name)
		err := next(ex)
		b.record(name + "-after")
		return err
	})
}

// stopAt registers an interceptor that records its name and returns without
// continuing, which must stop the request where it stands.
func (b *chainBuilder) stopAt(order httpsec.Order, name string) {
	b.register(order, func(_ *httpsec.Exchange, _ httpsec.Next) error {
		b.record(name)
		return nil
	})
}

// failAt registers an interceptor that refuses with err without continuing.
func (b *chainBuilder) failAt(order httpsec.Order, name string, err error) {
	b.register(order, func(_ *httpsec.Exchange, _ httpsec.Next) error {
		b.record(name)
		return err
	})
}

func (b *chainBuilder) register(order httpsec.Order, fn httpsec.InterceptorFunc) {
	b.opts = append(b.opts, httpsec.RegisterInterceptor(fn, order))
}

// run assembles the registered interceptors around a terminal that records
// "handler", and passes one exchange through the result.
func (b *chainBuilder) run(t *testing.T) error {
	t.Helper()

	chain, err := httpsec.New(b.opts...)
	require.NoError(t, err)

	run := chain.Assemble(func(_ *httpsec.Exchange) error {
		b.record("handler")
		return nil
	})

	return run(httpsec.NewExchange(t.Context(), stubRequest{}, &stubWriter{}))
}

func TestChainAssemble(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		register func(b *chainBuilder)
		assert   func(t *testing.T, trace []string, err error)
	}

	cases := []testCase{
		{
			name: "ascending slot order, lowest outermost",
			register: func(b *chainBuilder) {
				b.at(500, "five")
				b.at(100, "one")
				b.at(300, "three")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"one", "three", "five", "handler",
					"five-after", "three-after", "one-after",
				}, trace)
			},
		},
		{
			name: "equal slots keep registration order",
			register: func(b *chainBuilder) {
				b.at(400, "first")
				b.at(400, "second")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"first", "second", "handler", "second-after", "first-after",
				}, trace)
			},
		},
		{
			name: "equal slots keep registration order even when a lower slot was registered between them",
			register: func(b *chainBuilder) {
				b.at(400, "first")
				b.at(100, "outer")
				b.at(400, "second")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"outer", "first", "second", "handler",
					"second-after", "first-after", "outer-after",
				}, trace)
			},
		},
		{
			name: "Before and After bracket a named slot",
			register: func(b *chainBuilder) {
				b.at(httpsec.OrderBearerToken, "bearer")
				b.at(httpsec.After(httpsec.OrderBearerToken), "audit")
				b.at(httpsec.Before(httpsec.OrderBearerToken), "pre")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{
					"pre", "bearer", "audit", "handler",
					"audit-after", "bearer-after", "pre-after",
				}, trace)
			},
		},
		{
			name:     "no interceptors leaves the handler reachable",
			register: func(_ *chainBuilder) {},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"handler"}, trace)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newChainBuilder()
			tc.register(b)

			err := b.run(t)
			tc.assert(t, b.trace(), err)
		})
	}
}

func TestChainContinuation(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		register func(b *chainBuilder)
		assert   func(t *testing.T, trace []string, err error)
	}

	cases := []testCase{
		{
			name: "an interceptor that does not continue stops the request",
			register: func(b *chainBuilder) {
				b.at(100, "outer")
				b.stopAt(300, "gate")
				b.at(500, "inner")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"outer", "gate", "outer-after"}, trace)
				assert.NotContains(t, trace, "inner")
				assert.NotContains(t, trace, "handler")
			},
		},
		{
			name: "an error propagates outward unchanged",
			register: func(b *chainBuilder) {
				b.at(100, "outer")
				b.failAt(900, "deep", errDeepRefusal)
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.ErrorIs(t, err, errDeepRefusal)
				assert.Equal(t, []string{"outer", "deep", "outer-after"}, trace)
			},
		},
		{
			name: "the post-handler step runs after the handler returned",
			register: func(b *chainBuilder) {
				b.at(httpsec.OrderSessionTouch, "touch")
			},
			assert: func(t *testing.T, trace []string, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"touch", "handler", "touch-after"}, trace)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := newChainBuilder()
			tc.register(b)

			err := b.run(t)
			tc.assert(t, b.trace(), err)
		})
	}
}

// declaring is a consumer's own challenging policy: it declares the kinds it
// can raise and is asked per request, which is all the assembly check reads.
type declaring struct{ kinds []policy.ChallengeKind }

func (declaring) Name() string                         { return "chain_test: declaring" }
func (declaring) Phases() []policy.Phase               { return []policy.Phase{policy.PerRequest} }
func (d declaring) Challenges() []policy.ChallengeKind { return slices.Clone(d.kinds) }
func (declaring) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Allow}
}

// everyoneRequired is a requirement lookup under which every user must use a
// second factor.
type everyoneRequired struct{}

func (everyoneRequired) Required(context.Context, identity.UserID) (bool, error) { return true, nil }

// silentPolicy declares nothing, so the check reads it as raising nothing.
type silentPolicy struct{}

func (silentPolicy) Name() string           { return "chain_test: silent" }
func (silentPolicy) Phases() []policy.Phase { return []policy.Phase{policy.PerRequest} }
func (silentPolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Allow}
}

// TestUnenforcedChallenges pins that every kind a registered policy declares
// has something on the chain enforcing it. A challenge nothing enforces marks
// the session and serves it anyway, which is a bypass with no symptom, so the
// chain refuses to assemble instead.
func TestUnenforcedChallenges(t *testing.T) {
	t.Parallel()

	const terms policy.ChallengeKind = 100

	passwordAge := func(t *testing.T) policy.Policy {
		t.Helper()

		p, err := policy.NewPasswordAgePolicy()
		require.NoError(t, err)

		return p
	}

	enrolmentPath := func(t *testing.T) policy.Policy {
		t.Helper()

		p, err := policy.NewMFARequirementPolicy(
			everyoneRequired{}, []policy.MFAMethodLookup{enrollableLookup{idleLookup(t)}},
			policy.WithMFAEnrolmentPath())
		require.NoError(t, err)

		return p
	}

	type testCase struct {
		name     string
		policies func(t *testing.T) []policy.Policy
		opts     func(t *testing.T) []httpsec.Option
		assert   func(t *testing.T, c *httpsec.Chain, err error)
	}

	refusedNaming := func(kind string, enforcer string) func(t *testing.T, c *httpsec.Chain, err error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c)
			assert.ErrorContains(t, err, kind, "the error names the kind nothing enforces")
			assert.ErrorContains(t, err, enforcer, "the error names what would enforce it")
		}
	}

	assembles := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	none := func(*testing.T) []httpsec.Option { return nil }

	cases := []testCase{
		{
			name:     "password age without its gate",
			policies: func(t *testing.T) []policy.Policy { return []policy.Policy{passwordAge(t)} },
			opts:     none,
			assert:   refusedNaming("ChallengePasswordChange", "EnablePasswordChangeGate"),
		},
		{
			name:     "password age with its gate",
			policies: func(t *testing.T) []policy.Policy { return []policy.Policy{passwordAge(t)} },
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				m, err := session.NewManager()
				require.NoError(t, err)

				return []httpsec.Option{httpsec.EnablePasswordChangeGate(m)}
			},
			assert: assembles,
		},
		{
			name: "second-factor policy without its interceptor",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				p, err := policy.NewMFAPolicy([]policy.MFAMethodLookup{idleLookup(t)})
				require.NoError(t, err)

				return []policy.Policy{p}
			},
			opts:   none,
			assert: refusedNaming("ChallengeMFA", "EnableMFA"),
		},
		{
			name:     "enrolment path with the second factor but no enrolment interceptor",
			policies: func(t *testing.T) []policy.Policy { return []policy.Policy{enrolmentPath(t)} },
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{enableMFAFor(t)}
			},
			assert: refusedNaming("ChallengeMFAEnrolment", "EnableMFAEnrolment"),
		},
		{
			name:     "a consumer interceptor at Before(OrderMFAChallenge) is not the enrolment enforcer",
			policies: func(t *testing.T) []policy.Policy { return []policy.Policy{enrolmentPath(t)} },
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					enableMFAFor(t),
					passThroughAt(httpsec.Before(httpsec.OrderMFAChallenge)),
				}
			},
			assert: refusedNaming("ChallengeMFAEnrolment", "EnableMFAEnrolment"),
		},
		{
			name:     "enrolment path with the enrolment gate enabled",
			policies: func(t *testing.T) []policy.Policy { return []policy.Policy{enrolmentPath(t)} },
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					enableMFAFor(t),
					httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
				}
			},
			assert: assembles,
		},
		{
			name: "a consumer interceptor at OrderMFAChallenge is not the second-factor enforcer",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				p, err := policy.NewMFAPolicy([]policy.MFAMethodLookup{idleLookup(t)})
				require.NoError(t, err)

				return []policy.Policy{p}
			},
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{passThroughAt(httpsec.OrderMFAChallenge)}
			},
			assert: refusedNaming("ChallengeMFA", "EnableMFA"),
		},
		{
			name:     "a consumer interceptor at OrderPasswordChange is not the password-change enforcer",
			policies: func(t *testing.T) []policy.Policy { return []policy.Policy{passwordAge(t)} },
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{passThroughAt(httpsec.OrderPasswordChange)}
			},
			assert: refusedNaming("ChallengePasswordChange", "EnablePasswordChangeGate"),
		},
		{
			name: "a consumer kind declared",
			policies: func(*testing.T) []policy.Policy {
				return []policy.Policy{declaring{kinds: []policy.ChallengeKind{terms}}}
			},
			opts: func(*testing.T) []httpsec.Option {
				return []httpsec.Option{httpsec.WithChallengeEnforcer(terms)}
			},
			assert: assembles,
		},
		{
			name: "a consumer kind undeclared",
			policies: func(*testing.T) []policy.Policy {
				return []policy.Policy{declaring{kinds: []policy.ChallengeKind{terms}}}
			},
			opts:   none,
			assert: refusedNaming("ChallengeKind(100)", "WithChallengeEnforcer"),
		},
		{
			name:     "a policy declaring nothing",
			policies: func(*testing.T) []policy.Policy { return []policy.Policy{silentPolicy{}} },
			opts:     none,
			assert:   assembles,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := append([]httpsec.Option{
				chainSessions(t),
				httpsec.WithPolicyEngine(engineOf(t, tc.policies(t)...)),
			}, tc.opts(t)...)

			c, err := httpsec.New(opts...)
			tc.assert(t, c, err)
		})
	}
}

// TestWithChallengeEnforcer pins what the option refuses. A built-in kind is
// enforced only by its own built-in gate, so declaring one by hand could only
// ever silence the check for it; and ChallengeNone is not a challenge.
func TestWithChallengeEnforcer(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		kind   policy.ChallengeKind
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.ErrorContains(t, err, "WithChallengeEnforcer")
	}

	cases := []testCase{
		{name: "ChallengeNone", kind: policy.ChallengeNone, assert: refused},
		{name: "the built-in second factor", kind: policy.ChallengeMFA, assert: refused},
		{name: "the built-in password change", kind: policy.ChallengePasswordChange, assert: refused},
		{name: "the built-in enrolment", kind: policy.ChallengeMFAEnrolment, assert: refused},
		{
			name: "a consumer kind",
			kind: policy.ChallengeKind(100),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(httpsec.WithChallengeEnforcer(tc.kind))
			tc.assert(t, err)
		})
	}
}

// passThroughAt occupies the slot at with an interceptor that only passes the
// request on. It does not make the slot's challenge kind count as enforced —
// only the built-in gate does, which is what the rows using it pin; a test
// that needs the kind enforced records the gate with EnableGateForTest.
func passThroughAt(at httpsec.Order) httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(
		func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) }), at)
}

// raisingDeclared is a policy that declares kind and raises it in phase, the
// shape of a policy the assembly check would have refused had it been
// registered in time.
type raisingDeclared struct {
	kind  policy.ChallengeKind
	phase policy.Phase
}

func (raisingDeclared) Name() string                         { return "chain_test: raising declared" }
func (r raisingDeclared) Phases() []policy.Phase             { return []policy.Phase{r.phase} }
func (r raisingDeclared) Challenges() []policy.ChallengeKind { return []policy.ChallengeKind{r.kind} }
func (r raisingDeclared) Evaluate(context.Context, *policy.Input) policy.Decision {
	return policy.Decision{Outcome: policy.Challenge, Challenge: r.kind}
}

// TestUnenforcedChallengeAtRuntime pins the runtime half of the enforcer
// check. A policy added to the engine after the chain was built escapes the
// assembly check, so a challenge it raises that nothing on the chain enforces
// refuses the request with a configuration error: the session is not marked,
// and the handler does not run.
func TestUnenforcedChallengeAtRuntime(t *testing.T) {
	t.Parallel()

	const terms policy.ChallengeKind = 100

	type testCase struct {
		name  string
		phase policy.Phase

		// kind is what the late policy raises; zero means the password-change
		// challenge, whose gate no case enables.
		kind policy.ChallengeKind

		wire    func(t *testing.T, h *authHarness, stored *session.Session)
		options func(h *authHarness) []httpsec.Option
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, out served, stored *session.Session)
	}

	refusedNaming := func(t *testing.T, out served, kind string) {
		t.Helper()

		require.ErrorIs(t, out.err, httpsec.ErrConfig)
		assert.ErrorContains(t, out.err, kind, "the error names the kind")
		assert.False(t, out.handlerRan, "the handler does not run")

		var ch *httpsec.ChallengeError
		assert.NotErrorAs(t, out.err, &ch, "the refusal is not a challenge the caller could answer")
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err),
			"a wiring fault is the server's, never a refusal of the caller's credentials")
	}

	refused := func(t *testing.T, out served) {
		t.Helper()

		refusedNaming(t, out, "ChallengePasswordChange")
	}

	loginTail := func(_ *testing.T, h *authHarness, _ *session.Session) {
		h.expectAuthenticated(testPrincipal())
		h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
		// No expectation on the store or the generator: no session is
		// opened, so none is marked, and no token is issued.
	}

	// preAuthentication expects nothing at all: the refusal comes before the
	// credential is checked, so the authenticator is never asked.
	preAuthentication := func(*testing.T, *authHarness, *session.Session) {}

	bearer := func(_ *testing.T, h *authHarness, stored *session.Session) {
		h.expectVerified()
		h.store.EXPECT().Load(gomock.Any(), testJTI).Return(stored, nil)
		h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
		// The session touch may write back the activity of a request
		// that carried a session; what matters is what it wrote.
		h.acceptsActivityWriteBack()
	}

	formLogin := func(h *authHarness) []httpsec.Option {
		return []httpsec.Option{httpsec.EnableFormLogin(h.formLoginDeps())}
	}

	bearerOn := func(more ...httpsec.Option) func(h *authHarness) []httpsec.Option {
		return func(h *authHarness) []httpsec.Option {
			return append([]httpsec.Option{httpsec.EnableBearerToken(h.bearerTokenDeps())}, more...)
		}
	}

	loginRequest := func(ctx context.Context) *http.Request {
		return formRequest(ctx, "/login", "username=ada&password=s3cret")
	}

	bearerReq := func(ctx context.Context) *http.Request {
		return bearerRequest(ctx, "Bearer abc.def.ghi")
	}

	cases := []testCase{
		{
			name:    "a login tail",
			phase:   policy.PostAuthentication,
			wire:    loginTail,
			options: formLogin,
			request: loginRequest,
			assert: func(t *testing.T, out served, _ *session.Session) {
				t.Helper()

				refused(t, out)
			},
		},
		{
			name:    "a form login before the credential is checked",
			phase:   policy.PreAuthentication,
			wire:    preAuthentication,
			options: formLogin,
			request: loginRequest,
			assert: func(t *testing.T, out served, _ *session.Session) {
				t.Helper()

				refused(t, out)
			},
		},
		{
			name:  "a basic credential before it is checked",
			phase: policy.PreAuthentication,
			wire:  preAuthentication,
			options: func(h *authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableBasicAuth(h.basicAuthDeps())}
			},
			request: func(ctx context.Context) *http.Request {
				return basicRequest(ctx, "ada", "s3cret")
			},
			assert: func(t *testing.T, out served, _ *session.Session) {
				t.Helper()

				refused(t, out)
			},
		},
		{
			name:    "a bearer request",
			phase:   policy.PerRequest,
			wire:    bearer,
			options: bearerOn(),
			request: bearerReq,
			assert: func(t *testing.T, out served, stored *session.Session) {
				t.Helper()

				refused(t, out)
				assert.False(t, stored.PasswordChangePending, "the session is not marked")
			},
		},
		{
			name:    "an enrolment challenge with only an interceptor at the enrolment slot",
			phase:   policy.PerRequest,
			kind:    policy.ChallengeMFAEnrolment,
			wire:    bearer,
			options: bearerOn(passThroughAt(httpsec.OrderMFAEnrolment)),
			request: bearerReq,
			assert: func(t *testing.T, out served, stored *session.Session) {
				t.Helper()

				refusedNaming(t, out, "ChallengeMFAEnrolment")
				assert.NotEqual(t, session.MFAEnrolmentPending, stored.MFA, "the session is not marked")
			},
		},
		{
			name:    "a consumer kind nobody declared",
			phase:   policy.PerRequest,
			kind:    terms,
			wire:    bearer,
			options: bearerOn(),
			request: bearerReq,
			assert: func(t *testing.T, out served, _ *session.Session) {
				t.Helper()

				refusedNaming(t, out, "ChallengeKind(100)")
				assert.ErrorContains(t, out.err, "WithChallengeEnforcer", "the error names the remedy")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			stored := liveSession()
			tc.wire(t, h, stored)

			e := engineOf(t)
			chain, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.WithPolicyEngine(e),
			}, tc.options(h)...)...)
			require.NoError(t, err, "an empty engine raises nothing, so the chain assembles")

			kind := tc.kind
			if kind == policy.ChallengeNone {
				kind = policy.ChallengePasswordChange
			}

			// Added after the chain was built, so the assembly check never saw it.
			require.NoError(t, e.Add(raisingDeclared{kind: kind, phase: tc.phase}))

			tc.assert(t, serve(t, chain, tc.request(t.Context())), stored)
		})
	}
}

// TestUnenforcedChallengeAtRedemption pins that a redemption flow refuses an
// unenforced challenge inside its own policy check, before the one-time
// credential is spent: a user whose login the chain cannot complete keeps the
// link or the handoff code, rather than losing it to a refusal that was never
// theirs.
func TestUnenforcedChallengeAtRedemption(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// redeem builds the flow's chain on e, has late add the unenforced
		// policy once the chain exists, redeems one credential, and returns
		// what that produced along with a check that the credential was not
		// spent.
		redeem func(t *testing.T, e *policy.Engine, late func()) (served, func(t *testing.T))
	}

	cases := []testCase{
		{
			name: "a magic link",
			redeem: func(t *testing.T, e *policy.Engine, late func()) (served, func(t *testing.T)) {
				t.Helper()

				h := newMagicLinkHarness(t)
				token, nonce := h.link(t, h.chain(t))

				h.engine = e
				c := h.chain(t)
				late()

				out := h.redeem(t, c, token, nonce)

				return out, func(t *testing.T) {
					t.Helper()

					assert.Zero(t, h.activeSessions(t), "no session is established")

					h.engine = nil
					again := h.redeem(t, h.chain(t), token, nonce)
					require.NoError(t, again.err, "the link was not spent")
				}
			},
		},
		{
			name: "an OIDC handoff",
			redeem: func(t *testing.T, e *policy.Engine, late func()) (served, func(t *testing.T)) {
				t.Helper()

				h := newOIDCHarness(t)
				h.issueTokens()
				h.chainOpts = []httpsec.Option{httpsec.WithPolicyEngine(e)}

				code := h.issueHandoff(t, "")
				c := h.chain(t)
				late()

				out := serve(t, c, handoffRequest(t.Context(), oidcTestSource, code))

				return out, func(t *testing.T) {
					t.Helper()

					assert.Zero(t, h.activeSessions(t), "no session is established")
					requireRedeemable(t, h, code)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			e := engineOf(t)
			out, unspent := tc.redeem(t, e, func() {
				// Added after the chain was built, so the assembly check never
				// saw it.
				require.NoError(t, e.Add(raisingDeclared{
					kind: policy.ChallengePasswordChange, phase: policy.PostAuthentication,
				}))
			})

			require.ErrorIs(t, out.err, httpsec.ErrConfig)
			assert.ErrorContains(t, out.err, "ChallengePasswordChange", "the error names the kind")
			assert.False(t, out.handlerRan)
			unspent(t)
		})
	}
}
