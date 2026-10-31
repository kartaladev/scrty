package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/logsample"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// The summary records each component besides the chain (summaryChain) writes
// when a flush reports what it held back. A row reads its own component's
// summaries by these, so a row passes only when the flush reached that
// component, not merely some sampler.
const (
	summaryThrottle  = "mfa: verification refusals suppressed"
	summaryAuthn     = "authentication refusals suppressed"
	summaryOIDC      = "oidc refusals suppressed"
	summaryHandoff   = "oidc handoff refusals suppressed"
	summaryMFAPolicy = "policy: second-factor records suppressed"
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

		p, err := policy.NewPasswordAge()
		require.NoError(t, err)

		return p
	}

	enrolmentPath := func(t *testing.T) policy.Policy {
		t.Helper()

		p, err := policy.NewMFARequirement(
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

				m, err := session.New()
				require.NoError(t, err)

				return []httpsec.Option{httpsec.EnablePasswordChangeGate(m)}
			},
			assert: assembles,
		},
		{
			name: "second-factor policy without its interceptor",
			policies: func(t *testing.T) []policy.Policy {
				t.Helper()

				p, err := policy.NewMFA([]policy.MFAMethodLookup{idleLookup(t)})
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

				p, err := policy.NewMFA([]policy.MFAMethodLookup{idleLookup(t)})
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
			name: "the recovery gate's own kind",
			kind: policy.ChallengeAccountRecovery,
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.ErrorContains(t, err, "only the recovery gate raises",
					"the refusal says no policy may raise the kind, not that a gate is missing")
			},
		},
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
			// Only the recovery gate raises this kind, and only on a
			// recovery-pending session. Raised by a policy on an ordinary
			// session, nothing would confine it, so it is refused rather than
			// served.
			name:    "the account-recovery kind, with the recovery gate on",
			phase:   policy.PerRequest,
			kind:    policy.ChallengeAccountRecovery,
			wire:    bearer,
			options: bearerOn(httpsec.EnableRecoveryGateForTest()),
			request: bearerReq,
			assert: func(t *testing.T, out served, _ *session.Session) {
				t.Helper()

				refusedNaming(t, out, "ChallengeAccountRecovery")
				assert.ErrorContains(t, out.err, "only the recovery gate raises", "the error names the reason")
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

// mfaChallengingEngine is an engine holding the library's own second-factor
// policy, which declares that it can raise the challenge.
func mfaChallengingEngine(t *testing.T) *policy.Engine {
	t.Helper()

	p, err := policy.NewMFA([]policy.MFAMethodLookup{idleLookup(t)})
	require.NoError(t, err)

	return engineOf(t, p)
}

// idleLookup is a method lookup no case expects to be asked about a user: only
// its name may be read, which is what a policy constructor does.
func idleLookup(t *testing.T) *MockMFAMethodLookup {
	t.Helper()

	lookup := NewMockMFAMethodLookup(gomock.NewController(t))
	lookup.EXPECT().Name().Return("totp").AnyTimes()

	return lookup
}

// passwordChangeChallengingEngine holds a policy that can challenge, but for
// something the MFA interceptor has nothing to do with.
func passwordChangeChallengingEngine(t *testing.T) *policy.Engine {
	t.Helper()

	p, err := policy.NewPasswordAge()
	require.NoError(t, err)

	return engineOf(t, p)
}

// passwordChangeGateFor is the password-change gate wired to a session manager
// of its own, which is what a chain registering the password-age policy must
// also enable for that policy's challenge to be enforced.
func passwordChangeGateFor(t *testing.T) httpsec.Option {
	t.Helper()

	m, err := session.New()
	require.NoError(t, err)

	return httpsec.EnablePasswordChangeGate(m)
}

// chainSessions is a session manager for a chain that needs one, supplied
// through a built-in as a deployment would.
func chainSessions(t *testing.T) httpsec.Option {
	t.Helper()

	m, err := session.New()
	require.NoError(t, err)

	return httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: m})
}

// TestChainRefusesUnenforcedMFAChallenge pins the refusal http-security
// flagged and could not enforce itself.
//
// The per-request phase marks a second-factor challenge pending and continues,
// because the gate is what enforces it and the verify endpoint must stay
// reachable. With no gate, every challenged session is marked and served
// anyway: the caller goes on with an unsatisfied second factor and nothing in
// the request path says so. That silence is why this is a construction error.
//
// Not rows of TestUnenforcedChallenges: each case brings its own policy engine as an option.
func TestChainRefusesUnenforcedMFAChallenge(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	assembles := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	cases := []testCase{
		{
			name: "a policy that can challenge for MFA with no interceptor",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.WithPolicyEngine(mfaChallengingEngine(t))}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, strings.ToLower(err.Error()), "enablemfa",
					"the error names what is missing")
			},
		},
		{
			name: "the same policy with EnableMFA",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithPolicyEngine(mfaChallengingEngine(t)),
					enableMFAFor(t),
				}
			},
			assert: assembles,
		},
		{
			// Occupying the slot is not enforcing the challenge: the chain
			// cannot tell what a consumer's interceptor does there, so only
			// the built-in gate counts.
			name: "the same policy with a consumer's own interceptor at the slot",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				passes := httpsec.InterceptorFunc(
					func(ex *httpsec.Exchange, next httpsec.Next) error { return next(ex) })

				return []httpsec.Option{
					httpsec.WithPolicyEngine(mfaChallengingEngine(t)),
					httpsec.RegisterInterceptor(passes, httpsec.OrderMFAChallenge),
				}
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				t.Helper()

				require.ErrorIs(t, err, httpsec.ErrConfig)
				assert.Nil(t, c)
				assert.Contains(t, strings.ToLower(err.Error()), "enablemfa",
					"the error names the gate that would enforce it")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(append([]httpsec.Option{chainSessions(t)}, tc.opts(t)...)...)
			tc.assert(t, c, err)
		})
	}
}

// TestChainMFAChallengeRefusalScope pins that the refusal does not fire where
// it should not. A check that refuses working deployments is one consumers
// learn to route around.
func TestChainMFAChallengeRefusalScope(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts func(t *testing.T) []httpsec.Option
	}

	cases := []testCase{
		{
			// Its own gate is enabled, because a chain that raises a password
			// change nothing enforces is refused on that account; what is
			// pinned here is that the second-factor refusal does not fire too.
			name: "a policy that can only challenge for a password change",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithPolicyEngine(passwordChangeChallengingEngine(t)),
					passwordChangeGateFor(t),
				}
			},
		},
		{
			name: "no policy at all",
			opts: func(*testing.T) []httpsec.Option { return nil },
		},
		{
			name: "an engine holding no policies",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{httpsec.WithPolicyEngine(engineOf(t))}
			},
		},
		{
			// Enforcing a challenge nothing raises is harmless: the gate never
			// fires. Only the other direction is a hole.
			name: "EnableMFA without an MFA policy",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{enableMFAFor(t)}
			},
		},
		{
			name: "a policy that challenges for a password change, with EnableMFA",
			opts: func(t *testing.T) []httpsec.Option {
				t.Helper()

				return []httpsec.Option{
					httpsec.WithPolicyEngine(passwordChangeChallengingEngine(t)),
					passwordChangeGateFor(t),
					enableMFAFor(t),
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := httpsec.New(append([]httpsec.Option{chainSessions(t)}, tc.opts(t)...)...)

			require.NoError(t, err)
			assert.NotNil(t, c)
		})
	}
}

// compile-time proof that the method double these cases use is a real method.
var _ mfa.Method = (*MockMethod)(nil)

// namedChallengeStubs returns challenge methods with the given names, each
// one the user is enrolled on.
func namedChallengeStubs(names ...string) []mfa.Method {
	methods := make([]mfa.Method, 0, len(names))
	for _, name := range names {
		stub := newChallengeStub()
		stub.name = name
		methods = append(methods, stub)
	}

	return methods
}

// expiryMFAHarness is the MFA harness with its TOTP method double wired for a
// chain that begins challenges and verifies nothing, configured after it with
// extra.
func expiryMFAHarness(t *testing.T, extra ...mfa.Method) *mfaHarness {
	t.Helper()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
	h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).Return(false, nil).AnyTimes()
	h.extra = extra

	return h
}

// expiryRecoveryHarness is the recovery harness, whose core and default stores
// share its fake clock, with MFA over methods when there are any.
func expiryRecoveryHarness(t *testing.T, methods ...mfa.Method) *recoveryHarness {
	t.Helper()

	h := newRecoveryHarness(t)

	if len(methods) > 0 {
		h.chainOpts = append(h.chainOpts, httpsec.EnableMFA(methods, httpsec.WithMFATokens(h.tokens)))
	}

	return h
}

// TestChain_ExpiryTasks pins which tasks a chain returns for the one-time state
// of the components it builds, and that each task sweeps the state those
// components issued while serving requests, not a copy of it.
//
// Every case moves time on its harness's fake clock, which the chain reads
// through WithClock.
func TestChain_ExpiryTasks(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// chain builds the chain and issues, through it, whatever the case
		// sweeps.
		chain  func(t *testing.T) *httpsec.Chain
		assert func(t *testing.T, tasks []expiry.Task)
	}

	cases := []testCase{
		{
			name:  "nothing enabled gives no tasks",
			chain: func(t *testing.T) *httpsec.Chain { c, err := httpsec.New(); require.NoError(t, err); return c },
			assert: func(t *testing.T, tasks []expiry.Task) {
				require.NotNil(t, tasks)
				assert.Empty(t, tasks)

				_, err := expiry.NewRunner(tasks)
				require.ErrorIs(t, err, expiry.ErrNoTasks)
			},
		},
		{
			// A method with no begin step keeps no pending challenge, so
			// there is nothing of it to sweep.
			name:  "a method with no challenge step contributes no task",
			chain: func(t *testing.T) *httpsec.Chain { return expiryMFAHarness(t).bearerChain(t) },
			assert: func(t *testing.T, tasks []expiry.Task) {
				require.NotNil(t, tasks)
				assert.Empty(t, tasks)
			},
		},
		{
			name: "a challenge method contributes its task and recovery none",
			chain: func(t *testing.T) *httpsec.Chain {
				return expiryMFAHarness(t, namedChallengeStubs("passkey")...).bearerChain(t)
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				assert.Equal(t, []string{"mfa-challenges:passkey"}, expiryTaskNames(tasks))
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
				}
			},
		},
		{
			name: "challenge methods come in their configured order",
			chain: func(t *testing.T) *httpsec.Chain {
				return expiryMFAHarness(t, namedChallengeStubs("zeta", "alpha", "mid", "beta", "omega", "kappa")...).bearerChain(t)
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				assert.Equal(t, []string{
					"mfa-challenges:zeta", "mfa-challenges:alpha", "mfa-challenges:mid",
					"mfa-challenges:beta", "mfa-challenges:omega", "mfa-challenges:kappa",
				}, expiryTaskNames(tasks))
			},
		},
		{
			name:  "recovery without holds contributes its issued-code task",
			chain: func(t *testing.T) *httpsec.Chain { return expiryRecoveryHarness(t).build(t).chain },
			assert: func(t *testing.T, tasks []expiry.Task) {
				assert.Equal(t, []string{"recovery-issued-codes"}, expiryTaskNames(tasks))
			},
		},
		{
			name: "MFA tasks come before the recovery tasks",
			chain: func(t *testing.T) *httpsec.Chain {
				h := expiryRecoveryHarness(t, namedChallengeStubs("passkey")...)
				h.withHold()

				return h.build(t).chain
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				assert.Equal(t, []string{
					"mfa-challenges:passkey",
					"recovery-issued-codes", "recovery-finish-tokens", "recovery-cancel-tokens",
				}, expiryTaskNames(tasks))
				for _, task := range tasks {
					assert.Zero(t, task.Interval, task.Name)
				}
			},
		},
		{
			name: "the MFA task sweeps a challenge begun through the chain",
			chain: func(t *testing.T) *httpsec.Chain {
				h := expiryMFAHarness(t, namedChallengeStubs("passkey")...)
				c := h.bearerChain(t)
				s := h.pendingSession(t, factor.Password)

				out := serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID)))
				require.NoError(t, out.err)
				require.Equal(t, http.StatusOK, out.rec.Code, "the begin issued a challenge")

				// Past the challenge's lifetime and the hour-long issuance
				// window, with no begin since to sweep it inline.
				h.clock.Advance(httpsec.DefaultMFAChallengeTTL + time.Hour + time.Second)

				return c
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				removed, err := runExpiryTask(t, tasks, "mfa-challenges:passkey")
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "the issued-code task sweeps a code a start issued through the chain",
			chain: func(t *testing.T) *httpsec.Chain {
				h := expiryRecoveryHarness(t).build(t)
				h.issued(t)
				// Past the code's lifetime and the hour-long issuance window.
				h.clock.Advance(2 * time.Hour)

				return h.chain
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				removed, err := runExpiryTask(t, tasks, "recovery-issued-codes")
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
			},
		},
		{
			name: "the hold token tasks sweep the tokens of a hold made through the chain",
			chain: func(t *testing.T) *httpsec.Chain {
				h := expiryRecoveryHarness(t)
				h.withHold()
				h.build(t).hold(t)
				// Past the hold, its 24-hour completion window and the
				// issuance window.
				h.clock.Advance(recoveryHoldDelay + 26*time.Hour)

				return h.chain
			},
			assert: func(t *testing.T, tasks []expiry.Task) {
				for _, name := range []string{"recovery-finish-tokens", "recovery-cancel-tokens"} {
					removed, err := runExpiryTask(t, tasks, name)
					require.NoError(t, err)
					assert.Equal(t, 1, removed, name)
				}
			},
		},
	}

	for _, tc := range cases {
		run := func(t *testing.T) {
			tc.assert(t, tc.chain(t).ExpiryTasks())
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			run(t)
		})
	}
}

// refusingAuthenticator is the library's password authenticator over a user
// store that knows nobody, logging through log under a window no test outlives.
// It has already refused three logins, so it holds two suppressed refusals.
func refusingAuthenticator(t *testing.T, log *slog.Logger) authenticate.Authenticator {
	t.Helper()

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).
		Return(nil, identity.ErrUserNotFound).AnyTimes()

	authn, err := authenticate.NewUsernamePasswordAuthenticator(users,
		authenticate.WithPasswordLogger(log),
		authenticate.WithPasswordLogInterval(time.Hour))
	require.NoError(t, err)

	for range 3 {
		_, err := authn.Authenticate(t.Context(), identity.NewUsernamePassword("nobody", []byte("wrong")))
		require.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
	}

	return authn
}

// flushOIDCRegistry registers testOIDCProvider with pinned endpoints, so
// nothing built over it sends a request.
func flushOIDCRegistry(t *testing.T) *oidc.Registry {
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

	return registry
}

// oidcChain builds a chain with federated login over m and handoffs, logging
// through log, with a session manager and token generator no row exercises.
func oidcChain(
	t *testing.T,
	log *slog.Logger,
	m *oidc.RelyingParty,
	handoffs *oidc.Handoff,
	opts ...httpsec.OIDCOption,
) *httpsec.Chain {
	t.Helper()

	sessions, err := session.New()
	require.NoError(t, err)

	base := []httpsec.OIDCOption{httpsec.WithOIDCSessions(sessions)}
	if handoffs != nil {
		base = append(base, httpsec.WithOIDCTokens(NewMockGenerator(gomock.NewController(t))))
	}

	c, err := httpsec.New(
		httpsec.WithLogger(log),
		httpsec.EnableOIDCLogin(m, handoffs, append(base, opts...)...),
	)
	require.NoError(t, err)

	return c
}

// redeemGarbage posts a malformed handoff code to c from flushSource n times.
func redeemGarbage(t *testing.T, c *httpsec.Chain, n int) {
	t.Helper()

	for range n {
		out := serve(t, c, handoffRequest(t.Context(), flushSource, "not-a-code"))
		require.Error(t, out.err)
	}
}

// TestFlushRefusalLogsReachesComponents pins spec http-security-chain "Chain
// refusal logs are sampled and summarised", scenarios "One flush reaches the
// components" and "Registered policy flushed": one FlushRefusalLogs call
// reports what every component the chain holds is still holding back, each
// through its own reporter.
//
// Every row drives one component until it has suppressed records under a
// window no test outlives, then flushes the chains it built, once each, and
// reads the summaries that flush alone wrote.
func TestFlushRefusalLogsReachesComponents(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// arrange builds the chains under test, every one logging through
		// log, and leaves the row's component holding suppressed records.
		arrange func(t *testing.T, log *slog.Logger) []*httpsec.Chain

		// assert reads the records the flush wrote, and nothing earlier.
		assert func(t *testing.T, flushed []slog.Record)
	}

	cases := []testCase{
		{
			name: "the chain's own sampler",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newAPIKeyHarness(t)

				c, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableAPIKey(h.keys))
				require.NoError(t, err)

				// A request with no client address is refused by the chain
				// itself, before any guard is asked, under the chain's own
				// sampler key for the flow and the reason.
				for range 3 {
					out := h.withKey(t, c, "", h.valid)
					require.Error(t, out.err)
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2},
					summaries(t, flushed, summaryChain, "key", "api-key|no-client-address"))
			},
		},
		{
			name: "the verification throttle EnableMFA built",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
				h.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).Times(3)

				s := h.pendingSession(t, factor.Password)

				c, err := httpsec.New(
					httpsec.WithLogger(log),
					h.carries(s),
					httpsec.EnableMFA([]mfa.Method{h.method},
						httpsec.WithMFAVerifyLimiter(h.limiter),
						httpsec.WithMFATokens(h.tokens),
						httpsec.WithMFALogInterval(time.Hour)),
					httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
				)
				require.NoError(t, err)

				for range 3 {
					out := serve(t, c, postCode(t.Context(), testMFAVerifyPath))
					require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryThrottle, "", ""))
			},
		},
		{
			name: "a source guard the chain built over its default limiter",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				c := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
					httpsec.WithOIDCHandoffRateLimit(1, time.Hour))

				// The first failure spends the allowance; the three after it
				// are throttled, one written and two held back.
				redeemGarbage(t, c, 4)

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "oidc.handoff"))
			},
		},
		{
			name: "a source guard over a consumer-supplied limiter",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				c := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
					httpsec.WithOIDCHandoffLimiter(exceededLimiter(t)))
				redeemGarbage(t, c, 3)

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "oidc.handoff"))
			},
		},
		{
			name: "the API key source guard",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newAPIKeyHarness(t)

				c, err := httpsec.New(
					httpsec.WithLogger(log),
					httpsec.EnableAPIKey(h.keys, httpsec.WithAPIKeyLimiter(exceededLimiter(t))),
				)
				require.NoError(t, err)

				for range 3 {
					// A throttled source is refused with the same error as a
					// wrong key, so the refusal itself is all a row can see.
					out := h.withKey(t, c, flushSource, h.valid)
					require.Error(t, out.err)
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "api-key"))
			},
		},
		{
			name: "the magic-link source guard",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newMagicLinkHarness(t)
				h.linkOpts = []httpsec.MagicLinkOption{httpsec.WithMagicLinkLimiter(exceededLimiter(t))}
				h.chainOpts = []httpsec.Option{httpsec.WithLogger(log)}
				c := h.chain(t)

				for range 3 {
					out := h.redeemFrom(t, c, flushSource, "not-a-token", "")
					require.Error(t, out.err)
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "magic-link-redeem"))
			},
		},
		{
			// Review Focus 4: a limiter the consumer shares between two
			// chains shares its counts, never the guards' samplers, so both
			// chains flushing reports the pending count once.
			name: "a consumer limiter shared by two chains, both flushed",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				shared := exceededLimiter(t)
				a := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
					httpsec.WithOIDCHandoffLimiter(shared))
				b := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
					httpsec.WithOIDCHandoffLimiter(shared))
				redeemGarbage(t, a, 3)

				return []*httpsec.Chain{a, b}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "oidc.handoff"),
					"the pending count was reported other than exactly once")
			},
		},
		{
			name: "the password authenticator of form login",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newAuthHarness(t)
				deps := h.formLoginDeps()
				deps.Authenticator = refusingAuthenticator(t, log)

				c, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableFormLogin(deps))
				require.NoError(t, err)

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryAuthn, "", ""))
			},
		},
		{
			name: "the password authenticator of basic authentication",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				h := newAuthHarness(t)
				deps := h.basicAuthDeps()
				deps.Authenticator = refusingAuthenticator(t, log)

				c, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableBasicAuth(deps))
				require.NoError(t, err)

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryAuthn, "", ""))
			},
		},
		{
			// Review Focus 4 again, for a component the consumer hands to
			// two chains: each chain reaches it, and the second flush finds
			// nothing new pending.
			name: "one authenticator given to two chains, both flushed",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				authn := refusingAuthenticator(t, log)

				login := newAuthHarness(t).formLoginDeps()
				login.Authenticator = authn
				a, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableFormLogin(login))
				require.NoError(t, err)

				basic := newAuthHarness(t).basicAuthDeps()
				basic.Authenticator = authn
				b, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableBasicAuth(basic))
				require.NoError(t, err)

				return []*httpsec.Chain{a, b}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryAuthn, "", ""),
					"the pending count was reported other than exactly once")
			},
		},
		{
			name: "a policy registered on the chain's engine",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				// A magic-link login whose only second factor arrives by email
				// is two factors on one channel, so the policy refuses it.
				method := NewMockMFAMethodLookup(gomock.NewController(t))
				method.EXPECT().Name().Return("email-code").AnyTimes()
				method.EXPECT().Channel().Return(factor.Email).AnyTimes()
				method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				p, err := policy.NewMFA([]policy.MFAMethodLookup{method},
					policy.WithMFALogger(log),
					policy.WithMFALogInterval(time.Hour))
				require.NoError(t, err)

				engine, err := policy.NewEngine(p)
				require.NoError(t, err)

				c, err := httpsec.New(
					httpsec.WithLogger(log),
					httpsec.WithPolicyEngine(engine),
					httpsec.EnableGateForTest(policy.ChallengeMFA),
				)
				require.NoError(t, err)

				login := &policy.Input{User: "u-1", FirstFactor: factor.MagicLink, Now: time.Now()}
				for range 3 {
					d := engine.EvaluatePhase(t.Context(), policy.PostAuthentication, login)
					require.Equal(t, policy.Deny, d.Outcome, "the policy under test stopped refusing")
				}

				return []*httpsec.Chain{c}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryMFAPolicy, "", ""))
			},
		},
		{
			name: "the OIDC manager given to EnableOIDCLogin",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				// A flow-store fault is a refusal the manager samples itself.
				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, errFlushFlowFault).Times(3)

				m, err := oidc.NewRelyingParty(flushOIDCRegistry(t),
					NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows), oidc.WithLogger(log))
				require.NoError(t, err)

				for range 3 {
					_, err := m.Callback(t.Context(), testOIDCProvider, "the-code", "the-state", "the-handle")
					require.Error(t, err)
				}

				return []*httpsec.Chain{oidcChain(t, log, m, newTestHandoffManager(t))}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryOIDC, "", ""))
			},
		},
		{
			name: "the OIDC handoff manager given to EnableOIDCLogin",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(),
					NewMockUserLoader(gomock.NewController(t)), oidc.WithHandoffLogger(log))
				require.NoError(t, err)

				for range 3 {
					_, err := handoffs.Redeem(t.Context(), "not-a-code")
					require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
				}

				return []*httpsec.Chain{oidcChain(t, log, newTestOIDCManager(t), handoffs)}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryHandoff, "", ""))
			},
		},
		{
			// Review Focus 5: a login conveyed by WithOIDCCallbackSuccess has no
			// handoff manager and no redemption guard to flush; the manager
			// is still reached.
			name: "an OIDC chain with WithOIDCCallbackSuccess and no handoff manager",
			arrange: func(t *testing.T, log *slog.Logger) []*httpsec.Chain {
				t.Helper()

				flows := NewMockFlowStore(gomock.NewController(t))
				flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(oidc.Flow{}, errFlushFlowFault).Times(3)

				m, err := oidc.NewRelyingParty(flushOIDCRegistry(t),
					NewMockIdentityBroker(gomock.NewController(t)),
					oidc.WithFlowStore(flows), oidc.WithLogger(log))
				require.NoError(t, err)

				for range 3 {
					_, err := m.Callback(t.Context(), testOIDCProvider, "the-code", "the-state", "the-handle")
					require.Error(t, err)
				}

				conveyed := func(*httpsec.Exchange, oidc.CallbackResult, string) error { return nil }

				return []*httpsec.Chain{oidcChain(t, log, m, nil, httpsec.WithOIDCCallbackSuccess(conveyed))}
			},
			assert: func(t *testing.T, flushed []slog.Record) {
				assert.Equal(t, []int64{2}, summaries(t, flushed, summaryOIDC, "", ""))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &capturingHandler{}
			chains := tc.arrange(t, slog.New(logs))
			before := len(logs.records())

			require.NotPanics(t, func() {
				for _, c := range chains {
					assert.NoError(t, c.FlushRefusalLogs())
				}
			})

			tc.assert(t, logs.records()[before:])
		})
	}
}

// TestFlushRefusalLogsReachesEveryComponentOnOneChain pins spec
// http-security-chain "Chain refusal logs are sampled and summarised",
// scenario "One flush reaches the components", against the chain the
// scenario actually names: ONE chain carrying form login, the second-factor
// verify endpoint, a magic-link source guard and OIDC login, with a policy
// registered on its engine — not one chain built per component, as
// TestFlushRefusalLogsReachesComponents does. A chain.go that stopped after
// flushing the first component it reached would still pass every row of that
// table, because each row's chain holds only one; this test is the one that
// would catch it.
//
// It is a standalone test rather than another row of that table, because
// assembling six collaborators onto one chain and driving each into a
// refusal is not the "one component, one chain" shape the other rows share.
func TestFlushRefusalLogsReachesEveryComponentOnOneChain(t *testing.T) {
	t.Parallel()

	logs := &capturingHandler{}
	log := slog.New(logs)

	// The password authenticator of form login. It already holds two
	// suppressed refusals by the time it is handed over: refusingAuthenticator
	// drives them itself.
	loginDeps := newAuthHarness(t).formLoginDeps()
	loginDeps.Authenticator = refusingAuthenticator(t, log)

	// The verification throttle EnableMFA builds: the method's channel
	// differs from the session's first factor, so the same-channel exemption
	// never applies and every attempt reaches the throttle.
	mh := newMFAHarness(t)
	mh.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
	mh.limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Return(true, nil).Times(3)
	pending := mh.pendingSession(t, factor.Password)

	// The magic-link source guard, built over a consumer limiter reporting
	// every source exceeded.
	lh := newMagicLinkHarness(t)
	lh.linkOpts = []httpsec.MagicLinkOption{httpsec.WithMagicLinkLimiter(exceededLimiter(t))}

	// The OIDC manager and the handoff manager EnableOIDCLogin is given.
	flows := NewMockFlowStore(gomock.NewController(t))
	flows.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(oidc.Flow{}, errFlushFlowFault).Times(3)

	m, err := oidc.NewRelyingParty(flushOIDCRegistry(t), NewMockIdentityBroker(gomock.NewController(t)),
		oidc.WithFlowStore(flows), oidc.WithLogger(log))
	require.NoError(t, err)

	handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(),
		NewMockUserLoader(gomock.NewController(t)), oidc.WithHandoffLogger(log))
	require.NoError(t, err)

	oidcSessions, err := session.New()
	require.NoError(t, err)

	// A second-factor policy registered on the chain's engine: a magic-link
	// login whose only second factor arrives by email is two factors on one
	// channel, so the policy refuses it. EnableMFA below is what enforces the
	// challenge this policy raises, so no separate gate is needed.
	method := NewMockMFAMethodLookup(gomock.NewController(t))
	method.EXPECT().Name().Return("email-code").AnyTimes()
	method.EXPECT().Channel().Return(factor.Email).AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

	p, err := policy.NewMFA([]policy.MFAMethodLookup{method},
		policy.WithMFALogger(log), policy.WithMFALogInterval(time.Hour))
	require.NoError(t, err)

	engine, err := policy.NewEngine(p)
	require.NoError(t, err)

	c, err := httpsec.New(
		httpsec.WithLogger(log),
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableFormLogin(loginDeps),
		mh.carries(pending),
		httpsec.EnableMFA([]mfa.Method{mh.method},
			httpsec.WithMFAVerifyLimiter(mh.limiter),
			httpsec.WithMFATokens(mh.tokens),
			httpsec.WithMFALogInterval(time.Hour)),
		httpsec.EnableMagicLink(lh.manager, lh.options()...),
		httpsec.EnableOIDCLogin(m, handoffs,
			httpsec.WithOIDCSessions(oidcSessions),
			httpsec.WithOIDCTokens(NewMockGenerator(gomock.NewController(t)))),
	)
	require.NoError(t, err)

	// Drive every component but the authenticator — already refused above —
	// into holding suppressed refusals, all under one window no test outlives.
	for range 3 {
		out := serve(t, c, postCode(t.Context(), testMFAVerifyPath))
		require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
	}

	for range 3 {
		out := lh.redeemFrom(t, c, flushSource, "not-a-token", "")
		require.Error(t, out.err)
	}

	for range 3 {
		_, err := m.Callback(t.Context(), testOIDCProvider, "the-code", "the-state", "the-handle")
		require.Error(t, err)
	}

	for range 3 {
		_, err := handoffs.Redeem(t.Context(), "not-a-code")
		require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
	}

	login := &policy.Input{User: "u-1", FirstFactor: factor.MagicLink, Now: time.Now()}
	for range 3 {
		d := engine.EvaluatePhase(t.Context(), policy.PostAuthentication, login)
		require.Equal(t, policy.Deny, d.Outcome, "the policy under test stopped refusing")
	}

	before := len(logs.records())

	require.NotPanics(t, func() { assert.NoError(t, c.FlushRefusalLogs()) })

	flushed := logs.records()[before:]

	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryAuthn, "", ""),
		"the form login authenticator was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryThrottle, "", ""),
		"the verification throttle was not reached by the one flush")
	assert.Equal(t, []int64{2}, guardSummaries(t, flushed, "magic-link-redeem"),
		"the magic-link source guard was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryOIDC, "", ""),
		"the OIDC manager was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryHandoff, "", ""),
		"the OIDC handoff manager was not reached by the one flush")
	assert.Equal(t, []int64{2}, summaries(t, flushed, summaryMFAPolicy, "", ""),
		"the registered policy was not reached by the one flush")
}

// errAuthnFlush and errPolicyFlush are what a consumer's authenticator and a
// consumer's policy return from a flush whose reporter failed.
var (
	errAuthnFlush  = errors.New("chain_test: authenticator flush failed")
	errPolicyFlush = errors.New("chain_test: policy flush failed")
)

// failingFlushAuthenticator is a consumer's authenticator whose refusal-log
// flush fails. Authentication itself is the embedded authenticator's.
type failingFlushAuthenticator struct {
	authenticate.Authenticator
	flushes atomic.Int32
}

func (a *failingFlushAuthenticator) FlushRefusalLogs() error {
	a.flushes.Add(1)

	return errAuthnFlush
}

var _ logsample.Flusher = (*failingFlushAuthenticator)(nil)

// failingFlushPolicy is a consumer's policy whose refusal-log flush fails.
type failingFlushPolicy struct {
	silentPolicy
	flushes atomic.Int32
}

func (p *failingFlushPolicy) FlushRefusalLogs() error {
	p.flushes.Add(1)

	return errPolicyFlush
}

var _ logsample.Flusher = (*failingFlushPolicy)(nil)

// TestChain_FlushRefusalLogs_JoinsErrors pins design D2, that every flusher is
// still called and the errors joined: a consumer's authenticator and a
// consumer's policy whose flushes fail do not stop the chain flushing
// everything else it reaches, including the API key guard that follows the
// failing form login in flush order, and both errors reach the caller, joined. It stands alone rather than as a row of
// TestFlushRefusalLogsReachesComponents, whose rows assert the summary records
// a flush wrote, not the error it returned.
func TestChain_FlushRefusalLogs_JoinsErrors(t *testing.T) {
	t.Parallel()

	logs := &capturingHandler{}
	log := slog.New(logs)

	authn := &failingFlushAuthenticator{Authenticator: NewMockAuthenticator(gomock.NewController(t))}
	loginDeps := newAuthHarness(t).formLoginDeps()
	loginDeps.Authenticator = authn

	p := &failingFlushPolicy{}
	engine, err := policy.NewEngine(p)
	require.NoError(t, err)

	keys := newAPIKeyHarness(t)

	c, err := httpsec.New(
		httpsec.WithLogger(log),
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableFormLogin(loginDeps),
		httpsec.EnableAPIKey(keys.keys, httpsec.WithAPIKeyLimiter(exceededLimiter(t))),
	)
	require.NoError(t, err)

	// Three requests from one source are throttled by the API key guard, which
	// is flushed after the failing form login, and holds two suppressed.
	for range 3 {
		out := keys.withKey(t, c, flushSource, keys.valid)
		require.Error(t, out.err)
	}

	// A request with no client address is refused by the chain itself, under
	// the chain's own sampler, which then holds two suppressed refusals.
	for range 3 {
		out := keys.withKey(t, c, "", keys.valid)
		require.Error(t, out.err)
	}

	before := len(logs.records())

	err = c.FlushRefusalLogs()

	require.ErrorIs(t, err, errAuthnFlush, "the authenticator's flush error did not reach the caller")
	require.ErrorIs(t, err, errPolicyFlush, "the policy's flush error did not reach the caller")
	assert.Equal(t, int32(1), authn.flushes.Load(), "the authenticator was not flushed once")
	assert.Equal(t, int32(1), p.flushes.Load(), "the policy was not flushed once")
	assert.Equal(t, []int64{2},
		summaries(t, logs.records()[before:], summaryChain, "key", "api-key|no-client-address"),
		"the chain's own sampler was not flushed")
	assert.Equal(t, []int64{2}, guardSummaries(t, logs.records()[before:], "api-key"),
		"the API key guard, flushed after the failing authenticator, was not flushed")
}

// TestChain_FlushRefusalLogs_ReachesFirstOfDelegates pins design D2, that
// FirstOf forwards a flush to its delegates: a form login whose authenticator
// is a FirstOf over the password authenticator still gets that authenticator's
// suppressed refusals reported by one Chain.FlushRefusalLogs call.
func TestChain_FlushRefusalLogs_ReachesFirstOfDelegates(t *testing.T) {
	t.Parallel()

	logs := &capturingHandler{}
	log := slog.New(logs)

	// refusingAuthenticator already holds two suppressed refusals.
	first, err := authenticate.NewFirstOf(refusingAuthenticator(t, log))
	require.NoError(t, err)

	loginDeps := newAuthHarness(t).formLoginDeps()
	loginDeps.Authenticator = first

	c, err := httpsec.New(httpsec.WithLogger(log), httpsec.EnableFormLogin(loginDeps))
	require.NoError(t, err)

	before := len(logs.records())

	require.NoError(t, c.FlushRefusalLogs())

	assert.Equal(t, []int64{2}, summaries(t, logs.records()[before:], summaryAuthn, "", ""),
		"the password authenticator behind FirstOf was not flushed")
}

// errBrokerFlush is the failure a consumer's identity broker reports from its
// own refusal-log flush.
var errBrokerFlush = errors.New("chain_test: broker flush failure fixture")

// failingFlushBroker is a consumer's identity broker whose refusal-log flush
// fails.
type failingFlushBroker struct {
	*MockIdentityBroker
}

func (failingFlushBroker) FlushRefusalLogs() error { return errBrokerFlush }

var _ logsample.Flusher = failingFlushBroker{}

// TestChain_FlushRefusalLogs_OIDCFlushesHandoffAfterBrokerError pins design D2
// for the OIDC interceptor: when the relying party returns the error of a
// consumer's broker flush, the handoff manager is still flushed, and the
// caller receives the broker's error.
func TestChain_FlushRefusalLogs_OIDCFlushesHandoffAfterBrokerError(t *testing.T) {
	t.Parallel()

	logs := &capturingHandler{}
	log := slog.New(logs)

	m, err := oidc.NewRelyingParty(flushOIDCRegistry(t),
		failingFlushBroker{NewMockIdentityBroker(gomock.NewController(t))},
		oidc.WithLogger(log))
	require.NoError(t, err)

	handoffs, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(),
		NewMockUserLoader(gomock.NewController(t)), oidc.WithHandoffLogger(log))
	require.NoError(t, err)

	for range 3 {
		_, err := handoffs.Redeem(t.Context(), "not-a-code")
		require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
	}

	c := oidcChain(t, log, m, handoffs)
	before := len(logs.records())

	err = c.FlushRefusalLogs()

	require.ErrorIs(t, err, errBrokerFlush, "the broker's flush error did not reach the caller")
	assert.Equal(t, []int64{2}, summaries(t, logs.records()[before:], summaryHandoff, "", ""),
		"the handoff manager was not flushed after the broker's flush failed")
}

// errFlushFlowFault is a flow-store failure, which the OIDC manager samples
// under its own window, unlike an invalid state, which it never logs.
var errFlushFlowFault = errors.New("flush_test: flow store fault fixture")

// namedSlot pairs a built-in slot with the name a failure reports it by. It is
// a slice rather than a map keyed by the slot, because a map would silently
// collapse two constants that share a value — which is exactly the mistake
// these assertions exist to catch.
type namedSlot struct {
	name string
	slot httpsec.Order
}

func builtInSlots() []namedSlot {
	return []namedSlot{
		{"JWKS", httpsec.OrderJWKS},
		{"OIDC", httpsec.OrderOIDC},
		{"FormLogin", httpsec.OrderFormLogin},
		{"MagicLink", httpsec.OrderMagicLink},
		{"AccountRecoveryEndpoints", httpsec.OrderAccountRecoveryEndpoints},
		{"PasskeyLogin", httpsec.OrderPasskeyLogin},
		{"BasicAuth", httpsec.OrderBasicAuth},
		{"APIKey", httpsec.OrderAPIKey},
		{"MTLS", httpsec.OrderMTLS},
		{"BearerToken", httpsec.OrderBearerToken},
		{"MFAChallenge", httpsec.OrderMFAChallenge},
		{"PasswordChange", httpsec.OrderPasswordChange},
		{"Passkeys", httpsec.OrderPasskeys},
		{"SessionRenewal", httpsec.OrderSessionRenewal},
		{"Logout", httpsec.OrderLogout},
		{"SessionTouch", httpsec.OrderSessionTouch},
		{"Authorizer", httpsec.OrderAuthorizer},
	}
}

func TestOrder(t *testing.T) {
	t.Parallel()

	t.Run("every named slot is distinct", func(t *testing.T) {
		t.Parallel()

		taken := map[httpsec.Order]string{}
		for _, s := range builtInSlots() {
			if other, clash := taken[s.slot]; clash {
				assert.Failf(t, "two built-ins share a slot",
					"%s and %s are both at %d", other, s.name, s.slot)
				continue
			}
			taken[s.slot] = s.name
		}
	})

	t.Run("every named slot leaves its neighbours free", func(t *testing.T) {
		t.Parallel()

		named := map[httpsec.Order]string{}
		for _, s := range builtInSlots() {
			named[s.slot] = s.name
		}

		for _, s := range builtInSlots() {
			_, beforeTaken := named[httpsec.Before(s.slot)]
			_, afterTaken := named[httpsec.After(s.slot)]
			assert.False(t, beforeTaken, "the slot before %s is taken by another built-in", s.name)
			assert.False(t, afterTaken, "the slot after %s is taken by another built-in", s.name)
		}
	})

	t.Run("the plugin slots sit where the spec says", func(t *testing.T) {
		t.Parallel()

		// "an interceptor at the one-time link slot runs after form login and
		// before Basic authentication"
		assert.Greater(t, httpsec.OrderMagicLink, httpsec.OrderFormLogin)
		assert.Less(t, httpsec.OrderMagicLink, httpsec.OrderBasicAuth)

		// The recovery endpoints answer callers who cannot log in, between
		// the one-time link slot and Basic authentication.
		assert.Equal(t, httpsec.Order(375), httpsec.OrderAccountRecoveryEndpoints)
		assert.Greater(t, httpsec.OrderAccountRecoveryEndpoints, httpsec.OrderMagicLink)
		assert.Less(t, httpsec.OrderAccountRecoveryEndpoints, httpsec.OrderBasicAuth)

		// Passwordless login is a first factor of its own, after the one-time
		// link slot and before Basic authentication.
		assert.Equal(t, httpsec.Order(380), httpsec.OrderPasskeyLogin)
		assert.Greater(t, httpsec.OrderPasskeyLogin, httpsec.OrderMagicLink)
		assert.Greater(t, httpsec.OrderPasskeyLogin, httpsec.OrderAccountRecoveryEndpoints)
		assert.Less(t, httpsec.OrderPasskeyLogin, httpsec.OrderBasicAuth)

		// The session-bound passkey endpoints run inside every gate, the
		// password-change gate included, and before logout.
		assert.Equal(t, httpsec.Order(660), httpsec.OrderPasskeys)
		assert.Greater(t, httpsec.OrderPasskeys, httpsec.OrderPasswordChange)
		assert.Greater(t, httpsec.OrderPasskeys, httpsec.OrderMFAChallenge)
		assert.Less(t, httpsec.OrderPasskeys, httpsec.OrderLogout)

		// The renewal endpoint sits between the passkey endpoints and logout:
		// inside every gate and bearer authentication, outside logout.
		assert.Less(t, httpsec.OrderPasskeys, httpsec.OrderSessionRenewal)
		assert.Less(t, httpsec.OrderSessionRenewal, httpsec.OrderLogout)
		assert.Greater(t, httpsec.OrderSessionRenewal, httpsec.OrderPasswordChange)

		// "The refusal SHALL come before the password-change gate, the
		// enrolment gate, the MFA challenge gate": the recovery gate runs
		// after bearer authentication has resolved the session and
		// immediately outside the enrolment gate.
		assert.Equal(t, httpsec.Before(httpsec.OrderMFAEnrolment), httpsec.OrderAccountRecovery)
		assert.Greater(t, httpsec.OrderAccountRecovery, httpsec.OrderBearerToken)
		assert.Less(t, httpsec.OrderAccountRecovery, httpsec.OrderMFAEnrolment)
		assert.Less(t, httpsec.OrderAccountRecovery, httpsec.OrderMFAChallenge)
		assert.Less(t, httpsec.OrderAccountRecovery, httpsec.OrderPasswordChange)

		// The authorization stage is innermost of the built-ins, so everything
		// it judges has already been resolved.
		for _, s := range builtInSlots() {
			if s.name == "Authorizer" {
				continue
			}
			assert.Less(t, s.slot, httpsec.OrderAuthorizer,
				"%s must run outside the authorization stage", s.name)
		}
	})
}

// TestOrderSessionRenewal_Placement pins where a consumer interceptor lands
// relative to the renewal endpoint: one registered before its slot runs for a
// renewal request, and one registered after it never does, because the
// endpoint answers the request first.
func TestOrderSessionRenewal_Placement(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		slot   httpsec.Order
		assert func(t *testing.T, ran bool, out served)
	}

	cases := []testCase{
		{
			name: "an interceptor before the renewal slot runs for a renewal request",
			slot: httpsec.Before(httpsec.OrderSessionRenewal),
			assert: func(t *testing.T, ran bool, out served) {
				require.NoError(t, out.err)
				assert.True(t, ran, "the interceptor outside the renewal slot ran")
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
		{
			name: "an interceptor after the renewal slot does not run, the endpoint answered first",
			slot: httpsec.After(httpsec.OrderSessionRenewal),
			assert: func(t *testing.T, ran bool, out served) {
				require.NoError(t, out.err)
				assert.False(t, ran, "the interceptor inside the renewal slot ran")
				assert.Equal(t, http.StatusOK, out.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var ran atomic.Bool

			probe := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				ran.Store(true)
				return next(ex)
			})

			f := newRenewalFixture(t, renewalSetup{
				interceptors: []httpsec.Option{httpsec.RegisterInterceptor(probe, tc.slot)},
			})

			out := f.request(t, http.MethodPost, httpsec.DefaultSessionRenewalPath, f.old)
			tc.assert(t, ran.Load(), out)
		})
	}
}

func TestBeforeAndAfter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		slot   httpsec.Order
		assert func(t *testing.T, before, after httpsec.Order)
	}

	cases := []testCase{
		{
			name: "either side of the bearer slot",
			slot: httpsec.OrderBearerToken,
			assert: func(t *testing.T, before, after httpsec.Order) {
				assert.Equal(t, httpsec.Order(499), before)
				assert.Equal(t, httpsec.Order(501), after)
			},
		},
		{
			name: "either side of the outermost slot",
			slot: httpsec.OrderJWKS,
			assert: func(t *testing.T, before, after httpsec.Order) {
				assert.Equal(t, httpsec.Order(99), before)
				assert.Equal(t, httpsec.Order(101), after)
			},
		},
		{
			name: "before is outside the slot and after is inside it",
			slot: httpsec.OrderSessionTouch,
			assert: func(t *testing.T, before, after httpsec.Order) {
				assert.Less(t, before, httpsec.OrderSessionTouch)
				assert.Greater(t, after, httpsec.OrderSessionTouch)
				assert.Less(t, after, httpsec.OrderAuthorizer,
					"the slot after session touch must still precede the next named slot")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, httpsec.Before(tc.slot), httpsec.After(tc.slot))
		})
	}
}

func TestRegisterInterceptor(t *testing.T) {
	t.Parallel()

	noop := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		return next(ex)
	})

	type testCase struct {
		name   string
		opts   []httpsec.Option
		assert func(t *testing.T, regs []httpsec.Registration, err error)
	}

	cases := []testCase{
		{
			name: "nothing registered leaves no registrations",
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.NoError(t, err)
				assert.Empty(t, regs)
			},
		},
		{
			name: "a registration keeps the interceptor and the slot it was given",
			opts: []httpsec.Option{httpsec.RegisterInterceptor(noop, httpsec.After(httpsec.OrderBearerToken))},
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.NoError(t, err)
				require.Len(t, regs, 1)
				assert.Equal(t, httpsec.Order(501), regs[0].Order)
				assert.NotNil(t, regs[0].Interceptor)
			},
		},
		{
			name: "registrations at one slot are told apart by arrival",
			opts: []httpsec.Option{
				httpsec.RegisterInterceptor(noop, httpsec.OrderBearerToken),
				httpsec.RegisterInterceptor(noop, httpsec.OrderBearerToken),
			},
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.NoError(t, err)
				require.Len(t, regs, 2)
				assert.Less(t, regs[0].Seq, regs[1].Seq,
					"two interceptors at one slot must be distinguishable by arrival order")
			},
		},
		{
			name: "a nil interceptor is refused at construction, naming the option",
			opts: []httpsec.Option{httpsec.RegisterInterceptor(nil, httpsec.OrderBearerToken)},
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
				assert.Empty(t, regs)
			},
		},
		{
			name: "an interface holding a typed nil is refused too",
			opts: []httpsec.Option{
				httpsec.RegisterInterceptor((*nilInterceptor)(nil), httpsec.OrderBearerToken),
			},
			assert: func(t *testing.T, regs []httpsec.Registration, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "RegisterInterceptor")
				assert.Empty(t, regs)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			regs, err := httpsec.Registrations(tc.opts...)
			tc.assert(t, regs, err)
		})
	}
}

// TestOrderMFAEnrolment pins where the enrolment gate runs: immediately
// outside the second-factor gate, so an enrolment-only session is refused
// before anything at the second-factor slot, the verify endpoint included, can
// answer it, and after every first factor has resolved the session.
//
// It is deliberately not one of builtInSlots: it is Before a named slot, which
// is the one position the spacing rule leaves for exactly this.
func TestOrderMFAEnrolment(t *testing.T) {
	t.Parallel()

	assert.Equal(t, httpsec.Before(httpsec.OrderMFAChallenge), httpsec.OrderMFAEnrolment)
	assert.Greater(t, httpsec.OrderMFAEnrolment, httpsec.OrderBearerToken,
		"the session it confines is resolved by then")
}

func hasAttr(r slog.Record, name string) bool {
	_, ok := attrValue(r, name)

	return ok
}

// throttledAPIKeyChain builds a chain whose API key flow refuses every source as
// over its limit, logging through log, so each attempt from a source is one
// throttled-source refusal on the real throttle path.
//
// attempt presents the harness's live key from source once; the refusal it
// gets is the throttle's, because the limiter answers before the key is read.
func throttledAPIKeyChain(
	t *testing.T,
	log *slog.Logger,
	opts ...httpsec.Option,
) (c *httpsec.Chain, attempt func(source string)) {
	t.Helper()

	h := newAPIKeyHarness(t)

	// The limiter is a mock, which reports no policy, so the chain would warn
	// at construction that the flow counts no IPv6 aggregate. Every source
	// here is IPv4, which no aggregate counts, and the records under test are
	// the refusals alone, so the aggregate is turned off outright.
	c, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithLogger(log),
		httpsec.WithoutIPv6Aggregate(),
		httpsec.EnableAPIKey(h.keys, httpsec.WithAPIKeyLimiter(exceededLimiter(t))),
	}, opts...)...)
	require.NoError(t, err)

	return c, func(source string) {
		t.Helper()

		out := h.withKey(t, c, source, h.valid)
		require.Error(t, out.err, "a throttled source never authenticates")
	}
}

// TestRefusalLogSampling pins the window over the throttled-source record a
// chain-built guard writes: a refusal is driven by whoever is being refused, so
// an unsampled one is a log flood an attacker chooses the size of.
func TestRefusalLogSampling(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		opts []httpsec.Option
		// act drives the chain's throttled API key flow through attempt, and
		// the OIDC handoff flow of a chain over the same log through redeem.
		act    func(t *testing.T, attempt func(source string), redeem func(), advance func(time.Duration))
		assert func(t *testing.T, records []slog.Record)
	}

	cases := []testCase{
		{
			name: "a flood from one source writes one warning in the window",
			act: func(_ *testing.T, attempt func(string), _ func(), _ func(time.Duration)) {
				for range 50 {
					attempt("198.51.100.7")
				}
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 1,
					"an unsampled refusal is a log flood the attacker chooses the size of")
			},
		},
		{
			name: "two sources do not suppress each other",
			act: func(_ *testing.T, attempt func(string), _ func(), _ func(time.Duration)) {
				attempt("198.51.100.7")
				attempt("203.0.113.9")
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 2)
			},
		},
		{
			name: "a flood against one flow does not suppress another flow",
			act: func(_ *testing.T, attempt func(string), redeem func(), _ func(time.Duration)) {
				for range 10 {
					attempt(flushSource)
				}
				redeem()
			},
			assert: func(t *testing.T, records []slog.Record) {
				require.Len(t, records, 2, "every key starts with the flow, so flows never share a window")

				flows := make([]string, 0, len(records))
				for _, r := range records {
					v, _ := attrValue(r, "flow")
					flows = append(flows, v.String())
				}
				assert.ElementsMatch(t, []string{"api-key", "oidc.handoff"}, flows)
			},
		},
		{
			name: "an interval of zero disables sampling",
			opts: []httpsec.Option{httpsec.WithRefusalLogInterval(0)},
			act: func(_ *testing.T, attempt func(string), _ func(), _ func(time.Duration)) {
				for range 5 {
					attempt("198.51.100.7")
				}
			},
			assert: func(t *testing.T, records []slog.Record) {
				assert.Len(t, records, 5, "the documented way to ask for the full stream")
			},
		},
		{
			name: "a written record carries the count suppressed before it",
			act: func(_ *testing.T, attempt func(string), _ func(), advance func(time.Duration)) {
				for range 4 {
					attempt("198.51.100.7")
				}
				advance(time.Minute + time.Second) // the window rolls
				attempt("198.51.100.7")
			},
			assert: func(t *testing.T, records []slog.Record) {
				require.Len(t, records, 2)
				assert.Equal(t, int64(3), suppressedCount(t, records[1]),
					"the second record reports the three it stood in for")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The chain's sampler reads the chain's clock, which a case moves
			// by advancing it.
			fc := clockwork.NewFakeClock()

			var h capturingHandler

			log := slog.New(&h)
			_, attempt := throttledAPIKeyChain(t, log, append([]httpsec.Option{httpsec.WithClock(fc)}, tc.opts...)...)
			handoffs := oidcChain(t, log, newTestOIDCManager(t), newTestHandoffManager(t),
				httpsec.WithOIDCHandoffLimiter(exceededLimiter(t)))

			tc.act(t, attempt, func() { redeemGarbage(t, handoffs, 1) }, fc.Advance)
			tc.assert(t, throttledRecords(h.records()))
		})
	}
}

// reporterCall is one call the consumer's reporter received.
type reporterCall struct {
	key        string
	suppressed int
}

// TestRefusalLogReporter pins that the counts a chain-built source guard
// suppressed are always accounted for, through the chain's reporter: a key
// that goes quiet still reports what it stood for, and a consumer who wants
// those counts somewhere else gets them on flush.
func TestRefusalLogReporter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		attempts int
		opts     func(r *reporterCalls) []httpsec.Option
		assert   func(t *testing.T, records []slog.Record, calls []reporterCall)
	}

	cases := []testCase{
		{
			name:     "the default reporter summarises a key that goes quiet",
			attempts: 5,
			opts:     func(*reporterCalls) []httpsec.Option { return nil },
			assert: func(t *testing.T, records []slog.Record, _ []reporterCall) {
				require.Len(t, records, 2, "one sampled warning, then one summary")
				assert.Equal(t, guardThrottledMsg, records[0].Message)
				assert.Equal(t, "httpsec: refusal logs suppressed", records[1].Message)
				assert.Equal(t, slog.LevelWarn, records[1].Level)

				key, ok := attrValue(records[1], "key")
				require.True(t, ok, "the summary must name the key it stands for")
				assert.Contains(t, key.String(), "api-key", "the key names the flow")
				assert.Contains(t, key.String(), flushSource, "the key names the source")
				assert.Equal(t, int64(4), suppressedCount(t, records[1]))
			},
		},
		{
			name:     "a consumer reporter replaces it",
			attempts: 4,
			opts: func(r *reporterCalls) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogReporter(r.report)}
			},
			assert: func(t *testing.T, records []slog.Record, calls []reporterCall) {
				require.Len(t, calls, 1, "the consumer's reporter did not receive the throttled-source count")
				assert.Equal(t, 3, calls[0].suppressed)
				assert.Contains(t, calls[0].key, flushSource, "the key names the source")
				assert.Len(t, records, 1,
					"the consumer's reporter replaces the summary record, it does not add to it")
			},
		},
		{
			name:     "an interval of zero has nothing to summarise",
			attempts: 5,
			opts: func(*reporterCalls) []httpsec.Option {
				return []httpsec.Option{httpsec.WithRefusalLogInterval(0)}
			},
			assert: func(t *testing.T, records []slog.Record, _ []reporterCall) {
				assert.Len(t, records, 5, "every record was written, so none was suppressed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				h     capturingHandler
				calls reporterCalls
			)

			c, attempt := throttledAPIKeyChain(t, slog.New(&h), tc.opts(&calls)...)
			for range tc.attempts {
				attempt(flushSource)
			}

			require.NoError(t, c.FlushRefusalLogs())

			tc.assert(t, h.records(), calls.received())
		})
	}
}

// reporterCalls is a consumer's reporter that keeps every call it receives. A
// guard reports on whichever goroutine evicted the key, so it is guarded.
type reporterCalls struct {
	mu    sync.Mutex
	calls []reporterCall
}

func (r *reporterCalls) report(key string, suppressed int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, reporterCall{key: key, suppressed: suppressed})
}

func (r *reporterCalls) received() []reporterCall {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]reporterCall(nil), r.calls...)
}

// TestRefusalLogUnsampledDebug pins that a request the client itself ended is
// not treated as a refusal worth a sampled warning. Sampling it would let
// ordinary disconnections consume the window a real outage needs.
func TestRefusalLogUnsampledDebug(t *testing.T) {
	t.Parallel()

	var h capturingHandler
	log := slog.New(&h)
	sampler := logsample.New(time.Minute)

	ctrl := gomock.NewController(t)
	limiter := NewMockLimiter(ctrl)
	limiter.EXPECT().Exceeded(gomock.Any(), gomock.Any()).Times(5).
		DoAndReturn(func(ctx context.Context, _ string) (bool, error) {
			return true, ctx.Err()
		})
	guard := guardOver(t, limiter)

	for range 5 {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := httpsec.SourceThrottledForTest(ctx, guard, "198.51.100.7", "login",
			sampler, log, time.Now())
		require.Error(t, err)
	}

	records := h.records()
	require.Len(t, records, 5, "the ended requests went through the sampler")
	for i, r := range records {
		assert.Equal(t, slog.LevelDebug, r.Level, "record %d is not a debug record", i)
		assert.False(t, hasAttr(r, "suppressed"), "record %d was sampled", i)
	}
}
