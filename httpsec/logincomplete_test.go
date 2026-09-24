package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// maxPasswordAge is the age the stand-in password-age gate challenges beyond.
const maxPasswordAge = 90 * 24 * time.Hour

func testPrincipal() *identity.Principal {
	return &identity.Principal{ID: "u-1", Username: "ada", Name: "Ada Lovelace"}
}

// policyAnswering is a policy that gives one fixed answer in the
// post-authentication phase, which is how a test says what the phase decided
// without writing a rule of its own.
func policyAnswering(t *testing.T, d policy.Decision) policy.Policy {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: fixed answer").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).Return(d).AnyTimes()

	return p
}

func engineOf(t *testing.T, policies ...policy.Policy) *policy.Engine {
	t.Helper()

	e, err := policy.NewEngine(policies...)
	require.NoError(t, err)

	return e
}

func allowingEngine(t *testing.T) *policy.Engine {
	t.Helper()

	return engineOf(t, policyAnswering(t, policy.Decision{Outcome: policy.Allow}))
}

func denyingEngine(t *testing.T, reason error) *policy.Engine {
	t.Helper()

	return engineOf(t, policyAnswering(t, policy.Decision{Outcome: policy.Deny, Reason: reason}))
}

func challengingEngine(t *testing.T, kind policy.ChallengeKind) *policy.Engine {
	t.Helper()

	return engineOf(t, policyAnswering(t,
		policy.Decision{Outcome: policy.Challenge, Challenge: kind}))
}

// passwordAgeGate stands in for the rule a deployment writes against a stale
// password: it reads nothing but the two times the input carries, so an input
// that lost either of them cannot fire it.
func passwordAgeGate(t *testing.T) policy.Policy {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: password age").AnyTimes()
	p.EXPECT().Phases().Return([]policy.Phase{policy.PostAuthentication}).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, in *policy.Input) policy.Decision {
			if in.PasswordChangedAt.IsZero() ||
				in.Now.Sub(in.PasswordChangedAt) <= maxPasswordAge {
				return policy.Decision{Outcome: policy.Allow}
			}

			return policy.Decision{
				Outcome:   policy.Challenge,
				Challenge: policy.ChallengePasswordChange,
			}
		})

	return p
}

// TestPostAuthenticationInput pins which argument lands in which field. Every
// field is a parameter rather than a struct literal the caller fills in, so an
// interceptor cannot quietly omit one — a missing password change time disables
// the age gate on that interceptor's path alone.
func TestPostAuthenticationInput(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 23, 12, 0, 0, 0, time.UTC)

	type testCase struct {
		name              string
		principal         *identity.Principal
		first             factor.Kind
		username          string
		passwordChangedAt time.Time
		assert            func(t *testing.T, in *policy.Input, d policy.Decision)
	}

	cases := []testCase{
		{
			name:      "the principal and the user it resolves to are carried",
			principal: testPrincipal(),
			first:     factor.Password,
			username:  "ada",
			assert: func(t *testing.T, in *policy.Input, _ policy.Decision) {
				assert.Equal(t, identity.UserID("u-1"), in.User)
				require.NotNil(t, in.Principal)
				assert.Equal(t, "Ada Lovelace", in.Principal.Name)
			},
		},
		{
			name:      "the username is the one submitted, not the one resolved",
			principal: testPrincipal(),
			first:     factor.Password,
			username:  "ADA@example.com",
			assert: func(t *testing.T, in *policy.Input, _ policy.Decision) {
				assert.Equal(t, "ADA@example.com", in.Username,
					"a policy keying on what the caller typed must see what the caller typed")
			},
		},
		{
			name:      "the first factor is carried as the kind it was",
			principal: testPrincipal(),
			first:     factor.Kind("magic-link"),
			username:  "ada",
			assert: func(t *testing.T, in *policy.Input, _ policy.Decision) {
				assert.Equal(t, factor.Kind("magic-link"), in.FirstFactor)
			},
		},
		{
			name:              "a stale password fires the age gate",
			principal:         testPrincipal(),
			first:             factor.Password,
			username:          "ada",
			passwordChangedAt: now.Add(-maxPasswordAge - time.Hour),
			assert: func(t *testing.T, in *policy.Input, d policy.Decision) {
				assert.Equal(t, now, in.Now, "every policy in the phase judges the same instant")
				require.Equal(t, policy.Challenge, d.Outcome,
					"the password change time did not reach the field the gate reads")
				assert.Equal(t, policy.ChallengePasswordChange, d.Challenge)
			},
		},
		{
			name:              "a password changed inside the window does not",
			principal:         testPrincipal(),
			first:             factor.Password,
			username:          "ada",
			passwordChangedAt: now.Add(-time.Hour),
			assert: func(t *testing.T, _ *policy.Input, d policy.Decision) {
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
		{
			name:      "an unknown password change time gates nothing",
			principal: testPrincipal(),
			first:     factor.Password,
			username:  "ada",
			assert: func(t *testing.T, in *policy.Input, d policy.Decision) {
				assert.True(t, in.PasswordChangedAt.IsZero())
				assert.Equal(t, policy.Allow, d.Outcome)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := httpsec.PostAuthenticationInputForTest(
				tc.principal, tc.first, tc.username, tc.passwordChangedAt, now)
			require.NotNil(t, in)

			d := engineOf(t, passwordAgeGate(t)).
				EvaluatePhase(t.Context(), policy.PostAuthentication, in)
			tc.assert(t, in, d)
		})
	}
}

// callLog records the order the login tail's dependencies were called in. The
// order is the whole point of the seam, so the tests pin it rather than the
// outcome alone.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls = append(l.calls, name)
}

func (l *callLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.calls...)
}

// loginSpies is the store and the token generator the login tail is wired to,
// each recording that it was reached and in what order.
type loginSpies struct {
	store    *MockStore
	tokens   *MockGenerator
	sessions *session.Manager
}

func newLoginSpies(t *testing.T) *loginSpies {
	t.Helper()

	ctrl := gomock.NewController(t)
	store := NewMockStore(ctrl)

	manager, err := session.NewManager(session.WithStore(store))
	require.NoError(t, err)

	return &loginSpies{store: store, tokens: NewMockGenerator(ctrl), sessions: manager}
}

// expectCreate records that the session was created, which is the only place
// the first factor can be written.
func (s *loginSpies) expectCreate(log *callLog) {
	s.store.EXPECT().Create(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *session.Session) error {
			log.add("Create")

			return nil
		})
}

func (s *loginSpies) expectSave(log *callLog, err error) {
	s.store.EXPECT().Save(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *session.Session) error {
			log.add("Save")

			return err
		})
}

func (s *loginSpies) expectGenerate(log *callLog, jti *string) {
	s.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			log.add("Generate")
			if jti != nil {
				*jti = id
			}

			return "issued-token", nil
		})
}

func newExchange(t *testing.T) *httpsec.Exchange {
	t.Helper()

	ex := httpsec.NewExchange(t.Context(),
		stubRequest{method: http.MethodPost, path: "/login"}, &stubWriter{})
	ex.Authentication = &authenticate.Authentication{Principal: testPrincipal()}

	return ex
}

// TestCompleteLogin pins the order of the one tail every first factor shares.
// A token that exists before the session it belongs to is marked answers
// requests as if the challenge had been met, so the order is the guarantee.
func TestCompleteLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine
		wire   func(t *testing.T, s *loginSpies, log *callLog, jti *string)
		assert func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string, jti string)
	}

	cases := []testCase{
		{
			name:   "an allowed login creates the session, then issues the token",
			engine: allowingEngine,
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectCreate(log)
				s.expectGenerate(log, jti)
			},
			assert: func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string, jti string) {
				require.NoError(t, err)
				assert.Equal(t, "issued-token", tok)
				assert.Equal(t, []string{"Create", "Generate"}, calls)

				require.NotNil(t, ex.Session, "the session is published for a consumer handler")
				assert.Equal(t, factor.Password, ex.Session.FirstFactor)
				assert.Equal(t, ex.Session.ID, jti,
					"the token's jti is the session identifier a later request finds it by")

				published, ok := httpsec.SessionFromContext(ex.Context())
				require.True(t, ok, "the session must reach the handler through the context")
				assert.Same(t, ex.Session, published)

				auth, ok := authenticate.AuthenticationFromContext(ex.Context())
				require.True(t, ok, "the authentication must reach the handler too")
				assert.Equal(t, identity.UserID("u-1"), auth.Principal.ID)
			},
		},
		{
			name:   "no engine configured allows the login",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectCreate(log)
				s.expectGenerate(log, jti)
			},
			assert: func(t *testing.T, _ *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.NoError(t, err, "with no policies wired the chain rests on authentication alone")
				assert.Equal(t, "issued-token", tok)
				assert.Equal(t, []string{"Create", "Generate"}, calls)
			},
		},
		{
			name: "a deny refuses with the policy's reason and creates nothing",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingEngine(t, policy.ErrAccountLocked)
			},
			wire: func(*testing.T, *loginSpies, *callLog, *string) {},
			assert: func(t *testing.T, _ *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.ErrorIs(t, err, policy.ErrAccountLocked)
				assert.Empty(t, tok)
				assert.Empty(t, calls, "no session is created for a login policy refused")
			},
		},
		{
			name: "a reasonless deny still refuses, and never reads as success",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingEngine(t, nil) // the engine substitutes ErrPolicyDenied
			},
			wire: func(*testing.T, *loginSpies, *callLog, *string) {},
			assert: func(t *testing.T, _ *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.Error(t, err, "a reasonless deny must never return nil")
				require.ErrorIs(t, err, policy.ErrPolicyDenied)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(err))
				assert.Empty(t, tok)
				assert.Empty(t, calls)
			},
		},
		{
			name: "a challenge is marked and saved before the token is issued",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingEngine(t, policy.ChallengeMFA)
			},
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectCreate(log)
				s.expectSave(log, nil)
				s.expectGenerate(log, jti)
			},
			assert: func(t *testing.T, ex *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				require.NotNil(t, ch.Session)
				assert.Equal(t, session.MFAPending, ch.Session.MFA)
				assert.NotEmpty(t, ch.Token)
				assert.Equal(t, "issued-token", tok)
				assert.Equal(t, []string{"Create", "Save", "Generate"}, calls,
					"the pending marker must be durable before a token for it exists")
				assert.NotNil(t, ex.Session, "a consumer rendering the prompt reads who is challenged")
			},
		},
		{
			name: "a password-change challenge marks the session it is owed on",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingEngine(t, policy.ChallengePasswordChange)
			},
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectCreate(log)
				s.expectSave(log, nil)
				s.expectGenerate(log, jti)
			},
			assert: func(t *testing.T, _ *httpsec.Exchange, _ string, err error, calls []string, _ string) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				require.NotNil(t, ch.Session)
				assert.True(t, ch.Session.PasswordChangePending)
				assert.Equal(t, []string{"Create", "Save", "Generate"}, calls)
			},
		},
		{
			name: "a failed save leaves no token issued",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingEngine(t, policy.ChallengeMFA)
			},
			wire: func(_ *testing.T, s *loginSpies, log *callLog, _ *string) {
				s.expectCreate(log)
				s.expectSave(log, errors.New("store unavailable"))
				// No expectation on the generator: any call to it fails the test.
			},
			assert: func(t *testing.T, _ *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.Error(t, err)
				assert.Empty(t, tok)
				assert.NotContains(t, calls, "Generate",
					"a token must never exist for a session whose pending flag failed to persist")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var (
				log = &callLog{}
				jti string
			)

			spies := newLoginSpies(t)
			tc.wire(t, spies, log, &jti)

			ex := newExchange(t)
			in := httpsec.PostAuthenticationInputForTest(
				testPrincipal(), factor.Password, "ada", time.Time{}, time.Now())

			tok, err := httpsec.CompleteLoginForTest(ex,
				httpsec.LoginTailDepsForTest(tc.engine(t), spies.sessions, spies.tokens), in)
			tc.assert(t, ex, tok, err, log.all(), jti)
		})
	}
}

// TestCompleteLoginOtherFirstFactor proves the seam is the reason another
// capability's redemption interceptor cannot end a login differently from form
// login: it is the same phase, the same marking and the same refusal.
func TestCompleteLoginOtherFirstFactor(t *testing.T) {
	t.Parallel()

	log := &callLog{}
	spies := newLoginSpies(t)
	spies.expectCreate(log)
	spies.expectSave(log, nil)
	spies.expectGenerate(log, nil)

	ex := newExchange(t)

	// A stand-in for a redemption interceptor another capability adds: it
	// resolves a principal by its own means, then hands it to the seam.
	in := httpsec.PostAuthenticationInputForTest(
		testPrincipal(), factor.Kind("magic-link"), "ada", time.Time{}, time.Now())

	deps := httpsec.LoginTailDepsForTest(
		challengingEngine(t, policy.ChallengePasswordChange), spies.sessions, spies.tokens)

	_, err := httpsec.CompleteLoginForTest(ex, deps, in)

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, err, &ch)
	assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
	require.NotNil(t, ch.Session, "exactly as form login would refuse it")
	assert.True(t, ch.Session.PasswordChangePending)
	assert.Equal(t, factor.Kind("magic-link"), ch.Session.FirstFactor,
		"the session records the factor the login actually used")
	assert.Equal(t, []string{"Create", "Save", "Generate"}, log.all())
}

// tokenGeneratorIsAnInterface keeps the spy honest: if token.Generator stops
// being the port the seam depends on, this stops compiling here rather than
// somewhere an interceptor is wired.
var _ token.Generator = (*MockGenerator)(nil)
