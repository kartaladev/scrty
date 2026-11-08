package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authenticate/mfa"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/policy/lockout"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// maxPasswordAge is the age the stand-in password-age gate challenges beyond.
const maxPasswordAge = 90 * 24 * time.Hour

func allowingEngine(t *testing.T) *policy.Engine {
	t.Helper()

	return engineOf(t, policyAnswering(t, policy.Decision{Outcome: policy.Allow}))
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

// loginSpies is the store and the token generator the login tail is wired to,
// each recording that it was reached and in what order.
type loginSpies struct {
	store    *MockStore
	tokens   *MockGenerator
	sessions *session.Sessions

	mu      sync.Mutex
	created *session.Session
}

func newLoginSpies(t *testing.T) *loginSpies {
	t.Helper()

	ctrl := gomock.NewController(t)
	store := NewMockStore(ctrl)

	manager, err := session.New(session.WithStore(store))
	require.NoError(t, err)

	return &loginSpies{store: store, tokens: newMockGenerator(ctrl), sessions: manager}
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

// expectCreateCapturing is expectCreate that also keeps a copy of the session
// as the store received it, so a test reads what the creating write carried
// rather than what a later mutation left on the pointer.
func (s *loginSpies) expectCreateCapturing(log *callLog) {
	s.store.EXPECT().Create(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, got *session.Session) error {
			log.add("Create")

			written := *got

			s.mu.Lock()
			s.created = &written
			s.mu.Unlock()

			return nil
		})
}

// createdSession is the session the store's Create received, or nil.
func (s *loginSpies) createdSession() *session.Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.created
}

// recordSaves logs any save of the session without requiring one, so a test
// that pins "one write" reads a Save in the call order rather than as an
// unexpected call.
func (s *loginSpies) recordSaves(log *callLog) {
	s.store.EXPECT().Save(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, _ *session.Session) error {
			log.add("Save")

			return nil
		})
}

// expectCreateFailing records that the session's creating write was attempted,
// and fails it with err.
func (s *loginSpies) expectCreateFailing(log *callLog, err error) {
	s.store.EXPECT().Create(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ *session.Session) error {
			log.add("Create")

			return err
		})
}

// recordCreates logs any creating write without requiring one, so a test that
// pins "nothing is stored" reads a Create in the call order rather than as an
// unexpected call.
func (s *loginSpies) recordCreates(log *callLog) {
	s.store.EXPECT().Create(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, _ *session.Session) error {
			log.add("Create")

			return nil
		})
}

// expectGenerateFailing records that the token was asked for, and fails it
// with err.
func (s *loginSpies) expectGenerateFailing(log *callLog, err error) {
	s.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, _ *identity.Principal) (string, error) {
			log.add("Generate")

			return "", err
		})
}

// spendLogging is a spend step that logs it ran and fails with err.
func spendLogging(log *callLog, err error) func(context.Context) error {
	return func(context.Context) error {
		log.add("Spend")

		return err
	}
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
		stubRequest{method: http.MethodPost, path: httpsec.DefaultLoginPath}, &stubWriter{})
	ex.Authentication = &authenticate.Authentication{Principal: testPrincipal()}

	return ex
}

// errIssuing stands for a key source that cannot sign, errStoring for a
// session store that cannot write, and errSpending for a redemption that lost
// its consume. Neither dependency's text may reach a returned error.
var (
	errIssuing  = errors.New("complete_test: kms unreachable at 10.0.0.7")
	errStoring  = errors.New("complete_test: session store unreachable at 10.0.0.7")
	errSpending = errors.New("complete_test: the link was consumed by another redemption")
)

// TestCompleteLogin pins the order of the one tail every first factor shares:
// build the session, mark any challenge on it, issue the credential, then
// store the session in one write, and only then hand the credential out. A
// credential is never handed out for a session that was not stored, so a
// token never exists for a session whose challenge mark did not persist, and a
// credential that cannot be issued costs nothing.
//
// A row with a spend step runs the tail as a redemption does, in its two
// halves with the single-use credential spent between them: the first half
// stores nothing, so a spend that fails, or one never reached because issuing
// failed, leaves nothing stored.
func TestCompleteLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine
		opts   []session.CreateOption
		// spend is a redemption's spend step, run between the tail's two
		// halves; nil runs the tail whole, as form login does.
		spend  func(log *callLog) func(context.Context) error
		wire   func(t *testing.T, s *loginSpies, log *callLog, jti *string)
		assert func(t *testing.T, s *loginSpies, ex *httpsec.Exchange, tok string, err error, calls []string, jti string)
	}

	dependencyFailure := func(t *testing.T, ex *httpsec.Exchange, tok string, err error) {
		t.Helper()

		require.Error(t, err)
		assert.Empty(t, tok, "no credential is handed out")
		assert.NotErrorIs(t, err, authenticate.ErrAuthenticationFailed, "an outage is not a refusal")
		assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired, "an outage is not a refusal")
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err))
		assert.NotContains(t, err.Error(), "10.0.0.7", "a dependency's text stays out of the error")

		var ch *httpsec.ChallengeError
		assert.NotErrorAs(t, err, &ch, "no challenge carries a credential")
		assert.Nil(t, ex.Session, "no session is published")
	}

	cases := []testCase{
		{
			name:   "an allowed login issues the token, then creates the session",
			engine: allowingEngine,
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectCreate(log)
				s.expectGenerate(log, jti)
			},
			assert: func(t *testing.T, _ *loginSpies, ex *httpsec.Exchange, tok string, err error, calls []string, jti string) {
				require.NoError(t, err)
				assert.Equal(t, "issued-token", tok)
				assert.Equal(t, []string{"Generate", "Create"}, calls)

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
			assert: func(t *testing.T, _ *loginSpies, _ *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.NoError(t, err, "with no policies wired the chain rests on authentication alone")
				assert.Equal(t, "issued-token", tok)
				assert.Equal(t, []string{"Generate", "Create"}, calls)
			},
		},
		{
			name: "a deny refuses with the policy's reason and creates nothing",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingEngine(t, lockout.ErrAccountLocked)
			},
			wire: func(*testing.T, *loginSpies, *callLog, *string) {},
			assert: func(t *testing.T, _ *loginSpies, _ *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.ErrorIs(t, err, lockout.ErrAccountLocked)
				assert.Empty(t, tok)
				assert.Empty(t, calls, "no session is created for a login policy refused")
			},
		},
		{
			name: "a reasonless deny still refuses, and never reads as success",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingEngine(t, nil) // the engine substitutes ErrDenied
			},
			wire: func(*testing.T, *loginSpies, *callLog, *string) {},
			assert: func(t *testing.T, _ *loginSpies, _ *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.Error(t, err, "a reasonless deny must never return nil")
				require.ErrorIs(t, err, policy.ErrDenied)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(err))
				assert.Empty(t, tok)
				assert.Empty(t, calls)
			},
		},
		{
			name: "a challenge is marked in the creating write, after the token is issued",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingEngine(t, policy.ChallengeMFA)
			},
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectGenerate(log, jti)
				s.expectCreateCapturing(log)
				s.recordSaves(log)
			},
			assert: func(t *testing.T, s *loginSpies, ex *httpsec.Exchange, tok string, err error, calls []string, jti string) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				require.NotNil(t, ch.Session)
				assert.Equal(t, session.MFAPending, ch.Session.MFA)
				assert.NotEmpty(t, ch.Token)
				assert.Equal(t, "issued-token", tok)
				assert.Equal(t, []string{"Generate", "Create"}, calls,
					"the pending marker is in the one write that stores the session, before the token is handed out")

				created := s.createdSession()
				require.NotNil(t, created)
				assert.Equal(t, session.MFAPending, created.MFA, "the stored session is the marked one")
				assert.Equal(t, created.ID, jti, "the token names the session that was stored")
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
				s.expectGenerate(log, jti)
				s.expectCreateCapturing(log)
				s.recordSaves(log)
			},
			assert: func(t *testing.T, s *loginSpies, _ *httpsec.Exchange, _ string, err error, calls []string, _ string) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				require.NotNil(t, ch.Session)
				assert.True(t, ch.Session.PasswordChangePending)
				assert.Equal(t, []string{"Generate", "Create"}, calls)

				created := s.createdSession()
				require.NotNil(t, created)
				assert.True(t, created.PasswordChangePending, "the stored session is the marked one")
			},
		},
		{
			name: "a token that cannot be issued stores nothing, and is a dependency failure",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingEngine(t, policy.ChallengeMFA)
			},
			spend: func(log *callLog) func(context.Context) error { return spendLogging(log, nil) },
			wire: func(_ *testing.T, s *loginSpies, log *callLog, _ *string) {
				s.expectGenerateFailing(log, errIssuing)
				s.recordCreates(log)
				s.recordSaves(log)
			},
			assert: func(t *testing.T, _ *loginSpies, ex *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				dependencyFailure(t, ex, tok, err)
				require.ErrorIs(t, err, errIssuing, "the generator's error stays reachable")
				assert.Equal(t, []string{"Generate"}, calls,
					"nothing is spent and nothing is stored for a credential that was never issued")
			},
		},
		{
			name:   "a store that fails after the token is issued hands no token out",
			engine: allowingEngine,
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectGenerate(log, jti)
				s.expectCreateFailing(log, errStoring)
			},
			assert: func(t *testing.T, _ *loginSpies, ex *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				dependencyFailure(t, ex, tok, err)
				require.ErrorIs(t, err, errStoring, "the store's error stays reachable")
				assert.Equal(t, []string{"Generate", "Create"}, calls)
			},
		},
		{
			name: "a challenged login whose store fails after issuing raises no challenge",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingEngine(t, policy.ChallengeMFA)
			},
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectGenerate(log, jti)
				s.expectCreateFailing(log, errStoring)
				s.recordSaves(log)
			},
			assert: func(t *testing.T, _ *loginSpies, ex *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				dependencyFailure(t, ex, tok, err)
				assert.Equal(t, []string{"Generate", "Create"}, calls,
					"the token issued for the session that was never stored is discarded")
			},
		},
		{
			name:   "a redemption spends after the token is issued and before the session is stored",
			engine: allowingEngine,
			spend:  func(log *callLog) func(context.Context) error { return spendLogging(log, nil) },
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectGenerate(log, jti)
				s.expectCreate(log)
			},
			assert: func(t *testing.T, _ *loginSpies, ex *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.NoError(t, err)
				assert.Equal(t, "issued-token", tok)
				assert.Equal(t, []string{"Generate", "Spend", "Create"}, calls)
				assert.NotNil(t, ex.Session)
			},
		},
		{
			name:   "a redemption whose spend fails stores nothing, and the issued token is discarded",
			engine: allowingEngine,
			spend:  func(log *callLog) func(context.Context) error { return spendLogging(log, errSpending) },
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectGenerate(log, jti)
				s.recordCreates(log)
			},
			assert: func(t *testing.T, _ *loginSpies, ex *httpsec.Exchange, tok string, err error, calls []string, _ string) {
				require.ErrorIs(t, err, errSpending)
				assert.Empty(t, tok, "the issued token is discarded")
				assert.Nil(t, ex.Session, "no session is published")
				assert.Equal(t, []string{"Generate", "Spend"}, calls, "no session is stored")
			},
		},
		{
			name:   "a caller's first-factor option cannot replace the tail's",
			engine: allowingEngine,
			opts: []session.CreateOption{
				session.WithFirstFactor(factor.Kind("magic-link")),
			},
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectCreateCapturing(log)
				s.expectGenerate(log, jti)
			},
			assert: func(t *testing.T, s *loginSpies, ex *httpsec.Exchange, _ string, err error, calls []string, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []string{"Generate", "Create"}, calls)

				created := s.createdSession()
				require.NotNil(t, created, "the store must have received the session")
				assert.Equal(t, factor.Password, created.FirstFactor,
					"the tail's own first factor wins; a caller's option cannot replace it")

				require.NotNil(t, ex.Session)
				assert.Equal(t, factor.Password, ex.Session.FirstFactor)
			},
		},
		{
			// Form login calls the tail with no create options, so this is the
			// session a password login stores.
			name:   "a password session records no external provider, issuer, session id or ID token",
			engine: allowingEngine,
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectCreateCapturing(log)
				s.expectGenerate(log, jti)
			},
			assert: func(t *testing.T, s *loginSpies, ex *httpsec.Exchange, _ string, err error, _ []string, _ string) {
				require.NoError(t, err)

				created := s.createdSession()
				require.NotNil(t, created, "the store must have received the session")
				assert.Empty(t, created.ExternalProvider, "a password session names no provider")
				assert.Empty(t, created.ExternalIssuer, "a password session names no issuer")
				assert.Empty(t, created.ExternalSessionID, "a password session names no provider session")
				assert.Empty(t, created.ExternalIDToken, "a password session holds no ID token")

				require.NotNil(t, ex.Session)
				assert.Empty(t, ex.Session.ExternalProvider)
			},
		},
		{
			name:   "caller create options land in the creating write",
			engine: allowingEngine,
			opts: []session.CreateOption{
				session.WithExternalSession("corp", "https://idp.example", "sid-9", "raw.id.token"),
			},
			wire: func(_ *testing.T, s *loginSpies, log *callLog, jti *string) {
				s.expectCreateCapturing(log)
				s.expectGenerate(log, jti)
			},
			assert: func(t *testing.T, s *loginSpies, ex *httpsec.Exchange, _ string, err error, calls []string, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []string{"Generate", "Create"}, calls,
					"the federated fields are in the first write; no Save follows to add them")

				created := s.createdSession()
				require.NotNil(t, created, "the store must have received the session")
				assert.Equal(t, "corp", created.ExternalProvider)
				assert.Equal(t, "https://idp.example", created.ExternalIssuer)
				assert.Equal(t, "sid-9", created.ExternalSessionID)
				assert.Equal(t, "raw.id.token", created.ExternalIDToken)
				assert.Equal(t, factor.Password, created.FirstFactor,
					"the tail's own first factor still applies beside the caller's options")

				require.NotNil(t, ex.Session)
				assert.Equal(t, "corp", ex.Session.ExternalProvider)
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

			deps := httpsec.LoginTailDepsForTest(tc.engine(t), spies.sessions, spies.tokens)

			var (
				tok string
				err error
			)

			if tc.spend == nil {
				tok, err = httpsec.CompleteLoginForTest(ex, deps, in, tc.opts...)
			} else {
				// A redemption's order: the first half inside its checks, the
				// spend, and the second half only once the spend succeeded.
				spend := tc.spend(log)

				tok, err = func() (string, error) {
					login, err := httpsec.PrepareLoginForTest(ex.Context(), deps, in, tc.opts...)
					if err != nil {
						return "", err
					}

					if err := spend(ex.Context()); err != nil {
						return "", err
					}

					return httpsec.CommitLoginForTest(ex, login)
				}()
			}

			tc.assert(t, spies, ex, tok, err, log.all(), jti)
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
	spies.expectGenerate(log, nil)
	spies.expectCreate(log)
	spies.recordSaves(log)

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
	assert.Equal(t, []string{"Generate", "Create"}, log.all())
}

// writeLog is a session store that logs every creating write and every save
// into a shared call log, so a test reads the order of the writes beside the
// token's issuance.
type writeLog struct {
	session.Store

	log *callLog
}

func (w *writeLog) Create(ctx context.Context, s *session.Session) error {
	w.log.add("Create")

	return w.Store.Create(ctx, s)
}

func (w *writeLog) Save(ctx context.Context, s *session.Session) error {
	w.log.add("Save")

	return w.Store.Save(ctx, s)
}

// TestCompleteLogin_ChallengeStoredBeforeHandOut pins, through a whole form
// login over a real store, that a challenged login's session is in the store,
// carrying its challenge mark, by the time the challenge hands its token out,
// and that it got there in the one write that created it: no session is ever
// stored unmarked, and no token is issued for one that is.
//
// Not rows of TestCompleteLogin: it runs a real chain and a real store.
func TestCompleteLogin_ChallengeStoredBeforeHandOut(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		kind   policy.ChallengeKind
		assert func(t *testing.T, stored *session.Session)
	}

	cases := []testCase{
		{
			name: "a second-factor challenge",
			kind: policy.ChallengeMFA,
			assert: func(t *testing.T, stored *session.Session) {
				assert.Equal(t, session.MFAPending, stored.MFA)
			},
		},
		{
			name: "a password-change challenge",
			kind: policy.ChallengePasswordChange,
			assert: func(t *testing.T, stored *session.Session) {
				assert.True(t, stored.PasswordChangePending)
			},
		},
		{
			name: "an enrolment challenge",
			kind: policy.ChallengeMFAEnrolment,
			assert: func(t *testing.T, stored *session.Session) {
				assert.Equal(t, session.MFAEnrolmentPending, stored.MFA)
				assert.False(t, stored.EnrolmentOriginDeadline.IsZero(), "the enrolment-origin marker is set")
				assert.WithinDuration(t, stored.CreatedAt.Add(15*time.Minute), stored.AbsoluteExpiresAt, time.Second,
					"stored with its deadline already lowered to the default enrolment lifetime")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			log := &callLog{}

			h := newAuthHarness(t)
			sessions, err := session.New(session.WithStore(&writeLog{Store: must.Must(session.NewMemoryStore()), log: log}))
			require.NoError(t, err)
			h.sessions = sessions

			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
				DoAndReturn(func(ctx context.Context, sid string, _ *identity.Principal) (string, error) {
					log.add("Generate")

					_, err := sessions.Load(ctx, sid)
					assert.ErrorIs(t, err, session.ErrNotFound, "the token is issued before its session is stored")

					return "issued-token", nil
				})

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps()),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, tc.kind)),
				httpsec.EnableGateForTest(tc.kind),
			)
			require.NoError(t, err)

			out := serve(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath, "username=ada&password=s3cret"))

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch)
			assert.Equal(t, tc.kind, ch.Kind)
			assert.Equal(t, "issued-token", ch.Token)
			require.NotNil(t, ch.Session)

			assert.Equal(t, []string{"Generate", "Create"}, log.all(),
				"one write, after the token is issued, and no save to add the mark")

			stored, err := sessions.Load(t.Context(), ch.Session.ID)
			require.NoError(t, err, "the session the challenge hands out is stored")
			tc.assert(t, stored)
		})
	}
}

// tokenGeneratorIsAnInterface keeps the spy honest: if token.Generator stops
// being the port the seam depends on, this stops compiling here rather than
// somewhere an interceptor is wired.
var _ token.Generator = (*MockGenerator)(nil)

// TestCompleteLoginEnrolment pins what the login tail does with an enrolment
// challenge: the session is built, marked enrolment-pending with its
// deadlines lowered to the enrolment lifetime, and stored in that state, in
// the one write that creates it, before the token for it is handed out. A
// session stored before its mark would be a full session, however briefly.
func TestCompleteLoginEnrolment(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		lifetime time.Duration
		assert   func(t *testing.T, start time.Time, abs time.Duration, saved *session.Session)
	}

	lowered := func(to time.Duration) func(t *testing.T, start time.Time, abs time.Duration, saved *session.Session) {
		return func(t *testing.T, start time.Time, abs time.Duration, saved *session.Session) {
			t.Helper()

			assert.Equal(t, session.MFAEnrolmentPending, saved.MFA)
			assert.True(t, saved.AbsoluteExpiresAt.Equal(start.Add(to)),
				"the absolute deadline is lowered to the enrolment lifetime, got %s", saved.AbsoluteExpiresAt)
			assert.False(t, saved.IdleExpiresAt.After(saved.AbsoluteExpiresAt),
				"the idle deadline never outlives the absolute one")
			assert.True(t, saved.EnrolmentOriginDeadline.Equal(start.Add(abs)),
				"the marker records the deadline the upgrade may give back")
		}
	}

	cases := []testCase{
		{name: "the default lifetime", lifetime: 15 * time.Minute, assert: lowered(15 * time.Minute)},
		{name: "a configured lifetime", lifetime: 5 * time.Minute, assert: lowered(5 * time.Minute)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			start := time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

			ctrl := gomock.NewController(t)
			store := NewMockStore(ctrl)
			tokens := newMockGenerator(ctrl)

			sessions, err := session.New(session.WithStore(store),
				session.WithClock(clockwork.NewFakeClockAt(start)))
			require.NoError(t, err)

			var saved session.Session

			// One write, after the token: no Save is expected, so one fails
			// the test.
			gomock.InOrder(
				tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("issued-token", nil),
				store.EXPECT().Create(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, s *session.Session) error {
						saved = *s

						return nil
					}),
			)

			ex := newExchange(t)
			deps := httpsec.LoginTailDepsWithEnrolmentForTest(
				challengingEngine(t, policy.ChallengeMFAEnrolment), sessions, tokens, tc.lifetime)

			tok, err := httpsec.CompleteLoginForTest(ex, deps, httpsec.PostAuthenticationInputForTest(
				testPrincipal(), factor.MagicLink, "", time.Time{}, start))

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, err, &ch)
			assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
			assert.Equal(t, "issued-token", ch.Token, "the client holds a credential for the confined session")
			assert.Equal(t, "issued-token", tok)
			require.NotNil(t, ch.Session)
			assert.Equal(t, session.MFAEnrolmentPending, ch.Session.MFA)

			tc.assert(t, start, sessions.AbsoluteTimeout(), &saved)
		})
	}
}

// TestCompleteLoginEnrolmentMagicLink pins the scenario end to end through a
// real chain: a magic-link redemption of a required, unenrolled user, with the
// enrolment path on, is refused with an enrolment challenge carrying a token
// and a session stored in the enrolment-pending state.
func TestCompleteLoginEnrolmentMagicLink(t *testing.T) {
	t.Parallel()

	start := time.Now()

	h := newMagicLinkHarness(t)

	sessions, err := session.New(session.WithClock(clockwork.NewFakeClockAt(start)))
	require.NoError(t, err)
	h.sessions = sessions

	requesting := h.chain(t)
	tok, nonce := h.link(t, requesting)

	ctrl := gomock.NewController(t)
	method := NewMockMFAMethodLookup(ctrl)
	method.EXPECT().Name().Return("totp").AnyTimes()
	method.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(false, nil).AnyTimes()
	method.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()

	requirement, err := policy.NewMFARequirement(everyoneRequired{}, []policy.MFAMethodLookup{enrollableLookup{method}},
		policy.WithMFAEnrolmentPath())
	require.NoError(t, err)

	// Both gates the policy declares are recorded as enabled without being
	// registered. What is under test is what the login tail stores, not what a
	// gate does with it.
	chain, err := httpsec.New(
		httpsec.EnableMagicLink(h.manager, h.options()...),
		httpsec.WithPolicyEngine(engineOf(t, requirement)),
		httpsec.EnableGateForTest(policy.ChallengeMFAEnrolment),
		httpsec.EnableGateForTest(policy.ChallengeMFA),
	)
	require.NoError(t, err)

	out := h.redeem(t, chain, tok, nonce)

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch)
	assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
	assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
	assert.NotEmpty(t, ch.Token)

	stored := h.openedSession(t)
	assert.Equal(t, session.MFAEnrolmentPending, stored.MFA, "saved in that state before the token was issued")
	assert.Equal(t, factor.MagicLink, stored.FirstFactor)
	assert.True(t, stored.AbsoluteExpiresAt.Equal(start.Add(15*time.Minute)),
		"with no lifetime configured the documented default applies, got %s", stored.AbsoluteExpiresAt)
	assert.False(t, stored.EnrolmentOriginDeadline.IsZero(), "the enrolment-origin marker is set")
}

// TestCompleteLoginMFAMethods pins that a login challenged for a second factor
// tells the consumer which methods the user can answer it with, computed as the
// policies compute usability, and that a lookup that fails refuses the login
// instead of offering an empty or partial list.
func TestCompleteLoginMFAMethods(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// totpErr is what the TOTP method's enrolment lookup fails with.
		totpErr error
		stub    func(c *challengeStub)
		// writesNothing expects no session to be created or saved and no
		// token to be issued.
		writesNothing bool
		assert        func(t *testing.T, s served)
	}

	errLookup := errors.New("logincomplete_test: enrolment store unavailable for alice@example.com")

	cases := []testCase{
		{
			name: "challenge carries the usable methods",
			assert: func(t *testing.T, s served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, s.err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.Equal(t, "issued-token", ch.Token)
				assert.Equal(t, []httpsec.MFAMethod{
					{Name: "totp", Channel: factor.AuthenticatorApp},
					{Name: "passkey", Channel: testDeviceChannel, Begins: true},
				}, ch.Methods)
			},
		},
		{
			name: "challenge omits methods the user cannot use",
			stub: func(c *challengeStub) { c.enrolled = false },
			assert: func(t *testing.T, s served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, s.err, &ch)
				assert.Equal(t, []httpsec.MFAMethod{{Name: "totp", Channel: factor.AuthenticatorApp}},
					ch.Methods)
			},
		},
		{
			// The methods are looked up before the session is created, so a
			// failed lookup leaves no pending session behind and issues no
			// token; and the store's own text stays out of the refusal.
			name:          "a failed lookup never yields an empty list",
			totpErr:       errLookup,
			writesNothing: true,
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, errLookup)
				assert.NotContains(t, s.err.Error(), "alice@example.com")

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, s.err, &ch, "the failure replaces the challenge")
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(s.err))
				assert.Empty(t, s.rec.Body.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			if !tc.writesNothing {
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("issued-token", nil)
			}

			totp := NewMockMethod(gomock.NewController(t))
			totp.EXPECT().Name().Return("totp").AnyTimes()
			totp.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
			totp.EXPECT().Response().Return(mfa.FormField("code", 4<<10)).AnyTimes()
			totp.EXPECT().Enrolled(gomock.Any(), identity.UserID("u-1")).Return(tc.totpErr == nil, tc.totpErr).AnyTimes()

			passkey := newChallengeStub()
			if tc.stub != nil {
				tc.stub(passkey)
			}

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps()),
				httpsec.WithPolicyEngine(challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)),
				httpsec.EnableMFA([]mfa.Method{totp, passkey}, httpsec.WithMFATokens(h.tokens)),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, formRequest(t.Context(), httpsec.DefaultLoginPath, "username=ada&password=s3cret")))
		})
	}
}

// TestCompleteLogin_Proof pins that the login tail records a second factor met
// at the first factor: a login carrying the library's holding proof creates
// its session satisfied, in the creating write, and still owes any other
// challenge the phase raises; a login carrying none behaves as it always did.
//
// Not rows of TestCompleteLogin: each case builds a real MFA policy over method lookups.
func TestCompleteLogin_Proof(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

	type written struct {
		created *session.Session
		saved   *session.Session
	}

	type testCase struct {
		name string
		// proof is whether the input carries a holding proof.
		proof bool
		// passwordAge adds the password-age policy and a stale password.
		passwordAge bool
		// totpEnrolled enrols the user on TOTP besides their passkey.
		totpEnrolled bool
		assert       func(t *testing.T, tok string, err error, w written)
	}

	cases := []testCase{
		{
			name:  "satisfied at creation",
			proof: true,
			assert: func(t *testing.T, tok string, err error, w written) {
				require.NoError(t, err, "the second factor was met at the first, so no challenge is owed")
				assert.Equal(t, "issued-token", tok)

				require.NotNil(t, w.created)
				assert.Equal(t, session.MFASatisfied, w.created.MFA,
					"satisfied in the creating write, never briefly unsatisfied")
				assert.True(t, w.created.MFAAtFirstFactor)
				assert.True(t, w.created.MFASatisfiedAt.Equal(w.created.CreatedAt))
				assert.Equal(t, factor.Passkey, w.created.FirstFactor)
				assert.Nil(t, w.saved, "nothing is saved after the creating write")
			},
		},
		{
			name:        "password-change still challenges",
			proof:       true,
			passwordAge: true,
			assert: func(t *testing.T, tok string, err error, w written) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				assert.Equal(t, policy.ChallengePasswordChange, ch.Kind)
				assert.Equal(t, "issued-token", tok)

				require.NotNil(t, w.created, "the challenge is marked in the creating write")
				assert.Equal(t, session.MFASatisfied, w.created.MFA)
				assert.True(t, w.created.MFAAtFirstFactor)
				assert.True(t, w.created.PasswordChangePending)
				assert.Nil(t, w.saved, "nothing is saved after the creating write")
			},
		},
		{
			name:         "zero proof unchanged",
			totpEnrolled: true,
			assert: func(t *testing.T, tok string, err error, w written) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				assert.Equal(t, "issued-token", tok)

				require.NotNil(t, w.created, "the challenge is marked in the creating write")
				assert.Equal(t, session.MFAPending, w.created.MFA)
				assert.False(t, w.created.MFAAtFirstFactor)
				assert.Nil(t, w.saved, "nothing is saved after the creating write")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			passkey := NewMockMFAMethodLookup(ctrl)
			passkey.EXPECT().Name().Return("passkey").AnyTimes()
			passkey.EXPECT().Channel().Return(factor.PublicKey).AnyTimes()
			passkey.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

			totp := NewMockMFAMethodLookup(ctrl)
			totp.EXPECT().Name().Return("totp").AnyTimes()
			totp.EXPECT().Channel().Return(factor.AuthenticatorApp).AnyTimes()
			totp.EXPECT().Enrolled(gomock.Any(), gomock.Any()).Return(tc.totpEnrolled, nil).AnyTimes()

			lookups := []policy.MFAMethodLookup{passkey, totp}

			requirement, err := policy.NewMFARequirement(nil, lookups, policy.WithMFARequiredForAll())
			require.NoError(t, err)

			challenge, err := policy.NewMFA(lookups)
			require.NoError(t, err)

			policies := []policy.Policy{requirement, challenge}
			passwordChangedAt := start.Add(-time.Hour)

			if tc.passwordAge {
				age, err := policy.NewPasswordAge(policy.WithMaxPasswordAge(maxPasswordAge))
				require.NoError(t, err)

				policies = append(policies, age)
				passwordChangedAt = start.Add(-2 * maxPasswordAge)
			}

			store := NewMockStore(ctrl)
			tokens := newMockGenerator(ctrl)

			sessions, err := session.New(session.WithStore(store),
				session.WithClock(clockwork.NewFakeClockAt(start)))
			require.NoError(t, err)

			var w written

			store.EXPECT().Create(gomock.Any(), gomock.Any()).Times(1).
				DoAndReturn(func(_ context.Context, s *session.Session) error {
					c := *s
					w.created = &c

					return nil
				})
			store.EXPECT().Save(gomock.Any(), gomock.Any()).AnyTimes().
				DoAndReturn(func(_ context.Context, s *session.Session) error {
					c := *s
					w.saved = &c

					return nil
				})
			tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("issued-token", nil)

			in := httpsec.PostAuthenticationInputForTest(
				testPrincipal(), factor.Passkey, "ada", passwordChangedAt, start)
			if tc.proof {
				in.SecondFactorAtLogin = httpsec.MintProofForTest(factor.Passkey, start)
			}

			tok, err := httpsec.CompleteLoginForTest(newExchange(t),
				httpsec.LoginTailDepsForTest(engineOf(t, policies...), sessions, tokens), in)

			tc.assert(t, tok, err, w)
		})
	}
}
