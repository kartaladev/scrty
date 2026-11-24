package httpsec_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// errCarryingInvalidHandoff is a consumer dependency's failure that wraps
// oidc.ErrInvalidHandoff, the value completion refuses a user with: a failure is
// mapped by where it arose, never by what it wraps (D4).
var errCarryingInvalidHandoff = fmt.Errorf("oidc_parked_failure_completion_test: down: %w", oidc.ErrInvalidHandoff)

// errSigningKeyDown is what a token generator whose signing key is down answers.
var errSigningKeyDown = errors.New("oidc_parked_failure_completion_test: signing key down")

// failingCreateStore is a session store whose creating write fails with err.
type failingCreateStore struct {
	session.Store

	err error
}

func (s *failingCreateStore) Create(context.Context, *session.Session) error { return s.err }

// TestCompletion_RefusalsReturnToLogin pins that completion's own refusals of a
// parked login return to the login page with their code (D3, D4), mapped by the
// call site they arose at: the user's load refuses access_denied and fails
// server_error, the post-authentication and per-request policies refuse
// access_denied, and storing the session fails server_error, whatever the error
// wraps. A per-request refusal ends the session it judged first, and an owed step
// still falls back to the handoff.
func TestCompletion_RefusalsReturnToLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// users is OIDCDeps.Users; nil loads viewer.
		users identity.UserLoader
		// post denies at the post-authentication phase with this reason.
		post error
		// perRequest denies the stored session with errCompletionRefused.
		perRequest bool
		// store replaces the session store.
		store func(t *testing.T) session.Store
		// setup changes what the row's chain is built from.
		setup func(t *testing.T, s *completionSetup)
		// arm sets a fault once the request is parked.
		arm    func(t *testing.T, f *completionFlow)
		chain  func(t *testing.T, f *completionFlow) []httpsec.Option
		assert func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string)
	}

	returned := func(code string, stored int64) func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string) {
		return func(t *testing.T, f *completionFlow, a flowAnswer, handle, flow string) {
			t.Helper()

			assertReturnedToLogin(t, f, a, handle, flow, httpsec.DefaultOIDCLoginErrorParam, code)
			assert.Equal(t, stored, f.cancelled.Load(), "the session was stored first, or never")
			assert.False(t, f.sessionSeen.Load(), "no session on the exchange")
			assert.Zero(t, f.charged.Load(), "a live handle is charged nothing")
		}
	}

	denied := returned(oidcprovider.CodeAccessDenied, 0)
	failed := returned(oidcprovider.CodeServerError, 0)

	cases := []testCase{
		{name: "a user the loader does not know", users: loaderAnswering(t, nil, identity.ErrUserNotFound), assert: denied},
		{name: "a loader answering no user", users: loaderAnswering(t, nil, nil), assert: denied},
		{
			name:   "a disabled user",
			users:  loaderAnswering(t, &identity.Details{ID: oidcTestUserID, Username: "ada@example.com"}, nil),
			assert: denied,
		},
		{
			name:   "a loader answering another user",
			users:  loaderAnswering(t, &identity.Details{ID: "u-9", Username: "eve@example.com", Active: true}, nil),
			assert: denied,
		},
		{name: "a loader that fails", users: loaderAnswering(t, nil, errCompletionLoaderDown), assert: failed},
		{
			name:   "a loader failing with an error that wraps the refusal",
			users:  loaderAnswering(t, nil, errCarryingInvalidHandoff),
			assert: failed,
		},
		{
			// A consumer's broker that names no user: completion has no one to load.
			name: "a broker that names no user",
			setup: func(_ *testing.T, s *completionSetup) {
				s.broker = func(t *testing.T, _ *oidcTestProvider) oidc.IdentityBroker {
					t.Helper()

					b := NewMockIdentityBroker(gomock.NewController(t))
					b.EXPECT().Broker(gomock.Any(), gomock.Any()).AnyTimes().Return(&identity.Principal{}, nil)

					return b
				}
			},
			assert: denied,
		},
		{
			// Issuing the credential is the login tail's own step, before anything is
			// stored: a signing key that is down is the chain's outage, not a denial.
			name: "the token issuer fails",
			setup: func(t *testing.T, s *completionSetup) {
				t.Helper()

				issuer := newMockGenerator(gomock.NewController(t))
				issuer.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
					Return("", errSigningKeyDown)

				s.oidc = append(s.oidc, httpsec.WithOIDCTokens(issuer))
				s.bearer = func(t *testing.T, w *opFlow) httpsec.Option {
					t.Helper()

					verifier := must.Must(token.NewGenerator(tokenKeys(), token.WithoutIssuer(), token.WithoutAudience()))

					return httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: verifier, Sessions: w.sessions, Users: w.users,
					})
				}
			},
			assert: returned(oidcprovider.CodeServerError, 0),
		},
		{name: "the post-authentication policy denies", post: errCompletionDenied, assert: denied},
		{name: "the post-authentication policy denies with a store's error", post: errSessionStoreDown, assert: denied},
		{
			name:       "the per-request policy refuses",
			perRequest: true,
			assert:     returned(oidcprovider.CodeAccessDenied, 1),
		},
		{
			name: "the session store fails",
			store: func(*testing.T) session.Store {
				return &failingCreateStore{Store: must.Must(session.NewMemoryStore()), err: errSessionStoreDown}
			},
			assert: returned(oidcprovider.CodeServerError, 1),
		},
		{
			name: "the session store fails with an error that wraps the refusal",
			store: func(*testing.T) session.Store {
				return &failingCreateStore{Store: must.Must(session.NewMemoryStore()), err: errCarryingInvalidHandoff}
			},
			assert: returned(oidcprovider.CodeServerError, 1),
		},
		{
			name: "cancelling the held recoveries fails",
			arm: func(t *testing.T, f *completionFlow) {
				t.Helper()

				f.cancelFails.Store(&errRecoveryCancelDown)
			},
			assert: returned(oidcprovider.CodeServerError, 1),
		},
		{
			// The seam hands its error back unwrapped, so a stage that read the
			// value would take it for a refused user.
			name: "cancelling the held recoveries fails with the bare refusal",
			arm: func(t *testing.T, f *completionFlow) {
				t.Helper()

				bare := oidc.ErrInvalidHandoff
				f.cancelFails.Store(&bare)
			},
			assert: returned(oidcprovider.CodeServerError, 1),
		},
		{
			name:  "an owed step",
			chain: mfaRequired,
			assert: func(t *testing.T, f *completionFlow, a flowAnswer, handle, _ string) {
				t.Helper()

				loc, _ := handoffTo(t, a)
				assert.Equal(t, parkedAt(handle), loc.String(), "the handoff to the login page, as today")
				assert.Zero(t, f.storedSessions(t), "no session")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			users := tc.users
			if users == nil {
				users = loaderAnswering(t, viewer, nil)
			}

			judged := completionJudged{}
			if tc.perRequest {
				judged.perRequestDecision = policy.Decision{Outcome: policy.Deny, Reason: errCompletionRefused}
			}

			setup := completionSetup{
				users: users,
				chain: func(t *testing.T, f *completionFlow) []httpsec.Option {
					t.Helper()

					if tc.chain != nil {
						return append(tc.chain(t, f), observeSession(f))
					}

					engine := judged.engine(t)
					if tc.post != nil {
						engine = denyingEngine(t, tc.post)
					}

					return []httpsec.Option{httpsec.WithPolicyEngine(engine), observeSession(f)}
				},
			}
			if tc.setup != nil {
				tc.setup(t, &setup)
			}

			if tc.store != nil {
				setup.sessions = []session.Option{session.WithStore(tc.store(t))}
			}

			f := newCompletionFlow(t, setup)
			handle, flow := f.park(t, flowFirstParty)
			if tc.arm != nil {
				tc.arm(t, f)
			}

			tc.assert(t, f, f.signIn(t, parkedAt(handle), flowCookieOf(flowCookie, flow)), handle, flow)
		})
	}
}
