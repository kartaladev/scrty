package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/security"
	"github.com/kartaladev/scrty/token"
)

// errEventsStoreDown is a session store that cannot answer.
var errEventsStoreDown = errors.New("test: the session store is down")

// TestSecurityEvents_OnlyWhatHappened pins that an event reports what
// happened: a creation event only for a session stored and a credential handed
// out, and no failure or refusal for a dependency that failed or a request
// whose own context ended before a verdict.
//
// Rows share no setup beyond the recorder: each drives the one flow its
// outcome needs, and reports what was served and recorded.
func TestSecurityEvents_OnlyWhatHappened(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		run    func(t *testing.T, rec *eventRecorder) []served
		assert func(t *testing.T, rec *eventRecorder, out []served)
	}

	cases := []testCase{
		{
			name: "a lost magic-link redemption race reports one token, the winner's",
			run: func(t *testing.T, rec *eventRecorder) []served {
				const racers = 16

				h := newMagicLinkHarness(t)
				tok, nonce := h.link(t, h.chain(t))

				issuer := &barrierIssuer{release: make(chan struct{}), needed: 2}
				h.tokens = issuer.generator(t)
				h.chainOpts = append(h.chainOpts, httpsec.EnableSecurityEvents(rec.sink))
				c := h.chain(t)

				var (
					start, done sync.WaitGroup
					mu          sync.Mutex
					all         []served
				)

				start.Add(1)

				for i := range racers {
					done.Add(1)

					go func() {
						defer done.Done()

						start.Wait()

						out := h.redeemFrom(t, c, "203.0.113."+strconv.Itoa(10+i), tok, nonce)

						mu.Lock()
						all = append(all, out)
						mu.Unlock()
					}()
				}

				start.Done()
				done.Wait()

				// The barrier held the first issues until a second racer had
				// issued too, so at least one loser's credential was discarded.
				require.GreaterOrEqual(t, len(issuer.names()), 2, "a loser issued a credential too")

				return all
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				var winner served

				wins := 0
				for _, o := range out {
					if o.err == nil {
						winner = o
						wins++
					}
				}
				require.Equal(t, 1, wins, "exactly one racer redeems")

				var body magicLinkBody
				require.NoError(t, json.Unmarshal(winner.rec.Body.Bytes(), &body))
				sid, ok := strings.CutPrefix(body.AccessToken, recordedTokenPrefix)
				require.True(t, ok)

				created := rec.named(security.AuthnTokenCreated)
				require.Len(t, created, 1, "one credential was handed out")
				assert.Equal(t, digestOf(sid), created[0].Session, "the winner's")

				stored := rec.named(security.SessionCreated)
				require.Len(t, stored, 1, "one session was stored")
				assert.Equal(t, digestOf(sid), stored[0].Session)
			},
		},
		{
			name: "a login whose session cannot be stored reports no creation",
			run: func(t *testing.T, rec *eventRecorder) []served {
				h := newAuthHarness(t)
				h.expectAuthenticated(testPrincipal())
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return("issued-token", nil)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errEventsStoreDown)
				h.attempts.EXPECT().FailureCount(gomock.Any(), gomock.Any(), gomock.Any()).Return(0, nil).AnyTimes()
				h.attempts.EXPECT().Reset(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				c, err := httpsec.New(httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(h.formLoginDeps()), httpsec.EnableSecurityEvents(rec.sink))
				require.NoError(t, err)

				return []served{serve(t, c, formRequest(t.Context(), httpsec.DefaultLoginPath, "username=ada&password=pw"))}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, errEventsStoreDown)
				assert.Empty(t, rec.named(security.SessionCreated))
				assert.Empty(t, rec.named(security.AuthnTokenCreated))
				assert.Empty(t, rec.named(security.AuthnLoginSuccess))
			},
		},
		{
			name: "a bearer request whose session store is down reports no failure",
			run: func(t *testing.T, rec *eventRecorder) []served {
				h := newAuthHarness(t)
				h.expectVerified()
				h.store.EXPECT().Load(gomock.Any(), testJTI).Return(nil, errEventsStoreDown)

				c, err := httpsec.New(httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()), httpsec.EnableSecurityEvents(rec.sink))
				require.NoError(t, err)

				return []served{serve(t, c, bearerRequest(t.Context(), "Bearer a-token"))}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, errEventsStoreDown)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out[0].err))
				assert.Empty(t, rec.named(security.AuthnLoginFail))
				assert.Empty(t, rec.named(security.AuthzFail))
				assert.Empty(t, rec.all())
			},
		},
		{
			name: "a login whose client hung up before its password was compared reports no failure",
			run: func(t *testing.T, rec *eventRecorder) []served {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				h := newAuthHarness(t)
				h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).DoAndReturn(
					func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
						cancel()

						return nil, errors.Join(authenticate.ErrAuthenticationFailed, context.Canceled)
					})

				c, err := httpsec.New(httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(h.formLoginDeps()), httpsec.EnableSecurityEvents(rec.sink))
				require.NoError(t, err)

				return []served{serveWithContext(ctx, c,
					formRequest(ctx, httpsec.DefaultLoginPath, "username=ada&password=pw"))}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, context.Canceled)
				assert.Empty(t, rec.named(security.AuthnLoginFail))
				assert.Empty(t, rec.all())
			},
		},
		{
			name: "a bearer request whose client hung up during verification reports no failure",
			run: func(t *testing.T, rec *eventRecorder) []served {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				h := newAuthHarness(t)
				h.verifier.EXPECT().Verify(gomock.Any(), gomock.Any()).DoAndReturn(
					func(context.Context, string) (*token.Claims, error) {
						cancel()

						return nil, errors.Join(token.ErrInvalid, context.Canceled)
					})

				c, err := httpsec.New(httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()), httpsec.EnableSecurityEvents(rec.sink))
				require.NoError(t, err)

				return []served{serveWithContext(ctx, c, bearerRequest(ctx, "Bearer a-token"))}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.Error(t, out[0].err)
				assert.Empty(t, rec.all())
			},
		},
		{
			name: "an authorization rule whose store is down reports no authz_fail",
			run: func(t *testing.T, rec *eventRecorder) []served {
				w := newEventsWorldOf(t, eventsWorldSpec{rec: rec, rules: []authorize.Rule[httpsec.Request]{{
					Match:   func(r httpsec.Request) bool { return strings.HasPrefix(r.Path(), "/reports/") },
					Require: func(context.Context) error { return errEventsStoreDown },
				}}})
				tok := w.signedIn(t)

				return []served{w.send(t, http.MethodGet, "/reports/1", tok, nil, nil)}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, errEventsStoreDown)
				assert.Empty(t, rec.named(security.AuthzFail))
			},
		},
		{
			name: "a per-request policy whose store is down reports no authz_fail",
			run: func(t *testing.T, rec *eventRecorder) []served {
				down := &outagePolicy{}
				w := newEventsWorldOf(t, eventsWorldSpec{rec: rec, policies: []policy.Policy{down}})
				tok := w.signedIn(t)
				down.on.Store(true)

				return []served{w.send(t, http.MethodGet, "/api/orders", tok, nil, nil)}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, errEventsStoreDown)
				assert.Empty(t, rec.named(security.AuthzFail))
				assert.Empty(t, rec.named(security.SessionExpired))
			},
		},
		{
			name: "a password change whose store is down reports no failure",
			run: func(t *testing.T, rec *eventRecorder) []served {
				w := newEventsWorldOf(t, eventsWorldSpec{rec: rec})
				tok := w.signedIn(t)

				return []served{w.send(t, http.MethodPost, eventsChangePath, tok,
					url.Values{"current": {e2ePassword}, "new": {eventsUnstoredPassword}}, nil)}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, errEventsStoreDown)
				assert.Empty(t, rec.named(security.AuthnPasswordChangeFail))
				assert.Empty(t, rec.named(security.AuthnPasswordChange))
			},
		},
		{
			name: "a logout whose sign-in was already ended reports nothing",
			run: func(t *testing.T, rec *eventRecorder) []served {
				var w *eventsWorld

				// Another request ends the sign-in between the bearer's load
				// and the logout's revocation.
				racer := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
					if ex.Request.Path() == httpsec.DefaultLogoutPath && ex.Session != nil {
						_, err := w.sessions.RevokeFamily(ex.Context(), ex.Session.FamilyID)
						require.NoError(t, err)
					}

					return next(ex)
				})

				w = newEventsWorldOf(t, eventsWorldSpec{rec: rec},
					httpsec.RegisterInterceptor(racer, httpsec.Before(httpsec.OrderLogout)))
				tok := w.signedIn(t)

				return []served{w.send(t, http.MethodPost, httpsec.DefaultLogoutPath, tok, nil, nil)}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.NoError(t, out[0].err)
				assert.Empty(t, rec.named(security.SessionLogout), "the logout ended nothing")
				assert.Empty(t, rec.named(security.AuthnTokenRevoked))
			},
		},
		{
			name: "ending every other sign-in when there is none reports nothing",
			run: func(t *testing.T, rec *eventRecorder) []served {
				w := newEventsWorldOf(t, eventsWorldSpec{rec: rec})
				tok := w.signedIn(t)

				return []served{w.send(t, http.MethodDelete, httpsec.DefaultSessionManagementPrefix, tok, nil, nil)}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.NoError(t, out[0].err)
				assert.Empty(t, rec.named(security.SignInEnded), "no sign-in was ended")
			},
		},
		{
			name: "a second-factor response whose method could not answer reports no failure",
			run: func(t *testing.T, rec *eventRecorder) []served {
				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp).allows()
				h.method.EXPECT().Verify(gomock.Any(), testMFAUser, gomock.Any()).Return(errEventsStoreDown)
				h.limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				s := h.pendingSession(t, factor.Password)

				return []served{serve(t, h.chain(t, s, httpsec.EnableSecurityEvents(rec.sink)),
					postCode(t.Context(), testMFAVerifyPath))}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, errEventsStoreDown)
				assert.Empty(t, rec.named(security.MFAVerifyFail))
			},
		},
		{
			name: "a second-factor response whose client hung up reports no failure",
			run: func(t *testing.T, rec *eventRecorder) []served {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				h := newMFAHarness(t)
				h.channel(factor.AuthenticatorApp).allows()
				h.method.EXPECT().Verify(gomock.Any(), testMFAUser, gomock.Any()).DoAndReturn(
					func(context.Context, identity.UserID, []byte) error {
						cancel()

						return fmt.Errorf("totp store: %w", context.Canceled)
					})
				h.limiter.EXPECT().RecordFailure(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

				s := h.pendingSession(t, factor.Password)

				return []served{serveWithContext(ctx, h.chain(t, s, httpsec.EnableSecurityEvents(rec.sink)),
					postCode(ctx, testMFAVerifyPath))}
			},
			assert: func(t *testing.T, rec *eventRecorder, out []served) {
				require.ErrorIs(t, out[0].err, context.Canceled)
				assert.Empty(t, rec.named(security.MFAVerifyFail))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := &eventRecorder{}
			tc.assert(t, rec, tc.run(t, rec))
		})
	}
}

// TestSecurityEvents_GuardDenied pins that a route guard behind the chain
// reports its authorization denial as authz_fail, naming the caller, and
// reports nothing for an authorizer that could not answer.
func TestSecurityEvents_GuardDenied(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		judged error
		assert func(t *testing.T, rec *eventRecorder, status int)
	}

	cases := []testCase{
		{
			name:   "a denial is reported, naming the caller",
			judged: fmt.Errorf("%w: not yours", authorize.ErrAccessDenied),
			assert: func(t *testing.T, rec *eventRecorder, status int) {
				assert.Equal(t, http.StatusForbidden, status)

				denied := rec.named(security.AuthzFail)
				require.Len(t, denied, 1)
				assert.Equal(t, e2eUser, denied[0].User)
				assert.Equal(t, eventsClient, denied[0].ClientIP)
				assert.Equal(t, security.OutcomeFailure, denied[0].Outcome)
			},
		},
		{
			name:   "an authorizer that could not answer reports nothing",
			judged: errEventsStoreDown,
			assert: func(t *testing.T, rec *eventRecorder, status int) {
				assert.Equal(t, http.StatusInternalServerError, status)
				assert.Empty(t, rec.named(security.AuthzFail))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newEventsWorldJudgedBy(t, refusingAuthorizer(t, tc.judged))
			tok := w.signedIn(t)

			guards, err := httpsec.NewGuards(nil, httpsec.WithChainAuthorizer())
			require.NoError(t, err)

			route := guards.ResourcePrivileges("billing", "invoice").RequireOne("read")(
				http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) }))

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/invoices/1", nil)
			req.RemoteAddr = eventsProxy + ":51000"
			req.Header.Set("X-Forwarded-For", eventsClient)
			req.Header.Set("Authorization", "Bearer "+tok)

			res := httptest.NewRecorder()
			w.chain.Middleware()(route).ServeHTTP(res, req)

			tc.assert(t, w.rec, res.Code)
		})
	}
}

// barrierIssuer is a token generator that records the session each token
// names, and holds every issue until needed racers have issued or a second
// has passed, so a race reliably has losers that issued before the consume
// decided against them.
type barrierIssuer struct {
	release chan struct{}
	needed  int

	mu    sync.Mutex
	named []string
}

func (b *barrierIssuer) generator(t *testing.T) *MockGenerator {
	t.Helper()

	g := NewMockGenerator(gomock.NewController(t))
	g.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			b.mu.Lock()
			b.named = append(b.named, id)
			if len(b.named) == b.needed {
				close(b.release)
			}
			b.mu.Unlock()

			select {
			case <-b.release:
			case <-time.After(time.Second):
			}

			return recordedTokenPrefix + id, nil
		})

	return g
}

// names is every session identifier a token was issued for, in order.
func (b *barrierIssuer) names() []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]string(nil), b.named...)
}

// outagePolicy is a per-request policy whose store, once on is set, cannot
// answer: it denies with errEventsStoreDown, an outage rather than a verdict.
type outagePolicy struct{ on atomic.Bool }

func (*outagePolicy) Name() string { return "test: outage" }

func (*outagePolicy) Phases() []policy.Phase { return []policy.Phase{policy.PerRequest} }

func (p *outagePolicy) Evaluate(context.Context, *policy.Input) policy.Decision {
	if !p.on.Load() {
		return policy.Decision{Outcome: policy.Allow}
	}

	return policy.Decision{Outcome: policy.Deny, Reason: errEventsStoreDown}
}
