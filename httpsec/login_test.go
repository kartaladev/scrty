package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// authHarness is the collaborators a first-factor interceptor is wired to,
// each a double so a test says what the store, the authenticator or the policy
// answered without standing up any of them.
//
// It is shared by the form login, Basic and bearer tests because those three
// are wired to overlapping sets of the same collaborators, and one harness
// keeps "what was this test given" in one place per test rather than three.
type authHarness struct {
	authn    *MockAuthenticator
	users    *MockUserLoader
	verifier *MockVerifier
	store    *MockStore
	sessions *session.Manager
	tokens   *MockGenerator
	attempts *MockAttemptStore

	logs *capturingHandler
}

func newAuthHarness(t *testing.T) *authHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	store := NewMockStore(ctrl)

	manager, err := session.NewManager(session.WithStore(store))
	require.NoError(t, err)

	return &authHarness{
		authn:    NewMockAuthenticator(ctrl),
		users:    NewMockUserLoader(ctrl),
		verifier: NewMockVerifier(ctrl),
		store:    store,
		sessions: manager,
		tokens:   NewMockGenerator(ctrl),
		attempts: NewMockAttemptStore(ctrl),
		logs:     &capturingHandler{},
	}
}

func (h *authHarness) logger() *slog.Logger { return slog.New(h.logs) }

// expectAuthenticated wires the authenticator to resolve any credentials to p.
func (h *authHarness) expectAuthenticated(p *identity.Principal) {
	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		Return(&authenticate.Authentication{Principal: p, Time: time.Now()}, nil)
}

// expectAuthenticationFailed wires the authenticator to refuse any credentials.
func (h *authHarness) expectAuthenticationFailed() {
	h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		Return(nil, authenticate.ErrAuthenticationFailed)
}

// expectSessionOpened wires the store and the generator a successful login
// reaches: one created session, one issued token.
func (h *authHarness) expectSessionOpened(tok string) {
	h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).Return(tok, nil)
}

// basicAuthDeps is what EnableBasicAuth is handed for this harness.
func (h *authHarness) basicAuthDeps() httpsec.BasicAuthDeps {
	return httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: h.attempts}
}

// bearerTokenDeps is what EnableBearerToken is handed for this harness.
func (h *authHarness) bearerTokenDeps() httpsec.BearerTokenDeps {
	return httpsec.BearerTokenDeps{
		Verifier: h.verifier,
		Sessions: h.sessions,
		Users:    h.users,
	}
}

// formLoginDeps is what EnableFormLogin is handed for this harness.
func (h *authHarness) formLoginDeps() httpsec.FormLoginDeps {
	return httpsec.FormLoginDeps{
		Authenticator: h.authn,
		Sessions:      h.sessions,
		Tokens:        h.tokens,
		Attempts:      h.attempts,
	}
}

// served is what running one request through a chain produced.
type served struct {
	rec        *httptest.ResponseRecorder
	handlerRan bool
	err        error

	// handled is the exchange as the downstream handler saw it, and nil when
	// the handler was never reached. It is what a test reads to assert on the
	// state an interceptor published for the application.
	handled *httpsec.Exchange
}

// serve runs req through chain, recording whether the downstream handler was
// reached. The handler is the application's, so a built-in that answers the
// request itself must not call it.
func serve(t *testing.T, chain *httpsec.Chain, req *http.Request) served {
	t.Helper()

	out := served{rec: httptest.NewRecorder()}
	run := chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(t.Context(),
		httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

func formRequest(ctx context.Context, path, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}

func jsonRequest(ctx context.Context, path, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return req
}

// loginBody is the default success document, read back the way a client would.
type loginBody struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ValidUntil   time.Time `json:"valid_until"`
}

// TestFormLogin pins which requests form login claims, and how it reads the
// credentials out of the ones it does.
func TestFormLogin(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.LoginOption
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served)
	}

	cases := []testCase{
		{
			name: "a correct login answers with the token and never calls the handler",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.False(t, s.handlerRan,
					"a login is this library's own endpoint, so the application never sees it")
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Equal(t, "application/json", s.rec.Header().Get("Content-Type"))

				var body loginBody
				require.NoError(t, json.Unmarshal(s.rec.Body.Bytes(), &body))
				assert.Equal(t, "issued-token", body.AccessToken)
				assert.Empty(t, body.RefreshToken,
					"the field is present and empty, so a client need not change when one is issued")
				assert.False(t, body.ValidUntil.IsZero(), "the session's idle expiry is reported")
			},
		},
		{
			name: "a GET on the login path is not a login",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return httptest.NewRequestWithContext(ctx, http.MethodGet, "/login", nil)
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan, "the request continues to the handler untouched")
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Empty(t, s.rec.Body.String())
			},
		},
		{
			name: "a POST on another path is not a login",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/orders", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name: "consumer field names",
			opts: []httpsec.LoginOption{httpsec.WithLoginParams("email", "secret")},
			wire: func(_ *testing.T, h *authHarness) {
				h.authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, c identity.Credentials) (*authenticate.Authentication, error) {
						up, ok := c.(*identity.UsernamePassword)
						require.True(t, ok)
						assert.Equal(t, "ada@example.com", up.Username)

						return &authenticate.Authentication{Principal: testPrincipal()}, nil
					})
				h.attempts.EXPECT().Reset(gomock.Any(), "ada@example.com").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "email=ada%40example.com&secret=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name: "a JSON body when the form yields neither field",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", `{"username":"ada","password":"s3cret"}`)
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name: "a JSON body without a JSON content type is not read as one",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login",
					strings.NewReader(`{"username":"ada","password":"s3cret"}`))
				req.Header.Set("Content-Type", "text/plain")

				return req
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing,
					"the body says what it is, and this one does not say JSON")
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a consumer responder replaces the body",
			opts: []httpsec.LoginOption{
				httpsec.WithLoginResponder(func(ex *httpsec.Exchange, r httpsec.LoginResult) error {
					ex.Writer.SetHeader("Content-Type", "text/plain")
					ex.Writer.WriteHeader(http.StatusCreated)
					_, err := ex.Writer.Write([]byte(r.Token))

					return err
				}),
			},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusCreated, s.rec.Code)
				assert.Equal(t, "text/plain", s.rec.Header().Get("Content-Type"))
				assert.Equal(t, "issued-token", s.rec.Body.String())
			},
		},
		{
			name: "a consumer login path leaves the default passing through",
			opts: []httpsec.LoginOption{httpsec.WithLoginRequestPath("/session")},
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan, "the consumer moved the endpoint, so /login is theirs")
			},
		},
		{
			name: "the consumer login path answers the login",
			opts: []httpsec.LoginOption{httpsec.WithLoginRequestPath("/session")},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/session", "username=ada&password=s3cret")
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.False(t, s.handlerRan)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), tc.opts...),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// phasePolicy answers with one fixed decision in the phases it declares, which
// is how a test says what a phase decided without writing a rule of its own.
func phasePolicy(t *testing.T, d policy.Decision, phases ...policy.Phase) policy.Policy {
	t.Helper()

	p := NewMockPolicy(gomock.NewController(t))
	p.EXPECT().Name().Return("test: fixed answer").AnyTimes()
	p.EXPECT().Phases().Return(phases).AnyTimes()
	p.EXPECT().Evaluate(gomock.Any(), gomock.Any()).Return(d).AnyTimes()

	return p
}

// denyingIn is an engine that denies with reason in phase and allows elsewhere.
func denyingIn(t *testing.T, phase policy.Phase, reason error) *policy.Engine {
	t.Helper()

	return engineOf(t, phasePolicy(t, policy.Decision{Outcome: policy.Deny, Reason: reason}, phase))
}

// challengingIn is an engine that challenges for kind in phase and allows
// elsewhere.
func challengingIn(t *testing.T, phase policy.Phase, kind policy.ChallengeKind) *policy.Engine {
	t.Helper()

	return engineOf(t, phasePolicy(t,
		policy.Decision{Outcome: policy.Challenge, Challenge: kind}, phase))
}

// recordAt reports the first record written at level with this message, so a
// test asserts on what an operator would actually read.
func recordAt(records []slog.Record, level slog.Level, msg string) (slog.Record, bool) {
	for _, r := range records {
		if r.Level == level && r.Message == msg {
			return r, true
		}
	}

	return slog.Record{}, false
}

// TestFormLoginSequence pins the order of the steps, because the order is what
// the guarantees rest on: a locked account is refused before its password is
// tested, and bookkeeping never decides the outcome.
func TestFormLoginSequence(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		engine func(t *testing.T) *policy.Engine
		wire   func(t *testing.T, h *authHarness)
		assert func(t *testing.T, h *authHarness, s served)
	}

	cases := []testCase{
		{
			name: "a locked account is never probed",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingIn(t, policy.PreAuthentication, policy.ErrAccountLocked)
			},
			// No expectation on the authenticator at all: any call to it fails
			// the test, which is what "the password is never checked" means.
			wire: func(*testing.T, *authHarness) {},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.ErrorIs(t, s.err, policy.ErrAccountLocked)
				assert.Equal(t, http.StatusLocked, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name:   "a wrong password records one failed attempt",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
					Return(nil).Times(1)
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed)
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name:   "a correct password clears the attempts",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil).Times(1)
				h.expectSessionOpened("issued-token")
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name:   "an attempt store that cannot record does not change the outcome",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticationFailed()
				h.attempts.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
					Return(errors.New("attempts: store unreachable"))
			},
			assert: func(t *testing.T, h *authHarness, s served) {
				require.ErrorIs(t, s.err, authenticate.ErrAuthenticationFailed,
					"a broken ledger must not turn a wrong password into a server fault")
				assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(s.err))

				r, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: a failed login attempt could not be recorded")
				require.True(t, ok,
					"the lockout count has stopped moving, and only this record says so")
				assert.Positive(t, r.NumAttrs())
			},
		},
		{
			name:   "an attempt store that cannot clear does not change the outcome",
			engine: func(*testing.T) *policy.Engine { return nil },
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").
					Return(errors.New("attempts: store unreachable"))
				h.expectSessionOpened("issued-token")
			},
			assert: func(t *testing.T, h *authHarness, s served) {
				require.NoError(t, s.err, "a broken ledger must not refuse a correct password")
				assert.Equal(t, http.StatusOK, s.rec.Code)

				_, ok := recordAt(h.logs.records(), slog.LevelError,
					"httpsec: failed login attempts could not be cleared")
				assert.True(t, ok)
			},
		},
		{
			name: "a post-authentication deny refuses without creating a session",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return denyingIn(t, policy.PostAuthentication, policy.ErrTooManySessions)
			},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				// No expectation on the store or the generator: a login the
				// policy refused must mint neither a session nor a token.
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				require.ErrorIs(t, s.err, policy.ErrTooManySessions)
				assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
				assert.Empty(t, s.rec.Body.String())
			},
		},
		{
			name: "a post-authentication challenge refuses with the pending session and the token",
			engine: func(t *testing.T) *policy.Engine {
				t.Helper()

				return challengingIn(t, policy.PostAuthentication, policy.ChallengeMFA)
			},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.store.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)
				h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(nil)
				h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
					Return("issued-token", nil)
			},
			assert: func(t *testing.T, _ *authHarness, s served) {
				var ch *httpsec.ChallengeError
				require.ErrorAs(t, s.err, &ch)
				assert.Equal(t, policy.ChallengeMFA, ch.Kind)
				require.NotNil(t, ch.Session, "the caller answers the challenge on this session")
				assert.Equal(t, session.MFAPending, ch.Session.MFA)
				assert.Equal(t, "issued-token", ch.Token)
				assert.False(t, s.handlerRan)
				assert.Empty(t, s.rec.Body.String(),
					"a challenged login is a refusal, so no success document is written")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			opts := []httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps()),
			}
			if e := tc.engine(t); e != nil {
				opts = append(opts, httpsec.WithPolicyEngine(e))
			}

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, h, serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password=s3cret")))
		})
	}
}

// jsonLoginOfSize builds a JSON login document padded to at least n bytes, so
// a test can post a body of a chosen size that still carries real credentials.
func jsonLoginOfSize(n int) string {
	const shell = `{"username":"ada","password":"s3cret","note":""}`

	if n <= len(shell) {
		return shell
	}

	return `{"username":"ada","password":"s3cret","note":"` +
		strings.Repeat("p", n-len(shell)) + `"}`
}

// TestFormLoginBody pins the bound on an unauthenticated endpoint. An
// unbounded read here is a memory-exhaustion path that costs an attacker no
// credential at all, so the bound applies before anything is parsed.
func TestFormLoginBody(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		opts    []httpsec.LoginOption
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served)
	}

	cases := []testCase{
		{
			name: "a 1 MiB body under the default limit is refused unparsed",
			// No expectation on the authenticator: an oversized body must not
			// reach a credential check at all.
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", jsonLoginOfSize(1<<20))
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrRequestTooLarge)
				assert.Equal(t, http.StatusRequestEntityTooLarge, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a body one byte over the default limit is refused",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", jsonLoginOfSize(int(httpsec.DefaultLoginBodyLimit)+1))
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrRequestTooLarge)
			},
		},
		{
			name: "a body just under the default limit logs in normally",
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", jsonLoginOfSize(int(httpsec.DefaultLoginBodyLimit)-1))
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name: "a raised limit parses a 100 KiB body",
			opts: []httpsec.LoginOption{httpsec.WithLoginBodyLimit(256 << 10)},
			wire: func(_ *testing.T, h *authHarness) {
				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("issued-token")
			},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", jsonLoginOfSize(100<<10))
			},
			assert: func(t *testing.T, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
			},
		},
		{
			name: "no credentials at all",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "")
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "an identifier with no password",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada")
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing,
					"half a credential is not a credential to test")
			},
		},
		{
			name: "an undecodable JSON body",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", `{"username":"ada",`)
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing)
				assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
			},
		},
		{
			name: "a JSON body whose credential members are not strings",
			wire: func(*testing.T, *authHarness) {},
			request: func(ctx context.Context) *http.Request {
				return jsonRequest(ctx, "/login", `{"username":1,"password":true}`)
			},
			assert: func(t *testing.T, s served) {
				require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing,
					"a number is not an identifier, and coercing one would invent a login")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), tc.opts...),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// TestFormLoginResponse pins the document a login succeeds with, and that a
// consumer replaces it whole rather than having it reshaped.
func TestFormLoginResponse(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   func(t *testing.T) []httpsec.LoginOption
		assert func(t *testing.T, opened *session.Session, s served)
	}

	cases := []testCase{
		{
			name: "the default document carries the token, an empty refresh field and the idle expiry",
			opts: func(*testing.T) []httpsec.LoginOption { return nil },
			assert: func(t *testing.T, opened *session.Session, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.Equal(t, "application/json", s.rec.Header().Get("Content-Type"))

				var body loginBody
				require.NoError(t, json.Unmarshal(s.rec.Body.Bytes(), &body))
				assert.Equal(t, "issued-token", body.AccessToken)
				assert.Empty(t, body.RefreshToken)

				require.NotNil(t, opened)
				assert.WithinDuration(t, opened.IdleExpiresAt, body.ValidUntil, time.Second,
					"valid_until is the session's idle expiry, not the token's")

				var members map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(s.rec.Body.Bytes(), &members))
				assert.ElementsMatch(t,
					[]string{"access_token", "refresh_token", "valid_until"},
					slices.Collect(maps.Keys(members)),
					"the member names are the documented contract of the default")
			},
		},
		{
			name: "a consumer responder replaces the document whole",
			opts: func(*testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{
					httpsec.WithLoginResponder(func(ex *httpsec.Exchange, r httpsec.LoginResult) error {
						ex.Writer.SetHeader("Content-Type", "text/plain")
						ex.Writer.WriteHeader(http.StatusOK)
						_, err := ex.Writer.Write([]byte("token=" + r.Token +
							" session=" + r.Session.ID))

						return err
					}),
				}
			},
			assert: func(t *testing.T, opened *session.Session, s served) {
				require.NoError(t, s.err)
				assert.Equal(t, "text/plain", s.rec.Header().Get("Content-Type"))
				require.NotNil(t, opened)
				assert.Equal(t, "token=issued-token session="+opened.ID, s.rec.Body.String(),
					"the responder is handed both the token and the session it belongs to")
			},
		},
		{
			name: "a responder that fails leaves the chain as the request's refusal",
			opts: func(*testing.T) []httpsec.LoginOption {
				return []httpsec.LoginOption{
					httpsec.WithLoginResponder(func(*httpsec.Exchange, httpsec.LoginResult) error {
						return errors.New("responder: template missing")
					}),
				}
			},
			assert: func(t *testing.T, _ *session.Session, s served) {
				require.Error(t, s.err)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(s.err),
					"a response that could not be written is a server fault, not a quiet 200")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var opened *session.Session

			h := newAuthHarness(t)
			h.expectAuthenticated(testPrincipal())
			h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
			h.store.EXPECT().Create(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ context.Context, s *session.Session) error {
					opened = s

					return nil
				})
			h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).
				Return("issued-token", nil)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps(), tc.opts(t)...),
			)
			require.NoError(t, err)

			s := serve(t, chain, formRequest(t.Context(), "/login", "username=ada&password=s3cret"))
			tc.assert(t, opened, s)
		})
	}
}

// TestFormLoginConstruction pins that a login that could not work is refused
// before the chain exists, naming the option and the dependency at fault.
func TestFormLoginConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, h *authHarness) []httpsec.Option
		assert func(t *testing.T, chain *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, chain *httpsec.Chain, err error) {
			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, chain, "a chain that cannot work must not exist to serve traffic")
			for _, name := range names {
				assert.Contains(t, err.Error(), name)
			}
		}
	}

	cases := []testCase{
		{
			name: "a fully wired login builds",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableFormLogin(h.formLoginDeps())}
			},
			assert: func(t *testing.T, chain *httpsec.Chain, err error) {
				require.NoError(t, err)
				assert.NotNil(t, chain)
			},
		},
		{
			name: "no authenticator",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Authenticator = nil

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "authenticator"),
		},
		{
			name: "an authenticator holding a typed nil",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Authenticator = (*MockAuthenticator)(nil)

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "authenticator"),
		},
		{
			name: "no session manager",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Sessions = nil

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "session manager"),
		},
		{
			name: "no token generator",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Tokens = nil

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "token generator"),
		},
		{
			name: "no attempt store",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				d := h.formLoginDeps()
				d.Attempts = nil

				return []httpsec.Option{httpsec.EnableFormLogin(d)}
			},
			assert: refused("EnableFormLogin", "attempt store"),
		},
		{
			name: "a body limit of zero",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginBodyLimit(0)),
				}
			},
			assert: refused("WithLoginBodyLimit"),
		},
		{
			name: "a negative body limit",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginBodyLimit(-1)),
				}
			},
			assert: refused("WithLoginBodyLimit"),
		},
		{
			name: "an empty login path",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginRequestPath("")),
				}
			},
			assert: refused("WithLoginRequestPath"),
		},
		{
			name: "a missing field name",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginParams("email", "")),
				}
			},
			assert: refused("WithLoginParams"),
		},
		{
			name: "one field name for both credentials",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(),
						httpsec.WithLoginParams("login", "login")),
				}
			},
			assert: refused("WithLoginParams"),
		},
		{
			name: "a nil responder",
			build: func(_ *testing.T, h *authHarness) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps(), httpsec.WithLoginResponder(nil)),
				}
			},
			assert: refused("WithLoginResponder"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, err := httpsec.New(tc.build(t, newAuthHarness(t))...)
			tc.assert(t, chain, err)
		})
	}
}

// TestFormLoginIgnoresQueryCredentials pins that a credential in the URL query
// never authenticates.
//
// net/http's FormValue merges the query into the parsed form, so a login bound
// through it accepts a password that every access log, proxy log and browser
// history along the way has already recorded, and that the next page sends in
// its Referer. Form login binds from the body alone; the query is not a form
// field.
func TestFormLoginIgnoresQueryCredentials(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		wire    func(t *testing.T, h *authHarness)
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served)
	}

	// No expectation is wired on the authenticator for a refused row: any call
	// to it fails the case, which is what "the credential was never read" means.
	neverAuthenticates := func(*testing.T, *authHarness) {}

	refusedAsMissing := func(t *testing.T, s served) {
		require.ErrorIs(t, s.err, httpsec.ErrCredentialsMissing)
		assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
		assert.False(t, s.handlerRan)
	}

	loggedIn := func(t *testing.T, s served) {
		require.NoError(t, s.err)
		assert.Equal(t, http.StatusOK, s.rec.Code)
		assert.False(t, s.handlerRan)
	}

	succeeds := func(_ *testing.T, h *authHarness) {
		h.expectAuthenticated(testPrincipal())
		h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
		h.expectSessionOpened("issued-token")
	}

	cases := []testCase{
		{
			name: "credentials in the query alone do not authenticate",
			wire: neverAuthenticates,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login?username=ada&password=s3cret", "")
			},
			assert: refusedAsMissing,
		},
		{
			name: "credentials in the body still authenticate",
			wire: succeeds,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login", "username=ada&password=s3cret")
			},
			assert: loggedIn,
		},
		{
			name: "a query pair cannot complete a half-filled body",
			wire: neverAuthenticates,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login?password=s3cret", "username=ada")
			},
			assert: refusedAsMissing,
		},
		{
			name: "an unrelated query parameter is harmless",
			wire: succeeds,
			request: func(ctx context.Context) *http.Request {
				return formRequest(ctx, "/login?next=/home", "username=ada&password=s3cret")
			},
			assert: loggedIn,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			tc.wire(t, h)

			chain, err := httpsec.New(
				httpsec.WithLogger(h.logger()),
				httpsec.EnableFormLogin(h.formLoginDeps()),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())))
		})
	}
}
