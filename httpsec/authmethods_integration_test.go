package httpsec_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/apikey"
	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/ratelimit"
	"github.com/kartaladev/scrty/session"
	"github.com/kartaladev/scrty/token"
)

// The two callers in these tests: a person who signs in by link and then proves
// a second factor, and a machine that presents a key.
const (
	integrationUser    identity.UserID = "u-1"
	integrationAddress                 = "ada@example.com"
	integrationService identity.UserID = "svc-billing"
	integrationSource                  = "203.0.113.7"
	otherSource                        = "198.51.100.4"
)

// integrationClock is the instant the TOTP method matches codes against. It is
// this test's to move, because a confirmed code's step is recorded and the next
// code has to belong to a later one.
type integrationClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *integrationClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *integrationClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// integrationHarness is one deployment: one session store, one token
// generator, and all three authentication methods wired into one chain behind a
// second-factor policy — which is the only way to find out whether they
// compose.
type integrationHarness struct {
	sessions *session.Manager
	tokens   *MockGenerator
	users    *MockUserLoader
	sender   *capturingSender

	links  *magiclink.Manager
	totp   *mfa.TOTP
	secret string
	clock  *integrationClock

	keys   *apikey.Manager
	apiKey string

	// shared is one limiter handed to both the magic-link and the API key
	// flow, for the case that asks whether one instance merges their
	// allowances.
	shared ratelimit.Limiter

	chain *httpsec.Chain
}

func newIntegrationHarness(t *testing.T) *integrationHarness {
	t.Helper()

	ctrl := gomock.NewController(t)
	ctx := t.Context()

	sessions, err := session.NewManager()
	require.NoError(t, err)

	h := &integrationHarness{
		sessions: sessions,
		tokens:   NewMockGenerator(ctrl),
		users:    NewMockUserLoader(ctrl),
		sender:   &capturingSender{},
		clock:    &integrationClock{now: time.Date(2026, time.September, 24, 9, 0, 0, 0, time.UTC)},
	}

	h.wireUsers()
	h.wireTokens()

	onetimes, err := onetime.NewManager("magic-link", onetime.WithTTL(magicLinkTTL))
	require.NoError(t, err)

	h.links, err = magiclink.NewManager(
		onetimes, h.users, h.sender, "https://app.example.com")
	require.NoError(t, err)

	h.totp, err = mfa.NewTOTP(mfa.NewMemoryEnrolmentStore(), "Example Payroll",
		mfa.WithClock(h.clock.Now))
	require.NoError(t, err)

	h.enrol(ctx, t)

	h.keys, err = apikey.NewManager()
	require.NoError(t, err)

	h.apiKey, _, err = h.keys.Issue(ctx, integrationService, "billing", nil, 0)
	require.NoError(t, err)

	h.chain = h.buildChain(t)

	return h
}

// shareOneLimiter rebuilds the chain with a single limiter behind both the
// magic-link and the API key flow.
func (h *integrationHarness) shareOneLimiter(t *testing.T) {
	t.Helper()

	limiter, err := ratelimit.NewMemoryLimiter(10, 15*time.Minute)
	require.NoError(t, err)

	h.shared = limiter
	h.chain = h.buildChain(t)
}

// wireUsers answers for the one person in these tests, by address and by
// reference: a link records the reference and redemption loads by it.
func (h *integrationHarness) wireUsers() {
	details := func() *identity.Details {
		return &identity.Details{
			ID:       integrationUser,
			Name:     "Ada Lovelace",
			Username: integrationAddress,
			Active:   true,
		}
	}

	h.users.EXPECT().LoadByUsername(gomock.Any(), integrationAddress).AnyTimes().
		DoAndReturn(func(context.Context, string) (*identity.Details, error) {
			return details(), nil
		})

	h.users.EXPECT().LoadByUserID(gomock.Any(), integrationUser).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			return details(), nil
		})

	h.users.EXPECT().LoadByUsername(gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, identity.ErrUserNotFound)
	h.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).AnyTimes().
		Return(nil, identity.ErrUserNotFound)
}

// wireTokens issues tokens that name the session they were issued for and
// verifies them back, which is what a real generator does through the jti and
// what makes a rotation observable from the client's side.
func (h *integrationHarness) wireTokens() {
	h.tokens.EXPECT().Generate(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, id string, _ *identity.Principal) (string, error) {
			return mfaTokenFor(id), nil
		})

	h.tokens.EXPECT().Verify(gomock.Any(), gomock.Any()).AnyTimes().
		DoAndReturn(func(_ context.Context, presented string) (*token.Claims, error) {
			id, ok := strings.CutPrefix(presented, mfaTokenPrefix)
			if !ok {
				return nil, errMFATokenUnreadable
			}

			return token.NewClaims(integrationAddress, id), nil
		})
}

// enrol gives the user a confirmed authenticator enrolment, then moves the
// clock past the step the confirmation spent, so the next code is a new one.
func (h *integrationHarness) enrol(ctx context.Context, t *testing.T) {
	t.Helper()

	provisioning, err := h.totp.BeginEnrolment(ctx, integrationUser, integrationAddress)
	require.NoError(t, err)

	h.secret = provisioning.Secret

	require.NoError(t, h.totp.ConfirmEnrolment(ctx, integrationUser, h.code(t)))

	h.clock.advance(2 * 30 * time.Second)

	enrolled, err := h.totp.Enrolled(ctx, integrationUser)
	require.NoError(t, err)
	require.True(t, enrolled)
}

// code is the code an authenticator would show at the current instant.
func (h *integrationHarness) code(t *testing.T) string {
	t.Helper()

	c, err := totp.GenerateCode(h.secret, h.clock.Now())
	require.NoError(t, err)

	return c
}

// buildChain wires all three methods into one chain behind the real
// second-factor policy.
func (h *integrationHarness) buildChain(t *testing.T) *httpsec.Chain {
	t.Helper()

	lookup, err := mfa.LookupFor(h.totp)
	require.NoError(t, err)

	challenge, err := policy.NewMFAPolicy(lookup)
	require.NoError(t, err)

	engine, err := policy.NewEngine(challenge)
	require.NoError(t, err)

	linkOpts := []httpsec.MagicLinkOption{
		httpsec.WithMagicLinkSessions(h.sessions),
		httpsec.WithMagicLinkTokens(h.tokens),
	}

	var keyOpts []httpsec.APIKeyOption

	if h.shared != nil {
		linkOpts = append(linkOpts, httpsec.WithMagicLinkLimiter(h.shared))
		keyOpts = append(keyOpts, httpsec.WithAPIKeyLimiter(h.shared))
	}

	c, err := httpsec.New(
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableMagicLink(h.links, linkOpts...),
		httpsec.EnableAPIKey(h.keys, keyOpts...),
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: h.tokens,
			Sessions: h.sessions,
			Users:    h.users,
		}),
		httpsec.EnableMFA(h.totp, httpsec.WithMFATokens(h.tokens)),
	)
	require.NoError(t, err)

	return c
}

// requestLink asks for a link from source and returns the token the message
// carried and the binding the browser now holds.
func (h *integrationHarness) requestLink(t *testing.T, source string) (token, nonce string) {
	t.Helper()

	out := serve(t, h.chain, postValues(t.Context(), httpsec.DefaultMagicLinkRequestPath,
		source, url.Values{"email": {integrationAddress}, "next": {"/"}}))
	require.NoError(t, out.err)
	require.Equal(t, http.StatusAccepted, out.rec.Code)

	cookie := cookieNamed(out.rec, httpsec.DefaultBindingCookieName)
	require.NotNil(t, cookie)

	return h.sender.lastToken(t), cookie.Value
}

// redeem posts a link back from source, as the confirmation page would.
func (h *integrationHarness) redeem(t *testing.T, source, link, nonce string) served {
	t.Helper()

	req := postValues(t.Context(), httpsec.DefaultMagicLinkConsumePath, source,
		url.Values{"token": {link}})
	if nonce != "" {
		req.AddCookie(bindingCookie(nonce))
	}

	return serve(t, h.chain, req)
}

// get requests a protected route with an access token, as a client does.
func (h *integrationHarness) get(t *testing.T, accessToken string) served {
	t.Helper()

	req := getFrom(t.Context(), "/invoices", integrationSource)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	return serve(t, h.chain, req)
}

// getWithKey requests a protected route with an API key, as a machine does.
func (h *integrationHarness) getWithKey(t *testing.T, source, key string) served {
	t.Helper()

	req := getFrom(t.Context(), "/invoices", source)
	req.Header.Set("Authorization", httpsec.DefaultAPIKeyScheme+key)

	return serve(t, h.chain, req)
}

// verify posts a code from source with the credential the caller currently
// holds.
func (h *integrationHarness) verify(t *testing.T, source, accessToken, code string) served {
	t.Helper()

	req := postValues(t.Context(), httpsec.DefaultMFAVerifyPath, source,
		url.Values{"code": {code}})
	req.Header.Set("Authorization", "Bearer "+accessToken)

	return serve(t, h.chain, req)
}

// accessTokenFrom reads the credential a verify response returned.
func accessTokenFrom(t *testing.T, out served) string {
	t.Helper()

	var body verifyBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)

	return body.AccessToken
}

// TestMagicLinkThenMFA is the whole flow a person goes through when a
// deployment runs passwordless sign-in behind a second-factor policy: ask for a
// link, follow it, be challenged, prove the second factor, and carry on — with
// nothing but the credentials the responses handed back.
func TestMagicLinkThenMFA(t *testing.T) {
	t.Parallel()

	h := newIntegrationHarness(t)

	// 1. A link is asked for and sent.
	link, nonce := h.requestLink(t, integrationSource)

	// 2. Following it spends the link and opens a session, which the policy
	//    challenges because the user has an authenticator enrolment on a
	//    channel other than the link's.
	redeemed := h.redeem(t, integrationSource, link, nonce)

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, redeemed.err, &ch)
	assert.Equal(t, policy.ChallengeMFA, ch.Kind)
	require.NotNil(t, ch.Session)
	assert.Equal(t, factor.MagicLink, ch.Session.FirstFactor)
	assert.Equal(t, session.MFAPending, ch.Session.MFA)
	require.NotEmpty(t, ch.Token, "the credential the prompt is answered with")

	pending := ch.Session.ID

	// The credential the login handed back. It is kept in its own variable
	// because the gate's refusal below carries no token — a gate challenges a
	// session that already exists, so it issues nothing.
	pendingToken := ch.Token

	// 3. That credential reaches nothing but the endpoints a pending session
	//    may reach.
	held := h.get(t, pendingToken)

	var gate *httpsec.ChallengeError
	require.ErrorAs(t, held.err, &gate)
	assert.Equal(t, policy.ChallengeMFA, gate.Kind)
	assert.Empty(t, gate.Token)
	assert.False(t, held.handlerRan, "the gate holds the protected route")

	// 4. The second factor is accepted and the handle rotates.
	verified := h.verify(t, integrationSource, pendingToken, h.code(t))
	require.NoError(t, verified.err)
	require.Equal(t, http.StatusOK, verified.rec.Code)

	rotated := accessTokenFrom(t, verified)
	assert.NotEqual(t, pendingToken, rotated,
		"the credential the caller carries away is a new one")

	_, err := h.sessions.Load(t.Context(), pending)
	require.Error(t, err, "the pre-MFA handle is gone")

	// 5. The protected route now serves — with the credential the verify
	//    response returned, which is all a real client has.
	served := h.get(t, rotated)
	require.NoError(t, served.err)
	assert.True(t, served.handlerRan)

	// And the credential the caller arrived with is dead.
	stale := h.get(t, pendingToken)
	require.ErrorIs(t, stale.err, httpsec.ErrAuthenticationRequired)
	assert.False(t, stale.handlerRan)
}

// TestAPIKeyBypassesMFAGate pins that a machine caller is unaffected by a
// second-factor policy. Its first factor is exempt, and it holds no session for
// the gate to judge.
func TestAPIKeyBypassesMFAGate(t *testing.T) {
	t.Parallel()

	h := newIntegrationHarness(t)

	out := h.getWithKey(t, integrationSource, h.apiKey)

	require.NoError(t, out.err)
	require.True(t, out.handlerRan, "a valid key reaches the application")
	require.NotNil(t, out.handled.Authentication)
	assert.Equal(t, integrationService, out.handled.Authentication.Principal.ID)
	assert.Nil(t, out.handled.Session, "and establishes no session")

	count, err := h.sessions.CountActiveByUser(t.Context(), integrationService)
	require.NoError(t, err)
	assert.Zero(t, count)
}

// TestFlowLimitersAreIndependent pins that exhausting one flow's allowance from
// a source leaves the other flows open to it. A shared bucket would let anyone
// who can guess links lock a deployment's machines out of its API.
//
// The second case asks the sharper question: a consumer who hands one limiter
// to both flows is choosing one store and one limit, not one allowance. The
// flow name is part of every key, so the two still count separately — and a
// deployment that wires one Redis limiter everywhere does not discover
// otherwise under attack.
func TestFlowLimitersAreIndependent(t *testing.T) {
	t.Parallel()

	t.Run("the default limiters", func(t *testing.T) {
		t.Parallel()

		assertFlowsAreIndependent(t, newIntegrationHarness(t))
	})

	t.Run("one limiter shared by both flows", func(t *testing.T) {
		t.Parallel()

		h := newIntegrationHarness(t)
		h.shareOneLimiter(t)

		assertFlowsAreIndependent(t, h)
	})
}

// assertFlowsAreIndependent exhausts the magic-link allowance for one source
// and then asks the other two flows to serve it.
func assertFlowsAreIndependent(t *testing.T, h *integrationHarness) {
	t.Helper()

	// A session that owes a second factor, established from another source so
	// the throttling below cannot be what refuses it.
	link, nonce := h.requestLink(t, otherSource)

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, h.redeem(t, otherSource, link, nonce).err, &ch)
	require.NotEmpty(t, ch.Token)

	// Exhaust the magic-link allowance from the source under test.
	for range 10 {
		require.ErrorIs(t, h.redeem(t, integrationSource, "wrong-token", nonce).err,
			magiclink.ErrInvalidLink)
	}

	second, secondNonce := h.requestLink(t, otherSource)
	require.ErrorIs(t, h.redeem(t, integrationSource, second, secondNonce).err,
		magiclink.ErrInvalidLink, "the source is throttled for redemptions")

	// The same source still authenticates by key.
	byKey := h.getWithKey(t, integrationSource, h.apiKey)
	require.NoError(t, byKey.err, "the API key flow keeps its own allowance")
	assert.True(t, byKey.handlerRan)

	// And still verifies a second-factor code.
	verified := h.verify(t, integrationSource, ch.Token, h.code(t))
	require.NoError(t, verified.err, "the code verification flow keeps its own allowance")
	assert.Equal(t, http.StatusOK, verified.rec.Code)
}
