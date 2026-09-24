package httpsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// bearerChain is the chain a real deployment runs: a bearer first factor that
// resolves the session a token names, and the second factor behind it. It is
// what makes rotation observable end to end — the credential a caller holds
// names a session, and rotation moves the session out from under it.
func (h *mfaHarness) bearerChain(t *testing.T) *httpsec.Chain {
	t.Helper()

	mfaOpts := append([]httpsec.MFAOption{
		httpsec.WithMFAVerifyLimiter(h.limiter),
		httpsec.WithMFATokens(h.tokens),
	}, h.mfaOpts...)

	c, err := httpsec.New(
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: h.tokens,
			Sessions: h.sessions,
			Users:    h.users,
		}),
		httpsec.EnableMFA(h.method, mfaOpts...),
	)
	require.NoError(t, err)

	return c
}

// buildChain is bearerChain without the assertion, for the cases that are
// about the construction error itself.
func (h *mfaHarness) buildChain(t *testing.T) (*httpsec.Chain, error) {
	t.Helper()

	mfaOpts := append([]httpsec.MFAOption{
		httpsec.WithMFAVerifyLimiter(h.limiter),
		httpsec.WithMFATokens(h.tokens),
	}, h.mfaOpts...)

	return httpsec.New(
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
			Verifier: h.tokens,
			Sessions: h.sessions,
			Users:    h.users,
		}),
		httpsec.EnableMFA(h.method, mfaOpts...),
	)
}

// bearerRequestTo is a request carrying an access token, as a client that has
// logged in makes.
func bearerRequestTo(ctx context.Context, method, path, token, body string) *http.Request {
	var req *http.Request

	if method == http.MethodPost {
		req = formRequest(ctx, path, body)
	} else {
		req = httptest.NewRequestWithContext(ctx, method, path, nil)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return req
}

// verifyBody is the response document a successful verification answers with,
// read back the way a client would.
type verifyBody struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ValidUntil   time.Time `json:"valid_until"`
}

// TestMFAVerifyDoesNotStrandCaller pins the defect that made the responder
// necessary.
//
// The session identifier is the token's jti, so rotating the handle kills the
// token the caller arrived with. An endpoint that answers a bare 200 therefore
// signs a user out for passing their second factor, and the caller has no way
// to learn the handle that replaced theirs.
func TestMFAVerifyDoesNotStrandCaller(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()

	c := h.bearerChain(t)

	s := h.pendingSession(t, factor.Password)
	loginToken := mfaTokenFor(s.ID)

	out := serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
		httpsec.DefaultMFAVerifyPath, loginToken, "code="+testMFACode))
	require.NoError(t, out.err)

	var got verifyBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &got),
		"the verify response carries a credential for the rotated session")
	require.NotEmpty(t, got.AccessToken)
	assert.NotEqual(t, loginToken, got.AccessToken,
		"the pre-MFA token named the session that rotation deleted")
	assert.False(t, got.ValidUntil.IsZero(), "and says how long it is good for")

	// The credential the response returned works on a protected route.
	reached := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/invoices",
		got.AccessToken, ""))
	require.NoError(t, reached.err,
		"a caller that completed its second factor is not signed out")
	assert.True(t, reached.handlerRan)

	// And the credential it arrived with is genuinely dead, which is the
	// symptom this test exists to pin.
	stranded := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/invoices",
		loginToken, ""))
	require.ErrorIs(t, stranded.err, httpsec.ErrAuthenticationRequired,
		"the handle the caller arrived with no longer loads")
	assert.False(t, stranded.handlerRan)
}

// TestMFAVerifySatisfiedSessionPassesTheGate pins the other half of not being
// stranded: the rotated session carries its satisfied second factor, so the
// gate lets it through rather than challenging it again.
func TestMFAVerifySatisfiedSessionPassesTheGate(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()

	c := h.bearerChain(t)
	s := h.pendingSession(t, factor.Password)

	// Before: the gate holds every other request this session makes.
	held := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/invoices",
		mfaTokenFor(s.ID), ""))

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, held.err, &ch)

	out := serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
		httpsec.DefaultMFAVerifyPath, mfaTokenFor(s.ID), "code="+testMFACode))
	require.NoError(t, out.err)

	var got verifyBody
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &got))

	after := serve(t, c, bearerRequestTo(t.Context(), http.MethodGet, "/invoices",
		got.AccessToken, ""))
	require.NoError(t, after.err)
	assert.True(t, after.handlerRan)

	rotated := h.stored(t, h.rotatedID(t))
	assert.Equal(t, session.MFASatisfied, rotated.MFA)
}

// rotatedID is the identifier the last access token was issued against.
func (h *mfaHarness) rotatedID(t *testing.T) string {
	t.Helper()

	id, _ := h.issuedFor.Load().(string)
	require.NotEmpty(t, id, "no token was issued, so no handle was published")

	return id
}

// errMFAResponder is what a consumer's responder refuses with, so a test can
// assert the chain returned that error and not one of its own.
var errMFAResponder = errors.New("mfaresponder_test: the client cannot be answered")

// TestMFAVerifyResponder pins what writes the response to a successful second
// factor, and what happens when it will not.
func TestMFAVerifyResponder(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.MFAOption
		assert func(t *testing.T, h *mfaHarness, previous string, out served, buildErr error)
	}

	cases := []testCase{
		{
			name: "the default names the rotated session and not the previous one",
			assert: func(t *testing.T, h *mfaHarness, previous string, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.NoError(t, out.err)

				assert.Equal(t, http.StatusOK, out.rec.Code)
				assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))

				var body verifyBody
				require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &body))

				rotated := h.rotatedID(t)
				assert.NotEqual(t, previous, rotated, "the handle moved")
				assert.Equal(t, mfaTokenFor(rotated), body.AccessToken,
					"the credential names the session that now exists")
				assert.Empty(t, body.RefreshToken,
					"the field is present and empty, as a login's is")
				assert.False(t, body.ValidUntil.IsZero())
			},
		},
		{
			name: "a responder error refuses the request",
			opts: []httpsec.MFAOption{httpsec.WithMFAResponder(
				func(*httpsec.Exchange, httpsec.MFAResult) error { return errMFAResponder },
			)},
			assert: func(t *testing.T, _ *mfaHarness, _ string, out served, buildErr error) {
				require.NoError(t, buildErr)
				require.ErrorIs(t, out.err, errMFAResponder,
					"the consumer's error is the refusal, unchanged")
			},
		},
		{
			name: "a nil responder is a configuration error",
			opts: []httpsec.MFAOption{httpsec.WithMFAResponder(nil)},
			assert: func(t *testing.T, _ *mfaHarness, _ string, _ served, buildErr error) {
				require.ErrorIs(t, buildErr, httpsec.ErrConfig,
					"a responder that is not there would leave the caller with no credential")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)
			h.mfaOpts = tc.opts

			c, buildErr := h.buildChain(t)
			if buildErr != nil {
				tc.assert(t, h, "", served{}, buildErr)

				return
			}

			h.allows().accepts().recordsNoFailure()

			s := h.pendingSession(t, factor.Password)

			out := serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
				httpsec.DefaultMFAVerifyPath, mfaTokenFor(s.ID), "code="+testMFACode))

			tc.assert(t, h, s.ID, out, nil)
		})
	}
}

// TestMFAVerifyConsumerResponder pins that a consumer's responder replaces the
// default entirely and is handed the rotated session, which is the only place
// the new handle is available.
func TestMFAVerifyConsumerResponder(t *testing.T) {
	t.Parallel()

	var seen httpsec.MFAResult

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).allows().accepts().recordsNoFailure()
	h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAResponder(
		func(ex *httpsec.Exchange, r httpsec.MFAResult) error {
			seen = r
			ex.Writer.SetCookie(&http.Cookie{
				Name:     "session",
				Value:    r.Token,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})

			return nil
		})}

	c, err := h.buildChain(t)
	require.NoError(t, err)

	s := h.pendingSession(t, factor.Password)

	out := serve(t, c, bearerRequestTo(t.Context(), http.MethodPost,
		httpsec.DefaultMFAVerifyPath, mfaTokenFor(s.ID), "code="+testMFACode))
	require.NoError(t, out.err)

	assert.Empty(t, out.rec.Body.String(), "the consumer's responder replaces the default entirely")

	require.NotNil(t, seen.Session)
	assert.Equal(t, h.rotatedID(t), seen.Session.ID, "the responder receives the rotated session")
	assert.NotEqual(t, s.ID, seen.Session.ID)
	assert.Equal(t, mfaTokenFor(seen.Session.ID), seen.Token)

	cookie := cookieNamed(out.rec, "session")
	require.NotNil(t, cookie, "and its own response reached the client")
	assert.Equal(t, seen.Token, cookie.Value)
}

// TestMFAVerifyWithoutResolvedCaller pins that a session alone is not enough.
// The response hands back a credential issued for somebody, so a session whose
// first factor published no caller is refused before the code is read — rather
// than reaching the point where there is nobody to issue a token to.
func TestMFAVerifyWithoutResolvedCaller(t *testing.T) {
	t.Parallel()

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()

	s := h.pendingSession(t, factor.Password)

	sessionOnly := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		ex.Session = s
		ex.SetContext(httpsec.WithSession(ex.Context(), s))

		return next(ex)
	})

	c, err := httpsec.New(
		httpsec.RegisterInterceptor(sessionOnly, httpsec.Before(httpsec.OrderMFAChallenge)),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}),
		httpsec.EnableMFA(h.method,
			httpsec.WithMFAVerifyLimiter(h.limiter),
			httpsec.WithMFATokens(h.tokens)),
	)
	require.NoError(t, err)

	out := serve(t, c, postCode(t.Context(), httpsec.DefaultMFAVerifyPath))

	require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
	assert.Equal(t, session.MFAPending, h.stored(t, s.ID).MFA, "the challenge stays pending")
}
