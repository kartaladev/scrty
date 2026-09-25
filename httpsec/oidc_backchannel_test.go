package httpsec_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
	"github.com/kartaladev/scrty/session"
)

// otherIssuer is an issuer the test provider is not: sessions from it belong
// to another provider.
const otherIssuer = "https://b.example"

// offsetClock is the instant the OIDC manager judges token times at: the wall
// clock, moved forward by what a test advanced it.
type offsetClock struct {
	offset atomic.Int64

	// onRead, when set, runs every time the clock is read.
	onRead atomic.Pointer[func()]
}

func (c *offsetClock) Now() time.Time {
	if f := c.onRead.Load(); f != nil {
		(*f)()
	}

	return time.Now().Add(time.Duration(c.offset.Load()))
}

func (c *offsetClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// backchannelHarness is a federated-login chain with the sessions a
// back-channel logout is asked to end.
type backchannelHarness struct {
	*oidcHarness

	clock *offsetClock
	chain *httpsec.Chain

	// ctx is the context requests are served under.
	ctx context.Context

	// ids names the sessions a case created, by the label it gave them.
	ids map[string]string
}

func newBackchannelHarness(t *testing.T) *backchannelHarness {
	t.Helper()

	clock := &offsetClock{}

	return &backchannelHarness{
		oidcHarness: newOIDCHarness(t, oidc.WithClock(clock.Now)),
		clock:       clock,
		ctx:         t.Context(),
		ids:         map[string]string{},
	}
}

// cancelDuringVerification serves requests under a context that is cancelled
// while the manager verifies the logout token: the manager's clock is the
// last thing verification of an HS256 token consults, and nothing after it
// looks at the context, so the token still verifies and the caller is gone
// by the time sessions are ended.
func (h *backchannelHarness) cancelDuringVerification() {
	ctx, cancel := context.WithCancel(h.ctx)
	h.ctx = ctx

	f := func() { cancel() }
	h.clock.onRead.Store(&f)
}

// issuer is the test provider's issuer.
func (h *backchannelHarness) issuer() string { return h.provider.srv.URL }

// federated creates a session of the linked user from issuer with provider
// session sid, labelled label.
func (h *backchannelHarness) federated(t *testing.T, label, provider, issuer, sid string) {
	t.Helper()

	s, err := h.sessions.Create(t.Context(), oidcTestUserID,
		session.WithFirstFactor(factor.OIDC),
		session.WithExternalSession(provider, issuer, sid, oidcTestIDToken))
	require.NoError(t, err)

	h.ids[label] = s.ID
}

// password creates a password session of the linked user, labelled label.
func (h *backchannelHarness) password(t *testing.T, label string) {
	t.Helper()

	s, err := h.sessions.Create(t.Context(), oidcTestUserID, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	h.ids[label] = s.ID
}

// alive reports whether the session labelled label still loads.
func (h *backchannelHarness) alive(t *testing.T, label string) bool {
	t.Helper()

	id, ok := h.ids[label]
	require.True(t, ok, "no session labelled %q", label)

	_, err := h.sessions.Load(t.Context(), id)
	if errors.Is(err, session.ErrSessionNotFound) {
		return false
	}
	require.NoError(t, err)

	return true
}

// post delivers token to the test provider's back-channel endpoint, as the
// provider does: a form body, and no credential.
func (h *backchannelHarness) post(t *testing.T, token string) served {
	t.Helper()

	return h.serve(t, backchannelRequest(h.ctx, testOIDCProvider,
		"application/x-www-form-urlencoded", strings.NewReader(url.Values{"logout_token": {token}}.Encode())))
}

// serve runs req through the chain under h.ctx.
func (h *backchannelHarness) serve(t *testing.T, req *http.Request) served {
	t.Helper()

	out := served{rec: httptest.NewRecorder()}
	run := h.chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true
		out.handled = ex

		return nil
	})

	ex := httpsec.NewExchange(h.ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec))
	out.err = run(ex)

	return out
}

// backchannelRequest is a POST to provider's back-channel endpoint carrying
// body as contentType.
func backchannelRequest(ctx context.Context, provider, contentType string, body io.Reader) *http.Request {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost,
		httpsec.DefaultOIDCBackchannelPath+provider, body)
	req.Header.Set("Content-Type", contentType)

	return req
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))

	return n, err
}

// answeredEmpty asserts the back-channel's one answer to a verified token.
func answeredEmpty(t *testing.T, s served) {
	t.Helper()

	require.NoError(t, s.err)
	assert.Equal(t, http.StatusOK, s.rec.Code)
	assert.Empty(t, s.rec.Body.String(), "the answer says nothing about what was ended")
	assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"))
	assert.False(t, s.handlerRan)
}

// refusedInvalid asserts the back-channel's one refusal, which names no check.
func refusedInvalid(t *testing.T, s served) {
	t.Helper()

	require.ErrorIs(t, s.err, oidc.ErrInvalidLogoutToken)
	assert.Equal(t, http.StatusBadRequest, httpsec.StatusForError(s.err))
	assert.Empty(t, s.rec.Body.String())
	assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"))
	assert.False(t, s.handlerRan)
}

// failedAsServer asserts an outage surfaced as itself, not as a bad token.
func failedAsServer(t *testing.T, s served, cause error) {
	t.Helper()

	require.Error(t, s.err)
	if cause != nil {
		require.ErrorIs(t, s.err, cause)
	}
	assert.NotErrorIs(t, s.err, oidc.ErrInvalidLogoutToken)
	status := httpsec.StatusForError(s.err)
	assert.GreaterOrEqual(t, status, http.StatusInternalServerError)
	assert.False(t, s.handlerRan)
}

// TestOIDCBackchannel pins the back-channel logout endpoint: which sessions a
// verified token ends, that its answer reveals nothing, and that everything
// else is one uniform refusal or passes through.
func TestOIDCBackchannel(t *testing.T) {
	t.Parallel()

	errOutage := errors.New("store unavailable")

	type testCase struct {
		name string
		// setup creates the sessions the case needs and returns the options
		// EnableOIDCLogin gets; it may also replace h.manager.
		setup  func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption
		ctx    func(ctx context.Context) context.Context
		act    func(t *testing.T, h *backchannelHarness) served
		assert func(t *testing.T, h *backchannelHarness, s served)
	}

	twoFromIssuer := func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
		h.federated(t, "abc", testOIDCProvider, h.issuer(), "abc")
		h.federated(t, "def", testOIDCProvider, h.issuer(), "def")

		return nil
	}

	subjectOnly := func(t *testing.T, h *backchannelHarness) served {
		return h.post(t, h.provider.logoutToken(t, oidcTestSubject, ""))
	}

	cases := []testCase{
		{
			name:  "session id preferred over subject",
			setup: twoFromIssuer,
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.post(t, h.provider.logoutToken(t, oidcTestSubject, "abc"))
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.False(t, h.alive(t, "abc"))
				assert.True(t, h.alive(t, "def"), "only the named provider session ends")

				logs := h.logs.String()
				assert.Contains(t, logs, "flow=oidc.backchannel")
				assert.Contains(t, logs, "ended=1")
				assert.NotContains(t, logs, string(oidcTestUserID), "no user id is logged")
				assert.NotContains(t, logs, "eyJ", "no token is logged")
			},
		},
		{
			name:  "subject-only logout ends the user's sessions from the issuer",
			setup: twoFromIssuer,
			act:   subjectOnly,
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.False(t, h.alive(t, "abc"))
				assert.False(t, h.alive(t, "def"))
				assert.Contains(t, h.logs.String(), "ended=2")
			},
		},
		{
			name:  "an unlinked subject is a success that ends nothing",
			setup: twoFromIssuer,
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.post(t, h.provider.logoutToken(t, "sub-unlinked", ""))
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.True(t, h.alive(t, "abc"))
				assert.True(t, h.alive(t, "def"))
			},
		},
		{
			name: "a session id from another issuer ends nothing there",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				h.federated(t, "other", "other", otherIssuer, "abc")

				return nil
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.post(t, h.provider.logoutToken(t, "", "abc"))
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.True(t, h.alive(t, "other"))
			},
		},
		{
			name: "a password session survives a subject-only logout",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				h.password(t, "password")
				h.federated(t, "federated", testOIDCProvider, h.issuer(), "abc")

				return nil
			},
			act: subjectOnly,
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.False(t, h.alive(t, "federated"))
				assert.True(t, h.alive(t, "password"))
			},
		},
		{
			name: "another provider's session survives a subject-only logout",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				h.federated(t, "mine", testOIDCProvider, h.issuer(), "abc")
				h.federated(t, "other", "other", otherIssuer, "xyz")

				return nil
			},
			act: subjectOnly,
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.False(t, h.alive(t, "mine"))
				assert.True(t, h.alive(t, "other"))
			},
		},
		{
			name: "the consumer widens a subject-only logout to every session",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				h.password(t, "password")
				h.federated(t, "federated", testOIDCProvider, h.issuer(), "abc")

				return []httpsec.OIDCOption{httpsec.WithBackchannelLogoutScope(httpsec.AllSessions)}
			},
			act: subjectOnly,
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.False(t, h.alive(t, "federated"))
				assert.False(t, h.alive(t, "password"))
				assert.Contains(t, h.logs.String(), "reason=all_sessions", "a logout of every session is logged without a count")
				assert.NotContains(t, h.logs.String(), "ended=")
			},
		},
		{
			name: "the same answer whether three sessions ended or none",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				for _, l := range []string{"one", "two", "three"} {
					h.federated(t, l, testOIDCProvider, h.issuer(), l)
				}

				return nil
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				three := subjectOnly(t, h)
				none := h.post(t, h.provider.logoutToken(t, "", "no-such-session"))

				assert.Equal(t, three.rec.Code, none.rec.Code)
				assert.Equal(t, three.rec.Header(), none.rec.Header())
				assert.Equal(t, three.rec.Body.String(), none.rec.Body.String())
				answeredEmpty(t, three)

				return none
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.False(t, h.alive(t, "one"))
				assert.False(t, h.alive(t, "two"))
				assert.False(t, h.alive(t, "three"))

				logs := h.logs.String()
				assert.Contains(t, logs, "ended=3")
				assert.Contains(t, logs, "ended=0")
			},
		},
		{
			name: "a session store outage is a server failure, not a bad token",
			setup: func(t *testing.T, _ *backchannelHarness) []httpsec.OIDCOption {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().DeleteByExternalSession(gomock.Any(), gomock.Any(), "abc").Return(0, errOutage)

				m, err := session.NewManager(session.WithStore(store))
				require.NoError(t, err)

				return []httpsec.OIDCOption{httpsec.WithOIDCSessions(m)}
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.post(t, h.provider.logoutToken(t, oidcTestSubject, "abc"))
			},
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				failedAsServer(t, s, errOutage)
			},
		},
		{
			name: "a subject-scoped session store outage is a server failure",
			setup: func(t *testing.T, _ *backchannelHarness) []httpsec.OIDCOption {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), oidcTestUserID, gomock.Any()).
					Return(0, errOutage)

				m, err := session.NewManager(session.WithStore(store))
				require.NoError(t, err)

				return []httpsec.OIDCOption{httpsec.WithOIDCSessions(m)}
			},
			act: subjectOnly,
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				failedAsServer(t, s, errOutage)
			},
		},
		{
			name: "an all-sessions store outage is a server failure",
			setup: func(t *testing.T, _ *backchannelHarness) []httpsec.OIDCOption {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().DeleteByUser(gomock.Any(), oidcTestUserID).Return(errOutage)

				m, err := session.NewManager(session.WithStore(store))
				require.NoError(t, err)

				return []httpsec.OIDCOption{
					httpsec.WithOIDCSessions(m),
					httpsec.WithBackchannelLogoutScope(httpsec.AllSessions),
				}
			},
			act: subjectOnly,
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				failedAsServer(t, s, errOutage)
			},
		},
		{
			name: "a link store outage is a server failure",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				ctrl := gomock.NewController(t)
				links := NewMockLinkStore(ctrl)
				links.EXPECT().FindByExternal(gomock.Any(), testOIDCProvider, h.issuer(), oidcTestSubject).
					Return(nil, errOutage)

				broker, err := oidc.NewBroker(links, NewMockUserLoader(ctrl))
				require.NoError(t, err)

				h.manager = h.managerWith(t, broker, nil, oidc.WithClock(h.clock.Now))
				h.federated(t, "federated", testOIDCProvider, h.issuer(), "abc")

				return nil
			},
			act: subjectOnly,
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				failedAsServer(t, s, errOutage)
				assert.True(t, h.alive(t, "federated"))
			},
		},
		{
			name: "a link store answering no link and no error is a server failure",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				ctrl := gomock.NewController(t)
				links := NewMockLinkStore(ctrl)
				links.EXPECT().FindByExternal(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil, nil)

				broker, err := oidc.NewBroker(links, NewMockUserLoader(ctrl))
				require.NoError(t, err)

				h.manager = h.managerWith(t, broker, nil, oidc.WithClock(h.clock.Now))

				return nil
			},
			act: subjectOnly,
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				failedAsServer(t, s, nil)
			},
		},
		{
			name: "a consumer broker with no link store ends nothing for a subject and logs it",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				// No expectation: the broker is never consulted by a logout.
				broker := NewMockIdentityBroker(gomock.NewController(t))
				h.manager = h.managerWith(t, broker, nil, oidc.WithClock(h.clock.Now))
				h.federated(t, "federated", testOIDCProvider, h.issuer(), "abc")

				return nil
			},
			act: subjectOnly,
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.True(t, h.alive(t, "federated"))
				assert.Equal(t, 1, strings.Count(h.logs.String(), "reason=subject_unresolved"))
			},
		},
		{
			name: "a key set the provider cannot serve is a provider failure",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				h.manager = h.managerWith(t, NewMockIdentityBroker(gomock.NewController(t)),
					func(p *oidc.Provider) { p.SigningAlgs = []string{"RS256"} },
					oidc.WithClock(h.clock.Now))

				return nil
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				jwkKey, err := jwk.Import[jwk.Key](key)
				require.NoError(t, err)
				require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "k-1"))

				payload := h.provider.logoutClaims(time.Now(), oidcTestSubject, "abc")
				raw, err := json.Marshal(payload)
				require.NoError(t, err)

				signed, err := jws.Sign(raw, jws.WithKey(jwa.RS256(), jwkKey))
				require.NoError(t, err)

				return h.post(t, string(signed))
			},
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				failedAsServer(t, s, oidc.ErrDiscoveryFailed)
				assert.Equal(t, "no-store", s.rec.Header().Get("Cache-Control"))
			},
		},
		{
			name:  "a refused logout token leaves a sampled log record naming the cause",
			setup: twoFromIssuer,
			act: func(t *testing.T, h *backchannelHarness) served {
				tok := h.provider.signClaims(t, []byte(h.provider.provider().ClientSecret),
					h.provider.logoutClaims(time.Now().Add(-time.Hour), oidcTestSubject, "abc"))
				s := h.post(t, tok)

				logs := h.logs.String()
				assert.NotContains(t, logs, tok, "no token is logged")
				for _, part := range strings.Split(tok, ".") {
					assert.NotContains(t, logs, part, "no part of the token is logged")
				}

				return s
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				refusedInvalid(t, s)
				assert.True(t, h.alive(t, "abc"))

				logs := h.logs.String()
				assert.Contains(t, logs, "level=WARN")
				assert.Contains(t, logs, "flow=oidc.backchannel")
				assert.Contains(t, logs, "reason=invalid_token")
				assert.Contains(t, logs, "provider="+testOIDCProvider)
				assert.Contains(t, logs, "issued too long ago", "the record names the rule that failed")
				assert.NotContains(t, logs, oidcTestSubject, "no claim value is logged")
			},
		},
		{
			name:  "a forged token is refused without naming the check",
			setup: twoFromIssuer,
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.post(t, h.provider.signClaims(t, []byte("not-the-client-secret-0123456789abcdef"),
					h.provider.logoutClaims(time.Now(), oidcTestSubject, "abc")))
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				refusedInvalid(t, s)
				assert.True(t, h.alive(t, "abc"))
			},
		},
		{
			name:  "a request without a logout token is refused",
			setup: twoFromIssuer,
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.serve(t, backchannelRequest(t.Context(), testOIDCProvider,
					"application/x-www-form-urlencoded", strings.NewReader("other=value")))
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				refusedInvalid(t, s)
				assert.True(t, h.alive(t, "abc"))
			},
		},
		{
			name:  "a logout token in the query string is not read",
			setup: twoFromIssuer,
			act: func(t *testing.T, h *backchannelHarness) served {
				tok := h.provider.logoutToken(t, oidcTestSubject, "abc")
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
					httpsec.DefaultOIDCBackchannelPath+testOIDCProvider+"?"+
						url.Values{"logout_token": {tok}}.Encode(), strings.NewReader(""))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				return h.serve(t, req)
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				refusedInvalid(t, s)
				assert.True(t, h.alive(t, "abc"))
			},
		},
		{
			name:  "a JSON body is refused",
			setup: twoFromIssuer,
			act: func(t *testing.T, h *backchannelHarness) served {
				tok := h.provider.logoutToken(t, oidcTestSubject, "abc")

				return h.serve(t, backchannelRequest(t.Context(), testOIDCProvider,
					"application/json", strings.NewReader(`{"logout_token":"`+tok+`"}`)))
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				refusedInvalid(t, s)
				assert.True(t, h.alive(t, "abc"))
			},
		},
		{
			name:  "an oversized body is refused without reading past the bound",
			setup: twoFromIssuer,
			act: func(t *testing.T, h *backchannelHarness) served {
				tok := h.provider.logoutToken(t, oidcTestSubject, "abc")
				body := url.Values{
					"logout_token": {tok},
					"padding":      {strings.Repeat("x", 4*int(httpsec.DefaultLoginBodyLimit))},
				}.Encode()
				counted := &countingReader{r: strings.NewReader(body)}

				s := h.serve(t, backchannelRequest(t.Context(), testOIDCProvider,
					"application/x-www-form-urlencoded", counted))
				assert.LessOrEqual(t, counted.n.Load(), httpsec.DefaultLoginBodyLimit+1,
					"nothing past the bound is read")

				return s
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				refusedInvalid(t, s)
				assert.True(t, h.alive(t, "abc"))
			},
		},
		{
			name: "a GET passes through",
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.serve(t, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					httpsec.DefaultOIDCBackchannelPath+testOIDCProvider, nil))
			},
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name: "a path with a further segment passes through",
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.serve(t, backchannelRequest(t.Context(), testOIDCProvider+"/extra",
					"application/x-www-form-urlencoded", strings.NewReader("logout_token=x")))
			},
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
			},
		},
		{
			name: "an unknown provider is refused as unknown",
			act: func(t *testing.T, h *backchannelHarness) served {
				tok := h.provider.logoutToken(t, oidcTestSubject, "abc")
				counted := &countingReader{r: strings.NewReader(url.Values{"logout_token": {tok}}.Encode())}

				s := h.serve(t, backchannelRequest(t.Context(), "nobody",
					"application/x-www-form-urlencoded", counted))
				assert.Zero(t, counted.n.Load(), "the body of a delivery to an unknown provider is not read")

				return s
			},
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				require.ErrorIs(t, s.err, oidc.ErrUnknownProvider)
				assert.Equal(t, http.StatusNotFound, httpsec.StatusForError(s.err))
				assert.False(t, s.handlerRan)
			},
		},
		{
			name: "a replay inside the window ends a session created since",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				h.federated(t, "first", testOIDCProvider, h.issuer(), "abc")

				return nil
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				tok := h.provider.logoutToken(t, oidcTestSubject, "")
				answeredEmpty(t, h.post(t, tok))
				assert.False(t, h.alive(t, "first"))

				h.federated(t, "second", testOIDCProvider, h.issuer(), "def")
				h.clock.advance(oidc.DefaultLogoutTokenMaxAge / 2)

				return h.post(t, tok)
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				answeredEmpty(t, s)
				assert.False(t, h.alive(t, "second"), "a replay inside the window still ends sessions")
			},
		},
		{
			name: "a replay after the window is refused and ends nothing",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				h.federated(t, "first", testOIDCProvider, h.issuer(), "abc")

				return nil
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				tok := h.provider.logoutToken(t, oidcTestSubject, "")
				answeredEmpty(t, h.post(t, tok))

				h.federated(t, "second", testOIDCProvider, h.issuer(), "def")
				h.clock.advance(oidc.DefaultLogoutTokenMaxAge + oidc.DefaultClockSkew + time.Second)

				return h.post(t, tok)
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				refusedInvalid(t, s)
				assert.True(t, h.alive(t, "second"))
			},
		},
		{
			name: "a request cancelled after verification still ends the named sessions",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				twoFromIssuer(t, h)
				h.cancelDuringVerification()

				return nil
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.post(t, h.provider.logoutToken(t, oidcTestSubject, "abc"))
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				require.ErrorIs(t, h.ctx.Err(), context.Canceled, "the caller was gone before sessions were ended")
				answeredEmpty(t, s)
				assert.False(t, h.alive(t, "abc"))
				assert.True(t, h.alive(t, "def"))
			},
		},
		{
			name: "a session id logout reaches the store with a live context after the caller has gone",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				store := NewMockStore(gomock.NewController(t))
				store.EXPECT().DeleteByExternalSession(gomock.Any(), h.issuer(), "abc").
					DoAndReturn(func(ctx context.Context, _, _ string) (int, error) {
						return 1, ctx.Err()
					})

				m, err := session.NewManager(session.WithStore(store))
				require.NoError(t, err)

				h.cancelDuringVerification()

				return []httpsec.OIDCOption{httpsec.WithOIDCSessions(m)}
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.post(t, h.provider.logoutToken(t, oidcTestSubject, "abc"))
			},
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				answeredEmpty(t, s)
			},
		},
		{
			name: "a subject logout reaches the stores with a live context after the caller has gone",
			setup: func(t *testing.T, h *backchannelHarness) []httpsec.OIDCOption {
				ctrl := gomock.NewController(t)
				links := NewMockLinkStore(ctrl)
				links.EXPECT().FindByExternal(gomock.Any(), testOIDCProvider, h.issuer(), oidcTestSubject).
					DoAndReturn(func(ctx context.Context, _, _, _ string) (*oidc.Link, error) {
						return &oidc.Link{UserID: oidcTestUserID}, ctx.Err()
					})

				broker, err := oidc.NewBroker(links, NewMockUserLoader(ctrl))
				require.NoError(t, err)
				h.manager = h.managerWith(t, broker, nil, oidc.WithClock(h.clock.Now))

				store := NewMockStore(ctrl)
				store.EXPECT().DeleteByUserAndExternalIssuer(gomock.Any(), oidcTestUserID, h.issuer()).
					DoAndReturn(func(ctx context.Context, _ identity.UserID, _ string) (int, error) {
						return 1, ctx.Err()
					})

				m, err := session.NewManager(session.WithStore(store))
				require.NoError(t, err)

				h.cancelDuringVerification()

				return []httpsec.OIDCOption{httpsec.WithOIDCSessions(m)}
			},
			act: subjectOnly,
			assert: func(t *testing.T, _ *backchannelHarness, s served) {
				answeredEmpty(t, s)
			},
		},
		{
			name:  "a request cancelled before verification ends nothing",
			setup: twoFromIssuer,
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			act: func(t *testing.T, h *backchannelHarness) served {
				return h.post(t, h.provider.logoutToken(t, oidcTestSubject, "abc"))
			},
			assert: func(t *testing.T, h *backchannelHarness, s served) {
				require.ErrorIs(t, s.err, context.Canceled)
				assert.NotErrorIs(t, s.err, oidc.ErrInvalidLogoutToken)
				assert.True(t, h.alive(t, "abc"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newBackchannelHarness(t)

			var opts []httpsec.OIDCOption
			if tc.setup != nil {
				opts = tc.setup(t, h)
			}

			h.chain = h.oidcHarness.chain(t, opts...)

			if tc.ctx != nil {
				h.ctx = tc.ctx(h.ctx)
			}

			s := tc.act(t, h)
			tc.assert(t, h, s)
		})
	}
}
