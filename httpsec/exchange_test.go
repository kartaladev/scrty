package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// miniExchange is a framework of this test's own: a request of plain values,
// and a response of a header map and a byte buffer.
//
// It exists to prove that Request and ResponseWriter really are the public
// adapter contract. A consumer supports a framework this library has never
// heard of by implementing the two, and changes no interceptor to do it — so
// the outcomes a chain produces over this stand-in must be the ones it produces
// over net/http, byte for byte.
type miniExchange struct {
	method string

	// target is the request target, query string included, because a framework
	// that carried the path and the query separately would be hiding the split
	// the abstraction leaves to the adapter.
	target string

	header map[string]string
	body   []byte
	peer   string

	// query and form are parsed once, lazily, the way a framework parses them.
	query url.Values
	form  url.Values

	status    int
	outHeader http.Header
	out       []byte
	cookies   []*httpsec.Cookie

	// wrote records that a status has been chosen, so a second one is ignored
	// exactly as the net/http writer ignores it.
	wrote bool
}

// The stand-in satisfies the ports the chain runs on, so a change to either is
// a compile error here rather than a surprise for a consumer writing their own
// integration.
var (
	_ httpsec.Request        = (*miniRequest)(nil)
	_ httpsec.ResponseWriter = (*miniWriter)(nil)
)

// miniRequest reads the consumer's framework through the library's port.
type miniRequest struct{ ex *miniExchange }

func (r *miniRequest) Method() string { return r.ex.method }

func (r *miniRequest) Path() string {
	path, _, _ := strings.Cut(r.ex.target, "?")

	return path
}

func (r *miniRequest) Header(name string) string { return r.ex.header[http.CanonicalHeaderKey(name)] }

func (r *miniRequest) Query(name string) string {
	if r.ex.query == nil {
		_, raw, _ := strings.Cut(r.ex.target, "?")
		r.ex.query, _ = url.ParseQuery(raw)
	}

	return r.ex.query.Get(name)
}

func (r *miniRequest) QueryValues(name string) []string {
	r.Query(name) // parses the query on first use

	return r.ex.query[name]
}

// FormValue carries this framework's own semantics, which are net/http's: the
// posted form first, the query behind it. What an interceptor may read a
// credential from is the interceptor's decision, not the adapter's.
func (r *miniRequest) FormValue(name string) string {
	if r.ex.form == nil {
		r.ex.form, _ = url.ParseQuery(string(r.ex.body))
	}

	if v := r.ex.form.Get(name); v != "" {
		return v
	}

	return r.Query(name)
}

func (r *miniRequest) Cookie(name string) (string, bool) {
	raw := r.Header("Cookie")
	for part := range strings.SplitSeq(raw, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && key == name {
			return value, true
		}
	}

	return "", false
}

// Body returns what the framework buffered, bounded by limit. An oversized body
// is refused with the library's own sentinel rather than truncated, because a
// truncated body is one an interceptor would go on to parse.
func (r *miniRequest) Body(limit int64) ([]byte, error) {
	if int64(len(r.ex.body)) > limit {
		return nil, httpsec.ErrRequestTooLarge
	}

	return r.ex.body, nil
}

func (r *miniRequest) ClientIP() string { return r.ex.peer }

// miniWriter writes the consumer's framework through the library's port.
type miniWriter struct{ ex *miniExchange }

func (w *miniWriter) SetHeader(name, value string) {
	if w.ex.outHeader == nil {
		w.ex.outHeader = http.Header{}
	}

	w.ex.outHeader.Set(name, value)
}

func (w *miniWriter) SetCookie(c *httpsec.Cookie) { w.ex.cookies = append(w.ex.cookies, c) }

func (w *miniWriter) WriteHeader(status int) {
	if w.ex.wrote {
		return
	}

	w.ex.wrote, w.ex.status = true, status
}

func (w *miniWriter) Write(b []byte) (int, error) {
	if !w.ex.wrote {
		w.ex.wrote, w.ex.status = true, http.StatusOK
	}

	w.ex.out = append(w.ex.out, b...)

	return len(b), nil
}

// outcome is what one request produced, whichever framework carried it.
type outcome struct {
	status      int
	contentType string
	body        string
	err         error

	// caller is the principal the chain published for the handler, and "" when
	// it published none.
	caller identity.UserID

	handlerRan bool
}

// mintedInstant matches the one value in a login document that a clock decides.
var mintedInstant = regexp.MustCompile(`"valid_until":"[^"]*"`)

// comparable is the outcome with the parts a clock decides blanked out.
//
// The two runs open their own sessions, and the default login document carries
// that session's idle expiry, so the two instants differ by however long the
// first run took. Everything else in the body is still compared byte for byte,
// and the row asserts the token itself.
func (o outcome) comparable() outcome {
	o.body = mintedInstant.ReplaceAllString(o.body, `"valid_until":""`)

	return o
}

// TestConsumerAdapter pins that a consumer running the chain on a framework
// this library has never heard of gets the same outcomes as a consumer on
// net/http.
//
// Each row is served twice, once over each framework, with its own doubles: the
// chain is built from the same options both times, and the two outcomes must
// agree on the status, the library-set headers, the body and the refusal. That
// is the whole claim the abstraction makes — implement Request and
// ResponseWriter, change no interceptor.
func TestConsumerAdapter(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// build wires the doubles one run needs and returns the chain. It is
		// called once per framework, so neither run is credited with the other's
		// recorded calls.
		build func(t *testing.T, h *authHarness) *httpsec.Chain

		exchange func() *miniExchange

		assert func(t *testing.T, got outcome)
	}

	cases := []testCase{
		{
			name: "form login",
			build: func(t *testing.T, h *authHarness) *httpsec.Chain {
				t.Helper()

				h.expectAuthenticated(testPrincipal())
				h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil)
				h.expectSessionOpened("tok-1")

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableFormLogin(h.formLoginDeps()))
				require.NoError(t, err)

				return chain
			},
			exchange: func() *miniExchange {
				return &miniExchange{
					method: http.MethodPost,
					target: "/login",
					header: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: []byte("username=ada&password=s3cret"),
					peer: "198.51.100.7",
				}
			},
			assert: func(t *testing.T, got outcome) {
				require.NoError(t, got.err)
				assert.Equal(t, http.StatusOK, got.status)
				assert.Equal(t, "application/json", got.contentType)
				assert.Contains(t, got.body, `"access_token":"tok-1"`)
				assert.False(t, got.handlerRan, "the chain answered the login itself")
			},
		},
		{
			name: "bearer authentication",
			build: func(t *testing.T, h *authHarness) *httpsec.Chain {
				t.Helper()

				h.expectVerified()
				h.expectLiveSessionAndUser(liveSession())

				chain, err := httpsec.New(
					httpsec.WithLogger(h.logger()),
					httpsec.EnableBearerToken(h.bearerTokenDeps()))
				require.NoError(t, err)

				return chain
			},
			exchange: func() *miniExchange {
				return &miniExchange{
					method: http.MethodGet,
					target: "/orders",
					header: map[string]string{"Authorization": "Bearer abc.def.ghi"},
					peer:   "198.51.100.7",
				}
			},
			assert: func(t *testing.T, got outcome) {
				require.NoError(t, got.err)
				assert.True(t, got.handlerRan, "an authenticated request reaches the handler")
				assert.Equal(t, identity.UserID("u-1"), got.caller,
					"the handler reads the caller the chain resolved")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reference := serveOverNetHTTP(t, tc.build(t, newAuthHarness(t)), tc.exchange())
			consumer := serveOverMiniFramework(t, tc.build(t, newAuthHarness(t)), tc.exchange())

			tc.assert(t, reference)
			tc.assert(t, consumer)

			assert.Equal(t, reference.comparable(), consumer.comparable(),
				"a consumer's own adapter produces what net/http produces")
		})
	}
}

// serveOverMiniFramework runs one request through chain over the consumer's own
// adapter, answering a refusal the way the library's own entrypoint does.
func serveOverMiniFramework(
	t *testing.T, chain *httpsec.Chain, ex *miniExchange,
) outcome {
	t.Helper()

	var got outcome

	run := chain.Assemble(func(e *httpsec.Exchange) error {
		got.handlerRan = true

		if p, ok := identity.PrincipalFromContext(e.Context()); ok {
			got.caller = p.ID
		}

		return nil
	})

	writer := &miniWriter{ex: ex}

	err := run(httpsec.NewExchange(t.Context(), &miniRequest{ex: ex}, writer))
	if err != nil {
		// The library's own default, reproduced: the mapped status and no body.
		writer.WriteHeader(httpsec.StatusForError(err))
	}

	got.err = err

	// A response nothing wrote a status to is 200, which is what every HTTP
	// server answers and what the net/http recorder reports.
	got.status = ex.status
	if !ex.wrote {
		got.status = http.StatusOK
	}

	got.contentType = ex.outHeader.Get("Content-Type")
	got.body = string(ex.out)

	return got
}

// serveOverNetHTTP runs the same request through chain over the library's own
// net/http adapter, which is what the consumer's adapter is compared against.
func serveOverNetHTTP(t *testing.T, chain *httpsec.Chain, ex *miniExchange) outcome {
	t.Helper()

	var got outcome

	req := httptest.NewRequestWithContext(
		t.Context(), ex.method, ex.target, strings.NewReader(string(ex.body)))
	for name, value := range ex.header {
		req.Header.Set(name, value)
	}

	req.RemoteAddr = ex.peer + ":54321"

	rec := httptest.NewRecorder()

	run := chain.Assemble(func(e *httpsec.Exchange) error {
		got.handlerRan = true

		if p, ok := identity.PrincipalFromContext(e.Context()); ok {
			got.caller = p.ID
		}

		return nil
	})

	writer := httpsec.NewHTTPResponseWriter(rec)

	err := run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), writer))
	if err != nil {
		writer.WriteHeader(httpsec.StatusForError(err))
	}

	got.err = err
	got.status = rec.Code
	got.contentType = rec.Header().Get("Content-Type")
	got.body = rec.Body.String()

	return got
}

func TestExchangeContext(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		ctx    func(ctx context.Context) context.Context // nil means identity
		act    func(ex *httpsec.Exchange)
		assert func(t *testing.T, ex *httpsec.Exchange)
	}

	cases := []testCase{
		{
			name: "derives from the seed context",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-1")
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				assert.Equal(t, "r-1", ex.Context().Value(ctxKey("request-id")))
			},
		},
		{
			name: "SetContext is visible to a later reader",
			act: func(ex *httpsec.Exchange) {
				ex.SetContext(context.WithValue(ex.Context(), ctxKey("principal"), "alice"))
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				assert.Equal(t, "alice", ex.Context().Value(ctxKey("principal")))
			},
		},
		{
			name: "SetContext ignores a nil context rather than losing the one it has",
			ctx: func(ctx context.Context) context.Context {
				return context.WithValue(ctx, ctxKey("request-id"), "r-2")
			},
			act: func(ex *httpsec.Exchange) {
				ex.SetContext(nil) //nolint:staticcheck // the point of the case
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				require.NotNil(t, ex.Context())
				assert.Equal(t, "r-2", ex.Context().Value(ctxKey("request-id")))
			},
		},
		{
			name: "cancellation on the seed reaches the exchange",
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()
				return cctx
			},
			assert: func(t *testing.T, ex *httpsec.Exchange) {
				require.ErrorIs(t, ex.Context().Err(), context.Canceled)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			ex := httpsec.NewExchange(ctx, stubRequest{}, &stubWriter{})
			require.NotNil(t, ex)
			if tc.act != nil {
				tc.act(ex)
			}
			tc.assert(t, ex)
		})
	}
}

func TestExchangeCarriesTheRequestAndWriter(t *testing.T) {
	t.Parallel()

	req := stubRequest{method: "GET", path: "/health"}
	w := &stubWriter{}

	ex := httpsec.NewExchange(t.Context(), req, w)
	require.NotNil(t, ex)
	assert.Equal(t, "/health", ex.Request.Path())
	assert.Same(t, w, ex.Writer)
}

func TestInterceptorFunc(t *testing.T) {
	t.Parallel()

	called := false
	var i httpsec.Interceptor = httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		called = true
		return next(ex)
	})

	ex := httpsec.NewExchange(t.Context(), stubRequest{}, &stubWriter{})
	require.NotNil(t, ex)

	reached := false
	err := i.Intercept(ex, func(*httpsec.Exchange) error {
		reached = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called, "the adapted function was not run")
	assert.True(t, reached, "the adapted function did not continue the chain")
}

// TestPublishSession_Family pins that a session belonging to no family is
// refused by Exchange.PublishSession and publishes nothing, while a result
// published with no session is unaffected.
func TestPublishSession_Family(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// publish is the consumer interceptor's call, given the fixture's
		// session and the caller's authentication result.
		publish func(ex *httpsec.Exchange, a *authenticate.Authentication, s *session.Session) error

		assert func(t *testing.T, out served)
	}

	refused := func(t *testing.T, out served) {
		t.Helper()

		require.Error(t, out.err)
		assert.False(t, out.handlerRan, "the handler is not reached")
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
		assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)

		for _, sentinel := range []error{
			session.ErrNotFound, session.ErrExpired, session.ErrUnreadable,
			session.ErrReused, session.ErrRenewalRequired, session.ErrRenewalConflict,
			session.ErrSuccessorAdvanced, session.ErrSuperseded, session.ErrConfig,
		} {
			assert.NotErrorIs(t, out.err, sentinel)
		}
	}

	cases := []testCase{
		{
			name: "a session with no family is refused",
			publish: func(ex *httpsec.Exchange, a *authenticate.Authentication, s *session.Session) error {
				familyless := *s
				familyless.FamilyID = id.Nil

				err := ex.PublishSession(a, &familyless)

				// Nothing is published even when the interceptor ignores the error.
				_, ok := httpsec.SessionFromContext(ex.Context())
				assert.False(t, ok, "no session is published")
				_, ok = identity.PrincipalFromContext(ex.Context())
				assert.False(t, ok, "no caller is published")
				assert.Nil(t, ex.Session)
				assert.Nil(t, ex.Authentication)

				return err
			},
			assert: refused,
		},
		{
			name: "a family-less session with no result is refused too",
			publish: func(ex *httpsec.Exchange, _ *authenticate.Authentication, s *session.Session) error {
				familyless := *s
				familyless.FamilyID = id.Nil

				err := ex.PublishSession(nil, &familyless)

				_, ok := httpsec.SessionFromContext(ex.Context())
				assert.False(t, ok, "no session is published")
				assert.Nil(t, ex.Session)

				return err
			},
			assert: refused,
		},
		{
			name: "a result with no session is published",
			publish: func(ex *httpsec.Exchange, a *authenticate.Authentication, _ *session.Session) error {
				return ex.PublishSession(a, nil)
			},
			assert: func(t *testing.T, out served) {
				require.NoError(t, out.err)
				require.True(t, out.handlerRan)

				caller, ok := identity.PrincipalFromContext(out.handled.Context())
				require.True(t, ok, "the caller is visible to the handler")
				assert.Equal(t, identity.UserID("u-1"), caller.ID)

				_, ok = httpsec.SessionFromContext(out.handled.Context())
				assert.False(t, ok, "no session was published")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)
			require.NotEqual(t, id.Nil, f.session.FamilyID, "the fixture's session has a family")

			consumer := httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
				details := storedUser()
				a := &authenticate.Authentication{
					Principal:         identity.PrincipalFromDetails(details),
					Time:              f.clk.Now(),
					PasswordChangedAt: details.PasswordChangedAt,
				}

				if err := tc.publish(ex, a, f.session); err != nil {
					return err
				}

				return next(ex)
			})

			chain, err := httpsec.New(
				httpsec.WithSessions(f.sessions),
				httpsec.RegisterInterceptor(consumer, httpsec.OrderBearerToken),
			)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, bearerRequest(t.Context(), "")))
		})
	}
}
