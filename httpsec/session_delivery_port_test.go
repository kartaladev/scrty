package httpsec_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/passkey"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// errDeliveryDown is the failure a consumer delivery reports.
var errDeliveryDown = errors.New("delivery_port_test: the audit log is unreachable")

// errDeliveryPanic is the value a consumer delivery panics with.
var errDeliveryPanic = errors.New("delivery_port_test: the delivery panicked")

// misbehaviour is what a consumer delivery does in place of the well-behaved
// one, handed the delivery itself so it can record what it saw.
type misbehaviour func(d *auditDelivery, ex *httpsec.Exchange, s *session.Session, credential string) (string, error)

// auditDelivery is a consumer's session delivery: it sets the session cookie
// with the default attributes and records an audit entry naming the session,
// and misbehaves as misbehave says on the requests misbehaves selects.
type auditDelivery struct {
	mu      sync.Mutex
	entries []string
	saw     []string

	// misbehaves picks the requests on which misbehave runs in place of the
	// well-behaved delivery; nil picks none.
	misbehaves func(ex *httpsec.Exchange) bool
	misbehave  misbehaviour

	// cancel ends the request the case is running, for a delivery that
	// outlives its client's hang-up. kept is the exchange a delivery held on
	// to. Both are set and read on the request's goroutine.
	cancel context.CancelFunc
	kept   *httpsec.Exchange

	// probed is what a delivery's calls on its exchange copy returned.
	probed []error
}

// sessionCookieFor is the session cookie carrying value with the default
// attributes, as a consumer delivery writes it.
func sessionCookieFor(value string) *http.Cookie {
	return &http.Cookie{
		Name: httpsec.DefaultSessionCookieName, Value: value, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	}
}

func (d *auditDelivery) Deliver(ex *httpsec.Exchange, s *session.Session, credential string) (string, error) {
	if d.misbehaves != nil && d.misbehaves(ex) {
		d.mu.Lock()
		d.saw = append(d.saw, credential)
		d.mu.Unlock()

		return d.misbehave(d, ex, s, credential)
	}

	ex.Writer.SetCookie(sessionCookieFor(credential))

	d.mu.Lock()
	defer d.mu.Unlock()

	d.entries = append(d.entries, s.ID)

	return "", nil
}

// audited is what the delivery recorded, in order.
func (d *auditDelivery) audited() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]string(nil), d.entries...)
}

// seen is the identifiers the misbehaving delivery was handed, in order.
func (d *auditDelivery) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	return append([]string(nil), d.saw...)
}

// onPath selects the requests to path.
func onPath(path string) func(ex *httpsec.Exchange) bool {
	return func(ex *httpsec.Exchange) bool { return ex.Request.Path() == path }
}

// everywhere selects every request.
func everywhere(*httpsec.Exchange) bool { return true }

// deliveryRun is one case's world, its delivery, the chain's log and what the
// last request answered.
type deliveryRun struct {
	w    *browserWorld
	d    *auditDelivery
	logs *lockedBuffer
	out  served

	// rec is the recorder of a request a case ran itself.
	rec *httptest.ResponseRecorder
}

// idsEnded asserts none of ids authenticates any more: each is gone from the
// store, superseded ones included.
func idsEnded(t *testing.T, sessions *session.Sessions, ids ...string) {
	t.Helper()

	for _, id := range ids {
		_, err := sessions.Load(t.Context(), id)
		require.Error(t, err, "an identifier the delivery saw still authenticates")
	}
}

// refusedUndelivered asserts out is an issuing failure that wrote nothing at
// all.
func refusedUndelivered(t *testing.T, out served) {
	t.Helper()
	require.Error(t, out.err)

	var ch *httpsec.ChallengeError
	assert.False(t, errors.As(out.err, &ch), "no challenge is answered")
	assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err), "an issuing failure")
	assert.Empty(t, out.rec.Header().Values("Set-Cookie"), "no cookie is set or expired")
	assert.Empty(t, out.rec.Header().Values("X-Audited"), "nothing the delivery wrote reaches the response")
	assert.Empty(t, out.rec.Body.String())
}

// breaking is a delivery that sets the session cookie as mutate leaves it,
// beside nothing else.
func breaking(mutate func(c *http.Cookie)) misbehaviour {
	return func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
		c := sessionCookieFor(credential) //nolint:gosec // G124: the case is a delivery breaking the line on purpose
		mutate(c)
		ex.Writer.SetCookie(c)

		return "", nil
	}
}

// TestSessionCookie_DeliveryPort pins that a consumer may replace how a
// cookie chain writes the session cookie, and that a replacement cannot hand
// the identifier anywhere a script could read it, cannot weaken the cookie
// the chain would set, and cannot change what the endpoint publishes or
// stores: one that returns a body credential, fails, writes a body, puts the
// identifier in a header, a header name or another cookie's name, value or
// path, sets the cookie with other attributes than the chain's or sets none is
// an issuing failure, on a fresh sign-in, a challenged one, a renewal and
// every other rotation alike. Nothing it wrote reaches the response, nothing
// else is written either, and the sign-in it was handed is ended, so the
// identifier it saw authenticates nothing, even when the client hung up.
func TestSessionCookie_DeliveryPort(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// enrol enrols the user on TOTP first, so the sign-in is challenged.
		enrol bool

		misbehaves func(ex *httpsec.Exchange) bool
		misbehave  misbehaviour

		// act runs the requests and returns the last one's answer.
		act func(t *testing.T, r *deliveryRun) served

		assert func(t *testing.T, r *deliveryRun)
	}

	leaks := func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
		ex.Writer.SetCookie(sessionCookieFor(credential))
		ex.Writer.SetHeader("X-Audited", "yes")

		return credential, nil
	}

	fails := func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
		ex.Writer.SetCookie(sessionCookieFor(credential))

		return "", errDeliveryDown
	}

	// withLeak sets the right cookie, then leaks the identifier through
	// leak, and marks the response so a leak that got through shows.
	withLeak := func(leak func(ex *httpsec.Exchange, credential string)) misbehaviour {
		return func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
			ex.Writer.SetCookie(sessionCookieFor(credential))
			ex.Writer.SetHeader("X-Audited", "yes")
			leak(ex, credential)

			return "", nil
		}
	}

	login := func(t *testing.T, r *deliveryRun) served { return r.w.login(t) }

	renewal := func(t *testing.T, r *deliveryRun) served {
		id := r.w.signedIn(t)

		return r.w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, id, nil)
	}

	reauthentication := func(t *testing.T, r *deliveryRun) served {
		id := r.w.signedIn(t)

		return r.w.post(t.Context(), t, reauthPasswordPath, id, url.Values{"password": {e2ePassword}})
	}

	verification := func(t *testing.T, r *deliveryRun) served {
		challenged := r.w.login(t)
		require.Error(t, challenged.err)

		pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
		require.NotNil(t, pending, "the challenged login set the pending session's cookie")

		return r.w.post(t.Context(), t, testMFAVerifyPath, pending.Value, url.Values{"code": {r.w.code(t)}})
	}

	// nothingWritten asserts the request wrote nothing at all, and that the
	// user is left holding no live sign-in.
	nothingWritten := func(t *testing.T, r *deliveryRun) {
		t.Helper()
		refusedUndelivered(t, r.out)
		assert.Zero(t, r.w.active(t), "the sign-in the delivery was handed is ended")
		assert.Empty(t, r.d.audited(), "the well-behaved path never ran")
		idsEnded(t, r.w.sessions, r.d.seen()...)
	}

	// rotationRefused is nothingWritten for a rotation, whose sign-in's
	// original cookie no longer authenticates either.
	rotationRefused := func(t *testing.T, r *deliveryRun) {
		t.Helper()
		refusedUndelivered(t, r.out)
		assert.Zero(t, r.w.active(t), "the sign-in is ended, the identifier the delivery saw with it")
		require.Len(t, r.d.audited(), 1, "only the sign-in was delivered")
		require.Len(t, r.d.seen(), 1, "the rotation's delivery was handed the successor")
		idsEnded(t, r.w.sessions, append(r.d.audited(), r.d.seen()...)...)
	}

	cases := []testCase{
		{
			name: "a delivery that sets the cookie and records an audit entry",
			act: func(t *testing.T, r *deliveryRun) served {
				out := r.w.login(t)
				require.NoError(t, out.err)

				id := deliveredOnlyInCookie(t, r.w.sessions, out)

				return r.w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, id, nil)
			},
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()
				require.NoError(t, r.out.err)

				renewed := deliveredOnlyInCookie(t, r.w.sessions, r.out)
				entries := r.d.audited()
				require.Len(t, entries, 2, "the sign-in and the renewal were each audited")
				assert.Equal(t, renewed, entries[1])
			},
		},
		{
			name:       "a delivery returning a body credential on a fresh sign-in",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  leaks,
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery returning a body credential on a challenged sign-in",
			enrol:      true,
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  leaks,
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery returning a body credential on a renewal",
			misbehaves: onPath(httpsec.DefaultSessionRenewalPath),
			misbehave:  leaks,
			act:        renewal,
			assert:     rotationRefused,
		},
		{
			name:       "a delivery that fails on a fresh sign-in",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  fails,
			act:        login,
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()
				nothingWritten(t, r)
				assert.ErrorIs(t, r.out.err, errDeliveryDown, "the delivery's failure stays reachable")
				assert.NotContains(t, r.out.err.Error(), errDeliveryDown.Error(), "behind the library's own text")
			},
		},
		{
			name:       "a delivery that fails on a renewal",
			misbehaves: onPath(httpsec.DefaultSessionRenewalPath),
			misbehave:  fails,
			act:        renewal,
			assert:     rotationRefused,
		},
		{
			name:       "a delivery that fails on second-factor verification",
			enrol:      true,
			misbehaves: onPath(testMFAVerifyPath),
			misbehave:  fails,
			act:        verification,
			assert:     rotationRefused,
		},
		{
			name:       "a delivery that fails on re-authentication",
			misbehaves: onPath(reauthPasswordPath),
			misbehave:  fails,
			act:        reauthentication,
			assert:     rotationRefused,
		},
		{
			name:       "a delivery that fails after its client hung up still ends the sign-in",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(d *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
				d.cancel()
				ex.Writer.SetCookie(sessionCookieFor(credential))

				return "", errDeliveryDown
			},
			act: func(t *testing.T, r *deliveryRun) served {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				r.d.cancel = cancel

				return r.w.post(ctx, t, httpsec.DefaultLoginPath, "", url.Values{
					httpsec.DefaultLoginUsernameParam: {e2eAddress},
					httpsec.DefaultLoginPasswordParam: {e2ePassword},
				})
			},
			assert: nothingWritten,
		},
		{
			name:       "a delivery that fails ends the sign-in on a bounded context",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  fails,
			act:        login,
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()
				nothingWritten(t, r)
				assert.True(t, r.w.store.endBounded, "a store that hangs cannot hold the request for ever")
			},
		},
		{
			name:       "a delivery that panics ends the sign-in and the panic goes on",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
				ex.Writer.SetCookie(sessionCookieFor(credential))
				ex.Writer.SetHeader("X-Audited", "yes")

				panic(errDeliveryPanic)
			},
			act: func(t *testing.T, r *deliveryRun) served {
				r.rec = httptest.NewRecorder()
				req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
					httpsec.DefaultLoginUsernameParam: {e2eAddress},
					httpsec.DefaultLoginPasswordParam: {e2ePassword},
				})
				run := r.w.chain.Assemble(func(*httpsec.Exchange) error { return nil })
				ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(r.rec))

				require.PanicsWithValue(t, errDeliveryPanic, func() { _ = run(ex) }, "the consumer's panic is not swallowed")

				return served{rec: r.rec}
			},
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()
				assert.Empty(t, r.rec.Header().Values("Set-Cookie"), "no cookie reaches the response")
				assert.Empty(t, r.rec.Header().Values("X-Audited"), "nothing the delivery wrote reaches the response")
				assert.Empty(t, r.rec.Body.String())
				assert.Zero(t, r.w.active(t), "the sign-in the delivery was handed is ended")
				assert.True(t, r.w.store.endBounded, "on a bounded context")
				idsEnded(t, r.w.sessions, r.d.seen()...)
			},
		},
		{
			name:       "a delivery that ends its goroutine ends the sign-in and writes nothing",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
				ex.Writer.SetCookie(sessionCookieFor(credential))
				ex.Writer.SetHeader("X-Audited", "yes")

				runtime.Goexit()

				return "", nil
			},
			act: func(t *testing.T, r *deliveryRun) served {
				r.rec = httptest.NewRecorder()
				req := postValues(t.Context(), httpsec.DefaultLoginPath, e2eSource, url.Values{
					httpsec.DefaultLoginUsernameParam: {e2eAddress},
					httpsec.DefaultLoginPasswordParam: {e2ePassword},
				})
				run := r.w.chain.Assemble(func(*httpsec.Exchange) error { return nil })
				ex := httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(r.rec))

				// Goexit ends the goroutine it runs on, so the request runs on
				// one of its own, and the case waits for it to end.
				returned := make(chan bool, 1)
				done := make(chan struct{})

				go func() {
					defer close(done)

					_ = run(ex)
					returned <- true
				}()

				<-done
				require.Empty(t, returned, "the request's goroutine ended inside the delivery")

				return served{rec: r.rec}
			},
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()
				assert.Empty(t, r.rec.Header().Values("Set-Cookie"), "no cookie reaches the response")
				assert.Empty(t, r.rec.Header().Values("X-Audited"), "nothing the delivery wrote reaches the response")
				assert.Empty(t, r.rec.Body.String())
				assert.Zero(t, r.w.active(t), "the sign-in the delivery was handed is ended")
				assert.True(t, r.w.store.endBounded, "on a bounded context")
				idsEnded(t, r.w.sessions, r.d.seen()...)
			},
		},
		{
			name:       "a delivery that publishes and evaluates on its exchange copy changes nothing of the real one",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(d *auditDelivery, ex *httpsec.Exchange, s *session.Session, credential string) (string, error) {
				principal := &identity.Principal{ID: e2eUser, Username: e2eAddress}

				d.probed = append(d.probed,
					ex.PublishSession(&authenticate.Authentication{Principal: principal}, s),
					ex.EvaluatePerRequest(s, principal),
					ex.EvaluatePerRequest(ex.Session, principal))

				ex.Writer.SetCookie(sessionCookieFor(credential))

				return "", nil
			},
			act: login,
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()
				require.NoError(t, r.out.err, "the sign-in is served as it would have been")
				deliveredOnlyInCookie(t, r.w.sessions, r.out)

				require.Len(t, r.d.probed, 3)

				for _, err := range r.d.probed {
					require.ErrorIs(t, err, httpsec.ErrConfig, "a detached copy refuses, safely, and does not panic")
				}

				assert.Equal(t, 1, r.w.active(t))
			},
		},
		{
			name:       "a delivery that fails when the sign-in cannot be ended",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  fails,
			act: func(t *testing.T, r *deliveryRun) served {
				r.w.store.failDeleteFamily = true

				return r.w.login(t)
			},
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()
				refusedUndelivered(t, r.out)
				assert.Contains(t, r.logs.String(), "could not be ended", "the sign-in left to its deadlines is logged")
				assert.NotContains(t, r.logs.String(), r.d.seen()[0], "the log names no credential")
				assert.Contains(t, r.logs.String(), "reason=session-store", "the log carries the sanitized cause")
				assert.Contains(t, r.logs.String(), "error_type=", "the log carries the cause's type")
				assert.NotContains(t, r.logs.String(), errBrowserStoreDown.Error(), "and not its text")
			},
		},
		{
			name:       "a delivery that writes a body",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
				ex.Writer.SetCookie(sessionCookieFor(credential))
				_, _ = ex.Writer.Write([]byte(`{"session":"` + credential + `"}`))

				return "", nil
			},
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that puts the identifier in another header",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: withLeak(func(ex *httpsec.Exchange, credential string) {
				ex.Writer.AddHeader("X-Session", "id="+credential)
			}),
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that puts the identifier in a header name",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: withLeak(func(ex *httpsec.Exchange, credential string) {
				ex.Writer.SetHeader("X-Session-"+credential, "1")
			}),
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that sets the cookie readable by scripts",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  breaking(func(c *http.Cookie) { c.HttpOnly = false }), //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery that sets the cookie without Secure",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  breaking(func(c *http.Cookie) { c.Secure = false }), //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery that sets the cookie SameSite=None",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  breaking(func(c *http.Cookie) { c.SameSite = http.SameSiteNoneMode }), //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery that sets the cookie with the browser's SameSite default",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  breaking(func(c *http.Cookie) { c.SameSite = http.SameSiteDefaultMode }), //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery that adds a Domain to the cookie",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  breaking(func(c *http.Cookie) { c.Domain = "example.com" }), //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery that changes the cookie's Path",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  breaking(func(c *http.Cookie) { c.Path = "/app" }), //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery that makes the cookie persist",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  breaking(func(c *http.Cookie) { c.MaxAge = 3600 }), //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery that expires the cookie",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave:  breaking(func(c *http.Cookie) { c.MaxAge = -1 }), //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			act:        login,
			assert:     nothingWritten,
		},
		{
			name:       "a delivery that sets the cookie twice, the second with another value",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
				ex.Writer.SetCookie(sessionCookieFor(credential))
				ex.Writer.SetCookie(sessionCookieFor("planted"))

				return "", nil
			},
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that sets a cookie through a raw header",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
				ex.Writer.SetCookie(sessionCookieFor(credential))
				ex.Writer.AddHeader("Set-Cookie", httpsec.DefaultSessionCookieName+"=planted; Path=/; SameSite=None")

				return "", nil
			},
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that copies the identifier into another cookie",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: withLeak(func(ex *httpsec.Exchange, credential string) {
				ex.Writer.SetCookie(&http.Cookie{Name: "app-session", Value: credential, Path: "/"}) //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			}),
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that puts the identifier in another cookie's name",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: withLeak(func(ex *httpsec.Exchange, credential string) {
				ex.Writer.SetCookie(&http.Cookie{Name: "s" + credential, Value: "1", Path: "/"}) //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			}),
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that puts the identifier in another cookie's path",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: withLeak(func(ex *httpsec.Exchange, credential string) {
				ex.Writer.SetCookie(&http.Cookie{Name: "app", Value: "1", Path: "/" + credential}) //nolint:gosec // G124: the case is a delivery breaking the line on purpose
			}),
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that sets no session cookie",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, _ string) (string, error) {
				ex.Writer.SetHeader("X-Audited", "yes")

				return "", nil
			},
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that rewrites the identifier on its copy of the session and leaks the real one",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, s *session.Session, credential string) (string, error) {
				ex.Writer.SetHeader("X-Audited", credential)
				s.ID = "replaced"
				ex.Writer.SetCookie(sessionCookieFor(s.ID))

				return "", nil
			},
			act:    login,
			assert: nothingWritten,
		},
		{
			name:       "a delivery that edits its copy of the session leaves what the endpoint publishes alone",
			enrol:      true,
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, s *session.Session, credential string) (string, error) {
				s.ID = "replaced"
				s.Data = map[string]string{"planted": "yes"}
				ex.Writer.SetCookie(sessionCookieFor(credential))

				return "", nil
			},
			act: login,
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()

				var ch *httpsec.ChallengeError
				require.ErrorAs(t, r.out.err, &ch)
				require.NotNil(t, ch.Session)

				c := cookieNamed(r.out.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, c)
				assert.Equal(t, c.Value, ch.Session.ID, "the published session is the stored one")
				assert.NotContains(t, ch.Session.Data, "planted")

				stored, err := r.w.sessions.Load(t.Context(), c.Value)
				require.NoError(t, err)
				assert.NotContains(t, stored.Data, "planted")
			},
		},
		{
			name:       "a delivery that keeps the exchange and writes after it returned",
			misbehaves: onPath(httpsec.DefaultLoginPath),
			misbehave: func(d *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
				d.kept = ex
				ex.Writer.SetCookie(sessionCookieFor(credential))

				return "", nil
			},
			act: func(t *testing.T, r *deliveryRun) served {
				out := r.w.login(t)

				require.NotNil(t, r.d.kept)
				r.d.kept.Writer.SetHeader("X-Late", "yes")
				r.d.kept.Writer.SetCookie(&http.Cookie{Name: "late", Value: "1", Path: "/"}) //nolint:gosec // G124: the case writes late on purpose
				_, _ = r.d.kept.Writer.Write([]byte("late"))

				return out
			},
			assert: func(t *testing.T, r *deliveryRun) {
				t.Helper()
				require.NoError(t, r.out.err)

				assert.Empty(t, r.out.rec.Header().Values("X-Late"), "a write after Deliver returned goes nowhere")
				assert.Nil(t, cookieNamed(r.out.rec, "late"))
				assert.NotContains(t, r.out.rec.Body.String(), "late")
				assert.Len(t, r.out.rec.Header().Values("Set-Cookie"), 1)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &deliveryRun{
				d:    &auditDelivery{misbehaves: tc.misbehaves, misbehave: tc.misbehave},
				logs: &lockedBuffer{},
			}

			r.w = newBrowserWorld(t)
			if tc.enrol {
				r.w.enrol(t)
			}

			r.w.cookieOpts = append(r.w.cookieOpts, httpsec.WithSessionDelivery(r.d))
			r.w.extra = append(r.w.extra, httpsec.WithLogger(slog.New(slog.NewTextHandler(r.logs, nil))))
			r.w.build(t)

			r.out = tc.act(t, r)
			tc.assert(t, r)
		})
	}
}

// TestSessionCookie_DeliveryPortOtherIssuers pins that a delivery that fails
// on the issuing endpoints the table above does not reach (passwordless
// passkey login, recovery completion) is the same issuing failure: 500,
// nothing written, no credential anywhere, and the sign-in ended.
func TestSessionCookie_DeliveryPortOtherIssuers(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// issue runs the issuing request with d as the cookie chain's
		// delivery and returns the answer and the manager the session lives in.
		issue func(t *testing.T, d *auditDelivery) (served, *session.Sessions)

		assert func(t *testing.T, d *auditDelivery, out served, sessions *session.Sessions)
	}

	ended := func(t *testing.T, d *auditDelivery, out served, sessions *session.Sessions) {
		t.Helper()
		require.Error(t, out.err)
		assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err), "an issuing failure")
		assert.Nil(t, cookieNamed(out.rec, httpsec.DefaultSessionCookieName), "no session cookie is set or expired")
		assert.Empty(t, out.rec.Header().Values("X-Audited"), "nothing the delivery wrote reaches the response")
		require.Len(t, d.seen(), 1, "the delivery was handed the session once")
		assert.NotContains(t, out.rec.Body.String(), d.seen()[0])
		idsEnded(t, sessions, d.seen()...)

		n, err := sessions.CountActiveByUser(t.Context(), e2eUser)
		require.NoError(t, err)
		assert.Zero(t, n, "the sign-in the delivery was handed is ended")
	}

	cases := []testCase{
		{
			name: "passwordless passkey login",
			issue: func(t *testing.T, d *auditDelivery) (served, *session.Sessions) {
				dep := newPwlDeployment(t)
				_ = dep.options(t)

				chain, err := httpsec.New(
					httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: dep.sessions, Users: dep.users},
						httpsec.WithSessionDelivery(d)),
					httpsec.EnablePasskeys(
						httpsec.PasskeyDeps{Passkeys: dep.manager, Sessions: dep.sessions, Users: dep.users},
						httpsec.WithPasskeyPasswordlessLogin()),
				)
				require.NoError(t, err)

				dep.chain = chain

				return dep.login(t, "cred-1", dep.seed(t, e2eUser, "cred-1", passkey.StateActive)), dep.sessions
			},
			assert: ended,
		},
		{
			name: "recovery completion",
			issue: func(t *testing.T, d *auditDelivery) (served, *session.Sessions) {
				h := newRecoveryHarness(t)
				h.noFormLogin = true
				h.chainOpts = append(h.chainOpts, httpsec.WithoutCSRFProtection(),
					httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: h.sessions, Users: h.users},
						httpsec.WithSessionDelivery(d)),
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: h.authn, Sessions: h.sessions, Attempts: h.attempts,
					}))
				h.build(t)

				return h.complete(t, recoveryForm(
					httpsec.RecoverySavedCodeParam, h.saved(t),
					httpsec.RecoveryPasswordParam, e2ePassword)), h.sessions
			},
			assert: ended,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &auditDelivery{
				misbehaves: everywhere,
				misbehave: func(_ *auditDelivery, ex *httpsec.Exchange, _ *session.Session, credential string) (string, error) {
					ex.Writer.SetCookie(sessionCookieFor(credential))
					ex.Writer.SetHeader("X-Audited", "yes")

					return "", errDeliveryDown
				},
			}

			out, sessions := tc.issue(t, d)
			tc.assert(t, d, out, sessions)
		})
	}
}

// TestSessionCookie_DeliveryPortConstruction pins that a missing delivery is
// a configuration error, whether given as nil or as a typed nil.
func TestSessionCookie_DeliveryPortConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		delivery httpsec.SessionDelivery
		assert   func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()
		require.ErrorIs(t, err, httpsec.ErrConfig)
		assert.Contains(t, err.Error(), "WithSessionDelivery")
	}

	cases := []testCase{
		{name: "nil", delivery: nil, assert: refused},
		{name: "typed nil", delivery: (*auditDelivery)(nil), assert: refused},
		{
			name:     "a delivery",
			delivery: &auditDelivery{},
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)

			_, err := httpsec.New(
				httpsec.WithoutCSRFProtection(),
				httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: w.sessions, Users: w.users},
					httpsec.WithSessionDelivery(tc.delivery)),
			)

			tc.assert(t, err)
		})
	}
}
