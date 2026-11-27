package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/event"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// reSetAs asserts out set exactly one session cookie, with the identifier
// replacing presented, and that it is the cookie chain sets for that
// identifier, attribute for attribute. It returns the identifier.
func reSetAs(t *testing.T, chain *httpsec.Chain, out served, presented string) string {
	t.Helper()

	var set []string

	for _, line := range out.rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)

		if c.Name == httpsec.DefaultSessionCookieName {
			set = append(set, line)
		}
	}

	require.Len(t, set, 1, "the session cookie is re-set once")

	c, err := http.ParseSetCookie(set[0])
	require.NoError(t, err)
	assert.NotEqual(t, presented, c.Value, "the cookie carries the rotated identifier")
	assert.Equal(t, httpsec.SessionCookieOf(chain, c.Value, 0).String(), set[0],
		"with every attribute the chain sets the cookie with")

	return c.Value
}

// TestSessionCookie_ExistingRotationsReset pins that the rotations a sign-in
// already went through before the cookie session existed, second-factor
// verification and re-authentication, re-set the cookie on a cookie chain:
// the response carries the rotated identifier under the chain's own
// attributes, and the rotated one loads. What the presented identifier does
// afterwards, through its window and after it, is
// TestSessionCookie_ExistingRotationsGrace's.
func TestSessionCookie_ExistingRotationsReset(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// rotate builds w's chain and runs the rotation, returning what it
		// answered and the identifier it presented.
		rotate func(t *testing.T, w *browserWorld) (out served, presented string)
	}

	cases := []testCase{
		{
			name: "second-factor verification",
			rotate: func(t *testing.T, w *browserWorld) (served, string) {
				t.Helper()

				w.enrol(t)
				w.build(t)

				challenged := w.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending)

				return w.post(t.Context(), t, testMFAVerifyPath, pending.Value,
					url.Values{"code": {w.code(t)}}), pending.Value
			},
		},
		{
			name: "re-authentication",
			rotate: func(t *testing.T, w *browserWorld) (served, string) {
				t.Helper()

				w.build(t)
				id := w.signedIn(t)

				return w.post(t.Context(), t, reauthPasswordPath, id, url.Values{"password": {e2ePassword}}), id
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)
			// Attributes off the default, so the re-set cookie is shown to
			// carry the chain's own and not a fixed set.
			w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookieSameSite(http.SameSiteStrictMode))

			out, presented := tc.rotate(t, w)
			require.NoError(t, out.err)

			rotated := reSetAs(t, w.chain, out, presented)
			assert.Contains(t, out.rec.Header().Get("Set-Cookie"), "SameSite=Strict")

			s, err := w.sessions.Load(t.Context(), rotated)
			require.NoError(t, err, "the cookie names the stored successor")
			assert.Equal(t, e2eUser, s.UserID)
		})
	}
}

// visit sends a GET for an application page, presenting cookie as the session
// cookie.
func (w *browserWorld) visit(t *testing.T, cookie string) served {
	t.Helper()

	req := getFrom(t.Context(), "/orders", e2eSource)
	req.Header.Set("Cookie", named(cookie))

	return serve(t, w.chain, req)
}

// verifiedSignIn signs the world's enrolled user in, verifies the second
// factor the sign-in is challenged for, and returns the pending identifier the
// verification was presented with and the one it re-set the cookie to.
func verifiedSignIn(t *testing.T, w *browserWorld) (pending, rotated string, code string) {
	t.Helper()

	challenged := w.login(t)
	require.Error(t, challenged.err)

	c := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
	require.NotNil(t, c, "the challenged sign-in set the pending cookie")

	code = w.code(t)
	out := w.post(t.Context(), t, testMFAVerifyPath, c.Value, url.Values{"code": {code}})
	require.NoError(t, out.err)

	return c.Value, reSetAs(t, w.chain, out, c.Value), code
}

// reauthenticated signs the world's user in, moves the clock on, so the
// re-proof's authentication time differs from the sign-in's, re-authenticates
// with the password, and returns the identifier presented, the one the cookie
// was re-set to, and the sign-in's authentication time.
func reauthenticated(t *testing.T, w *browserWorld) (old, rotated string, signedInAt time.Time) {
	t.Helper()

	old = w.signedIn(t)
	signedInAt = loaded(t, w, old).AuthenticatedAt
	w.clk.Advance(time.Minute)

	out := w.post(t.Context(), t, reauthPasswordPath, old, url.Values{"password": {e2ePassword}})
	require.NoError(t, out.err)

	return old, reSetAs(t, w.chain, out, old), signedInAt
}

// keepsCookie asserts out did not expire the session cookie.
func keepsCookie(t *testing.T, out served) {
	t.Helper()

	for _, line := range out.rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)

		if c.Name == httpsec.DefaultSessionCookieName {
			assert.GreaterOrEqual(t, c.MaxAge, 0, "the session cookie is not expired: %s", line)
		}
	}
}

// loaded is the stored session id names, failing the test when it does not
// load.
func loaded(t *testing.T, w *browserWorld, id string) *session.Session {
	t.Helper()

	s, err := w.sessions.Load(t.Context(), id)
	require.NoError(t, err)

	return s
}

// enrolmentBehindSecondFactor is a post-authentication policy that confines a
// sign-in to enrolment once its second factor is satisfied, as a policy
// demanding a further factor does, and allows anything else.
type enrolmentBehindSecondFactor struct{}

func (enrolmentBehindSecondFactor) Name() string { return "test: enrolment behind the second factor" }

func (enrolmentBehindSecondFactor) Phases() []policy.Phase {
	return []policy.Phase{policy.PostAuthentication}
}

func (enrolmentBehindSecondFactor) Challenges() []policy.ChallengeKind {
	return []policy.ChallengeKind{policy.ChallengeMFAEnrolment}
}

func (enrolmentBehindSecondFactor) Evaluate(_ context.Context, in *policy.Input) policy.Decision {
	if in.MFASatisfied {
		return policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengeMFAEnrolment}
	}

	return policy.Decision{Outcome: policy.Allow}
}

// confineMidVerification is a post-authentication policy that, once armed with
// a session identifier, saves an enrolment confinement on that stored session
// the first time it is asked with the second factor satisfied, as another
// request confining the sign-in between the verification's load of the
// session and its rotation would. It allows every request.
type confineMidVerification struct {
	sessions *session.Sessions
	target   atomic.Pointer[string]
	saved    atomic.Pointer[error]
}

func (*confineMidVerification) Name() string { return "test: confine mid-verification" }

func (*confineMidVerification) Phases() []policy.Phase {
	return []policy.Phase{policy.PostAuthentication}
}

// arm makes the next satisfied evaluation confine the session id names.
func (p *confineMidVerification) arm(id string) { p.target.Store(&id) }

// result reports whether the confining save ran, and its error.
func (p *confineMidVerification) result() (bool, error) {
	err := p.saved.Load()
	if err == nil {
		return false, nil
	}

	return true, *err
}

func (p *confineMidVerification) Evaluate(ctx context.Context, in *policy.Input) policy.Decision {
	if in.MFASatisfied {
		if id := p.target.Swap(nil); id != nil {
			err := p.confine(ctx, *id)
			p.saved.Store(&err)
		}
	}

	return policy.Decision{Outcome: policy.Allow}
}

func (p *confineMidVerification) confine(ctx context.Context, id string) error {
	s, err := p.sessions.Load(ctx, id)
	if err != nil {
		return err
	}

	p.sessions.MarkEnrolmentPending(s, 15*time.Minute)

	return p.sessions.Save(ctx, s)
}

// passwordChangeEveryRequest is a per-request policy that, once armed, raises
// a password change on every request, as a consumer's "reset required" rule
// does. The phase marks it on the request's session in memory only.
type passwordChangeEveryRequest struct{ armed atomic.Bool }

func (*passwordChangeEveryRequest) Name() string { return "test: password change every request" }

func (*passwordChangeEveryRequest) Phases() []policy.Phase {
	return []policy.Phase{policy.PerRequest}
}

func (*passwordChangeEveryRequest) Challenges() []policy.ChallengeKind {
	return []policy.ChallengeKind{policy.ChallengePasswordChange}
}

func (p *passwordChangeEveryRequest) Evaluate(context.Context, *policy.Input) policy.Decision {
	if !p.armed.Load() {
		return policy.Decision{Outcome: policy.Allow}
	}

	return policy.Decision{Outcome: policy.Challenge, Challenge: policy.ChallengePasswordChange}
}

// confineOnRequest is a per-request policy that, once armed with a session
// identifier, saves an enrolment confinement on that stored session the first
// time a request on it is judged, as another request confining the sign-in
// after this one loaded it would. The request's own copy is left as it was
// loaded. It allows every request.
type confineOnRequest struct {
	confineMidVerification
}

func (*confineOnRequest) Name() string { return "test: confine on request" }

func (*confineOnRequest) Phases() []policy.Phase {
	return []policy.Phase{policy.PerRequest}
}

func (p *confineOnRequest) Evaluate(ctx context.Context, in *policy.Input) policy.Decision {
	if in.Session != nil {
		if id := p.target.Load(); id != nil && *id == in.Session.ID && p.target.CompareAndSwap(id, nil) {
			err := p.confine(ctx, *id)
			p.saved.Store(&err)
		}
	}

	return policy.Decision{Outcome: policy.Allow}
}

// reloadsSession is a consumer interceptor that, once armed, puts on the
// exchange's Session the stored session id names, loaded afresh from the
// store, by assigning the field directly rather than publishing it.
type reloadsSession struct {
	sessions *session.Sessions
	target   atomic.Pointer[string]
}

func (r *reloadsSession) option() httpsec.Option {
	return httpsec.RegisterInterceptor(httpsec.InterceptorFunc(func(ex *httpsec.Exchange, next httpsec.Next) error {
		if id := r.target.Load(); id != nil && ex.Session != nil {
			s, err := r.sessions.Load(ex.Context(), *id)
			if err != nil {
				return err
			}

			ex.Session = s
			ex.SetContext(httpsec.WithSession(ex.Context(), s))
		}

		return next(ex)
	}), httpsec.Before(httpsec.OrderMFAChallenge))
}

// TestSessionCookie_ExistingRotationsGrace pins that on a cookie chain
// second-factor verification and re-authentication rotate with a grace
// window: a request already in flight with the old cookie loads the old
// session with its own, lower state, and its answer keeps the cookie; after
// the window the old cookie is reuse, which revokes the sign-in. The window is
// the renewal endpoint's grace. A double-submitted code, a second code on the
// superseded session and a renewal that superseded the session first write
// nothing and expire nothing; a renewal with the old cookie after a
// re-authentication re-rotates, and the new cookie is then reuse (accepted,
// fail-closed). A confinement another request saves while the verification
// runs is a lost race (409) that writes nothing. An enrolment challenge raised
// at verification keeps the confinement's lowered deadline on the successor,
// and with a zero grace both
// rotate strictly, so an in-flight old cookie is not found and nothing is
// revoked. A re-proof over mTLS or with a DPoP proof is
// TestSessionCookie_SignInNeverBinds's.
func TestSessionCookie_ExistingRotationsGrace(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// configure adjusts the world before its chain is built.
		configure func(t *testing.T, w *browserWorld)

		assert func(t *testing.T, w *browserWorld)
	}

	enrolled := func(t *testing.T, w *browserWorld) {
		t.Helper()
		w.enrol(t)
	}

	cases := []testCase{
		{
			name:      "second-factor verification: the old cookie inside the window loads the pending session",
			configure: enrolled,
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				pending, rotated, _ := verifiedSignIn(t, w)
				w.clk.Advance(time.Second)

				late := w.visit(t, pending)
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, late.err, &challenge, "the old session still owes its second factor")
				assert.NotErrorIs(t, late.err, httpsec.ErrAuthenticationRequired)
				assert.False(t, late.handlerRan)
				keepsCookie(t, late)

				assert.Equal(t, session.MFAPending, loaded(t, w, pending).MFA, "the old record keeps its own state")
				assert.Equal(t, session.MFASatisfied, loaded(t, w, rotated).MFA)

				next := w.visit(t, rotated)
				require.NoError(t, next.err, "the new cookie is served")
				assert.True(t, next.handlerRan)
			},
		},
		{
			name:      "second-factor verification: the old cookie after the window is reuse, and the family is revoked",
			configure: enrolled,
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				pending, rotated, _ := verifiedSignIn(t, w)
				w.clk.Advance(session.DefaultRenewalGrace + time.Second)

				late := w.visit(t, pending)
				require.ErrorIs(t, late.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, late.err, session.ErrReused)

				_, err := w.sessions.Load(t.Context(), rotated)
				require.Error(t, err, "the family, the new identifier included, is revoked")
			},
		},
		{
			name: "second-factor verification: the window is the renewal endpoint's grace",
			configure: func(t *testing.T, w *browserWorld) {
				t.Helper()
				w.enrol(t)
				w.renewalOpts = append(w.renewalOpts, httpsec.WithRenewalGrace(2*time.Minute))
			},
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				pending, _, _ := verifiedSignIn(t, w)
				w.clk.Advance(90 * time.Second)

				late := w.visit(t, pending)
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, late.err, &challenge, "past the default grace, inside the renewal's")
				keepsCookie(t, late)
			},
		},
		{
			name: "re-authentication: the old cookie inside the window keeps its authentication time",
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				old, rotated, before := reauthenticated(t, w)
				w.clk.Advance(time.Second)

				late := w.visit(t, old)
				require.NoError(t, late.err, "an in-flight request is not signed out")
				require.True(t, late.handlerRan)
				assert.Equal(t, old, late.handled.Session.ID)
				assert.True(t, late.handled.Session.AuthenticatedAt.Equal(before),
					"the old session's own authentication time: %s", late.handled.Session.AuthenticatedAt)
				keepsCookie(t, late)

				assert.True(t, loaded(t, w, rotated).AuthenticatedAt.After(before), "the re-proof refreshed the new one")
			},
		},
		{
			name: "re-authentication: the old cookie after the window is reuse, and the family is revoked",
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				old, rotated, _ := reauthenticated(t, w)
				w.clk.Advance(session.DefaultRenewalGrace + time.Second)

				late := w.visit(t, old)
				require.ErrorIs(t, late.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, late.err, session.ErrReused)

				_, err := w.sessions.Load(t.Context(), rotated)
				require.Error(t, err, "the family, the new identifier included, is revoked")
			},
		},
		{
			// A session confined to enrolment that has since bound a factor
			// owes its second factor with its deadlines still lowered; the
			// verification restores the deadline its sign-in had.
			name:      "second-factor verification out of an enrolment confinement restores the sign-in's deadline",
			configure: enrolled,
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				challenged := w.login(t)
				require.Error(t, challenged.err)

				c := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, c)

				s := loaded(t, w, c.Value)
				signInDeadline := s.AbsoluteExpiresAt

				w.sessions.MarkEnrolmentPending(s, 15*time.Minute)
				s.MFA = session.MFAPending
				require.NoError(t, w.sessions.Save(t.Context(), s))
				require.True(t, loaded(t, w, c.Value).AbsoluteExpiresAt.Before(signInDeadline), "the deadline is lowered")

				out := w.post(t.Context(), t, testMFAVerifyPath, c.Value, url.Values{"code": {w.code(t)}})
				require.NoError(t, out.err)

				rotated := loaded(t, w, reSetAs(t, w.chain, out, c.Value))
				assert.Equal(t, session.MFASatisfied, rotated.MFA)
				assert.True(t, rotated.EnrolmentOriginDeadline.IsZero(), "the marker is cleared")
				assert.True(t, rotated.AbsoluteExpiresAt.Equal(signInDeadline),
					"the sign-in's deadline %s is restored, got %s", signInDeadline, rotated.AbsoluteExpiresAt)
			},
		},
		{
			name:      "a double-submitted code is a second-factor failure that rotates nothing and keeps the cookie",
			configure: enrolled,
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				pending, rotated, code := verifiedSignIn(t, w)
				active := w.active(t)

				again := w.post(t.Context(), t, testMFAVerifyPath, pending, url.Values{"code": {code}})
				require.Error(t, again.err)
				assert.NotErrorIs(t, again.err, httpsec.ErrAuthenticationRequired)
				assert.NotErrorIs(t, again.err, httpsec.ErrSessionRenewalConflict, "refused as the code, before any rotation")
				noSessionCookie(t, again)

				assert.Equal(t, active, w.active(t), "nothing was stored")
				assert.Equal(t, session.MFASatisfied, loaded(t, w, rotated).MFA, "the new cookie is untouched")
			},
		},
		{
			name: "a second code that verifies on the superseded session is a lost race that writes nothing",
			configure: func(t *testing.T, w *browserWorld) {
				t.Helper()
				w.enrol(t)
				// Wide enough that the next code's time step is inside it.
				w.renewalOpts = append(w.renewalOpts, httpsec.WithRenewalGrace(2*time.Minute))
			},
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				pending, rotated, _ := verifiedSignIn(t, w)
				active := w.active(t)

				again := w.post(t.Context(), t, testMFAVerifyPath, pending, url.Values{"code": {w.code(t)}})
				require.ErrorIs(t, again.err, httpsec.ErrSessionRenewalConflict)
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(again.err))
				noSessionCookie(t, again)

				assert.Equal(t, active, w.active(t), "nothing was stored")
				assert.Equal(t, session.MFAPending, loaded(t, w, pending).MFA, "the old record is unchanged")
				assert.Equal(t, session.MFASatisfied, loaded(t, w, rotated).MFA, "the new cookie keeps its window")
			},
		},
		{
			name:      "a renewal that superseded the pending session first is a lost race that revokes nothing",
			configure: enrolled,
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				challenged := w.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending)

				// The code first, since taking it moves the clock a time step on.
				code := w.code(t)

				// Another server sharing the store renews the session first.
				renewed, _, err := w.sessions.RotateWithGrace(t.Context(), loaded(t, w, pending.Value),
					session.DefaultRenewalGrace)
				require.NoError(t, err)

				out := w.post(t.Context(), t, testMFAVerifyPath, pending.Value, url.Values{"code": {code}})
				require.ErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
				assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))
				noSessionCookie(t, out)

				assert.Equal(t, session.MFAPending, loaded(t, w, renewed.ID).MFA, "the renewal's successor is kept")
				assert.Equal(t, session.MFAPending, loaded(t, w, pending.Value).MFA)
			},
		},
		{
			name:      "a renewal with the old cookie after verification is held at the second-factor gate",
			configure: enrolled,
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				pending, rotated, _ := verifiedSignIn(t, w)
				active := w.active(t)

				renewal := w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, pending, nil)
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, renewal.err, &challenge, "the old session still owes its second factor")
				noSessionCookie(t, renewal)
				assert.Equal(t, active, w.active(t), "nothing was stored")

				next := w.visit(t, rotated)
				require.NoError(t, next.err, "the new cookie is served")
			},
		},
		{
			// Accepted, fail-closed: the renewal re-rotates the old record,
			// which closes the re-authentication successor's window.
			name: "a renewal with the old cookie after re-authentication re-rotates, and the new cookie is then reuse",
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				old, rotated, _ := reauthenticated(t, w)

				renewal := w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, old, nil)
				require.NoError(t, renewal.err)
				renewed := reSetAs(t, w.chain, renewal, old)
				require.NotEqual(t, rotated, renewed)

				next := w.visit(t, rotated)
				require.ErrorIs(t, next.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, next.err, session.ErrReused, "the re-authentication's cookie is reuse")

				_, err := w.sessions.Load(t.Context(), renewed)
				require.Error(t, err, "the family is revoked")
			},
		},
		{
			// The policy confines the verified copy (MarkEnrolmentPending),
			// lowering its deadline; the successor keeps the lowered one.
			name: "an enrolment challenge raised at verification keeps the confinement's deadline",
			configure: func(t *testing.T, w *browserWorld) {
				t.Helper()
				w.enrol(t)
				w.policies = append(w.policies, enrolmentBehindSecondFactor{})
				w.extra = append(w.extra, httpsec.EnableMFAEnrolment(httpsec.EnrolmentDeps{
					Users: w.users, Sender: &capturingSender{},
				}))
			},
			assert: func(t *testing.T, w *browserWorld) {
				t.Helper()

				challenged := w.login(t)
				require.Error(t, challenged.err)

				pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
				require.NotNil(t, pending)
				signInDeadline := loaded(t, w, pending.Value).AbsoluteExpiresAt

				out := w.post(t.Context(), t, testMFAVerifyPath, pending.Value, url.Values{"code": {w.code(t)}})
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, out.err, &challenge)
				require.Equal(t, policy.ChallengeMFAEnrolment, challenge.Kind)

				rotated := loaded(t, w, reSetAs(t, w.chain, out, pending.Value))
				confinedUntil := w.clk.Now().Add(15 * time.Minute)
				assert.False(t, rotated.AbsoluteExpiresAt.After(confinedUntil),
					"the enrolment-only successor ends by %s, got %s", confinedUntil, rotated.AbsoluteExpiresAt)
				assert.Equal(t, signInDeadline, rotated.EnrolmentOriginDeadline, "the sign-in's deadline is the origin")
			},
		},
		func() testCase {
			confiner := &confineMidVerification{}

			return testCase{
				// Another request confines the sign-in after the verification
				// loaded the session and before it rotates: the verified copy,
				// loaded before the confinement, must not overwrite it.
				name: "a confinement saved while the verification runs is a lost race that writes nothing",
				configure: func(t *testing.T, w *browserWorld) {
					t.Helper()
					w.enrol(t)
					confiner.sessions = w.sessions
					w.policies = append(w.policies, confiner)
				},
				assert: func(t *testing.T, w *browserWorld) {
					t.Helper()

					challenged := w.login(t)
					require.Error(t, challenged.err)

					pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
					require.NotNil(t, pending)

					code := w.code(t)
					active := w.active(t)
					confiner.arm(pending.Value)

					out := w.post(t.Context(), t, testMFAVerifyPath, pending.Value, url.Values{"code": {code}})
					ran, saveErr := confiner.result()
					require.True(t, ran, "the confinement was saved during the verification")
					require.NoError(t, saveErr)

					require.ErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
					assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))
					noSessionCookie(t, out)
					assert.Equal(t, active, w.active(t), "nothing was stored")

					stored := loaded(t, w, pending.Value)
					assert.Equal(t, session.MFAEnrolmentPending, stored.MFA, "the confinement stands")
					assert.False(t, stored.EnrolmentOriginDeadline.IsZero(), "the confinement stands")
					assert.True(t, stored.SupersededAt.IsZero(), "nothing was superseded")
				},
			}
		}(),
		func() testCase {
			raises := &passwordChangeEveryRequest{}

			return testCase{
				// The per-request phase marks the password change on the
				// request's session in memory, before the verification: the
				// stored record is compared with the session as loaded, so
				// the mark is no conflict, and the successor carries it.
				name: "a password change the per-request phase marks is carried to the successor, not a conflict",
				configure: func(t *testing.T, w *browserWorld) {
					t.Helper()
					w.enrol(t)
					w.policies = append(w.policies, raises)
					w.extra = append(w.extra, httpsec.EnablePasswordChangeGate(w.sessions))
				},
				assert: func(t *testing.T, w *browserWorld) {
					t.Helper()

					challenged := w.login(t)
					require.Error(t, challenged.err)

					pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
					require.NotNil(t, pending)

					raises.armed.Store(true)
					out := w.post(t.Context(), t, testMFAVerifyPath, pending.Value, url.Values{"code": {w.code(t)}})
					require.NotErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
					require.NoError(t, out.err)

					rotated := loaded(t, w, reSetAs(t, w.chain, out, pending.Value))
					assert.Equal(t, session.MFASatisfied, rotated.MFA)
					assert.True(t, rotated.PasswordChangePending, "the successor carries the marked password change")
				},
			}
		}(),
		func() testCase {
			confiner := &confineOnRequest{}

			return testCase{
				// Another request confines the sign-in after this one loaded
				// it and before the re-authentication rotates it.
				name: "re-authentication on a record changed since it was loaded is a lost race that writes nothing",
				configure: func(t *testing.T, w *browserWorld) {
					t.Helper()
					confiner.sessions = w.sessions
					w.policies = append(w.policies, confiner)
				},
				assert: func(t *testing.T, w *browserWorld) {
					t.Helper()

					old := w.signedIn(t)
					active := w.active(t)
					confiner.arm(old)

					out := w.post(t.Context(), t, reauthPasswordPath, old, url.Values{"password": {e2ePassword}})
					ran, saveErr := confiner.result()
					require.True(t, ran, "the confinement was saved during the re-authentication")
					require.NoError(t, saveErr)

					require.ErrorIs(t, out.err, httpsec.ErrSessionRenewalConflict)
					assert.Equal(t, http.StatusConflict, httpsec.StatusForError(out.err))
					noSessionCookie(t, out)
					assert.Equal(t, active, w.active(t), "nothing was stored")

					stored := loaded(t, w, old)
					assert.Equal(t, session.MFAEnrolmentPending, stored.MFA, "the confinement stands")
					assert.True(t, stored.SupersededAt.IsZero(), "nothing was superseded")
				},
			}
		}(),
		func() testCase {
			reloads := &reloadsSession{}

			return testCase{
				// A consumer interceptor that puts the session on the exchange
				// itself, loaded afresh from the store, rather than publishing
				// it: it is compared as it was loaded, and verifies.
				name: "a session a consumer assigns to the exchange, as the store returned it, verifies",
				configure: func(t *testing.T, w *browserWorld) {
					t.Helper()
					w.enrol(t)
					reloads.sessions = w.sessions
					w.extra = append(w.extra, reloads.option())
				},
				assert: func(t *testing.T, w *browserWorld) {
					t.Helper()

					challenged := w.login(t)
					require.Error(t, challenged.err)

					pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
					require.NotNil(t, pending)

					reloads.target.Store(&pending.Value)
					out := w.post(t.Context(), t, testMFAVerifyPath, pending.Value, url.Values{"code": {w.code(t)}})
					require.NoError(t, out.err)

					rotated := loaded(t, w, reSetAs(t, w.chain, out, pending.Value))
					assert.Equal(t, session.MFASatisfied, rotated.MFA)
				},
			}
		}(),
		func() testCase {
			reloads := &reloadsSession{}

			return testCase{
				// The consumer puts another of the user's stored sign-ins on
				// the exchange: no copy was taken of it, so it is compared as
				// the consumer gave it, and verifies.
				name: "another stored session a consumer assigns to the exchange verifies as itself",
				configure: func(t *testing.T, w *browserWorld) {
					t.Helper()
					w.enrol(t)
					reloads.sessions = w.sessions
					w.extra = append(w.extra, reloads.option())
				},
				assert: func(t *testing.T, w *browserWorld) {
					t.Helper()

					challenged := w.login(t)
					require.Error(t, challenged.err)

					pending := cookieNamed(challenged.rec, httpsec.DefaultSessionCookieName)
					require.NotNil(t, pending)

					other := w.login(t)
					require.Error(t, other.err)
					otherPending := cookieNamed(other.rec, httpsec.DefaultSessionCookieName)
					require.NotNil(t, otherPending)
					require.NotEqual(t, pending.Value, otherPending.Value)

					reloads.target.Store(&otherPending.Value)
					out := w.post(t.Context(), t, testMFAVerifyPath, pending.Value, url.Values{"code": {w.code(t)}})
					require.NoError(t, out.err)

					stored, err := w.sessions.Load(t.Context(), otherPending.Value)
					require.NoError(t, err, "the other sign-in is superseded inside its window")
					assert.False(t, stored.SupersededAt.IsZero(), "the session the consumer assigned is the one rotated")
					assert.True(t, loaded(t, w, pending.Value).SupersededAt.IsZero(), "the cookie's own session is not rotated")
				},
			}
		}(),
		func() testCase {
			watch := &zeroGraceWatch{}

			return testCase{
				name: "with a zero grace second-factor verification rotates strictly",
				configure: func(t *testing.T, w *browserWorld) {
					t.Helper()
					w.enrol(t)
					w.renewalOpts = append(w.renewalOpts, httpsec.WithRenewalGrace(0))
					watch.attach(t, w)
				},
				assert: func(t *testing.T, w *browserWorld) {
					t.Helper()

					pending, rotated, _ := verifiedSignIn(t, w)

					watch.assertRefusedAsUnknown(t, w, pending, rotated)
				},
			}
		}(),
		func() testCase {
			watch := &zeroGraceWatch{}

			return testCase{
				name: "with a zero grace re-authentication rotates strictly",
				configure: func(t *testing.T, w *browserWorld) {
					t.Helper()
					w.renewalOpts = append(w.renewalOpts, httpsec.WithRenewalGrace(0))
					watch.attach(t, w)
				},
				assert: func(t *testing.T, w *browserWorld) {
					t.Helper()

					old, rotated, _ := reauthenticated(t, w)

					watch.assertRefusedAsUnknown(t, w, old, rotated)
				},
			}
		}(),
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)
			if tc.configure != nil {
				tc.configure(t, w)
			}

			w.build(t)

			tc.assert(t, w)
		})
	}
}

// zeroGraceWatch measures what a cookie presented after a zero-grace rotation
// costs: the source's charge and the security events the chain reported.
type zeroGraceWatch struct {
	charges *chargeRecorder
	events  *eventRecorder
}

// attach wires a recording limiter on the cookie session and a recording sink
// on the chain, before the world is built.
func (z *zeroGraceWatch) attach(t *testing.T, w *browserWorld) {
	t.Helper()

	z.charges = newChargeRecorder(t)
	z.events = &eventRecorder{}

	w.cookieOpts = append(w.cookieOpts, httpsec.WithSessionCookieLimiter(z.charges))
	w.extra = append(w.extra, httpsec.EnableSecurityEvents(z.events.sink))
}

// assertRefusedAsUnknown pins that stale, presented after rotated replaced it
// with no grace window, is refused as an unknown reference: gone from the
// store, a 401 that expires the cookie and charges the source once, never
// reuse (no reuse event, no family revocation), so rotated is still served.
func (z *zeroGraceWatch) assertRefusedAsUnknown(t *testing.T, w *browserWorld, stale, rotated string) {
	t.Helper()

	_, err := w.sessions.Load(t.Context(), stale)
	require.ErrorIs(t, err, session.ErrNotFound, "the old identifier is gone at once")

	before := len(z.charges.recorded())

	late := w.visit(t, stale)
	require.ErrorIs(t, late.err, httpsec.ErrAuthenticationRequired)
	assert.NotErrorIs(t, late.err, session.ErrReused, "an in-flight old cookie is not reuse")
	assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(late.err))
	assert.False(t, late.handlerRan)

	expired := cookieNamed(late.rec, httpsec.DefaultSessionCookieName)
	require.NotNil(t, expired, "the refusal expires the session cookie")
	assert.Negative(t, expired.MaxAge, "the cookie is expired, not re-set")

	charged := z.charges.recorded()
	require.Len(t, charged, before+1, "a refused reference is one failed guess")
	assert.Contains(t, charged[len(charged)-1], e2eSource)

	assert.Empty(t, z.events.named(event.AuthnTokenReuse), "an unknown reference is not reuse")

	next := w.visit(t, rotated)
	require.NoError(t, next.err, "the family is not revoked: the new cookie is served")
	assert.True(t, next.handlerRan)
}

// cookiePasswordPath is where the password-change gate's resolve endpoint
// answers in the password-change rotation cases.
const cookiePasswordPath = "/account/password"

// TestSessionCookie_PasswordChangeRotates pins that on a cookie chain the
// password-change gate's resolve endpoint rotates the sign-in and re-sets the
// cookie before the consumer's change runs: the response carries the new
// identifier, on which the change is recorded, and the old one is reuse once
// its window ends; a rotation that cannot be written changes no password and
// sets no cookie, and the old cookie keeps working.
func TestSessionCookie_PasswordChangeRotates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// change is the consumer's change function, nil for one that succeeds.
		change func(ex *httpsec.Exchange) error

		// failSupersede fails the rotation's write.
		failSupersede bool

		assert func(t *testing.T, w *browserWorld, out served, presented string, changed int)
	}

	cases := []testCase{
		{
			name: "the change re-sets the cookie to the rotated sign-in",
			assert: func(t *testing.T, w *browserWorld, out served, presented string, changed int) {
				t.Helper()
				require.NoError(t, out.err)
				assert.Equal(t, 1, changed)

				rotated := reSetAs(t, w.chain, out, presented)

				s, err := w.sessions.Load(t.Context(), rotated)
				require.NoError(t, err)
				assert.False(t, s.PasswordChangePending, "the change is recorded on the rotated session")

				w.clk.Advance(session.DefaultRenewalGrace + time.Second)

				late := w.post(t.Context(), t, httpsec.DefaultSessionRenewalPath, presented, nil)
				require.ErrorIs(t, late.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, late.err, session.ErrReused, "the old identifier after its window is reuse")
			},
		},
		{
			name:   "a refused change leaves the browser on the rotated sign-in",
			change: func(*httpsec.Exchange) error { return errPasswordRefused },
			assert: func(t *testing.T, w *browserWorld, out served, presented string, changed int) {
				t.Helper()
				require.ErrorIs(t, out.err, errPasswordRefused)
				assert.Equal(t, 1, changed)

				rotated := reSetAs(t, w.chain, out, presented)
				_, err := w.sessions.Load(t.Context(), rotated)
				require.NoError(t, err, "the refusal still carries a cookie naming a stored session")
			},
		},
		{
			name:          "a rotation that cannot be written changes nothing and sets no cookie",
			failSupersede: true,
			assert: func(t *testing.T, w *browserWorld, out served, presented string, changed int) {
				t.Helper()
				require.ErrorIs(t, out.err, errBrowserStoreDown, "the store's failure stays reachable")
				assert.NotErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err), "a dependency failure")
				assert.Zero(t, changed, "no password is changed on a request that is then refused")
				noSessionCookie(t, out)

				w.store.failSupersede = false

				again := w.post(t.Context(), t, reauthPasswordPath, presented, url.Values{"password": {e2ePassword}})
				require.NoError(t, again.err, "the old cookie still works")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var changed int

			change := tc.change
			if change == nil {
				change = func(*httpsec.Exchange) error { return nil }
			}

			w := newBrowserWorld(t)
			w.extra = append(w.extra, httpsec.EnablePasswordChangeGate(w.sessions,
				httpsec.WithPasswordChangeEndpoint(cookiePasswordPath, func(ex *httpsec.Exchange) error {
					changed++

					return change(ex)
				})))
			w.build(t)

			presented := w.signedIn(t)
			w.store.failSupersede = tc.failSupersede

			out := w.post(t.Context(), t, cookiePasswordPath, presented, url.Values{"password": {"n3w-Passw0rd!"}})

			tc.assert(t, w, out, presented, changed)
		})
	}
}

// errPasswordRefused is the refusal a consumer's change function returns.
var errPasswordRefused = errors.New("rotation_test: the new password is too weak")

// selectingStore is a browserStore that records selected roles through the
// memory store it forwards to.
type selectingStore struct {
	*browserStore

	hooks *storeHooks
}

// storeHooks are what a case may change in, and read from, a selectingStore
// while its requests run.
type storeHooks struct {
	// selects counts the SelectRole writes the store was asked for.
	selects atomic.Int32

	// successorRole, when set, replaces the role every superseding write is
	// asked to store on the successor, as a store that ignores the field does.
	successorRole atomic.Pointer[string]
}

func (s selectingStore) Supersede(ctx context.Context, sup session.Supersession) error {
	if role := s.hooks.successorRole.Load(); role != nil {
		sup.SuccessorRole = role
	}

	return s.browserStore.Supersede(ctx, sup)
}

func (s selectingStore) SelectRole(ctx context.Context, id, role string) error {
	s.hooks.selects.Add(1)

	return s.Store.(session.RoleSelector).SelectRole(ctx, id, role) //nolint:forcetypeassert // the memory store selects roles
}

// switchCookieWorld is a cookie chain with CSRF protection and role switching
// on, over the browser world's failing store on a fake clock, with a live
// sign-in of ada, who holds sales (primary) and audit, carrying a CSRF token.
type switchCookieWorld struct {
	clk      *clockwork.FakeClock
	store    *browserStore
	sessions *session.Sessions
	chain    *httpsec.Chain
	signIn   *session.Session
	hooks    *storeHooks
}

func newSwitchCookieWorld(t *testing.T, extra ...httpsec.Option) *switchCookieWorld {
	t.Helper()

	return newSwitchCookieWorldOver(t, func(*session.Sessions) []httpsec.Option { return extra })
}

// newSwitchCookieWorldOver is newSwitchCookieWorld with options that need the
// world's session manager, such as the password-change gate.
func newSwitchCookieWorldOver(t *testing.T, extra func(*session.Sessions) []httpsec.Option) *switchCookieWorld {
	t.Helper()

	return newSwitchCookieWorldWith(t, nil, nil, nil, extra)
}

// newSwitchCookieWorldWith is newSwitchCookieWorldOver with further session
// manager options, create options for the sign-in, such as its timeouts and a
// persistent cookie, and options of the cookie session.
func newSwitchCookieWorldWith(t *testing.T, sessionOpts []session.Option, createOpts []session.CreateOption,
	cookieOpts []httpsec.SessionCookieOption, extra func(*session.Sessions) []httpsec.Option,
) *switchCookieWorld {
	t.Helper()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC))
	store := &browserStore{Store: must.Must(session.NewMemoryStore(session.WithMemoryStoreClock(clk)))}

	hooks := &storeHooks{}

	sessions, err := session.New(append([]session.Option{
		session.WithClock(clk), session.WithStore(selectingStore{browserStore: store, hooks: hooks}),
	}, sessionOpts...)...)
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), testUserID).AnyTimes().
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) { return adaWithGrants(), nil })

	chain, err := httpsec.New(append([]httpsec.Option{
		httpsec.WithClock(clk),
		httpsec.WithLogger(discardLogger()),
		httpsec.EnableCSRFProtection(),
		httpsec.EnableSessionCookie(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}, cookieOpts...),
		httpsec.WithSwitchableRoles(),
	}, extra(sessions)...)...)
	require.NoError(t, err)

	signIn, err := sessions.Create(t.Context(), testUserID, append([]session.CreateOption{
		session.WithFirstFactor(factor.Password), session.WithCSRFToken(),
	}, createOpts...)...)
	require.NoError(t, err)

	return &switchCookieWorld{clk: clk, store: store, sessions: sessions, chain: chain, signIn: signIn, hooks: hooks}
}

// post sends an unsafe same-origin request presenting id as the session
// cookie and the sign-in's CSRF token, with handler as the application, and
// returns what the chain answered.
func (w *switchCookieWorld) post(t *testing.T, id string, handler func(ex *httpsec.Exchange) error) served {
	t.Helper()

	req := sessionCookieRequest(t.Context(), http.MethodPost, named(id),
		map[string]string{"X-CSRF-Token": w.signIn.CSRFToken})
	out := served{rec: httptest.NewRecorder()}

	run := w.chain.Assemble(func(ex *httpsec.Exchange) error {
		out.handlerRan = true

		return handler(ex)
	})

	out.err = run(httpsec.NewExchange(t.Context(), httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(out.rec)))

	return out
}

// switchTo switches the role of the request presenting id to role, and
// returns what the chain answered and what the switch returned.
func (w *switchCookieWorld) switchTo(t *testing.T, id, role string) (served, error) {
	t.Helper()

	var switched error

	out := w.post(t, id, func(ex *httpsec.Exchange) error {
		switched = w.chain.SwitchActiveRole(ex.Context(), role)

		return switched
	})
	require.True(t, out.handlerRan, "the request reached the application")

	return out, switched
}

// activeRole is the active role of a request presenting id, failing the test
// when the request is refused.
func (w *switchCookieWorld) activeRole(t *testing.T, id string) string {
	t.Helper()

	var name string

	out := w.post(t, id, func(ex *httpsec.Exchange) error {
		p, ok := identity.PrincipalFromContext(ex.Context())
		require.True(t, ok)

		if p.ActiveRole != nil {
			name = p.ActiveRole.Name
		}

		return nil
	})
	require.NoError(t, out.err)
	require.True(t, out.handlerRan)

	return name
}

// TestSessionCookie_RoleSwitchRotates pins that on a cookie chain an
// active-role switch rotates the sign-in with a grace window and re-sets the
// cookie: the new identifier carries the switched role and the sign-in's CSRF
// token, the old one works through its window and is reuse after it, which
// revokes the family; a rotation that cannot be written switches nothing and
// sets no cookie; and a switch called once its request is over is refused.
func TestSessionCookie_RoleSwitchRotates(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		assert func(t *testing.T, w *switchCookieWorld)
	}

	cases := []testCase{
		{
			name: "the switch re-sets the cookie, and the CSRF token still holds",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)
				require.NoError(t, out.err)

				rotated := reSetAs(t, w.chain, out, w.signIn.ID)
				assert.Equal(t, "audit", w.activeRole(t, rotated),
					"the next unsafe request with the new cookie and the same CSRF token is served under audit")

				s, err := w.sessions.Load(t.Context(), rotated)
				require.NoError(t, err)
				assert.Equal(t, w.signIn.CSRFToken, s.CSRFToken)
				assert.Equal(t, w.signIn.FamilyID, s.FamilyID, "the same sign-in")
			},
		},
		{
			name: "the old identifier works inside its window",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				_, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)

				w.clk.Advance(time.Second)
				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "an in-flight request is not signed out")
			},
		},
		{
			name: "the old identifier after its window is reuse, and the family is revoked",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.NoError(t, err)

				rotated := reSetAs(t, w.chain, out, w.signIn.ID)

				w.clk.Advance(session.DefaultRenewalGrace + time.Second)

				late := w.post(t, w.signIn.ID, func(*httpsec.Exchange) error { return nil })
				require.ErrorIs(t, late.err, httpsec.ErrAuthenticationRequired)
				require.ErrorIs(t, late.err, session.ErrReused)
				assert.False(t, late.handlerRan)

				_, err = w.sessions.Load(t.Context(), rotated)
				require.Error(t, err, "the family, the new identifier included, is revoked")
			},
		},
		{
			name: "a rotation that cannot be written switches nothing and sets no cookie",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				w.store.failSupersede = true

				out, err := w.switchTo(t, w.signIn.ID, "audit")
				require.ErrorIs(t, err, errBrowserStoreDown, "the store's failure stays reachable")
				assert.NotErrorIs(t, err, httpsec.ErrAuthenticationRequired)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(err), "a dependency failure")
				noSessionCookie(t, out)

				w.store.failSupersede = false

				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "the old cookie still works, unswitched")
			},
		},
		{
			name: "a second switch on one request rotates the first's successor",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				// onSuccessor asserts the request is now on the identifier the
				// last cookie it set names, in its exchange and its context.
				var set []string

				onSuccessor := func(t *testing.T, ex *httpsec.Exchange, first bool) {
					t.Helper()

					require.NotNil(t, ex.Session)
					assert.NotEqual(t, w.signIn.ID, ex.Session.ID, "the exchange is on the successor")

					inCtx, ok := httpsec.SessionFromContext(ex.Context())
					require.True(t, ok)
					assert.Equal(t, ex.Session.ID, inCtx.ID, "the context is on the successor")

					if !first {
						assert.NotEqual(t, set[0], ex.Session.ID, "the second switch moved on again")
					}

					set = append(set, ex.Session.ID)
				}

				out := w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
					require.NoError(t, w.chain.SwitchActiveRole(ex.Context(), "audit"))
					onSuccessor(t, ex, true)
					require.NoError(t, w.chain.SwitchActiveRole(ex.Context(), "sales"))
					onSuccessor(t, ex, false)

					return nil
				})
				require.NoError(t, out.err)

				lines := out.rec.Header().Values("Set-Cookie")
				require.Len(t, lines, 2, "each switch re-sets the cookie")
				require.Len(t, set, 2)

				last, err := http.ParseSetCookie(lines[1])
				require.NoError(t, err)
				assert.NotEqual(t, w.signIn.ID, last.Value)
				assert.Equal(t, set[1], last.Value, "the final cookie names the latest successor")

				s, err := w.sessions.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.Equal(t, "sales", s.SelectedRole, "the browser keeps the last cookie, on the last selection")
			},
		},
		{
			name: "a switch called once its request is over is refused",
			assert: func(t *testing.T, w *switchCookieWorld) {
				t.Helper()

				var kept context.Context

				out := w.post(t, w.signIn.ID, func(ex *httpsec.Exchange) error {
					kept = context.WithoutCancel(ex.Context())

					return nil
				})
				require.NoError(t, out.err)

				err := w.chain.SwitchActiveRole(kept, "audit")
				require.ErrorIs(t, err, httpsec.ErrConfig, "the response that would carry the cookie is gone")

				assert.Equal(t, "sales", w.activeRole(t, w.signIn.ID), "nothing was rotated or switched")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, newSwitchCookieWorld(t))
		})
	}
}

// TestSessionCookie_RoleSwitchInPasswordChange pins how the password-change
// resolution is saved when the consumer's change function rotates the sign-in
// again or tampers with the exchange: a role switch it makes is made on the
// rotation's successor rather than refused; the resolution is saved on the
// latest successor the chain holds, without loading it, so its first
// presentation is still the browser's; a persistent recovery-pending
// sign-in's last cookie carries the deadline the saved session has; and a
// session the function puts on the exchange is never the one saved.
func TestSessionCookie_RoleSwitchInPasswordChange(t *testing.T) {
	t.Parallel()

	twelveHours := []session.Option{
		session.WithAbsoluteTimeout(12 * time.Hour), session.WithIdleTimeout(12 * time.Hour),
	}

	// fixture is one case's world, and another user's session where the case
	// has one.
	type fixture struct {
		w     *switchCookieWorld
		other *session.Session
	}

	type testCase struct {
		name string

		sessionOpts []session.Option
		createOpts  []session.CreateOption
		cookieOpts  []httpsec.SessionCookieOption

		// prepare changes the stored sign-in before the request; nil marks it
		// as owing a password change.
		prepare func(t *testing.T, f *fixture)

		// change is the consumer's change function.
		change func(f *fixture) httpsec.ChangePasswordFunc

		// last is the last session cookie the response set.
		assert func(t *testing.T, f *fixture, out served, last *http.Cookie)
	}

	switchToAudit := func(f *fixture) httpsec.ChangePasswordFunc {
		return func(ex *httpsec.Exchange) error {
			return f.w.chain.SwitchActiveRole(ex.Context(), "audit")
		}
	}

	cases := []testCase{
		{
			name:   "a switch is made on the successor and the resolution saved on the latest one, unloaded",
			change: switchToAudit,
			assert: func(t *testing.T, f *fixture, out served, last *http.Cookie) {
				t.Helper()
				require.NoError(t, out.err, "the switch on the rotated session is not refused")
				require.Len(t, out.rec.Header().Values("Set-Cookie"), 2,
					"the password change and the switch each re-set the cookie")

				raw, err := f.w.store.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.True(t, raw.FirstPresentedAt.IsZero(),
					"the chain did not load the successor the browser has not presented yet")

				s, err := f.w.sessions.Load(t.Context(), last.Value)
				require.NoError(t, err, "the final cookie names a live session")
				assert.Equal(t, "audit", s.SelectedRole, "the selection survives the change's save")
				assert.False(t, s.PasswordChangePending)
				assert.Equal(t, f.w.signIn.FamilyID, s.FamilyID)
			},
		},
		{
			name:        "a persistent recovery-pending sign-in's last cookie carries the restored deadline",
			sessionOpts: twelveHours,
			createOpts:  []session.CreateOption{session.WithPersistentCookie()},
			prepare: func(t *testing.T, f *fixture) {
				t.Helper()

				s, err := f.w.sessions.Load(t.Context(), f.w.signIn.ID)
				require.NoError(t, err)
				f.w.sessions.MarkRecoveryPending(s, 10*time.Minute, f.w.clk.Now())
				s.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), s))
			},
			change: switchToAudit,
			assert: func(t *testing.T, f *fixture, out served, last *http.Cookie) {
				t.Helper()
				require.NoError(t, out.err)
				assert.Equal(t, 43200, last.MaxAge,
					"the deadline the saved session has, not the switch successor's lowered one")

				raw, err := f.w.store.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.False(t, raw.PasswordChangePending)
				assert.Equal(t, session.MFANone, raw.MFA)
				assert.Equal(t, f.w.clk.Now().Add(12*time.Hour), raw.AbsoluteExpiresAt,
					"the restored absolute deadline the cookie was set for")
				assert.Equal(t, "audit", raw.SelectedRole)
			},
		},
		{
			name:        "with the password change's rotation off, the switch's cookie carries the restored deadline",
			sessionOpts: twelveHours,
			createOpts:  []session.CreateOption{session.WithPersistentCookie()},
			cookieOpts:  []httpsec.SessionCookieOption{httpsec.WithoutSessionRotation(httpsec.RotateOnPasswordChange)},
			prepare: func(t *testing.T, f *fixture) {
				t.Helper()

				s, err := f.w.sessions.Load(t.Context(), f.w.signIn.ID)
				require.NoError(t, err)
				f.w.sessions.MarkRecoveryPending(s, 10*time.Minute, f.w.clk.Now())
				s.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), s))
			},
			change: switchToAudit,
			assert: func(t *testing.T, f *fixture, out served, last *http.Cookie) {
				t.Helper()
				require.NoError(t, out.err)
				require.Len(t, out.rec.Header().Values("Set-Cookie"), 1, "only the switch re-sets the cookie")
				assert.Equal(t, 43200, last.MaxAge,
					"the deadline the change restores, not the recovery-lowered one the switch rotated from")

				raw, err := f.w.store.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.False(t, raw.PasswordChangePending)
				assert.Equal(t, session.MFANone, raw.MFA)
				assert.Equal(t, f.w.clk.Now().Add(12*time.Hour), raw.AbsoluteExpiresAt)
				assert.Equal(t, "audit", raw.SelectedRole)
			},
		},
		{
			name: "a session the function puts on the exchange is not the one saved",
			prepare: func(t *testing.T, f *fixture) {
				t.Helper()

				owing := *f.w.signIn
				owing.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), &owing))

				var err error
				f.other, err = f.w.sessions.Create(t.Context(), identity.UserID("someone-else"),
					session.WithFirstFactor(factor.Password))
				require.NoError(t, err)

				f.other.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), f.other))
			},
			change: func(f *fixture) httpsec.ChangePasswordFunc {
				return func(ex *httpsec.Exchange) error {
					ex.Session = f.other

					return nil
				}
			},
			assert: func(t *testing.T, f *fixture, out served, last *http.Cookie) {
				t.Helper()
				require.NoError(t, out.err)

				untouched, err := f.w.store.Load(t.Context(), f.other.ID)
				require.NoError(t, err)
				assert.True(t, untouched.PasswordChangePending, "another user's session is never resolved")

				own, err := f.w.store.Load(t.Context(), last.Value)
				require.NoError(t, err)
				assert.False(t, own.PasswordChangePending, "the resolution is saved on the gate's own successor")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &fixture{}
			f.w = newSwitchCookieWorldWith(t, tc.sessionOpts, tc.createOpts, tc.cookieOpts,
				func(sessions *session.Sessions) []httpsec.Option {
					return []httpsec.Option{httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithPasswordChangeEndpoint("/orders", func(ex *httpsec.Exchange) error {
							return tc.change(f)(ex)
						}))}
				})

			if tc.prepare != nil {
				tc.prepare(t, f)
			} else {
				owing := *f.w.signIn
				owing.PasswordChangePending = true
				require.NoError(t, f.w.sessions.Save(t.Context(), &owing))
			}

			out := f.w.post(t, f.w.signIn.ID, func(*httpsec.Exchange) error { return nil })

			var last *http.Cookie

			for _, line := range out.rec.Header().Values("Set-Cookie") {
				c, err := http.ParseSetCookie(line)
				require.NoError(t, err)

				if c.Name == httpsec.DefaultSessionCookieName {
					last = c
				}
			}

			require.NotNil(t, last, "the session cookie is re-set")

			tc.assert(t, f, out, last)
		})
	}
}
