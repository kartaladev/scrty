package httpsec_test

import (
	"crypto/elliptic"
	"net/http"
	"net/url"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// TestSessionCookie_BoundSessionNotContinued pins that a cookie chain, which
// judges no DPoP proof and reads no client certificate, refuses to continue a
// session bound to a DPoP key or a certificate that a consumer's own
// authenticator published: second-factor verification, re-authentication by
// password or by a second factor, and renewal each refuse it as
// authentication required, before anything is spent, so the code still
// verifies afterwards and the session is neither rotated nor superseded. An
// unbound session published the same way still continues on each of them.
func TestSessionCookie_BoundSessionNotContinued(t *testing.T) {
	t.Parallel()

	var (
		boundJKT  = session.KeyBinding{JKT: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}
		boundX5T  = session.KeyBinding{X5TS256: "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}
		noBinding = session.KeyBinding{}
	)

	type testCase struct {
		name string

		// binding is the published session's key binding; the zero value is
		// an unbound session.
		binding session.KeyBinding

		// bindToProofKey binds the published session to the key that signs the
		// request's DPoP proof, instead of binding.
		bindToProofKey bool

		// dpop is the DPoP header the request carries: "" for none, "valid" for
		// a proof signed by the session's key, "invalid" for one that does not
		// verify.
		dpop string

		// enrolled enrols the user on TOTP.
		enrolled bool

		// pending enrols the user on TOTP and marks the session as owing a
		// second factor.
		pending bool

		// request is the continuation request for w, before the consumer's
		// cookie naming the session is added.
		request func(t *testing.T, w *browserWorld) *http.Request

		assert func(t *testing.T, w *browserWorld, s *session.Session, out served)
	}

	// refusedUnspent is a 401 that ran no handler, set no session cookie, and
	// left s live: not rotated, not superseded.
	refusedUnspent := func(t *testing.T, w *browserWorld, s *session.Session, out served) {
		t.Helper()
		require.ErrorIs(t, out.err, httpsec.ErrAuthenticationRequired)
		assert.Equal(t, http.StatusUnauthorized, httpsec.StatusForError(out.err))
		assert.False(t, out.handlerRan)
		noSessionCookie(t, out)

		got, err := w.sessions.Load(t.Context(), s.ID)
		require.NoError(t, err, "the session is still live")
		assert.False(t, got.RotatedStrictly, "the session was not rotated")
		assert.Zero(t, got.SupersededAt, "the session was not superseded")
		assert.Empty(t, got.SuccessorDigest, "the session has no successor")
	}

	// proceeded is a continuation that succeeded and set the successor's
	// session cookie, naming another session than s.
	proceeded := func(t *testing.T, _ *browserWorld, s *session.Session, out served) {
		t.Helper()
		require.NoError(t, out.err)

		c := cookieNamed(out.rec, httpsec.DefaultSessionCookieName)
		require.NotNil(t, c, "the continuation set the successor's cookie")
		assert.NotEqual(t, s.ID, c.Value)
	}

	// reauthCodeNotSpent is refusedUnspent for a second-factor re-proof, and
	// checks the refused code still re-proves an unbound session of the same
	// user.
	reauthCodeNotSpent := func(t *testing.T, w *browserWorld, s *session.Session, out served) {
		t.Helper()
		refusedUnspent(t, w, s, out)

		unbound := consumerSignIn(t, w, noBinding, false)
		again := serve(t, w.chain, withConsumerCookie(
			postValues(t.Context(), reauthVerifyTOTP, e2eSource,
				url.Values{"code": {mustCurrentCode(t, w)}}), unbound.ID))
		require.NoError(t, again.err, "the code was not spent by the refused re-proof")
	}

	cases := []testCase{
		{
			name:    "second-factor verification of a bound session is refused, and the code is not spent",
			binding: boundJKT,
			pending: true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), testMFAVerifyPath, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: func(t *testing.T, w *browserWorld, s *session.Session, out served) {
				t.Helper()
				refusedUnspent(t, w, s, out)

				// The same code verifies an unbound pending session of the
				// same user: the refusal spent nothing.
				unbound := consumerSignIn(t, w, session.KeyBinding{}, true)
				again := serve(t, w.chain, withConsumerCookie(
					postValues(t.Context(), testMFAVerifyPath, e2eSource,
						url.Values{"code": {mustCurrentCode(t, w)}}), unbound.ID))
				require.NoError(t, again.err, "the code was not spent by the refused verification")
			},
		},
		{
			name:    "second-factor verification of a certificate-bound session is refused",
			binding: boundX5T,
			pending: true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), testMFAVerifyPath, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: refusedUnspent,
		},
		{
			name:    "second-factor verification of an unbound session published the same way proceeds",
			binding: noBinding,
			pending: true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), testMFAVerifyPath, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: proceeded,
		},
		{
			name:    "re-authentication of a bound session is refused",
			binding: boundJKT,
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), reauthPasswordPath, e2eSource, url.Values{"password": {e2ePassword}})
			},
			assert: refusedUnspent,
		},
		{
			name:    "re-authentication of a certificate-bound session is refused",
			binding: boundX5T,
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), reauthPasswordPath, e2eSource, url.Values{"password": {e2ePassword}})
			},
			assert: refusedUnspent,
		},
		{
			name:    "re-authentication of an unbound session published the same way proceeds",
			binding: noBinding,
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), reauthPasswordPath, e2eSource, url.Values{"password": {e2ePassword}})
			},
			assert: proceeded,
		},
		{
			name:     "second-factor re-authentication of a bound session is refused, and the code is not spent",
			binding:  boundJKT,
			enrolled: true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), reauthVerifyTOTP, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: reauthCodeNotSpent,
		},
		{
			name:     "second-factor re-authentication of a certificate-bound session is refused",
			binding:  boundX5T,
			enrolled: true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), reauthVerifyTOTP, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: refusedUnspent,
		},
		{
			name:     "second-factor re-authentication of an unbound session published the same way proceeds",
			binding:  noBinding,
			enrolled: true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), reauthVerifyTOTP, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: proceeded,
		},
		{
			name:    "renewal of a bound session is refused",
			binding: boundJKT,
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, url.Values{})
			},
			assert: refusedUnspent,
		},
		{
			name:    "renewal of a certificate-bound session is refused",
			binding: boundX5T,
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, url.Values{})
			},
			assert: refusedUnspent,
		},
		{
			name:    "renewal of an unbound session published the same way proceeds",
			binding: noBinding,
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, url.Values{})
			},
			assert: proceeded,
		},
		{
			name:           "second-factor verification of a bound session presenting a valid proof for its key is still refused",
			bindToProofKey: true,
			dpop:           "valid",
			pending:        true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), testMFAVerifyPath, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: refusedUnspent,
		},
		{
			name:           "renewal of a bound session presenting a valid proof for its key is still refused",
			bindToProofKey: true,
			dpop:           "valid",
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), httpsec.DefaultSessionRenewalPath, e2eSource, url.Values{})
			},
			assert: refusedUnspent,
		},
		{
			name:    "second-factor verification of an unbound session carrying a valid DPoP header proceeds",
			dpop:    "valid",
			pending: true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), testMFAVerifyPath, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: proceeded,
		},
		{
			name:    "second-factor verification of an unbound session carrying an invalid DPoP header proceeds",
			dpop:    "invalid",
			pending: true,
			request: func(t *testing.T, w *browserWorld) *http.Request {
				return postValues(t.Context(), testMFAVerifyPath, e2eSource, url.Values{"code": {w.code(t)}})
			},
			assert: proceeded,
		},
		{
			name: "re-authentication of an unbound session carrying a valid DPoP header proceeds",
			dpop: "valid",
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), reauthPasswordPath, e2eSource, url.Values{"password": {e2ePassword}})
			},
			assert: proceeded,
		},
		{
			name: "re-authentication of an unbound session carrying an invalid DPoP header proceeds",
			dpop: "invalid",
			request: func(t *testing.T, _ *browserWorld) *http.Request {
				return postValues(t.Context(), reauthPasswordPath, e2eSource, url.Values{"password": {e2ePassword}})
			},
			assert: proceeded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newBrowserWorld(t)
			if tc.pending || tc.enrolled {
				// Only a user enrolled on a second factor owes one; an
				// enrolled user re-proves with it rather than a password.
				w.enrol(t)
			}

			w.extra = append(w.extra, dpopFeatures(false)...)
			w.extra = append(w.extra, cookieSession(w.sessions))
			w.build(t)

			binding := tc.binding
			key := newDPoPKey(t, elliptic.P256())

			if tc.bindToProofKey {
				binding = session.KeyBinding{JKT: key.jkt}
			}

			s := consumerSignIn(t, w, binding, tc.pending)
			req := withConsumerCookie(tc.request(t, w), s.ID)

			switch tc.dpop {
			case "valid":
				req.Header.Set("DPoP", key.validProver("jti-1")(t, req.URL.Path, ""))
			case "invalid":
				req.Header.Set("DPoP", key.brokenProver("jti-1")(t, req.URL.Path, ""))
			}

			out := serve(t, w.chain, req)

			tc.assert(t, w, s, out)
		})
	}
}

// consumerSignIn stores a password sign-in for e2eUser bound to binding,
// owing a second factor when pending, as a consumer's own authenticator would
// have created it.
func consumerSignIn(t *testing.T, w *browserWorld, binding session.KeyBinding, pending bool) *session.Session {
	t.Helper()

	opts := []session.CreateOption{session.WithFirstFactor(factor.Password)}
	if !binding.IsZero() {
		opts = append(opts, session.WithKeyBinding(binding))
	}

	s, err := w.sessions.Create(t.Context(), e2eUser, opts...)
	require.NoError(t, err)

	if pending {
		s.MFA = session.MFAPending
		require.NoError(t, w.sessions.Save(t.Context(), s))
	}

	return s
}

// withConsumerCookie is req presenting sid in the consumer authenticator's
// own cookie (cookieSession), not the chain's session cookie.
func withConsumerCookie(req *http.Request, sid string) *http.Request {
	req.AddCookie(&http.Cookie{Name: "sid", Value: sid}) //nolint:gosec // G124: a request cookie

	return req
}

// mustCurrentCode is the TOTP code for the world's current time step, the one
// w.code last returned.
func mustCurrentCode(t *testing.T, w *browserWorld) string {
	t.Helper()

	c, err := totp.GenerateCode(w.secret, w.clk.Now())
	require.NoError(t, err)

	return c
}
