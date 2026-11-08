package httpsec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// TestBasePath_EveryGateExemptionFollows pins that each path the recovery gate
// and the enrolment gate exempt moves under the base path, not just the first
// of each kind: a path left unmoved would lock a pending session out of the
// endpoint it needs, and the unmoved path would stay open.
func TestBasePath_EveryGateExemptionFollows(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// recovered carries a recovery-pending session; otherwise an
		// enrolment-only one.
		recovered bool

		path   string
		assert func(t *testing.T, out served)
	}

	reached := func(t *testing.T, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.False(t, errors.As(out.err, &ch), "a gate refused the moved endpoint: %v", out.err)
		assert.False(t, out.handlerRan, "the endpoint answers the request itself")
	}

	challenged := func(kind policy.ChallengeKind) func(t *testing.T, out served) {
		return func(t *testing.T, out served) {
			t.Helper()

			var ch *httpsec.ChallengeError
			require.ErrorAs(t, out.err, &ch, "got %v", out.err)
			assert.Equal(t, kind, ch.Kind)
			assert.False(t, out.handlerRan)
		}
	}

	var cases []testCase

	add := func(gate string, recovered bool, kind policy.ChallengeKind, what, path string) {
		cases = append(cases,
			testCase{
				name: gate + ": the moved " + what + " is reachable", recovered: recovered,
				path: derivedBase + path, assert: reached,
			},
			testCase{
				name: gate + ": the " + what + " without the base is refused", recovered: recovered,
				path: path, assert: challenged(kind),
			},
		)
	}

	passkeys := []struct{ what, path string }{
		{"passkey registration begin", passkeyBeginPath},
		{"passkey registration finish", passkeyFinishPath},
		{"passkey saved-code confirm", passkeyConfirmPath},
		{"passkey emailed-code confirm", passkeyConfirmEmailPath},
	}

	for _, p := range passkeys {
		add("recovery gate", true, policy.ChallengeAccountRecovery, p.what, p.path)
		add("enrolment gate", false, policy.ChallengeMFAEnrolment, p.what, p.path)
	}

	enrolments := []struct{ what, path string }{
		{"enrolment begin", enrolBeginPath},
		{"enrolment confirm", enrolConfirmPath},
		{"enrolment emailed-code confirm", enrolEmailPath},
	}

	for _, e := range enrolments {
		add("recovery gate", true, policy.ChallengeAccountRecovery, e.what, e.path)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newPasskeyHarness(t)
			h.passkeyMethod = true
			h.withRecoveryGate = tc.recovered

			var s *session.Session
			if tc.recovered {
				s = h.recoveryPending(t)
			} else {
				s = h.enrolmentOnly(t, factor.Password)
			}

			c, err := httpsec.New(append(h.chainOptions(t, s), httpsec.WithBasePath(derivedBase))...)
			require.NoError(t, err)

			tc.assert(t, serve(t, c, post(t.Context(), tc.path, "")))
		})
	}
}

// TestBasePath_PasswordChangeGatesAnswerNothingOrOne pins that a
// password-change gate with no endpoint of its own does not hide the endpoints
// of the rest of the chain from the base path, and does not refuse a second
// gate that has one.
func TestBasePath_PasswordChangeGatesAnswerNothingOrOne(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		build  func(t *testing.T, sessions *session.Sessions) []httpsec.Option
		assert func(t *testing.T, c *httpsec.Chain, err error)
	}

	resolve := func(path string) httpsec.PasswordChangeOption {
		return httpsec.WithPasswordChangeEndpoint(path, func(*httpsec.Exchange) error { return nil })
	}

	cases := []testCase{
		{
			name: "an endpoint-less gate beside form login builds and sign-in answers at the moved path",
			build: func(t *testing.T, sessions *session.Sessions) []httpsec.Option {
				return append([]httpsec.Option{httpsec.EnablePasswordChangeGate(sessions)},
					coreEndpoints()[0].options(t, "")...)
			},
			assert: func(t *testing.T, c *httpsec.Chain, err error) {
				require.NoError(t, err)

				moved := serve(t, c, formRequest(t.Context(), derivedBase+httpsec.DefaultLoginPath, ""))
				assert.False(t, moved.handlerRan, "sign-in answers at the moved path")

				bare := serve(t, c, formRequest(t.Context(), httpsec.DefaultLoginPath, ""))
				assert.True(t, bare.handlerRan, "the path without the base is an ordinary route")
			},
		},
		{
			name: "one gate with an endpoint and one without builds under the base path",
			build: func(_ *testing.T, sessions *session.Sessions) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnablePasswordChangeGate(sessions, resolve(testChangePasswordPath)),
					httpsec.EnablePasswordChangeGate(sessions),
				}
			},
			assert: func(t *testing.T, _ *httpsec.Chain, err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "one gate without an endpoint and one with builds under the base path",
			build: func(_ *testing.T, sessions *session.Sessions) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnablePasswordChangeGate(sessions),
					httpsec.EnablePasswordChangeGate(sessions, resolve(testChangePasswordPath)),
				}
			},
			assert: func(t *testing.T, _ *httpsec.Chain, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessions, err := session.New()
			require.NoError(t, err)

			c, err := httpsec.New(append(tc.build(t, sessions), httpsec.WithBasePath(derivedBase))...)
			tc.assert(t, c, err)
		})
	}
}

// TestBasePath_ClearedCookiesCarryMovedPath pins that a cookie the chain clears
// carries the Path it was set with under the base path: a clearing header on
// the declared path would match no cookie, and the stale cookie would stay.
//
// The magic-link binding cookie is never cleared by the chain, so it has no
// case here.
func TestBasePath_ClearedCookiesCarryMovedPath(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		cookie string

		// clear runs the request after which the chain clears the cookie.
		clear func(t *testing.T) served

		path string
	}

	cases := []testCase{
		{
			name:   "the OIDC flow cookie is cleared on the moved callback",
			cookie: httpsec.DefaultOIDCFlowCookieName,
			clear: func(t *testing.T) served {
				h := newOIDCHarnessAt(t, derivedBase+httpsec.DefaultOIDCCallbackPath)
				h.chainOpts = []httpsec.Option{httpsec.WithBasePath(derivedBase)}

				chain := h.chain(t)

				begun := serve(t, chain, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					derivedBase+httpsec.DefaultOIDCAuthorizePath+testOIDCProvider, nil))
				require.NoError(t, begun.err)

				flow := cookieNamed(begun.rec, httpsec.DefaultOIDCFlowCookieName)
				require.NotNil(t, flow)

				loc, err := url.Parse(begun.rec.Header().Get("Location"))
				require.NoError(t, err)

				// A callback for the real flow with a code the provider never
				// issued: the flow is spent, so the chain clears the cookie.
				query := url.Values{"code": {"not-the-code"}, "state": {loc.Query().Get("state")}}.Encode()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
					derivedBase+httpsec.DefaultOIDCCallbackPath+testOIDCProvider+"?"+query, nil)
				req.AddCookie(&http.Cookie{Name: httpsec.DefaultOIDCFlowCookieName, Value: flow.Value}) //nolint:gosec // G124: a request cookie, never set

				return serve(t, chain, req)
			},
			path: derivedBase + httpsec.DefaultOIDCCallbackPath,
		},
		{
			name:   "the passkey ceremony cookie is cleared on the moved finish",
			cookie: httpsec.DefaultPasswordlessCookieName,
			clear: func(t *testing.T) served {
				h := newPasskeyHarness(t)
				h.withPasswordless()

				c, err := httpsec.New(append(h.chainOptions(t, nil), httpsec.WithBasePath(derivedBase))...)
				require.NoError(t, err)

				return serve(t, c, post(t.Context(), derivedBase+passwordlessFinishPath, ""))
			},
			path: derivedBase + passwordlessFinishPath,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out := tc.clear(t)

			c := cookieNamed(out.rec, tc.cookie)
			require.NotNil(t, c, "the chain clears %s (err %v)", tc.cookie, out.err)
			assert.Empty(t, c.Value)
			assert.Negative(t, c.MaxAge, "the cookie is cleared")
			assert.Equal(t, tc.path, c.Path)
		})
	}
}
