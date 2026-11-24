package oidcprovider_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/token"
)

// TestProvider_ResumeOutcome pins that every answer of an authorization request's
// resume names what RedirectTo carries, so a caller never has to read it from the
// redirect's query, and that a refusal names nothing. The device request's outcomes
// are pinned with the device consent tests.
func TestProvider_ResumeOutcome(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// hint parks the request with an id_token_hint naming u-1.
		hint bool
		// remember gives u-1's consent to billing-web before the request is parked.
		remember bool
		// resume answers the parked request, from the login stage.
		resume func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error)
		assert func(t *testing.T, res oidcprovider.ResumeResult, err error)
	}

	login := func(user identity.UserID) func(*testing.T, *parkFixture, parked) (oidcprovider.ResumeResult, error) {
		return func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error) {
			t.Helper()

			signIn := testSignIn(f, user)

			return f.p.Resume(t.Context(), r.input(&signIn))
		}
	}
	consent := func(deny bool) func(*testing.T, *parkFixture, parked) (oidcprovider.ResumeResult, error) {
		return func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error) {
			t.Helper()

			signIn := testSignIn(f, "u-1")
			_, err := f.p.Resume(t.Context(), r.input(&signIn))
			require.NoError(t, err)
			require.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))

			in := r.input(&signIn)
			in.Answer = &oidcprovider.ConsentAnswer{Deny: deny}
			if !deny {
				answerWith(&in, "openid")
			}

			return f.p.Resume(t.Context(), in)
		}
	}
	outcome := func(want oidcprovider.ResumeOutcome, query string) func(*testing.T, oidcprovider.ResumeResult, error) {
		return func(t *testing.T, res oidcprovider.ResumeResult, err error) {
			t.Helper()

			require.NoError(t, err)
			assert.Equal(t, want, res.Outcome)
			assert.NotEmpty(t, queryOf(t, res.RedirectTo).Get(query), res.RedirectTo)
		}
	}

	cases := []testCase{
		{
			name:   "a login stage that needs consent sends to the consent page",
			resume: login("u-1"),
			assert: outcome(oidcprovider.ResumeOutcomeConsent, oidcprovider.HandleParam),
		},
		{
			name:     "a login stage that needs no consent sends a code",
			remember: true,
			resume:   login("u-1"),
			assert:   outcome(oidcprovider.ResumeOutcomeCode, "code"),
		},
		{
			name:   "a hint naming another subject sends the client's error response",
			hint:   true,
			resume: login("u-2"),
			assert: outcome(oidcprovider.ResumeOutcomeClientError, "error"),
		},
		{
			name:   "a consent granted sends a code",
			resume: consent(false),
			assert: outcome(oidcprovider.ResumeOutcomeCode, "code"),
		},
		{
			name:   "a consent denied sends the client's error response",
			resume: consent(true),
			assert: outcome(oidcprovider.ResumeOutcomeClientError, "error"),
		},
		{
			name: "a refusal names no outcome",
			resume: func(t *testing.T, f *parkFixture, r parked) (oidcprovider.ResumeResult, error) {
				t.Helper()

				return f.p.Resume(t.Context(), r.input(nil))
			},
			assert: func(t *testing.T, res oidcprovider.ResumeResult, err error) {
				t.Helper()

				require.ErrorIs(t, err, oidcprovider.ErrReauthenticate)
				assert.Equal(t, oidcprovider.ResumeOutcomeUnknown, res.Outcome)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var f *parkFixture
			var change func(url.Values)
			if tc.hint {
				hints := newHintFixture(t)
				f = newParkFixtureKeys(t, issuer+"/login", hints.keys)
				change = set("id_token_hint", hints.issued(t, token.TypeIDToken, issuer, f.clk.Now()))
			} else {
				f = newParkFixture(t, issuer+"/login")
			}
			if tc.remember {
				require.NoError(t, f.consents.Give(t.Context(), "u-1", "billing-web",
					[]string{"openid", "profile"}, false, f.clk.Now()))
			}

			r := park(t, f, change)
			res, err := tc.resume(t, f, r)
			tc.assert(t, res, err)
		})
	}
}
