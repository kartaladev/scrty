package httpsec_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// defaultListing is the document the listing answers with by default when the
// user can use TOTP alone.
const defaultListing = `{"methods":[{"name":"totp","channel":"authenticator-app","begins":false}]}`

// TestMFAMethodListing pins the opt-in endpoint a session owing a second
// factor asks which methods it can answer with: whom it answers, what it
// answers with, and what it leaves alone.
func TestMFAMethodListing(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string

		// wire configures the chain: the listing option, and what the second
		// method — "email-code", on the email channel, not enrolled unless a
		// case enrols it — answers.
		wire func(h *mfaHarness, email *challengeStub)

		// state is the MFA state of the carried session; noSession carries
		// none at all.
		state     session.MFAState
		noSession bool

		request func(r *http.Request) *http.Request
		assert  func(t *testing.T, out served)
	}

	listing := func(settings ...httpsec.ListingSetting) func(*mfaHarness, *challengeStub) {
		return func(h *mfaHarness, _ *challengeStub) {
			h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAMethodListing(settings...)}
		}
	}

	get := func(target string) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return httptest.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
		}
	}

	to := func(method, target string) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return httptest.NewRequestWithContext(r.Context(), method, target, nil)
		}
	}

	lists := func(want string) func(*testing.T, served) {
		return func(t *testing.T, out served) {
			t.Helper()

			require.NoError(t, out.err)
			assert.False(t, out.handlerRan, "the endpoint answers the request itself")
			assert.Equal(t, http.StatusOK, out.rec.Code)
			assert.Equal(t, "application/json", out.rec.Header().Get("Content-Type"))
			assert.JSONEq(t, want, out.rec.Body.String())
		}
	}

	// challenged is the gate's refusal, which a request the listing does not
	// answer meets when its session owes a second factor.
	challenged := func(t *testing.T, out served) {
		t.Helper()

		var ch *httpsec.ChallengeError
		require.ErrorAs(t, out.err, &ch, "the gate, not the listing, answered")
		assert.Equal(t, policy.ChallengeMFA, ch.Kind)
		assert.False(t, out.handlerRan)
		assert.Zero(t, out.rec.Body.Len(), "no listing was written")
	}

	// passed is a request the listing does not answer reaching the
	// application.
	passed := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan, "the request passed through to the application")
		assert.Zero(t, out.rec.Body.Len(), "no listing was written")
	}

	refusedWith := func(want error) func(*testing.T, served) {
		return func(t *testing.T, out served) {
			t.Helper()

			require.ErrorIs(t, out.err, want)
			assert.False(t, out.handlerRan)
			assert.Zero(t, out.rec.Body.Len(), "no listing was written")
		}
	}

	errLookup := errors.New("mfalisting_test: enrolment store unavailable for ana@example.com")

	cases := []testCase{
		{
			name:    "off by default: a pending session meets the gate",
			wire:    func(*mfaHarness, *challengeStub) {},
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  challenged,
		},
		{
			name:    "off by default: another session reaches the application",
			wire:    func(*mfaHarness, *challengeStub) {},
			state:   session.MFASatisfied,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  passed,
		},
		{
			name:    "a pending session lists the methods its user can use",
			wire:    listing(),
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  lists(defaultListing),
		},
		{
			name: "a method with a begin step is listed as one, in configuration order",
			wire: func(h *mfaHarness, email *challengeStub) {
				listing()(h, email)
				email.enrolled = true
			},
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert: lists(`{"methods":[` +
				`{"name":"totp","channel":"authenticator-app","begins":false},` +
				`{"name":"email-code","channel":"email","begins":true}]}`),
		},
		{
			// The lookups answered, and nothing is left: an empty list, never
			// null, and never a refusal.
			name: "no usable method left",
			wire: func(h *mfaHarness, email *challengeStub) {
				listing()(h, email)
				h.totpUnenrolled = true
			},
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  lists(`{"methods":[]}`),
		},
		{
			name:    "a full session is refused",
			wire:    listing(),
			state:   session.MFASatisfied,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert: func(t *testing.T, out served) {
				t.Helper()

				refusedWith(httpsec.ErrNoMFAChallengePending)(t, out)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
			},
		},
		{
			name:    "a single-factor session is refused",
			wire:    listing(),
			state:   session.MFANone,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  refusedWith(httpsec.ErrNoMFAChallengePending),
		},
		{
			name:      "no session",
			wire:      listing(),
			noSession: true,
			request:   get(httpsec.DefaultMFAMethodListingPath),
			assert:    refusedWith(httpsec.ErrAuthenticationRequired),
		},
		{
			name: "a failed lookup is a refusal, never a shorter list",
			wire: func(h *mfaHarness, email *challengeStub) {
				listing()(h, email)
				email.enrolledErr = errLookup
			},
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert: func(t *testing.T, out served) {
				t.Helper()

				refusedWith(errLookup)(t, out)

				var ch *httpsec.ChallengeError
				assert.NotErrorAs(t, out.err, &ch)
				assert.NotContains(t, out.err.Error(), "ana@example.com",
					"the dependency's text stays out of the refusal")
			},
		},
		{
			name: "consumer path and responder",
			wire: listing(
				httpsec.ListingPath("/account/mfa/methods"),
				httpsec.ListingResponder(func(ex *httpsec.Exchange, methods []httpsec.MFAMethod) error {
					names := make([]string, 0, len(methods))
					for _, m := range methods {
						names = append(names, m.Name+"@"+string(m.Channel))
					}

					body, err := json.Marshal(map[string][]string{"offered": names})
					if err != nil {
						return err
					}

					ex.Writer.SetHeader("Content-Type", "application/json")
					ex.Writer.WriteHeader(http.StatusOK)
					_, err = ex.Writer.Write(body)

					return err
				}),
			),
			state:   session.MFAPending,
			request: get("/account/mfa/methods"),
			assert:  lists(`{"offered":["totp@authenticator-app"]}`),
		},
		{
			name:    "a consumer path moves the endpoint off the default",
			wire:    listing(httpsec.ListingPath("/account/mfa/methods")),
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath),
			assert:  challenged,
		},
		{
			name:    "the query is not read",
			wire:    listing(),
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath + "?user=u-2&method=email-code"),
			assert:  lists(defaultListing),
		},
		{
			name:    "only the exact path is the listing",
			wire:    listing(),
			state:   session.MFAPending,
			request: get(httpsec.DefaultMFAMethodListingPath + "/"),
			assert:  challenged,
		},
		{
			name:    "a POST from a pending session is not answered by the listing",
			wire:    listing(),
			state:   session.MFAPending,
			request: to(http.MethodPost, httpsec.DefaultMFAMethodListingPath),
			assert:  challenged,
		},
		{
			name:    "a HEAD from a pending session is not answered by the listing",
			wire:    listing(),
			state:   session.MFAPending,
			request: to(http.MethodHead, httpsec.DefaultMFAMethodListingPath),
			assert:  challenged,
		},
		{
			// The listing would refuse a full session; passing through shows it
			// never looked at the request.
			name:    "a POST from a full session passes through",
			wire:    listing(),
			state:   session.MFASatisfied,
			request: to(http.MethodPost, httpsec.DefaultMFAMethodListingPath),
			assert:  passed,
		},
		{
			name:    "a HEAD from a full session passes through",
			wire:    listing(),
			state:   session.MFASatisfied,
			request: to(http.MethodHead, httpsec.DefaultMFAMethodListingPath),
			assert:  passed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp).neverVerifies().neverChecked().recordsNoFailure()

			email := newChallengeStub()
			email.name, email.channel, email.enrolled = "email-code", factor.Email, false
			h.extra = []mfa.Method{email}

			tc.wire(h, email)

			var s *session.Session
			if !tc.noSession {
				s = h.newSession(t, factor.Password, tc.state)
			}

			base := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			out := serve(t, h.chain(t, s), tc.request(base))

			tc.assert(t, out)
			assert.Zero(t, email.verifyCalls.Load(), "nothing is verified")
		})
	}
}

// TestMFAMethodListingConstruction pins the listing's wiring mistakes: a
// setting given explicitly with no value, and a path another endpoint of the
// chain already answers.
func TestMFAMethodListingConstruction(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		mfaOpts    []httpsec.MFAOption
		logoutOpts []httpsec.LogoutOption
		assert     func(t *testing.T, c *httpsec.Chain, err error)
	}

	refused := func(names ...string) func(*testing.T, *httpsec.Chain, error) {
		return func(t *testing.T, c *httpsec.Chain, err error) {
			t.Helper()

			require.ErrorIs(t, err, httpsec.ErrConfig)
			assert.Nil(t, c)

			for _, n := range names {
				assert.ErrorContains(t, err, n, "the error names what is at fault")
			}
		}
	}

	assembles := func(t *testing.T, c *httpsec.Chain, err error) {
		t.Helper()

		require.NoError(t, err)
		assert.NotNil(t, c)
	}

	with := func(settings ...httpsec.ListingSetting) []httpsec.MFAOption {
		return []httpsec.MFAOption{httpsec.WithMFAMethodListing(settings...)}
	}

	cases := []testCase{
		{
			name:    "every default",
			mfaOpts: with(),
			assert:  assembles,
		},
		{
			name:    "an explicitly empty path",
			mfaOpts: with(httpsec.ListingPath("")),
			assert:  refused("ListingPath"),
		},
		{
			name:    "a path that matches no request",
			mfaOpts: with(httpsec.ListingPath("mfa/methods")),
			assert:  refused("ListingPath"),
		},
		{
			name:    "an absent responder",
			mfaOpts: with(httpsec.ListingResponder(nil)),
			assert:  refused("ListingResponder"),
		},
		{
			name:    "a path under the verify prefix",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix + "/totp")),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFAVerifyPrefix),
		},
		{
			name:    "the verify prefix itself",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix)),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFAVerifyPrefix),
		},
		{
			name:    "a path under the begin prefix",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultMFABeginPrefix + "/passkey")),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultMFABeginPrefix),
		},
		{
			name: "a path under a consumer's verify prefix",
			mfaOpts: append(with(httpsec.ListingPath("/2fa/check/totp")),
				httpsec.WithMFAVerifyPrefix("/2fa/check")),
			assert: refused("WithMFAMethodListing", "/2fa/check"),
		},
		{
			name: "the default verify path once the verify prefix has moved",
			mfaOpts: append(with(httpsec.ListingPath(httpsec.DefaultMFAVerifyPrefix+"/totp")),
				httpsec.WithMFAVerifyPrefix("/2fa/check")),
			assert: assembles,
		},
		{
			name:    "the logout path",
			mfaOpts: with(httpsec.ListingPath(httpsec.DefaultLogoutPath)),
			assert:  refused("WithMFAMethodListing", httpsec.DefaultLogoutPath),
		},
		{
			name:       "a consumer's logout path",
			mfaOpts:    with(httpsec.ListingPath("/auth/sign-out")),
			logoutOpts: []httpsec.LogoutOption{httpsec.WithLogoutRequestPath("/auth/sign-out")},
			assert:     refused("WithMFAMethodListing", "/auth/sign-out"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newMFAHarness(t)
			h.channel(factor.AuthenticatorApp)

			c, err := httpsec.New(
				httpsec.EnableMFA([]mfa.Method{h.method}, append([]httpsec.MFAOption{
					httpsec.WithMFAVerifyLimiter(h.limiter),
					httpsec.WithMFATokens(h.tokens),
				}, tc.mfaOpts...)...),
				httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: h.sessions}, tc.logoutOpts...),
			)

			tc.assert(t, c, err)
		})
	}
}

// TestMFAMethodListingEnrolmentOnly pins that an enrolment-only session never
// reaches the listing: the enrolment gate refuses it first, like any other
// route. Its setup is the enrolment harness's, not the MFA harness's, so it
// stands apart from the table above.
func TestMFAMethodListingEnrolmentOnly(t *testing.T) {
	t.Parallel()

	h := newEnrolHarness(t)
	h.mfaOpts = []httpsec.MFAOption{httpsec.WithMFAMethodListing()}

	s := h.enrolmentOnly(t, factor.Password)

	out := serve(t, h.chain(t, s),
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, httpsec.DefaultMFAMethodListingPath, nil))

	var ch *httpsec.ChallengeError
	require.ErrorAs(t, out.err, &ch)
	assert.Equal(t, policy.ChallengeMFAEnrolment, ch.Kind)
	assert.False(t, out.handlerRan)
	assert.Zero(t, out.rec.Body.Len(), "no listing was written")
}
