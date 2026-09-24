package fibersec_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authorize"
	"github.com/kartaladev/scrty/fibersec"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
	"github.com/kartaladev/scrty/session"
)

// errLookupFailed is the internal fault a refusal must not repeat to a client.
// Its text names a host and a port on purpose: that is what leaks.
var errLookupFailed = errors.New("connection refused to db-primary:5432")

// The fixture strings a challenge carries. Neither is a real credential: they
// are here to be looked for in places they must not appear.
const (
	pendingToken   = "eyJhbGciOiJFUzI1NiJ9.pending.sig" //nolint:gosec // a fixture string, not a credential
	pendingSession = "sess-handle-0123456789"
)

// pendingChallenge is a refusal a consumer is expected to render a prompt from,
// carrying the two things such a prompt needs.
func pendingChallenge() *httpsec.ChallengeError {
	return &httpsec.ChallengeError{
		Kind:    policy.ChallengeMFA,
		Session: &session.Session{ID: pendingSession},
		Token:   pendingToken,
	}
}

// refusedBy runs one request through a chain that refuses it with err, and
// returns the error the adapter handed fiber.
//
// The chain's own handler is called directly rather than through the app, so
// the error is read before fiber's error handling consumes it.
func refusedBy(t *testing.T, err error) error {
	t.Helper()

	var handed error

	app := fiber.New()
	chain := fibersec.Middleware(newChain(t,
		httpsec.RegisterInterceptor(refusing(err, nil), httpsec.OrderBearerToken)))

	app.Use(func(fc fiber.Ctx) error {
		handed = chain(fc)

		return nil
	})
	app.Get("/orders", func(fc fiber.Ctx) error { return fc.SendStatus(http.StatusNoContent) })

	_ = serve(t, app, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil))

	return handed
}

// TestFiberRefusalError pins what a refusal still carries once the adapter has
// wrapped it for fiber: the original refusal, the mapped status in the form
// fiber reads, and a text that is only the standard status text.
func TestFiberRefusalError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		refuse error
		assert func(t *testing.T, err error)
	}

	cases := []testCase{
		{
			name:   "the original refusal is still matchable",
			refuse: authorize.ErrAccessDenied,
			assert: func(t *testing.T, err error) {
				require.ErrorIs(t, err, authorize.ErrAccessDenied,
					"a consumer matches the refusal they would have matched on net/http")
			},
		},
		{
			name:   "a challenge is still readable, with everything a prompt needs",
			refuse: pendingChallenge(),
			assert: func(t *testing.T, err error) {
				var challenge *httpsec.ChallengeError
				require.ErrorAs(t, err, &challenge)

				assert.Equal(t, policy.ChallengeMFA, challenge.Kind)
				require.NotNil(t, challenge.Session)
				assert.Equal(t, pendingSession, challenge.Session.ID)
				assert.Equal(t, pendingToken, challenge.Token)
			},
		},
		{
			name:   "the mapped status is carried the way fiber reads it",
			refuse: authorize.ErrAccessDenied,
			assert: func(t *testing.T, err error) {
				var fe *fiber.Error
				require.ErrorAs(t, err, &fe)

				assert.Equal(t, http.StatusForbidden, fe.Code)
			},
		},
		{
			name:   "the text of an internal fault is only the status text",
			refuse: errLookupFailed,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)

				assert.Equal(t, http.StatusText(http.StatusInternalServerError), err.Error())
				assert.NotContains(t, err.Error(), "connection refused")
				assert.NotContains(t, err.Error(), "db-primary")
			},
		},
		{
			name:   "the text of a refusal is only the status text",
			refuse: authorize.ErrAccessDenied,
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Equal(t, http.StatusText(http.StatusForbidden), err.Error())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.assert(t, refusedBy(t, tc.refuse))
		})
	}
}

// refused is what serving one refused request produced.
type refused struct {
	routeRan bool

	// seen is what a consumer's own fiber error handler was handed.
	seen error

	// challenge is the challenge such a handler extracted from it.
	challenge *httpsec.ChallengeError
}

// TestFiberRefusalResponse pins what a client is answered, from fiber's own
// built-in handler through to a consumer's.
func TestFiberRefusalResponse(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		refuse error
		config func(out *refused) fiber.Config
		assert func(t *testing.T, res response, out refused)
	}

	cases := []testCase{
		{
			name:   "fiber's built-in handler cannot put the cause in the body",
			refuse: errLookupFailed,
			config: func(*refused) fiber.Config { return fiber.Config{} },
			assert: func(t *testing.T, res response, _ refused) {
				assert.Equal(t, http.StatusInternalServerError, res.status)
				assert.Equal(t, http.StatusText(http.StatusInternalServerError), res.body,
					"fiber's own handler writes the error's text, so the error's text "+
						"is the status text and nothing else")
				assert.NotContains(t, res.body, "connection refused")
				assert.NotContains(t, res.body, "db-primary")
			},
		},
		{
			name:   "fibersec's handler answers the bare status with an empty body",
			refuse: httpsec.ErrAuthenticationRequired,
			config: func(*refused) fiber.Config {
				return fiber.Config{ErrorHandler: fibersec.ErrorHandler}
			},
			assert: func(t *testing.T, res response, _ refused) {
				assert.Equal(t, http.StatusUnauthorized, res.status)
				assert.Empty(t, res.body)
			},
		},
		{
			name:   "a consumer's handler renders its own prompt from the challenge",
			refuse: pendingChallenge(),
			config: func(out *refused) fiber.Config {
				return fiber.Config{ErrorHandler: func(fc fiber.Ctx, err error) error {
					out.seen = err

					var challenge *httpsec.ChallengeError
					if errors.As(err, &challenge) {
						out.challenge = challenge
					}

					fc.Status(httpsec.StatusForError(err))

					return fc.JSON(fiber.Map{"prompt": "second-factor"})
				}}
			},
			assert: func(t *testing.T, res response, out refused) {
				assert.Equal(t, http.StatusUnauthorized, res.status)
				assert.JSONEq(t, `{"prompt":"second-factor"}`, res.body)

				require.NotNil(t, out.challenge, "the consumer reached the challenge")
				assert.Equal(t, policy.ChallengeMFA, out.challenge.Kind)
				assert.Equal(t, pendingToken, out.challenge.Token)
			},
		},
		{
			name:   "a consumer's handler sends what the mapping helper gives",
			refuse: authorize.ErrAccessDenied,
			config: func(out *refused) fiber.Config {
				return fiber.Config{ErrorHandler: func(fc fiber.Ctx, err error) error {
					out.seen = err

					status, payload := fibersec.MapError(err)

					return fc.Status(status).JSON(payload)
				}}
			},
			assert: func(t *testing.T, res response, out refused) {
				require.ErrorIs(t, out.seen, authorize.ErrAccessDenied,
					"the refusal the consumer logs is the one the chain decided")
				assert.Equal(t, http.StatusForbidden, res.status)
				assert.JSONEq(t, `{"error":"Forbidden"}`, res.body)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out refused

			app := fiber.New(tc.config(&out))
			app.Use(fibersec.Middleware(newChain(t,
				httpsec.RegisterInterceptor(refusing(tc.refuse, nil), httpsec.OrderBearerToken))))
			app.Get("/orders", func(fc fiber.Ctx) error {
				out.routeRan = true

				return fc.SendStatus(http.StatusNoContent)
			})

			res := serve(t, app,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/orders", nil))

			assert.False(t, out.routeRan, "a refused request never reaches the route")
			tc.assert(t, res, out)
		})
	}
}

// TestFiberMapError pins the helper a consumer's own error handler calls after
// it has logged or enriched a refusal.
func TestFiberMapError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		err    error
		assert func(t *testing.T, status int, body any)
	}

	cases := []testCase{
		{
			name: "an access-denied refusal",
			err:  authorize.ErrAccessDenied,
			assert: func(t *testing.T, status int, body any) {
				assert.Equal(t, http.StatusForbidden, status)
				assert.Equal(t, fiber.Map{"error": "Forbidden"}, body)
			},
		},
		{
			name: "an unauthenticated request",
			err:  httpsec.ErrAuthenticationRequired,
			assert: func(t *testing.T, status int, body any) {
				assert.Equal(t, http.StatusUnauthorized, status)
				assert.Equal(t, fiber.Map{"error": "Unauthorized"}, body)
			},
		},
		{
			name: "an internal fault says nothing about its cause",
			err:  errLookupFailed,
			assert: func(t *testing.T, status int, body any) {
				assert.Equal(t, http.StatusInternalServerError, status)
				assert.Equal(t, fiber.Map{"error": "Internal Server Error"}, body)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status, body := fibersec.MapError(tc.err)
			tc.assert(t, status, body)
		})
	}
}
