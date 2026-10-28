package httpsec_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

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
