package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// TestLogoutEndsTheWholeSignIn pins that logging out with an identifier that
// was already renewed inside its window ends the successor too, because the
// sign-in is the family, not the one record.
func TestLogoutEndsTheWholeSignIn(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))

	sessions, err := session.New(
		session.WithClock(clk),
		session.WithStore(session.NewMemoryStore(session.WithMemoryStoreClock(clk))))
	require.NoError(t, err)

	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(storedUser(), nil).AnyTimes()

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
	require.NoError(t, err)

	old, err := sessions.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	loaded, err := sessions.LoadForRenewal(t.Context(), old.ID)
	require.NoError(t, err)

	successor, _, err := sessions.RotateWithGrace(t.Context(), loaded, 30*time.Second)
	require.NoError(t, err)

	clk.Advance(5 * time.Second)

	bearing := func(method, path, credential string) served {
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		req.Header.Set("Authorization", "Bearer "+credential)

		return serve(t, chain, req)
	}

	out := bearing(http.MethodPost, httpsec.DefaultLogoutPath, old.ID)
	require.NoError(t, out.err)
	assert.Equal(t, http.StatusOK, out.rec.Code)

	later := bearing(http.MethodGet, "/resource", successor.ID)
	require.ErrorIs(t, later.err, httpsec.ErrAuthenticationRequired,
		"the successor belongs to the sign-in the logout ended")
	assert.False(t, later.handlerRan)
}
