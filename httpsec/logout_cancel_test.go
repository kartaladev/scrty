package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/session"
)

// TestLogout_EndsTheSignInWhenTheClientHangsUp pins that a logout the chain
// has accepted ends the sign-in even when the client disconnects before the
// revocation reaches a context-honouring store: the client that asked to be
// logged out is not there to see a failure and retry.
func TestLogout_EndsTheSignInWhenTheClientHangsUp(t *testing.T) {
	t.Parallel()

	clk := clockwork.NewFakeClockAt(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC))
	held := session.NewMemoryStore(session.WithMemoryStoreClock(clk))

	// The store the chain sees holds everything in held, and honours the
	// context on the revocation as database/sql and pgx do.
	store := NewMockStore(gomock.NewController(t))
	store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(held.Load).AnyTimes()
	store.EXPECT().MarkPresented(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(held.MarkPresented).AnyTimes()
	store.EXPECT().RecordActivity(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(held.RecordActivity).AnyTimes()
	var seen error
	store.EXPECT().DeleteFamily(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, family id.ID) (int, error) {
		seen = ctx.Err()
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		return held.DeleteFamily(ctx, family)
	}).Times(1)

	sessions, err := session.NewManager(session.WithClock(clk), session.WithStore(store))
	require.NoError(t, err)

	signIn, err := session.NewManager(session.WithClock(clk), session.WithStore(held))
	require.NoError(t, err)
	s, err := signIn.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	ctx, hangUp := context.WithCancel(t.Context())
	defer hangUp()

	// The client hangs up once it has been authenticated: the logout itself
	// runs on a cancelled request.
	users := NewMockUserLoader(gomock.NewController(t))
	users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
		DoAndReturn(func(context.Context, identity.UserID) (*identity.Details, error) {
			hangUp()
			return storedUser(), nil
		}).AnyTimes()

	chain, err := httpsec.New(
		httpsec.WithClock(clk),
		httpsec.EnableSessionBearer(httpsec.SessionBearerDeps{Sessions: sessions, Users: users}),
		httpsec.EnableLogout(httpsec.LogoutDeps{Sessions: sessions}))
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, httpsec.DefaultLogoutPath, nil)
	req.Header.Set("Authorization", "Bearer "+s.ID)
	rec := httptest.NewRecorder()
	run := chain.Assemble(func(*httpsec.Exchange) error { return nil })
	_ = run(httpsec.NewExchange(ctx, httpsec.NewHTTPRequest(req), httpsec.NewHTTPResponseWriter(rec)))

	require.NoError(t, seen, "the revocation ran on the request's cancelled context, and a context-honouring store aborted it")
	_, err = held.Load(t.Context(), s.ID)
	assert.ErrorIs(t, err, session.ErrSessionNotFound, "the session the client logged out of is still live")
}
