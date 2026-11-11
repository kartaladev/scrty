package httpsec_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
)

// TestPublishSession_CooldownSlot pins why a consumer authenticator belongs at
// OrderBearerToken and no later: the recovery cool-down judges a request by the
// session it carries when it runs, so an authenticator registered after the
// cool-down's slot publishes its session once the cool-down has let the
// sessionless request through. The second row documents that hazard; it is not
// a behaviour to rely on.
func TestPublishSession_CooldownSlot(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		at     httpsec.Order
		assert func(t *testing.T, o publishOutcome)
	}

	cases := []testCase{
		{
			name: "an authenticator at OrderBearerToken is judged by the cool-down",
			at:   httpsec.OrderBearerToken,
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached)
				require.NoError(t, o.probe.err)
				assert.False(t, o.handlerRan, "the cool-down let a marked route through")
				assert.Equal(t, http.StatusForbidden, o.status)
			},
		},
		{
			name: "an authenticator after the cool-down's slot is not judged by it",
			at:   httpsec.Before(httpsec.OrderAccountRecovery),
			assert: func(t *testing.T, o publishOutcome) {
				t.Helper()

				require.True(t, o.probe.reached)
				require.NoError(t, o.probe.err)
				assert.True(t, o.handlerRan, "the cool-down judged a session published after its slot")
				assert.Equal(t, http.StatusOK, o.status)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newResolveFixture(t)

			rid, err := id.NewV7Generator().NewID()
			require.NoError(t, err)

			at := time.Now().Add(-time.Hour)
			records := recovery.NewMemoryRecordStore()
			require.NoError(t, records.Insert(t.Context(), recovery.Record{
				ID: rid, User: f.session.UserID, StartedAt: at, NotBefore: at, CompletedAt: at,
			}))

			o := publishOutcome{probe: &publishProbe{}}

			chain, err := httpsec.New(
				httpsec.WithSessions(f.sessions),
				httpsec.EnableRecoveryCooldown(records, recoveryCooldown, emailRoute),
				httpsec.RegisterInterceptor(publishingAuthenticator(f.sessions, f.session.ID, false, o.probe), tc.at),
			)
			require.NoError(t, err)

			h := chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				o.handlerRan = true
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/account/email", nil))
			o.status = rec.Code

			tc.assert(t, o)
		})
	}
}
