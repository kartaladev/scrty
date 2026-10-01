package httpsec_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/session"
)

// recoveryCooldown is the cool-down the guard cases configure.
const recoveryCooldown = 48 * time.Hour

// emailRoute is the route the cool-down cases mark as sensitive.
var emailRoute = httpsec.Route{Method: http.MethodPost, Path: "/account/email"}

// completedRecoveryAgo is a record store holding one recovery of the harness's
// user, completed ago before now.
func completedRecoveryAgo(t *testing.T, ago time.Duration) recovery.RecordStore {
	t.Helper()

	rid, err := id.NewV7Generator().NewID()
	require.NoError(t, err)

	at := time.Now().Add(-ago)

	store := recovery.NewMemoryRecordStore()
	require.NoError(t, store.Insert(t.Context(), recovery.Record{
		ID: rid, User: e2eUser, StartedAt: at, NotBefore: at, CompletedAt: at,
	}))

	return store
}

// cooldownChain is a chain with bearer authentication and the cool-down guard
// over records, and the credential of a fresh session for the harness's user:
// a login made after the recovery.
func cooldownChain(t *testing.T, records recovery.RecordStore) (*httpsec.Chain, string) {
	t.Helper()

	h := newRecoveryHarness(t)

	chain, err := httpsec.New(
		httpsec.EnableBearerToken(httpsec.BearerTokenDeps{Verifier: h.tokens, Sessions: h.sessions, Users: h.users}),
		httpsec.EnableRecoveryCooldown(records, recoveryCooldown, emailRoute),
	)
	require.NoError(t, err)

	s, err := h.sessions.Create(t.Context(), e2eUser, session.WithFirstFactor(factor.Password))
	require.NoError(t, err)

	return chain, mfaTokenFor(s.ID)
}

// TestRecoveryCooldown pins the cool-down guard: a marked route is refused
// during the cool-down after the user's latest recovery, whatever session
// asks, and everything else passes.
func TestRecoveryCooldown(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		records func(t *testing.T) recovery.RecordStore
		request func(ctx context.Context, credential string) *http.Request
		assert  func(t *testing.T, out served)
	}

	request := func(method, path string) func(ctx context.Context, credential string) *http.Request {
		return func(ctx context.Context, credential string) *http.Request {
			req := httptest.NewRequestWithContext(ctx, method, path, nil)
			req.RemoteAddr = e2eSource + ":51000"
			if credential != "" {
				req.Header.Set("Authorization", "Bearer "+credential)
			}

			return req
		}
	}

	anonymous := func(method, path string) func(ctx context.Context, credential string) *http.Request {
		return func(ctx context.Context, _ string) *http.Request {
			return request(method, path)(ctx, "")
		}
	}

	reached := func(t *testing.T, out served) {
		t.Helper()

		require.NoError(t, out.err)
		assert.True(t, out.handlerRan)
	}

	cases := []testCase{
		{
			name:    "a marked route 3 hours after a recovery, from a session made since, is refused",
			records: func(t *testing.T) recovery.RecordStore { return completedRecoveryAgo(t, 3*time.Hour) },
			request: request(http.MethodPost, "/account/email"),
			assert: func(t *testing.T, out served) {
				require.ErrorIs(t, out.err, recovery.ErrCooldown)
				assert.Equal(t, http.StatusForbidden, httpsec.StatusForError(out.err))
				assert.False(t, out.handlerRan)
			},
		},
		{
			name:    "the same request 49 hours after the recovery reaches the handler",
			records: func(t *testing.T) recovery.RecordStore { return completedRecoveryAgo(t, 49*time.Hour) },
			request: request(http.MethodPost, "/account/email"),
			assert:  reached,
		},
		{
			name:    "a user who never recovered reaches the handler",
			records: func(*testing.T) recovery.RecordStore { return recovery.NewMemoryRecordStore() },
			request: request(http.MethodPost, "/account/email"),
			assert:  reached,
		},
		{
			name:    "an unmarked route during the cool-down reaches the handler",
			records: func(t *testing.T) recovery.RecordStore { return completedRecoveryAgo(t, 3*time.Hour) },
			request: request(http.MethodGet, "/invoices"),
			assert:  reached,
		},
		{
			name:    "the marked path by another method is not marked",
			records: func(t *testing.T) recovery.RecordStore { return completedRecoveryAgo(t, 3*time.Hour) },
			request: request(http.MethodGet, "/account/email"),
			assert:  reached,
		},
		{
			name:    "a path under the marked one is not marked",
			records: func(t *testing.T) recovery.RecordStore { return completedRecoveryAgo(t, 3*time.Hour) },
			request: request(http.MethodPost, "/account/email/verify"),
			assert:  reached,
		},
		{
			name: "an unauthenticated marked request is passed on without a lookup",
			records: func(t *testing.T) recovery.RecordStore {
				// A strict double: any lookup fails the test.
				return NewMockRecordStore(gomock.NewController(t))
			},
			request: anonymous(http.MethodPost, "/account/email"),
			assert:  reached,
		},
		{
			name: "a lookup failure is refused with 500 behind fixed text",
			records: func(t *testing.T) recovery.RecordStore {
				m := NewMockRecordStore(gomock.NewController(t))
				m.EXPECT().LatestCompletion(gomock.Any(), e2eUser).Return(time.Time{}, false, errRecordStoreDown)

				return m
			},
			request: request(http.MethodPost, "/account/email"),
			assert: func(t *testing.T, out served) {
				require.Error(t, out.err)
				require.ErrorIs(t, out.err, errRecordStoreDown)
				assert.Equal(t, http.StatusInternalServerError, httpsec.StatusForError(out.err))
				assert.NotContains(t, out.err.Error(), "10.0.0.9", "the store's text is not the library's")
				assert.False(t, out.handlerRan)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chain, credential := cooldownChain(t, tc.records(t))

			tc.assert(t, serve(t, chain, tc.request(t.Context(), credential)))
		})
	}
}

// TestRecoveryCooldown_Response pins what a client is answered when the guard
// refuses: the cool-down's 403, and nothing of the store's.
func TestRecoveryCooldown_Response(t *testing.T) {
	t.Parallel()

	chain, credential := cooldownChain(t, completedRecoveryAgo(t, time.Hour))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/account/email", nil)
	req.Header.Set("Authorization", "Bearer "+credential)

	rec := httptest.NewRecorder()
	chain.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestEnableRecoveryCooldown_Config pins the wiring the guard refuses at
// construction, and where it registers.
func TestEnableRecoveryCooldown_Config(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		option func() httpsec.Option
		assert func(t *testing.T, err error)
	}

	refused := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, httpsec.ErrConfig)
	}

	records := recovery.NewMemoryRecordStore()

	cases := []testCase{
		{
			name:   "a zero cool-down",
			option: func() httpsec.Option { return httpsec.EnableRecoveryCooldown(records, 0, emailRoute) },
			assert: refused,
		},
		{
			name:   "a negative cool-down",
			option: func() httpsec.Option { return httpsec.EnableRecoveryCooldown(records, -time.Hour, emailRoute) },
			assert: refused,
		},
		{
			name:   "no routes",
			option: func() httpsec.Option { return httpsec.EnableRecoveryCooldown(records, time.Hour) },
			assert: refused,
		},
		{
			name:   "a nil store",
			option: func() httpsec.Option { return httpsec.EnableRecoveryCooldown(nil, time.Hour, emailRoute) },
			assert: refused,
		},
		{
			name: "a typed-nil store",
			option: func() httpsec.Option {
				return httpsec.EnableRecoveryCooldown((*recovery.MemoryRecordStore)(nil), time.Hour, emailRoute)
			},
			assert: refused,
		},
		{
			name: "a route with no method",
			option: func() httpsec.Option {
				return httpsec.EnableRecoveryCooldown(records, time.Hour, httpsec.Route{Path: "/account/email"})
			},
			assert: refused,
		},
		{
			name: "a route with no path",
			option: func() httpsec.Option {
				return httpsec.EnableRecoveryCooldown(records, time.Hour, httpsec.Route{Method: http.MethodPost})
			},
			assert: refused,
		},
		{
			name:   "a valid guard builds",
			option: func() httpsec.Option { return httpsec.EnableRecoveryCooldown(records, time.Hour, emailRoute) },
			assert: func(t *testing.T, err error) { require.NoError(t, err) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := httpsec.New(tc.option())
			tc.assert(t, err)
		})
	}
}

// TestEnableRecoveryCooldown_Order pins that the guard runs just after bearer
// authentication, so it sees the session's user.
func TestEnableRecoveryCooldown_Order(t *testing.T) {
	t.Parallel()

	regs, err := httpsec.Registrations(
		httpsec.EnableRecoveryCooldown(recovery.NewMemoryRecordStore(), time.Hour, emailRoute))
	require.NoError(t, err)
	require.Len(t, regs, 1)
	assert.Equal(t, httpsec.After(httpsec.OrderBearerToken), regs[0].Order)
}
