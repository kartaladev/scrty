package httpsec_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/session"
)

// errGuardRefused is what an interceptor inside the touch refuses with, so a
// test can tell the chain's own refusal from anything the write-back did.
var errGuardRefused = errors.New("sessiontouch_test: refused by a guard")

// errStoreUnreachable is what the store fails the activity write-back with.
var errStoreUnreachable = errors.New("sessiontouch_test: store unreachable")

// touchableSession is a live session whose idle deadline is well short of the
// manager's idle timeout, so an advance is a visible five-and-twenty minutes
// rather than the nanoseconds between two calls to time.Now.
func touchableSession() *session.Session {
	now := time.Now()

	return &session.Session{
		ID:                testJTI,
		UserID:            "u-1",
		CreatedAt:         now.Add(-time.Hour),
		LastAccessedAt:    now.Add(-25 * time.Minute),
		IdleExpiresAt:     now.Add(5 * time.Minute),
		AbsoluteExpiresAt: now.Add(11 * time.Hour),
		FirstFactor:       factor.Password,
	}
}

// savedSessions records what the store was asked to persist. Each entry is a
// copy taken at the moment of the call, so a later mutation of the live
// session cannot rewrite what a test observed.
type savedSessions struct {
	mu      sync.Mutex
	records []session.Session
}

func (s *savedSessions) record(v *session.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, *v)
}

func (s *savedSessions) all() []session.Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]session.Session(nil), s.records...)
}

// expectResolvedSession wires the session and the user a bearer request
// resolves, and deliberately not the write-back: this test's own recorder is
// what the store's Save must reach.
func (h *authHarness) expectResolvedSession(s *session.Session) {
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(s, nil)
	h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil)
}

// expectSaved wires the store to accept the activity write-back, recording
// what it was handed, and to fail with err when one is given.
func (h *authHarness) expectSaved(saved *savedSessions, err error) {
	h.store.EXPECT().Save(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, s *session.Session) error {
			saved.record(s)

			return err
		}).AnyTimes()
}

// acceptsActivityWriteBack lets the store take the activity write-back the
// chain performs after every request that carried a session through to the
// handler. The write-back is always active, so a test pinning something else
// about such a request still performs one.
func (h *authHarness) acceptsActivityWriteBack() {
	h.store.EXPECT().Save(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
}

// TestSessionTouch pins the activity write-back: it runs after everything
// inside it, it runs for a refused request too, and it never changes what the
// request answered with.
func TestSessionTouch(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		wire    func(t *testing.T, h *authHarness, saved *savedSessions)
		inner   []httpsec.Option
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, s served, saved *savedSessions)
	}

	authenticated := func(ctx context.Context) *http.Request {
		return bearerRequest(ctx, "Bearer a-token")
	}

	advanced := func(t *testing.T, saved *savedSessions) {
		t.Helper()

		records := saved.all()
		require.Len(t, records, 1, "activity is recorded once per request")
		assert.True(t, records[0].IdleExpiresAt.After(time.Now().Add(20*time.Minute)),
			"the idle deadline was moved to now plus the manager's idle timeout")
		assert.True(t, records[0].LastAccessedAt.After(time.Now().Add(-time.Minute)),
			"the last-access time was moved to now")
	}

	cases := []testCase{
		{
			name: "a completed request advances the idle deadline",
			wire: func(_ *testing.T, h *authHarness, saved *savedSessions) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.expectSaved(saved, nil)
			},
			request: authenticated,
			assert: func(t *testing.T, s served, saved *savedSessions) {
				require.NoError(t, s.err)
				require.True(t, s.handlerRan)
				advanced(t, saved)
			},
		},
		{
			name: "a request refused by a guard still advances it",
			wire: func(_ *testing.T, h *authHarness, saved *savedSessions) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.expectSaved(saved, nil)
			},
			inner: []httpsec.Option{
				httpsec.RegisterInterceptor(
					httpsec.InterceptorFunc(func(*httpsec.Exchange, httpsec.Next) error {
						return errGuardRefused
					}),
					httpsec.OrderAuthorizer),
			},
			request: authenticated,
			assert: func(t *testing.T, s served, saved *savedSessions) {
				require.ErrorIs(t, s.err, errGuardRefused)
				assert.False(t, s.handlerRan)
				advanced(t, saved)
			},
		},
		{
			name: "a touch failure after a 200 changes neither the response nor the error",
			wire: func(_ *testing.T, h *authHarness, saved *savedSessions) {
				h.expectVerified()
				h.expectResolvedSession(touchableSession())
				h.expectSaved(saved, errStoreUnreachable)
			},
			inner: []httpsec.Option{
				httpsec.RegisterInterceptor(
					httpsec.InterceptorFunc(func(ex *httpsec.Exchange, _ httpsec.Next) error {
						ex.Writer.WriteHeader(http.StatusOK)

						return nil
					}),
					httpsec.OrderAuthorizer),
			},
			request: authenticated,
			assert: func(t *testing.T, s served, saved *savedSessions) {
				require.NoError(t, s.err,
					"bookkeeping that could not be written must not turn a served request into a fault")
				assert.Equal(t, http.StatusOK, s.rec.Code)
				assert.NotEmpty(t, saved.all(), "the write-back was attempted")
			},
		},
		{
			name: "a request with no session touches nothing",
			// No expectation on the store at all: any write fails the case.
			wire: func(*testing.T, *authHarness, *savedSessions) {},
			request: func(ctx context.Context) *http.Request {
				return bearerRequest(ctx, "")
			},
			assert: func(t *testing.T, s served, saved *savedSessions) {
				require.NoError(t, s.err)
				assert.True(t, s.handlerRan)
				assert.Empty(t, saved.all())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			saved := &savedSessions{}
			tc.wire(t, h, saved)

			opts := append([]httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(h.bearerTokenDeps()),
			}, tc.inner...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.request(t.Context())), saved)
		})
	}
}
