package onetime_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/internal/detach"
	"github.com/kartaladev/scrty/pkg/id"
	"github.com/kartaladev/scrty/token/onetime"
)

// The library's own bound on detached work ending is an outage of the store,
// not the client hanging up, so the failure is logged at error level.
func TestTokens_ConsumeBoundExpiryLogsError(t *testing.T) {
	presented := checkTokenID.String() + "." + checkSecret

	// waits blocks until the context ends and returns its error, as a store
	// that never answers does.
	waits := func(ctx context.Context) error {
		<-ctx.Done()

		return ctx.Err()
	}

	type testCase struct {
		name string
		// arrange makes the store wait at this site.
		arrange func(t *testing.T, s *MockStore)
		act     func(ctx context.Context, m *onetime.Tokens) error
	}
	cases := []testCase{
		{
			name: "Check's read",
			arrange: func(_ *testing.T, s *MockStore) {
				s.EXPECT().FindByID(gomock.Any(), checkTokenID).
					DoAndReturn(func(ctx context.Context, _ id.ID) (*onetime.Token, error) {
						return nil, waits(ctx)
					})
			},
			act: func(ctx context.Context, m *onetime.Tokens) error {
				_, err := m.Check(ctx, presented, "")

				return err
			},
		},
		{
			name: "Consume's write",
			arrange: func(t *testing.T, s *MockStore) {
				t.Helper()
				rec := liveRecord(t)
				s.EXPECT().FindByID(gomock.Any(), checkTokenID).Return(&rec, nil)
				s.EXPECT().Consume(gomock.Any(), checkTokenID, gomock.Any()).
					DoAndReturn(func(ctx context.Context, _ id.ID, _ time.Time) error {
						return waits(ctx)
					})
			},
			act: func(ctx context.Context, m *onetime.Tokens) error {
				c, err := m.Check(ctx, presented, "")
				if err != nil {
					return err
				}

				return m.Consume(ctx, c)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs bytes.Buffer
				s := NewMockStore(gomock.NewController(t))
				tc.arrange(t, s)
				m, err := onetime.New("magic-link",
					onetime.WithStore(s),
					onetime.WithClock(clockwork.NewFakeClockAt(issuedAt.Add(time.Minute))),
					onetime.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))
				require.NoError(t, err)

				ctx, cancel := detach.Bounded(t.Context(), detach.WriteTimeout)
				defer cancel()

				require.ErrorIs(t, tc.act(ctx, m), onetime.ErrInvalidToken)
				require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded, "the bound did not pass")

				assert.Contains(t, logs.String(), "level=ERROR", "the library's own bound expiring was told as a hang-up")
				assert.NotContains(t, logs.String(), "level=DEBUG")
			})
		})
	}
}
