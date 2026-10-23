package recovery_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/recovery"
)

// countHoldingTokenStore is a memory token store whose recent-issue count,
// once read, waits until every racer has read it too (or a bound passes), so
// a flow that counts and then issues lets the whole burst see the same count.
// A flow that decides with one bounded insert never calls the count.
type countHoldingTokenStore struct {
	*onetime.MemoryStore

	racers int

	mu      sync.Mutex
	counted int
	all     chan struct{}
}

func (s *countHoldingTokenStore) CountRecentBySubject(
	ctx context.Context, purpose, subject string, since time.Time,
) (int, error) {
	n, err := s.MemoryStore.CountRecentBySubject(ctx, purpose, subject, since)

	s.mu.Lock()
	s.counted++
	if s.counted == s.racers {
		close(s.all)
	}
	s.mu.Unlock()

	select {
	case <-s.all:
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
	}

	return n, err
}

// TestStart_ConcurrentBurstStaysWithinIssuanceLimit releases twenty recovery
// starts for one username at once against the default issued-code limit of
// five: exactly five codes are stored and exactly five messages are sent.
func TestStart_ConcurrentBurstStaysWithinIssuanceLimit(t *testing.T) {
	t.Parallel()

	const racers, limit = 20, 5

	f := newFixture(t)
	f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil).AnyTimes()
	var sent atomic.Int32
	f.sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, notify.Message) error {
		sent.Add(1)
		return nil
	}).AnyTimes()

	store := &countHoldingTokenStore{
		MemoryStore: onetime.NewMemoryStore(onetime.WithMemoryStoreClock(f.clock)),
		racers:      racers,
		all:         make(chan struct{}),
	}
	r, err := recovery.NewRecoverer(f.deps(), f.opts(recovery.WithIssuedCodeStore(store))...)
	require.NoError(t, err)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			<-start
			r.Start(t.Context(), anaUsername)
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, limit, store.Len(), "codes issued")
	assert.Equal(t, limit, int(sent.Load()), "emails sent")
	assert.Equal(t, store.Len(), int(sent.Load()), "every issued code is sent, and nothing else")
}
