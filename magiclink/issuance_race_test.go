package magiclink_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kartaladev/scrty/magiclink"
	"github.com/kartaladev/scrty/onetime"
)

// countHoldingStore is a memory token store whose recent-issue count, once
// read, waits until every racer has read it too (or a bound passes), so a
// flow that counts and then issues lets the whole burst see the same count.
// A flow that decides with one bounded insert never calls the count, and the
// hold costs it nothing.
type countHoldingStore struct {
	*onetime.MemoryStore

	racers int

	mu      sync.Mutex
	counted int
	all     chan struct{}
}

func newCountHoldingStore(racers int) *countHoldingStore {
	return &countHoldingStore{MemoryStore: onetime.NewMemoryStore(), racers: racers, all: make(chan struct{})}
}

func (s *countHoldingStore) CountRecentBySubject(
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

// TestRequest_ConcurrentBurstStaysWithinIssuanceLimit releases twenty link
// requests for one address at once against the default limit of five: no more
// than five links are stored and no more than five messages are sent.
func TestRequest_ConcurrentBurstStaysWithinIssuanceLimit(t *testing.T) {
	t.Parallel()

	const racers, limit = 20, 5

	store := newCountHoldingStore(racers)
	sender := &recordingSender{}
	m, err := magiclink.NewManager(tokensWithStore(t, store), activeLoader(), sender, "https://app.example.com")
	require.NoError(t, err)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			<-start
			m.Request(t.Context(), "ada@example.com", "/")
		})
	}
	close(start)
	wg.Wait()

	assert.LessOrEqual(t, store.Len(), limit, "links issued")
	assert.LessOrEqual(t, sender.Count(), limit, "emails sent")
	assert.Equal(t, store.Len(), sender.Count(), "every issued link is sent, and nothing else")
}
