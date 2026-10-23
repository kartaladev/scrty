package httpsec_test

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/factor"
	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/mfa"
	"github.com/kartaladev/scrty/onetime"
)

// countBarrier is a consumer's challenge store whose issuance count waits
// until racers callers have all counted, or a few seconds have passed, before
// answering. It holds a count-then-issue begin at the worst moment: every
// racer has read the same count before any of them issues. A begin whose
// count and issue are one store decision never calls it.
type countBarrier struct {
	*onetime.MemoryStore

	racers  int32
	counted atomic.Int32
	all     chan struct{}
}

func newCountBarrier(racers int32) *countBarrier {
	return &countBarrier{MemoryStore: onetime.NewMemoryStore(), racers: racers, all: make(chan struct{})}
}

func (s *countBarrier) CountRecentBySubject(
	ctx context.Context, purpose, subject string, since time.Time,
) (int, error) {
	n, err := s.MemoryStore.CountRecentBySubject(ctx, purpose, subject, since)

	if s.counted.Add(1) == s.racers {
		close(s.all)
	}

	select {
	case <-s.all:
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}

	return n, err
}

// TestMFABegin_ConcurrentBeginsDoNotExceedChallengeLimit races 12 begins of
// one method for one user against a challenge limit of 3. The count and the
// issue are one decision, so exactly 3 challenges are issued and the other 9
// begins are refused as throttled.
func TestMFABegin_ConcurrentBeginsDoNotExceedChallengeLimit(t *testing.T) {
	t.Parallel()

	const (
		racers = 12
		limit  = 3
	)

	h := newMFAHarness(t)
	h.channel(factor.AuthenticatorApp).neverVerifies().recordsNoFailure()
	h.limiter.EXPECT().Exceeded(gomock.Any(), mfa.VerifyThrottleKey(testMFAUser)).
		Return(false, nil).AnyTimes()

	stub := newChallengeStub()
	h.extra = []mfa.Method{stub}
	h.chainOpts = []httpsec.Option{httpsec.WithLogger(slog.New(&capturingHandler{}))}
	h.mfaOpts = []httpsec.MFAOption{
		httpsec.WithMFAChallengeStore(newCountBarrier(racers)),
		httpsec.WithMFAChallengeLimit(limit),
	}

	s := h.pendingSession(t, factor.Password)
	c := h.bearerChain(t)

	outs := make([]served, racers)

	var wg sync.WaitGroup
	for n := range outs {
		wg.Go(func() { outs[n] = serve(t, c, bearerPost(t.Context(), testMFABeginPath, mfaTokenFor(s.ID))) })
	}
	wg.Wait()

	var issued, throttled int
	for _, out := range outs {
		switch {
		case out.err == nil:
			assert.Equal(t, http.StatusOK, out.rec.Code)
			issued++
		default:
			require.ErrorIs(t, out.err, mfa.ErrVerifyThrottled)
			throttled++
		}
	}

	assert.Equal(t, limit, issued, "begins issued")
	assert.Equal(t, racers-limit, throttled, "begins refused as throttled")
	assert.Len(t, stub.issuedAll(), limit, "the refused begins reach no method")
}
