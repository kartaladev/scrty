package oidcprovider_test

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
)

// These tests end a parked request against something else spending it. Each has its own
// setup shape (a barrier on the read, or two ends in turn), so they are standalone tests
// rather than rows.

// barrierPending is the fixture's memory store behind a mock whose Load, once a barrier is
// armed, waits until every racer has read the request, so each reaches the spend and the
// conditional write alone decides the race.
func barrierPending(t *testing.T, f *parkFixture, barrier *atomic.Pointer[sync.WaitGroup]) *MockPendingRequestStore {
	t.Helper()

	store := passThroughPending(t, f.store)
	store.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte) (*oidcprovider.PendingRequest, error) {
			r, err := f.store.Load(ctx, digest)
			if wg := barrier.Load(); wg != nil {
				wg.Done()
				wg.Wait()
			}

			return r, err
		}).AnyTimes()
	store.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(f.store.Advance).AnyTimes()

	return store
}

// recordingCodes is a code store that remembers the records it was asked to create.
type recordingCodes struct {
	oidcprovider.CodeStore

	mu      sync.Mutex
	records []*oidcprovider.CodeRecord
}

func (c *recordingCodes) Create(ctx context.Context, record *oidcprovider.CodeRecord) error {
	c.mu.Lock()
	c.records = append(c.records, record)
	c.mu.Unlock()

	return c.CodeStore.Create(ctx, record)
}

func (c *recordingCodes) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = nil
}

func (c *recordingCodes) written() []*oidcprovider.CodeRecord {
	c.mu.Lock()
	defer c.mu.Unlock()

	return slices.Clone(c.records)
}

// TestEndPending_RacesResumeOnce starts an end and a resume of one login-stage handle
// together, many times over: exactly one is answered, and the other is an unknown handle
// (F6).
func TestEndPending_RacesResumeOnce(t *testing.T) {
	t.Parallel()

	const iterations = 50

	f := newParkFixture(t, issuer+"/login")
	rememberAll(t, f)
	var barrier atomic.Pointer[sync.WaitGroup]
	grants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	codes := &recordingCodes{CodeStore: f.p.CodesForTest()}
	p := rebuilt(t, f,
		oidcprovider.WithPendingRequestStore(barrierPending(t, f, &barrier)),
		oidcprovider.WithGrantStore(grants),
		oidcprovider.WithCodeStore(codes),
	)

	ended, resumed := 0, 0
	for range iterations {
		barrier.Store(nil)
		codes.reset()
		res, err := p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
		require.NoError(t, err)
		r := parked{handle: handleOf(t, res.Location), flow: res.FlowSecret}

		wg := &sync.WaitGroup{}
		wg.Add(2)
		barrier.Store(wg)

		var (
			racers           sync.WaitGroup
			endRes, resumeRe oidcprovider.ResumeResult
			endErr, resumeEr error
		)
		signIn := testSignIn(f, "u-1")
		racers.Go(func() { endRes, endErr = p.EndPending(t.Context(), r.end(oidcprovider.CodeAccessDenied)) })
		racers.Go(func() { resumeRe, resumeEr = p.Resume(t.Context(), r.input(&signIn)) })
		racers.Wait()

		switch {
		case endErr == nil:
			ended++
			require.ErrorIs(t, resumeEr, oidcprovider.ErrUnknownHandle, "the resume lost to the end")
			assert.Empty(t, resumeRe.RedirectTo)
			assert.Equal(t, "access_denied", queryOf(t, endRes.RedirectTo).Get("error"))
			for _, record := range codes.written() {
				withdrawn(t, grants, record) // the losing resume's code is one no answer carried
			}
		case resumeEr == nil:
			resumed++
			require.ErrorIs(t, endErr, oidcprovider.ErrUnknownHandle, "the end lost to the resume")
			assert.Empty(t, endRes.RedirectTo)
			assert.NotEmpty(t, queryOf(t, resumeRe.RedirectTo).Get("code"))
			for _, record := range codes.written() {
				grant, loadErr := grants.Load(t.Context(), record.GrantFamily)
				assert.ErrorIs(t, loadErr, oidcprovider.ErrNotFound, "the winning resume's code is handed out, so its family is not withdrawn")
				assert.Nil(t, grant)
			}
		default:
			t.Fatalf("neither was answered: end %v, resume %v", endErr, resumeEr)
		}
		assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r))
	}
	assert.Equal(t, iterations, ended+resumed, "exactly one of each pair is answered")
	t.Logf("ended %d, resumed %d", ended, resumed)
}

// TestEndPending_SecondEndIsUnknownHandle answers a page that ends one handle twice, as a
// double click would, once: the second end is an unknown handle and answers nothing.
func TestEndPending_SecondEndIsUnknownHandle(t *testing.T) {
	t.Parallel()

	f := newParkFixture(t, issuer+"/login")
	r := park(t, f, nil)

	first, err := f.p.EndPending(t.Context(), r.end(oidcprovider.CodeAccessDenied))
	require.NoError(t, err)
	assert.Equal(t, "access_denied", queryOf(t, first.RedirectTo).Get("error"))

	second, err := f.p.EndPending(t.Context(), r.end(oidcprovider.CodeAccessDenied))
	require.ErrorIs(t, err, oidcprovider.ErrUnknownHandle)
	assert.Empty(t, second.RedirectTo)
	assert.Equal(t, oidcprovider.ResumeOutcomeUnknown, second.Outcome)
}
