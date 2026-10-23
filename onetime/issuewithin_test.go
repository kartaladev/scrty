package onetime_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/onetime"
)

func TestIssueWithin(t *testing.T) {
	t.Parallel()

	type env struct {
		m     *onetime.Manager
		store *onetime.MemoryStore
		clk   *clockwork.FakeClock
	}

	type testCase struct {
		name string
		// subject is who the issue is for; empty means "ana".
		subject string
		limit   int
		// setup issues or moves time before the call.
		setup  func(t *testing.T, ctx context.Context, e env)
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, e env, presented string, tok onetime.Token, err error)
	}

	issueN := func(n int, subject string) func(t *testing.T, ctx context.Context, e env) {
		return func(t *testing.T, ctx context.Context, e env) {
			for range n {
				_, _, err := e.m.Issue(ctx, subject)
				require.NoError(t, err)
			}
		}
	}

	cases := []testCase{
		{
			name:  "below the limit a token is issued and redeemable",
			limit: 5,
			setup: issueN(4, "ana"),
			assert: func(t *testing.T, e env, presented string, tok onetime.Token, err error) {
				require.NoError(t, err)
				assert.Equal(t, "ana", tok.Subject)
				_, err = e.m.Check(t.Context(), presented, "")
				require.NoError(t, err, "the bounded token is one the manager honours")
				assert.Equal(t, 5, e.store.Len())
			},
		},
		{
			name:  "at the limit nothing is issued and nothing is stored",
			limit: 5,
			setup: issueN(5, "ana"),
			assert: func(t *testing.T, e env, presented string, tok onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrIssueLimitReached)
				assert.Empty(t, presented)
				assert.Zero(t, tok)
				assert.Equal(t, 5, e.store.Len(), "a refused issue writes nothing")
			},
		},
		{
			name:  "another subject's tokens do not count",
			limit: 1,
			setup: issueN(3, "bob"),
			assert: func(t *testing.T, _ env, _ string, _ onetime.Token, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:  "tokens issued before the manager's window no longer count",
			limit: 2,
			setup: func(t *testing.T, ctx context.Context, e env) {
				issueN(2, "ana")(t, ctx, e)
				e.clk.Advance(time.Hour + time.Second)
			},
			assert: func(t *testing.T, _ env, _ string, _ onetime.Token, err error) {
				require.NoError(t, err)
			},
		},
		{
			name:  "a token issued exactly at the window's start still counts",
			limit: 2,
			setup: func(t *testing.T, ctx context.Context, e env) {
				issueN(2, "ana")(t, ctx, e)
				e.clk.Advance(time.Hour)
			},
			assert: func(t *testing.T, _ env, _ string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrIssueLimitReached)
			},
		},
		{
			name:  "a limit below one refuses every issue",
			limit: 0,
			assert: func(t *testing.T, e env, _ string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrIssueLimitReached)
				assert.Zero(t, e.store.Len())
			},
		},
		{
			name:    "an empty subject is refused before the limit is consulted",
			subject: "-",
			limit:   5,
			assert: func(t *testing.T, e env, _ string, _ onetime.Token, err error) {
				require.ErrorIs(t, err, onetime.ErrSubjectRequired)
				assert.Zero(t, e.store.Len())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			clk := clockwork.NewFakeClockAt(issuedAt)
			m, store := newManager(t, clk)
			e := env{m: m, store: store, clk: clk}
			if tc.setup != nil {
				tc.setup(t, ctx, e)
			}

			subject := tc.subject
			switch subject {
			case "":
				subject = "ana"
			case "-":
				subject = ""
			}

			presented, tok, err := m.IssueWithin(ctx, subject, tc.limit)
			tc.assert(t, e, presented, tok, err)
		})
	}
}

func TestIssueWithin_StoreDecision(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		expect func(s *MockStore)
		assert func(t *testing.T, presented string, err error)
	}

	cases := []testCase{
		{
			name: "the store is asked once, with the window's start and the caller's limit",
			expect: func(s *MockStore) {
				s.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), issuedAt.Add(-time.Hour), 3).
					DoAndReturn(func(_ context.Context, tok onetime.Token, _ time.Time, _ int) (bool, error) {
						assert.Equal(t, "magic-link", tok.Purpose)
						assert.Equal(t, "ana", tok.Subject)
						return true, nil
					})
			},
			assert: func(t *testing.T, presented string, err error) {
				require.NoError(t, err)
				assert.NotEmpty(t, presented)
			},
		},
		{
			name: "a store that cannot decide is an outage, never the limit",
			expect: func(s *MockStore) {
				s.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, errStoreDown)
			},
			assert: func(t *testing.T, presented string, err error) {
				require.ErrorIs(t, err, errStoreDown)
				assert.NotErrorIs(t, err, onetime.ErrIssueLimitReached)
				assert.Empty(t, presented)
			},
		},
		{
			name: "a store that refuses is the limit",
			expect: func(s *MockStore) {
				s.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
			},
			assert: func(t *testing.T, presented string, err error) {
				require.ErrorIs(t, err, onetime.ErrIssueLimitReached)
				assert.Empty(t, presented)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewMockStore(gomock.NewController(t))
			tc.expect(store)
			m, err := onetime.NewManager("magic-link",
				onetime.WithStore(store), onetime.WithClock(clockwork.NewFakeClockAt(issuedAt)))
			require.NoError(t, err)

			presented, _, err := m.IssueWithin(t.Context(), "ana", 3)
			tc.assert(t, presented, err)
		})
	}
}

// TestIssueWithin_ConcurrentBoundedIssuesStayWithinLimit releases twenty
// bounded issues at once against a limit of five, for each of fifty subjects
// raced together: for every subject exactly five are issued and the rest are
// refused as the limit. Many subjects, not one, because a single burst over
// an in-memory store finishes too quickly to interleave reliably.
func TestIssueWithin_ConcurrentBoundedIssuesStayWithinLimit(t *testing.T) {
	t.Parallel()

	const subjects, racers, limit = 50, 20, 5

	m, store := newManager(t, clockwork.NewFakeClockAt(issuedAt))

	errs := make([][]error, subjects)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for s := range subjects {
		errs[s] = make([]error, racers)
		for i := range racers {
			wg.Go(func() {
				<-start
				_, _, errs[s][i] = m.IssueWithin(t.Context(), fmt.Sprintf("subject-%d", s), limit)
			})
		}
	}
	close(start)
	wg.Wait()

	for s, subjectErrs := range errs {
		issued, refused := 0, 0
		for _, err := range subjectErrs {
			switch {
			case err == nil:
				issued++
			case assert.ErrorIs(t, err, onetime.ErrIssueLimitReached):
				refused++
			}
		}
		assert.Equal(t, limit, issued, "subject %d: issued", s)
		assert.Equal(t, racers-limit, refused, "subject %d: refused as the limit", s)
	}
	assert.Equal(t, subjects*limit, store.Len(), "stored")
}
