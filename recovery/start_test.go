package recovery_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/internal/must"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/recovery"
	"github.com/kartaladev/scrty/token/onetime"
)

// startRun is what one Start case observed: every message sent, and every
// code the message builder was handed.
type startRun struct {
	sent  []notify.Message
	codes []string
}

func TestRecoverer_Start(t *testing.T) {
	t.Parallel()

	errOutage := errors.New("store unreachable: ana@example.com")

	type testCase struct {
		name  string
		opts  func(f *fixture) []recovery.Option
		setup func(f *fixture)
		ctx   func(ctx context.Context) context.Context
		// act runs Start; nil starts once for ana@example.com.
		act    func(ctx context.Context, f *fixture, r *recovery.Recoverer)
		assert func(t *testing.T, f *fixture, r *recovery.Recoverer, run *startRun)
	}

	loadsAna := func(f *fixture) {
		f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(anaDetails(), nil).AnyTimes()
	}
	sendsNothing := func(t *testing.T, _ *fixture, _ *recovery.Recoverer, run *startRun) {
		t.Helper()
		assert.Empty(t, run.sent)
		assert.Empty(t, run.codes)
	}
	logged := func(t *testing.T, f *fixture, text string) {
		t.Helper()
		assert.Contains(t, f.logs.String(), text)
	}

	cases := []testCase{
		{
			name:  "a code is sent to the contact address",
			setup: loadsAna,
			assert: func(t *testing.T, _ *fixture, r *recovery.Recoverer, run *startRun) {
				require.Len(t, run.sent, 1)
				require.Len(t, run.codes, 1)
				assert.Equal(t, anaUsername, run.sent[0].To)
				assert.Contains(t, run.sent[0].TextBody, run.codes[0])
				require.NoError(t, r.CheckIssued(t.Context(), anaID, run.codes[0]), "the code sent is one ana can present")
			},
		},
		{
			name: "a consumer resolver chooses the address",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(recovery.WithContactResolver(func(_ context.Context, d *identity.Details) (string, error) {
					assert.Equal(t, anaID, d.ID)

					return "ana.home@example.com", nil
				}))
			},
			setup: loadsAna,
			assert: func(t *testing.T, _ *fixture, _ *recovery.Recoverer, run *startRun) {
				require.Len(t, run.sent, 1)
				assert.Equal(t, "ana.home@example.com", run.sent[0].To)
			},
		},
		{
			name: "the message builder's wording is sent, and the library sets the recipient",
			opts: func(f *fixture) []recovery.Option {
				msgs := NewMockMessages(f.ctrl)
				msgs.EXPECT().IssuedCode(gomock.Any(), monday1000.Add(15*time.Minute)).Return("custom subject", "custom body")

				return f.opts(recovery.WithMessages(msgs))
			},
			setup: loadsAna,
			assert: func(t *testing.T, _ *fixture, _ *recovery.Recoverer, run *startRun) {
				require.Len(t, run.sent, 1)
				assert.Equal(t, notify.Message{To: anaUsername, Subject: "custom subject", TextBody: "custom body"}, run.sent[0])
			},
		},
		{
			name: "an unknown username sends nothing",
			setup: func(f *fixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(nil, identity.ErrUserNotFound)
			},
			assert: sendsNothing,
		},
		{
			name: "a disabled user is sent nothing",
			setup: func(f *fixture) {
				d := anaDetails()
				d.Active = false
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(d, nil)
			},
			assert: sendsNothing,
		},
		{
			name: "a user with no reference is sent nothing",
			setup: func(f *fixture) {
				d := anaDetails()
				d.ID = ""
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(d, nil)
			},
			assert: sendsNothing,
		},
		{
			name: "a lookup failure sends nothing and is logged",
			setup: func(f *fixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).Return(nil, errOutage)
			},
			assert: func(t *testing.T, f *fixture, r *recovery.Recoverer, run *startRun) {
				sendsNothing(t, f, r, run)
				logged(t, f, "user-loader")
			},
		},
		{
			name: "a cancelled context sends nothing",
			setup: func(f *fixture) {
				f.users.EXPECT().LoadByUsername(gomock.Any(), anaUsername).DoAndReturn(
					func(ctx context.Context, _ string) (*identity.Details, error) { return nil, ctx.Err() })
			},
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: sendsNothing,
		},
		{
			name: "an empty username looks nothing up and sends nothing",
			act: func(ctx context.Context, _ *fixture, r *recovery.Recoverer) {
				r.Start(ctx, "")
			},
			assert: sendsNothing,
		},
		{
			name:  "the issuance limit: after five codes the sixth start sends nothing",
			setup: loadsAna,
			act: func(ctx context.Context, _ *fixture, r *recovery.Recoverer) {
				for range 6 {
					r.Start(ctx, anaUsername)
				}
			},
			assert: func(t *testing.T, f *fixture, _ *recovery.Recoverer, run *startRun) {
				assert.Len(t, run.sent, 5)
				logged(t, f, "issuance limit")
			},
		},
		{
			name:  "a consumer issuance limit",
			opts:  func(f *fixture) []recovery.Option { return f.opts(recovery.WithIssuedCodeLimit(2)) },
			setup: loadsAna,
			act: func(ctx context.Context, _ *fixture, r *recovery.Recoverer) {
				for range 3 {
					r.Start(ctx, anaUsername)
				}
			},
			assert: func(t *testing.T, _ *fixture, _ *recovery.Recoverer, run *startRun) {
				assert.Len(t, run.sent, 2)
			},
		},
		{
			name: "a token store that cannot decide the bounded issue sends nothing and is logged",
			opts: func(f *fixture) []recovery.Option {
				store := NewMockTokenStore(f.ctrl)
				store.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), 5).
					DoAndReturn(func(_ context.Context, tok onetime.Token, _ time.Time, _ int) (bool, error) {
						assert.Equal(t, recovery.IssuedCodePurpose, tok.Purpose)
						assert.Equal(t, string(anaID), tok.Subject, "the subject is the user reference, never the username")

						return false, errOutage
					})

				return f.opts(recovery.WithIssuedCodeStore(store))
			},
			setup: loadsAna,
			assert: func(t *testing.T, f *fixture, r *recovery.Recoverer, run *startRun) {
				sendsNothing(t, f, r, run)
				logged(t, f, "token-issue")
			},
		},
		{
			name: "a store refusing the bounded issue at the limit sends nothing and is logged",
			opts: func(f *fixture) []recovery.Option {
				store := NewMockTokenStore(f.ctrl)
				store.EXPECT().InsertWithin(gomock.Any(), gomock.Any(), gomock.Any(), 5).Return(false, nil)

				return f.opts(recovery.WithIssuedCodeStore(store))
			},
			setup: loadsAna,
			assert: func(t *testing.T, f *fixture, r *recovery.Recoverer, run *startRun) {
				sendsNothing(t, f, r, run)
				logged(t, f, "issuance limit")
			},
		},
		{
			name: "a contact resolver failure sends nothing and is logged",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(recovery.WithContactResolver(func(context.Context, *identity.Details) (string, error) {
					return "", errOutage
				}))
			},
			setup: loadsAna,
			assert: func(t *testing.T, f *fixture, r *recovery.Recoverer, run *startRun) {
				sendsNothing(t, f, r, run)
				logged(t, f, "contact-resolver")
			},
		},
		{
			name: "the sender refuses: nothing panics and the reason is logged",
			setup: func(f *fixture) {
				loadsAna(f)
				f.sender.EXPECT().Send(gomock.Any(), gomock.Any()).Return(notify.ErrQueueFull)
			},
			assert: func(t *testing.T, f *fixture, _ *recovery.Recoverer, _ *startRun) {
				logged(t, f, "sender")
			},
		},
		{
			name: "issued codes not enabled: nothing is looked up or sent",
			opts: func(f *fixture) []recovery.Option {
				return f.opts(recovery.WithProofs(recovery.ProofSaved, recovery.ProofPassword),
					recovery.WithPasswordCheck(func(context.Context, string, []byte) error { return nil }))
			},
			assert: sendsNothing,
		},
		{
			name:  "an expired code: sent at 10:00, still good at 10:14, refused at 10:16",
			setup: loadsAna,
			assert: func(t *testing.T, f *fixture, r *recovery.Recoverer, run *startRun) {
				require.Len(t, run.codes, 1)

				f.clock.Advance(14 * time.Minute)
				require.NoError(t, r.CheckIssued(t.Context(), anaID, run.codes[0]))

				f.clock.Advance(2 * time.Minute)
				require.ErrorIs(t, r.CheckIssued(t.Context(), anaID, run.codes[0]), recovery.ErrRefused)
			},
		},
		{
			name:  "a code is refused for another user",
			setup: loadsAna,
			assert: func(t *testing.T, _ *fixture, r *recovery.Recoverer, run *startRun) {
				require.Len(t, run.codes, 1)
				require.ErrorIs(t, r.CheckIssued(t.Context(), "u-2", run.codes[0]), recovery.ErrRefused)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			run := &startRun{}

			if tc.setup != nil {
				tc.setup(f)
			}

			// The sender records every message; a case expecting a refusal has
			// set its own expectation first, which gomock matches first.
			f.sender.EXPECT().Send(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, m notify.Message) error {
				run.sent = append(run.sent, m)

				return nil
			}).AnyTimes()

			// The capturing builder comes first, so a case's own WithMessages,
			// given later, replaces it.
			opts := append([]recovery.Option{recovery.WithMessages(capturingMessages(f, run))}, f.opts()...)
			if tc.opts != nil {
				opts = append([]recovery.Option{recovery.WithMessages(capturingMessages(f, run))}, tc.opts(f)...)
			}

			r, err := recovery.NewRecoverer(f.deps(), opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			if tc.act != nil {
				tc.act(ctx, f, r)
			} else {
				r.Start(ctx, anaUsername)
			}

			tc.assert(t, f, r, run)

			logs := f.logs.String()
			assert.NotContains(t, logs, anaUsername, "no record names the username or the address")
			assert.NotContains(t, logs, "ana.home", "no record names the address")
			for _, code := range run.codes {
				assert.NotContains(t, logs, code, "no record carries the code")
			}
		})
	}
}

// capturingMessages is a message builder that records every code it is handed
// and otherwise writes the default messages.
func capturingMessages(f *fixture, run *startRun) recovery.Messages {
	msgs := NewMockMessages(f.ctrl)
	msgs.EXPECT().IssuedCode(gomock.Any(), gomock.Any()).DoAndReturn(func(code string, until time.Time) (string, string) {
		run.codes = append(run.codes, code)

		return recovery.DefaultMessages().IssuedCode(code, until)
	}).AnyTimes()

	return msgs
}

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
// It stands apart from TestRecoverer_Start because it runs twenty goroutines
// over a token store that holds them at the count.
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
		MemoryStore: must.Must(onetime.NewMemoryStore(onetime.WithMemoryStoreClock(f.clock))),
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
