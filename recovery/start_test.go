package recovery_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/notify"
	"github.com/kartaladev/scrty/onetime"
	"github.com/kartaladev/scrty/recovery"
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
			name: "an issuance count failure sends nothing and is logged",
			opts: func(f *fixture) []recovery.Option {
				store := NewMockTokenStore(f.ctrl)
				store.EXPECT().CountRecentBySubject(gomock.Any(), recovery.IssuedCodePurpose, string(anaID), gomock.Any()).Return(0, errOutage)

				return f.opts(recovery.WithIssuedCodeStore(store))
			},
			setup: loadsAna,
			assert: func(t *testing.T, f *fixture, r *recovery.Recoverer, run *startRun) {
				sendsNothing(t, f, r, run)
				logged(t, f, "token-count")
			},
		},
		{
			name: "a token store that cannot insert sends nothing and is logged",
			opts: func(f *fixture) []recovery.Option {
				store := NewMockTokenStore(f.ctrl)
				store.EXPECT().CountRecentBySubject(gomock.Any(), recovery.IssuedCodePurpose, string(anaID), gomock.Any()).Return(0, nil)
				store.EXPECT().Insert(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, tok onetime.Token) error {
					assert.Equal(t, string(anaID), tok.Subject, "the subject is the user reference, never the username")

					return errOutage
				})

				return f.opts(recovery.WithIssuedCodeStore(store))
			},
			setup: loadsAna,
			assert: func(t *testing.T, f *fixture, _ *recovery.Recoverer, run *startRun) {
				assert.Empty(t, run.sent)
				logged(t, f, "token-issue")
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

func TestDefaultMessages_IssuedCode(t *testing.T) {
	t.Parallel()

	subject, body := recovery.DefaultMessages().IssuedCode("tok.secret", monday1000.Add(15*time.Minute))

	assert.NotEmpty(t, subject)
	assert.Contains(t, body, "tok.secret")
	assert.Contains(t, body, "28 September 2026 10:15 UTC", "the expiry is stated")
	assert.Contains(t, body, "once", "single use is stated")
	assert.NotContains(t, body, "<", "plain text")
	assert.NotContains(t, strings.ToLower(body+subject), "scrty", "no brand is named")
}
