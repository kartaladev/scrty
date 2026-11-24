package oidcprovider_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/oidcprovider"
	"github.com/kartaladev/scrty/pkg/id"
)

// answerFailedLog is the record a dependency failure answered with server_error writes.
const answerFailedLog = "oidcprovider: a parked request could not be answered"

// dependencyArms are the writes a row fails, each while it is set.
type dependencyArms struct {
	// create fails the code store's Create, put the browser session store's Put, and
	// advance every pending-request spend, with errOutage.
	create, put, advance atomic.Bool
	// advanceLost answers every spend with ErrNotFound, as a spend lost to a race does.
	advanceLost atomic.Bool
	// hangUp fails the code store's Create with errOutage, which is no context error: the
	// row's context is cancelled, so only the provider's own check can keep it from answering.
	hangUp atomic.Bool
	// commitThenFail has the code store's Create write the record and then report errOutage,
	// as a store whose commit succeeded and whose acknowledgement was lost does.
	commitThenFail atomic.Bool
	// written is the last record the code store's Create was given.
	written atomic.Pointer[oidcprovider.CodeRecord]
	// grants is the grant store the provider was rebuilt over, set by dependencyProvider.
	grants *oidcprovider.MemoryGrantStore
	// revoke fails the grant store's Revoke with errOutage.
	revoke atomic.Bool
}

// revokeFailingGrants is a memory grant store whose Revoke fails while its arms say.
type revokeFailingGrants struct {
	*oidcprovider.MemoryGrantStore

	arms *dependencyArms
}

func (g revokeFailingGrants) Revoke(
	ctx context.Context, family id.ID, cause oidcprovider.RevocationCause, at time.Time,
) (bool, error) {
	if g.arms.revoke.Load() {
		return false, errOutage
	}

	return g.MemoryGrantStore.Revoke(ctx, family, cause, at)
}

// dependencyProvider is the fixture's provider rebuilt over mocks of the code, browser
// session and pending-request stores, each delegating to the fixture's memory store until a
// row arms its failure.
func dependencyProvider(t *testing.T, f *parkFixture, arms *dependencyArms, opts ...oidcprovider.Option) *oidcprovider.Provider {
	t.Helper()

	ctrl := gomock.NewController(t)
	memCodes := f.p.CodesForTest()
	codes := NewMockCodeStore(ctrl)
	codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, record *oidcprovider.CodeRecord) error {
			arms.written.Store(record)
			switch {
			case arms.hangUp.Load(), arms.create.Load():
				return errOutage
			case arms.commitThenFail.Load():
				if err := memCodes.Create(ctx, record); err != nil {
					return err
				}

				return errOutage
			}

			return memCodes.Create(ctx, record)
		}).AnyTimes()
	codes.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(memCodes.Load).AnyTimes()
	codes.EXPECT().UnspentByClient(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memCodes.UnspentByClient).AnyTimes()
	codes.EXPECT().UnspentBySignIn(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memCodes.UnspentBySignIn).AnyTimes()
	codes.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memCodes.DeleteExpired).AnyTimes()

	memSessions := f.p.BrowserSessionStoreForTest()
	sessions := NewMockBrowserSessionStore(ctrl)
	sessions.EXPECT().Put(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, s *oidcprovider.BrowserSession) error {
			if arms.put.Load() {
				return errOutage
			}

			return memSessions.Put(ctx, s)
		}).AnyTimes()
	sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Load).AnyTimes()
	sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Touch).AnyTimes()
	sessions.EXPECT().Delete(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.Delete).AnyTimes()
	sessions.EXPECT().DeleteBySignIn(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteBySignIn).AnyTimes()
	sessions.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memSessions.DeleteExpired).AnyTimes()

	pending := passThroughPending(t, f.store)
	pending.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(f.store.Load).AnyTimes()
	pending.EXPECT().Advance(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, digest []byte, from, to oidcprovider.Stage, s *oidcprovider.SignIn) error {
			switch {
			case arms.advanceLost.Load():
				return oidcprovider.ErrNotFound
			case arms.advance.Load():
				return errOutage
			}

			return f.store.Advance(ctx, digest, from, to, s)
		}).AnyTimes()

	grants, err := oidcprovider.NewMemoryGrantStore()
	require.NoError(t, err)
	arms.grants = grants

	return rebuilt(t, f, append([]oidcprovider.Option{
		oidcprovider.WithGrantStore(revokeFailingGrants{MemoryGrantStore: grants, arms: arms}),
		oidcprovider.WithCodeStore(codes),
		oidcprovider.WithBrowserSessionStore(sessions),
		oidcprovider.WithPendingRequestStore(pending),
	}, opts...)...)
}

// parkOn parks authzParams with p, which may be a provider rebuilt over the fixture.
func parkOn(t *testing.T, p *oidcprovider.Provider) parked {
	t.Helper()

	res, err := p.Authorize(t.Context(), oidcprovider.AuthorizeInput{Params: authzParams()})
	require.NoError(t, err)
	require.NotEmpty(t, res.FlowSecret, "the request was parked: %s", res.Location)

	return parked{handle: handleOf(t, res.Location), flow: res.FlowSecret}
}

// TestResume_DependencyFailureAnswersServerError answers a dependency failing after the
// request was read and judged with server_error at the redirect URI, spending the stage; and
// returns the failure unchanged, leaving the stage unspent, when the spend fails too (F12).
func TestResume_DependencyFailureAnswersServerError(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// consent answers the consent stage, which the row reaches with nothing armed.
		consent bool
		arm     func(*dependencyArms)
		ctx     func(ctx context.Context) context.Context
		assert  func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error)
	}

	answeredServerError := func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Equal(t, oidcprovider.ResumeOutcomeClientError, res.Outcome)
		assert.Empty(t, res.BrowserSessionSecret, "no session handed out")
		assert.True(t, strings.HasPrefix(res.RedirectTo, authzRedirect+"?"), res.RedirectTo)
		assert.Equal(t,
			map[string][]string{"error": {"server_error"}, "state": {authzState}, "iss": {issuer}},
			map[string][]string(queryOf(t, res.RedirectTo)), "server_error, state and iss, and no code or description")
		assert.Equal(t, oidcprovider.StageDone, stageOf(t, f, r), "the stage is spent")

		logs := f.logs.String()
		assert.Equal(t, 1, strings.Count(logs, answerFailedLog), "one record of the failure: %s", logs)
		assert.Contains(t, logs, "error_type=")
		for _, secret := range []string{r.handle, r.flow, authzRedirect, "state=" + authzState, errOutage.Error()} {
			assert.NotContains(t, logs, secret, "the log holds no handle, flow secret, state, redirect target or store text")
		}
	}
	unspentWith := func(want error, stage oidcprovider.Stage) func(*testing.T, *parkFixture, parked, oidcprovider.ResumeResult, error) {
		return func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
			t.Helper()
			require.ErrorIs(t, err, want)
			assert.NotContains(t, err.Error(), errOutage.Error())
			assert.Empty(t, res.RedirectTo, "no redirect")
			assert.Equal(t, oidcprovider.ResumeOutcomeUnknown, res.Outcome)
			assert.Equal(t, stage, stageOf(t, f, r), "the stage is left unspent")
			assert.NotContains(t, f.logs.String(), answerFailedLog, "nothing was answered")
		}
	}

	cases := []testCase{
		{
			name:   "login: the code cannot be stored",
			arm:    func(a *dependencyArms) { a.create.Store(true) },
			assert: answeredServerError,
		},
		{
			name:   "login: the browser session cannot be stored once the code is",
			arm:    func(a *dependencyArms) { a.put.Store(true) },
			assert: answeredServerError,
		},
		{
			name: "login: the code no answer carries cannot be withdrawn either, which is logged",
			arm:  func(a *dependencyArms) { a.put.Store(true); a.revoke.Store(true) },
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				answeredServerError(t, f, r, res, err)
				assert.Equal(t, 1, strings.Count(f.logs.String(), "a code no answer carried could not be withdrawn"))
			},
		},
		{
			name:    "consent: the code cannot be stored",
			consent: true,
			arm:     func(a *dependencyArms) { a.create.Store(true) },
			assert: func(t *testing.T, f *parkFixture, r parked, res oidcprovider.ResumeResult, err error) {
				t.Helper()
				answeredServerError(t, f, r, res, err)
				_, loadErr := f.consents.Load(t.Context(), "u-1", "billing-web")
				require.ErrorIs(t, loadErr, oidcprovider.ErrNotFound, "no consent is remembered for an answer that failed")
			},
		},
		{
			name:   "login: the code cannot be stored nor the request spent",
			arm:    func(a *dependencyArms) { a.create.Store(true); a.advance.Store(true) },
			assert: unspentWith(oidcprovider.ErrDependency, oidcprovider.StageLogin),
		},
		{
			name:    "consent: the code cannot be stored nor the request spent",
			consent: true,
			arm:     func(a *dependencyArms) { a.create.Store(true); a.advance.Store(true) },
			assert:  unspentWith(oidcprovider.ErrDependency, oidcprovider.StageConsent),
		},
		{
			name:   "login: a spend lost to a race is an unknown handle, and no server_error",
			arm:    func(a *dependencyArms) { a.advanceLost.Store(true) },
			assert: unspentWith(oidcprovider.ErrUnknownHandle, oidcprovider.StageLogin),
		},
		{
			name: "login: a caller that hung up is answered nothing",
			arm:  func(a *dependencyArms) { a.hangUp.Store(true) },
			ctx: func(ctx context.Context) context.Context {
				cctx, cancel := context.WithCancel(ctx)
				cancel()

				return cctx
			},
			assert: unspentWith(oidcprovider.ErrDependency, oidcprovider.StageLogin),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			if !tc.consent {
				rememberAll(t, f)
			}
			var arms dependencyArms
			p := dependencyProvider(t, f, &arms)
			r := parkOn(t, p)
			signIn := testSignIn(f, "u-1")
			in := r.input(&signIn)
			if tc.consent {
				_, err := p.Resume(t.Context(), in)
				require.NoError(t, err)
				require.Equal(t, oidcprovider.StageConsent, stageOf(t, f, r))
				in.Answer = &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}
			}
			tc.arm(&arms)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			res, err := p.Resume(ctx, in)
			tc.assert(t, f, r, res, err)
		})
	}
}

// TestEndPending_SpendFailureIsDependency: an end's one write is its spend, so a spend that
// fails is returned as the dependency failure it is, and the request stays parked.
func TestEndPending_SpendFailureIsDependency(t *testing.T) {
	t.Parallel()

	f := newParkFixture(t, issuer+"/login")
	var arms dependencyArms
	p := dependencyProvider(t, f, &arms)
	r := parkOn(t, p)
	arms.advance.Store(true)

	res, err := p.EndPending(t.Context(), r.end(oidcprovider.CodeAccessDenied))
	require.ErrorIs(t, err, oidcprovider.ErrDependency)
	assert.NotContains(t, err.Error(), errOutage.Error())
	assert.Empty(t, res.RedirectTo)
	assert.Equal(t, oidcprovider.StageLogin, stageOf(t, f, r), "the request stays parked")
}

// TestExchange_CodeLeftByFailedResumeIsRefused: a resume that wrote its code and then failed
// answers server_error, never the code, and that code is refused at the exchange even
// presented with everything it was issued for (F26). Two providers over the same random
// source draw the same code, so the first, which nothing fails, shows the second's code.
func TestExchange_CodeLeftByFailedResumeIsRefused(t *testing.T) {
	t.Parallel()

	seed := [32]byte{2, 6}
	codeOf := func(t *testing.T, arm bool) (string, *oidcprovider.Provider, oidcprovider.ResumeResult) {
		t.Helper()
		f := newParkFixture(t, issuer+"/login")
		rememberAll(t, f)
		var arms dependencyArms
		p := dependencyProvider(t, f, &arms, oidcprovider.WithRandom(rand.NewChaCha8(seed)))
		r := parkOn(t, p)
		arms.put.Store(arm)

		signIn := testSignIn(f, "u-1")
		res, err := p.Resume(t.Context(), r.input(&signIn))
		require.NoError(t, err)

		return queryOf(t, res.RedirectTo).Get("code"), p, res
	}

	handedOut, _, _ := codeOf(t, false)
	require.NotEmpty(t, handedOut, "precondition: nothing failing, the resume hands out its code")

	none, p, res := codeOf(t, true)
	require.Empty(t, none, "the failed resume hands out no code")
	require.Equal(t, "server_error", queryOf(t, res.RedirectTo).Get("error"))
	_, err := p.CodesForTest().Load(t.Context(), tokenIDOf(t, handedOut))
	require.NoError(t, err, "precondition: the failed resume wrote the code the first one handed out")

	tokens, err := p.Token(t.Context(), billingExchange(issuedCode{code: handedOut}, nil))
	assert.Nil(t, tokens, "no tokens for a code no answer carried")
	assertRefused(t, err, oidcprovider.CodeInvalidGrant)
}

// withdrawn asserts that the grant family of record is recorded revoked as unanswered,
// the mark the exchange refuses a code no answer carried by.
func withdrawn(t *testing.T, grants *oidcprovider.MemoryGrantStore, record *oidcprovider.CodeRecord) {
	t.Helper()

	require.NotNil(t, record, "the code store was asked to write a code")
	grant, err := grants.Load(t.Context(), record.GrantFamily)
	require.NoError(t, err, "the code's family is recorded")
	assert.True(t, grant.Revoked)
	assert.Equal(t, oidcprovider.CauseUnanswered, grant.RevokeCause)
}

// TestResume_CommittedCodeWriteFailureIsWithdrawn: a code store that commits the record and
// then reports a failure leaves a code no answer carries, so the resume answers server_error
// and records the code's family revoked (F26).
func TestResume_CommittedCodeWriteFailureIsWithdrawn(t *testing.T) {
	t.Parallel()

	for _, consent := range []bool{false, true} {
		name := "login"
		if consent {
			name = "consent"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newParkFixture(t, issuer+"/login")
			if !consent {
				rememberAll(t, f)
			}
			var arms dependencyArms
			p := dependencyProvider(t, f, &arms)
			r := parkOn(t, p)
			signIn := testSignIn(f, "u-1")
			in := r.input(&signIn)
			if consent {
				_, err := p.Resume(t.Context(), in)
				require.NoError(t, err)
				in.Answer = &oidcprovider.ConsentAnswer{Scopes: []string{"openid"}}
			}
			arms.commitThenFail.Store(true)

			res, err := p.Resume(t.Context(), in)
			require.NoError(t, err)
			answer := queryOf(t, res.RedirectTo)
			assert.Equal(t, "server_error", answer.Get("error"))
			assert.Empty(t, answer.Get("code"))
			withdrawn(t, arms.grants, arms.written.Load())
		})
	}
}

// TestAuthorize_SessionTouchFailureWithdrawsCode: answering from a browser session writes a
// code before the session is touched, so a touch that fails, or a code write that committed
// and then failed, answers server_error and records the code's family revoked (F29).
func TestAuthorize_SessionTouchFailureWithdrawsCode(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name           string
		commitThenFail bool
		touch          error
	}
	cases := []testCase{
		{name: "the touch fails after the code is written", touch: errOutage},
		{name: "the code write commits and then fails", commitThenFail: true},
		{name: "the session ended while the code was written, which answers no session", touch: oidcprovider.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
			family, err := id.NewV7Generator().NewID()
			require.NoError(t, err)
			held := &oidcprovider.BrowserSession{
				Digest: digestOf(t, sessionSecret),
				SignIn: oidcprovider.SignIn{
					User: "u-1", Family: family, AuthenticatedAt: now.Add(-time.Minute), AMR: []string{"pwd"},
					AbsoluteExpiresAt: now.Add(time.Hour),
				},
				IdleExpiresAt:     now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(time.Hour),
			}
			ctrl := gomock.NewController(t)
			sessions := NewMockBrowserSessionStore(ctrl)
			sessions.EXPECT().Load(gomock.Any(), gomock.Any(), gomock.Any()).Return(held, nil).AnyTimes()
			sessions.EXPECT().Touch(gomock.Any(), gomock.Any(), gomock.Any()).Return(tc.touch).AnyTimes()

			memCodes, err := oidcprovider.NewMemoryCodeStore()
			require.NoError(t, err)
			var written atomic.Pointer[oidcprovider.CodeRecord]
			codes := NewMockCodeStore(ctrl)
			codes.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ctx context.Context, record *oidcprovider.CodeRecord) error {
					written.Store(record)
					if err := memCodes.Create(ctx, record); err != nil {
						return err
					}
					if tc.commitThenFail {
						return errOutage
					}

					return nil
				}).AnyTimes()
			codes.EXPECT().Load(gomock.Any(), gomock.Any()).DoAndReturn(memCodes.Load).AnyTimes()
			codes.EXPECT().UnspentByClient(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memCodes.UnspentByClient).AnyTimes()
			codes.EXPECT().UnspentBySignIn(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(memCodes.UnspentBySignIn).AnyTimes()
			codes.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).DoAndReturn(memCodes.DeleteExpired).AnyTimes()
			grants, err := oidcprovider.NewMemoryGrantStore()
			require.NoError(t, err)

			f := newSessionFixture(t, plainKeys(t),
				oidcprovider.WithBrowserSessionStore(sessions),
				oidcprovider.WithCodeStore(codes),
				oidcprovider.WithGrantStore(grants),
			)
			rememberAll(t, f.parkFixture)

			res, err := f.p.Authorize(t.Context(), oidcprovider.AuthorizeInput{
				Params: authzParams(), BrowserSessionSecret: sessionSecret, IdleTimeout: sessionIdle,
			})

			if tc.touch != nil && errors.Is(tc.touch, oidcprovider.ErrNotFound) {
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(res.Location, issuer+"/login?"), res.Location)
			} else {
				serverError(t, res, err)
			}
			withdrawn(t, grants, written.Load())
		})
	}
}
