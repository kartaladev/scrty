package oidc_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
)

// handoffPasswordChangedAt is when the redeeming user last changed password.
var handoffPasswordChangedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// handoffUser returns the loader's record for user reference u-1.
func handoffUser() *identity.Details {
	return &identity.Details{
		ID:                "u-1",
		Name:              "Alice",
		Username:          "alice",
		Active:            true,
		Roles:             []*identity.AssignedRole{{ID: "r-1", Name: "editor", Primary: true}},
		PasswordChangedAt: handoffPasswordChangedAt,
	}
}

// handoffRedeemFixture is one issued code and everything around it.
type handoffRedeemFixture struct {
	ctrl  *gomock.Controller
	clock *handoffClock
	mem   *oidc.MemoryHandoffStore
	users *MockUserLoader
	logs  *handoffLogSink
	m     *oidc.HandoffManager
	code  string
}

// consumed reports whether the fixture's code has been spent.
func (f *handoffRedeemFixture) consumed(t *testing.T) bool {
	t.Helper()

	tokenID, _ := splitHandoffCode(t, f.code)
	rec, err := f.mem.FindByTokenID(t.Context(), tokenID)
	require.NoError(t, err)
	return rec.ConsumedAt != nil
}

// wrongSecret is the fixture's code with a well-formed secret that is not its
// own.
func (f *handoffRedeemFixture) wrongSecret(t *testing.T) string {
	t.Helper()

	tokenID, _ := splitHandoffCode(t, f.code)
	return tokenID + "." + strings.Repeat("A", 43)
}

// newHandoffRedeemFixture issues one code at handoffT0 into an in-memory store
// and builds the manager under test over store(mem), or over mem itself.
func newHandoffRedeemFixture(
	t *testing.T,
	store func(t *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore,
) *handoffRedeemFixture {
	t.Helper()

	f := &handoffRedeemFixture{ctrl: gomock.NewController(t), clock: newHandoffClock(handoffT0), logs: &handoffLogSink{}}
	f.mem = oidc.NewMemoryHandoffStore()
	f.users = NewMockUserLoader(f.ctrl)

	issuer, err := oidc.NewHandoffManager(f.mem, NewMockUserLoader(f.ctrl), oidc.WithHandoffClock(f.clock.Now))
	require.NoError(t, err)
	f.code, err = issuer.Issue(t.Context(), handoffCallback())
	require.NoError(t, err)

	var s oidc.HandoffStore = f.mem
	if store != nil {
		s = store(t, f.ctrl, f.mem)
	}
	f.m, err = oidc.NewHandoffManager(s, f.users,
		oidc.WithHandoffClock(f.clock.Now), oidc.WithHandoffLogger(f.logs.Logger()))
	require.NoError(t, err)

	return f
}

// refusedAsInvalid asserts the one outcome every non-check failure has.
func refusedAsInvalid(t *testing.T, res oidc.HandoffResult, err error) {
	t.Helper()

	require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
	assert.Same(t, oidc.ErrInvalidHandoff, err, "every refusal is the sentinel itself, with nothing wrapped around it")
	assert.ErrorIs(t, err, authenticate.ErrAuthenticationFailed)
	assert.Zero(t, res, "a refused redemption yields no principal")
}

// loggedAt asserts the fixture logged at level and, unless level is ERROR, at
// nothing higher.
func loggedAt(t *testing.T, f *handoffRedeemFixture, level string) {
	t.Helper()

	logs := f.logs.String()
	assert.Contains(t, logs, "level="+level)
	if level != "ERROR" {
		assert.NotContains(t, logs, "level=ERROR", "a refusal that is not an outage is not an error")
	}
}

// handoffBcryptHash is a bcrypt-shaped value a consumer port's error might
// quote.
const handoffBcryptHash = "$2a$12$" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0"

func TestHandoffRedeem(t *testing.T) {
	t.Parallel()

	errRefusedByCheck := errors.New("password too old")

	// delegating returns a store mock whose finds and inserts go to mem, so a
	// row can fail just one operation.
	delegating := func(t *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) *MockHandoffStore {
		t.Helper()
		s := NewMockHandoffStore(ctrl)
		s.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).DoAndReturn(mem.FindByTokenID).AnyTimes()
		return s
	}
	// untouched returns a store mock that fails the row on any call.
	untouched := func(_ *testing.T, ctrl *gomock.Controller, _ *oidc.MemoryHandoffStore) oidc.HandoffStore {
		return NewMockHandoffStore(ctrl)
	}

	type testCase struct {
		name    string
		store   func(t *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore
		arrange func(t *testing.T, f *handoffRedeemFixture)
		code    func(t *testing.T, f *handoffRedeemFixture) string
		checks  func(t *testing.T, f *handoffRedeemFixture) []oidc.RedeemCheck
		ctx     func(ctx context.Context) context.Context
		assert  func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error)
	}

	cases := []testCase{
		{
			name: "a valid code redeems once",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.clock.Set(handoffT0.Add(30 * time.Second))
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, *identity.PrincipalFromDetails(handoffUser()), res.Principal)
				assert.Equal(t, handoffPasswordChangedAt, res.PasswordChangedAt)
				assert.Equal(t, "corp", res.Provider)
				assert.Equal(t, "https://corp.example", res.Issuer)
				assert.Equal(t, "sid-1", res.SessionID)
				assert.Equal(t, handoffIDToken, res.IDToken)
				assert.Equal(t, "/dashboard", res.Next)

				tokenID, _ := splitHandoffCode(t, f.code)
				rec, ferr := f.mem.FindByTokenID(t.Context(), tokenID)
				require.NoError(t, ferr)
				require.NotNil(t, rec.ConsumedAt, "a redeemed code is spent")
				assert.Equal(t, handoffT0.Add(30*time.Second), *rec.ConsumedAt)

				again, err := f.m.Redeem(t.Context(), f.code)
				refusedAsInvalid(t, again, err)
			},
		},
		{
			name:  "malformed: no separator",
			store: untouched,
			code:  func(*testing.T, *handoffRedeemFixture) string { return strings.Repeat("A", 66) },
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
			},
		},
		{
			name:  "malformed: a second separator",
			store: untouched,
			code:  func(_ *testing.T, f *handoffRedeemFixture) string { return f.code + ".x" },
			assert: func(t *testing.T, _ *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
			},
		},
		{
			name:  "malformed: halves of the wrong length",
			store: untouched,
			code: func(t *testing.T, f *handoffRedeemFixture) string {
				tokenID, secret := splitHandoffCode(t, f.code)
				return tokenID[:21] + "." + secret
			},
			assert: func(t *testing.T, _ *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
			},
		},
		{
			name:  "malformed: characters outside base64url",
			store: untouched,
			code: func(t *testing.T, f *handoffRedeemFixture) string {
				tokenID, secret := splitHandoffCode(t, f.code)
				return tokenID + "." + "+" + secret[1:]
			},
			assert: func(t *testing.T, _ *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
			},
		},
		{
			name:  "malformed: empty",
			store: untouched,
			code:  func(*testing.T, *handoffRedeemFixture) string { return "" },
			assert: func(t *testing.T, _ *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
			},
		},
		{
			name: "unknown",
			code: func(t *testing.T, f *handoffRedeemFixture) string {
				_, secret := splitHandoffCode(t, f.code)
				return strings.Repeat("B", 22) + "." + secret
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
				assert.False(t, f.consumed(t))
			},
		},
		{
			name: "wrong secret",
			code: func(t *testing.T, f *handoffRedeemFixture) string { return f.wrongSecret(t) },
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
				assert.False(t, f.consumed(t), "a wrong secret spends nothing")
			},
		},
		{
			name:    "expired: exactly at the expiry",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) { f.clock.Set(handoffT0.Add(oidc.HandoffTTL)) },
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
				assert.False(t, f.consumed(t))
			},
		},
		{
			name: "one nanosecond before the expiry redeems",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.clock.Set(handoffT0.Add(oidc.HandoffTTL - time.Nanosecond))
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, _ oidc.HandoffResult, err error) {
				require.NoError(t, err)
				assert.True(t, f.consumed(t))
			},
		},
		{
			name: "a clock stepped back before issue still redeems",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.clock.Set(handoffT0.Add(-5 * time.Second))
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
			},
			assert: func(t *testing.T, _ *handoffRedeemFixture, _ oidc.HandoffResult, err error) {
				require.NoError(t, err)
			},
		},
		{
			// No loader expectation: the fast path must refuse before loading.
			name: "already consumed, and the fast path skips the loader",
			arrange: func(t *testing.T, f *handoffRedeemFixture) {
				tokenID, _ := splitHandoffCode(t, f.code)
				require.NoError(t, f.mem.Consume(t.Context(), tokenID, handoffT0))
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
			},
		},
		{
			name: "a disabled user and a wrong secret look alike",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				disabled := handoffUser()
				disabled.Active = false
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(disabled, nil)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				_, wrongErr := f.m.Redeem(t.Context(), f.wrongSecret(t))
				assert.Equal(t, wrongErr, err, "a disabled user and a wrong secret must be indistinguishable")
				assert.Equal(t, wrongErr.Error(), err.Error())
				loggedAt(t, f, "DEBUG")
				assert.False(t, f.consumed(t), "a refused account leaves the code")
			},
		},
		{
			name: "a missing user leaves the code",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, identity.ErrUserNotFound)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
				assert.False(t, f.consumed(t))
			},
		},
		{
			name: "a loader returning no details and no error leaves the code",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, nil)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				assert.False(t, f.consumed(t))
			},
		},
		{
			name: "a reference mismatch leaves the code",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				other := handoffUser()
				other.ID = "u-2"
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(other, nil)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
				assert.False(t, f.consumed(t), "a mismatched account leaves the code")
			},
		},
		{
			name: "a loader outage then success",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				gomock.InOrder(
					f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
						Return(nil, errors.New("connection refused")),
					f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil),
				)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "ERROR")
				assert.False(t, f.consumed(t), "an outage leaves the code")

				again, err := f.m.Redeem(t.Context(), f.code)
				require.NoError(t, err, "the same code redeems once the loader recovers")
				assert.Equal(t, identity.UserID("u-1"), again.Principal.ID)
				assert.True(t, f.consumed(t))
			},
		},
		{
			name: "a check refusal is returned unwrapped and leaves the code",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil).Times(2)
			},
			checks: func(*testing.T, *handoffRedeemFixture) []oidc.RedeemCheck {
				return []oidc.RedeemCheck{func(context.Context, identity.Principal, time.Time) error {
					return errRefusedByCheck
				}}
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				assert.Same(t, errRefusedByCheck, err, "a check's own error is returned exactly")
				assert.Zero(t, res)
				assert.False(t, f.consumed(t), "a check refusal leaves the code")

				pass := func(context.Context, identity.Principal, time.Time) error { return nil }
				_, err = f.m.Redeem(t.Context(), f.code, pass)
				require.NoError(t, err, "a following redemption with a passing check succeeds")
				assert.True(t, f.consumed(t))
			},
		},
		{
			name: "checks run in order, see the principal, and stop at the first refusal",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
			},
			checks: func(t *testing.T, _ *handoffRedeemFixture) []oidc.RedeemCheck {
				var calls []int
				t.Cleanup(func() { assert.Equal(t, []int{1, 2}, calls, "the third check must not run") })
				record := func(n int, err error) oidc.RedeemCheck {
					return func(_ context.Context, p identity.Principal, changed time.Time) error {
						calls = append(calls, n)
						assert.Equal(t, identity.UserID("u-1"), p.ID)
						assert.Equal(t, handoffPasswordChangedAt, changed)
						return err
					}
				}
				return []oidc.RedeemCheck{record(1, nil), nil, record(2, errRefusedByCheck), record(3, nil)}
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, _ oidc.HandoffResult, err error) {
				assert.Same(t, errRefusedByCheck, err)
				assert.False(t, f.consumed(t))
			},
		},
		{
			name: "a consume failure is invalid-handoff and yields no principal",
			store: func(t *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := delegating(t, ctrl, mem)
				s.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("db down"))
				return s
			},
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "ERROR")
			},
		},
		{
			name: "a lost consume race is invalid-handoff",
			store: func(t *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := delegating(t, ctrl, mem)
				s.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).Return(oidc.ErrHandoffNotFound)
				return s
			},
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
			},
		},
		{
			name: "a store find outage is invalid-handoff",
			store: func(_ *testing.T, ctrl *gomock.Controller, _ *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := NewMockHandoffStore(ctrl)
				s.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).Return(nil, errors.New("db down"))
				return s
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "ERROR")
			},
		},
		{
			name: "a store returning no record and no error is invalid-handoff",
			store: func(_ *testing.T, ctrl *gomock.Controller, _ *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := NewMockHandoffStore(ctrl)
				s.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).Return(nil, nil)
				return s
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "ERROR")
			},
		},
		{
			// The loader's error text never reaches the log at all: the
			// record carries a fixed reason and the error's type (see
			// diagnostic-redaction), not a scrubbed copy of its text.
			name: "a loader error's text never reaches the log",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
					Return(nil, errors.New("scan failed: row password="+handoffBcryptHash))
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "ERROR")
				logs := f.logs.String()
				assert.NotContains(t, logs, handoffBcryptHash, "a loader error's hash reaches the log")
				assert.NotContains(t, logs, "scan failed", "the loader's own text reaches the log")
				assert.Contains(t, logs, "reason=user-loader")
				assert.Contains(t, logs, "error_type=")
			},
		},
		{
			name: "a consume error's text never reaches the log",
			store: func(t *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := delegating(t, ctrl, mem)
				s.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(fmt.Errorf("update handoff for user_ref=u-1 hash=%s failed", handoffBcryptHash))
				return s
			},
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "ERROR")
				logs := f.logs.String()
				assert.NotContains(t, logs, "user_ref=u-1", "a store error's user reference reaches the log")
				assert.NotContains(t, logs, handoffBcryptHash, "a store error's hash reaches the log")
				assert.NotContains(t, logs, "update handoff", "the store's own text reaches the log")
				assert.Contains(t, logs, "reason=handoff-store")
				assert.Contains(t, logs, "error_type=")
			},
		},
		{
			name: "a find error's text never reaches the log",
			store: func(_ *testing.T, ctrl *gomock.Controller, _ *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := NewMockHandoffStore(ctrl)
				s.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, tokenID string) (*oidc.HandoffRecord, error) {
						return nil, fmt.Errorf("select handoff token_id=%s: timeout", tokenID)
					})
				return s
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "ERROR")
				logs := f.logs.String()
				assert.NotContains(t, logs, "select handoff", "the store's own text reaches the log")
				assert.Contains(t, logs, "reason=handoff-store")
				assert.Contains(t, logs, "error_type=")
				// The runner asserts the token id itself is absent.
			},
		},
		{
			name: "a cancelled request spends nothing",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil).MaxTimes(1)
			},
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()
				return c
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				assert.False(t, f.consumed(t), "a request nobody will read the answer to must not spend the code")
			},
		},
		{
			name: "no error or log contains the code",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("connection refused")).AnyTimes()
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				for _, c := range []string{f.code, f.wrongSecret(t), f.code + ".x", ""} {
					_, err := f.m.Redeem(t.Context(), c)
					require.Error(t, err)
				}
				// The runner asserts no code, half of one, or ID token in the
				// logs or the errors, for every row.
				assert.NotEmpty(t, f.logs.String())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newHandoffRedeemFixture(t, tc.store)
			if tc.arrange != nil {
				tc.arrange(t, f)
			}
			code := f.code
			if tc.code != nil {
				code = tc.code(t, f)
			}
			var checks []oidc.RedeemCheck
			if tc.checks != nil {
				checks = tc.checks(t, f)
			}
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}

			res, err := f.m.Redeem(ctx, code, checks...)
			tc.assert(t, f, res, err)

			tokenID, secret := splitHandoffCode(t, f.code)
			logs := f.logs.String()
			for _, secretValue := range []string{f.code, tokenID, secret, handoffIDToken} {
				assert.NotContains(t, logs, secretValue, "a log record carries the code or the ID token")
				if err != nil {
					assert.NotContains(t, err.Error(), secretValue, "the error carries the code or the ID token")
				}
			}
		})
	}
}

// TestHandoffRedeemRacing redeems one code from eight goroutines released
// together, over the in-memory store: exactly one wins.
func TestHandoffRedeemRacing(t *testing.T) {
	t.Parallel()

	const racers = 8

	f := newHandoffRedeemFixture(t, nil)
	f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil).AnyTimes()

	var (
		start = make(chan struct{})
		wg    sync.WaitGroup
		errs  = make([]error, racers)
	)
	for i := range racers {
		wg.Go(func() {
			<-start
			_, errs[i] = f.m.Redeem(t.Context(), f.code)
		})
	}
	close(start)
	wg.Wait()

	won, refused := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, oidc.ErrInvalidHandoff):
			refused++
		default:
			t.Errorf("redemption %d failed with %v, not the invalid-handoff outcome", i, err)
		}
	}
	assert.Equal(t, 1, won, "exactly one racing redemption may succeed")
	assert.Equal(t, racers-1, refused)
	assert.True(t, f.consumed(t))
}
