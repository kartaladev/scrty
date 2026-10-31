package oidc_test

//go:generate mockgen -destination=handoff_idgenerator_mock_test.go -package=oidc_test -typed -mock_names=Generator=MockHandoffIDGenerator github.com/kartaladev/scrty/pkg/id Generator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/authenticate"
	"github.com/kartaladev/scrty/authenticate/oidc"
	"github.com/kartaladev/scrty/expiry"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/pkg/id"
)

// handoffT0 is when every handoff in the issue and redeem tables is issued.
var handoffT0 = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

// handoffIDToken stands in for the raw ID token a callback verified.
const handoffIDToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzLTEifQ.c2lnbmF0dXJl" //nolint:gosec // G101: a test fixture, not a credential

// handoffCallback is the completed callback a handoff is issued for.
func handoffCallback() oidc.CallbackResult {
	return oidc.CallbackResult{
		Principal: &identity.Principal{ID: "u-1", Username: "alice"},
		Provider:  "corp",
		Issuer:    "https://corp.example",
		SessionID: "sid-1",
		IDToken:   handoffIDToken,
		Next:      "/dashboard",
	}
}

// handoffLogSink collects every record a handoff manager writes, at every
// level, and is safe for concurrent writes.
type handoffLogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *handoffLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *handoffLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *handoffLogSink) Logger() *slog.Logger {
	return testTextLogger(s)
}

// handoffFixedRandom returns a source yielding bytes 0, 1, 2, ... n-1 and then
// EOF, so the code it produces is known in advance.
func handoffFixedRandom(n int) io.Reader {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return bytes.NewReader(b)
}

// splitHandoffCode returns the token id and secret halves of a code.
func splitHandoffCode(t *testing.T, code string) (tokenID, secret string) {
	t.Helper()

	tokenID, secret, ok := strings.Cut(code, ".")
	require.True(t, ok, "a handoff code is <tokenID>.<secret>")
	return tokenID, secret
}

func TestHandoffIssue(t *testing.T) {
	t.Parallel()

	type deps struct {
		store oidc.HandoffStore
		clock *clockwork.FakeClock
		m     *oidc.Handoff
		users *MockUserLoader
	}

	type testCase struct {
		name string
		// setup returns the store the manager writes to and extra options.
		setup  func(t *testing.T, ctrl *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption)
		res    func() oidc.CallbackResult
		ctx    func(ctx context.Context) context.Context
		assert func(t *testing.T, d deps, code string, err error)
	}

	memory := func(*testing.T, *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
		return oidc.NewMemoryHandoffStore(), nil
	}

	stored := func(t *testing.T, d deps, code string) *oidc.HandoffRecord {
		t.Helper()
		tokenID, _ := splitHandoffCode(t, code)
		rec, err := d.store.FindByTokenID(t.Context(), tokenID)
		require.NoError(t, err, "the issued code's record must be stored under its token id")
		return rec
	}

	cases := []testCase{
		{
			name:  "the stored record holds a digest, not the secret",
			setup: memory,
			assert: func(t *testing.T, d deps, code string, err error) {
				require.NoError(t, err)
				_, secret := splitHandoffCode(t, code)
				rec := stored(t, d, code)

				sum := sha256.Sum256([]byte(secret))
				assert.Equal(t, sum[:], rec.SecretHash, "the record holds SHA-256 of the secret")
				assert.NotContains(t, fmt.Sprintf("%+v", *rec), secret, "no field of the record holds the secret")
				assert.NotContains(t, string(rec.SecretHash), secret)
			},
		},
		{
			name:  "the record carries the reference, provider, issuer, sid, ID token and next",
			setup: memory,
			assert: func(t *testing.T, d deps, code string, err error) {
				require.NoError(t, err)
				rec := stored(t, d, code)

				tokenID, _ := splitHandoffCode(t, code)
				assert.Equal(t, tokenID, rec.TokenID)
				assert.Equal(t, identity.UserID("u-1"), rec.UserID)
				assert.Equal(t, "corp", rec.Provider)
				assert.Equal(t, "https://corp.example", rec.Issuer)
				assert.Equal(t, "sid-1", rec.SessionID)
				assert.Equal(t, handoffIDToken, rec.IDToken)
				assert.Equal(t, "/dashboard", rec.Next)
				assert.Nil(t, rec.ConsumedAt, "a fresh code is unconsumed")
				assert.False(t, rec.ID.IsZero(), "the record has an identifier")
			},
		},
		{
			name: "the code is 16 and 32 random bytes, base64url",
			setup: func(*testing.T, *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				return oidc.NewMemoryHandoffStore(), []oidc.HandoffOption{oidc.WithHandoffRandom(handoffFixedRandom(48))}
			},
			assert: func(t *testing.T, _ deps, code string, err error) {
				require.NoError(t, err)

				all, _ := io.ReadAll(handoffFixedRandom(48))
				want := base64.RawURLEncoding.EncodeToString(all[:16]) + "." +
					base64.RawURLEncoding.EncodeToString(all[16:])
				assert.Equal(t, want, code)

				tokenID, secret := splitHandoffCode(t, code)
				assert.Len(t, tokenID, 22, "16 bytes, base64url without padding")
				assert.Len(t, secret, 43, "32 bytes, base64url without padding")
			},
		},
		{
			name: "two codes differ with the default random source",
			setup: func(*testing.T, *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				return oidc.NewMemoryHandoffStore(), nil
			},
			assert: func(t *testing.T, d deps, code string, err error) {
				require.NoError(t, err)
				m, err := oidc.NewHandoff(d.store, NewMockUserLoader(gomock.NewController(t)))
				require.NoError(t, err)
				other, err := m.Issue(t.Context(), handoffCallback())
				require.NoError(t, err)
				assert.NotEqual(t, code, other)
			},
		},
		{
			name: "the record id comes from the generator",
			setup: func(_ *testing.T, ctrl *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				g := NewMockHandoffIDGenerator(ctrl)
				g.EXPECT().NewID().Return(id.MustParse("01926a4e-0000-7000-8000-00000000beef"), nil)
				return oidc.NewMemoryHandoffStore(), []oidc.HandoffOption{oidc.WithHandoffIDGenerator(g)}
			},
			assert: func(t *testing.T, d deps, code string, err error) {
				require.NoError(t, err)
				assert.Equal(t, id.MustParse("01926a4e-0000-7000-8000-00000000beef"), stored(t, d, code).ID)
			},
		},
		{
			name:  "expiry is exactly 60 seconds after issue, and creation is the issue time",
			setup: memory,
			assert: func(t *testing.T, d deps, code string, err error) {
				require.NoError(t, err)
				rec := stored(t, d, code)
				assert.Equal(t, 60*time.Second, oidc.HandoffTTL)
				assert.Equal(t, handoffT0, rec.CreatedAt)
				assert.Equal(t, handoffT0.Add(60*time.Second), rec.ExpiresAt)
			},
		},
		{
			name: "a generator failure issues nothing",
			setup: func(_ *testing.T, ctrl *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				g := NewMockHandoffIDGenerator(ctrl)
				g.EXPECT().NewID().Return(id.Nil, errors.New("clock went backwards"))
				return NewMockHandoffStore(ctrl), []oidc.HandoffOption{oidc.WithHandoffIDGenerator(g)}
			},
			assert: func(t *testing.T, _ deps, code string, err error) {
				require.Error(t, err)
				assert.Empty(t, code)
			},
		},
		{
			name: "a random source failure issues nothing",
			setup: func(_ *testing.T, ctrl *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				return NewMockHandoffStore(ctrl), []oidc.HandoffOption{oidc.WithHandoffRandom(handoffFixedRandom(20))}
			},
			assert: func(t *testing.T, _ deps, code string, err error) {
				require.Error(t, err)
				assert.Empty(t, code)
			},
		},
		{
			name: "a store failure is returned and no code is handed out",
			setup: func(_ *testing.T, ctrl *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				s := NewMockHandoffStore(ctrl)
				s.EXPECT().Insert(gomock.Any(), gomock.Any()).Return(errors.New("db down"))
				return s, nil
			},
			assert: func(t *testing.T, _ deps, code string, err error) {
				require.Error(t, err)
				assert.Empty(t, code)
			},
		},
		{
			name: "a result with no principal issues nothing",
			setup: func(_ *testing.T, ctrl *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				return NewMockHandoffStore(ctrl), nil
			},
			res: func() oidc.CallbackResult {
				r := handoffCallback()
				r.Principal = nil
				return r
			},
			assert: func(t *testing.T, _ deps, code string, err error) {
				require.Error(t, err)
				assert.Empty(t, code)
			},
		},
		{
			name: "a principal with no user reference issues nothing",
			setup: func(_ *testing.T, ctrl *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				return NewMockHandoffStore(ctrl), nil
			},
			res: func() oidc.CallbackResult {
				r := handoffCallback()
				r.Principal = &identity.Principal{Username: "alice"}
				return r
			},
			assert: func(t *testing.T, _ deps, code string, err error) {
				require.Error(t, err)
				assert.Empty(t, code)
			},
		},
		{
			name:  "a code redeemed exactly at expiry is refused, and just before it is not",
			setup: memory,
			assert: func(t *testing.T, d deps, code string, err error) {
				require.NoError(t, err)

				d.clock.Advance(handoffT0.Add(60 * time.Second).Sub(d.clock.Now()))
				_, err = d.m.Redeem(t.Context(), code)
				require.ErrorIs(t, err, oidc.ErrInvalidHandoff, "a code issued at 10:00:00 is refused at 10:01:00")

				d.clock.Advance(handoffT0.Add(60*time.Second - time.Nanosecond).Sub(d.clock.Now()))
				d.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).
					Return(&identity.Details{ID: "u-1", Active: true}, nil)
				_, err = d.m.Redeem(t.Context(), code)
				require.NoError(t, err, "the refusal at expiry spent nothing, and the code is live until then")
			},
		},
		{
			name: "a cancelled context issues nothing",
			setup: func(_ *testing.T, ctrl *gomock.Controller) (oidc.HandoffStore, []oidc.HandoffOption) {
				return NewMockHandoffStore(ctrl), nil
			},
			ctx: func(ctx context.Context) context.Context {
				c, cancel := context.WithCancel(ctx)
				cancel()
				return c
			},
			assert: func(t *testing.T, _ deps, code string, err error) {
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, code)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			clock := clockwork.NewFakeClockAt(handoffT0)
			store, opts := tc.setup(t, ctrl)
			opts = append([]oidc.HandoffOption{oidc.WithHandoffClock(clock)}, opts...)

			users := NewMockUserLoader(ctrl)
			m, err := oidc.NewHandoff(store, users, opts...)
			require.NoError(t, err)

			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(ctx)
			}
			res := handoffCallback()
			if tc.res != nil {
				res = tc.res()
			}

			code, err := m.Issue(ctx, res)
			tc.assert(t, deps{store: store, clock: clock, m: m, users: users}, code, err)
		})
	}
}

func TestHandoffIssueConstruction(t *testing.T) {
	t.Parallel()

	var (
		typedNilStore  *oidc.MemoryHandoffStore
		typedNilLoader *MockUserLoader
		typedNilReader *bytes.Reader
	)

	type testCase struct {
		name   string
		build  func(t *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error)
		assert func(t *testing.T, m *oidc.Handoff, err error)
	}

	refusedAsMissingPort := func(t *testing.T, m *oidc.Handoff, err error) {
		require.ErrorIs(t, err, oidc.ErrConfig)
		require.ErrorIs(t, err, identity.ErrMissingPort)
		assert.Nil(t, m)
	}
	refusedAsConfig := func(t *testing.T, m *oidc.Handoff, err error) {
		require.ErrorIs(t, err, oidc.ErrConfig)
		assert.Nil(t, m)
	}

	cases := []testCase{
		{
			name: "the defaults issue a code",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl))
			},
			assert: func(t *testing.T, m *oidc.Handoff, err error) {
				require.NoError(t, err)
				code, err := m.Issue(t.Context(), handoffCallback())
				require.NoError(t, err)
				tokenID, secret := splitHandoffCode(t, code)
				assert.Len(t, tokenID, 22)
				assert.Len(t, secret, 43)
			},
		},
		{
			name: "a nil option is ignored",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl), nil)
			},
			assert: func(t *testing.T, m *oidc.Handoff, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "a nil store is a missing port",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(nil, NewMockUserLoader(ctrl))
			},
			assert: refusedAsMissingPort,
		},
		{
			name: "a typed nil store is a missing port",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(typedNilStore, NewMockUserLoader(ctrl))
			},
			assert: refusedAsMissingPort,
		},
		{
			name: "a nil loader is a missing port",
			build: func(*testing.T, *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), nil)
			},
			assert: refusedAsMissingPort,
		},
		{
			name: "a typed nil loader is a missing port",
			build: func(*testing.T, *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), typedNilLoader)
			},
			assert: refusedAsMissingPort,
		},
		{
			name: "WithHandoffRandom(nil) is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffRandom(nil))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffRandom of a typed nil is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffRandom(typedNilReader))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffClock(nil) is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffClock(nil))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffClock with a typed-nil clock is refused like an untyped one",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffClock((*nilClock)(nil)))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffIDGenerator(nil) is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffIDGenerator(nil))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffLogger(nil) is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.Handoff, error) {
				return oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffLogger(nil))
			},
			assert: refusedAsConfig,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := tc.build(t, gomock.NewController(t))
			tc.assert(t, m, err)
		})
	}
}

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
	clock *clockwork.FakeClock
	mem   *oidc.MemoryHandoffStore
	users *MockUserLoader
	logs  *handoffLogSink
	m     *oidc.Handoff
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

	f := &handoffRedeemFixture{ctrl: gomock.NewController(t), clock: clockwork.NewFakeClockAt(handoffT0), logs: &handoffLogSink{}}
	f.mem = oidc.NewMemoryHandoffStore()
	f.users = NewMockUserLoader(f.ctrl)

	issuer, err := oidc.NewHandoff(f.mem, NewMockUserLoader(f.ctrl), oidc.WithHandoffClock(f.clock))
	require.NoError(t, err)
	f.code, err = issuer.Issue(t.Context(), handoffCallback())
	require.NoError(t, err)

	var s oidc.HandoffStore = f.mem
	if store != nil {
		s = store(t, f.ctrl, f.mem)
	}
	f.m, err = oidc.NewHandoff(s, f.users,
		oidc.WithHandoffClock(f.clock), oidc.WithHandoffLogger(f.logs.Logger()))
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
				f.clock.Advance(handoffT0.Add(30 * time.Second).Sub(f.clock.Now()))
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
			name: "expired: exactly at the expiry",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.clock.Advance(handoffT0.Add(oidc.HandoffTTL).Sub(f.clock.Now()))
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				refusedAsInvalid(t, res, err)
				loggedAt(t, f, "DEBUG")
				assert.False(t, f.consumed(t))
			},
		},
		{
			name: "one nanosecond before the expiry redeems",
			arrange: func(_ *testing.T, f *handoffRedeemFixture) {
				f.clock.Advance(handoffT0.Add(oidc.HandoffTTL - time.Nanosecond).Sub(f.clock.Now()))
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
				f.clock.Advance(handoffT0.Add(-5 * time.Second).Sub(f.clock.Now()))
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
				return []oidc.RedeemCheck{func(context.Context, oidc.RedeemCandidate) error {
					return errRefusedByCheck
				}}
			},
			assert: func(t *testing.T, f *handoffRedeemFixture, res oidc.HandoffResult, err error) {
				assert.Same(t, errRefusedByCheck, err, "a check's own error is returned exactly")
				assert.Zero(t, res)
				assert.False(t, f.consumed(t), "a check refusal leaves the code")

				pass := func(context.Context, oidc.RedeemCandidate) error { return nil }
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
					return func(_ context.Context, c oidc.RedeemCandidate) error {
						calls = append(calls, n)
						assert.Equal(t, identity.UserID("u-1"), c.Principal.ID)
						assert.Equal(t, handoffPasswordChangedAt, c.PasswordChangedAt)
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

// handoffAssuranceEnv is one code issued for a callback result, the store it
// was written to, and every candidate the redemption's check was handed.
type handoffAssuranceEnv struct {
	mem   *oidc.MemoryHandoffStore
	m     *oidc.Handoff
	users *MockUserLoader
	code  string

	mu   sync.Mutex
	seen []oidc.RedeemCandidate
}

// record returns a check that keeps each candidate it is handed, then lets
// mutate change it, so a row can show what writing to it reaches.
func (e *handoffAssuranceEnv) record(mutate func(c *oidc.RedeemCandidate)) oidc.RedeemCheck {
	return func(_ context.Context, c oidc.RedeemCandidate) error {
		e.mu.Lock()
		e.seen = append(e.seen, c)
		e.mu.Unlock()
		if mutate != nil {
			mutate(&c)
		}
		return nil
	}
}

// stored returns the record the env's code was issued as.
func (e *handoffAssuranceEnv) stored(t *testing.T) oidc.HandoffRecord {
	t.Helper()

	tokenID, _ := splitHandoffCode(t, e.code)
	rec, err := e.mem.FindByTokenID(t.Context(), tokenID)
	require.NoError(t, err)
	require.NotNil(t, rec)
	return *rec
}

// assertedCallback is handoffCallback for a login whose verified ID token
// asserted amr ["pwd","mfa"] and acr urn:corp:loa:2.
func assertedCallback() oidc.CallbackResult {
	res := handoffCallback()
	res.AMR = []string{"pwd", "mfa"}
	res.ACR = "urn:corp:loa:2"
	return res
}

// TestHandoff_Assurance pins that the amr and acr a verified ID token asserted
// travel with the handoff code: written at issue, handed to every redemption
// check with the record's provider and issuer, and returned at redemption,
// each as a copy no reader can write through.
// Standalone from TestHandoffRedeem: each row issues its own code from an asserted callback before redeeming it.
func TestHandoff_Assurance(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name     string
		callback func() oidc.CallbackResult
		// afterIssue runs once the code is issued, before anything is read.
		afterIssue func(res *oidc.CallbackResult)
		mutate     func(c *oidc.RedeemCandidate)
		assert     func(t *testing.T, e *handoffAssuranceEnv, res oidc.HandoffResult, err error)
	}

	cases := []testCase{
		{
			name:     "issue then find: the record carries the asserted amr and acr",
			callback: assertedCallback,
			assert: func(t *testing.T, e *handoffAssuranceEnv, _ oidc.HandoffResult, err error) {
				require.NoError(t, err)
				rec := e.stored(t)
				assert.Equal(t, []string{"pwd", "mfa"}, rec.AMR)
				assert.Equal(t, "urn:corp:loa:2", rec.ACR)
			},
		},
		{
			name:     "issue copies the caller's amr",
			callback: assertedCallback,
			afterIssue: func(res *oidc.CallbackResult) {
				for i := range res.AMR {
					res.AMR[i] = "x"
				}
			},
			assert: func(t *testing.T, e *handoffAssuranceEnv, _ oidc.HandoffResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"pwd", "mfa"}, e.stored(t).AMR,
					"the record aliased the callback result's amr")
			},
		},
		{
			name:     "the check receives the record's provider, issuer, amr and acr",
			callback: assertedCallback,
			assert: func(t *testing.T, e *handoffAssuranceEnv, _ oidc.HandoffResult, err error) {
				require.NoError(t, err)
				require.Len(t, e.seen, 1)
				c := e.seen[0]
				assert.Equal(t, *identity.PrincipalFromDetails(handoffUser()), c.Principal)
				assert.Equal(t, handoffPasswordChangedAt, c.PasswordChangedAt)
				assert.Equal(t, "corp", c.Provider)
				assert.Equal(t, "https://corp.example", c.Issuer)
				assert.Equal(t, []string{"pwd", "mfa"}, c.AMR)
				assert.Equal(t, "urn:corp:loa:2", c.ACR)
			},
		},
		{
			name:     "the result carries the record's amr and acr",
			callback: assertedCallback,
			assert: func(t *testing.T, _ *handoffAssuranceEnv, res oidc.HandoffResult, err error) {
				require.NoError(t, err)
				assert.Equal(t, []string{"pwd", "mfa"}, res.AMR)
				assert.Equal(t, "urn:corp:loa:2", res.ACR)
			},
		},
		{
			name:     "the check's amr is a copy: writing to it changes neither the result nor the record",
			callback: assertedCallback,
			mutate: func(c *oidc.RedeemCandidate) {
				for i := range c.AMR {
					c.AMR[i] = "x"
				}
			},
			assert: func(t *testing.T, e *handoffAssuranceEnv, res oidc.HandoffResult, err error) {
				require.NoError(t, err)
				require.Len(t, e.seen, 1)
				assert.Equal(t, []string{"x", "x"}, e.seen[0].AMR, "the check was handed the record's amr to write to")
				assert.Equal(t, []string{"pwd", "mfa"}, res.AMR, "the result shares the check's amr")
				assert.Equal(t, []string{"pwd", "mfa"}, e.stored(t).AMR, "the record shares the check's amr")
			},
		},
		{
			name:     "a login that asserted nothing carries no assurance",
			callback: handoffCallback,
			assert: func(t *testing.T, e *handoffAssuranceEnv, res oidc.HandoffResult, err error) {
				require.NoError(t, err)
				require.Len(t, e.seen, 1)
				assert.Empty(t, e.seen[0].AMR)
				assert.Empty(t, e.seen[0].ACR)
				assert.Equal(t, "corp", e.seen[0].Provider, "the provider is still named")
				assert.Empty(t, res.AMR)
				assert.Empty(t, res.ACR)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			clk := clockwork.NewFakeClockAt(handoffT0)
			e := &handoffAssuranceEnv{mem: oidc.NewMemoryHandoffStore(), users: NewMockUserLoader(ctrl)}
			e.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil).AnyTimes()

			var err error
			e.m, err = oidc.NewHandoff(e.mem, e.users, oidc.WithHandoffClock(clk))
			require.NoError(t, err)

			res := tc.callback()
			e.code, err = e.m.Issue(t.Context(), res)
			require.NoError(t, err)
			if tc.afterIssue != nil {
				tc.afterIssue(&res)
			}

			got, err := e.m.Redeem(t.Context(), e.code, e.record(tc.mutate))
			tc.assert(t, e, got, err)
		})
	}
}

// TestHandoffFailureRecords pins that every handoff redemption stopped by a
// consumer dependency — the user loader, the store's find, the store's
// consume — is recorded through a fixed reason and the error's type, never the
// dependency's own text. The fixture error quotes a username and a user
// reference the manager never held, which scrubbing known values cannot catch.
// Standalone from TestHandoffRedeem: its rows assert only the failure record, and one redeems two codes.
func TestHandoffFailureRecords(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		store   func(t *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore
		arrange func(f *handoffRedeemFixture)
		assert  func(t *testing.T, logs string)
	}

	// failureRecord asserts the one record a dependency failure writes: no
	// dependency text, the fixed reason exactly once, and the error's type.
	// op, when not empty, is the operation the record must also name — find
	// or consume, for the two handoff-store call sites that share one
	// reason.
	failureRecord := func(reason, op string) func(t *testing.T, logs string) {
		return func(t *testing.T, logs string) {
			t.Helper()
			assert.NotContains(t, logs, "alice@example.com")
			assert.NotContains(t, logs, "u-123")
			assert.NotContains(t, logs, "[redacted]", "the record carries no scrubbed dependency text either")
			assert.Contains(t, logs, "reason="+reason)
			assert.Contains(t, logs, "error_type=*errors.errorString")
			assert.Equal(t, 1, strings.Count(logs, " reason="), "the record names its reason exactly once")
			if op != "" {
				assert.Contains(t, logs, "op="+op)
			}
		}
	}

	loads := func(f *handoffRedeemFixture) {
		f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)
	}

	cases := []testCase{
		{
			name: "a user loader failure",
			arrange: func(f *handoffRedeemFixture) {
				f.users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(nil, errRedactionFixture)
			},
			assert: failureRecord("user-loader", ""),
		},
		{
			name: "a store find failure",
			store: func(_ *testing.T, ctrl *gomock.Controller, _ *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := NewMockHandoffStore(ctrl)
				s.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).Return(nil, errRedactionFixture)
				return s
			},
			assert: failureRecord("handoff-store", "find"),
		},
		{
			name: "a store consume failure",
			store: func(_ *testing.T, ctrl *gomock.Controller, mem *oidc.MemoryHandoffStore) oidc.HandoffStore {
				s := NewMockHandoffStore(ctrl)
				s.EXPECT().FindByTokenID(gomock.Any(), gomock.Any()).DoAndReturn(mem.FindByTokenID)
				s.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).Return(errRedactionFixture)
				return s
			},
			arrange: loads,
			assert:  failureRecord("handoff-store", "consume"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newHandoffRedeemFixture(t, tc.store)
			if tc.arrange != nil {
				tc.arrange(f)
			}

			res, err := f.m.Redeem(t.Context(), f.code)
			refusedAsInvalid(t, res, err)
			tc.assert(t, f.logs.String())
		})
	}

	// A find failure and a consume failure share the reason handoff-store.
	// Before op distinguished them, the second failure's sampling key was
	// identical to the first's, so it was suppressed rather than recorded —
	// an operator could see one failure and not tell which call it was.
	t.Run("a find failure and a consume failure in one window write separate records", func(t *testing.T) {
		t.Parallel()

		mem := oidc.NewMemoryHandoffStore()
		issuer, err := oidc.NewHandoff(mem, NewMockUserLoader(gomock.NewController(t)))
		require.NoError(t, err)

		code1, err := issuer.Issue(t.Context(), handoffCallback())
		require.NoError(t, err)
		code2, err := issuer.Issue(t.Context(), handoffCallback())
		require.NoError(t, err)

		tokenID1, _ := splitHandoffCode(t, code1)
		tokenID2, _ := splitHandoffCode(t, code2)

		ctrl := gomock.NewController(t)
		store := NewMockHandoffStore(ctrl)
		store.EXPECT().FindByTokenID(gomock.Any(), tokenID1).Return(nil, errRedactionFixture)
		store.EXPECT().FindByTokenID(gomock.Any(), tokenID2).DoAndReturn(mem.FindByTokenID)
		store.EXPECT().Consume(gomock.Any(), tokenID2, gomock.Any()).Return(errRedactionFixture)

		users := NewMockUserLoader(ctrl)
		users.EXPECT().LoadByUserID(gomock.Any(), identity.UserID("u-1")).Return(handoffUser(), nil)

		logs := &handoffLogSink{}
		m, err := oidc.NewHandoff(store, users, oidc.WithHandoffLogger(logs.Logger()))
		require.NoError(t, err)

		res1, err1 := m.Redeem(t.Context(), code1)
		refusedAsInvalid(t, res1, err1)
		res2, err2 := m.Redeem(t.Context(), code2)
		refusedAsInvalid(t, res2, err2)

		out := logs.String()
		assert.Equal(t, 2, strings.Count(out, "reason=handoff-store"),
			"both the find and the consume failure wrote a record")
		assert.Contains(t, out, "op=find")
		assert.Contains(t, out, "op=consume")
	})
}

// TestHandoffManagerFlushRefusalLogs pins spec oidc-login "OIDC components
// flush their refusal logs": FlushRefusalLogs reports what the handoff
// manager's sampler is holding back, reports nothing when there is nothing
// pending, and leaves the manager usable afterward.
func TestHandoffManagerFlushRefusalLogs(t *testing.T) {
	t.Parallel()

	// buildHandoff issues one code and returns the manager under test, the
	// issued code, and a sink of every record it writes. Every case shares a
	// clock that never advances, so repeated refusals of one reason land in
	// the same sampling window.
	buildHandoff := func(t *testing.T) (m *oidc.Handoff, code string, logs *handoffLogSink) {
		t.Helper()

		logs = &handoffLogSink{}
		m, err := oidc.NewHandoff(oidc.NewMemoryHandoffStore(), NewMockUserLoader(gomock.NewController(t)),
			oidc.WithHandoffClock(flushFixedClock()), oidc.WithHandoffLogger(logs.Logger()))
		require.NoError(t, err)

		code, err = m.Issue(t.Context(), handoffCallback())
		require.NoError(t, err)

		return m, code, logs
	}

	// wrongSecretFor returns a well-formed secret half that is not code's
	// own, so FindByTokenID still finds the record and the secret mismatch is
	// what refuses the redemption, every time, under one sampling key.
	wrongSecretFor := func(t *testing.T, code string) string {
		t.Helper()

		tokenID, _ := splitHandoffCode(t, code)
		return tokenID + "." + strings.Repeat("A", 43)
	}

	type testCase struct {
		name string
		act  func(t *testing.T, m *oidc.Handoff, code string)

		// afterFlush runs after FlushRefusalLogs, only for the row proving the
		// manager still works afterward; nil for every other row.
		afterFlush func(t *testing.T, m *oidc.Handoff, code string)

		assert func(t *testing.T, err error, logs string)
	}

	redeemWrongThrice := func(t *testing.T, m *oidc.Handoff, code string) {
		t.Helper()

		wrong := wrongSecretFor(t, code)
		for range 3 {
			_, err := m.Redeem(t.Context(), wrong)
			require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
		}
	}

	cases := []testCase{
		{
			name: "records suppressed within a window are reported by the flush with their count",
			act:  redeemWrongThrice,
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				sums := flushSummaries(t, logs, "oidc handoff refusals suppressed")
				require.Len(t, sums, 1, "three refusals of one reason must flush to exactly one summary record")
				assert.Equal(t, 2, sums[0], "the first refusal was already written; the flush owes the other two")
			},
		},
		{
			name: "a flush with nothing pending reports nothing",
			act:  func(*testing.T, *oidc.Handoff, string) {},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)
				assert.Empty(t, flushSummaries(t, logs, "oidc handoff refusals suppressed"))
			},
		},
		{
			name: "the component still works after a flush",
			act:  redeemWrongThrice,
			afterFlush: func(t *testing.T, m *oidc.Handoff, code string) {
				t.Helper()

				// One more refusal of the same reason, after the flush, must
				// be written again rather than counted as still suppressed.
				wrong := wrongSecretFor(t, code)
				_, err := m.Redeem(t.Context(), wrong)
				require.ErrorIs(t, err, oidc.ErrInvalidHandoff)
			},
			assert: func(t *testing.T, err error, logs string) {
				require.NoError(t, err)

				// The flush forgot the key, so the redemption afterFlush
				// drove is written again, unsampled, rather than counted as
				// still suppressed.
				sums := flushSummaries(t, logs, "oidc handoff refusals suppressed")
				require.Len(t, sums, 1)
				assert.Equal(t, 2, sums[0])

				assert.Equal(t, 2, strings.Count(logs, `msg="oidc handoff redemption refused"`),
					"the refusal after the flush must be written again, not suppressed")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, code, logs := buildHandoff(t)
			tc.act(t, m, code)
			err := m.FlushRefusalLogs()

			if tc.afterFlush != nil {
				tc.afterFlush(t, m, code)
			}

			tc.assert(t, err, logs.String())
		})
	}
}

// handoffStoreT0 is when every record in the memory store table was issued.
var handoffStoreT0 = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

// handoffStoreRecord is one record as Insert would receive it, issued at
// handoffStoreT0 and expiring a minute later.
func handoffStoreRecord(tokenID string) oidc.HandoffRecord {
	sum := sha256.Sum256([]byte("secret-of-" + tokenID))

	return oidc.HandoffRecord{
		ID:         id.MustParse("01926a4e-0000-7000-8000-000000000001"),
		TokenID:    tokenID,
		SecretHash: sum[:],
		UserID:     "u-1",
		Provider:   "corp",
		Issuer:     "https://idp.example.com",
		SessionID:  "sid-1",
		IDToken:    "id-token",
		Next:       "/home",
		AMR:        []string{"pwd", "mfa"},
		ACR:        "urn:corp:loa:2",
		CreatedAt:  handoffStoreT0,
		ExpiresAt:  handoffStoreT0.Add(time.Minute),
	}
}

func TestMemoryHandoffStore(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		seed   []oidc.HandoffRecord
		assert func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore)
	}

	cases := []testCase{
		{
			name: "insert then find returns what was stored",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, handoffStoreRecord("tok-a"), *got)
			},
		},
		{
			name: "find returns a copy the caller cannot write through",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				first, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				clear(first.SecretHash)
				first.AMR[1] = "x"
				first.UserID = "u-2"
				spent := handoffStoreT0
				first.ConsumedAt = &spent

				again, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assert.Equal(t, handoffStoreRecord("tok-a"), *again, "the store aliased its own record on read")
			},
		},
		{
			name: "insert copies the caller's buffers",
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				rec := handoffStoreRecord("tok-a")
				require.NoError(t, s.Insert(ctx, rec))
				clear(rec.SecretHash)
				rec.AMR[1] = "x"

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assert.Equal(t, handoffStoreRecord("tok-a").SecretHash, got.SecretHash,
					"the store aliased the caller's buffer on write")
				assert.Equal(t, handoffStoreRecord("tok-a").AMR, got.AMR,
					"the store aliased the caller's amr on write")
			},
		},
		{
			name: "a second insert of one token id is refused and the first record survives",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				other := handoffStoreRecord("tok-a")
				other.UserID = "u-2"
				require.Error(t, s.Insert(ctx, other))

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				assert.Equal(t, handoffStoreRecord("tok-a"), *got)
			},
		},
		{
			name: "find of a missing id is not-found, and a present one is still found",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				got, err := s.FindByTokenID(ctx, "tok-missing")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)
				assert.Nil(t, got)

				_, err = s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
			},
		},
		{
			name: "consume of an unconsumed record succeeds and records when",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				at := handoffStoreT0.Add(10 * time.Second)
				require.NoError(t, s.Consume(ctx, "tok-a", at))

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NotNil(t, got.ConsumedAt)
				assert.Equal(t, at, *got.ConsumedAt)
			},
		},
		{
			name: "a second consume is not-found and keeps the first consume time",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				first := handoffStoreT0.Add(10 * time.Second)
				require.NoError(t, s.Consume(ctx, "tok-a", first))
				require.ErrorIs(t, s.Consume(ctx, "tok-a", first.Add(time.Second)), oidc.ErrHandoffNotFound)

				got, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NotNil(t, got.ConsumedAt)
				assert.Equal(t, first, *got.ConsumedAt)
			},
		},
		{
			name: "consume of a missing id is not-found, and another record still consumes",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				require.ErrorIs(t, s.Consume(ctx, "tok-missing", handoffStoreT0), oidc.ErrHandoffNotFound)

				_, err := s.FindByTokenID(ctx, "tok-a")
				require.NoError(t, err)
				require.NoError(t, s.Consume(ctx, "tok-a", handoffStoreT0))
			},
		},
		{
			name: "delete-expired removes only records expired before the cutoff and counts them",
			seed: func() []oidc.HandoffRecord {
				early := handoffStoreRecord("tok-early") // expires T0+1m
				late := handoffStoreRecord("tok-late")
				late.ExpiresAt = handoffStoreT0.Add(5 * time.Minute)
				live := handoffStoreRecord("tok-live")
				live.ExpiresAt = handoffStoreT0.Add(time.Hour)
				return []oidc.HandoffRecord{early, late, live}
			}(),
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				n, err := s.DeleteExpired(ctx, handoffStoreT0.Add(2*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 1, n)

				_, err = s.FindByTokenID(ctx, "tok-early")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)
				_, err = s.FindByTokenID(ctx, "tok-late")
				require.NoError(t, err, "a record that expired after the cutoff must survive")
				_, err = s.FindByTokenID(ctx, "tok-live")
				require.NoError(t, err)
			},
		},
		{
			name: "a cutoff after a record's expiry deletes it even if the store clock has not reached it",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a")}, // expires T0+1m; store clock stays T0
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				n, err := s.DeleteExpired(ctx, handoffStoreT0.Add(time.Hour))
				require.NoError(t, err)
				assert.Equal(t, 1, n,
					"the port contract judges expiry against the cutoff alone, not the store's own clock")

				_, err = s.FindByTokenID(ctx, "tok-a")
				require.ErrorIs(t, err, oidc.ErrHandoffNotFound)
			},
		},
		{
			name: "a zero cutoff is refused, every record survives, and a real cutoff then works",
			seed: []oidc.HandoffRecord{handoffStoreRecord("tok-a"), handoffStoreRecord("tok-b")},
			assert: func(t *testing.T, ctx context.Context, s *oidc.MemoryHandoffStore) {
				n, err := s.DeleteExpired(ctx, time.Time{})
				require.ErrorIs(t, err, oidc.ErrRetainSinceRequired)
				assert.Zero(t, n)

				for _, tok := range []string{"tok-a", "tok-b"} {
					_, err := s.FindByTokenID(ctx, tok)
					require.NoError(t, err, "a refused purge must delete nothing")
				}

				n, err = s.DeleteExpired(ctx, handoffStoreT0.Add(5*time.Minute))
				require.NoError(t, err)
				assert.Equal(t, 2, n)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := oidc.NewMemoryHandoffStore()
			for _, rec := range tc.seed {
				require.NoError(t, s.Insert(t.Context(), rec))
			}

			tc.assert(t, t.Context(), s)
		})
	}
}

// handoffExpiryManager returns a handoff manager over store, reading time from
// clk.
func handoffExpiryManager(t *testing.T, store oidc.HandoffStore, clk clockwork.Clock) *oidc.Handoff {
	t.Helper()

	h, err := oidc.NewHandoff(store, NewMockUserLoader(gomock.NewController(t)), oidc.WithHandoffClock(clk))
	require.NoError(t, err)

	return h
}

// expiryHandoff is a record issued at expiryT0 that expires after ttl.
func expiryHandoff(tokenID string, n byte, ttl time.Duration) oidc.HandoffRecord {
	rec := handoffStoreRecord(tokenID)
	rec.ID = id.MustParse("01926a4e-0000-7000-8000-0000000000" + string([]byte{'a', 'a' + n}))
	rec.CreatedAt = expiryT0
	rec.ExpiresAt = expiryT0.Add(ttl)

	return rec
}

func TestHandoffExpiryTask(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name string
		// task builds the task under test, seeding whatever it sweeps, and
		// returns a check of what is left after the run.
		task   func(t *testing.T, ctx context.Context) (expiry.Task, func(t *testing.T))
		assert func(t *testing.T, task expiry.Task, removed int, err error)
	}

	cases := []testCase{
		{
			name: "handoffs: the expired handoff goes and the live one stays",
			task: func(t *testing.T, ctx context.Context) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryT0)
				store := oidc.NewMemoryHandoffStore()
				require.NoError(t, store.Insert(ctx, expiryHandoff("tok-old", 1, time.Minute)))
				require.NoError(t, store.Insert(ctx, expiryHandoff("tok-live", 2, time.Hour)))
				h := handoffExpiryManager(t, store, clk)
				clk.Advance(10 * time.Minute)

				return oidc.HandoffExpiryTask(h), func(t *testing.T) {
					_, err := store.FindByTokenID(ctx, "tok-old")
					require.ErrorIs(t, err, oidc.ErrHandoffNotFound)
					_, err = store.FindByTokenID(ctx, "tok-live")
					assert.NoError(t, err, "the live handoff must survive the sweep")
				}
			},
			assert: func(t *testing.T, task expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 1, removed)
				assert.Equal(t, "oidc-handoffs", task.Name)
				assert.Zero(t, task.Interval)
			},
		},
		{
			name: "handoffs: the cutoff is the manager's own now",
			task: func(t *testing.T, _ context.Context) (expiry.Task, func(t *testing.T)) {
				clk := clockwork.NewFakeClockAt(expiryT0)
				store := NewMockHandoffStore(gomock.NewController(t))
				store.EXPECT().DeleteExpired(gomock.Any(), expiryT0.Add(time.Hour)).Return(3, nil)
				h := handoffExpiryManager(t, store, clk)
				clk.Advance(time.Hour)

				return oidc.HandoffExpiryTask(h), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.NoError(t, err)
				assert.Equal(t, 3, removed)
			},
		},
		{
			name: "handoffs: a store error is returned with the count",
			task: func(t *testing.T, _ context.Context) (expiry.Task, func(t *testing.T)) {
				store := NewMockHandoffStore(gomock.NewController(t))
				store.EXPECT().DeleteExpired(gomock.Any(), gomock.Any()).Return(1, errExpiryStore)

				return oidc.HandoffExpiryTask(handoffExpiryManager(t, store, clockwork.NewFakeClockAt(expiryT0))), func(*testing.T) {}
			},
			assert: func(t *testing.T, _ expiry.Task, removed int, err error) {
				require.ErrorIs(t, err, errExpiryStore)
				assert.Equal(t, 1, removed)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			task, after := tc.task(t, ctx)
			require.NotNil(t, task.Run, "the task must have a Run")

			removed, err := task.Run(ctx)
			tc.assert(t, task, removed, err)
			after(t)
		})
	}
}
