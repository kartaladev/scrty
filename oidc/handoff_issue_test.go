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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/oidc"
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

// handoffClock is a settable clock safe for concurrent reads.
type handoffClock struct {
	mu  sync.Mutex
	now time.Time
}

func newHandoffClock(at time.Time) *handoffClock { return &handoffClock{now: at} }

func (c *handoffClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *handoffClock) Set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = at
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
		clock *handoffClock
		m     *oidc.HandoffManager
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
				m, err := oidc.NewHandoffManager(d.store, NewMockUserLoader(gomock.NewController(t)))
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

				d.clock.Set(handoffT0.Add(60 * time.Second))
				_, err = d.m.Redeem(t.Context(), code)
				require.ErrorIs(t, err, oidc.ErrInvalidHandoff, "a code issued at 10:00:00 is refused at 10:01:00")

				d.clock.Set(handoffT0.Add(60*time.Second - time.Nanosecond))
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
			clock := newHandoffClock(handoffT0)
			store, opts := tc.setup(t, ctrl)
			opts = append([]oidc.HandoffOption{oidc.WithHandoffClock(clock.Now)}, opts...)

			users := NewMockUserLoader(ctrl)
			m, err := oidc.NewHandoffManager(store, users, opts...)
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
		build  func(t *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error)
		assert func(t *testing.T, m *oidc.HandoffManager, err error)
	}

	refusedAsMissingPort := func(t *testing.T, m *oidc.HandoffManager, err error) {
		require.ErrorIs(t, err, oidc.ErrConfig)
		require.ErrorIs(t, err, identity.ErrMissingPort)
		assert.Nil(t, m)
	}
	refusedAsConfig := func(t *testing.T, m *oidc.HandoffManager, err error) {
		require.ErrorIs(t, err, oidc.ErrConfig)
		assert.Nil(t, m)
	}

	cases := []testCase{
		{
			name: "the defaults issue a code",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl))
			},
			assert: func(t *testing.T, m *oidc.HandoffManager, err error) {
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
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl), nil)
			},
			assert: func(t *testing.T, m *oidc.HandoffManager, err error) {
				require.NoError(t, err)
				assert.NotNil(t, m)
			},
		},
		{
			name: "a nil store is a missing port",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(nil, NewMockUserLoader(ctrl))
			},
			assert: refusedAsMissingPort,
		},
		{
			name: "a typed nil store is a missing port",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(typedNilStore, NewMockUserLoader(ctrl))
			},
			assert: refusedAsMissingPort,
		},
		{
			name: "a nil loader is a missing port",
			build: func(*testing.T, *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), nil)
			},
			assert: refusedAsMissingPort,
		},
		{
			name: "a typed nil loader is a missing port",
			build: func(*testing.T, *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), typedNilLoader)
			},
			assert: refusedAsMissingPort,
		},
		{
			name: "WithHandoffRandom(nil) is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffRandom(nil))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffRandom of a typed nil is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffRandom(typedNilReader))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffClock(nil) is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffClock(nil))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffIDGenerator(nil) is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
					oidc.WithHandoffIDGenerator(nil))
			},
			assert: refusedAsConfig,
		},
		{
			name: "WithHandoffLogger(nil) is refused",
			build: func(_ *testing.T, ctrl *gomock.Controller) (*oidc.HandoffManager, error) {
				return oidc.NewHandoffManager(oidc.NewMemoryHandoffStore(), NewMockUserLoader(ctrl),
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
